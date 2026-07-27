//! Concurrent, retrying convergence of registered environments.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::apply;
use crate::client::Ctx;
use crate::ontology::KIND_ENVIRONMENT;
use crate::plan::{self, PlanState};
use crate::reconcile_fence::{FenceAdmission, FenceGuard, ReconcileTickFence};

#[derive(Debug, Clone)]
pub struct Config {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_concurrency: usize,
    pub skip_gates: bool,
    pub unapproved_development_reason: Option<String>,
    pub approval_directory: Option<PathBuf>,
    pub approval_trust_roots: Option<PathBuf>,
    /// TTL for multi-host reconcile tick claims (milliseconds).
    pub fence_ttl_ms: i64,
    /// Stable host/instance identity used for tick fencing.
    pub instance_id: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(5 * 60),
            max_concurrency: 8,
            skip_gates: false,
            unapproved_development_reason: None,
            approval_directory: std::env::var_os("TENKAI_PLAN_APPROVAL_DIR").map(PathBuf::from),
            approval_trust_roots: std::env::var_os("TENKAI_PLAN_APPROVAL_TRUST_ROOTS")
                .map(PathBuf::from),
            fence_ttl_ms: 30_000,
            instance_id: format!("reconciler-{}", uuid::Uuid::new_v4()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum EnvironmentStatus {
    Current,
    Applied { plan_id: String, steps: usize },
    AwaitingRuntime { plan_id: String, steps: usize },
    AwaitingApproval { plan_id: String, steps: usize },
    Failed { error: String },
    Deferred { retry_at: i64 },
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentResult {
    pub environment: String,
    pub status: EnvironmentStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TickReport {
    pub environments: Vec<EnvironmentResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStepReceipt {
    pub step_id: String,
    pub succeeded: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCompletion {
    pub plan_id: String,
    pub generation: u64,
    pub succeeded: bool,
    pub detail: String,
    pub receipts: Vec<RuntimeStepReceipt>,
}

impl TickReport {
    pub fn failures(&self) -> usize {
        self.environments
            .iter()
            .filter(|result| matches!(result.status, EnvironmentStatus::Failed { .. }))
            .count()
    }

    pub fn successes(&self) -> usize {
        self.environments
            .len()
            .saturating_sub(self.failures())
            .saturating_sub(
                self.environments
                    .iter()
                    .filter(|result| {
                        matches!(
                            result.status,
                            EnvironmentStatus::Busy | EnvironmentStatus::Deferred { .. }
                        )
                    })
                    .count(),
            )
    }

    /// Operator diagnostics without secrets or tenant identifiers beyond env names.
    pub fn diagnostics(&self) -> TickDiagnostics {
        let mut failed = 0usize;
        let mut busy = 0usize;
        let mut deferred = 0usize;
        let mut applied = 0usize;
        let mut current = 0usize;
        let mut awaiting_runtime = 0usize;
        let mut awaiting_approval = 0usize;
        for result in &self.environments {
            match &result.status {
                EnvironmentStatus::Failed { .. } => failed += 1,
                EnvironmentStatus::Busy => busy += 1,
                EnvironmentStatus::Deferred { .. } => deferred += 1,
                EnvironmentStatus::Applied { .. } => applied += 1,
                EnvironmentStatus::Current => current += 1,
                EnvironmentStatus::AwaitingRuntime { .. } => awaiting_runtime += 1,
                EnvironmentStatus::AwaitingApproval { .. } => awaiting_approval += 1,
            }
        }
        TickDiagnostics {
            environments_total: self.environments.len(),
            environments_failed: failed,
            environments_busy: busy,
            environments_deferred: deferred,
            environments_applied: applied,
            environments_current: current,
            environments_awaiting_runtime: awaiting_runtime,
            environments_awaiting_approval: awaiting_approval,
            outcome: if failed == 0 { "ok" } else { "degraded" },
        }
    }
}

/// Stable diagnostic fields for logging and operator tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TickDiagnostics {
    pub environments_total: usize,
    pub environments_failed: usize,
    pub environments_busy: usize,
    pub environments_deferred: usize,
    pub environments_applied: usize,
    pub environments_current: usize,
    pub environments_awaiting_runtime: usize,
    pub environments_awaiting_approval: usize,
    /// `ok` when no environment failed this tick; otherwise `degraded`.
    pub outcome: &'static str,
}

/// Cumulative counters retained across ticks for diagnostics and OpenMetrics (#137).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileDiagnostics {
    pub ticks_total: u64,
    pub ticks_failed: u64,
    pub last_outcome: String,
    pub last_environments_total: usize,
    pub last_environments_failed: usize,
    /// Cumulative `EnvironmentStatus::Busy` admissions (local in-flight or fence).
    pub environments_busy_total: u64,
}

impl ReconcileDiagnostics {
    pub fn record_tick(&mut self, report: &TickReport) {
        self.ticks_total = self.ticks_total.saturating_add(1);
        let diag = report.diagnostics();
        if diag.environments_failed > 0 {
            self.ticks_failed = self.ticks_failed.saturating_add(1);
        }
        self.last_outcome = diag.outcome.into();
        self.last_environments_total = diag.environments_total;
        self.last_environments_failed = diag.environments_failed;
        self.environments_busy_total = self
            .environments_busy_total
            .saturating_add(diag.environments_busy as u64);
    }

    pub fn record_tick_error(&mut self) {
        self.ticks_total = self.ticks_total.saturating_add(1);
        self.ticks_failed = self.ticks_failed.saturating_add(1);
        self.last_outcome = "error".into();
    }
}

#[derive(Default)]
struct SchedulerState {
    in_flight: HashSet<String>,
    retries: HashMap<String, RetryState>,
}

struct RetryState {
    failures: u32,
    retry_at: i64,
}

enum Admission {
    Started,
    Busy,
    Deferred(i64),
}

impl SchedulerState {
    fn begin(&mut self, environment: &str, now: i64) -> Admission {
        if self.in_flight.contains(environment) {
            return Admission::Busy;
        }
        if let Some(retry) = self.retries.get(environment)
            && retry.retry_at > now
        {
            return Admission::Deferred(retry.retry_at);
        }
        self.in_flight.insert(environment.into());
        Admission::Started
    }

    fn finish(&mut self, environment: &str, succeeded: bool, now: i64, config: &Config) {
        self.in_flight.remove(environment);
        if succeeded {
            self.retries.remove(environment);
            return;
        }
        let failures = self
            .retries
            .get(environment)
            .map_or(1, |retry| retry.failures.saturating_add(1));
        let multiplier = 1_u32 << failures.saturating_sub(1).min(31);
        let delay = config
            .initial_backoff
            .saturating_mul(multiplier)
            .min(config.max_backoff);
        let delay = i64::try_from(delay.as_millis()).unwrap_or(i64::MAX);
        self.retries.insert(
            environment.into(),
            RetryState {
                failures,
                retry_at: now.saturating_add(delay),
            },
        );
    }
}

struct AdmissionGuard {
    environment: String,
    state: Arc<Mutex<SchedulerState>>,
    config: Config,
    completed: bool,
}

impl AdmissionGuard {
    fn finish(mut self, succeeded: bool) {
        self.state.lock().expect("reconciler state lock").finish(
            &self.environment,
            succeeded,
            crate::now_millis(),
            &self.config,
        );
        self.completed = true;
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.state.lock().expect("reconciler state lock").finish(
                &self.environment,
                false,
                crate::now_millis(),
                &self.config,
            );
        }
    }
}

#[derive(Clone)]
pub struct Reconciler {
    ctx: Ctx,
    config: Config,
    state: Arc<Mutex<SchedulerState>>,
    tick_lock: Arc<tokio::sync::Mutex<()>>,
    runtime_environments: Arc<HashSet<String>>,
    diagnostics: Arc<Mutex<ReconcileDiagnostics>>,
    /// Optional multi-host tick fence (shared across reconcilers / processes).
    shared_fence: Option<Arc<dyn ReconcileTickFence>>,
}

impl Reconciler {
    pub fn new(ctx: Ctx, config: Config) -> Result<Self> {
        if config.initial_backoff.is_zero() {
            bail!("initial reconciler backoff must be greater than zero");
        }
        if config.max_backoff < config.initial_backoff {
            bail!("maximum reconciler backoff must not be smaller than the initial backoff");
        }
        if config.max_concurrency == 0 {
            bail!("reconciler maximum concurrency must be greater than zero");
        }
        if config.fence_ttl_ms <= 0 {
            bail!("reconciler fence TTL must be greater than zero");
        }
        if config.instance_id.trim().is_empty() {
            bail!("reconciler instance_id must not be empty");
        }
        Ok(Self {
            ctx,
            config,
            state: Arc::new(Mutex::new(SchedulerState::default())),
            tick_lock: Arc::new(tokio::sync::Mutex::new(())),
            runtime_environments: Arc::new(HashSet::new()),
            diagnostics: Arc::new(Mutex::new(ReconcileDiagnostics::default())),
            shared_fence: None,
        })
    }

    pub fn with_runtime_environments(mut self, environments: HashSet<String>) -> Self {
        self.runtime_environments = Arc::new(environments);
        self
    }

    /// Attach a multi-host tick fence (ADR 0009 / #129). Required for multi-process
    /// reconcile against shared operational state.
    pub fn with_shared_fence(mut self, fence: Arc<dyn ReconcileTickFence>) -> Self {
        self.shared_fence = Some(fence);
        self
    }

    pub fn diagnostics_snapshot(&self) -> ReconcileDiagnostics {
        self.diagnostics
            .lock()
            .expect("reconciler diagnostics lock")
            .clone()
    }

    pub fn ctx_clone(&self) -> Ctx {
        self.ctx.clone()
    }

    /// Reconcile every registered environment once. Environments run concurrently.
    pub async fn run_once(&self) -> Result<TickReport> {
        // Periodic and requested ticks share this lock so a successful request
        // always represents a complete tick rather than a transient Busy report.
        let _tick = self.tick_lock.lock().await;
        let mut listing = self.ctx.clone();
        let mut environments = listing.list_kind(KIND_ENVIRONMENT).await?;
        environments.sort_by(|left, right| left.name.cmp(&right.name));
        let permits = Arc::new(tokio::sync::Semaphore::new(self.config.max_concurrency));
        let mut jobs = tokio::task::JoinSet::new();
        let mut report = TickReport::default();

        for environment in environments {
            let name = environment.name;
            match self
                .state
                .lock()
                .expect("reconciler state lock")
                .begin(&name, crate::now_millis())
            {
                Admission::Busy => report.environments.push(EnvironmentResult {
                    environment: name,
                    status: EnvironmentStatus::Busy,
                }),
                Admission::Deferred(retry_at) => report.environments.push(EnvironmentResult {
                    environment: name,
                    status: EnvironmentStatus::Deferred { retry_at },
                }),
                Admission::Started => {
                    // Multi-host fence (optional): at most one live claim per environment.
                    let fence_guard = if let Some(fence) = &self.shared_fence {
                        let now = crate::now_millis();
                        match fence.try_begin(
                            &name,
                            &self.config.instance_id,
                            now,
                            self.config.fence_ttl_ms,
                        ) {
                            Ok(FenceAdmission::Started { generation }) => Some(FenceGuard::new(
                                Arc::clone(fence),
                                name.clone(),
                                self.config.instance_id.clone(),
                                generation,
                            )),
                            Ok(FenceAdmission::Busy { .. }) | Ok(FenceAdmission::Stale) => {
                                self.state.lock().expect("reconciler state lock").finish(
                                    &name,
                                    true, // not a local failure; clear in_flight
                                    crate::now_millis(),
                                    &self.config,
                                );
                                report.environments.push(EnvironmentResult {
                                    environment: name,
                                    status: EnvironmentStatus::Busy,
                                });
                                continue;
                            }
                            Err(error) => {
                                self.state.lock().expect("reconciler state lock").finish(
                                    &name,
                                    false,
                                    crate::now_millis(),
                                    &self.config,
                                );
                                report.environments.push(EnvironmentResult {
                                    environment: name,
                                    status: EnvironmentStatus::Failed {
                                        error: format!("reconcile fence: {error}"),
                                    },
                                });
                                continue;
                            }
                        }
                    } else {
                        None
                    };

                    let mut ctx = self.ctx.clone();
                    let config = self.config.clone();
                    let runtime_managed = self.runtime_environments.contains(&name);
                    let guard = AdmissionGuard {
                        environment: name.clone(),
                        state: Arc::clone(&self.state),
                        config: config.clone(),
                        completed: false,
                    };
                    let permits = Arc::clone(&permits);
                    jobs.spawn(async move {
                        let _permit = permits
                            .acquire_owned()
                            .await
                            .expect("semaphore remains open");
                        let _fence = fence_guard;
                        let result = reconcile_environment(
                            &mut ctx,
                            &name,
                            config.skip_gates,
                            runtime_managed,
                            config.unapproved_development_reason.as_deref(),
                            config.approval_directory.as_deref(),
                            config.approval_trust_roots.as_deref(),
                        )
                        .await;
                        guard.finish(result.is_ok());
                        (name, result)
                    });
                }
            }
        }

        while let Some(job) = jobs.join_next().await {
            let (environment, status) = match job {
                Ok((environment, Ok(status))) => (environment, status),
                Ok((environment, Err(error))) => (
                    environment,
                    EnvironmentStatus::Failed {
                        error: format!("{error:#}"),
                    },
                ),
                Err(error) => (
                    "unknown".into(),
                    EnvironmentStatus::Failed {
                        error: format!("reconciler environment task failed: {error}"),
                    },
                ),
            };
            report.environments.push(EnvironmentResult {
                environment,
                status,
            });
        }
        report
            .environments
            .sort_by(|left, right| left.environment.cmp(&right.environment));
        self.diagnostics
            .lock()
            .expect("reconciler diagnostics lock")
            .record_tick(&report);
        Ok(report)
    }

    /// Return the oldest executable plan visible to this environment in the
    /// current operational authority. The server enforces environment scope
    /// before calling this application operation.
    ///
    /// Plan work selection is **environment-scoped** (property-indexed query),
    /// not a full plan catalog scan.
    pub async fn pending_work(&self, environment: &str) -> Result<Option<plan::Plan>> {
        let mut ctx = self.ctx.clone();
        plan::oldest_for_environment(
            &mut ctx,
            environment,
            &[PlanState::Computed, PlanState::Running],
        )
        .await
    }

    pub async fn check_provider_health(&self) -> Result<()> {
        let mut ctx = self.ctx.clone();
        let _ = ctx.get("tenkai:server:health-probe").await?;
        Ok(())
    }

    pub async fn complete_runtime_work(
        &self,
        environment: &str,
        completion: &RuntimeCompletion,
    ) -> Result<()> {
        self.validate_runtime_completion(environment, completion)
            .await?;
        let mut ctx = self.ctx.clone();
        let mut stored = plan::load(&mut ctx, &completion.plan_id).await?;
        let terminal = if completion.succeeded {
            PlanState::Succeeded
        } else {
            PlanState::Failed
        };
        if matches!(stored.state, PlanState::Succeeded | PlanState::Failed) {
            return Ok(());
        }
        if stored.state == PlanState::Computed {
            stored.state = PlanState::Running;
            stored.status_detail = "claimed by assigned environment runtime".into();
            plan::store(&mut ctx, &stored).await?;
        }
        if completion.succeeded {
            for step in &stored.steps {
                plan::reconcile_deployment(&mut ctx, environment, &step.product, Some(&step.to))
                    .await?;
            }
        }
        stored.state = terminal;
        stored.status_detail = completion.detail.clone();
        plan::store(&mut ctx, &stored).await?;
        Ok(())
    }

    pub async fn validate_runtime_completion(
        &self,
        environment: &str,
        completion: &RuntimeCompletion,
    ) -> Result<()> {
        let mut ctx = self.ctx.clone();
        let stored = plan::load(&mut ctx, &completion.plan_id).await?;
        if stored.environment != environment {
            bail!(
                "plan {} belongs to {}, not {environment}",
                completion.plan_id,
                stored.environment
            );
        }
        let expected = stored
            .steps
            .iter()
            .map(|step| step.id.as_str())
            .collect::<HashSet<_>>();
        let received = completion
            .receipts
            .iter()
            .map(|receipt| receipt.step_id.as_str())
            .collect::<HashSet<_>>();
        if expected != received || received.len() != completion.receipts.len() {
            bail!("runtime completion receipts must cover every plan step exactly once");
        }
        if completion.succeeded && completion.receipts.iter().any(|receipt| !receipt.succeeded) {
            bail!("a successful runtime completion cannot contain a failed step receipt");
        }
        let terminal = if completion.succeeded {
            PlanState::Succeeded
        } else {
            PlanState::Failed
        };
        if matches!(stored.state, PlanState::Succeeded | PlanState::Failed) {
            anyhow::ensure!(
                stored.state == terminal,
                "runtime completion conflicts with terminal plan state"
            );
            return Ok(());
        }
        anyhow::ensure!(
            matches!(stored.state, PlanState::Computed | PlanState::Running),
            "runtime plan is not executable"
        );
        Ok(())
    }

    /// Run complete ticks until Ctrl-C. A slow tick never overlaps its successor.
    pub async fn run_until<H>(&self, interval: Duration, mut handle_report: H) -> Result<()>
    where
        H: FnMut(Result<TickReport>),
    {
        if interval.is_zero() {
            bail!("reconciler interval must be greater than zero");
        }
        let mut timer = tokio::time::interval(interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = timer.tick() => handle_report(self.run_once().await),
                signal = tokio::signal::ctrl_c() => {
                    signal.context("installing reconciler shutdown handler")?;
                    return Ok(());
                }
            }
        }
    }
}

async fn reconcile_environment(
    ctx: &mut Ctx,
    environment: &str,
    skip_gates: bool,
    runtime_managed: bool,
    unapproved_development_reason: Option<&str>,
    approval_directory: Option<&std::path::Path>,
    approval_trust_roots: Option<&std::path::Path>,
) -> Result<EnvironmentStatus> {
    if runtime_managed {
        // Environment-scoped plan query (not a full-kind scan).
        if let Some(plan) = plan::oldest_for_environment(
            ctx,
            environment,
            &[PlanState::Computed, PlanState::Running],
        )
        .await?
        {
            return Ok(EnvironmentStatus::AwaitingRuntime {
                plan_id: plan.id,
                steps: plan.steps.len(),
            });
        }
        let stored = plan::create(ctx, environment).await?;
        if stored.steps.is_empty() {
            return Ok(EnvironmentStatus::Current);
        }
        return Ok(EnvironmentStatus::AwaitingRuntime {
            plan_id: stored.id,
            steps: stored.steps.len(),
        });
    }
    if recover_or_detect_active_plan(ctx, environment).await? {
        return Ok(EnvironmentStatus::Busy);
    }
    let approval_required =
        unapproved_development_reason.is_none() || environment != "local" || !ctx.is_embedded();
    let stored = if approval_required {
        // Environment-scoped plan query (not a full-kind scan).
        let mut computed = Vec::new();
        for candidate in
            plan::list_for_environment(ctx, environment, Some(&[PlanState::Computed])).await?
        {
            if !candidate.steps.is_empty()
                && apply::validate_preconditions(ctx, &candidate).await.is_ok()
            {
                computed.push(candidate);
            }
        }
        // list_for_environment already orders by created_at ascending.
        match computed.into_iter().next() {
            Some(stored) => stored,
            None => plan::create(ctx, environment).await?,
        }
    } else {
        plan::create(ctx, environment).await?
    };
    if stored.steps.is_empty() {
        return Ok(EnvironmentStatus::Current);
    }
    let plan_id = stored.id;
    let steps = stored.steps.len();
    if approval_required {
        let (Some(directory), Some(roots)) = (approval_directory, approval_trust_roots) else {
            return Ok(EnvironmentStatus::AwaitingApproval { plan_id, steps });
        };
        let envelope = directory.join(format!("{plan_id}.json"));
        if !envelope.is_file() {
            return Ok(EnvironmentStatus::AwaitingApproval { plan_id, steps });
        }
        let outcomes = apply::execute_with_options(
            ctx,
            &plan_id,
            apply::ExecutionOptions {
                skip_gates,
                emergency_reason: None,
                approval: Some(&envelope),
                approval_trust_roots: Some(roots),
                unapproved_development_reason: None,
            },
        )
        .await?;
        if let Some(failed) = outcomes
            .iter()
            .find(|outcome| outcome.status != "succeeded")
        {
            bail!(
                "environment {environment} failed while reconciling {}: {}",
                failed.step.product,
                failed.detail
            );
        }
        return Ok(EnvironmentStatus::Applied { plan_id, steps });
    }
    let reason = unapproved_development_reason
        .expect("authorization was classified as an embedded local-development bypass");
    let outcomes = apply::execute_with_options(
        ctx,
        &plan_id,
        apply::ExecutionOptions {
            skip_gates,
            emergency_reason: None,
            approval: None,
            approval_trust_roots: None,
            unapproved_development_reason: Some(reason),
        },
    )
    .await?;
    if let Some(failed) = outcomes
        .iter()
        .find(|outcome| outcome.status != "succeeded")
    {
        bail!(
            "environment {environment} failed while reconciling {}: {}",
            failed.step.product,
            failed.detail
        );
    }
    Ok(EnvironmentStatus::Applied { plan_id, steps })
}

/// Deterministically terminate plans orphaned by a stopped controller. An active
/// generation-fenced lease proves another process still owns the environment.
async fn recover_or_detect_active_plan(ctx: &mut Ctx, environment: &str) -> Result<bool> {
    // Environment-scoped plan query (not a full-kind scan).
    let running = plan::list_for_environment(ctx, environment, Some(&[PlanState::Running])).await?;
    if running.is_empty() {
        return Ok(false);
    }
    if apply::environment_lease_status(ctx, environment)
        .await?
        .is_some()
    {
        return Ok(true);
    }
    for mut abandoned in running {
        abandoned.state = PlanState::Failed;
        abandoned.status_detail =
            "controller stopped after execution began; lease expired before recovery".into();
        plan::store(ctx, &abandoned).await?;
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::plan::{self, Plan, PlanState};

    fn config() -> Config {
        Config {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(250),
            max_concurrency: 2,
            skip_gates: false,
            unapproved_development_reason: Some("reconciler test".into()),
            approval_directory: None,
            approval_trust_roots: None,
            fence_ttl_ms: 30_000,
            instance_id: "reconciler-test".into(),
        }
    }

    fn test_plan(env: &str, created_at: i64, state: PlanState) -> Plan {
        use crate::ontology::plan_id;
        use crate::plan::{Action, DesiredStateInput, PLAN_FORMAT_VERSION, ReleasePin, Step};
        use sha2::{Digest as _, Sha256};

        let inputs = vec![DesiredStateInput {
            product: "api".into(),
            channel: "stable".into(),
            channel_id: "tenkai:channel:api/stable".into(),
            desired_version: "2.0.0".into(),
            release_id: "tenkai:release:api@2.0.0".into(),
            release_digest: "target-digest".into(),
            artifact_digest: "target-artifact-digest".into(),
            deployed_version: Some("1.0.0".into()),
        }];
        let mut steps = vec![Step {
            id: String::new(),
            order: 0,
            product: "api".into(),
            action: Action::Upgrade,
            from: Some("1.0.0".into()),
            to: "2.0.0".into(),
            release_id: "tenkai:release:api@2.0.0".into(),
            release_digest: "target-digest".into(),
            artifact_digest: "target-artifact-digest".into(),
            workdir: "/srv/api".into(),
            restore: Some(ReleasePin {
                release_id: "tenkai:release:api@1.0.0".into(),
                digest: "restore-digest".into(),
                artifact_digest: "restore-artifact-digest".into(),
                workdir: "/srv/api".into(),
            }),
        }];
        let mut normalized = steps.clone();
        for step in &mut normalized {
            step.id.clear();
        }
        let content_id = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(PLAN_FORMAT_VERSION, env, created_at, &inputs, &normalized))
                    .unwrap()
            )
        );
        let id = plan_id(env, created_at, &content_id);
        steps[0].id = format!("{id}:step:0");
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            id,
            content_id,
            environment: env.into(),
            created_at,
            inputs,
            steps,
            state,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
        }
    }

    #[tokio::test]
    async fn pending_work_selects_oldest_env_plan_only() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-pending-work-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        let env_a_old = test_plan("env_a", 100, PlanState::Computed);
        let env_a_new = test_plan("env_a", 300, PlanState::Running);
        let env_b = test_plan("env_b", 50, PlanState::Computed);
        for plan in [&env_a_old, &env_a_new, &env_b] {
            plan::store(&mut ctx, plan).await.unwrap();
        }
        for i in 0..30 {
            let noise = test_plan(&format!("other-{i}"), 1_000 + i, PlanState::Computed);
            plan::store(&mut ctx, &noise).await.unwrap();
        }

        let reconciler = Reconciler::new(ctx.clone(), config()).unwrap();
        let selected = reconciler.pending_work("env_a").await.unwrap().unwrap();
        assert_eq!(selected.id, env_a_old.id);
        assert_eq!(selected.environment, "env_a");

        let other = reconciler.pending_work("env_b").await.unwrap().unwrap();
        assert_eq!(other.id, env_b.id);
        assert_ne!(other.id, env_a_old.id);

        assert!(
            reconciler
                .pending_work("env_missing")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            reconciler
                .pending_work("")
                .await
                .unwrap_err()
                .to_string()
                .contains("required")
        );
        let _ = std::fs::remove_file(&database);
    }

    #[test]
    fn shared_fence_serializes_two_hosts_on_same_environment() {
        use crate::reconcile_fence::SharedReconcileFence;

        let fence = SharedReconcileFence::new().into_arc();
        let host_a = fence.try_begin("prod", "host-a", 1_000, 10_000).unwrap();
        let host_b = fence.try_begin("prod", "host-b", 1_100, 10_000).unwrap();
        assert!(matches!(
            host_a,
            crate::reconcile_fence::FenceAdmission::Started { generation: 1 }
        ));
        assert!(matches!(
            host_b,
            crate::reconcile_fence::FenceAdmission::Busy { .. }
        ));
        fence.release("prod", "host-a", 1, 1_200).unwrap();
        let host_b_again = fence.try_begin("prod", "host-b", 1_300, 10_000).unwrap();
        assert!(matches!(
            host_b_again,
            crate::reconcile_fence::FenceAdmission::Started { generation: 1 }
        ));
    }

    #[test]
    fn concurrent_ticks_serialize_an_environment() {
        let mut state = SchedulerState::default();
        assert!(matches!(state.begin("prod", 1_000), Admission::Started));
        assert!(matches!(state.begin("prod", 1_000), Admission::Busy));
        assert!(matches!(state.begin("staging", 1_000), Admission::Started));
    }

    #[test]
    fn failures_back_off_independently_and_success_resets() {
        let mut state = SchedulerState::default();
        let config = config();
        assert!(matches!(state.begin("prod", 1_000), Admission::Started));
        state.finish("prod", false, 1_000, &config);
        assert!(matches!(
            state.begin("prod", 1_099),
            Admission::Deferred(1_100)
        ));
        assert!(matches!(state.begin("staging", 1_099), Admission::Started));
        assert!(matches!(state.begin("prod", 1_100), Admission::Started));
        state.finish("prod", true, 1_100, &config);
        assert!(matches!(state.begin("prod", 1_100), Admission::Started));
    }

    #[test]
    fn retry_delay_is_capped() {
        let mut state = SchedulerState::default();
        let config = config();
        for now in [0, 100, 300, 550] {
            assert!(matches!(state.begin("prod", now), Admission::Started));
            state.finish("prod", false, now, &config);
        }
        assert!(matches!(state.begin("prod", 799), Admission::Deferred(800)));
    }

    #[test]
    fn tick_diagnostics_report_ok_without_secrets() {
        let report = TickReport {
            environments: vec![
                EnvironmentResult {
                    environment: "alpha".into(),
                    status: EnvironmentStatus::Current,
                },
                EnvironmentResult {
                    environment: "beta".into(),
                    status: EnvironmentStatus::Applied {
                        plan_id: "plan-1".into(),
                        steps: 1,
                    },
                },
            ],
        };
        let diag = report.diagnostics();
        assert_eq!(diag.outcome, "ok");
        assert_eq!(diag.environments_total, 2);
        assert_eq!(diag.environments_failed, 0);
        let encoded = serde_json::to_string(&diag).unwrap();
        assert!(!encoded.contains("Bearer"));
        assert!(!encoded.contains("secret"));

        let mut cumulative = ReconcileDiagnostics::default();
        cumulative.record_tick(&report);
        assert_eq!(cumulative.ticks_total, 1);
        assert_eq!(cumulative.ticks_failed, 0);
        assert_eq!(cumulative.last_outcome, "ok");
    }

    #[test]
    fn failed_environment_marks_tick_degraded() {
        let report = TickReport {
            environments: vec![EnvironmentResult {
                environment: "prod".into(),
                status: EnvironmentStatus::Failed {
                    error: "boom".into(),
                },
            }],
        };
        assert_eq!(report.diagnostics().outcome, "degraded");
        let mut cumulative = ReconcileDiagnostics::default();
        cumulative.record_tick(&report);
        assert_eq!(cumulative.ticks_failed, 1);
        assert_eq!(cumulative.last_outcome, "degraded");
    }
}
