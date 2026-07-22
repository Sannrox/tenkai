//! Concurrent, retrying convergence of registered environments.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::apply;
use crate::client::Ctx;
use crate::ontology::{KIND_ENVIRONMENT, KIND_PLAN};
use crate::plan::{self, PlanState};

#[derive(Debug, Clone)]
pub struct Config {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_concurrency: usize,
    pub skip_gates: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(5 * 60),
            max_concurrency: 8,
            skip_gates: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum EnvironmentStatus {
    Current,
    Applied { plan_id: String, steps: usize },
    AwaitingRuntime { plan_id: String, steps: usize },
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
        Ok(Self {
            ctx,
            config,
            state: Arc::new(Mutex::new(SchedulerState::default())),
            tick_lock: Arc::new(tokio::sync::Mutex::new(())),
            runtime_environments: Arc::new(HashSet::new()),
        })
    }

    pub fn with_runtime_environments(mut self, environments: HashSet<String>) -> Self {
        self.runtime_environments = Arc::new(environments);
        self
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
                        let result = reconcile_environment(
                            &mut ctx,
                            &name,
                            config.skip_gates,
                            runtime_managed,
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
        Ok(report)
    }

    /// Return the oldest executable plan visible to this environment in the
    /// current operational authority. The server enforces environment scope
    /// before calling this application operation.
    pub async fn pending_work(&self, environment: &str) -> Result<Option<plan::Plan>> {
        let mut ctx = self.ctx.clone();
        let mut candidates = Vec::new();
        for object in ctx.list_kind(KIND_PLAN).await? {
            if object
                .properties
                .get("environment")
                .is_some_and(|value| value == environment)
                && object
                    .properties
                    .get("status")
                    .is_some_and(|value| value == "computed" || value == "running")
            {
                candidates.push(plan::load(&mut ctx, &object.id).await?);
            }
        }
        candidates.sort_by_key(|candidate| candidate.created_at);
        Ok(candidates.into_iter().next())
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
) -> Result<EnvironmentStatus> {
    if runtime_managed {
        let mut computed = Vec::new();
        for object in ctx.list_kind(KIND_PLAN).await? {
            if object
                .properties
                .get("environment")
                .is_some_and(|value| value == environment)
                && object
                    .properties
                    .get("status")
                    .is_some_and(|value| value == "computed" || value == "running")
            {
                computed.push(plan::load(ctx, &object.id).await?);
            }
        }
        computed.sort_by_key(|candidate| candidate.created_at);
        if let Some(plan) = computed.into_iter().next() {
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
    let stored = plan::create(ctx, environment).await?;
    if stored.steps.is_empty() {
        return Ok(EnvironmentStatus::Current);
    }
    let plan_id = stored.id;
    let steps = stored.steps.len();
    let outcomes = apply::execute(ctx, &plan_id, skip_gates).await?;
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
    let plans = ctx.list_kind(KIND_PLAN).await?;
    let mut running = Vec::new();
    for object in plans {
        if object
            .properties
            .get("environment")
            .is_some_and(|value| value == environment)
            && object
                .properties
                .get("status")
                .is_some_and(|value| value == "running")
        {
            running.push(plan::load(ctx, &object.id).await?);
        }
    }
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

    fn config() -> Config {
        Config {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(250),
            max_concurrency: 2,
            skip_gates: false,
        }
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
}
