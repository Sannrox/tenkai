//! Concurrent, retrying convergence of registered environments.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::plan::{self, PlanState};
use crate::reconcile_fence::ReconcileTickFence;

mod environment_lifecycle;
mod tick_admission;

use tick_admission::{EnvironmentIndex, SchedulerState};

// Preserve the public protocol path while runtime delivery owns the types.
pub use crate::runtime_delivery::{RuntimeCompletion, RuntimeStepReceipt};

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

#[derive(Clone)]
pub struct Reconciler {
    ctx: Ctx,
    config: Config,
    state: Arc<Mutex<SchedulerState>>,
    environment_index: Arc<Mutex<EnvironmentIndex>>,
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
            environment_index: Arc::new(Mutex::new(EnvironmentIndex::default())),
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

    pub(crate) async fn inspect_environment_without_outcome_export(
        &self,
        environment: String,
    ) -> Result<crate::plan::EnvironmentInspectReport> {
        let mut ctx = self.ctx.without_outcome_export();
        crate::plan::inspect_environment_with_outcomes(&mut ctx, &environment).await
    }

    pub(crate) async fn fleet_status_without_outcome_export(
        &self,
    ) -> Result<crate::plan::FleetStatusReport> {
        let mut ctx = self.ctx.without_outcome_export();
        crate::plan::fleet_status(&mut ctx).await
    }

    /// Reconcile every registered environment once. Environments run concurrently.
    pub async fn run_once(&self) -> Result<TickReport> {
        self.run_once_bounded(None).await
    }

    /// Reconcile only the registered environments admitted by the caller's
    /// already-verified authority boundary.
    pub async fn run_once_for(&self, allowed_environments: &[String]) -> Result<TickReport> {
        self.run_once_bounded(Some(allowed_environments.iter().cloned().collect()))
            .await
    }

    async fn run_once_bounded(
        &self,
        allowed_environments: Option<HashSet<String>>,
    ) -> Result<TickReport> {
        tick_admission::run(tick_admission::TickRequest {
            ctx: self.ctx.clone(),
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            environment_index: Arc::clone(&self.environment_index),
            tick_lock: self.tick_lock.as_ref(),
            runtime_environments: Arc::clone(&self.runtime_environments),
            diagnostics: Arc::clone(&self.diagnostics),
            shared_fence: self.shared_fence.clone(),
            allowed_environments,
        })
        .await
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

    /// Compatibility shim; runtime delivery owns completion validation.
    #[deprecated(note = "use the runtime_delivery interface")]
    pub async fn validate_runtime_completion(
        &self,
        environment: &str,
        completion: &RuntimeCompletion,
    ) -> Result<()> {
        let mut ctx = self.ctx.clone();
        crate::runtime_delivery::validate_runtime_completion(&mut ctx, environment, completion)
            .await
    }

    /// Compatibility shim; runtime delivery owns durable completion effects.
    #[deprecated(note = "use the runtime_delivery interface")]
    pub async fn complete_runtime_work(
        &self,
        environment: &str,
        completion: &RuntimeCompletion,
    ) -> Result<()> {
        let mut ctx = self.ctx.clone();
        crate::runtime_delivery::complete_runtime_work(&mut ctx, environment, completion).await
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

#[cfg(test)]
mod tests {
    use super::tick_admission::Admission;
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

    fn temp_ctx(label: &str) -> (std::path::PathBuf, Ctx) {
        let database = std::env::temp_dir().join(format!(
            "tenkai-{label}-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        (database.clone(), Ctx::embedded(&database).unwrap())
    }

    async fn registered_ctx(label: &str, environments: &[&str]) -> (std::path::PathBuf, Ctx) {
        let (database, mut ctx) = temp_ctx(label);
        crate::ontology::register(&mut ctx).await.unwrap();
        for name in environments {
            plan::env_add(&mut ctx, name, *name).await.unwrap();
        }
        (database, ctx)
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

    #[tokio::test]
    async fn bounded_tick_excludes_foreign_work_before_reconcile() {
        let (database, ctx) = registered_ctx("bounded-reconcile", &["env-a", "env-b"]).await;

        let reconciler = Reconciler::new(ctx, config()).unwrap();
        let report = reconciler
            .run_once_for(&["env-a".into(), "unknown".into()])
            .await
            .unwrap();

        assert_eq!(report.environments.len(), 1);
        assert_eq!(report.environments[0].environment, "env-a");
        assert_eq!(report.environments[0].status, EnvironmentStatus::Current);
        assert!(
            !serde_json::to_string(&report).unwrap().contains("env-b"),
            "foreign environment must be excluded before reconcile admission"
        );
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn unbounded_tick_does_not_list_kind_when_membership_is_unchanged() {
        let names: Vec<String> = (0..8).map(|i| format!("env-{i}")).collect();
        let env_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let (database, ctx) = registered_ctx("tick-env-index", &env_refs).await;
        let reconciler = Reconciler::new(ctx, config()).unwrap();

        let (reports, log) = super::tick_admission::admission_io::capture(|| async {
            let first = reconciler.run_once().await.unwrap();
            let second = reconciler.run_once().await.unwrap();
            (first, second)
        })
        .await;
        let (first, second) = reports;

        assert_eq!(first.environments.len(), 8);
        assert_eq!(second.environments.len(), 8);
        assert_eq!(
            first
                .environments
                .iter()
                .map(|row| row.environment.as_str())
                .collect::<Vec<_>>(),
            names.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(log.list_kinds, vec![crate::ontology::KIND_ENVIRONMENT]);
        assert_eq!(log.list_kind_ids, vec![crate::ontology::KIND_ENVIRONMENT]);
        assert!(
            log.gets.is_empty(),
            "unchanged membership must not get environment objects: {:?}",
            log.gets
        );
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn bounded_tick_gets_only_allowed_environment_names() {
        let (database, ctx) =
            registered_ctx("bounded-env-gets", &["env-a", "env-b", "env-c"]).await;
        let reconciler = Reconciler::new(ctx, config()).unwrap();

        let (report, log) = super::tick_admission::admission_io::capture(|| async {
            reconciler
                .run_once_for(&["env-a".into(), "unknown".into()])
                .await
                .unwrap()
        })
        .await;

        assert_eq!(report.environments.len(), 1);
        assert_eq!(report.environments[0].environment, "env-a");
        assert!(
            log.list_kinds.is_empty(),
            "bounded tick listed the fleet: {:?}",
            log.list_kinds
        );
        assert!(
            log.list_kind_ids.is_empty(),
            "bounded tick listed fleet ids: {:?}",
            log.list_kind_ids
        );
        let mut gets = log.gets;
        gets.sort();
        assert_eq!(
            gets,
            vec![
                crate::ontology::env_id("env-a"),
                crate::ontology::env_id("unknown"),
            ]
        );
        assert!(
            !gets.iter().any(|id| id == &crate::ontology::env_id("env-b")
                || id == &crate::ontology::env_id("env-c")),
            "bounded tick must not get unmentioned environments"
        );
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn unbounded_tick_gets_only_environments_that_appeared() {
        let (database, mut ctx) = registered_ctx("tick-env-appear", &["env-a", "env-b"]).await;
        let reconciler = Reconciler::new(ctx.clone(), config()).unwrap();

        let (reports, log) = super::tick_admission::admission_io::capture(|| async {
            let first = reconciler.run_once().await.unwrap();
            plan::env_add(&mut ctx, "env-c", "env-c").await.unwrap();
            let second = reconciler.run_once().await.unwrap();
            (first, second)
        })
        .await;
        let (first, second) = reports;

        assert_eq!(
            first
                .environments
                .iter()
                .map(|row| row.environment.as_str())
                .collect::<Vec<_>>(),
            ["env-a", "env-b"]
        );
        assert_eq!(
            second
                .environments
                .iter()
                .map(|row| row.environment.as_str())
                .collect::<Vec<_>>(),
            ["env-a", "env-b", "env-c"]
        );
        assert_eq!(log.list_kinds.len(), 1);
        assert_eq!(log.list_kind_ids.len(), 1);
        assert_eq!(log.gets, vec![crate::ontology::env_id("env-c")]);
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn unbounded_tick_drops_disappeared_environments_without_getting_them() {
        let (database, mut ctx) = registered_ctx("tick-env-disappear", &["env-a", "env-b"]).await;
        let reconciler = Reconciler::new(ctx.clone(), config()).unwrap();

        let (reports, log) = super::tick_admission::admission_io::capture(|| async {
            let first = reconciler.run_once().await.unwrap();
            ctx.delete(&crate::ontology::env_id("env-b")).await.unwrap();
            let second = reconciler.run_once().await.unwrap();
            (first, second)
        })
        .await;
        let (first, second) = reports;

        assert_eq!(first.environments.len(), 2);
        assert_eq!(
            second
                .environments
                .iter()
                .map(|row| row.environment.as_str())
                .collect::<Vec<_>>(),
            ["env-a"]
        );
        assert_eq!(log.list_kinds.len(), 1);
        assert_eq!(log.list_kind_ids.len(), 1);
        assert!(
            log.gets.is_empty(),
            "disappeared environments are dropped from the index without get: {:?}",
            log.gets
        );
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn fence_busy_still_admits_without_listing_unmentioned_environments() {
        use crate::reconcile_fence::SharedReconcileFence;

        let (database, ctx) = registered_ctx("tick-fence-busy", &["env-a", "env-b"]).await;
        let fence = SharedReconcileFence::new().into_arc();
        let now = crate::now_millis();
        fence.try_begin("env-a", "other-host", now, 30_000).unwrap();
        let reconciler = Reconciler::new(ctx, config())
            .unwrap()
            .with_shared_fence(fence);

        let (report, log) = super::tick_admission::admission_io::capture(|| async {
            reconciler.run_once_for(&["env-a".into()]).await.unwrap()
        })
        .await;

        assert_eq!(report.environments.len(), 1);
        assert_eq!(report.environments[0].environment, "env-a");
        assert_eq!(report.environments[0].status, EnvironmentStatus::Busy);
        assert!(log.list_kinds.is_empty());
        assert_eq!(log.gets, vec![crate::ontology::env_id("env-a")]);
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
            crate::reconcile_fence::FenceAdmission::Started { generation: 2 }
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
