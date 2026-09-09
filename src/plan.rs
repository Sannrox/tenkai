//! Environments, subscriptions, and plan computation (desired vs deployed).

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::*;
use crate::pb::sekai::Object;

mod convergence;
mod lifecycle;
mod release_selection;

pub use release_selection::model_requirements_fit;
pub(crate) use release_selection::resolve_subscription_selection;

pub(crate) use crate::environment::update_runtime_deployments_object;
pub use crate::environment::{
    ENVIRONMENT_FACT_KEYS, EnvironmentInspectReport, EnvironmentListEntry,
    EnvironmentPlanStepSummary, EnvironmentPlanSummary, EnvironmentSubscriptionView, StatusRow,
    apply_runtime_inventory_facts, clear_environment_constraint, clear_environment_fact,
    clear_environment_overlay, env_add, fleet_status, inspect_environment,
    inspect_environment_with_outcomes, list_environment_constraints, list_environment_facts,
    list_environment_overlays, list_environments, overlay_digest, product_overlays,
    reconcile_deployment, require_environment_fact, set_environment_constraint,
    set_environment_fact, set_environment_overlay, status, subscribe, subscription_state,
};

pub use crate::fleet::{
    FleetDriftSummary, FleetEnvironmentRow, FleetPostureSnapshot, FleetStatusReport,
    compare_fleet_posture, fleet_posture_snapshot, fleet_status_from_inspects,
    fleet_status_from_rows, is_hard_drift_posture, load_fleet_posture_baseline,
    write_fleet_posture_baseline,
};
pub use crate::workshop_module::set_observed_compatibility;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Install,
    Upgrade,
    Downgrade,
    Rollback,
    Restart,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Action::Install => "install",
            Action::Upgrade => "upgrade",
            Action::Downgrade => "downgrade",
            Action::Rollback => "rollback",
            Action::Restart => "restart",
        };
        f.write_str(s)
    }
}

pub const PLAN_FORMAT_VERSION: u32 = 1;

/// Operator-facing detail for a zero-step Succeeded plan. Inspect uses this
/// instead of treating empty success as applied delivery.
pub const NO_OP_STATUS_DETAIL: &str = "no-op; environment already current";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub id: String,
    pub order: u32,
    pub product: String,
    pub action: Action,
    pub from: Option<String>,
    pub to: String,
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub workdir: String,
    pub restore: Option<ReleasePin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePin {
    pub release_id: String,
    pub digest: String,
    pub artifact_digest: String,
    pub workdir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredStateInput {
    pub product: String,
    pub channel: String,
    pub channel_id: String,
    pub desired_version: String,
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub deployed_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanState {
    Computed,
    Running,
    Blocked,
    Succeeded,
    Failed,
}

impl std::fmt::Display for PlanState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Computed => "computed",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub format_version: u32,
    pub id: String,
    pub content_id: String,
    pub environment: String,
    pub created_at: i64,
    pub inputs: Vec<DesiredStateInput>,
    pub steps: Vec<Step>,
    pub state: PlanState,
    pub gates_skipped: Option<bool>,
    pub status_detail: String,
    #[serde(default)]
    pub maintenance_blocked: bool,
    /// Advisory prior warnings (optional planner intelligence). Never hard-blocks.
    #[serde(default)]
    pub prior_warnings: Vec<String>,
    /// Audited reason that admits rollback onto recalled Catalog content.
    #[serde(default)]
    pub recalled_recovery_reason: Option<String>,
}

#[derive(Serialize)]
struct ExecutableContent<'a> {
    format_version: u32,
    id: &'a str,
    content_id: &'a str,
    environment: &'a str,
    created_at: i64,
    inputs: &'a [DesiredStateInput],
    steps: &'a [Step],
    #[serde(skip_serializing_if = "Option::is_none")]
    recalled_recovery_reason: Option<&'a str>,
}

fn content_address(
    environment: &str,
    created_at: i64,
    inputs: &[DesiredStateInput],
    steps: &[Step],
    recalled_recovery_reason: Option<&str>,
) -> Result<String> {
    let mut normalized_steps = steps.to_vec();
    for step in &mut normalized_steps {
        step.id.clear();
    }
    let bytes = if let Some(reason) = recalled_recovery_reason.filter(|value| !value.is_empty()) {
        serde_json::to_vec(&(
            PLAN_FORMAT_VERSION,
            environment,
            created_at,
            inputs,
            normalized_steps,
            reason,
        ))?
    } else {
        serde_json::to_vec(&(
            PLAN_FORMAT_VERSION,
            environment,
            created_at,
            inputs,
            normalized_steps,
        ))?
    };
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl Plan {
    pub fn executable_digest(&self) -> Result<String> {
        let content = ExecutableContent {
            format_version: self.format_version,
            id: &self.id,
            content_id: &self.content_id,
            environment: &self.environment,
            created_at: self.created_at,
            inputs: &self.inputs,
            steps: &self.steps,
            recalled_recovery_reason: self.recalled_recovery_reason.as_deref(),
        };
        let bytes = serde_json::to_vec(&content)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub(crate) fn to_object(&self) -> Result<Object> {
        lifecycle::to_object(self)
    }
}

pub async fn store(ctx: &mut Ctx, plan: &Plan) -> Result<()> {
    lifecycle::store(ctx, plan).await
}

pub async fn load(ctx: &mut Ctx, id: &str) -> Result<Plan> {
    lifecycle::load(ctx, id).await
}

/// Load plans for one environment without scanning the full plan kind set.
///
/// Uses the store property index (`environment`, optional `status`, ordered by
/// `created_at`). Empty environment ids fail closed rather than falling back to
/// an unscoped list. When `statuses` is `Some`, only matching lifecycle states
/// are returned. Results are ordered by `created_at` ascending (oldest first),
/// matching reconcile work selection.
pub async fn list_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: Option<&[PlanState]>,
) -> Result<Vec<Plan>> {
    lifecycle::list_for_environment(ctx, environment, statuses).await
}

/// Oldest plan with steps for `environment` whose status is in `statuses`.
///
/// Zero-step plans are excluded by the `has_steps` index, not by decoding
/// every matching payload.
pub async fn oldest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Option<Plan>> {
    lifecycle::oldest_for_environment(ctx, environment, statuses).await
}

/// Plans with steps for `environment` whose status is in `statuses`.
///
/// Zero-step plans are excluded by the `has_steps` index, not by decoding
/// every matching payload. Ordered oldest `created_at` first.
#[cfg(test)]
pub(crate) async fn executable_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Vec<Plan>> {
    lifecycle::executable_for_environment(ctx, environment, statuses).await
}

pub(crate) const EXECUTABLE_ADMISSION_BATCH: u32 = 8;

pub(crate) async fn executable_batch_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
    limit: u32,
    offset: u32,
) -> Result<Vec<Plan>> {
    lifecycle::executable_batch_for_environment(ctx, environment, statuses, limit, offset).await
}

/// Newest stored plan for `environment`, if any.
///
/// Checks every matching `created_at` index against a payload peek so a
/// depressed newest index cannot hide behind `LIMIT 1`. Full Plan decode
/// runs only for the newest validated row.
pub async fn latest_for_environment(ctx: &mut Ctx, environment: &str) -> Result<Option<Plan>> {
    lifecycle::latest_for_environment(ctx, environment).await
}

pub(crate) async fn require_environment_indexes_match_payloads(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<()> {
    lifecycle::require_environment_indexes_match_payloads(ctx, environment).await
}

pub(crate) async fn retire_empty_executable_plans(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<usize> {
    lifecycle::retire_empty_executable_plans(ctx, environment).await
}

pub(crate) use lifecycle::{Persistence, Transition};

pub(crate) async fn transition(
    ctx: &mut Ctx,
    plan: &mut Plan,
    update: Transition,
    persistence: Persistence<'_>,
) -> Result<()> {
    lifecycle::transition(ctx, plan, update, persistence).await
}

pub async fn compute(ctx: &mut Ctx, env: &str) -> Result<Vec<Step>> {
    convergence::compute(ctx, env).await
}

pub async fn create(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    convergence::create(ctx, env).await
}

pub async fn create_from_steps(ctx: &mut Ctx, env: &str, steps: Vec<Step>) -> Result<Plan> {
    convergence::create_from_steps(ctx, env, steps).await
}

pub async fn create_from_steps_with_recovery(
    ctx: &mut Ctx,
    env: &str,
    steps: Vec<Step>,
    reason: String,
) -> Result<Plan> {
    convergence::create_from_steps_with_recovery(ctx, env, steps, reason).await
}

pub async fn rollback_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    convergence::rollback_step(ctx, env, product).await
}

pub async fn rollback_step_with_recovery(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    recovery: Option<&str>,
) -> Result<Step> {
    convergence::rollback_step_with_recovery(ctx, env, product, recovery).await
}

pub async fn restart_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    convergence::restart_step(ctx, env, product).await
}

pub async fn create_for_reconcile(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    convergence::create_for_reconcile(ctx, env).await
}

pub fn model_routing_rollout_rank(kind: crate::manifest::ProductKind, action: Action) -> u8 {
    convergence::model_routing_rollout_rank(kind, action)
}

pub fn validate_model_routing_rollout_order(
    steps: &[(crate::manifest::ProductKind, Action)],
) -> Result<()> {
    convergence::validate_model_routing_rollout_order(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_plan() -> Plan {
        let mut plan = Plan {
            format_version: PLAN_FORMAT_VERSION,
            id: String::new(),
            content_id: String::new(),
            environment: "prod".into(),
            created_at: 123,
            inputs: vec![DesiredStateInput {
                product: "api".into(),
                channel: "stable".into(),
                channel_id: "tenkai:channel:api/stable".into(),
                desired_version: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "target-digest".into(),
                artifact_digest: "target-artifact-digest".into(),
                deployed_version: Some("1.0.0".into()),
            }],
            steps: vec![Step {
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
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
        };
        plan.content_id = content_address(
            &plan.environment,
            plan.created_at,
            &plan.inputs,
            &plan.steps,
            plan.recalled_recovery_reason.as_deref(),
        )
        .unwrap();
        plan.id = plan_id(&plan.environment, plan.created_at, &plan.content_id);
        plan.steps[0].id = format!("{}:step:0", plan.id);
        plan
    }

    #[test]
    fn recalled_recovery_reason_is_part_of_signed_plan_identity() {
        let mut left = example_plan();
        let mut right = example_plan();
        right.recalled_recovery_reason = Some("restore last known-good".into());
        left.content_id = content_address(
            &left.environment,
            left.created_at,
            &left.inputs,
            &left.steps,
            left.recalled_recovery_reason.as_deref(),
        )
        .unwrap();
        right.content_id = content_address(
            &right.environment,
            right.created_at,
            &right.inputs,
            &right.steps,
            right.recalled_recovery_reason.as_deref(),
        )
        .unwrap();
        assert_ne!(left.content_id, right.content_id);
        assert_ne!(
            left.executable_digest().unwrap(),
            right.executable_digest().unwrap()
        );
    }

    #[test]
    fn serialized_plan_round_trips() {
        let plan = example_plan();
        let object = plan.to_object().unwrap();
        assert_eq!(lifecycle::from_object(&object).unwrap(), plan);
    }

    fn plan_for(env: &str, created_at: i64, state: PlanState) -> Plan {
        let mut plan = example_plan();
        plan.environment = env.into();
        plan.created_at = created_at;
        plan.state = state;
        plan.content_id = content_address(
            &plan.environment,
            plan.created_at,
            &plan.inputs,
            &plan.steps,
            plan.recalled_recovery_reason.as_deref(),
        )
        .unwrap();
        plan.id = plan_id(&plan.environment, plan.created_at, &plan.content_id);
        plan.steps[0].id = format!("{}:step:0", plan.id);
        plan
    }

    #[tokio::test]
    async fn list_for_environment_scopes_status_and_order() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-scope-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let env_a_old = plan_for("env_a", 100, PlanState::Computed);
        let env_a_new = plan_for("env_a", 200, PlanState::Running);
        let env_a_done = plan_for("env_a", 50, PlanState::Succeeded);
        let env_b = plan_for("env_b", 10, PlanState::Computed);
        for plan in [&env_a_old, &env_a_new, &env_a_done, &env_b] {
            store(&mut ctx, plan).await.unwrap();
        }

        // Noise: many other environments must not affect env_a selection.
        for i in 0..40 {
            let noise = plan_for(&format!("noise-{i}"), 1_000 + i, PlanState::Computed);
            store(&mut ctx, &noise).await.unwrap();
        }

        let executable = list_for_environment(
            &mut ctx,
            "env_a",
            Some(&[PlanState::Computed, PlanState::Running]),
        )
        .await
        .unwrap();
        assert_eq!(
            executable
                .iter()
                .map(|plan| plan.id.as_str())
                .collect::<Vec<_>>(),
            vec![env_a_old.id.as_str(), env_a_new.id.as_str()]
        );
        assert!(executable.iter().all(|plan| plan.environment == "env_a"
            && matches!(plan.state, PlanState::Computed | PlanState::Running)));

        let oldest = oldest_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed, PlanState::Running],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(oldest.id, env_a_old.id);

        let mut empty = env_a_old.clone();
        empty.created_at = 1;
        empty.steps.clear();
        empty.content_id = content_address(
            &empty.environment,
            empty.created_at,
            &empty.inputs,
            &empty.steps,
            empty.recalled_recovery_reason.as_deref(),
        )
        .unwrap();
        empty.id = plan_id(&empty.environment, empty.created_at, &empty.content_id);
        store(&mut ctx, &empty).await.unwrap();
        let oldest_with_work = oldest_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed, PlanState::Running],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(oldest_with_work.id, env_a_old.id);
        let latest = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.id, env_a_new.id);

        let env_b_only = list_for_environment(
            &mut ctx,
            "env_b",
            Some(&[PlanState::Computed, PlanState::Running]),
        )
        .await
        .unwrap();
        assert_eq!(env_b_only.len(), 1);
        assert_eq!(env_b_only[0].id, env_b.id);
        assert!(!env_b_only.iter().any(|plan| plan.environment == "env_a"));

        let empty = list_for_environment(&mut ctx, "env_missing", Some(&[PlanState::Computed]))
            .await
            .unwrap();
        assert!(empty.is_empty());
        assert!(
            list_for_environment(&mut ctx, "", None)
                .await
                .unwrap_err()
                .to_string()
                .contains("required")
        );

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_and_oldest_fail_closed_on_created_at_index_mismatch() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-created-at-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let older = plan_for("env_a", 100, PlanState::Computed);
        let newer = plan_for("env_a", 200, PlanState::Running);
        store(&mut ctx, &older).await.unwrap();
        store(&mut ctx, &newer).await.unwrap();

        let latest = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.id, newer.id);
        let oldest = oldest_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed, PlanState::Running],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(oldest.id, older.id);

        let mut poisoned = ctx.get(&older.id).await.unwrap().unwrap();
        poisoned
            .properties
            .insert("created_at".into(), "9999".into());
        ctx.put(poisoned).await.unwrap();

        let latest_error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            latest_error.contains("does not match payload"),
            "{latest_error}"
        );
        let oldest_error = oldest_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed, PlanState::Running],
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            oldest_error.contains("does not match payload"),
            "{oldest_error}"
        );
        let listed_error = list_for_environment(&mut ctx, "env_a", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            listed_error.contains("does not match payload"),
            "{listed_error}"
        );

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_fail_closed_on_environment_index_retarget() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-env-retarget-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let older = plan_for("env_a", 100, PlanState::Computed);
        let newer = plan_for("env_a", 200, PlanState::Running);
        store(&mut ctx, &older).await.unwrap();
        store(&mut ctx, &newer).await.unwrap();

        let mut retargeted = ctx.get(&newer.id).await.unwrap().unwrap();
        retargeted
            .properties
            .insert("environment".into(), "other".into());
        ctx.put(retargeted).await.unwrap();

        let error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("environment index other does not match payload env_a"),
            "{error}"
        );

        ctx.put(newer.to_object().unwrap()).await.unwrap();
        let foreign = plan_for("env_b", 300, PlanState::Computed);
        store(&mut ctx, &foreign).await.unwrap();
        let mut foreign_poisoned = ctx.get(&foreign.id).await.unwrap().unwrap();
        foreign_poisoned
            .properties
            .insert("status".into(), "nope".into());
        ctx.put(foreign_poisoned).await.unwrap();
        let mut foreign_malformed = ctx.get(&foreign.id).await.unwrap().unwrap();
        foreign_malformed
            .properties
            .insert("plan".into(), "not-json".into());
        ctx.put(foreign_malformed).await.unwrap();
        let latest = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.id, newer.id);

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_fail_closed_on_status_index_poison() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-status-poison-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let older = plan_for("env_a", 100, PlanState::Computed);
        let newer = plan_for("env_a", 200, PlanState::Computed);
        store(&mut ctx, &older).await.unwrap();
        store(&mut ctx, &newer).await.unwrap();

        let mut poisoned = ctx.get(&newer.id).await.unwrap().unwrap();
        poisoned
            .properties
            .insert("status".into(), "succeeded".into());
        ctx.put(poisoned).await.unwrap();

        let error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("status index succeeded does not match payload computed"),
            "{error}"
        );

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn executable_fail_closed_on_status_index_poison() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-exec-status-poison-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let live = plan_for("env_a", 200, PlanState::Computed);
        store(&mut ctx, &live).await.unwrap();
        let mut poisoned = ctx.get(&live.id).await.unwrap().unwrap();
        poisoned
            .properties
            .insert("status".into(), "succeeded".into());
        ctx.put(poisoned).await.unwrap();

        let error = executable_for_environment(&mut ctx, "env_a", &[PlanState::Computed])
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("status index succeeded does not match payload computed"),
            "{error}"
        );

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_fail_closed_when_true_newest_created_at_index_is_depressed() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-newest-depressed-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let older = plan_for("env_a", 100, PlanState::Computed);
        let newer = plan_for("env_a", 200, PlanState::Running);
        store(&mut ctx, &older).await.unwrap();
        store(&mut ctx, &newer).await.unwrap();

        let mut deflated = ctx.get(&newer.id).await.unwrap().unwrap();
        deflated.properties.insert("created_at".into(), "1".into());
        ctx.put(deflated).await.unwrap();
        let deflated_error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            deflated_error.contains("does not match payload"),
            "{deflated_error}"
        );

        ctx.put(newer.to_object().unwrap()).await.unwrap();
        let mut missing = ctx.get(&newer.id).await.unwrap().unwrap();
        missing.properties.remove("created_at");
        ctx.put(missing).await.unwrap();
        let missing_error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            missing_error.contains("no created_at index"),
            "{missing_error}"
        );

        ctx.put(newer.to_object().unwrap()).await.unwrap();
        let mut non_int = ctx.get(&newer.id).await.unwrap().unwrap();
        non_int
            .properties
            .insert("created_at".into(), "later".into());
        ctx.put(non_int).await.unwrap();
        let non_int_error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(non_int_error.contains("not an integer"), "{non_int_error}");

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_selects_newest_without_requiring_full_history_plan_decode() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-latest-history-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let mut newest_id = String::new();
        for (index, created_at) in (1..=16).enumerate() {
            let state = if index + 1 == 16 {
                PlanState::Running
            } else {
                PlanState::Succeeded
            };
            let stored = plan_for("env_a", created_at * 10, state);
            if index + 1 == 16 {
                newest_id = stored.id.clone();
            }
            store(&mut ctx, &stored).await.unwrap();
        }

        let latest = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.id, newest_id);
        assert_eq!(latest.created_at, 160);
        assert_eq!(latest.state, PlanState::Running);

        let mut poisoned = ctx.get(&newest_id).await.unwrap().unwrap();
        poisoned.properties.insert("created_at".into(), "1".into());
        ctx.put(poisoned).await.unwrap();
        let error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match payload"), "{error}");

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn pending_work_and_retirement_filter_has_steps() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-has-steps-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let mut empty = plan_for("env_a", 10, PlanState::Computed);
        empty.steps.clear();
        empty.content_id = content_address(
            &empty.environment,
            empty.created_at,
            &empty.inputs,
            &empty.steps,
            empty.recalled_recovery_reason.as_deref(),
        )
        .unwrap();
        empty.id = plan_id(&empty.environment, empty.created_at, &empty.content_id);
        let work = plan_for("env_a", 20, PlanState::Computed);
        store(&mut ctx, &empty).await.unwrap();
        store(&mut ctx, &work).await.unwrap();

        let oldest = oldest_for_environment(&mut ctx, "env_a", &[PlanState::Computed])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(oldest.id, work.id);
        let executable = executable_for_environment(&mut ctx, "env_a", &[PlanState::Computed])
            .await
            .unwrap();
        assert_eq!(
            executable
                .iter()
                .map(|plan| plan.id.as_str())
                .collect::<Vec<_>>(),
            vec![work.id.as_str()]
        );

        let retired = retire_empty_executable_plans(&mut ctx, "env_a")
            .await
            .unwrap();
        assert_eq!(retired, 1);
        assert_eq!(
            load(&mut ctx, &empty.id).await.unwrap().state,
            PlanState::Succeeded
        );
        assert_eq!(
            load(&mut ctx, &work.id).await.unwrap().state,
            PlanState::Computed
        );
        let oldest = oldest_for_environment(&mut ctx, "env_a", &[PlanState::Computed])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(oldest.id, work.id);

        let _ = std::fs::remove_file(&database);
    }

    #[test]
    fn lifecycle_changes_do_not_change_executable_digest() {
        let plan = example_plan();
        let mut blocked = plan.clone();
        blocked.state = PlanState::Blocked;
        blocked.maintenance_blocked = true;
        assert_eq!(
            plan.executable_digest().unwrap(),
            blocked.executable_digest().unwrap()
        );
        assert!(
            lifecycle::from_object(&blocked.to_object().unwrap())
                .unwrap()
                .maintenance_blocked
        );
    }

    #[test]
    fn executable_mutation_is_detected() {
        let plan = example_plan();
        let mut object = plan.to_object().unwrap();
        let mut changed = plan;
        changed.steps[0].to = "3.0.0".into();
        object
            .properties
            .insert("plan".into(), serde_json::to_string(&changed).unwrap());
        let error = lifecycle::from_object(&object).unwrap_err().to_string();
        assert!(error.contains("content-addressed id"));
    }

    #[test]
    fn environment_plan_summary_is_bounded_and_omits_executable_payloads() {
        let mut plan = example_plan();
        plan.state = PlanState::Blocked;
        plan.status_detail = format!("token=do-not-return {}", "x".repeat(600));
        let release_digest = plan.steps[0].release_digest.clone();
        let artifact_digest = plan.steps[0].artifact_digest.clone();
        let workdir = plan.steps[0].workdir.clone();

        let summary = crate::environment::environment_plan_summary(plan);

        assert_eq!(summary.state, "blocked");
        assert_eq!(
            summary.status_detail,
            "blocked by Tenkai approval or policy requirements"
        );
        assert!(!summary.status_detail.contains("do-not-return"));
        assert_eq!(summary.steps.len(), 1);
        assert_eq!(summary.steps[0].action, "upgrade");
        assert!(!summary.steps_truncated);
        let encoded = serde_json::to_string(&summary).unwrap();
        assert!(!encoded.contains(&release_digest));
        assert!(!encoded.contains(&artifact_digest));
        assert!(!encoded.contains(&workdir));
    }

    #[test]
    fn inspect_distinguishes_noop_succeeded_from_applied_delivery() {
        let mut noop = example_plan();
        noop.steps.clear();
        noop.state = PlanState::Succeeded;
        noop.status_detail = format!("token=do-not-return {}", "x".repeat(32));
        let summary = crate::environment::environment_plan_summary(noop);
        assert_eq!(summary.state, "succeeded");
        assert_eq!(summary.step_count, 0);
        assert_eq!(summary.status_detail, NO_OP_STATUS_DETAIL);
        assert!(!summary.status_detail.contains("do-not-return"));
        assert!(summary.steps.is_empty());

        let mut applied = example_plan();
        applied.state = PlanState::Succeeded;
        applied.status_detail = format!("complete; token=do-not-return {}", "x".repeat(32));
        let summary = crate::environment::environment_plan_summary(applied);
        assert_eq!(summary.state, "succeeded");
        assert_eq!(summary.step_count, 1);
        assert!(summary.status_detail.is_empty());
        assert!(!summary.status_detail.contains("do-not-return"));
    }

    #[test]
    fn environment_record_initializes_without_deployment_state() {
        let record =
            crate::environment::environment_record(None, "prod", "production", 20).unwrap();
        assert_eq!(record.properties.get("description").unwrap(), "production");
        assert_eq!(record.created, 20);
        assert_eq!(record.updated, 20);
    }

    #[tokio::test]
    async fn list_and_inspect_cover_multiple_environments() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-env-list-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        assert!(list_environments(&mut ctx).await.unwrap().is_empty());

        env_add(&mut ctx, "alpha", "first").await.unwrap();
        env_add(&mut ctx, "beta", "second").await.unwrap();
        let listed = list_environments(&mut ctx).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].name, "alpha");
        assert_eq!(listed[1].name, "beta");
        assert!(!listed[0].lease_held);
        assert_eq!(listed[0].subscription_count, 0);
        assert_eq!(listed[0].deployed_product_count, 0);

        let missing = inspect_environment(&mut ctx, "missing").await;
        assert!(missing.is_err());
        assert!(missing.unwrap_err().to_string().contains("not registered"));

        let report = inspect_environment(&mut ctx, "alpha").await.unwrap();
        assert_eq!(report.name, "alpha");
        assert!(report.subscriptions.is_empty());
        assert!(!report.lease.held);
        // No active apply: either no lease row ("absent") or a non-active row
        // (e.g. "released") — never held.
        assert!(
            report.lease.status == "absent" || report.lease.status == "released",
            "unexpected lease status {}",
            report.lease.status
        );
        assert!(report.latest_plan.is_none());
        assert!(!report.execution_note.contains("Bearer"));
        assert!(!report.execution_note.to_lowercase().contains("token="));
        // Runtime-token vs embedded executor split is documented, not a secret surface.
        assert!(report.execution_note.contains("runtime-token"));

        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("Bearer "));
        assert!(!encoded.contains("management-secret"));

        set_environment_fact(&mut ctx, "alpha", "architecture", "arm64")
            .await
            .unwrap();
        set_environment_fact(&mut ctx, "alpha", "memory_gib", "32")
            .await
            .unwrap();
        let mut runtime_facts = std::collections::BTreeMap::new();
        runtime_facts.insert("architecture".into(), "x86_64".into());
        runtime_facts.insert("memory_gib".into(), "64".into());
        let applied = apply_runtime_inventory_facts(&mut ctx, "alpha", &runtime_facts)
            .await
            .unwrap();
        assert_eq!(
            applied,
            vec!["architecture".to_string(), "memory_gib".to_string()]
        );
        let listed = list_environment_facts(&mut ctx, "alpha").await.unwrap();
        assert_eq!(
            listed.get("architecture").map(String::as_str),
            Some("x86_64")
        );
        assert_eq!(listed.get("memory_gib").map(String::as_str), Some("64"));
        let mut bad = std::collections::BTreeMap::new();
        bad.insert("not_a_key".into(), "x".into());
        assert!(
            apply_runtime_inventory_facts(&mut ctx, "alpha", &bad)
                .await
                .is_err()
        );
        assert!(
            set_environment_fact(&mut ctx, "alpha", "memory_gib", "0")
                .await
                .is_err()
        );
        assert!(
            set_environment_fact(&mut ctx, "alpha", "token", "x")
                .await
                .is_err()
        );
        assert!(
            set_environment_fact(&mut ctx, "alpha", "architecture", "token=abc")
                .await
                .is_err()
        );
        let facts = list_environment_facts(&mut ctx, "alpha").await.unwrap();
        assert_eq!(
            facts.get("architecture").map(String::as_str),
            Some("x86_64")
        );
        assert_eq!(
            require_environment_fact(&mut ctx, "alpha", "architecture")
                .await
                .unwrap(),
            "x86_64"
        );
        assert!(
            require_environment_fact(&mut ctx, "alpha", "accelerator")
                .await
                .unwrap_err()
                .to_string()
                .contains("missing required fact")
        );
        clear_environment_fact(&mut ctx, "alpha", "architecture")
            .await
            .unwrap();
        assert!(
            !list_environment_facts(&mut ctx, "alpha")
                .await
                .unwrap()
                .contains_key("architecture")
        );

        let _ = std::fs::remove_file(&database);
    }

    #[test]
    fn model_requirements_match_architecture_memory_and_accelerator() {
        let mut facts = std::collections::BTreeMap::new();
        facts.insert("architecture".into(), "arm64".into());
        facts.insert("memory_gib".into(), "32".into());
        facts.insert("accelerator".into(), "apple-metal".into());
        let requirements = crate::manifest::ModelRequirementsSection {
            architecture: vec!["arm64".into(), "x86_64".into()],
            memory_gib: 24,
            accelerator: vec!["apple-metal".into()],
        };
        model_requirements_fit("local", "qwen", "1.0.0", &facts, &requirements).unwrap();

        facts.insert("memory_gib".into(), "8".into());
        let err = model_requirements_fit("local", "qwen", "1.0.0", &facts, &requirements)
            .unwrap_err()
            .to_string();
        assert!(err.contains("memory_gib"), "{err}");

        facts.insert("memory_gib".into(), "32".into());
        facts.insert("architecture".into(), "riscv".into());
        let err = model_requirements_fit("local", "qwen", "1.0.0", &facts, &requirements)
            .unwrap_err()
            .to_string();
        assert!(err.contains("architecture"), "{err}");
    }
}
