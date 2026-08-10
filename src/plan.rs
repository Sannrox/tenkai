//! Environments, subscriptions, and plan computation (desired vs deployed).

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::*;
use crate::pb::sekai::Object;

mod release_selection;

pub use release_selection::model_requirements_fit;

pub(crate) use crate::environment::update_runtime_deployments_object;
pub use crate::environment::{
    ENVIRONMENT_FACT_KEYS, EnvironmentInspectReport, EnvironmentListEntry,
    EnvironmentPlanStepSummary, EnvironmentPlanSummary, EnvironmentSubscriptionView, StatusRow,
    apply_runtime_inventory_facts, clear_environment_constraint, clear_environment_fact, env_add,
    fleet_status, inspect_environment, inspect_environment_with_outcomes,
    list_environment_constraints, list_environment_facts, list_environments, reconcile_deployment,
    require_environment_fact, set_environment_constraint, set_environment_fact, status, subscribe,
};
pub use crate::fleet::{
    FleetDriftSummary, FleetEnvironmentRow, FleetPostureSnapshot, FleetStatusReport,
    compare_fleet_posture, fleet_posture_snapshot, fleet_status_from_inspects,
    fleet_status_from_rows, is_hard_drift_posture, load_fleet_posture_baseline,
    write_fleet_posture_baseline,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Install,
    Upgrade,
    Downgrade,
    Rollback,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Action::Install => "install",
            Action::Upgrade => "upgrade",
            Action::Downgrade => "downgrade",
            Action::Rollback => "rollback",
        };
        f.write_str(s)
    }
}

fn classify_change(current: &str, desired: &str) -> Action {
    match (
        semver::Version::parse(current),
        semver::Version::parse(desired),
    ) {
        (Ok(current), Ok(target)) if target < current => Action::Downgrade,
        _ => Action::Upgrade,
    }
}

pub const PLAN_FORMAT_VERSION: u32 = 1;

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
}

fn content_address(
    environment: &str,
    created_at: i64,
    inputs: &[DesiredStateInput],
    steps: &[Step],
) -> Result<String> {
    let mut normalized_steps = steps.to_vec();
    for step in &mut normalized_steps {
        step.id.clear();
    }
    let bytes = serde_json::to_vec(&(
        PLAN_FORMAT_VERSION,
        environment,
        created_at,
        inputs,
        normalized_steps,
    ))?;
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
        };
        let bytes = serde_json::to_vec(&content)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub(crate) fn to_object(&self) -> Result<Object> {
        let now = crate::now_millis();
        Ok(Object {
            id: self.id.clone(),
            kind: KIND_PLAN.into(),
            name: format!("{} plan {}", self.environment, self.created_at),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("format_version".into(), self.format_version.to_string()),
                ("environment".into(), self.environment.clone()),
                ("created_at".into(), self.created_at.to_string()),
                ("content_digest".into(), self.executable_digest()?),
                ("plan".into(), serde_json::to_string(self)?),
                ("status".into(), self.state.to_string()),
            ]),
            created: self.created_at,
            updated: now,
        })
    }

    fn from_object(object: &Object) -> Result<Self> {
        if object.kind != KIND_PLAN {
            bail!("object {} is {}, not {KIND_PLAN}", object.id, object.kind);
        }
        let raw = object
            .properties
            .get("plan")
            .with_context(|| format!("plan object {} has no serialized plan", object.id))?;
        let plan: Self = serde_json::from_str(raw)
            .with_context(|| format!("parsing stored plan {}", object.id))?;
        if plan.format_version != PLAN_FORMAT_VERSION {
            bail!(
                "plan {} uses unsupported format version {}",
                object.id,
                plan.format_version
            );
        }
        if plan.maintenance_blocked && plan.state != PlanState::Blocked {
            bail!(
                "plan {} has a maintenance-block marker outside the blocked state",
                plan.id
            );
        }
        if plan.id != object.id {
            bail!(
                "stored plan id {} does not match object id {}",
                plan.id,
                object.id
            );
        }
        let expected_content_id = content_address(
            &plan.environment,
            plan.created_at,
            &plan.inputs,
            &plan.steps,
        )?;
        if plan.content_id != expected_content_id
            || plan.id != plan_id(&plan.environment, plan.created_at, &expected_content_id)
        {
            bail!(
                "stored plan {} does not match its content-addressed id",
                object.id
            );
        }
        for (order, step) in plan.steps.iter().enumerate() {
            if step.order != order as u32 || step.id != format!("{}:step:{order}", plan.id) {
                bail!("stored plan {} has invalid step ordering or ids", object.id);
            }
        }
        let status = object
            .properties
            .get("status")
            .with_context(|| format!("plan object {} has no lifecycle status", object.id))?;
        if status != &plan.state.to_string() {
            bail!("stored plan {} has inconsistent lifecycle state", object.id);
        }
        let stored_digest = object
            .properties
            .get("content_digest")
            .with_context(|| format!("plan object {} has no content digest", object.id))?;
        if plan.executable_digest()? != *stored_digest {
            bail!("stored plan {} executable content was mutated", object.id);
        }
        Ok(plan)
    }
}

pub async fn store(ctx: &mut Ctx, plan: &Plan) -> Result<()> {
    store_with_provider_events(ctx, plan, &[]).await
}

pub(crate) async fn store_with_provider_events(
    ctx: &mut Ctx,
    plan: &Plan,
    provider_events: &[crate::storage::ProviderEventRecord],
) -> Result<()> {
    let object = validated_plan_object(ctx, plan).await?;
    ctx.put_with_provider_events(object, provider_events)
        .await?;
    Ok(())
}

pub(crate) async fn store_with_environment_and_provider_events(
    ctx: &mut Ctx,
    plan: &Plan,
    environment: Object,
    provider_events: &[crate::storage::ProviderEventRecord],
) -> Result<()> {
    let plan_object = validated_plan_object(ctx, plan).await?;
    ctx.put_objects_with_provider_events(&[plan_object, environment], provider_events)
        .await
}

async fn validated_plan_object(ctx: &mut Ctx, plan: &Plan) -> Result<Object> {
    let existing = ctx.get(&plan.id).await?;
    if let Some(existing) = existing.as_ref() {
        let stored = Plan::from_object(existing)?;
        if stored.executable_digest()? != plan.executable_digest()? {
            bail!("plan {} executable content is immutable", plan.id);
        }
        if stored.state == plan.state
            && stored.state != PlanState::Blocked
            && (stored.gates_skipped != plan.gates_skipped
                || stored.status_detail != plan.status_detail
                || stored.maintenance_blocked != plan.maintenance_blocked)
        {
            bail!("plan {} lifecycle audit fields are immutable", plan.id);
        }
        let valid_transition = stored.state == plan.state
            || matches!(
                (stored.state, plan.state),
                (PlanState::Computed, PlanState::Running)
                    | (PlanState::Computed, PlanState::Blocked)
                    | (PlanState::Blocked, PlanState::Running)
                    | (PlanState::Running, PlanState::Blocked)
                    | (PlanState::Running, PlanState::Succeeded)
                    | (PlanState::Running, PlanState::Failed)
            );
        if !valid_transition {
            bail!(
                "plan {} cannot transition from {} to {}",
                plan.id,
                stored.state,
                plan.state
            );
        }
    }
    let mut object = plan.to_object()?;
    if let Some(existing) = existing.as_ref() {
        for property in [
            "last_emergency_override_reason",
            "last_emergency_override_correlation",
        ] {
            if let Some(value) = existing.properties.get(property) {
                object.properties.insert(property.into(), value.clone());
            }
        }
    }
    Ok(object)
}

pub async fn load(ctx: &mut Ctx, id: &str) -> Result<Plan> {
    let object = ctx
        .get(id)
        .await?
        .with_context(|| format!("plan {id} not found"))?;
    Plan::from_object(&object)
}

/// Load plans for one environment without scanning the full plan kind set.
///
/// Uses the store property index (`find_by_property` on `environment`). Empty
/// environment ids fail closed rather than falling back to an unscoped list.
/// When `statuses` is `Some`, only matching lifecycle states are returned.
/// Results are ordered by `created_at` ascending (oldest first), matching
/// reconcile work selection.
pub async fn list_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: Option<&[PlanState]>,
) -> Result<Vec<Plan>> {
    anyhow::ensure!(
        !environment.trim().is_empty(),
        "environment is required for plan work selection"
    );
    let objects = ctx
        .find_by_property(KIND_PLAN, "environment", environment)
        .await?;
    let mut plans = Vec::with_capacity(objects.len());
    for object in objects {
        let plan = Plan::from_object(&object)?;
        if plan.environment != environment {
            bail!(
                "plan {} property index returned environment {}, expected {environment}",
                plan.id,
                plan.environment
            );
        }
        if let Some(allowed) = statuses
            && !allowed.contains(&plan.state)
        {
            continue;
        }
        plans.push(plan);
    }
    plans.sort_by_key(|plan| plan.created_at);
    Ok(plans)
}

/// Oldest plan for `environment` whose status is in `statuses`, or `None`.
pub async fn oldest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Option<Plan>> {
    let plans = list_for_environment(ctx, environment, Some(statuses)).await?;
    Ok(plans.into_iter().next())
}

async fn pin_release(ctx: &mut Ctx, id: &str, environment: &str) -> Result<ReleasePin> {
    use crate::catalog::CatalogReader as _;

    let descriptor = crate::catalog::EmbeddedCatalog::new(ctx)
        .lookup_release(id, environment)
        .await?;
    Ok(ReleasePin {
        release_id: descriptor.release_id,
        digest: descriptor.manifest_digest,
        artifact_digest: descriptor.artifact_digest,
        workdir: descriptor.content_path,
    })
}

async fn compute_snapshot(ctx: &mut Ctx, env: &str) -> Result<(Vec<DesiredStateInput>, Vec<Step>)> {
    let env_obj = crate::environment::environment(ctx, env).await?;
    let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;

    let mut products = std::collections::HashSet::new();
    for channel in &channels {
        let product = channel
            .properties
            .get("product")
            .cloned()
            .unwrap_or_default();
        if !products.insert(product.clone()) {
            bail!(
                "environment {env} has multiple channel subscriptions for {product}; subscribe again after concurrent updates settle"
            );
        }
    }

    let mut inputs = Vec::new();
    let mut pending = Vec::new();
    for ch in channels {
        let product = ch.properties.get("product").cloned().unwrap_or_default();
        let channel = ch.properties.get("channel").cloned().unwrap_or_default();
        let channel_version = ch
            .properties
            .get("current_version")
            .cloned()
            .unwrap_or_default();
        let channel_release = ch
            .properties
            .get("current_release")
            .cloned()
            .unwrap_or_default();
        if channel_version.is_empty() || channel_release.is_empty() {
            continue; // channel exists but nothing promoted yet
        }
        let selected = release_selection::select(
            ctx,
            &env_obj,
            env,
            release_selection::ChannelHead {
                product: &product,
                version: &channel_version,
                release_id: &channel_release,
            },
        )
        .await?;
        let desired = selected.version;
        let release = selected.release_id;
        let target = pin_release(ctx, &release, env).await?;
        if env_obj
            .properties
            .get(&format!("deployment_health.{product}"))
            .is_some_and(|health| health == "unknown")
        {
            let detail = env_obj
                .properties
                .get(&format!("deployment_error.{product}"))
                .map(String::as_str)
                .unwrap_or("deployment state requires manual reconciliation");
            bail!(
                "deployment state for {product} in {env} is unknown: {detail}; reconcile it or use rollback before creating a new plan"
            );
        }
        let deployed = env_obj
            .properties
            .get(&format!("deployed.{product}"))
            .cloned();
        let kind = selected.kind;
        inputs.push(DesiredStateInput {
            product: product.clone(),
            channel,
            channel_id: ch.id,
            desired_version: desired.clone(),
            release_id: release.clone(),
            release_digest: target.digest.clone(),
            artifact_digest: target.artifact_digest.clone(),
            deployed_version: deployed.clone(),
        });
        match deployed {
            Some(v) if v == desired => {}
            Some(v) => {
                let action = classify_change(&v, &desired);
                let restore = pin_release(ctx, &release_id(&product, &v), env).await?;
                pending.push((
                    product,
                    action,
                    Some(v),
                    desired,
                    target,
                    Some(restore),
                    kind,
                ));
            }
            None => pending.push((product, Action::Install, None, desired, target, None, kind)),
        }
    }
    inputs.sort_by(|a, b| a.product.cmp(&b.product));
    // Enforce model_runtime ↔ routing_config rollout order (see docs).
    pending.sort_by(|a, b| {
        model_routing_rollout_rank(a.6, a.1)
            .cmp(&model_routing_rollout_rank(b.6, b.1))
            .then_with(|| a.0.cmp(&b.0))
    });
    validate_model_routing_rollout_order(
        &pending
            .iter()
            .map(|entry| (entry.6, entry.1))
            .collect::<Vec<_>>(),
    )?;
    let steps = pending
        .into_iter()
        .enumerate()
        .map(
            |(index, (product, action, from, to, release, restore, _kind))| Step {
                id: format!("{}:step:{index}", env_id(env)),
                order: index as u32,
                product,
                action,
                from,
                to,
                release_id: release.release_id,
                release_digest: release.digest,
                artifact_digest: release.artifact_digest,
                workdir: release.workdir,
                restore,
            },
        )
        .collect();
    Ok((inputs, steps))
}

/// Deterministic step ranking for coordinated model_runtime + routing_config
/// rollouts without merging the product kinds.
///
/// Forward (install/upgrade): model_runtime first, then routing_config.
/// Reverse (downgrade/rollback): routing_config first (drain traffic), then
/// model_runtime (retire generation). Other products keep a neutral rank and
/// sort by product name among themselves.
pub fn model_routing_rollout_rank(kind: crate::manifest::ProductKind, action: Action) -> u8 {
    use crate::manifest::ProductKind;
    match (kind, action) {
        (ProductKind::ModelRuntime, Action::Install | Action::Upgrade) => 0,
        (ProductKind::RoutingConfig, Action::Install | Action::Upgrade) => 1,
        (ProductKind::RoutingConfig, Action::Downgrade | Action::Rollback) => 0,
        (ProductKind::ModelRuntime, Action::Downgrade | Action::Rollback) => 1,
        _ => 2,
    }
}

/// Reject unsafe model/routing step order (routing switch before model ready,
/// or model retire while routes still target it).
pub fn validate_model_routing_rollout_order(
    steps: &[(crate::manifest::ProductKind, Action)],
) -> Result<()> {
    use crate::manifest::ProductKind;
    let mut last_forward_model = None;
    let mut last_forward_routing = None;
    let mut last_reverse_routing = None;
    let mut last_reverse_model = None;
    for (index, (kind, action)) in steps.iter().enumerate() {
        match (kind, action) {
            (ProductKind::ModelRuntime, Action::Install | Action::Upgrade) => {
                last_forward_model = Some(index);
            }
            (ProductKind::RoutingConfig, Action::Install | Action::Upgrade) => {
                last_forward_routing = Some(index);
            }
            (ProductKind::RoutingConfig, Action::Downgrade | Action::Rollback) => {
                last_reverse_routing = Some(index);
            }
            (ProductKind::ModelRuntime, Action::Downgrade | Action::Rollback) => {
                last_reverse_model = Some(index);
            }
            _ => {}
        }
    }
    if let (Some(model_i), Some(routing_i)) = (last_forward_model, last_forward_routing)
        && model_i > routing_i
    {
        bail!(
            "unsafe rollout order: routing_config step at {routing_i} precedes model_runtime step at {model_i}; install/verify model before switching routes"
        );
    }
    if let (Some(routing_i), Some(model_i)) = (last_reverse_routing, last_reverse_model)
        && routing_i > model_i
    {
        bail!(
            "unsafe rollback order: model_runtime step at {model_i} precedes routing_config step at {routing_i}; switch routes away before retiring the model"
        );
    }
    Ok(())
}

/// Compute the steps that converge the environment on its subscribed channels.
pub async fn compute(ctx: &mut Ctx, env: &str) -> Result<Vec<Step>> {
    Ok(compute_snapshot(ctx, env).await?.1)
}

/// Compute and persist an immutable executable plan before any step is run.
pub async fn create(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    let (inputs, mut steps) = compute_snapshot(ctx, env).await?;
    create_with_content(ctx, env, inputs, &mut steps).await
}

/// Persist an explicitly constructed operation, such as a rollback, as a plan.
pub async fn create_from_steps(ctx: &mut Ctx, env: &str, mut steps: Vec<Step>) -> Result<Plan> {
    crate::environment::environment(ctx, env).await?;
    create_with_content(ctx, env, Vec::new(), &mut steps).await
}

async fn create_with_content(
    ctx: &mut Ctx,
    env: &str,
    inputs: Vec<DesiredStateInput>,
    steps: &mut [Step],
) -> Result<Plan> {
    let created_at = crate::now_millis();
    for (order, step) in steps.iter_mut().enumerate() {
        step.order = order as u32;
    }
    let content_id = content_address(env, created_at, &inputs, steps)?;
    let id = plan_id(env, created_at, &content_id);
    for (order, step) in steps.iter_mut().enumerate() {
        step.id = format!("{id}:step:{order}");
    }
    let plan = Plan {
        format_version: PLAN_FORMAT_VERSION,
        id,
        content_id,
        environment: env.to_string(),
        created_at,
        inputs,
        steps: steps.to_vec(),
        state: PlanState::Computed,
        gates_skipped: None,
        status_detail: String::new(),
        maintenance_blocked: false,
        prior_warnings: Vec::new(),
    };
    // Optional advisory priors (default off). Never hard-block or change steps.
    let mut plan = plan;
    if let Ok(inspect) = inspect_environment(ctx, env).await {
        let _ = crate::plan_priors::annotate_plan_with_priors(
            &mut plan,
            &inspect,
            &crate::plan_priors::PriorConfig::from_env(),
        );
    }
    store(ctx, &plan).await?;
    Ok(plan)
}

/// A rollback step to the previously deployed version of one product.
pub async fn rollback_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    validate_identifier("product", product)?;
    let env_obj = crate::environment::environment(ctx, env).await?;
    let current = env_obj
        .properties
        .get(&format!("deployed.{product}"))
        .cloned();
    let Some(prev) = env_obj
        .properties
        .get(&format!("deployed_prev.{product}"))
        .cloned()
        .filter(|v| !v.is_empty())
    else {
        bail!("no previous version of {product} recorded in {env} — nothing to roll back to");
    };
    let target = pin_release(ctx, &release_id(product, &prev), env).await?;
    let restore = match current.as_deref() {
        Some(version) => Some(pin_release(ctx, &release_id(product, version), env).await?),
        None => None,
    };
    Ok(Step {
        id: format!("{}:rollback:{product}", env_id(env)),
        order: 0,
        release_id: target.release_id,
        release_digest: target.digest,
        artifact_digest: target.artifact_digest,
        workdir: target.workdir,
        restore,
        product: product.into(),
        action: Action::Rollback,
        from: current,
        to: prev,
    })
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
        };
        plan.content_id = content_address(
            &plan.environment,
            plan.created_at,
            &plan.inputs,
            &plan.steps,
        )
        .unwrap();
        plan.id = plan_id(&plan.environment, plan.created_at, &plan.content_id);
        plan.steps[0].id = format!("{}:step:0", plan.id);
        plan
    }

    #[test]
    fn serialized_plan_round_trips() {
        let plan = example_plan();
        let object = plan.to_object().unwrap();
        assert_eq!(Plan::from_object(&object).unwrap(), plan);
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
            Plan::from_object(&blocked.to_object().unwrap())
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
        let error = Plan::from_object(&object).unwrap_err().to_string();
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
    fn semantic_version_direction_is_recorded() {
        assert_eq!(classify_change("2.0.0", "1.9.0"), Action::Downgrade);
        assert_eq!(classify_change("1.9.0", "2.0.0"), Action::Upgrade);
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
    fn model_routing_forward_order_requires_model_before_routing() {
        use crate::manifest::ProductKind;
        validate_model_routing_rollout_order(&[
            (ProductKind::ModelRuntime, Action::Install),
            (ProductKind::RoutingConfig, Action::Upgrade),
        ])
        .unwrap();
        let err = validate_model_routing_rollout_order(&[
            (ProductKind::RoutingConfig, Action::Upgrade),
            (ProductKind::ModelRuntime, Action::Install),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("unsafe rollout order"), "{err}");
    }

    #[test]
    fn model_routing_rollback_order_requires_routing_before_model() {
        use crate::manifest::ProductKind;
        validate_model_routing_rollout_order(&[
            (ProductKind::RoutingConfig, Action::Rollback),
            (ProductKind::ModelRuntime, Action::Downgrade),
        ])
        .unwrap();
        let err = validate_model_routing_rollout_order(&[
            (ProductKind::ModelRuntime, Action::Downgrade),
            (ProductKind::RoutingConfig, Action::Rollback),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("unsafe rollback order"), "{err}");
    }

    #[test]
    fn model_routing_rank_orders_forward_and_reverse() {
        use crate::manifest::ProductKind;
        assert!(
            model_routing_rollout_rank(ProductKind::ModelRuntime, Action::Install)
                < model_routing_rollout_rank(ProductKind::RoutingConfig, Action::Install)
        );
        assert!(
            model_routing_rollout_rank(ProductKind::RoutingConfig, Action::Rollback)
                < model_routing_rollout_rank(ProductKind::ModelRuntime, Action::Rollback)
        );
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

    fn write_model_runtime_manifest(
        dir: &std::path::Path,
        version: &str,
        memory_gib: u32,
        quantization: &str,
    ) {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let body = format!(
            r#"[product]
name = "qwen-coder"
version = "{version}"
kind = "model_runtime"
description = "variant fixture"

[model]
source = "file:///tmp/weights.bin"
revision = "fixture"
format = "gguf"
quantization = "{quantization}"
artifact_digest = "{digest}"
license = "apache-2.0"

[runtime]
engine = "llama.cpp"
port = 8080
context_length = 8192

[requirements]
architecture = ["arm64"]
memory_gib = {memory_gib}
accelerator = ["apple-metal"]

[health]
endpoint = "http://127.0.0.1:8080/v1/models"
smoke_prompt = "OK"
max_startup_seconds = 60
"#
        );
        std::fs::write(dir.join("tenkai.toml"), body).unwrap();
    }

    #[tokio::test]
    async fn plan_selects_feasible_model_runtime_variant() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-variant-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let q4_dir = root.join("q4");
        let q8_dir = root.join("q8");
        std::fs::create_dir_all(&q4_dir).unwrap();
        std::fs::create_dir_all(&q8_dir).unwrap();
        write_model_runtime_manifest(&q4_dir, "1.0.0", 16, "Q4_K_M");
        write_model_runtime_manifest(&q8_dir, "1.1.0", 48, "Q8_0");

        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = crate::catalog::PublishOptions {
            signature: None,
            trust_roots: None,
            allow_unsigned_development: true,
            provenance: Vec::new(),
            provenance_trust_roots: None,
        };
        crate::catalog::publish(&mut ctx, &q4_dir.join("tenkai.toml"), &options)
            .await
            .unwrap();
        crate::catalog::publish(&mut ctx, &q8_dir.join("tenkai.toml"), &options)
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, "qwen-coder@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, "qwen-coder@1.1.0", "stable")
            .await
            .unwrap();

        env_add(&mut ctx, "local", "fixture").await.unwrap();
        subscribe(&mut ctx, "local", "qwen-coder", "stable")
            .await
            .unwrap();
        set_environment_fact(&mut ctx, "local", "architecture", "arm64")
            .await
            .unwrap();
        set_environment_fact(&mut ctx, "local", "accelerator", "apple-metal")
            .await
            .unwrap();
        // Only enough memory for Q4; channel head is Q8 (1.1.0).
        set_environment_fact(&mut ctx, "local", "memory_gib", "24")
            .await
            .unwrap();

        let plan = create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].product, "qwen-coder");
        assert_eq!(plan.steps[0].to, "1.0.0");
        assert_eq!(plan.steps[0].release_id, release_id("qwen-coder", "1.0.0"));

        // Infeasible: too little memory for any published variant.
        set_environment_fact(&mut ctx, "local", "memory_gib", "8")
            .await
            .unwrap();
        let err = create(&mut ctx, "local").await.unwrap_err().to_string();
        assert!(
            err.contains("no model_runtime variant") || err.contains("memory_gib"),
            "{err}"
        );

        // High memory selects channel head Q8.
        set_environment_fact(&mut ctx, "local", "memory_gib", "64")
            .await
            .unwrap();
        let plan = create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps[0].to, "1.1.0");

        let _ = std::fs::remove_dir_all(&root);
    }
}
