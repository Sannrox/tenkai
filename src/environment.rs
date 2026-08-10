//! Environment identity, subscriptions, constraints, facts, observations, and readback.
//!
//! This module concentrates Environment invariants behind the application core's
//! in-process interface. Planning consumes Environment state but does not own its
//! mutation or operator readback rules.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::ontology::*;
use crate::pb::sekai::Object;
use crate::plan::{Plan, PlanState, Step};

pub(crate) fn environment_record(
    existing: Option<Object>,
    name: &str,
    description: &str,
    now: i64,
) -> Result<Object> {
    let id = env_id(name);
    Ok(match existing {
        Some(mut existing) => {
            if existing.kind != KIND_ENVIRONMENT {
                bail!("object {id} is {}, not {KIND_ENVIRONMENT}", existing.kind);
            }
            existing
                .properties
                .insert("description".into(), description.to_string());
            existing.updated = now;
            existing
        }
        None => Object {
            id,
            kind: KIND_ENVIRONMENT.into(),
            name: name.into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([("description".into(), description.to_string())]),
            created: now,
            updated: now,
        },
    })
}

pub async fn env_add(ctx: &mut Ctx, name: &str, description: &str) -> Result<String> {
    validate_identifier("environment", name)?;
    let now = crate::now_millis();
    let id = env_id(name);
    if let Some(existing) = ctx.get(&id).await? {
        if existing.kind != KIND_ENVIRONMENT {
            bail!("object {id} is {}, not {KIND_ENVIRONMENT}", existing.kind);
        }
        crate::maintenance::ensure_configuration(ctx, name).await?;
        return Ok(format!("environment {name} already registered"));
    }
    let object = environment_record(None, name, description, now)?;
    match ctx.create_once(object).await {
        Ok(_) => {}
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE")) => {}
        Err(status) => return Err(status.into()),
    }
    crate::maintenance::ensure_configuration(ctx, name).await?;
    Ok(format!("environment {name} registered"))
}

pub async fn reconcile_deployment(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    deployed: Option<&str>,
) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("product", product)?;
    if crate::apply::environment_lease_status(ctx, env)
        .await?
        .is_some()
    {
        bail!("environment {env} has an apply in progress");
    }
    let mut object = environment(ctx, env).await?;
    let was_unknown = object
        .properties
        .get(&format!("deployment_health.{product}"))
        .is_some_and(|health| health == "unknown");
    let unknown_origin = (
        object
            .properties
            .get(&format!("deployment_unknown_plan.{product}"))
            .cloned(),
        object
            .properties
            .get(&format!("deployment_unknown_step.{product}"))
            .cloned(),
        object
            .properties
            .get(&format!("deployment_unknown_attempt.{product}"))
            .cloned(),
    );
    let observed_at = crate::now_millis();
    let provider_events = if ctx.outcome_export_enabled() && was_unknown {
        match unknown_origin {
            (Some(plan_id), Some(step_id), Some(deployment_id)) => {
                let plan = crate::plan::load(ctx, &plan_id).await?;
                anyhow::ensure!(
                    plan.environment == env,
                    "unknown deployment origin belongs to a different environment"
                );
                let step = plan
                    .steps
                    .iter()
                    .find(|step| step.id == step_id && step.product == product)
                    .with_context(|| {
                        format!(
                            "unknown deployment origin step {step_id} is absent from plan {plan_id}"
                        )
                    })?;
                vec![crate::providers::terminal_outcome_record(
                    &plan,
                    step,
                    &deployment_id,
                    crate::providers::TerminalOutcomeState::UnknownReconciled,
                    &object,
                    observed_at,
                )?]
            }
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };
    update_reconciled_deployment_object(ctx, &mut object, product, deployed, observed_at).await?;
    ctx.put_with_provider_events(object, &provider_events)
        .await?;
    Ok(match deployed {
        Some(version) => format!("recorded {product}@{version} as deployed in {env}"),
        None => format!("cleared unknown deployment state for {product} in {env}"),
    })
}

async fn update_reconciled_deployment_object(
    ctx: &mut Ctx,
    object: &mut Object,
    product: &str,
    deployed: Option<&str>,
    observed_at: i64,
) -> Result<()> {
    match deployed {
        Some(version) => {
            validate_identifier("version", version)?;
            let release = release_id(product, version);
            if ctx.get(&release).await?.is_none() {
                bail!("release {product}@{version} is not published");
            }
            object
                .properties
                .insert(format!("deployed.{product}"), version.into());
            object
                .properties
                .insert(format!("deployed_release.{product}"), release);
        }
        None => {
            object.properties.remove(&format!("deployed.{product}"));
            object
                .properties
                .remove(&format!("deployed_release.{product}"));
        }
    }
    object
        .properties
        .remove(&format!("deployment_health.{product}"));
    object
        .properties
        .remove(&format!("deployment_error.{product}"));
    object
        .properties
        .remove(&format!("deployed_prev.{product}"));
    for prefix in [
        "deployment_unknown_plan.",
        "deployment_unknown_step.",
        "deployment_unknown_attempt.",
    ] {
        object.properties.remove(&format!("{prefix}{product}"));
    }
    object.updated = observed_at;
    Ok(())
}

pub(crate) async fn update_runtime_deployments_object(
    ctx: &mut Ctx,
    object: &mut Object,
    steps: &[Step],
    observed_at: i64,
) -> Result<()> {
    for step in steps {
        validate_identifier("product", &step.product)?;
        update_reconciled_deployment_object(
            ctx,
            object,
            &step.product,
            Some(&step.to),
            observed_at,
        )
        .await?;
    }
    Ok(())
}

/// Subscribe an environment to a product channel. The channel must exist.
pub async fn subscribe(ctx: &mut Ctx, env: &str, product: &str, channel: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("product", product)?;
    validate_identifier("channel", channel)?;
    let eid = env_id(env);
    if ctx.get(&eid).await?.is_none() {
        bail!("environment {env} is not registered (tenkaictl env add {env})");
    }
    let cid = channel_id(product, channel);
    if ctx.get(&cid).await?.is_none() {
        bail!("channel {product}/{channel} does not exist — promote a release into it first");
    }
    let links = ctx.links(&eid, REL_SUBSCRIBES).await?;
    let mut existing = Vec::new();
    for link in links {
        let channel = ctx
            .get(&link.to_id)
            .await?
            .with_context(|| format!("subscription link {} has no channel", link.id))?;
        if channel.properties.get("product").map(String::as_str) == Some(product) {
            existing.push(link);
        }
    }
    if existing.len() > 1 {
        bail!("environment {env} has conflicting subscriptions for {product}");
    }
    if existing.first().is_some_and(|link| link.to_id == cid) {
        return Ok(format!("{env} already subscribed to {product}/{channel}"));
    }
    let mut params = HashMap::from([("id".into(), eid), ("channel_id".into(), cid)]);
    let action = if let Some(link) = existing.first() {
        params.insert("old_link_id".into(), link.id.clone());
        ACTION_REPLACE_SUBSCRIPTION
    } else {
        ACTION_SUBSCRIBE
    };
    ctx.execute_action(action, params).await?;
    Ok(format!("{env} subscribed to {product}/{channel}"))
}

pub(crate) async fn environment(ctx: &mut Ctx, env: &str) -> Result<Object> {
    validate_identifier("environment", env)?;
    match ctx.get(&env_id(env)).await? {
        Some(o) => Ok(o),
        None => bail!("environment {env} is not registered (tenkaictl env add {env})"),
    }
}

pub async fn set_environment_constraint(
    ctx: &mut Ctx,
    env: &str,
    kind: &str,
    name: &str,
    value: &str,
) -> Result<String> {
    validate_identifier("environment", env)?;
    if value.trim().is_empty() {
        bail!("constraint value must not be empty");
    }
    let property = match kind {
        "version_pin" => {
            validate_identifier("product", name)?;
            semver::Version::parse(value)
                .with_context(|| format!("version pin must be valid semver, got {value:?}"))?;
            format!("constraint.version_pin.{name}")
        }
        "version_range" => {
            validate_identifier("product", name)?;
            let (min, max) = value
                .split_once("..")
                .context("version range must be min..max")?;
            let min_v = semver::Version::parse(min.trim())
                .with_context(|| format!("invalid version range minimum in {value:?}"))?;
            let max_v = semver::Version::parse(max.trim())
                .with_context(|| format!("invalid version range maximum in {value:?}"))?;
            if min_v >= max_v {
                bail!("version range minimum must be less than maximum");
            }
            format!("constraint.version_range.{name}")
        }
        "require_fact" => {
            validate_fact_key(name)?;
            if value != "*" {
                validate_fact_value(name, value)?;
            }
            format!("constraint.require_fact.{name}")
        }
        other => bail!(
            "unknown constraint kind {other:?}; expected version_pin, version_range, or require_fact"
        ),
    };
    let mut env_obj = environment(ctx, env).await?;
    env_obj.properties.insert(property.clone(), value.into());
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} constraint {property}={value}"))
}

pub async fn clear_environment_constraint(
    ctx: &mut Ctx,
    env: &str,
    kind: &str,
    name: &str,
) -> Result<String> {
    let property = match kind {
        "version_pin" => format!("constraint.version_pin.{name}"),
        "version_range" => format!("constraint.version_range.{name}"),
        "require_fact" => format!("constraint.require_fact.{name}"),
        other => bail!("unknown constraint kind {other:?}"),
    };
    let mut env_obj = environment(ctx, env).await?;
    if env_obj.properties.remove(&property).is_none() {
        bail!("environment {env} has no constraint {property}");
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("cleared {env} constraint {property}"))
}

pub async fn list_environment_constraints(
    ctx: &mut Ctx,
    env: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let env_obj = environment(ctx, env).await?;
    let mut out = std::collections::BTreeMap::new();
    for (key, value) in &env_obj.properties {
        if key.starts_with("constraint.") {
            out.insert(key.clone(), value.clone());
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRow {
    pub product: String,
    pub channel: String,
    pub deployed: Option<String>,
    pub health: Option<String>,
    pub error: Option<String>,
    pub head: String,
}

/// Summary row for fleet listing (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentListEntry {
    pub name: String,
    pub id: String,
    pub description: String,
    pub subscription_count: usize,
    pub deployed_product_count: usize,
    pub lease_held: bool,
}

/// Initial capability/inventory fact keys admitted for environments.
pub const ENVIRONMENT_FACT_KEYS: &[&str] =
    &["architecture", "memory_gib", "accelerator", "free_disk_gib"];

const ENVIRONMENT_FACT_PREFIX: &str = "fact.";

/// Detailed inspect report for one environment (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentInspectReport {
    pub name: String,
    pub id: String,
    pub description: String,
    pub subscriptions: Vec<EnvironmentSubscriptionView>,
    pub facts: std::collections::BTreeMap<String, String>,
    pub lease: crate::apply::EnvironmentLeaseInspect,
    /// Most recent plan for this environment by `created_at`, if any.
    pub latest_plan: Option<EnvironmentPlanSummary>,
    /// Bounded terminal-outcome identities and outbox delivery state. Event
    /// payloads and retry errors are intentionally excluded.
    #[serde(default)]
    pub terminal_outcomes: Vec<crate::providers::TerminalOutcomeProjection>,
    /// Execution ownership note: Tenkai never prints runtime bearer tokens.
    pub execution_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSubscriptionView {
    pub product: String,
    pub channel: String,
    pub head: String,
    pub deployed: Option<String>,
    pub health: Option<String>,
    pub error: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPlanSummary {
    pub id: String,
    pub state: String,
    pub created_at: i64,
    pub step_count: usize,
    /// Bounded operator-facing lifecycle detail; never contains executable payloads.
    #[serde(default)]
    pub status_detail: String,
    /// Ordered, bounded summaries of executable steps.
    #[serde(default)]
    pub steps: Vec<EnvironmentPlanStepSummary>,
    /// True when `step_count` exceeds the number of returned summaries.
    #[serde(default)]
    pub steps_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPlanStepSummary {
    pub id: String,
    pub order: u32,
    pub product: String,
    pub action: String,
    pub from: Option<String>,
    pub to: String,
    pub release_id: String,
}

pub async fn status(ctx: &mut Ctx, env: &str) -> Result<Vec<StatusRow>> {
    let env_obj = environment(ctx, env).await?;
    let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;
    let mut rows = Vec::new();
    for ch in channels {
        let product = ch.properties.get("product").cloned().unwrap_or_default();
        rows.push(StatusRow {
            deployed: env_obj
                .properties
                .get(&format!("deployed.{product}"))
                .cloned(),
            health: env_obj
                .properties
                .get(&format!("deployment_health.{product}"))
                .cloned(),
            error: env_obj
                .properties
                .get(&format!("deployment_error.{product}"))
                .cloned(),
            channel: ch.properties.get("channel").cloned().unwrap_or_default(),
            head: ch
                .properties
                .get("current_version")
                .cloned()
                .unwrap_or_else(|| "-".into()),
            product,
        });
    }
    rows.sort_by(|a, b| a.product.cmp(&b.product));
    Ok(rows)
}

/// List registered environments with compact delivery summaries.
pub async fn list_environments(ctx: &mut Ctx) -> Result<Vec<EnvironmentListEntry>> {
    let mut environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    let mut entries = Vec::with_capacity(environments.len());
    for env_obj in environments {
        let name = env_obj.name.clone();
        let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;
        let deployed_product_count = env_obj
            .properties
            .keys()
            .filter(|key| key.starts_with("deployed.") && !key.starts_with("deployed_"))
            .count();
        let lease = crate::apply::inspect_environment_lease(ctx, &name).await?;
        entries.push(EnvironmentListEntry {
            name,
            id: env_obj.id,
            description: env_obj
                .properties
                .get("description")
                .cloned()
                .unwrap_or_default(),
            subscription_count: channels.len(),
            deployed_product_count,
            lease_held: lease.held,
        });
    }
    Ok(entries)
}

// Fleet posture aggregation, drift, and baseline I/O live in [`crate::fleet`].
// Re-export the pure interface so existing `plan::Fleet*` call sites keep working.
pub use crate::fleet::{
    FleetDriftSummary, FleetEnvironmentRow, FleetPostureSnapshot, FleetStatusReport,
    compare_fleet_posture, fleet_posture_snapshot, fleet_status_from_inspects,
    fleet_status_from_rows, is_hard_drift_posture, load_fleet_posture_baseline,
    write_fleet_posture_baseline,
};

/// Summarize delivery posture for every registered environment.
///
/// Complements `list_environments` / `inspect_environment` and server reconcile
/// diagnostics: this is the operator fleet table (drift, health, lease, plan).
/// Pure aggregation lives in [`crate::fleet`]; this function only loads inspect
/// reports from the application context.
pub async fn fleet_status(ctx: &mut Ctx) -> Result<FleetStatusReport> {
    let listed = list_environments(ctx).await?;
    let mut reports = Vec::with_capacity(listed.len());
    for entry in listed {
        reports.push(inspect_environment(ctx, &entry.name).await?);
    }
    Ok(fleet_status_from_inspects(reports))
}

/// Inspect one environment's subscriptions, lease/fence, and latest plan.
pub async fn inspect_environment(ctx: &mut Ctx, env: &str) -> Result<EnvironmentInspectReport> {
    inspect_environment_base(ctx, env).await
}

/// Inspect one environment and, when the context permits it, include the
/// bounded Tenkai-owned terminal-outcome projection for management readback.
pub async fn inspect_environment_with_outcomes(
    ctx: &mut Ctx,
    env: &str,
) -> Result<EnvironmentInspectReport> {
    let mut report = inspect_environment_base(ctx, env).await?;
    report.terminal_outcomes = ctx.terminal_outcomes(env, crate::now_millis())?;
    Ok(report)
}

async fn inspect_environment_base(ctx: &mut Ctx, env: &str) -> Result<EnvironmentInspectReport> {
    let env_obj = environment(ctx, env).await?;
    let rows = status(ctx, env).await?;
    let subscriptions = rows
        .into_iter()
        .map(|row| {
            let state = match (&row.deployed, row.health.as_deref()) {
                (_, Some("unknown")) => "unknown",
                (Some(version), _) if *version == row.head => "current",
                (Some(_), _) => "behind",
                (None, _) => "missing",
            }
            .to_string();
            EnvironmentSubscriptionView {
                product: row.product,
                channel: row.channel,
                head: row.head,
                deployed: row.deployed,
                health: row.health,
                error: row.error,
                state,
            }
        })
        .collect();
    let facts = environment_facts_from_object(&env_obj);
    let lease = crate::apply::inspect_environment_lease(ctx, env).await?;
    let latest_plan = latest_plan_for_environment(ctx, env).await?;
    Ok(EnvironmentInspectReport {
        name: env_obj.name,
        id: env_obj.id,
        description: env_obj
            .properties
            .get("description")
            .cloned()
            .unwrap_or_default(),
        subscriptions,
        facts,
        lease,
        latest_plan,
        terminal_outcomes: Vec::new(),
        execution_note: "Apply leases and runtime credentials are distinct; inspect never prints bearer tokens. Server-side runtime-token environments are not executed by the embedded server executor."
            .into(),
    })
}

fn environment_facts_from_object(env_obj: &Object) -> std::collections::BTreeMap<String, String> {
    let mut facts = std::collections::BTreeMap::new();
    for (key, value) in &env_obj.properties {
        if let Some(name) = key.strip_prefix(ENVIRONMENT_FACT_PREFIX) {
            facts.insert(name.to_string(), value.clone());
        }
    }
    facts
}

pub(crate) fn validate_fact_key(key: &str) -> Result<()> {
    if !ENVIRONMENT_FACT_KEYS.contains(&key) {
        bail!(
            "unknown environment fact {key:?}; allowed: {}",
            ENVIRONMENT_FACT_KEYS.join(", ")
        );
    }
    Ok(())
}

fn validate_fact_value(key: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("environment fact {key} must not be empty");
    }
    if value
        .chars()
        .any(|c| c.is_control() || c == '\n' || c == '\r')
    {
        bail!("environment fact {key} must not contain control characters");
    }
    // Reject values that look like secrets/credentials.
    let lower = value.to_ascii_lowercase();
    for needle in ["bearer ", "password=", "secret=", "token="] {
        if lower.contains(needle) {
            bail!("environment fact {key} must not contain credential material");
        }
    }
    if matches!(key, "memory_gib" | "free_disk_gib") {
        let parsed: u64 = value
            .parse()
            .with_context(|| format!("environment fact {key} must be a non-negative integer"))?;
        if parsed == 0 {
            bail!("environment fact {key} must be greater than zero");
        }
    }
    Ok(())
}

/// Set a capability/inventory fact on an environment.
pub async fn set_environment_fact(
    ctx: &mut Ctx,
    env: &str,
    key: &str,
    value: &str,
) -> Result<String> {
    validate_fact_key(key)?;
    validate_fact_value(key, value)?;
    let mut env_obj = environment(ctx, env).await?;
    env_obj
        .properties
        .insert(format!("{ENVIRONMENT_FACT_PREFIX}{key}"), value.to_string());
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} fact {key}={value}"))
}

/// Apply admitted inventory facts from a runtime heartbeat report (#136).
///
/// Only [`ENVIRONMENT_FACT_KEYS`] are accepted (via [`set_environment_fact`]).
/// Unknown keys and credential-like values fail closed before any write.
pub async fn apply_runtime_inventory_facts(
    ctx: &mut Ctx,
    env: &str,
    facts: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<String>> {
    // Validate all first so a bad key never partially mutates.
    for (key, value) in facts {
        validate_fact_key(key)?;
        validate_fact_value(key, value)?;
    }
    let mut applied = Vec::with_capacity(facts.len());
    for (key, value) in facts {
        set_environment_fact(ctx, env, key, value).await?;
        applied.push(key.clone());
    }
    applied.sort();
    Ok(applied)
}

/// Clear one capability/inventory fact from an environment.
pub async fn clear_environment_fact(ctx: &mut Ctx, env: &str, key: &str) -> Result<String> {
    validate_fact_key(key)?;
    let mut env_obj = environment(ctx, env).await?;
    let property = format!("{ENVIRONMENT_FACT_PREFIX}{key}");
    if env_obj.properties.remove(&property).is_none() {
        bail!("environment {env} has no fact {key}");
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("cleared {env} fact {key}"))
}

/// List capability/inventory facts for an environment.
pub async fn list_environment_facts(
    ctx: &mut Ctx,
    env: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let env_obj = environment(ctx, env).await?;
    Ok(environment_facts_from_object(&env_obj))
}

/// Require a named fact for planning; fail closed when missing.
pub async fn require_environment_fact(ctx: &mut Ctx, env: &str, key: &str) -> Result<String> {
    validate_fact_key(key)?;
    let facts = list_environment_facts(ctx, env).await?;
    facts.get(key).cloned().with_context(|| {
        format!("environment {env} is missing required fact {key}; set it with `tenkaictl env facts set {env} {key}=…`")
    })
}

async fn latest_plan_for_environment(
    ctx: &mut Ctx,
    env: &str,
) -> Result<Option<EnvironmentPlanSummary>> {
    // Environment-scoped property query — not a full plan catalog scan.
    let plans = crate::plan::list_for_environment(ctx, env, None).await?;
    Ok(plans.into_iter().next_back().map(environment_plan_summary))
}

pub(crate) fn environment_plan_summary(plan: Plan) -> EnvironmentPlanSummary {
    const MAX_PLAN_STEP_SUMMARIES: usize = 256;
    let step_count = plan.steps.len();
    let status_detail = operator_safe_status_detail(&plan);
    let steps = plan
        .steps
        .into_iter()
        .take(MAX_PLAN_STEP_SUMMARIES)
        .map(|step| EnvironmentPlanStepSummary {
            id: step.id,
            order: step.order,
            product: step.product,
            action: step.action.to_string(),
            from: step.from,
            to: step.to,
            release_id: step.release_id,
        })
        .collect::<Vec<_>>();
    EnvironmentPlanSummary {
        id: plan.id,
        state: plan.state.to_string(),
        created_at: plan.created_at,
        step_count,
        status_detail,
        steps_truncated: steps.len() < step_count,
        steps,
    }
}

fn operator_safe_status_detail(plan: &Plan) -> String {
    match plan.state {
        PlanState::Blocked if plan.maintenance_blocked => {
            "blocked outside the configured maintenance window".into()
        }
        PlanState::Blocked => "blocked by Tenkai approval or policy requirements".into(),
        PlanState::Failed => {
            "plan execution failed; inspect authorized Tenkai audit evidence".into()
        }
        PlanState::Computed | PlanState::Running | PlanState::Succeeded => String::new(),
    }
}
