//! Environment identity, subscriptions, constraints, facts, observations, and readback.
//!
//! This module concentrates Environment invariants behind the application core's
//! in-process interface. Planning consumes Environment state but does not own its
//! mutation or operator readback rules.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::*;
use crate::pb::sekai::Object;
use crate::plan::{Plan, PlanState, Step};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeploymentTransition {
    Unchanged,
    Deployed {
        version: String,
        previous: Option<String>,
    },
    /// Same-version refresh: health and overlays change, rollback history does not.
    Refreshed,
    Unknown,
}

pub(crate) struct DeploymentObservation<'a> {
    pub environment: &'a str,
    pub plan_id: &'a str,
    pub step: &'a Step,
    pub status: &'a str,
    pub detail: &'a str,
    pub transition: DeploymentTransition,
}

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
        .insert(format!("deployment_health.{product}"), "healthy".into());
    object
        .properties
        .remove(&format!("deployment_error.{product}"));
    stamp_applied_overlays(object, product);
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

pub(crate) async fn record_deployed(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    environment_name: &str,
    product: &str,
    version: &str,
    previous: Option<&str>,
) -> Result<()> {
    let mut object = environment(ctx, environment_name).await?;
    object
        .properties
        .insert(format!("deployed.{product}"), version.to_string());
    object.properties.insert(
        format!("deployed_release.{product}"),
        release_id(product, version),
    );
    if let Some(previous) = previous {
        object
            .properties
            .insert(format!("deployed_prev.{product}"), previous.to_string());
    }
    object
        .properties
        .insert(format!("deployment_health.{product}"), "healthy".into());
    object
        .properties
        .remove(&format!("deployment_error.{product}"));
    stamp_applied_overlays(&mut object, product);
    object.updated = crate::now_millis();
    guarded_update(ctx, lease, object).await
}

pub(crate) async fn record_unknown(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    environment_name: &str,
    product: &str,
    detail: &str,
) -> Result<()> {
    let mut object = environment(ctx, environment_name).await?;
    transition_deployment(
        &mut object,
        product,
        &DeploymentTransition::Unknown,
        detail,
        crate::now_millis(),
    );
    clear_unknown_origin(&mut object, product);
    guarded_update(ctx, lease, object).await
}

pub(crate) async fn record_deployment_observation(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    observation: DeploymentObservation<'_>,
) -> Result<()> {
    let observed_at = crate::now_millis();
    let attempt_id = deployment_id(
        observation.environment,
        &observation.step.product,
        observed_at,
    );
    let mut deployment = Object {
        id: attempt_id.clone(),
        kind: KIND_DEPLOYMENT.into(),
        name: format!(
            "{} {} -> {} ({})",
            observation.step.product,
            observation.step.from.as_deref().unwrap_or("none"),
            observation.step.to,
            observation.environment
        ),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("environment".into(), observation.environment.to_string()),
            ("product".into(), observation.step.product.clone()),
            (
                "from_version".into(),
                observation.step.from.clone().unwrap_or_default(),
            ),
            ("to_version".into(), observation.step.to.clone()),
            ("status".into(), "failed".into()),
            ("detail".into(), "deployment bookkeeping incomplete".into()),
            ("lease_generation".into(), lease.generation.to_string()),
        ]),
        created: observed_at,
        updated: observed_at,
    };
    ctx.guarded_create(
        deployment.clone(),
        crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    crate::apply::refresh_environment_lease(ctx, lease).await?;
    ctx.link(
        &attempt_id,
        &observation.step.release_id,
        REL_DEPLOYED_RELEASE,
    )
    .await?;
    crate::apply::refresh_environment_lease(ctx, lease).await?;
    ctx.link(
        &attempt_id,
        &env_id(observation.environment),
        REL_IN_ENVIRONMENT,
    )
    .await?;
    crate::apply::refresh_environment_lease(ctx, lease).await?;
    ctx.link(&attempt_id, observation.plan_id, REL_PART_OF_PLAN)
        .await?;

    deployment
        .properties
        .insert("status".into(), observation.status.into());
    deployment
        .properties
        .insert("detail".into(), observation.detail.into());
    deployment.updated = crate::now_millis();
    let mut environment = if ctx.outcome_export_enabled()
        || observation.transition != DeploymentTransition::Unchanged
    {
        Some(environment(ctx, observation.environment).await?)
    } else {
        None
    };
    if let Some(environment) = environment.as_mut()
        && observation.transition != DeploymentTransition::Unchanged
    {
        transition_deployment(
            environment,
            &observation.step.product,
            &observation.transition,
            observation.detail,
            deployment.updated,
        );
        if observation.transition == DeploymentTransition::Unknown {
            environment.properties.insert(
                format!("deployment_unknown_plan.{}", observation.step.product),
                observation.plan_id.into(),
            );
            environment.properties.insert(
                format!("deployment_unknown_step.{}", observation.step.product),
                observation.step.id.clone(),
            );
            environment.properties.insert(
                format!("deployment_unknown_attempt.{}", observation.step.product),
                attempt_id.clone(),
            );
        }
    }
    let provider_events = if ctx.outcome_export_enabled() {
        let plan = crate::plan::load(ctx, observation.plan_id).await?;
        let environment = environment
            .as_ref()
            .expect("outcome export loads Environment");
        crate::terminal_outcome::classify(
            observation.step.action,
            crate::terminal_outcome::Observation::Controller {
                status: observation.status,
                detail: observation.detail,
                had_previous_release: observation.step.from.is_some(),
            },
        )
        .map(|terminal_state| {
            crate::providers::terminal_outcome_record(
                &plan,
                observation.step,
                &attempt_id,
                terminal_state,
                environment,
                deployment.updated,
            )
            .map_err(anyhow::Error::from)
        })
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let update_result = if ctx.outcome_export_enabled() {
        let mut objects = vec![deployment];
        if observation.transition != DeploymentTransition::Unchanged {
            objects.push(environment.expect("an Environment transition loads its object"));
        }
        ctx.guarded_update_objects_with_provider_events(
            &objects,
            crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
            &lease.environment,
            &lease.fencing_token,
            &provider_events,
        )
        .await
    } else {
        if observation.transition != DeploymentTransition::Unchanged {
            guarded_update(
                ctx,
                lease,
                environment.expect("an Environment transition loads its object"),
            )
            .await?;
        }
        guarded_update(ctx, lease, deployment).await
    };
    match update_result {
        Ok(()) => Ok(()),
        Err(error) => {
            let persisted = ctx.get(&attempt_id).await;
            if matches!(
                persisted,
                Ok(Some(ref object))
                    if object.properties.get("status").map(String::as_str) == Some(observation.status)
                        && object.properties.get("detail").map(String::as_str) == Some(observation.detail)
            ) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

async fn guarded_update(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    object: Object,
) -> Result<()> {
    ctx.guarded_update(
        object,
        crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

fn clear_unknown_origin(environment: &mut Object, product: &str) {
    for prefix in [
        "deployment_unknown_plan.",
        "deployment_unknown_step.",
        "deployment_unknown_attempt.",
    ] {
        environment.properties.remove(&format!("{prefix}{product}"));
    }
}

fn transition_deployment(
    environment: &mut Object,
    product: &str,
    transition: &DeploymentTransition,
    detail: &str,
    observed_at: i64,
) {
    match transition {
        DeploymentTransition::Unchanged => return,
        DeploymentTransition::Refreshed => {
            environment
                .properties
                .insert(format!("deployment_health.{product}"), "healthy".into());
            environment
                .properties
                .remove(&format!("deployment_error.{product}"));
            stamp_applied_overlays(environment, product);
            clear_unknown_origin(environment, product);
        }
        DeploymentTransition::Deployed { version, previous } => {
            environment
                .properties
                .insert(format!("deployed.{product}"), version.clone());
            environment.properties.insert(
                format!("deployed_release.{product}"),
                release_id(product, version),
            );
            if let Some(previous) = previous {
                environment
                    .properties
                    .insert(format!("deployed_prev.{product}"), previous.clone());
            }
            environment
                .properties
                .insert(format!("deployment_health.{product}"), "healthy".into());
            environment
                .properties
                .remove(&format!("deployment_error.{product}"));
            stamp_applied_overlays(environment, product);
            clear_unknown_origin(environment, product);
        }
        DeploymentTransition::Unknown => {
            environment
                .properties
                .remove(&format!("deployed.{product}"));
            environment
                .properties
                .remove(&format!("deployed_release.{product}"));
            environment
                .properties
                .insert(format!("deployment_health.{product}"), "unknown".into());
            environment
                .properties
                .insert(format!("deployment_error.{product}"), detail.into());
        }
    }
    environment.updated = observed_at;
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
    #[serde(default)]
    pub overlay_stale: bool,
}

/// Classify one subscription for inspect, status, and fleet posture.
pub fn subscription_state(
    deployed: Option<&str>,
    head: &str,
    health: Option<&str>,
    overlay_stale: bool,
) -> &'static str {
    match (deployed, health) {
        (_, Some("unknown")) => "unknown",
        (_, Some("unhealthy")) => "unhealthy",
        (Some(version), _) if version == head && overlay_stale => "config_stale",
        (Some(version), _) if version == head => "current",
        (Some(_), _) => "behind",
        (None, _) => "missing",
    }
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
    /// Non-secret product overlays as `product.key=value`.
    #[serde(default)]
    pub overlays: BTreeMap<String, String>,
    pub lease: crate::apply::EnvironmentLeaseInspect,
    /// Most recent plan for this environment by `created_at`, if any.
    pub latest_plan: Option<EnvironmentPlanSummary>,
    /// Bounded terminal-outcome identities and outbox delivery state. Event
    /// payloads and retry errors are intentionally excluded.
    #[serde(default)]
    pub terminal_outcomes: Vec<crate::providers::TerminalOutcomeProjection>,
    /// Execution ownership note: Tenkai never prints runtime bearer tokens.
    pub execution_note: String,
    /// Observed type digest used for workshop-module compatibility admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_type_digest: Option<String>,
    /// Observed runtime digest used for workshop-module compatibility admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_runtime_digest: Option<String>,
    /// Accepted workshop-module activation receipts for this environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub module_activations: Vec<crate::workshop_module::ModuleActivationReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSubscriptionView {
    pub product: String,
    pub channel: String,
    pub head: String,
    pub deployed: Option<String>,
    pub health: Option<String>,
    pub error: Option<String>,
    #[serde(default)]
    pub overlay_digest: Option<String>,
    #[serde(default)]
    pub applied_overlay: Option<String>,
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
    status_from_object(ctx, &env_obj).await
}

async fn status_from_object(ctx: &mut Ctx, env_obj: &Object) -> Result<Vec<StatusRow>> {
    let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;
    let mut rows = Vec::new();
    for ch in channels {
        let product = ch.properties.get("product").cloned().unwrap_or_default();
        let overlay_digest = overlay_digest_for(env_obj, &product);
        let applied = env_obj
            .properties
            .get(&format!("applied_config.{product}"))
            .cloned()
            .unwrap_or_default();
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
            overlay_stale: overlay_digest != applied,
            product,
        });
    }
    rows.sort_by(|a, b| a.product.cmp(&b.product));
    Ok(rows)
}

fn subscription_views_from_status(
    env_obj: &Object,
    rows: Vec<StatusRow>,
) -> Vec<EnvironmentSubscriptionView> {
    rows.into_iter()
        .map(|row| {
            let overlay_digest = overlay_digest_for(env_obj, &row.product);
            let applied_overlay = env_obj
                .properties
                .get(&format!("applied_config.{}", row.product))
                .cloned()
                .filter(|value| !value.is_empty());
            let config_stale = overlay_digest != applied_overlay.clone().unwrap_or_default();
            EnvironmentSubscriptionView {
                product: row.product.clone(),
                channel: row.channel,
                head: row.head.clone(),
                deployed: row.deployed.clone(),
                health: row.health.clone(),
                error: row.error,
                overlay_digest: (!overlay_digest.is_empty()).then_some(overlay_digest),
                applied_overlay,
                state: subscription_state(
                    row.deployed.as_deref(),
                    &row.head,
                    row.health.as_deref(),
                    config_stale,
                )
                .to_string(),
            }
        })
        .collect()
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
/// diagnostics: this is the operator fleet table (drift, health, lease).
/// Pure aggregation lives in [`crate::fleet`].
///
/// One pass over registered environments: subscription posture from the
/// environment object and its channel links. Does not inspect each environment
/// (facts, overlays, modules, or the plan catalog). Plan state belongs on
/// environment detail, not the fleet table. `latest_plan_state` on fleet rows
/// is therefore always `None`.
pub async fn fleet_status(ctx: &mut Ctx) -> Result<FleetStatusReport> {
    let mut environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    let mut reports = Vec::with_capacity(environments.len());
    for env_obj in environments {
        let rows = status_from_object(ctx, &env_obj).await?;
        let subscriptions = subscription_views_from_status(&env_obj, rows);
        let lease = crate::apply::inspect_environment_lease(ctx, &env_obj.name).await?;
        reports.push(EnvironmentInspectReport {
            name: env_obj.name,
            id: env_obj.id,
            description: env_obj
                .properties
                .get("description")
                .cloned()
                .unwrap_or_default(),
            subscriptions,
            facts: Default::default(),
            overlays: Default::default(),
            lease,
            latest_plan: None,
            terminal_outcomes: Vec::new(),
            execution_note: String::new(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
        });
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
    let rows = status_from_object(ctx, &env_obj).await?;
    let subscriptions = subscription_views_from_status(&env_obj, rows);
    let facts = environment_facts_from_object(&env_obj);
    let overlays = environment_overlays_from_object(&env_obj);
    let lease = crate::apply::inspect_environment_lease(ctx, env).await?;
    let latest_plan = latest_plan_for_environment(ctx, env).await?;
    let observed = crate::workshop_module::observed_from_object(&env_obj)?;
    let module_activations = crate::workshop_module::activations_from_object(&env_obj)?;
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
        overlays,
        lease,
        latest_plan,
        terminal_outcomes: Vec::new(),
        execution_note: "Apply leases and runtime credentials are distinct; inspect never prints bearer tokens. Server-side runtime-token environments are not executed by the embedded server executor."
            .into(),
        observed_type_digest: observed.as_ref().map(|value| value.type_digest.clone()),
        observed_runtime_digest: observed.map(|value| value.runtime_digest),
        module_activations,
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

const ENVIRONMENT_OVERLAY_PREFIX: &str = "overlay.";

fn reject_credential_material(label: &str, key: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} {key} must not be empty");
    }
    if value
        .chars()
        .any(|c| c.is_control() || c == '\n' || c == '\r')
    {
        bail!("{label} {key} must not contain control characters");
    }
    if value.contains(',') || value.contains('=') || value.contains('{') || value.contains('}') {
        bail!("{label} {key} must not contain ',', '=', '{{', or '}}'");
    }
    let compact_key = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    // Heuristic denylist, not a secret store. Unknown keys still accept
    // ordinary values; credential-like names and prefixes fail closed.
    for fragment in [
        "password",
        "passwd",
        "secret",
        "token",
        "bearer",
        "credential",
        "privatekey",
        "apikey",
        "accesskey",
        "sessionkey",
        "kubeconfig",
        "certificate",
        "clientkey",
    ] {
        if compact_key.contains(fragment) {
            bail!("{label} key {key} must not look like a credential name");
        }
    }
    let lower = value.to_ascii_lowercase();
    for needle in ["bearer ", "password=", "secret=", "token="] {
        if lower.contains(needle) {
            bail!("{label} {key} must not contain credential material");
        }
    }
    Ok(())
}

/// Digest of one product's non-secret overlays. Empty overlays yield an empty digest.
pub fn overlay_digest(values: &BTreeMap<String, String>) -> String {
    if values.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    for (key, value) in values {
        hasher.update(key.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

fn parse_overlay_map(raw: Option<&String>) -> Result<BTreeMap<String, String>> {
    match raw {
        None => Ok(BTreeMap::new()),
        Some(raw) if raw.is_empty() => Ok(BTreeMap::new()),
        Some(raw) => serde_json::from_str(raw)
            .with_context(|| "stored product overlay map is not valid JSON"),
    }
}

/// Current overlays for one product on an environment object.
pub fn product_overlays(env_obj: &Object, product: &str) -> Result<BTreeMap<String, String>> {
    parse_overlay_map(env_obj.properties.get(&format!("overlay.{product}")))
}

fn overlay_digest_for(env_obj: &Object, product: &str) -> String {
    product_overlays(env_obj, product)
        .ok()
        .map(|values| overlay_digest(&values))
        .unwrap_or_default()
}

fn stamp_applied_overlays(environment: &mut Object, product: &str) {
    let digest = overlay_digest_for(environment, product);
    if digest.is_empty() {
        environment
            .properties
            .remove(&format!("applied_config.{product}"));
        environment
            .properties
            .remove(&format!("config_digest.{product}"));
    } else {
        environment
            .properties
            .insert(format!("applied_config.{product}"), digest.clone());
        environment
            .properties
            .insert(format!("config_digest.{product}"), digest);
    }
}

fn environment_overlays_from_object(env_obj: &Object) -> BTreeMap<String, String> {
    let mut overlays = BTreeMap::new();
    for (key, raw) in &env_obj.properties {
        let Some(product) = key.strip_prefix(ENVIRONMENT_OVERLAY_PREFIX) else {
            continue;
        };
        if let Ok(values) = parse_overlay_map(Some(raw)) {
            for (overlay_key, value) in values {
                overlays.insert(format!("{product}.{overlay_key}"), value);
            }
        }
    }
    overlays
}

fn persist_product_overlays(
    env_obj: &mut Object,
    product: &str,
    values: &BTreeMap<String, String>,
) {
    let digest = overlay_digest(values);
    if values.is_empty() {
        env_obj.properties.remove(&format!("overlay.{product}"));
        env_obj
            .properties
            .remove(&format!("config_digest.{product}"));
    } else {
        env_obj.properties.insert(
            format!("overlay.{product}"),
            serde_json::to_string(values).expect("overlay map is JSON-serializable"),
        );
        env_obj
            .properties
            .insert(format!("config_digest.{product}"), digest);
    }
}

/// Set a non-secret overlay for one product in an environment.
pub async fn set_environment_overlay(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    key: &str,
    value: &str,
) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("product", product)?;
    validate_identifier("overlay key", key)?;
    reject_credential_material("overlay", key, value)?;
    let mut env_obj = environment(ctx, env).await?;
    let mut values = product_overlays(&env_obj, product)?;
    values.insert(key.to_string(), value.to_string());
    persist_product_overlays(&mut env_obj, product, &values);
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} overlay {product}.{key}={value}"))
}

/// Clear one overlay key, or every overlay for the product when `key` is `None`.
pub async fn clear_environment_overlay(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    key: Option<&str>,
) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("product", product)?;
    let mut env_obj = environment(ctx, env).await?;
    let mut values = product_overlays(&env_obj, product)?;
    match key {
        Some(key) => {
            validate_identifier("overlay key", key)?;
            if values.remove(key).is_none() {
                bail!("environment {env} has no overlay {product}.{key}");
            }
            persist_product_overlays(&mut env_obj, product, &values);
            env_obj.updated = crate::now_millis();
            ctx.put(env_obj).await?;
            Ok(format!("cleared {env} overlay {product}.{key}"))
        }
        None => {
            if values.is_empty() {
                bail!("environment {env} has no overlays for {product}");
            }
            persist_product_overlays(&mut env_obj, product, &BTreeMap::new());
            env_obj.updated = crate::now_millis();
            ctx.put(env_obj).await?;
            Ok(format!("cleared {env} overlays for {product}"))
        }
    }
}

/// List overlays for one product, or every product when `product` is `None`.
pub async fn list_environment_overlays(
    ctx: &mut Ctx,
    env: &str,
    product: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let env_obj = environment(ctx, env).await?;
    match product {
        Some(product) => {
            validate_identifier("product", product)?;
            Ok(product_overlays(&env_obj, product)?
                .into_iter()
                .map(|(key, value)| (format!("{product}.{key}"), value))
                .collect())
        }
        None => Ok(environment_overlays_from_object(&env_obj)),
    }
}

/// Record observed mid-life health without changing the deployed pin.
pub async fn record_observed_health(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    healthy: bool,
    detail: &str,
) -> Result<()> {
    validate_identifier("environment", env)?;
    validate_identifier("product", product)?;
    let mut env_obj = environment(ctx, env).await?;
    env_obj.properties.insert(
        format!("deployment_health.{product}"),
        if healthy { "healthy" } else { "unhealthy" }.into(),
    );
    if healthy || detail.is_empty() {
        env_obj
            .properties
            .remove(&format!("deployment_error.{product}"));
    } else {
        env_obj
            .properties
            .insert(format!("deployment_error.{product}"), detail.into());
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn environment_object() -> Object {
        Object {
            id: env_id("stage"),
            kind: KIND_ENVIRONMENT.into(),
            name: "stage".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("deployment_health.api".into(), "unknown".into()),
                ("deployment_error.api".into(), "old failure".into()),
                ("deployment_unknown_plan.api".into(), "old-plan".into()),
                ("deployment_unknown_step.api".into(), "old-step".into()),
                (
                    "deployment_unknown_attempt.api".into(),
                    "old-attempt".into(),
                ),
            ]),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn deployed_observation_replaces_unknown_state() {
        let mut environment = environment_object();

        transition_deployment(
            &mut environment,
            "api",
            &DeploymentTransition::Deployed {
                version: "2.0.0".into(),
                previous: Some("1.0.0".into()),
            },
            "",
            42,
        );

        assert_eq!(environment.properties.get("deployed.api").unwrap(), "2.0.0");
        assert_eq!(
            environment.properties.get("deployed_release.api").unwrap(),
            &release_id("api", "2.0.0")
        );
        assert_eq!(
            environment.properties.get("deployed_prev.api").unwrap(),
            "1.0.0"
        );
        assert_eq!(
            environment.properties.get("deployment_health.api").unwrap(),
            "healthy"
        );
        assert!(
            !environment
                .properties
                .contains_key("deployment_unknown_plan.api")
        );
        assert_eq!(environment.updated, 42);
    }

    #[test]
    fn unknown_observation_clears_claimed_deployment() {
        let mut environment = environment_object();
        environment
            .properties
            .insert("deployed.api".into(), "1.0.0".into());
        environment
            .properties
            .insert("deployed_release.api".into(), release_id("api", "1.0.0"));

        transition_deployment(
            &mut environment,
            "api",
            &DeploymentTransition::Unknown,
            "cleanup failed",
            84,
        );

        assert!(!environment.properties.contains_key("deployed.api"));
        assert!(!environment.properties.contains_key("deployed_release.api"));
        assert_eq!(
            environment.properties.get("deployment_health.api").unwrap(),
            "unknown"
        );
        assert_eq!(
            environment.properties.get("deployment_error.api").unwrap(),
            "cleanup failed"
        );
        assert_eq!(environment.updated, 84);
    }

    #[test]
    fn subscription_state_distinguishes_health_and_overlay_drift() {
        assert_eq!(
            subscription_state(Some("1.0.0"), "1.0.0", Some("healthy"), false),
            "current"
        );
        assert_eq!(
            subscription_state(Some("1.0.0"), "1.0.0", Some("healthy"), true),
            "config_stale"
        );
        assert_eq!(
            subscription_state(Some("1.0.0"), "1.0.0", Some("unhealthy"), false),
            "unhealthy"
        );
        assert_eq!(
            subscription_state(Some("1.0.0"), "1.0.0", Some("unknown"), true),
            "unknown"
        );
        assert_eq!(
            subscription_state(Some("1.0.0"), "2.0.0", Some("healthy"), false),
            "behind"
        );
        assert_eq!(subscription_state(None, "1.0.0", None, false), "missing");
    }

    #[test]
    fn overlay_digest_is_order_independent_and_empty_when_unset() {
        let mut first = BTreeMap::new();
        first.insert("region".into(), "eu".into());
        first.insert("replicas".into(), "3".into());
        let mut second = BTreeMap::new();
        second.insert("replicas".into(), "3".into());
        second.insert("region".into(), "eu".into());
        assert_eq!(overlay_digest(&first), overlay_digest(&second));
        assert!(overlay_digest(&BTreeMap::new()).is_empty());
    }

    #[test]
    fn overlay_values_reject_credential_material() {
        let err = reject_credential_material("overlay", "replicas", "bearer abc")
            .unwrap_err()
            .to_string();
        assert!(err.contains("credential material"), "{err}");
        let err = reject_credential_material("overlay", "api_token", "n1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("credential name"), "{err}");
    }

    #[test]
    fn overlay_digest_changes_when_a_value_changes() {
        let mut first = BTreeMap::new();
        first.insert("region".into(), "eu".into());
        let mut second = BTreeMap::new();
        second.insert("region".into(), "us".into());
        assert_ne!(overlay_digest(&first), overlay_digest(&second));
    }

    #[tokio::test]
    async fn fleet_status_walks_registered_environments_once() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-fleet-status-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "prod", "Prod").await.unwrap();
        env_add(&mut ctx, "stage", "Stage").await.unwrap();
        let report = fleet_status(&mut ctx).await.unwrap();
        assert_eq!(report.environment_count, 2);
        assert_eq!(
            report
                .environments
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            ["prod", "stage"]
        );
        assert!(
            report
                .environments
                .iter()
                .all(|row| row.posture == "empty" && row.latest_plan_state.is_none())
        );
        let _ = std::fs::remove_file(&database);
    }
}
