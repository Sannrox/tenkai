//! Environment identity, subscriptions, constraints, facts, observations, and readback.
//!
//! This module concentrates Environment invariants behind the application core's
//! in-process interface. Planning consumes Environment state but does not own its
//! mutation or operator readback rules.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};

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
    /// The product's release was uninstalled; it is the rollback target.
    Removed {
        version: String,
    },
    Unknown,
}

pub(crate) struct DeploymentObservation<'a> {
    pub environment: &'a str,
    pub plan_id: &'a str,
    pub step: &'a Step,
    pub status: &'a str,
    pub detail: &'a str,
    pub transition: DeploymentTransition,
    /// When the step's execution began in this process, for the feedback
    /// observation's duration (#802).
    pub started_at_ms: Option<i64>,
    pub cause: Option<&'a crate::apply::DeploymentCause>,
    pub restore: Option<&'a crate::apply::DeploymentCause>,
}

/// Durable evidence explaining why an environment is no longer operational.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentRetirement {
    pub reason: String,
    pub actor: String,
    pub retired_at: i64,
}

const RETIREMENT_REASON: &str = "tenkai.retirement.reason";
const RETIREMENT_ACTOR: &str = "tenkai.retirement.actor";
const RETIREMENT_AT: &str = "tenkai.retirement.at";
pub(crate) const TENANT_RETIREMENT_KEY: &str = "_tenkai_retirement";

fn retirement_from_properties(
    properties: &HashMap<String, String>,
) -> Option<EnvironmentRetirement> {
    Some(EnvironmentRetirement {
        reason: properties.get(RETIREMENT_REASON)?.clone(),
        actor: properties.get(RETIREMENT_ACTOR)?.clone(),
        retired_at: properties.get(RETIREMENT_AT)?.parse().ok()?,
    })
}

pub fn retirement_from_configuration_json(
    configuration_json: &str,
) -> Option<EnvironmentRetirement> {
    let value: serde_json::Value = serde_json::from_str(configuration_json).ok()?;
    if let Some(properties) = value
        .get("properties")
        .and_then(serde_json::Value::as_object)
    {
        let retirement = (|| {
            Some(EnvironmentRetirement {
                reason: properties.get(RETIREMENT_REASON)?.as_str()?.to_owned(),
                actor: properties.get(RETIREMENT_ACTOR)?.as_str()?.to_owned(),
                retired_at: properties.get(RETIREMENT_AT)?.as_str()?.parse().ok()?,
            })
        })();
        if retirement.is_some() {
            return retirement;
        }
    }
    serde_json::from_value(value.get(TENANT_RETIREMENT_KEY)?.clone()).ok()
}

pub(crate) fn with_tenant_retirement(
    configuration_json: &str,
    retirement: &EnvironmentRetirement,
) -> Result<String> {
    let mut value = serde_json::from_str::<serde_json::Value>(configuration_json)
        .unwrap_or_else(|_| serde_json::json!({ "configuration": configuration_json }));
    if !value.is_object() {
        value = serde_json::json!({ "configuration": value });
    }
    value.as_object_mut().expect("object value").insert(
        TENANT_RETIREMENT_KEY.into(),
        serde_json::to_value(retirement)?,
    );
    Ok(serde_json::to_string(&value)?)
}

pub(crate) fn retirement_from_object(object: &Object) -> Option<EnvironmentRetirement> {
    retirement_from_properties(&object.properties)
}

pub(crate) fn is_retired_object(object: &Object) -> bool {
    retirement_from_object(object).is_some()
}

/// Return the registered environment only while it remains operational.
pub(crate) async fn active_environment(ctx: &mut Ctx, name: &str) -> Result<Object> {
    let object = environment(ctx, name).await?;
    if retirement_from_object(&object).is_some() {
        bail!("environment {name} is retired and cannot accept new delivery work");
    }
    Ok(object)
}

pub(crate) async fn environment_retirement(
    ctx: &mut Ctx,
    name: &str,
) -> Result<Option<EnvironmentRetirement>> {
    let object = match ctx.get(&env_id(name)).await? {
        Some(object) if object.kind == KIND_ENVIRONMENT => object,
        _ => return Ok(None),
    };
    Ok(retirement_from_object(&object))
}

/// Persist operator retirement evidence. A held apply lease must be released
/// with the existing unlock path before the terminal lifecycle transition.
pub async fn retire_environment(
    ctx: &mut Ctx,
    name: &str,
    reason: &str,
    actor: &str,
) -> Result<EnvironmentRetirement> {
    anyhow::ensure!(
        ctx.is_embedded(),
        "retirement through a remote catalog must use the authenticated management route"
    );
    validate_identifier("environment", name)?;
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "retirement reason must not be empty");
    anyhow::ensure!(reason.len() <= 1024, "retirement reason exceeds 1024 bytes");
    anyhow::ensure!(
        !actor.trim().is_empty(),
        "retirement actor must not be empty"
    );
    let mut object = environment(ctx, name).await?;
    if let Some(retirement) = retirement_from_object(&object) {
        return Ok(retirement);
    }

    if crate::apply::inspect_environment_lease(ctx, name)
        .await?
        .held
    {
        bail!(
            "environment {name} has an apply in progress; run `tenkaictl env unlock {name}` after verifying it is safe"
        );
    }
    let retirement = EnvironmentRetirement {
        reason: reason.to_owned(),
        actor: actor.to_owned(),
        retired_at: crate::now_millis(),
    };
    object
        .properties
        .insert(RETIREMENT_REASON.into(), retirement.reason.clone());
    object
        .properties
        .insert(RETIREMENT_ACTOR.into(), retirement.actor.clone());
    object
        .properties
        .insert(RETIREMENT_AT.into(), retirement.retired_at.to_string());
    object.updated = retirement.retired_at;
    match ctx.put(object).await {
        Ok(_) => Ok(retirement),
        Err(error) => match environment_retirement(ctx, name).await {
            Ok(Some(retirement)) => Ok(retirement),
            Ok(None) => Err(error),
            Err(read_error) => Err(error.context(format!(
                "reloading retirement evidence also failed: {read_error:#}"
            ))),
        },
    }
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
        if retirement_from_object(&existing).is_some() {
            bail!(
                "environment {name} is retired; registering it again requires a new environment name"
            );
        }
        crate::maintenance::ensure_configuration(ctx, name).await?;
        return Ok(format!("environment {name} already registered"));
    }
    let object = environment_record(None, name, description, now)?;
    match ctx.create_once(object).await {
        Ok(_) => {}
        Err(status) if crate::client::is_unique_conflict(&status) => {}
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
        match unknown_origin.clone() {
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
    // An operator resolving an unknown state is a committed outcome too
    // (#802); its identity is the deployment attempt that left it unknown.
    let feedback = match (&unknown_origin, was_unknown) {
        ((Some(plan_id), Some(step_id), Some(deployment_id)), true) => {
            // An unreadable origin still leaves a degraded observation.
            let action = match crate::plan::load(ctx, plan_id).await {
                Ok(plan) => plan
                    .steps
                    .iter()
                    .find(|step| &step.id == step_id)
                    .map(|step| step.action),
                Err(_) => None,
            };
            vec![crate::feedback_observation::FeedbackObservation::capture(
                crate::feedback_observation::Capture {
                    id: &format!("{deployment_id}:reconciled:{observed_at}"),
                    operation: crate::feedback_observation::Operation::UnknownReconciliation,
                    environment: env,
                    product,
                    plan_id,
                    step_id,
                    action,
                    release_id: &deployed
                        .map(|version| release_id(product, version))
                        .unwrap_or_default(),
                    status: "reconciled",
                    reason: crate::feedback_observation::Reason::Reconciled,
                    started_at_ms: None,
                    lease_generation: 0,
                    observed_at_ms: observed_at,
                    context: Default::default(),
                },
            )]
        }
        _ => Vec::new(),
    };
    // Confirming the release already recorded keeps the peers it was
    // granted; a different or no release has no known grant.
    let unchanged = deployed.is_some()
        && object
            .properties
            .get(&format!("deployed.{product}"))
            .map(String::as_str)
            == deployed;
    let kept_peers = unchanged
        .then(|| crate::dependency_document::applied_peers(&object, product))
        .filter(|peers| !peers.is_empty());
    update_reconciled_deployment_object(
        ctx,
        &mut object,
        product,
        product,
        deployed,
        None,
        observed_at,
    )
    .await?;
    crate::dependency_document::stamp(ctx, &mut object, product, kept_peers.as_ref()).await?;
    ctx.put_with_provider_events(object, &provider_events, &feedback)
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
    instance: &str,
    deployed: Option<&str>,
    sealed: Option<&[crate::plan::SealedStep]>,
    observed_at: i64,
) -> Result<()> {
    let key = if instance.is_empty() {
        product
    } else {
        instance
    };
    match deployed {
        Some(version) => {
            validate_identifier("version", version)?;
            let release = release_id(product, version);
            if ctx.get(&release).await?.is_none() {
                bail!("release {product}@{version} is not published");
            }
            object
                .properties
                .insert(format!("deployed.{key}"), version.into());
            object
                .properties
                .insert(format!("deployed_release.{key}"), release);
            stamp_deployment(object, key);
        }
        None => {
            object.properties.remove(&format!("deployed.{key}"));
            object.properties.remove(&format!("deployed_release.{key}"));
            object.properties.remove(&format!("{DEPLOYMENT_AT}{key}"));
        }
    }
    object
        .properties
        .insert(format!("deployment_health.{key}"), "healthy".into());
    object.properties.remove(&format!("deployment_error.{key}"));
    stamp_applied_overlays(object, product, instance, sealed);
    object.properties.remove(&format!("deployed_prev.{key}"));
    for prefix in [
        "deployment_unknown_plan.",
        "deployment_unknown_step.",
        "deployment_unknown_attempt.",
    ] {
        object.properties.remove(&format!("{prefix}{key}"));
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
        // A removal leaves nothing deployed; the removed release is the
        // rollback target, as when the server runs it.
        if step.action == crate::plan::Action::Remove {
            transition_deployment(
                object,
                &step.product,
                step.instance_name(),
                None,
                &DeploymentTransition::Removed {
                    version: step.to.clone(),
                },
                "",
                observed_at,
            );
            continue;
        }
        let previous_key = format!("deployed_prev.{}", step.instance_name());
        let kept_previous = object.properties.get(&previous_key).cloned();
        update_reconciled_deployment_object(
            ctx,
            object,
            &step.product,
            step.instance_name(),
            Some(&step.to),
            Some(&step.sealed),
            observed_at,
        )
        .await?;
        if step.delivers_dependencies() {
            crate::dependency_document::stamp(
                ctx,
                object,
                step.instance_name(),
                step.granted_peers(),
            )
            .await?;
        }
        // As server execution records it, so a runtime-run component rolls
        // back to the version it replaced (#685). A same-version step (a
        // restart) replaced nothing and keeps the version recorded before.
        match step.from.as_deref().filter(|previous| *previous != step.to) {
            Some(previous) => {
                object.properties.insert(previous_key, previous.to_string());
            }
            None => {
                if let Some(kept) = kept_previous {
                    object.properties.insert(previous_key, kept);
                }
            }
        }
    }
    Ok(())
}

/// Record a runtime's failed removal of `step`'s instance as unknown: it may
/// be partly removed, and the next plan removes its target again (ADR 0049).
pub(crate) fn record_removal_unknown(
    object: &mut Object,
    step: &Step,
    detail: &str,
    observed_at: i64,
) {
    transition_deployment(
        object,
        &step.product,
        step.instance_name(),
        None,
        &DeploymentTransition::Unknown,
        detail,
        observed_at,
    );
}

pub(crate) async fn record_deployed(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    environment_name: &str,
    step: &Step,
    version: &str,
    previous: Option<&str>,
) -> Result<()> {
    let product = step.product.as_str();
    let instance = step.instance_name();
    let key = instance;
    let mut object = environment(ctx, environment_name).await?;
    object
        .properties
        .insert(format!("deployed.{key}"), version.to_string());
    object.properties.insert(
        format!("deployed_release.{key}"),
        release_id(product, version),
    );
    stamp_deployment(&mut object, key);
    if let Some(previous) = previous {
        object
            .properties
            .insert(format!("deployed_prev.{key}"), previous.to_string());
    }
    object
        .properties
        .insert(format!("deployment_health.{key}"), "healthy".into());
    object.properties.remove(&format!("deployment_error.{key}"));
    stamp_applied_overlays(&mut object, product, instance, Some(&step.sealed));
    if step.delivers_dependencies() {
        crate::dependency_document::stamp(ctx, &mut object, key, step.granted_peers()).await?;
    }
    object.updated = crate::now_millis();
    guarded_update(ctx, lease, object).await
}

pub(crate) async fn record_unknown(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    environment_name: &str,
    product: &str,
    instance: &str,
    detail: &str,
) -> Result<()> {
    let mut object = environment(ctx, environment_name).await?;
    transition_deployment(
        &mut object,
        product,
        instance,
        None,
        &DeploymentTransition::Unknown,
        detail,
        crate::now_millis(),
    );
    clear_unknown_origin(&mut object, instance);
    guarded_update(ctx, lease, object).await
}

/// Record one deployment attempt and return its id (#1054, #1076).
pub(crate) async fn record_deployment_observation(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    observation: DeploymentObservation<'_>,
) -> Result<String> {
    let observed_at = crate::now_millis();
    let instance = observation.step.instance_name();
    let attempt_id = deployment_id(observation.environment, instance, observed_at);
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
            ("instance".into(), instance.to_string()),
            (
                "from_version".into(),
                observation.step.from.clone().unwrap_or_default(),
            ),
            ("to_version".into(), observation.step.to.clone()),
            ("status".into(), "failed".into()),
            ("detail".into(), "deployment bookkeeping incomplete".into()),
            ("lease_generation".into(), lease.generation.to_string()),
            ("action".into(), observation.step.action.to_string()),
            ("plan_id".into(), observation.plan_id.to_string()),
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
    let classified = observation.cause.cloned().or_else(|| {
        if matches!(observation.status, "failed" | "rolled_back") && !observation.detail.is_empty()
        {
            Some(crate::apply::DeploymentCause::classify(observation.detail))
        } else {
            None
        }
    });
    if let Some(cause) = classified.as_ref()
        && let Some(encoded) = cause.to_property()
    {
        deployment.properties.insert("cause".into(), encoded);
    }
    if let Some(restore) = observation.restore
        && let Some(encoded) = restore.to_property()
    {
        deployment.properties.insert("restore".into(), encoded);
    }
    deployment.updated = crate::now_millis();
    let mut environment = if ctx.outcome_export_enabled()
        || observation.transition != DeploymentTransition::Unchanged
        || matches!(observation.status, "failed" | "rolled_back" | "succeeded")
    {
        Some(environment(ctx, observation.environment).await?)
    } else {
        None
    };
    let failed_target_before = environment.as_ref().and_then(|environment| {
        environment
            .properties
            .get(&failed_target_key(instance))
            .cloned()
    });
    if let Some(environment) = environment.as_mut() {
        transition_deployment(
            environment,
            &observation.step.product,
            instance,
            Some(&observation.step.sealed),
            &observation.transition,
            observation.detail,
            deployment.updated,
        );
        let failed_target_key = self::failed_target_key(instance);
        if matches!(observation.status, "failed" | "rolled_back")
            && observation.step.action != crate::plan::Action::Rollback
        {
            environment.properties.insert(
                failed_target_key.clone(),
                observation.step.release_id.clone(),
            );
            environment.properties.insert(
                format!("failed_target_plan.{instance}"),
                observation.plan_id.into(),
            );
            environment.properties.insert(
                format!("failed_target_at.{instance}"),
                deployment.updated.to_string(),
            );
            record_failed_target_error(
                &mut environment.properties,
                instance,
                &observation.step.release_id,
                observation.detail,
            );
            if let Some(summary) = classified.as_ref().map(|cause| cause.summary.as_str()) {
                record_failed_target_summary(
                    &mut environment.properties,
                    instance,
                    &observation.step.release_id,
                    summary,
                );
            }
        } else if observation.status == "succeeded"
            && environment.properties.get(&failed_target_key) == Some(&observation.step.release_id)
            && matches!(
                observation.transition,
                DeploymentTransition::Deployed { .. }
                    | DeploymentTransition::Refreshed
                    | DeploymentTransition::Removed { .. }
            )
        {
            environment.properties.remove(&failed_target_key);
            environment
                .properties
                .remove(&format!("failed_target_plan.{instance}"));
            environment
                .properties
                .remove(&format!("failed_target_summary.{instance}"));
        }
        if observation.transition == DeploymentTransition::Unknown {
            environment.properties.insert(
                format!("deployment_unknown_plan.{instance}"),
                observation.plan_id.into(),
            );
            environment.properties.insert(
                format!("deployment_unknown_step.{instance}"),
                observation.step.id.clone(),
            );
            environment.properties.insert(
                format!("deployment_unknown_attempt.{instance}"),
                attempt_id.clone(),
            );
        }
        if observation.status == "succeeded" {
            match observation.transition {
                DeploymentTransition::Deployed { .. } | DeploymentTransition::Refreshed
                    if observation.step.delivers_dependencies() =>
                {
                    crate::dependency_document::stamp(
                        ctx,
                        environment,
                        observation.step.instance_name(),
                        observation.step.granted_peers(),
                    )
                    .await?;
                }
                DeploymentTransition::Removed { .. } => {
                    for prefix in [
                        crate::dependency_document::APPLIED_PROPERTY_PREFIX,
                        crate::dependency_document::APPLIED_PEERS_PREFIX,
                    ] {
                        environment
                            .properties
                            .remove(&format!("{prefix}{}", observation.step.instance_name()));
                    }
                }
                _ => {}
            }
        }
    }
    let webhook_endpoints = environment
        .as_ref()
        .map(crate::deploy_webhook::configured_endpoints)
        .unwrap_or_default();
    let needs_plan = ctx.outcome_export_enabled() || !webhook_endpoints.is_empty();
    let plan = if needs_plan {
        Some(crate::plan::load(ctx, observation.plan_id).await?)
    } else {
        None
    };
    let mut provider_events = if ctx.outcome_export_enabled() {
        let plan = plan.as_ref().expect("outcome export loads Plan");
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
                plan,
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
    if !webhook_endpoints.is_empty() {
        let source_revision =
            crate::deploy_webhook::source_revision(ctx, &observation.step.release_id).await;
        let summary = classified.as_ref().and_then(|cause| {
            matches!(observation.status, "failed" | "rolled_back").then_some(cause.summary.as_str())
        });
        provider_events.extend(crate::deploy_webhook::records_for_observation(
            &webhook_endpoints,
            plan.as_ref().expect("webhooks load Plan"),
            observation.step,
            observation.status,
            deployment.updated,
            &source_revision,
            Some(attempt_id.as_str()),
            summary,
        ));
    }
    let environment_changed = observation.transition != DeploymentTransition::Unchanged
        || matches!(observation.status, "failed" | "rolled_back");
    // Retry and recovery context (#803): whether this step retried the
    // release the environment held as failed, read before this outcome
    // changed it, and the reason that admitted a recalled rollback.
    let failed_target_retry =
        failed_target_before.as_deref() == Some(observation.step.release_id.as_str());
    let recovery_reason = match (&plan, observation.step.action) {
        (Some(plan), _) => plan.recalled_recovery_reason.clone(),
        (None, crate::plan::Action::Rollback) => crate::plan::load(ctx, observation.plan_id)
            .await
            .ok()
            .and_then(|plan| plan.recalled_recovery_reason),
        _ => None,
    };
    // Captured always, independent of outcome export, and committed with the
    // deployment record wherever this process holds the store (#802).
    let feedback = [crate::feedback_observation::FeedbackObservation::capture(
        crate::feedback_observation::Capture {
            id: &attempt_id,
            operation: crate::feedback_observation::Operation::ApplyStep,
            environment: observation.environment,
            product: &observation.step.product,
            plan_id: observation.plan_id,
            step_id: &observation.step.id,
            action: Some(observation.step.action),
            release_id: &observation.step.release_id,
            status: observation.status,
            reason: crate::feedback_observation::controller_reason(
                observation.status,
                observation.detail,
                observation.transition == DeploymentTransition::Unknown,
            ),
            started_at_ms: observation.started_at_ms,
            lease_generation: lease.generation,
            observed_at_ms: deployment.updated,
            context: crate::feedback_observation::RetryContext {
                takeover: lease.took_over,
                failed_target_retry,
                recovery_reason,
                ..Default::default()
            },
        },
    )];
    let update_result = if ctx.outcome_export_enabled()
        || !provider_events.is_empty()
        || ctx.is_embedded()
        || ctx.has_catalog()
    {
        let mut objects = vec![deployment];
        if environment_changed {
            objects.push(environment.expect("an Environment transition loads its object"));
        }
        ctx.guarded_update_objects_with_provider_events(
            &objects,
            crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
            &lease.environment,
            &lease.fencing_token,
            &provider_events,
            &feedback,
        )
        .await
    } else {
        if environment_changed {
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
        Ok(()) => Ok(attempt_id),
        Err(error) => {
            let persisted = ctx.get(&attempt_id).await;
            if matches!(
                persisted,
                Ok(Some(ref object))
                    if object.properties.get("status").map(String::as_str) == Some(observation.status)
                        && object.properties.get("detail").map(String::as_str) == Some(observation.detail)
            ) {
                Ok(attempt_id)
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

/// Prefix of `deployment_at.{instance}`: when the server last recorded a
/// release deployed to the instance, in Unix milliseconds. Workload
/// certificate evidence older than it no longer describes the instance
/// (ADR 0046 §7).
pub const DEPLOYMENT_AT: &str = "deployment_at.";

/// Stamp that a release was just deployed to `key`.
fn stamp_deployment(object: &mut Object, key: &str) {
    object.properties.insert(
        format!("{DEPLOYMENT_AT}{key}"),
        crate::now_millis().to_string(),
    );
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
    instance: &str,
    sealed: Option<&[crate::plan::SealedStep]>,
    transition: &DeploymentTransition,
    detail: &str,
    observed_at: i64,
) {
    let key = if instance.is_empty() {
        product
    } else {
        instance
    };
    match transition {
        DeploymentTransition::Unchanged => return,
        DeploymentTransition::Refreshed => {
            environment
                .properties
                .insert(format!("deployment_health.{key}"), "healthy".into());
            environment
                .properties
                .remove(&format!("deployment_error.{key}"));
            stamp_applied_overlays(environment, product, instance, sealed);
            environment.properties.remove(&format!("spec_drift.{key}"));
            clear_unknown_origin(environment, key);
        }
        DeploymentTransition::Deployed { version, previous } => {
            environment
                .properties
                .insert(format!("deployed.{key}"), version.clone());
            environment.properties.insert(
                format!("deployed_release.{key}"),
                release_id(product, version),
            );
            stamp_deployment(environment, key);
            if let Some(previous) = previous {
                environment
                    .properties
                    .insert(format!("deployed_prev.{key}"), previous.clone());
            }
            environment
                .properties
                .insert(format!("deployment_health.{key}"), "healthy".into());
            environment
                .properties
                .remove(&format!("deployment_error.{key}"));
            stamp_applied_overlays(environment, product, instance, sealed);
            environment.properties.remove(&format!("spec_drift.{key}"));
            clear_unknown_origin(environment, key);
        }
        DeploymentTransition::Removed { version } => {
            for prefix in [
                "deployed",
                "deployed_release",
                "deployment_health",
                "deployment_error",
                "applied_dependencies",
                "applied_peers",
                "applied_config",
                "applied_spec",
                "spec_drift",
            ] {
                environment.properties.remove(&format!("{prefix}.{key}"));
            }
            environment
                .properties
                .insert(format!("deployed_prev.{key}"), version.clone());
            clear_unknown_origin(environment, key);
        }
        DeploymentTransition::Unknown => {
            environment.properties.remove(&format!("deployed.{key}"));
            environment
                .properties
                .remove(&format!("deployed_release.{key}"));
            environment
                .properties
                .remove(&format!("{DEPLOYMENT_AT}{key}"));
            environment
                .properties
                .insert(format!("deployment_health.{key}"), "unknown".into());
            environment
                .properties
                .insert(format!("deployment_error.{key}"), detail.into());
        }
    }
    environment.updated = observed_at;
}

/// Subscribe an environment to a product channel. The channel must exist.
/// `instance` defaults to the product name (ADR 0044 §1).
pub async fn subscribe(ctx: &mut Ctx, env: &str, product: &str, channel: &str) -> Result<String> {
    subscribe_instance(ctx, env, product, channel, None).await
}

/// Subscribe a named instance of `product` in `env` to `channel`.
pub async fn subscribe_instance(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    channel: &str,
    instance: Option<&str>,
) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("product", product)?;
    validate_identifier("channel", channel)?;
    let instance = instance_or_product(instance, product)?;
    let eid = env_id(env);
    let existing = active_environment(ctx, env).await?;
    crate::preview::refuse_channel_promotion(&existing)?;
    let cid = channel_id(product, channel);
    if ctx.get(&cid).await?.is_none() {
        bail!("channel {product}/{channel} does not exist — promote a release into it first");
    }
    if instance != product {
        return subscribe_named_instance(ctx, env, product, channel, &instance, &eid, &cid).await;
    }
    if named_instance_exists(ctx, &eid, &instance).await? {
        bail!("environment {env} already has instance {instance}");
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

async fn subscribe_named_instance(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    channel: &str,
    instance: &str,
    eid: &str,
    cid: &str,
) -> Result<String> {
    let iid = instance_id(env, instance);
    if let Some(existing) = ctx.get(&iid).await? {
        if existing.properties.get("product").map(String::as_str) != Some(product) {
            bail!("environment {env} already has instance {instance}");
        }
        let links = ctx.links(&iid, REL_SUBSCRIBES).await?;
        if links.iter().any(|link| link.to_id == cid) {
            return Ok(format!(
                "{env} instance {instance} already subscribed to {product}/{channel}"
            ));
        }
        for link in links {
            ctx.unlink(&iid, &link.to_id, REL_SUBSCRIBES).await?;
        }
        ctx.link(eid, &iid, REL_HAS_INSTANCE).await?;
        ctx.link(&iid, cid, REL_SUBSCRIBES).await?;
        return Ok(format!(
            "{env} instance {instance} subscribed to {product}/{channel}"
        ));
    }
    for linked in ctx.linked(eid, REL_HAS_INSTANCE, "out").await? {
        if linked.properties.get("name").map(String::as_str) == Some(instance) {
            bail!("environment {env} already has instance {instance}");
        }
    }
    if default_instance_exists(ctx, eid, instance).await? {
        bail!("environment {env} already has instance {instance}");
    }
    let now = crate::now_millis();
    ctx.put(Object {
        id: iid.clone(),
        kind: KIND_INSTANCE.into(),
        name: instance.to_string(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("environment".into(), env.to_string()),
            ("name".into(), instance.to_string()),
            ("product".into(), product.to_string()),
        ]),
        created: now,
        updated: now,
    })
    .await?;
    ctx.link(eid, &iid, REL_HAS_INSTANCE).await?;
    ctx.link(&iid, cid, REL_SUBSCRIBES).await?;
    Ok(format!(
        "{env} instance {instance} subscribed to {product}/{channel}"
    ))
}

async fn named_instance_exists(ctx: &mut Ctx, eid: &str, instance: &str) -> Result<bool> {
    for linked in ctx.linked(eid, REL_HAS_INSTANCE, "out").await? {
        if linked.properties.get("name").map(String::as_str) == Some(instance) {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn default_instance_exists(ctx: &mut Ctx, eid: &str, instance: &str) -> Result<bool> {
    for channel in ctx.linked(eid, REL_SUBSCRIBES, "out").await? {
        if channel.properties.get("product").map(String::as_str) == Some(instance) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Remove `product` from `env`'s desired state. When a release of it is
/// deployed, it must be a `host` release: the next approved plan uninstalls
/// it through the root-side applier (ADR 0041 section 2). Removing a
/// deployed release of another executor is not supported, so it is refused
/// here rather than left running unmanaged, and so is a host release when
/// `executors` has no host executor to plan its removal with.
///
/// It runs under the environment apply lease, so no apply starts, or
/// installs the product, between reading what is deployed and removing the
/// subscription. `fence` runs inside the lease with the generation that
/// claiming it superseded and refuses a stale one before any change, as
/// environment configuration changes do.
pub async fn unsubscribe(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    expected_version: Option<&str>,
    executors: &crate::software_executor::SoftwareExecutors,
    fence: impl FnOnce(u64) -> Result<()>,
) -> Result<String> {
    unsubscribe_instance(ctx, env, product, None, expected_version, executors, fence).await
}

/// Remove a named instance, or the default instance when `instance` is
/// omitted. `expected_version` names the release the operator means to
/// remove (ADR 0049 §4): required while one is recorded, and refused when
/// another is.
pub async fn unsubscribe_instance(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    instance: Option<&str>,
    expected_version: Option<&str>,
    executors: &crate::software_executor::SoftwareExecutors,
    fence: impl FnOnce(u64) -> Result<()>,
) -> Result<String> {
    validate_identifier("environment", env)?;
    let instance = instance_or_product(instance, product)?;
    let lease =
        crate::apply::claim_environment(ctx, env, &format!("unsubscribe:{instance}")).await?;
    let unsubscribed = match fence(lease.generation.saturating_sub(1)) {
        Ok(()) => unsubscribe_held(ctx, env, product, &instance, expected_version, executors).await,
        Err(error) => Err(error),
    };
    let released = crate::apply::release_environment(ctx, &lease).await;
    match (unsubscribed, released) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("releasing the environment apply lease")),
    }
}

/// Whether `env` subscribes to a channel of `product`.
pub(crate) async fn subscribes(ctx: &mut Ctx, env: &str, product: &str) -> Result<bool> {
    Ok(ctx
        .linked(&env_id(env), REL_SUBSCRIBES, "out")
        .await?
        .iter()
        .any(|channel| channel.properties.get("product").map(String::as_str) == Some(product)))
}

/// [`unsubscribe`] under the environment's apply lease.
async fn unsubscribe_held(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    instance: &str,
    expected_version: Option<&str>,
    executors: &crate::software_executor::SoftwareExecutors,
) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("product", product)?;
    let eid = env_id(env);
    let existing = active_environment(ctx, env).await?;
    let property = |key: &str| {
        existing
            .properties
            .get(&format!("{key}.{instance}"))
            .cloned()
    };
    // What may be on the host: the deployed release, and a release whose
    // failed step left the deployment unknown.
    let candidates: Vec<String> = [
        property("deployed").map(|version| release_id(product, &version)),
        property("failed_target"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if candidates.is_empty() && property("deployment_health").as_deref() == Some("unknown") {
        bail!(
            "deployment state of {instance} in {env} is unknown; record it with `tenkaictl env reconcile` before unsubscribing"
        );
    }
    // The deployed version, or the failed target's when that is all that
    // is recorded (ADR 0049 §4).
    let recorded = property("deployed").or_else(|| {
        property("failed_target").and_then(|release| {
            crate::plan::split_release_id(&release).map(|(_, version)| version.to_string())
        })
    });
    match (recorded.as_deref(), expected_version) {
        (Some(recorded), Some(expected)) if recorded != expected => bail!(
            "{instance} in {env} is recorded at {recorded}, not {expected}; nothing was unsubscribed"
        ),
        (Some(recorded), None) => bail!(
            "{instance} in {env} is recorded at {recorded}; name the version to remove with --version {recorded}"
        ),
        (None, Some(expected)) => {
            bail!("{instance} in {env} has no recorded release, not {expected}")
        }
        _ => {}
    }
    let mut host = false;
    for release in &candidates {
        let manifest = crate::plan::stored_release_manifest(ctx, release).await?;
        if manifest.deploy.executor == Some(crate::software_executor::SoftwareExecutorKind::Host) {
            host = true;
        } else {
            crate::plan::require_removable(executors, release, &manifest)?;
        }
    }
    if host {
        // The uninstall this promises is planned from the applier's records:
        // this server's own, or those the environment's runtime reports.
        crate::host_records::HostRecords::of(ctx, executors, env).await?;
    }
    refuse_dependents(ctx, env, &existing, instance).await?;
    let removed = if instance == product {
        let mut removed = 0;
        for link in ctx.links(&eid, REL_SUBSCRIBES).await? {
            let channel = ctx
                .get(&link.to_id)
                .await?
                .with_context(|| format!("subscription link {} has no channel", link.id))?;
            if channel.properties.get("product").map(String::as_str) == Some(product) {
                ctx.unlink(&eid, &link.to_id, REL_SUBSCRIBES).await?;
                removed += 1;
            }
        }
        removed
    } else {
        let iid = instance_id(env, instance);
        match ctx.get(&iid).await? {
            Some(object)
                if object.properties.get("product").map(String::as_str) == Some(product) =>
            {
                ctx.unlink(&eid, &iid, REL_HAS_INSTANCE).await?;
                for link in ctx.links(&iid, REL_SUBSCRIBES).await? {
                    ctx.unlink(&iid, &link.to_id, REL_SUBSCRIBES).await?;
                }
                ctx.delete(&iid).await?;
                1
            }
            Some(_) | None => 0,
        }
    };
    if removed == 0 {
        return Ok(format!("{env} is not subscribed to {instance}"));
    }
    Ok(if candidates.is_empty() {
        format!("{env} unsubscribed from {instance}")
    } else {
        format!("{env} unsubscribed from {instance}; the next approved plan removes it")
    })
}

/// Refuse to unsubscribe `instance` while another subscribed instance depends
/// on it (ADR 0049 §3): it holds a binding to it (ADR 0044 §3), or needs it as
/// the sole provider of a required contract (ADR 0043 §5). Dependents being
/// unsubscribed too do not count; the next plan removes them first.
async fn refuse_dependents(
    ctx: &mut Ctx,
    env: &str,
    existing: &Object,
    instance: &str,
) -> Result<()> {
    let subscribed: BTreeSet<String> = list_subscriptions(ctx, existing)
        .await?
        .into_iter()
        .map(|subscription| subscription.instance)
        .filter(|name| name != instance)
        .collect();
    let bindings =
        crate::environment_bindings::EnvironmentBindings::from_properties(&existing.properties);
    let mut dependents: BTreeSet<String> = bindings
        .iter()
        .filter(|(dependent, _, provider)| *provider == instance && subscribed.contains(*dependent))
        .map(|(dependent, _, _)| dependent.to_string())
        .collect();
    let before: BTreeMap<String, crate::software_compatibility::CompatibilityProfile> =
        crate::dependency_document::deployed_set(ctx, existing)
            .await?
            .into_iter()
            .filter(|(name, _)| name == instance || subscribed.contains(name))
            .map(|(name, deployed)| (name, deployed.profile))
            .collect();
    let mut after = before.clone();
    after.remove(instance);
    if let Some(refusal) = crate::software_compatibility::remaining_dependent_refusal_bound(
        &after, &before, &bindings,
    )? {
        dependents.insert(refusal.dependent);
    }
    if !dependents.is_empty() {
        bail!(
            "{instance} in {env} still has subscribed dependents: {}; unsubscribe them first",
            dependents.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

pub(crate) async fn environment(ctx: &mut Ctx, env: &str) -> Result<Object> {
    validate_identifier("environment", env)?;
    match ctx.get(&env_id(env)).await? {
        Some(o) => Ok(o),
        None => {
            // Box the miss path so listing names does not enlarge every caller.
            Box::pin(missing_environment(ctx, env)).await
        }
    }
}

async fn missing_environment(ctx: &mut Ctx, env: &str) -> Result<Object> {
    bail!(
        "{}",
        unregistered_environment_message(env, &registered_environment_names(ctx).await?)
    )
}

/// Names of environments that are still operational, sorted.
pub async fn registered_environment_names(ctx: &mut Ctx) -> Result<Vec<String>> {
    let mut environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(environments
        .into_iter()
        .filter(|object| retirement_from_object(object).is_none())
        .map(|object| object.name)
        .collect())
}

fn unregistered_environment_message(env: &str, registered: &[String]) -> String {
    if registered.is_empty() {
        format!("environment {env} is not registered; the store has no environments")
    } else {
        format!(
            "environment {env} is not registered; registered: {}",
            registered.join(", ")
        )
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
    let property = constraint_property(kind, name, value)?;
    let mut env_obj = environment(ctx, env).await?;
    env_obj.properties.insert(property.clone(), value.into());
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} constraint {property}={value}"))
}

/// Validate one constraint and return the environment property it is stored in.
pub(crate) fn constraint_property(kind: &str, name: &str, value: &str) -> Result<String> {
    if value.trim().is_empty() {
        bail!("constraint value must not be empty");
    }
    Ok(match kind {
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
    })
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StatusRow {
    pub product: String,
    /// Instance this row describes. Equals `product` when unnamed (ADR 0044 §1).
    #[serde(default)]
    pub instance: String,
    pub channel: String,
    pub deployed: Option<String>,
    pub health: Option<String>,
    pub error: Option<String>,
    pub head: String,
    #[serde(default)]
    pub overlay_stale: bool,
    /// Present while the subscribed channel is held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub delivery_hold: Option<crate::delivery_hold::DeliveryHold>,
    /// Present while a required contract is unmet (ADR 0043).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub dependency_hold: Option<StatusDependencyHold>,
    /// Report-only live-spec comparison (#1028). Omitted when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub spec_drift: Option<crate::spec_drift::SpecDriftView>,
    /// The instance's workload certificate, as its runtime last reported
    /// it (ADR 0046 §3). Omitted when none was reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub certificate: Option<crate::certificate_reports::CertificateStatus>,
    /// Failing and warning checks from the latest health observation (#1057).
    /// Empty when none were reported or the observation is stale.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health_checks: Vec<crate::instance_health::HealthCheck>,
}

/// Unmet contract named by a dependency hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UnmetContract {
    pub contract: String,
    pub minimum: String,
    /// Satisfying provider instances when the contract is ambiguous.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}

/// Dependency hold carried on a status row (no product; the row already names it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StatusDependencyHold {
    pub release_id: String,
    pub contracts: Vec<UnmetContract>,
    pub held_at: i64,
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

/// Classify one status row. A dependency hold is `waiting`; health stays on
/// the row so recovery output can still print from `unknown`/`unhealthy`.
/// Spec drift only overrides a row that would otherwise be `current`.
pub fn status_state(row: &StatusRow) -> &'static str {
    if row.dependency_hold.is_some() {
        return "waiting";
    }
    let state = subscription_state(
        row.deployed.as_deref(),
        &row.head,
        row.health.as_deref(),
        row.overlay_stale,
    );
    if state == "current"
        && row
            .spec_drift
            .as_ref()
            .is_some_and(crate::spec_drift::SpecDriftView::is_modified)
    {
        crate::spec_drift::SPEC_DRIFT_MODIFIED
    } else {
        state
    }
}

/// Summary row for fleet listing (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentListEntry {
    pub name: String,
    pub id: String,
    pub description: String,
    pub subscription_count: usize,
    pub deployed_product_count: usize,
    pub lease_held: bool,
    /// The environment or one of its subscribed channels is held.
    #[serde(default)]
    pub delivery_held: bool,
}

/// Initial capability/inventory fact keys admitted for environments.
pub const ENVIRONMENT_FACT_KEYS: &[&str] = &[
    "architecture",
    "memory_gib",
    "accelerator",
    "free_disk_gib",
    "gpu_vendor",
    "gpu_family",
    "gpu_model",
    "gpu_vram_gib",
    "gpu_count",
    "gpu_driver_version",
    "gpu_runtime",
    "gpu_runtime_version",
    // Placement facts for replica topologies (#689).
    "host",
    "zone",
];

const ENVIRONMENT_FACT_PREFIX: &str = "fact.";

/// Detailed inspect report for one environment (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentInspectReport {
    pub name: String,
    pub id: String,
    pub description: String,
    pub subscriptions: Vec<EnvironmentSubscriptionView>,
    pub facts: std::collections::BTreeMap<String, String>,
    /// Non-secret product overlays as `product.key=value`.
    #[serde(default)]
    pub overlays: BTreeMap<String, String>,
    /// Effective non-secret config and declared secret names per product (#1019).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config: Vec<EnvironmentProductConfig>,
    pub lease: crate::apply::EnvironmentLeaseInspect,
    /// Most recent plan for this environment by `created_at`, if any.
    pub latest_plan: Option<EnvironmentPlanSummary>,
    /// Maintenance windows and their eligibility at inspect time. Absent for
    /// projections that do not read Tenkai-owned environment configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub maintenance: Option<EnvironmentMaintenanceInspect>,
    /// Environment constraints (`version_pin`, `version_range`, `require_fact`).
    #[serde(default)]
    pub constraints: Vec<EnvironmentConstraint>,
    /// Configured post-deploy webhooks (#820): URL, the name of the variable
    /// holding the HMAC secret, and events. The secret itself is never stored
    /// or returned. Edits are conditional on `lease.generation`.
    #[serde(default)]
    pub webhooks: Vec<crate::deploy_webhook::WebhookEndpoint>,
    /// The plan approval policy file this environment uses, as configured,
    /// when one is set (#820).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub approval_policy: Option<String>,
    /// Bounded terminal-outcome identities and outbox delivery state. Event
    /// payloads and retry errors are intentionally excluded.
    #[serde(default)]
    pub terminal_outcomes: Vec<crate::providers::TerminalOutcomeProjection>,
    /// Execution ownership note: Tenkai never prints runtime bearer tokens.
    pub execution_note: String,
    /// Observed type digest used for workshop-module compatibility admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub observed_type_digest: Option<String>,
    /// Observed runtime digest used for workshop-module compatibility admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub observed_runtime_digest: Option<String>,
    /// Accepted workshop-module activation receipts for this environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub module_activations: Vec<crate::workshop_module::ModuleActivationReceipt>,
    /// Present only for preview environments bound to a branch pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub preview: Option<crate::preview::PreviewInspect>,
    /// Present after this environment has been retired from operational use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub retirement: Option<EnvironmentRetirement>,
    /// Present while delivery is paused for this environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub delivery_hold: Option<crate::delivery_hold::DeliveryHold>,
    /// Active and upcoming dated change freezes. Omitted when none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_freezes: Vec<crate::delivery_hold::DeliveryFreeze>,
    /// Declared and derived criticality when either is set (#694).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub criticality: Option<EnvironmentCriticality>,
    /// Latest failed or rolled back attempt per instance (#1054).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub latest_failures: Vec<crate::deployment_history::DeploymentAttemptView>,
    /// Why sealed values would be lost with every runtime (ADR 0045 §7):
    /// no recovery key, or values without a wrap for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub sealed_recovery_warning: Option<String>,
    /// The workload identity issuer, its requested generation and its
    /// uploaded candidate (ADR 0046 §2), when any is set. Never a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub identity_issuer: Option<crate::identity_issuer::IssuerStatus>,
    /// The instances the next issuer rotation step waits for, each with why
    /// (ADR 0046 §7). Beside `identity_issuer`, whose shape older clients
    /// decode strictly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_issuer_waiting: Vec<String>,
}

/// Inspect copy of declared/derived criticality. Lives here so this module
/// does not import the criticality leaf (that cycle breaks `Send` on inspect).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentCriticality {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub effective: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub declared: Option<EnvironmentDeclaredCriticality>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub derived: Option<EnvironmentDerivedCriticality>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentDeclaredCriticality {
    pub level: String,
    pub owner: String,
    pub reason: String,
    pub set_at: i64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentDerivedCriticality {
    pub level: String,
    pub source: String,
    pub reason: String,
    pub generated_at: i64,
    pub imported_at: i64,
    pub age_ms: i64,
    pub stale: bool,
}

/// Read-only view of the environment's own maintenance schedule, evaluated
/// with the same rules as apply admission. Product maintenance windows
/// (`tenkaictl product maintenance`) are not included and may further
/// restrict when a plan touching that product can apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentMaintenanceInspect {
    /// `unrestricted` (no environment windows), `open`, `closed`, or
    /// `invalid`. Invalid configuration blocks apply until it is corrected.
    pub eligibility: String,
    /// When `open`: end of the current window, in Unix milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub open_until_ms: Option<i64>,
    /// When `closed`: next opening of any window, in Unix milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub next_opens_at_ms: Option<i64>,
    /// When `invalid`: why the configuration cannot be evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub detail: Option<String>,
    pub windows: Vec<EnvironmentMaintenanceWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentMaintenanceWindow {
    pub identity: String,
    /// IANA timezone of `start`.
    pub timezone: String,
    /// ISO weekday numbers: Monday is 1 and Sunday is 7.
    pub weekdays: Vec<u32>,
    /// Local wall-clock start in HH:MM form.
    pub start: String,
    pub duration_minutes: u32,
    /// Next start of this window strictly after inspect time, in Unix
    /// milliseconds; absent when the window cannot be evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub next_opens_at_ms: Option<i64>,
}

/// One environment constraint, as set by `tenkaictl env constraints set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentConstraint {
    /// `version_pin`, `version_range`, or `require_fact`.
    pub kind: String,
    /// Product for version constraints; fact key for `require_fact`.
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentSubscriptionView {
    pub product: String,
    /// Instance this subscription names. Equals `product` when unnamed.
    #[serde(default)]
    pub instance: String,
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
    /// Present while the subscribed channel is held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub delivery_hold: Option<crate::delivery_hold::DeliveryHold>,
    /// Report-only live-spec comparison (#1028). Omitted when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub spec_drift: Option<crate::spec_drift::SpecDriftView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentPlanSummary {
    pub id: String,
    pub state: String,
    pub created_at: i64,
    pub step_count: usize,
    /// `sha256:` digest of the versioned executable-plan encoding, the value
    /// the plan route returns and approvals bind to. Absent for projections
    /// without an executable plan, such as development fixtures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub digest: Option<String>,
    /// Bounded operator-facing lifecycle detail; never contains executable payloads.
    #[serde(default)]
    pub status_detail: String,
    /// Ordered, bounded summaries of executable steps.
    #[serde(default)]
    pub steps: Vec<EnvironmentPlanStepSummary>,
    /// True when `step_count` exceeds the number of returned summaries.
    #[serde(default)]
    pub steps_truncated: bool,
    /// Whether the latest plan was approved by policy or still needs a human.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub approval: Option<crate::approval_policy::PlanApprovalView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentPlanStepSummary {
    pub id: String,
    pub order: u32,
    pub product: String,
    /// Instance this step applies to. Equals `product` when unnamed.
    #[serde(default)]
    pub instance: String,
    pub action: String,
    pub from: Option<String>,
    pub to: String,
    pub release_id: String,
}

/// Effective overlay config for one product, with secret names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentProductConfig {
    pub product: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub defaults: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overlay: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub digest: String,
    /// Declared secret key names. Values are never stored or returned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
}

/// One channel subscription, keyed by instance (ADR 0044 §1).
pub(crate) struct Subscription {
    pub instance: String,
    pub product: String,
    pub channel: Object,
}

fn product_of_channel(channel: &Object) -> String {
    channel
        .properties
        .get("product")
        .cloned()
        .filter(|name| !name.is_empty())
        .or_else(|| {
            channel
                .id
                .strip_prefix("tenkai:channel:")
                .and_then(|rest| rest.split_once('/'))
                .map(|(product, _)| product.to_string())
        })
        .unwrap_or_default()
}

/// Default (env→channel) subscriptions plus named instance subscriptions.
pub(crate) async fn list_subscriptions(
    ctx: &mut Ctx,
    env_obj: &Object,
) -> Result<Vec<Subscription>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for instance in ctx.linked(&env_obj.id, REL_HAS_INSTANCE, "out").await? {
        let name = instance
            .properties
            .get("name")
            .cloned()
            .unwrap_or_else(|| instance.name.clone());
        let product = instance
            .properties
            .get("product")
            .cloned()
            .unwrap_or_default();
        let channels = ctx.linked(&instance.id, REL_SUBSCRIBES, "out").await?;
        let Some(channel) = channels.into_iter().next() else {
            continue;
        };
        let product = if product.is_empty() {
            product_of_channel(&channel)
        } else {
            product
        };
        if !seen.insert(name.clone()) {
            bail!("environment {} has duplicate instance {name}", env_obj.name);
        }
        out.push(Subscription {
            instance: name,
            product,
            channel,
        });
    }
    for channel in ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await? {
        let product = product_of_channel(&channel);
        if product.is_empty() || !seen.insert(product.clone()) {
            continue;
        }
        out.push(Subscription {
            instance: product.clone(),
            product,
            channel,
        });
    }
    out.sort_by(|left, right| left.instance.cmp(&right.instance));
    Ok(out)
}

pub async fn status(ctx: &mut Ctx, env: &str) -> Result<Vec<StatusRow>> {
    let env_obj = environment(ctx, env).await?;
    status_from_object(ctx, &env_obj).await
}

async fn status_from_object(ctx: &mut Ctx, env_obj: &Object) -> Result<Vec<StatusRow>> {
    let subscriptions = list_subscriptions(ctx, env_obj).await?;
    let certificates = crate::certificate_reports::reported(ctx, &env_obj.name).await?;
    let observations = crate::instance_health::reported(ctx, &env_obj.name).await?;
    let now_ms = crate::now_millis();
    let now_secs = now_ms / 1000;
    let max_age_ms = crate::instance_health::max_age_ms(env_obj);
    let mut rows = Vec::new();
    for sub in subscriptions {
        let product = sub.product;
        let instance = sub.instance;
        let ch = sub.channel;
        let channel = ch.properties.get("channel").cloned().unwrap_or_default();
        let delivery_hold = crate::delivery_hold::get(
            ctx,
            &crate::delivery_hold::HoldScope::channel(&product, &channel),
        )
        .await?;
        let applied_key = if instance.is_empty() {
            product.clone()
        } else {
            instance.clone()
        };
        let overlay_digest = crate::sealed_secret::instance_config_digest(
            env_obj,
            &overlay_digest_for(env_obj, &product),
            &applied_key,
        );
        let applied = env_obj
            .properties
            .get(&format!("applied_config.{applied_key}"))
            .cloned()
            .unwrap_or_default();
        let selected_release = crate::plan::resolve_subscription_selection(
            ctx,
            env_obj,
            &env_obj.name,
            &product,
            ch.properties
                .get("current_version")
                .map(String::as_str)
                .unwrap_or_default(),
            ch.properties
                .get("current_release")
                .map(String::as_str)
                .unwrap_or_default(),
        )
        .await;
        let held = selected_release.as_ref().is_ok_and(|(_, release)| {
            held_failed_target_release(&env_obj.properties, &instance) == Some(release.as_str())
        });
        let dependency_hold =
            dependency_hold(&env_obj.properties, &instance).map(|hold| hold.to_status_view());
        let apply_health = env_obj
            .properties
            .get(&format!("deployment_health.{instance}"))
            .cloned();
        let deployed_digest = match env_obj
            .properties
            .get(&format!("deployed_release.{applied_key}"))
        {
            Some(id) => ctx
                .get(id)
                .await?
                .and_then(|release| release.properties.get("artifact_digest").cloned()),
            None => None,
        };
        let (health, health_checks) = crate::instance_health::overlay(
            apply_health,
            observations.get(&applied_key),
            deployed_digest.as_deref(),
            now_ms,
            max_age_ms,
        );
        let certificate = certificates
            .get(&applied_key)
            .map(|report| report.status(now_secs));
        rows.push(StatusRow {
            instance: instance.clone(),
            deployed: env_obj
                .properties
                .get(&format!("deployed.{instance}"))
                .cloned(),
            health,
            error: if held
                && env_obj
                    .properties
                    .get(&format!("deployment_health.{instance}"))
                    .is_none_or(|health| health != "unknown")
            {
                let cause = held_failed_target_summary(&env_obj.properties, &instance)
                    .or_else(|| held_failed_target_error(&env_obj.properties, &instance))
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default();
                Some(format!("target failed{cause}; automatic retry held; create and approve an explicit plan to retry"))
            } else {
                env_obj
                    .properties
                    .get(&format!("deployment_error.{instance}"))
                    .cloned()
            },
            channel,
            head: ch
                .properties
                .get("current_version")
                .cloned()
                .unwrap_or_else(|| "-".into()),
            overlay_stale: overlay_digest != applied,
            product,
            delivery_hold,
            dependency_hold,
            spec_drift: spec_drift_from_object(env_obj, &applied_key),
            certificate,
            health_checks,
        });
    }
    rows.sort_by(|a, b| {
        a.instance
            .cmp(&b.instance)
            .then_with(|| a.product.cmp(&b.product))
    });
    Ok(rows)
}

fn subscription_views_from_status(
    env_obj: &Object,
    rows: Vec<StatusRow>,
) -> Vec<EnvironmentSubscriptionView> {
    rows.into_iter()
        .map(|row| {
            let applied_key = if row.instance.is_empty() {
                &row.product
            } else {
                &row.instance
            };
            let overlay_digest = crate::sealed_secret::instance_config_digest(
                env_obj,
                &overlay_digest_for(env_obj, &row.product),
                applied_key,
            );
            let applied_overlay = env_obj
                .properties
                .get(&format!("applied_config.{applied_key}"))
                .cloned()
                .filter(|value| !value.is_empty());
            let state = status_state(&row).to_string();
            EnvironmentSubscriptionView {
                product: row.product.clone(),
                instance: if row.instance.is_empty() {
                    row.product.clone()
                } else {
                    row.instance.clone()
                },
                channel: row.channel,
                head: row.head.clone(),
                deployed: row.deployed.clone(),
                health: row.health.clone(),
                error: row.error,
                overlay_digest: (!overlay_digest.is_empty()).then_some(overlay_digest),
                applied_overlay,
                state,
                delivery_hold: row.delivery_hold,
                spec_drift: row.spec_drift,
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
        if retirement_from_object(&env_obj).is_some() {
            continue;
        }
        let name = env_obj.name.clone();
        let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;
        let deployed_product_count = env_obj
            .properties
            .keys()
            .filter(|key| key.starts_with("deployed.") && !key.starts_with("deployed_"))
            .count();
        let lease = crate::apply::inspect_environment_lease(ctx, &name).await?;
        // Held when the environment itself or any subscribed channel is held.
        let mut scopes = vec![crate::delivery_hold::HoldScope::environment(&name)];
        scopes.extend(channels.iter().map(|channel| {
            let property = |key: &str| channel.properties.get(key).cloned().unwrap_or_default();
            crate::delivery_hold::HoldScope::channel(&property("product"), &property("channel"))
        }));
        let mut delivery_held = false;
        for scope in &scopes {
            if crate::delivery_hold::get(ctx, scope).await?.is_some() {
                delivery_held = true;
                break;
            }
        }
        if !delivery_held {
            delivery_held =
                crate::delivery_hold::environment_delivery_held(ctx, &name, crate::now_millis())
                    .await?;
        }
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
            delivery_held,
        });
    }
    Ok(entries)
}

// Fleet posture aggregation, drift, and baseline I/O live in [`crate::fleet`].
// Re-export the pure interface so existing `plan::Fleet*` call sites keep working.
pub use crate::fleet::{
    FleetDriftSummary, FleetEnvironmentRow, FleetPostureSnapshot, FleetStatusReport,
    OpenEnvironmentExposure, compare_fleet_posture, fleet_posture_snapshot,
    fleet_status_from_inspects, fleet_status_from_rows, is_hard_drift_posture,
    load_fleet_posture_baseline, overdue_exposures, write_fleet_posture_baseline,
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
        if retirement_from_object(&env_obj).is_some() {
            continue;
        }
        let rows = status_from_object(ctx, &env_obj).await?;
        let subscriptions = subscription_views_from_status(&env_obj, rows);
        let lease = crate::apply::inspect_environment_lease(ctx, &env_obj.name).await?;
        let retirement = retirement_from_object(&env_obj);
        let delivery_hold = crate::delivery_hold::get(
            ctx,
            &crate::delivery_hold::HoldScope::environment(&env_obj.name),
        )
        .await?;
        let delivery_freezes =
            crate::delivery_hold::visible_freezes(ctx, &env_obj.name, crate::now_millis()).await?;
        let criticality = criticality_from_properties(&env_obj.properties, crate::now_millis());
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
            config: Vec::new(),
            lease,
            latest_plan: None,
            maintenance: None,
            constraints: Vec::new(),
            webhooks: Vec::new(),
            approval_policy: None,
            terminal_outcomes: Vec::new(),
            execution_note: String::new(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
            preview: None,
            retirement,
            delivery_hold,
            delivery_freezes,
            criticality,
            latest_failures: Vec::new(),
            sealed_recovery_warning: None,
            identity_issuer: None,
            identity_issuer_waiting: Vec::new(),
        });
    }
    let mut report = fleet_status_from_inspects(reports);
    report.promotion_policies = crate::channel_promotion::status_snapshot(ctx).await?;
    let open_exposures = crate::exposure::open_environment_exposures(ctx).await?;
    for row in &mut report.environments {
        if let Some(exposures) = open_exposures.get(&row.name) {
            row.open_exposures = exposures.clone();
        }
    }
    Ok(report)
}

/// Inspect one environment's subscriptions, lease/fence, and latest plan.
pub async fn inspect_environment(ctx: &mut Ctx, env: &str) -> Result<EnvironmentInspectReport> {
    inspect_environment_base(ctx, env, crate::approval_policy::ExecutionPolicy::default()).await
}

/// Inspect one environment and, when the context permits it, include the
/// bounded Tenkai-owned terminal-outcome projection for management readback.
pub async fn inspect_environment_with_outcomes(
    ctx: &mut Ctx,
    env: &str,
) -> Result<EnvironmentInspectReport> {
    inspect_environment_for_policy(
        ctx,
        env,
        crate::approval_policy::ExecutionPolicy::from_host_env(),
    )
    .await
}

pub(crate) async fn inspect_environment_for_policy(
    ctx: &mut Ctx,
    env: &str,
    execution: crate::approval_policy::ExecutionPolicy,
) -> Result<EnvironmentInspectReport> {
    let mut report = inspect_environment_base(ctx, env, execution).await?;
    report.terminal_outcomes = ctx.terminal_outcomes(env, crate::now_millis()).await?;
    Ok(report)
}

async fn inspect_environment_base(
    ctx: &mut Ctx,
    env: &str,
    execution: crate::approval_policy::ExecutionPolicy,
) -> Result<EnvironmentInspectReport> {
    let env_obj = environment(ctx, env).await?;
    let rows = status_from_object(ctx, &env_obj).await?;
    let subscriptions = subscription_views_from_status(&env_obj, rows);
    let facts = environment_facts_from_object(&env_obj);
    let overlays = environment_overlays_from_object(&env_obj);
    let config = product_config_views(ctx, &env_obj).await?;
    let lease = crate::apply::inspect_environment_lease(ctx, env).await?;
    let latest_plan = latest_plan_for_environment(ctx, env, &env_obj.properties, execution).await?;
    let observed = crate::workshop_module::observed_from_object(&env_obj)?;
    let module_activations = crate::workshop_module::activations_from_object(&env_obj)?;
    let preview = crate::preview::inspect_from_object(&env_obj)?;
    let retirement = retirement_from_object(&env_obj);
    let delivery_hold = crate::delivery_hold::get(
        ctx,
        &crate::delivery_hold::HoldScope::environment(&env_obj.name),
    )
    .await?;
    let delivery_freezes =
        crate::delivery_hold::visible_freezes(ctx, &env_obj.name, crate::now_millis()).await?;
    let constraints = environment_constraints_from_object(&env_obj);
    let webhooks = crate::deploy_webhook::parse_endpoints(&env_obj)
        .with_context(|| format!("reading the webhooks of environment {env}"))?;
    let approval_policy = env_obj
        .properties
        .get(crate::approval_policy::PLAN_APPROVAL_POLICY_PROPERTY)
        .cloned();
    let now = chrono::DateTime::from_timestamp_millis(crate::now_millis())
        .context("current time is outside the supported maintenance-window range")?;
    let maintenance = maintenance_inspect(crate::maintenance::list(ctx, env).await, now);
    let criticality = criticality_from_properties(&env_obj.properties, crate::now_millis());
    let latest_failures = crate::deployment_history::latest_failures(ctx, env).await?;
    let sealed_recovery_warning =
        crate::sealed_secret::list_from_object(&env_obj, false)?.recovery_warning();
    let identity_issuer =
        Some(crate::identity_issuer::status(&env_obj)?).filter(|status| !status.is_empty());
    // Progress is optional here: an unreadable report shows as such instead
    // of failing the inspection.
    let identity_issuer_waiting = if identity_issuer.is_some() {
        crate::identity_issuer::rotation_waiting(ctx, &env_obj, crate::now_millis() / 1000)
            .await
            .unwrap_or_else(|error| vec![format!("rotation progress unreadable: {error:#}")])
    } else {
        Vec::new()
    };
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
        config,
        lease,
        latest_plan,
        maintenance: Some(maintenance),
        constraints,
        webhooks,
        approval_policy,
        terminal_outcomes: Vec::new(),
        execution_note: "Apply leases and runtime credentials are distinct; inspect never prints bearer tokens. Server-side runtime-token environments are not executed by the embedded server executor."
            .into(),
        observed_type_digest: observed.as_ref().map(|value| value.type_digest.clone()),
        observed_runtime_digest: observed.map(|value| value.runtime_digest),
        module_activations,
        preview,
        retirement,
        delivery_hold,
        delivery_freezes,
        criticality,
        latest_failures,
        sealed_recovery_warning,
        identity_issuer,
        identity_issuer_waiting,
    })
}

fn criticality_from_properties(
    properties: &HashMap<String, String>,
    now: i64,
) -> Option<EnvironmentCriticality> {
    let declared =
        properties
            .get("criticality.declared")
            .map(|level| EnvironmentDeclaredCriticality {
                level: level.clone(),
                owner: properties
                    .get("criticality.declared.owner")
                    .cloned()
                    .unwrap_or_default(),
                reason: properties
                    .get("criticality.declared.reason")
                    .cloned()
                    .unwrap_or_default(),
                set_at: properties
                    .get("criticality.declared.set_at")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0),
                source: "declared".into(),
            });
    let derived = properties.get("criticality.derived").map(|level| {
        let generated_at = properties
            .get("criticality.derived.generated_at")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let imported_at = properties
            .get("criticality.derived.imported_at")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let max_age_ms = properties
            .get("criticality.derived.max_age_ms")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let age_ms = now.saturating_sub(generated_at);
        EnvironmentDerivedCriticality {
            level: level.clone(),
            source: properties
                .get("criticality.derived.source")
                .cloned()
                .unwrap_or_default(),
            reason: properties
                .get("criticality.derived.reason")
                .cloned()
                .unwrap_or_default(),
            generated_at,
            imported_at,
            age_ms,
            stale: max_age_ms > 0 && age_ms > max_age_ms,
        }
    });
    if declared.is_none() && derived.is_none() {
        return None;
    }
    let effective = [
        declared.as_ref().map(|value| value.level.as_str()),
        derived
            .as_ref()
            .and_then(|value| (!value.stale).then_some(value.level.as_str())),
    ]
    .into_iter()
    .flatten()
    .max_by_key(|level| match *level {
        "low" => 0u8,
        "medium" => 1,
        "high" => 2,
        "critical" => 3,
        _ => 0,
    })
    .map(str::to_owned);
    Some(EnvironmentCriticality {
        effective,
        declared,
        derived,
    })
}

fn environment_constraints_from_object(env_obj: &Object) -> Vec<EnvironmentConstraint> {
    let mut constraints = env_obj
        .properties
        .iter()
        .filter_map(|(key, value)| {
            let (kind, name) = key.strip_prefix("constraint.")?.split_once('.')?;
            Some(EnvironmentConstraint {
                kind: kind.to_string(),
                name: name.to_string(),
                value: value.clone(),
            })
        })
        .collect::<Vec<_>>();
    constraints.sort_by(|left, right| (&left.kind, &left.name).cmp(&(&right.kind, &right.name)));
    constraints
}

/// Project maintenance configuration for inspect. A configuration that cannot
/// be read is reported as `invalid`, matching apply admission, rather than
/// failing the whole inspect report.
pub(crate) fn maintenance_inspect(
    windows: Result<Vec<crate::maintenance::Window>>,
    now: chrono::DateTime<chrono::Utc>,
) -> EnvironmentMaintenanceInspect {
    use crate::maintenance::{Eligibility, evaluate};

    let windows = match windows {
        Ok(windows) => windows,
        Err(error) => {
            return EnvironmentMaintenanceInspect {
                eligibility: "invalid".into(),
                open_until_ms: None,
                next_opens_at_ms: None,
                detail: Some(format!(
                    "maintenance window configuration is invalid: {error}"
                )),
                windows: Vec::new(),
            };
        }
    };
    let (eligibility, open_until_ms, next_opens_at_ms, detail) = match evaluate(&windows, now) {
        _ if windows.is_empty() => ("unrestricted", None, None, None),
        Eligibility::Open { closes_at, .. } => ("open", Some(closes_at), None, None),
        Eligibility::Closed { next_opens_at } => ("closed", None, next_opens_at, None),
        Eligibility::Invalid { detail } => ("invalid", None, None, Some(detail)),
    };
    let windows = windows
        .into_iter()
        .map(|window| {
            let next_opens_at_ms = crate::maintenance::next_start_after(&window, now)
                .map(|start| start.timestamp_millis());
            EnvironmentMaintenanceWindow {
                identity: window.identity,
                timezone: window.timezone,
                weekdays: window.weekdays,
                start: window.start,
                duration_minutes: window.duration_minutes,
                next_opens_at_ms,
            }
        })
        .collect();
    EnvironmentMaintenanceInspect {
        eligibility: eligibility.into(),
        open_until_ms,
        next_opens_at_ms,
        detail,
        windows,
    }
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

pub(crate) fn validate_fact_value(key: &str, value: &str) -> Result<()> {
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
    if matches!(key, "memory_gib" | "free_disk_gib" | "gpu_vram_gib") {
        let parsed: u64 = value
            .parse()
            .with_context(|| format!("environment fact {key} must be a non-negative integer"))?;
        if parsed == 0 {
            bail!("environment fact {key} must be greater than zero");
        }
    }
    if key == "gpu_count" {
        value
            .parse::<u64>()
            .with_context(|| format!("environment fact {key} must be a non-negative integer"))?;
    }
    if matches!(key, "gpu_driver_version" | "gpu_runtime_version")
        && crate::plan::dotted_version(value).is_none()
    {
        bail!("environment fact {key} must be a dotted numeric version");
    }
    Ok(())
}

/// Set a capability/inventory fact on an environment, as declared by an
/// operator (`env facts set`, the facts route).
pub async fn set_environment_fact(
    ctx: &mut Ctx,
    env: &str,
    key: &str,
    value: &str,
) -> Result<String> {
    validate_fact_key(key)?;
    validate_fact_value(key, value)?;
    let mut env_obj = environment(ctx, env).await?;
    record_fact(
        &mut env_obj,
        key,
        value,
        crate::runner_attestation::OPERATOR_FACT_SOURCE,
    );
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} fact {key}={value}"))
}

/// Write fact `key` with its provenance (#675).
fn record_fact(env_obj: &mut Object, key: &str, value: &str, source: &str) {
    env_obj
        .properties
        .insert(format!("{ENVIRONMENT_FACT_PREFIX}{key}"), value.to_string());
    env_obj.properties.insert(
        format!("{}{key}", crate::runner_attestation::FACT_SOURCE_PREFIX),
        source.to_string(),
    );
}

/// Apply admitted inventory facts from a runtime heartbeat report (#136).
///
/// Only [`ENVIRONMENT_FACT_KEYS`] are accepted. Unknown keys and
/// credential-like values fail closed before any write. While the
/// environment requires runner attestation (#675), a report that
/// contradicts an operator-declared fact is refused whole with
/// [`crate::runner_attestation::AttestationRefusal::InventoryContradictsDeclaredFact`]
/// and overwrites nothing.
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
    if facts.is_empty() {
        return Ok(Vec::new());
    }
    let mut env_obj = environment(ctx, env).await?;
    if crate::runner_attestation::policy_from_properties(&env_obj.properties)?.is_some() {
        let declared = crate::runner_attestation::declared_facts(&env_obj.properties);
        if let Some(key) = facts
            .iter()
            .find(|(key, value)| {
                declared
                    .get(*key)
                    .is_some_and(|declared| declared != *value)
            })
            .map(|(key, _)| key.clone())
        {
            return Err(
                crate::runner_attestation::AttestationRefusal::InventoryContradictsDeclaredFact {
                    key,
                }
                .into(),
            );
        }
    }
    let declared = crate::runner_attestation::declared_facts(&env_obj.properties);
    let mut applied = Vec::with_capacity(facts.len());
    for (key, value) in facts {
        // An equal operator declaration keeps its provenance.
        if declared.get(key) != Some(value) {
            record_fact(
                &mut env_obj,
                key,
                value,
                crate::runner_attestation::RUNTIME_FACT_SOURCE,
            );
        }
        applied.push(key.clone());
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
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
    env_obj.properties.remove(&format!(
        "{}{key}",
        crate::runner_attestation::FACT_SOURCE_PREFIX
    ));
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

/// Record the environment-scoped artifact mirror for one origin registry.
pub async fn set_artifact_mirror(
    ctx: &mut Ctx,
    env: &str,
    registry: &str,
    mirror: &str,
) -> Result<String> {
    validate_identifier("environment", env)?;
    crate::oci_artifact::validate_registry_host("artifact registry", registry)?;
    crate::oci_artifact::validate_registry_host("artifact mirror", mirror)?;
    let mut env_obj = environment(ctx, env).await?;
    env_obj.properties.insert(
        format!("{}{registry}", crate::oci_artifact::MIRROR_PROPERTY_PREFIX),
        mirror.to_string(),
    );
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} artifact mirror {registry}={mirror}"))
}

/// Remove one environment-scoped artifact mirror.
pub async fn clear_artifact_mirror(ctx: &mut Ctx, env: &str, registry: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    let mut env_obj = environment(ctx, env).await?;
    let property = format!("{}{registry}", crate::oci_artifact::MIRROR_PROPERTY_PREFIX);
    if env_obj.properties.remove(&property).is_none() {
        bail!("environment {env} has no artifact mirror for {registry}");
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("cleared {env} artifact mirror {registry}"))
}

/// List environment-scoped artifact mirrors as origin registry → mirror host.
pub async fn list_artifact_mirrors(
    ctx: &mut Ctx,
    env: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let env_obj = environment(ctx, env).await?;
    Ok(crate::oci_artifact::mirrors_from_properties(
        &env_obj.properties,
    ))
}

/// Record the environment-scoped kubeconfig file path. Never stores credential bytes.
pub async fn set_cluster_config_path(ctx: &mut Ctx, env: &str, path: &Path) -> Result<String> {
    validate_identifier("environment", env)?;
    crate::software_executor::validate_cluster_config_path(path)?;
    let canonical = match path.canonicalize() {
        Ok(canonical) if canonical.is_file() => canonical,
        Ok(canonical) => bail!(
            "cluster_config_path {} is not a readable kubeconfig file",
            canonical.display()
        ),
        // A file that does not exist yet is stored as given: a host release
        // that installs the cluster writes it later, and in-cluster releases
        // fail closed until then (ADR 0041 sections 3 and 4).
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound && path.symlink_metadata().is_err() =>
        {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            {
                bail!(
                    "cluster_config_path {} does not exist yet, so it must be an absolute path without . or .. components",
                    path.display()
                );
            }
            path.to_path_buf()
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "cluster_config_path {} is not a readable kubeconfig file",
                    path.display()
                )
            });
        }
    };
    let stored = canonical.to_string_lossy().into_owned();
    crate::software_executor::validate_cluster_config_path(Path::new(&stored))?;
    let mut env_obj = environment(ctx, env).await?;
    env_obj.properties.insert(
        crate::software_executor::CLUSTER_CONFIG_PATH_PROPERTY.into(),
        stored.clone(),
    );
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} cluster_config_path {stored}"))
}

/// Remove the environment-scoped kubeconfig file path.
pub async fn clear_cluster_config_path(ctx: &mut Ctx, env: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    let mut env_obj = environment(ctx, env).await?;
    if env_obj
        .properties
        .remove(crate::software_executor::CLUSTER_CONFIG_PATH_PROPERTY)
        .is_none()
    {
        bail!("environment {env} has no cluster_config_path");
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("cleared {env} cluster_config_path"))
}

/// Read the stored environment-scoped kubeconfig file path, if any.
pub async fn cluster_config_path(ctx: &mut Ctx, env: &str) -> Result<Option<PathBuf>> {
    validate_identifier("environment", env)?;
    let env_obj = environment(ctx, env).await?;
    crate::software_executor::cluster_config_path_from_properties(&env_obj.properties)
}

/// Record the environment-scoped Docker secret-file directory. Never stores secret bytes.
pub async fn set_docker_secret_dir(ctx: &mut Ctx, env: &str, path: &Path) -> Result<String> {
    validate_identifier("environment", env)?;
    crate::software_executor::validate_secret_dir_path(path)?;
    let canonical = path.canonicalize().with_context(|| {
        format!(
            "docker_secret_dir {} is not a readable directory",
            path.display()
        )
    })?;
    if !canonical.is_dir() {
        bail!(
            "docker_secret_dir {} is not a readable directory",
            canonical.display()
        );
    }
    let stored = canonical.to_string_lossy().into_owned();
    crate::software_executor::validate_secret_dir_path(Path::new(&stored))?;
    let mut env_obj = environment(ctx, env).await?;
    env_obj.properties.insert(
        crate::software_executor::DOCKER_SECRET_DIR_PROPERTY.into(),
        stored.clone(),
    );
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} docker_secret_dir {stored}"))
}

/// Remove the environment-scoped Docker secret-file directory path.
pub async fn clear_docker_secret_dir(ctx: &mut Ctx, env: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    let mut env_obj = environment(ctx, env).await?;
    if env_obj
        .properties
        .remove(crate::software_executor::DOCKER_SECRET_DIR_PROPERTY)
        .is_none()
    {
        bail!("environment {env} has no docker_secret_dir");
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("cleared {env} docker_secret_dir"))
}

/// Read the stored environment-scoped Docker secret-file directory, if any.
pub async fn docker_secret_dir(ctx: &mut Ctx, env: &str) -> Result<Option<PathBuf>> {
    validate_identifier("environment", env)?;
    let env_obj = environment(ctx, env).await?;
    crate::software_executor::secret_dir_from_properties(&env_obj.properties)
}

/// Record the environment-scoped plan approval policy file path. Never stores key bytes.
pub async fn set_plan_approval_policy(ctx: &mut Ctx, env: &str, path: &Path) -> Result<String> {
    validate_identifier("environment", env)?;
    crate::approval_policy::validate_policy_file_path(path)?;
    let canonical = path.canonicalize().with_context(|| {
        format!(
            "plan_approval_policy {} is not a readable policy file",
            path.display()
        )
    })?;
    if !canonical.is_file() {
        bail!(
            "plan_approval_policy {} is not a readable policy file",
            canonical.display()
        );
    }
    let policy = crate::approval_policy::ApprovalPolicy::load(&canonical)?;
    let stored = canonical.to_string_lossy().into_owned();
    crate::approval_policy::validate_policy_file_path(Path::new(&stored))?;
    let mut env_obj = environment(ctx, env).await?;
    if let Some(key_id) = crate::approval_policy::signer_key_id(&policy)? {
        let mut keys: std::collections::BTreeSet<String> = env_obj
            .properties
            .get(crate::approval_policy::AUTO_SIGNER_KEYS_PROPERTY)
            .map(|raw| serde_json::from_str(raw))
            .transpose()?
            .unwrap_or_default();
        keys.insert(key_id);
        env_obj.properties.insert(
            crate::approval_policy::AUTO_SIGNER_KEYS_PROPERTY.into(),
            serde_json::to_string(&keys)?,
        );
    }
    env_obj.properties.insert(
        crate::approval_policy::PLAN_APPROVAL_POLICY_PROPERTY.into(),
        stored.clone(),
    );
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} plan_approval_policy {stored}"))
}

/// Remove the environment-scoped plan approval policy path.
pub async fn clear_plan_approval_policy(ctx: &mut Ctx, env: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    let mut env_obj = environment(ctx, env).await?;
    if env_obj
        .properties
        .remove(crate::approval_policy::PLAN_APPROVAL_POLICY_PROPERTY)
        .is_none()
    {
        bail!("environment {env} has no plan_approval_policy");
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("cleared {env} plan_approval_policy"))
}

/// Read the stored environment-scoped plan approval policy path, if any.
pub async fn plan_approval_policy(ctx: &mut Ctx, env: &str) -> Result<Option<PathBuf>> {
    validate_identifier("environment", env)?;
    let env_obj = environment(ctx, env).await?;
    crate::approval_policy::policy_path_from_properties(&env_obj.properties)
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

/// Environment property key for a held failed target of `product`.
pub fn failed_target_key(product: &str) -> String {
    format!("failed_target.{product}")
}

/// Longest failure cause kept for a held failed target.
const FAILED_TARGET_ERROR_CHARS: usize = 1_000;

/// Record why `release_id` failed next to the held failed target (#982).
/// The value names the release, so a cause written for an older failed
/// target is never shown for a newer one.
pub(crate) fn record_failed_target_error(
    properties: &mut HashMap<String, String>,
    product: &str,
    release_id: &str,
    detail: &str,
) {
    let detail: String = detail.chars().take(FAILED_TARGET_ERROR_CHARS).collect();
    properties.insert(
        format!("failed_target_error.{product}"),
        format!("{release_id}\n{detail}"),
    );
}

fn record_failed_target_summary(
    properties: &mut HashMap<String, String>,
    product: &str,
    release_id: &str,
    summary: &str,
) {
    let summary: String = summary.chars().take(FAILED_TARGET_ERROR_CHARS).collect();
    properties.insert(
        format!("failed_target_summary.{product}"),
        format!("{release_id}\n{summary}"),
    );
}

/// Why the held failed target of `product` failed, when it was recorded for
/// that release.
fn held_failed_target_error<'a>(
    properties: &'a HashMap<String, String>,
    product: &str,
) -> Option<&'a str> {
    held_failed_target_text(properties, product, "failed_target_error")
}

fn held_failed_target_summary<'a>(
    properties: &'a HashMap<String, String>,
    product: &str,
) -> Option<&'a str> {
    held_failed_target_text(properties, product, "failed_target_summary")
}

fn held_failed_target_text<'a>(
    properties: &'a HashMap<String, String>,
    product: &str,
    prefix: &str,
) -> Option<&'a str> {
    let held = held_failed_target_release(properties, product)?;
    let (release, detail) = properties
        .get(&format!("{prefix}.{product}"))?
        .split_once('\n')?;
    (release == held && !detail.is_empty()).then_some(detail)
}

/// Release id of a held failed target, if automatic retry is paused for `product`.
pub fn held_failed_target_release<'a>(
    properties: &'a HashMap<String, String>,
    product: &str,
) -> Option<&'a str> {
    properties
        .get(&failed_target_key(product))
        .map(String::as_str)
        .filter(|release| !release.is_empty())
}

/// Release id of a held failed target in `environment`, if any.
pub async fn held_failed_target(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
) -> Result<Option<String>> {
    let env = self::environment(ctx, environment).await?;
    Ok(held_failed_target_release(&env.properties, product).map(str::to_string))
}

/// Durable wait for a required contract that is not yet in the environment (ADR 0043 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyHold {
    pub release_id: String,
    pub contracts: Vec<(String, String)>,
    pub held_at: i64,
    pub candidates: BTreeMap<String, Vec<String>>,
}

impl DependencyHold {
    /// Status-row view of this hold (product is already on the row).
    pub fn to_status_view(&self) -> StatusDependencyHold {
        StatusDependencyHold {
            release_id: self.release_id.clone(),
            contracts: self
                .contracts
                .iter()
                .map(|(contract, minimum)| UnmetContract {
                    contract: contract.clone(),
                    minimum: minimum.clone(),
                    candidates: self.candidates.get(contract).cloned().unwrap_or_default(),
                })
                .collect(),
            held_at: self.held_at,
        }
    }
}

/// One product's hold to persist after a reconcile snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DependencyHoldWrite {
    pub release_id: String,
    pub contracts: Vec<(String, String)>,
    pub candidates: BTreeMap<String, Vec<String>>,
}

/// Environment property key for a dependency hold of `product`.
pub fn dependency_hold_key(product: &str) -> String {
    format!("dependency_hold.{product}")
}

fn dependency_hold_contracts_key(product: &str) -> String {
    format!("dependency_hold_contracts.{product}")
}

fn dependency_hold_at_key(product: &str) -> String {
    format!("dependency_hold_at.{product}")
}

fn dependency_hold_candidates_key(product: &str) -> String {
    format!("dependency_hold_candidates.{product}")
}

fn encode_hold_candidates(candidates: &BTreeMap<String, Vec<String>>) -> String {
    candidates
        .iter()
        .map(|(contract, names)| format!("{contract}={}", names.join("|")))
        .collect::<Vec<_>>()
        .join(";")
}

fn decode_hold_candidates(raw: &str) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    if raw.is_empty() {
        return out;
    }
    for part in raw.split(';') {
        let Some((contract, names)) = part.split_once('=') else {
            continue;
        };
        if contract.is_empty() {
            continue;
        }
        out.insert(
            contract.to_string(),
            names
                .split('|')
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect(),
        );
    }
    out
}

/// Active dependency hold for `product`, if the stored properties are complete.
pub fn dependency_hold(
    properties: &HashMap<String, String>,
    product: &str,
) -> Option<DependencyHold> {
    let release_id = properties.get(&dependency_hold_key(product))?.clone();
    if release_id.is_empty() {
        return None;
    }
    let contracts_raw = properties.get(&dependency_hold_contracts_key(product))?;
    let mut contracts = Vec::new();
    for part in contracts_raw.split(',') {
        let (contract, minimum) = part.split_once('=')?;
        if contract.is_empty() || minimum.is_empty() {
            return None;
        }
        contracts.push((contract.to_string(), minimum.to_string()));
    }
    if contracts.is_empty() {
        return None;
    }
    let held_at = properties
        .get(&dependency_hold_at_key(product))?
        .parse()
        .ok()?;
    let candidates = properties
        .get(&dependency_hold_candidates_key(product))
        .map(|raw| decode_hold_candidates(raw))
        .unwrap_or_default();
    Some(DependencyHold {
        release_id,
        contracts,
        held_at,
        candidates,
    })
}

/// Record a hold for `release_id`. The same release and contracts keep `held_at`.
pub(crate) fn record_dependency_hold(
    properties: &mut HashMap<String, String>,
    product: &str,
    release_id: &str,
    contracts: &[(String, String)],
    candidates: &BTreeMap<String, Vec<String>>,
    now_ms: i64,
) -> bool {
    if let Some(existing) = dependency_hold(properties, product)
        && existing.release_id == release_id
        && existing.contracts == contracts
        && existing.candidates == *candidates
    {
        return false;
    }
    properties.insert(dependency_hold_key(product), release_id.to_string());
    properties.insert(
        dependency_hold_contracts_key(product),
        contracts
            .iter()
            .map(|(contract, minimum)| format!("{contract}={minimum}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    properties.insert(dependency_hold_at_key(product), now_ms.to_string());
    if candidates.is_empty() {
        properties.remove(&dependency_hold_candidates_key(product));
    } else {
        properties.insert(
            dependency_hold_candidates_key(product),
            encode_hold_candidates(candidates),
        );
    }
    true
}

/// Remove a dependency hold for `product`. Returns whether anything was stored.
pub(crate) fn clear_dependency_hold(
    properties: &mut HashMap<String, String>,
    product: &str,
) -> bool {
    let release = properties.remove(&dependency_hold_key(product)).is_some();
    let contracts = properties
        .remove(&dependency_hold_contracts_key(product))
        .is_some();
    let held_at = properties
        .remove(&dependency_hold_at_key(product))
        .is_some();
    let candidates = properties
        .remove(&dependency_hold_candidates_key(product))
        .is_some();
    release || contracts || held_at || candidates
}

/// Reload the environment and write only dependency-hold properties.
///
/// Planning loads a snapshot before live observation. Putting that snapshot
/// back would overwrite a concurrent apply or configuration update. This
/// reloads immediately before the write and changes only `dependency_hold.*`.
/// Environment objects have no compare-and-swap; other property writes use the
/// same read-modify-put (`set_environment_constraint`, overlays, failed_target).
pub(crate) async fn persist_dependency_holds(
    ctx: &mut Ctx,
    env: &str,
    sets: &BTreeMap<String, DependencyHoldWrite>,
    clears: &BTreeSet<String>,
) -> Result<()> {
    if sets.is_empty() && clears.is_empty() {
        return Ok(());
    }
    let mut env_obj = environment(ctx, env).await?;
    let now = crate::now_millis();
    let mut changed = false;
    for product in clears {
        if !sets.contains_key(product) {
            changed |= clear_dependency_hold(&mut env_obj.properties, product);
        }
    }
    for (product, hold) in sets {
        changed |= record_dependency_hold(
            &mut env_obj.properties,
            product,
            &hold.release_id,
            &hold.contracts,
            &hold.candidates,
            now,
        );
    }
    if changed {
        env_obj.updated = now;
        ctx.put(env_obj).await?;
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

fn spec_drift_from_object(env_obj: &Object, key: &str) -> Option<crate::spec_drift::SpecDriftView> {
    let raw = env_obj.properties.get(&format!("spec_drift.{key}"))?;
    let view: crate::spec_drift::SpecDriftView = serde_json::from_str(raw).ok()?;
    (view.status != crate::spec_drift::SPEC_DRIFT_UNKNOWN).then_some(view)
}

/// Record a report-only spec-drift observation. Never creates a Plan.
/// Unknown does not replace a stored `current` or `modified` report.
/// Returns the property key when a value was written.
pub(crate) fn stamp_spec_drift(
    environment: &mut Object,
    product: &str,
    instance: &str,
    drift: &crate::spec_drift::SpecDriftView,
) -> Option<String> {
    let key = if instance.is_empty() {
        product
    } else {
        instance
    };
    let property = format!("spec_drift.{key}");
    if drift.status == crate::spec_drift::SPEC_DRIFT_UNKNOWN {
        return None;
    }
    match serde_json::to_string(drift) {
        Ok(raw) => {
            environment.properties.insert(property, raw);
            Some(key.to_string())
        }
        Err(_) => {
            environment.properties.remove(&property);
            None
        }
    }
}

/// Record the configuration an instance now runs. `sealed` is what the
/// executed step named; `None` (an out-of-band reconcile) reads the
/// environment's current sealed records.
fn stamp_applied_overlays(
    environment: &mut Object,
    product: &str,
    instance: &str,
    sealed: Option<&[crate::plan::SealedStep]>,
) {
    let key = if instance.is_empty() {
        product
    } else {
        instance
    };
    let digest = overlay_digest_for(environment, product);
    let applied = match sealed {
        Some(sealed) => crate::sealed_secret::config_digest(&digest, sealed),
        None => crate::sealed_secret::instance_config_digest(environment, &digest, key),
    };
    if applied.is_empty() {
        environment
            .properties
            .remove(&format!("applied_config.{key}"));
    } else {
        environment
            .properties
            .insert(format!("applied_config.{key}"), applied);
    }
    if digest.is_empty() {
        environment
            .properties
            .remove(&format!("config_digest.{product}"));
    } else {
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

pub(crate) async fn release_config_schema(
    ctx: &mut Ctx,
    release: &str,
) -> Result<Option<crate::manifest::ConfigSection>> {
    let Some(object) = ctx.get(release).await? else {
        return Ok(None);
    };
    let Some(raw) = object.properties.get("manifest") else {
        return Ok(None);
    };
    Ok(crate::manifest::parse_raw(raw)?.config)
}

async fn subscribed_config_schema(
    ctx: &mut Ctx,
    env_obj: &Object,
    product: &str,
) -> Result<Option<crate::manifest::ConfigSection>> {
    let Some(sub) = list_subscriptions(ctx, env_obj)
        .await?
        .into_iter()
        .find(|sub| sub.product == product)
    else {
        return Ok(None);
    };
    let Some(release) = sub.channel.properties.get("current_release").cloned() else {
        return Ok(None);
    };
    release_config_schema(ctx, &release).await
}

pub(crate) fn admit_overlay_key(
    schema: &crate::manifest::ConfigSection,
    key: &str,
    value: &str,
) -> Result<()> {
    if schema.secrets.iter().any(|name| name == key) {
        bail!("overlay {key} is a declared secret name; secret values are not overlays");
    }
    let Some(spec) = schema.overlay.get(key) else {
        bail!("overlay {key} is not declared by the release config schema");
    };
    admit_overlay_value(spec, key, value)
}

fn admit_overlay_value(
    spec: &crate::manifest::OverlayKeySchema,
    key: &str,
    value: &str,
) -> Result<()> {
    use crate::manifest::OverlayValueType;
    match spec.value_type {
        OverlayValueType::String => Ok(()),
        OverlayValueType::Integer => {
            if value.parse::<i64>().is_err() {
                bail!("overlay {key} must be an integer");
            }
            Ok(())
        }
        OverlayValueType::Boolean => {
            if matches!(value, "true" | "false") {
                Ok(())
            } else {
                bail!("overlay {key} must be true or false");
            }
        }
        OverlayValueType::Enum => {
            if spec.values.iter().any(|allowed| allowed == value) {
                Ok(())
            } else {
                bail!("overlay {key} is not an allowed value");
            }
        }
    }
}

/// Plan admission: overlays plus defaults must satisfy the candidate schema.
pub(crate) fn admit_product_overlays(
    schema: &crate::manifest::ConfigSection,
    overlays: &BTreeMap<String, String>,
) -> Result<()> {
    for key in overlays.keys() {
        if !schema.overlay.contains_key(key) {
            bail!("overlay {key} is not declared by the release config schema");
        }
    }
    for (key, spec) in &schema.overlay {
        match overlays.get(key) {
            Some(value) => admit_overlay_value(spec, key, value)?,
            None if spec.required && spec.default.is_none() => {
                bail!("overlay {key} is required by the release config schema");
            }
            None => {}
        }
    }
    Ok(())
}

async fn product_config_views(
    ctx: &mut Ctx,
    env_obj: &Object,
) -> Result<Vec<EnvironmentProductConfig>> {
    let mut views = Vec::new();
    for sub in list_subscriptions(ctx, env_obj).await? {
        let overlay = product_overlays(env_obj, &sub.product)?;
        let schema = match sub.channel.properties.get("current_release") {
            Some(release) => release_config_schema(ctx, release).await?,
            None => None,
        };
        let Some(schema) = schema else {
            if overlay.is_empty() {
                continue;
            }
            views.push(EnvironmentProductConfig {
                product: sub.product,
                defaults: BTreeMap::new(),
                digest: overlay_digest(&overlay),
                overlay,
                secrets: Vec::new(),
            });
            continue;
        };
        let mut defaults = BTreeMap::new();
        for (key, spec) in &schema.overlay {
            if let Some(value) = spec.default.as_ref()
                && !overlay.contains_key(key)
            {
                defaults.insert(key.clone(), value.clone());
            }
        }
        views.push(EnvironmentProductConfig {
            product: sub.product,
            digest: overlay_digest(&overlay),
            overlay,
            defaults,
            secrets: schema.secrets,
        });
    }
    Ok(views)
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
    if let Some(schema) = subscribed_config_schema(ctx, &env_obj, product).await? {
        admit_overlay_key(&schema, key, value)?;
    }
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
    properties: &HashMap<String, String>,
    execution: crate::approval_policy::ExecutionPolicy,
) -> Result<Option<EnvironmentPlanSummary>> {
    // Newest after checking every created_at index against its payload peek
    // so a depressed index cannot hide the true newest behind LIMIT 1.
    let Some(plan) = crate::plan::latest_for_environment(ctx, env).await? else {
        return Ok(None);
    };
    let recorded = crate::plan_approval::latest_for_plan(ctx, &plan.id).await?;
    let now = crate::now_millis();
    let inspected =
        crate::approval_policy::inspect_approval_evidence(ctx, &plan, recorded, &execution, now)
            .await;
    let policy = crate::approval_policy::load_live_policy(properties);
    let signals = crate::approval_policy::delivery_signals_for_plan(ctx, &plan).await?;
    let live_policy = policy.as_ref().ok().and_then(|value| value.as_ref());
    let products: Vec<String> = plan.steps.iter().map(|step| step.product.clone()).collect();
    let plan_criticality = crate::criticality_store::effective_for_targets(ctx, env, &products)
        .await?
        .map(|level| level.as_str().to_owned());
    let approval = if crate::approval_policy::plan_awaiting_execution(&plan)
        && crate::approval_policy::development_bypass_current(&plan, &execution)
    {
        crate::approval_policy::explain_plan_approval(
            live_policy,
            &plan,
            signals,
            inspected.evidence.as_ref(),
            now,
            execution,
            plan_criticality.as_deref(),
        )
    } else if crate::approval_policy::plan_awaiting_execution(&plan) && policy.is_err() {
        // Before the pending-human check: an unreadable policy also blocks
        // human approvals (it may require a preflight), and is the cause.
        crate::approval_policy::PlanApprovalView {
            source: "required".into(),
            reason: Some("approval policy is unreadable".into()),
            policy_provider: inspected
                .evidence
                .as_ref()
                .map(|evidence| evidence.policy_provider.clone()),
        }
    } else if inspected.blocked_human {
        crate::approval_policy::blocked_pending_human_view()
    } else if crate::approval_policy::plan_awaiting_execution(&plan)
        && crate::approval_policy::reused_auto_envelope_is_unexecutable(
            ctx,
            live_policy,
            &plan,
            signals,
            &execution,
            now,
        )
        .await
    {
        crate::approval_policy::PlanApprovalView {
            source: "required".into(),
            reason: Some("pending automatic approval is not executable".into()),
            policy_provider: Some(crate::approval_policy::POLICY_PROVIDER.into()),
        }
    } else {
        crate::approval_policy::explain_plan_approval(
            live_policy,
            &plan,
            signals,
            inspected.evidence.as_ref(),
            now,
            execution,
            plan_criticality.as_deref(),
        )
    };
    let mut summary = environment_plan_summary(plan)?;
    summary.approval = Some(approval);
    Ok(Some(summary))
}

pub(crate) fn environment_plan_summary(plan: Plan) -> Result<EnvironmentPlanSummary> {
    const MAX_PLAN_STEP_SUMMARIES: usize = 256;
    let digest = format!("sha256:{}", plan.executable_digest()?);
    let step_count = plan.steps.len();
    let status_detail = operator_safe_status_detail(&plan);
    let steps = plan
        .steps
        .into_iter()
        .take(MAX_PLAN_STEP_SUMMARIES)
        .map(|step| {
            let instance = step.instance_name().to_string();
            EnvironmentPlanStepSummary {
                id: step.id,
                order: step.order,
                instance,
                product: step.product,
                action: step.action.to_string(),
                from: step.from,
                to: step.to,
                release_id: step.release_id,
            }
        })
        .collect::<Vec<_>>();
    Ok(EnvironmentPlanSummary {
        id: plan.id,
        state: plan.state.to_string(),
        created_at: plan.created_at,
        step_count,
        digest: Some(digest),
        status_detail,
        steps_truncated: steps.len() < step_count,
        steps,
        approval: None,
    })
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
        PlanState::Succeeded if plan.steps.is_empty() => crate::plan::NO_OP_STATUS_DETAIL.into(),
        PlanState::Computed | PlanState::Running | PlanState::Succeeded => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_inspect_reports_eligibility_and_next_openings() {
        use chrono::TimeZone as _;

        let window =
            crate::maintenance::Window::new("weekly", "UTC", vec![1], "02:00", 60).unwrap();
        // Monday 2026-10-05 02:30 UTC: inside the window.
        let inside = chrono::Utc.with_ymd_and_hms(2026, 10, 5, 2, 30, 0).unwrap();
        let next_monday = chrono::Utc.with_ymd_and_hms(2026, 10, 12, 2, 0, 0).unwrap();
        let open = maintenance_inspect(Ok(vec![window.clone()]), inside);
        assert_eq!(open.eligibility, "open");
        assert_eq!(
            open.open_until_ms,
            Some(
                chrono::Utc
                    .with_ymd_and_hms(2026, 10, 5, 3, 0, 0)
                    .unwrap()
                    .timestamp_millis()
            )
        );
        assert_eq!(
            open.windows[0].next_opens_at_ms,
            Some(next_monday.timestamp_millis())
        );

        // Tuesday: closed until next Monday.
        let tuesday = chrono::Utc.with_ymd_and_hms(2026, 10, 6, 12, 0, 0).unwrap();
        let closed = maintenance_inspect(Ok(vec![window]), tuesday);
        assert_eq!(closed.eligibility, "closed");
        assert_eq!(
            closed.next_opens_at_ms,
            Some(next_monday.timestamp_millis())
        );
        assert_eq!(
            closed.windows[0].next_opens_at_ms,
            Some(next_monday.timestamp_millis())
        );

        // Occurrences that overlap still report the next start.
        let long = crate::maintenance::Window::new(
            "long",
            "UTC",
            vec![1, 2, 3, 4, 5, 6, 7],
            "00:00",
            1500,
        )
        .unwrap();
        let overlapping = maintenance_inspect(Ok(vec![long]), tuesday);
        assert_eq!(overlapping.eligibility, "open");
        assert_eq!(
            overlapping.windows[0].next_opens_at_ms,
            Some(
                chrono::Utc
                    .with_ymd_and_hms(2026, 10, 7, 0, 0, 0)
                    .unwrap()
                    .timestamp_millis()
            )
        );

        let unrestricted = maintenance_inspect(Ok(Vec::new()), tuesday);
        assert_eq!(unrestricted.eligibility, "unrestricted");
        assert!(unrestricted.windows.is_empty());

        let invalid =
            maintenance_inspect(Err(anyhow::anyhow!("configuration is missing")), tuesday);
        assert_eq!(invalid.eligibility, "invalid");
        assert!(invalid.detail.unwrap().contains("configuration is missing"));
    }

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
        environment.properties.insert(
            "spec_drift.api".into(),
            serde_json::to_string(&crate::spec_drift::SpecDriftView {
                status: crate::spec_drift::SPEC_DRIFT_MODIFIED.into(),
                objects: Vec::new(),
            })
            .unwrap(),
        );

        transition_deployment(
            &mut environment,
            "api",
            "api",
            None,
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
        assert!(!environment.properties.contains_key("spec_drift.api"));
        assert_eq!(environment.updated, 42);
    }

    #[test]
    fn applied_config_records_the_sealed_values_the_step_ran_with() {
        // The environment holds no sealed value by the time the step lands
        // (rotated or deleted mid-run); the stamp still names what ran.
        let mut environment = environment_object();
        let ran = [crate::plan::SealedStep {
            secret: "db".into(),
            key: "password".into(),
            digest: "sha256:1".into(),
        }];
        transition_deployment(
            &mut environment,
            "api",
            "api",
            Some(&ran),
            &DeploymentTransition::Refreshed,
            "",
            42,
        );
        assert_eq!(
            environment.properties.get("applied_config.api").unwrap(),
            &crate::sealed_secret::config_digest("", &ran)
        );
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
            "api",
            None,
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
    fn dependency_hold_is_idempotent_for_the_same_contracts() {
        let mut properties = HashMap::new();
        let contracts = vec![("database".into(), "1.2.0".into())];
        let candidates = BTreeMap::new();
        assert!(record_dependency_hold(
            &mut properties,
            "app",
            "tenkai:release:app@1.0.0",
            &contracts,
            &candidates,
            10,
        ));
        assert!(!record_dependency_hold(
            &mut properties,
            "app",
            "tenkai:release:app@1.0.0",
            &contracts,
            &candidates,
            20,
        ));
        let hold = dependency_hold(&properties, "app").unwrap();
        assert_eq!(hold.release_id, "tenkai:release:app@1.0.0");
        assert_eq!(hold.contracts, contracts);
        assert_eq!(hold.held_at, 10);
        assert!(record_dependency_hold(
            &mut properties,
            "app",
            "tenkai:release:app@1.1.0",
            &contracts,
            &candidates,
            30,
        ));
        assert_eq!(dependency_hold(&properties, "app").unwrap().held_at, 30);
        assert!(clear_dependency_hold(&mut properties, "app"));
        assert_eq!(dependency_hold(&properties, "app"), None);
        assert!(!clear_dependency_hold(&mut properties, "app"));
    }

    #[test]
    fn dependency_hold_persists_named_candidates() {
        let mut properties = HashMap::new();
        let contracts = vec![("database".into(), "1.0.0".into())];
        let candidates = BTreeMap::from([("database".into(), vec!["db-a".into(), "db-b".into()])]);
        assert!(record_dependency_hold(
            &mut properties,
            "app",
            "tenkai:release:app@1.0.0",
            &contracts,
            &candidates,
            10,
        ));
        let hold = dependency_hold(&properties, "app").unwrap();
        assert_eq!(hold.candidates, candidates);
        assert_eq!(
            properties
                .get("dependency_hold_candidates.app")
                .map(String::as_str),
            Some("database=db-a|db-b")
        );
        let view = hold.to_status_view();
        assert_eq!(view.contracts[0].candidates, vec!["db-a", "db-b"]);
        assert!(!record_dependency_hold(
            &mut properties,
            "app",
            "tenkai:release:app@1.0.0",
            &contracts,
            &candidates,
            20,
        ));
        assert!(clear_dependency_hold(&mut properties, "app"));
        assert!(
            !properties.contains_key("dependency_hold_candidates.app"),
            "{properties:?}"
        );
    }

    #[test]
    fn a_held_failed_target_names_its_own_cause_only() {
        let mut properties = HashMap::from([(
            failed_target_key("web"),
            "tenkai:release:web@2.0.0".to_string(),
        )]);
        assert_eq!(held_failed_target_error(&properties, "web"), None);
        record_failed_target_error(
            &mut properties,
            "web",
            "tenkai:release:web@2.0.0",
            "Deployment web cannot become Available: pod web-1 container app CrashLoopBackOff after 3 restarts",
        );
        assert_eq!(
            held_failed_target_error(&properties, "web"),
            Some(
                "Deployment web cannot become Available: pod web-1 container app CrashLoopBackOff after 3 restarts"
            )
        );
        // A newer failed target recorded without a cause hides the old one.
        properties.insert(failed_target_key("web"), "tenkai:release:web@3.0.0".into());
        assert_eq!(held_failed_target_error(&properties, "web"), None);
        properties.insert(failed_target_key("web"), "tenkai:release:web@4.0.0".into());
        let long = "x".repeat(2_000);
        record_failed_target_error(&mut properties, "web", "tenkai:release:web@4.0.0", &long);
        assert_eq!(
            held_failed_target_error(&properties, "web")
                .unwrap()
                .chars()
                .count(),
            FAILED_TARGET_ERROR_CHARS
        );
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
        let waiting = StatusRow {
            product: "app".into(),

            instance: "app".into(),
            channel: "stable".into(),
            deployed: None,
            health: None,
            error: None,
            head: "1.0.0".into(),
            overlay_stale: false,
            delivery_hold: None,
            spec_drift: None,
            certificate: None,
            health_checks: Vec::new(),
            dependency_hold: Some(StatusDependencyHold {
                release_id: "tenkai:release:app@1.0.0".into(),
                contracts: vec![UnmetContract {
                    contract: "database".into(),
                    minimum: "1.0.0".into(),
                    candidates: Vec::new(),
                }],
                held_at: 1,
            }),
        };
        assert_eq!(status_state(&waiting), "waiting");
        let mut missing = waiting.clone();
        missing.dependency_hold = None;
        assert_eq!(status_state(&missing), "missing");
        let mut drifted = missing.clone();
        drifted.deployed = Some("1.0.0".into());
        drifted.health = Some("healthy".into());
        drifted.spec_drift = Some(crate::spec_drift::SpecDriftView {
            status: crate::spec_drift::SPEC_DRIFT_MODIFIED.into(),
            objects: vec![crate::spec_drift::SpecDriftObject {
                kind: "Deployment".into(),
                name: "web".into(),
                status: crate::spec_drift::SPEC_DRIFT_MODIFIED.into(),
                fields: vec!["containers".into()],
            }],
        });
        assert_eq!(
            status_state(&drifted),
            crate::spec_drift::SPEC_DRIFT_MODIFIED
        );
        drifted.health = Some("unknown".into());
        assert_eq!(status_state(&drifted), "unknown");
        drifted.health = Some("healthy".into());
        drifted.head = "2.0.0".into();
        assert_eq!(status_state(&drifted), "behind");
        drifted.head = "1.0.0".into();
        drifted.overlay_stale = true;
        assert_eq!(status_state(&drifted), "config_stale");
        drifted.overlay_stale = false;
        drifted.spec_drift = None;
        assert_eq!(status_state(&drifted), "current");
    }

    #[test]
    fn unknown_spec_drift_does_not_replace_current() {
        let mut environment = environment_object();
        let current = crate::spec_drift::SpecDriftView {
            status: crate::spec_drift::SPEC_DRIFT_CURRENT.into(),
            objects: Vec::new(),
        };
        stamp_spec_drift(&mut environment, "api", "", &current);
        let stored = environment
            .properties
            .get("spec_drift.api")
            .cloned()
            .expect("stored current");
        assert!(
            stored.contains(crate::spec_drift::SPEC_DRIFT_CURRENT),
            "{stored}"
        );
        stamp_spec_drift(
            &mut environment,
            "api",
            "",
            &crate::spec_drift::SpecDriftView::unknown(),
        );
        assert_eq!(
            environment
                .properties
                .get("spec_drift.api")
                .map(String::as_str),
            Some(stored.as_str())
        );
        assert_eq!(
            spec_drift_from_object(&environment, "api")
                .expect("current")
                .status,
            crate::spec_drift::SPEC_DRIFT_CURRENT
        );
        let mut empty = environment_object();
        stamp_spec_drift(
            &mut empty,
            "api",
            "",
            &crate::spec_drift::SpecDriftView::unknown(),
        );
        assert!(!empty.properties.contains_key("spec_drift.api"));
        empty.properties.insert(
            "spec_drift.api".into(),
            serde_json::to_string(&crate::spec_drift::SpecDriftView::unknown()).unwrap(),
        );
        assert_eq!(spec_drift_from_object(&empty, "api"), None);
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

    #[tokio::test]
    async fn retirement_is_idempotent_hides_fleet_and_blocks_new_delivery() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-environment-retirement-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "prod", "Prod").await.unwrap();
        let stale_environment = environment(&mut ctx, "prod").await.unwrap();
        let historical_plan = crate::plan::create(&mut ctx, "prod").await.unwrap();
        let mut late_plan = historical_plan.clone();
        late_plan.id.push_str(":late");

        ctx.acquire_lease(
            crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
            "prod",
            "controller",
            1,
        )
        .await
        .unwrap();
        let lease = crate::apply::inspect_environment_lease(&mut ctx, "prod")
            .await
            .unwrap();
        assert!(lease.held, "{lease:?}");
        let held = retire_environment(&mut ctx, "prod", "service ended", "operator")
            .await
            .unwrap_err()
            .to_string();
        assert!(held.contains("apply in progress"), "{held}");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        crate::apply::unlock_environment(&mut ctx, "prod")
            .await
            .unwrap();

        let retirement = retire_environment(&mut ctx, "prod", "service ended", "operator")
            .await
            .unwrap();
        assert_eq!(
            retire_environment(&mut ctx, "prod", "different reason", "another-operator")
                .await
                .unwrap(),
            retirement
        );
        assert_eq!(
            inspect_environment(&mut ctx, "prod")
                .await
                .unwrap()
                .retirement,
            Some(retirement.clone())
        );
        assert!(
            ctx.put(stale_environment)
                .await
                .unwrap_err()
                .to_string()
                .contains("retired")
        );
        ctx.put(historical_plan.to_object().unwrap()).await.unwrap();
        assert!(
            ctx.put(late_plan.to_object().unwrap())
                .await
                .unwrap_err()
                .to_string()
                .contains("retired")
        );
        assert_eq!(
            inspect_environment(&mut ctx, "prod")
                .await
                .unwrap()
                .retirement,
            Some(retirement.clone())
        );
        assert!(list_environments(&mut ctx).await.unwrap().is_empty());
        assert_eq!(fleet_status(&mut ctx).await.unwrap().environment_count, 0);
        assert!(
            crate::plan::create(&mut ctx, "prod")
                .await
                .unwrap_err()
                .to_string()
                .contains("retired")
        );
        assert!(
            crate::plan::create_from_steps(&mut ctx, "prod", Vec::new())
                .await
                .unwrap_err()
                .to_string()
                .contains("retired")
        );
        assert!(
            subscribe(&mut ctx, "prod", "api", "stable")
                .await
                .unwrap_err()
                .to_string()
                .contains("retired")
        );
        let lease_error =
            match crate::apply::claim_environment(&mut ctx, "prod", "controller").await {
                Ok(_) => panic!("retired environment accepted a new apply lease"),
                Err(error) => error.to_string(),
            };
        assert!(lease_error.contains("retired"), "{lease_error}");
        let store = crate::storage::SqliteStore::open(&database).unwrap();
        assert!(
            crate::storage::OperationalStore::claim_runtime_plan(
                &store,
                "prod",
                "plan-1",
                "runtime",
                crate::now_millis() + 60_000,
            )
            .unwrap_err()
            .to_string()
            .contains("retired")
        );
        assert!(
            env_add(&mut ctx, "prod", "Prod")
                .await
                .unwrap_err()
                .to_string()
                .contains("retired")
        );
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn cluster_config_path_stores_canonical_file_and_refuses_credential_bytes() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-cluster-config-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let kubeconfig = std::env::temp_dir().join(format!(
            "tenkai-cluster-config-{}-{}.kubeconfig",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_file(&kubeconfig);
        std::fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\nclusters: []\n").unwrap();
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "lab", "Lab").await.unwrap();
        let set = set_cluster_config_path(&mut ctx, "lab", &kubeconfig)
            .await
            .unwrap();
        assert!(set.contains("cluster_config_path"), "{set}");
        let stored = cluster_config_path(&mut ctx, "lab").await.unwrap().unwrap();
        assert_eq!(stored, kubeconfig.canonicalize().unwrap());
        assert!(
            clear_cluster_config_path(&mut ctx, "lab")
                .await
                .unwrap()
                .contains("cleared")
        );
        assert!(
            cluster_config_path(&mut ctx, "lab")
                .await
                .unwrap()
                .is_none()
        );
        let err =
            set_cluster_config_path(&mut ctx, "lab", Path::new("-----BEGIN PRIVATE KEY-----"))
                .await
                .unwrap_err()
                .to_string();
        assert!(err.contains("file path"), "{err}");
        // A file a host release has not written yet is stored as given.
        let future = kubeconfig.with_extension("future");
        set_cluster_config_path(&mut ctx, "lab", &future)
            .await
            .unwrap();
        assert_eq!(
            cluster_config_path(&mut ctx, "lab").await.unwrap(),
            Some(future)
        );
        let err = set_cluster_config_path(&mut ctx, "lab", Path::new("relative.kubeconfig"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute path"), "{err}");
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_file(&kubeconfig);
    }

    #[tokio::test]
    async fn docker_secret_dir_stores_canonical_directory_and_refuses_credential_bytes() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-docker-secrets-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let secret_dir = std::env::temp_dir().join(format!(
            "tenkai-docker-secrets-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&secret_dir);
        std::fs::create_dir_all(&secret_dir).unwrap();
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "lab", "Lab").await.unwrap();
        let set = set_docker_secret_dir(&mut ctx, "lab", &secret_dir)
            .await
            .unwrap();
        assert!(set.contains("docker_secret_dir"), "{set}");
        let stored = docker_secret_dir(&mut ctx, "lab").await.unwrap().unwrap();
        assert_eq!(stored, secret_dir.canonicalize().unwrap());
        assert!(
            clear_docker_secret_dir(&mut ctx, "lab")
                .await
                .unwrap()
                .contains("cleared")
        );
        assert!(docker_secret_dir(&mut ctx, "lab").await.unwrap().is_none());
        let err = set_docker_secret_dir(&mut ctx, "lab", Path::new("password=s3cret"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("directory path"), "{err}");
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&secret_dir);
    }

    #[tokio::test]
    async fn plan_approval_policy_stores_canonical_file_and_refuses_credential_bytes() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-approval-policy-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let policy_dir = std::env::temp_dir().join(format!(
            "tenkai-approval-policy-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&policy_dir);
        std::fs::create_dir_all(&policy_dir).unwrap();
        let policy = policy_dir.join("policy.toml");
        std::fs::write(&policy, "version = 1\nmode = \"manual\"\nttl_ms = 60000\n").unwrap();
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "lab", "Lab").await.unwrap();
        let set = set_plan_approval_policy(&mut ctx, "lab", &policy)
            .await
            .unwrap();
        assert!(set.contains("plan_approval_policy"), "{set}");
        let stored = plan_approval_policy(&mut ctx, "lab")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, policy.canonicalize().unwrap());
        assert!(
            clear_plan_approval_policy(&mut ctx, "lab")
                .await
                .unwrap()
                .contains("cleared")
        );
        assert!(
            plan_approval_policy(&mut ctx, "lab")
                .await
                .unwrap()
                .is_none()
        );
        let err = set_plan_approval_policy(&mut ctx, "lab", Path::new("password=s3cret"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("file path"), "{err}");
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&policy_dir);
    }

    #[tokio::test]
    async fn inspect_plan_approval_covers_policy_downgrade_and_stale_refresh() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-inspect-approval-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "lab", "Lab").await.unwrap();

        let mut install = crate::plan::Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: String::new(),
            content_id: String::new(),
            environment: "lab".into(),
            created_at: 100,
            inputs: vec![crate::plan::DesiredStateInput {
                product: "api".into(),

                instance: String::new(),
                channel: "stable".into(),
                channel_id: "tenkai:channel:api/stable".into(),
                desired_version: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                deployed_version: None,
                providers: Default::default(),
            }],
            steps: vec![crate::plan::Step {
                id: String::new(),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action: crate::plan::Action::Install,
                from: None,
                to: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                workdir: ".".into(),
                host: None,
                sealed: Vec::new(),
                restore: None,
                rewrap: None,
                issuer: None,
                identity: None,
                restore_identity: None,
                target_changes: Vec::new(),
            }],
            state: crate::plan::PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        };
        install.bind_content_identity().unwrap();
        crate::plan::store(&mut ctx, &install).await.unwrap();

        let missing = inspect_environment(&mut ctx, "lab")
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(missing.source, "required");
        assert_eq!(
            missing.reason.as_deref(),
            Some("no environment approval policy")
        );

        let key = root.join("auto-approver.ed25519");
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key)
                .unwrap();
            file.write_all(&[7_u8; 32]).unwrap();
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&key, [7_u8; 32]).unwrap();
        }
        let policy = root.join("policy.toml");
        std::fs::write(
            &policy,
            format!(
                "version = 1\nmode = \"auto\"\nttl_ms = 60000\nauto_signer_key = \"{}\"\n",
                key.display()
            ),
        )
        .unwrap();
        set_plan_approval_policy(&mut ctx, "lab", &policy)
            .await
            .unwrap();

        let approved = inspect_environment(&mut ctx, "lab")
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(approved.source, "policy");
        assert_eq!(approved.reason, None);

        crate::plan_approval::record(
            &mut ctx,
            &crate::plan_approval::VerificationEvidence {
                schema: crate::plan_approval::APPROVAL_SCHEMA.into(),
                plan_id: install.id.clone(),
                plan_digest: format!("sha256:{}", install.executable_digest().unwrap()),
                environment: "lab".into(),
                signer_identity: "auto".into(),
                key_id: "kid".into(),
                policy_provider: crate::approval_policy::POLICY_PROVIDER.into(),
                policy_evidence_id: "auto".into(),
                policy_digest: "sha256:old".into(),
                issued_at: 1,
                expires_at: 2,
                verified_at: crate::now_millis(),
                skip_gates: false,
                bypass_reason: None,
            },
        )
        .await
        .unwrap();
        let stale = inspect_environment(&mut ctx, "lab")
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(stale.source, "policy");
        assert_eq!(
            stale.reason.as_deref(),
            Some("stale automatic approval will refresh")
        );

        let mut downgrade = install.clone();
        downgrade.created_at = 200;
        downgrade.steps[0].action = crate::plan::Action::Downgrade;
        downgrade.steps[0].from = Some("1.0.0".into());
        downgrade.steps[0].to = "0.9.0".into();
        downgrade.bind_content_identity().unwrap();
        crate::plan::store(&mut ctx, &downgrade).await.unwrap();
        let human = inspect_environment(&mut ctx, "lab")
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(human.source, "required");
        assert!(
            human.reason.as_deref().unwrap().contains("downgrade"),
            "{human:?}"
        );

        std::fs::write(&policy, "not toml").unwrap();
        let broken = inspect_environment(&mut ctx, "lab").await.unwrap();
        let approval = broken.latest_plan.unwrap().approval.unwrap();
        assert_eq!(broken.name, "lab");
        assert_eq!(approval.source, "required");
        assert_eq!(
            approval.reason.as_deref(),
            Some("approval policy is unreadable")
        );
        assert!(
            !approval
                .reason
                .as_deref()
                .unwrap()
                .contains(&policy.display().to_string()),
            "{approval:?}"
        );
        crate::plan_approval::record(
            &mut ctx,
            &crate::plan_approval::VerificationEvidence {
                schema: crate::plan_approval::APPROVAL_SCHEMA.into(),
                plan_id: downgrade.id.clone(),
                plan_digest: format!("sha256:{}", downgrade.executable_digest().unwrap()),
                environment: "lab".into(),
                signer_identity: "alice".into(),
                key_id: "kid".into(),
                policy_provider: "alice".into(),
                policy_evidence_id: "decision".into(),
                policy_digest: "sha256:human".into(),
                issued_at: 1,
                expires_at: crate::now_millis() + 60_000,
                verified_at: crate::now_millis(),
                skip_gates: false,
                bypass_reason: None,
            },
        )
        .await
        .unwrap();
        let pending = inspect_environment(&mut ctx, "lab")
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(pending.source, "required");
        downgrade.state = crate::plan::PlanState::Running;
        crate::plan::store(&mut ctx, &downgrade).await.unwrap();
        let preserved = inspect_environment(&mut ctx, "lab")
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(preserved.source, "human");
        assert_eq!(preserved.policy_provider.as_deref(), Some("alice"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn inspect_plan_approval_uses_plan_product_criticality() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-inspect-product-criticality-{}-{}-{}",
            std::process::id(),
            crate::now_millis(),
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "lab", "Lab").await.unwrap();
        ctx.put(Object {
            id: product_id("api"),
            kind: KIND_PRODUCT.into(),
            name: "api".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .await
        .unwrap();

        let mut install = crate::plan::Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: String::new(),
            content_id: String::new(),
            environment: "lab".into(),
            created_at: 100,
            inputs: vec![crate::plan::DesiredStateInput {
                product: "api".into(),

                instance: String::new(),
                channel: "stable".into(),
                channel_id: "tenkai:channel:api/stable".into(),
                desired_version: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                deployed_version: None,
                providers: Default::default(),
            }],
            steps: vec![crate::plan::Step {
                id: String::new(),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action: crate::plan::Action::Install,
                from: None,
                to: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                workdir: ".".into(),
                host: None,
                sealed: Vec::new(),
                restore: None,
                rewrap: None,
                issuer: None,
                identity: None,
                restore_identity: None,
                target_changes: Vec::new(),
            }],
            state: crate::plan::PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        };
        install.bind_content_identity().unwrap();
        crate::plan::store(&mut ctx, &install).await.unwrap();

        let key = root.join("auto-approver.ed25519");
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key)
                .unwrap();
            file.write_all(&[7_u8; 32]).unwrap();
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&key, [7_u8; 32]).unwrap();
        }
        let policy = root.join("policy.toml");
        std::fs::write(
            &policy,
            format!(
                "version = 1\nmode = \"auto\"\nttl_ms = 60000\nauto_signer_key = \"{}\"\n\n[[quorum]]\npurpose = \"execute_plan\"\nn = 2\nmin_criticality = \"critical\"\n",
                key.display()
            ),
        )
        .unwrap();
        set_plan_approval_policy(&mut ctx, "lab", &policy)
            .await
            .unwrap();

        let approved = inspect_environment(&mut ctx, "lab")
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(approved.source, "policy");
        assert_eq!(approved.reason, None);

        crate::criticality_store::set_product(
            &mut ctx,
            "api",
            &crate::criticality::SetCriticalityRequest {
                level: crate::criticality::CriticalityLevel::Critical,
                owner: "alice".into(),
                reason: "marked data".into(),
            },
        )
        .await
        .unwrap();
        let required = inspect_environment(&mut ctx, "lab")
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(required.source, "required");
        assert!(
            required.reason.as_deref().unwrap().contains("multi-party"),
            "{required:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn inspect_reads_pending_human_envelope_before_execution() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-inspect-pending-envelope-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "lab", "Lab").await.unwrap();

        let mut install = crate::plan::Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: String::new(),
            content_id: String::new(),
            environment: "lab".into(),
            created_at: 100,
            inputs: vec![crate::plan::DesiredStateInput {
                product: "api".into(),

                instance: String::new(),
                channel: "stable".into(),
                channel_id: "tenkai:channel:api/stable".into(),
                desired_version: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                deployed_version: None,
                providers: Default::default(),
            }],
            steps: vec![crate::plan::Step {
                id: String::new(),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action: crate::plan::Action::Install,
                from: None,
                to: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                workdir: ".".into(),
                host: None,
                sealed: Vec::new(),
                restore: None,
                rewrap: None,
                issuer: None,
                identity: None,
                restore_identity: None,
                target_changes: Vec::new(),
            }],
            state: crate::plan::PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        };
        install.bind_content_identity().unwrap();
        crate::plan::store(&mut ctx, &install).await.unwrap();

        let key = root.join("auto-approver.ed25519");
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key)
                .unwrap();
            file.write_all(&[7_u8; 32]).unwrap();
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&key, [7_u8; 32]).unwrap();
        }
        let policy = root.join("policy.toml");
        std::fs::write(
            &policy,
            format!(
                "version = 1\nmode = \"auto\"\nttl_ms = 60000\nauto_signer_key = \"{}\"\n",
                key.display()
            ),
        )
        .unwrap();
        set_plan_approval_policy(&mut ctx, "lab", &policy)
            .await
            .unwrap();

        let approvals = root.join("approvals");
        std::fs::create_dir_all(&approvals).unwrap();
        let envelope = approvals.join(format!("{}.json", install.id));
        let human_roots = root.join("human-trust.toml");
        crate::dev_sign::sign_plan_approval_for_digest(
            &root.join("human-keys"),
            &format!("sha256:{}", install.executable_digest().unwrap()),
            "lab",
            &envelope,
            &human_roots,
            3600,
        )
        .unwrap();
        let eligibility = inspect_environment(&mut ctx, "lab")
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(eligibility.source, "policy");
        let execution = crate::approval_policy::ExecutionPolicy {
            trust_roots: Some(human_roots),
            approval_directory: Some(approvals),
            ..crate::approval_policy::ExecutionPolicy::default()
        };
        let human = inspect_environment_for_policy(&mut ctx, "lab", execution.clone())
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(human.source, "human");
        assert_eq!(human.policy_provider.as_deref(), Some("builtin"));
        std::fs::write(&policy, "not toml").unwrap();
        let blocked = inspect_environment_for_policy(&mut ctx, "lab", execution)
            .await
            .unwrap()
            .latest_plan
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(blocked.source, "required");
        assert_eq!(
            blocked.reason.as_deref(),
            Some("approval policy is unreadable")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn missing_environment_lists_registered_names_or_empty_store() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-env-hint-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let empty = environment(&mut ctx, "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(empty.contains("the store has no environments"), "{empty}");
        env_add(&mut ctx, "edge", "Edge").await.unwrap();
        env_add(&mut ctx, "lab", "Lab").await.unwrap();
        let listed = environment(&mut ctx, "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(listed.contains("registered: edge, lab"), "{listed}");
        assert!(!listed.contains("tenkaictl env add"), "{listed}");
        let _ = std::fs::remove_file(&database);
    }

    async fn published_channel(ctx: &mut Ctx, root: &std::path::Path, product: &str) {
        std::fs::write(
            root.join("tenkai.toml"),
            format!(
                "[product]\nname = \"{product}\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\ninstances = \"many\"\n"
            ),
        )
        .unwrap();
        crate::catalog::publish(
            ctx,
            &root.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("instances");
        crate::catalog::promote(ctx, &actor, &format!("{product}@1.0.0"), "stable")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn named_instance_subscribe_is_distinct_and_inspects() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-instance-subscribe-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "local", "Local").await.unwrap();
        published_channel(&mut ctx, &root, "database").await;
        published_channel(&mut ctx, &root, "cache").await;

        subscribe(&mut ctx, "local", "database", "stable")
            .await
            .unwrap();
        let default = inspect_environment(&mut ctx, "local").await.unwrap();
        assert_eq!(default.subscriptions.len(), 1);
        assert_eq!(default.subscriptions[0].product, "database");
        assert_eq!(default.subscriptions[0].instance, "database");

        let named = subscribe_instance(&mut ctx, "local", "database", "stable", Some("db-a"))
            .await
            .unwrap();
        assert!(named.contains("db-a"), "{named}");
        let duplicate = subscribe_instance(&mut ctx, "local", "database", "stable", Some("db-a"))
            .await
            .unwrap();
        assert!(duplicate.contains("already"), "{duplicate}");
        let taken = subscribe_instance(&mut ctx, "local", "cache", "stable", Some("db-a"))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            taken.contains("environment local already has instance db-a"),
            "{taken}"
        );
        let named_default =
            subscribe_instance(&mut ctx, "local", "cache", "stable", Some("database"))
                .await
                .unwrap_err()
                .to_string();
        assert!(
            named_default.contains("environment local already has instance database"),
            "{named_default}"
        );
        let invalid = subscribe_instance(&mut ctx, "local", "database", "stable", Some("db_a"))
            .await
            .unwrap_err()
            .to_string();
        assert!(invalid.contains("DNS label"), "{invalid}");

        let inspected = inspect_environment(&mut ctx, "local").await.unwrap();
        let names: Vec<_> = inspected
            .subscriptions
            .iter()
            .map(|row| (row.instance.as_str(), row.product.as_str()))
            .collect();
        assert!(names.contains(&("database", "database")), "{names:?}");
        assert!(names.contains(&("db-a", "database")), "{names:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn two_instances_plan_distinct_steps_and_resume() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-instance-plan-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "local", "Local").await.unwrap();
        published_channel(&mut ctx, &root, "database").await;
        subscribe_instance(&mut ctx, "local", "database", "stable", Some("db-a"))
            .await
            .unwrap();
        subscribe_instance(&mut ctx, "local", "database", "stable", Some("db-b"))
            .await
            .unwrap();

        let first = crate::plan::create(&mut ctx, "local").await.unwrap();
        let instances: Vec<_> = first
            .steps
            .iter()
            .map(|step| step.instance_name().to_string())
            .collect();
        assert_eq!(first.steps.len(), 2, "{first:?}");
        assert!(instances.contains(&"db-a".into()), "{instances:?}");
        assert!(instances.contains(&"db-b".into()), "{instances:?}");
        assert!(
            first.steps.iter().all(|step| step.product == "database"),
            "{first:?}"
        );
        assert_eq!(
            crate::apply::classify_candidate(&mut ctx, &first)
                .await
                .unwrap(),
            crate::apply::CandidateAdmission::Admissible
        );

        let mut env = environment(&mut ctx, "local").await.unwrap();
        env.properties
            .insert("deployed.db-a".into(), "1.0.0".into());
        env.properties
            .insert("deployment_health.db-a".into(), "healthy".into());
        ctx.put(env).await.unwrap();

        let resumed = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert_eq!(resumed.steps.len(), 1, "{resumed:?}");
        assert_eq!(resumed.steps[0].instance_name(), "db-b");
        assert_eq!(resumed.steps[0].product, "database");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn one_release_refuses_a_second_instance_at_plan() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-instance-one-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "local", "Local").await.unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            "[product]\nname = \"database\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        crate::catalog::publish(
            &mut ctx,
            &root.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("instances");
        crate::catalog::promote(&mut ctx, &actor, "database@1.0.0", "stable")
            .await
            .unwrap();
        subscribe_instance(&mut ctx, "local", "database", "stable", Some("db-a"))
            .await
            .unwrap();
        subscribe_instance(&mut ctx, "local", "database", "stable", Some("db-b"))
            .await
            .unwrap();
        let err = crate::plan::create(&mut ctx, "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("already has instance") && err.contains("instances = \"many\""),
            "{err}"
        );
        assert!(err.contains("db-a") && err.contains("db-b"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn overlay_set_and_plan_refuse_keys_the_release_schema_does_not_declare() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-config-schema-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "api"
version = "1.0.0"

[deploy]
install = "true"

[config]
secrets = ["db-password"]

[config.overlay.replicas]
type = "integer"
required = true
default = "1"

[config.overlay.region]
type = "enum"
values = ["eu", "us"]
"#,
        )
        .unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::catalog::publish(
            &mut ctx,
            &root.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("config-schema");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        subscribe(&mut ctx, "local", "api", "stable").await.unwrap();

        let unknown = set_environment_overlay(&mut ctx, "local", "api", "colour", "blue")
            .await
            .unwrap_err()
            .to_string();
        assert!(unknown.contains("colour"), "{unknown}");
        let typed = set_environment_overlay(&mut ctx, "local", "api", "replicas", "many")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            typed.contains("replicas") && typed.contains("integer"),
            "{typed}"
        );
        let secret = set_environment_overlay(&mut ctx, "local", "api", "db-password", "s3cret")
            .await
            .unwrap_err()
            .to_string();
        assert!(secret.contains("db-password"), "{secret}");
        set_environment_overlay(&mut ctx, "local", "api", "region", "eu")
            .await
            .unwrap();
        crate::plan::create(&mut ctx, "local").await.unwrap();

        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "api"
version = "2.0.0"

[deploy]
install = "true"

[config]
secrets = ["db-password"]

[config.overlay.replicas]
type = "integer"
required = true

[config.overlay.region]
type = "enum"
values = ["eu", "us"]
"#,
        )
        .unwrap();
        crate::catalog::publish(
            &mut ctx,
            &root.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        let plan_err = crate::plan::create(&mut ctx, "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            plan_err.contains("replicas") && plan_err.contains("required"),
            "{plan_err}"
        );

        let inspect = inspect_environment(&mut ctx, "local").await.unwrap();
        let config = inspect
            .config
            .iter()
            .find(|row| row.product == "api")
            .expect("config");
        assert_eq!(config.overlay.get("region").map(String::as_str), Some("eu"));
        assert_eq!(config.secrets, vec!["db-password".to_string()]);
        assert!(!serde_json::to_string(&inspect).unwrap().contains("s3cret"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
