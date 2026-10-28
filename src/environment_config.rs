//! Remote environment registration and configuration (#679).
//!
//! `POST /v1/environments` registers an environment. Generation-fenced
//! `PUT`/`DELETE` routes under `/v1/environments/{environment}/` change its
//! facts, constraints, maintenance windows, webhooks, approval policy and
//! runner attestation policy (#675). Every
//! change runs the same embedded function, and so the same validation, as the
//! CLI. Every change also appends an immutable audit event that records the
//! actor and the reason.

use std::collections::HashMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::connectivity::ConnectivityClass;
use crate::deploy_webhook::{WebhookEndpoint, WebhookEvent};
use crate::ontology::{NS, validate_identifier};
use crate::pb::sekai::Object;

pub const CONFIG_AUDIT_KIND: &str = "tenkai.environment_config_audit";
const MAX_REASON_BYTES: usize = 1024;

/// Body of `POST /v1/environments`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterEnvironmentRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connectivity_class: Option<ConnectivityClass>,
    pub reason: String,
}

/// Body of every `PUT`/`DELETE` configuration route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfigRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    pub reason: String,
    pub change: EnvironmentConfigChange,
}

/// One configuration change. The variant decides the route: its resource
/// path and whether it is a `PUT` or a `DELETE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvironmentConfigChange {
    SetFact {
        key: String,
        value: String,
    },
    ClearFact {
        key: String,
    },
    SetConstraint {
        constraint: String,
        name: String,
        value: String,
    },
    ClearConstraint {
        constraint: String,
        name: String,
    },
    SetMaintenanceWindow {
        name: String,
        timezone: String,
        weekdays: Vec<u32>,
        start: String,
        duration_minutes: u32,
    },
    RemoveMaintenanceWindow {
        name: String,
    },
    SetWebhook {
        url: String,
        secret_env: String,
        #[serde(default)]
        events: Vec<WebhookEvent>,
        /// Operational events the endpoint also receives (#724).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        operational: Vec<crate::deploy_webhook::OperationalEvent>,
    },
    /// Clears one URL, or every webhook when `url` is absent.
    ClearWebhooks {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    /// `path` names a policy file on the server host. Never key material.
    SetApprovalPolicy {
        path: String,
    },
    ClearApprovalPolicy,
    /// Require attested runner enrollment and renewal (#675) with evidence
    /// at most `max_age_ms` old.
    SetRunnerAttestation {
        max_age_ms: u64,
    },
    ClearRunnerAttestation,
}

/// The configuration resource a route serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigResource {
    Facts,
    Constraints,
    MaintenanceWindow,
    Webhooks,
    ApprovalPolicy,
    RunnerAttestation,
}

impl ConfigResource {
    fn segment(self) -> &'static str {
        match self {
            Self::Facts => "facts",
            Self::Constraints => "constraints",
            Self::MaintenanceWindow => "maintenance-windows",
            Self::Webhooks => "webhooks",
            Self::ApprovalPolicy => "approval-policy",
            Self::RunnerAttestation => "runner-attestation",
        }
    }
}

impl EnvironmentConfigChange {
    pub fn resource(&self) -> ConfigResource {
        match self {
            Self::SetFact { .. } | Self::ClearFact { .. } => ConfigResource::Facts,
            Self::SetConstraint { .. } | Self::ClearConstraint { .. } => {
                ConfigResource::Constraints
            }
            Self::SetMaintenanceWindow { .. } | Self::RemoveMaintenanceWindow { .. } => {
                ConfigResource::MaintenanceWindow
            }
            Self::SetWebhook { .. } | Self::ClearWebhooks { .. } => ConfigResource::Webhooks,
            Self::SetApprovalPolicy { .. } | Self::ClearApprovalPolicy => {
                ConfigResource::ApprovalPolicy
            }
            Self::SetRunnerAttestation { .. } | Self::ClearRunnerAttestation => {
                ConfigResource::RunnerAttestation
            }
        }
    }

    /// True for the `DELETE` variants.
    pub fn clears(&self) -> bool {
        matches!(
            self,
            Self::ClearFact { .. }
                | Self::ClearConstraint { .. }
                | Self::RemoveMaintenanceWindow { .. }
                | Self::ClearWebhooks { .. }
                | Self::ClearApprovalPolicy
                | Self::ClearRunnerAttestation
        )
    }

    /// The maintenance window a change names; it must match the route path.
    pub fn window_name(&self) -> Option<&str> {
        match self {
            Self::SetMaintenanceWindow { name, .. } | Self::RemoveMaintenanceWindow { name } => {
                Some(name)
            }
            _ => None,
        }
    }

    /// Request path of this change for `environment`.
    pub fn path(&self, environment: &str) -> String {
        let segment = self.resource().segment();
        match self.window_name() {
            Some(name) => format!("/v1/environments/{environment}/{segment}/{name}"),
            None => format!("/v1/environments/{environment}/{segment}"),
        }
    }

    /// Stable action name recorded in audit events.
    pub fn action(&self) -> &'static str {
        match self {
            Self::SetFact { .. } => "set_fact",
            Self::ClearFact { .. } => "clear_fact",
            Self::SetConstraint { .. } => "set_constraint",
            Self::ClearConstraint { .. } => "clear_constraint",
            Self::SetMaintenanceWindow { .. } => "set_maintenance_window",
            Self::RemoveMaintenanceWindow { .. } => "remove_maintenance_window",
            Self::SetWebhook { .. } => "set_webhook",
            Self::ClearWebhooks { .. } => "clear_webhooks",
            Self::SetApprovalPolicy { .. } => "set_approval_policy",
            Self::ClearApprovalPolicy => "clear_approval_policy",
            Self::SetRunnerAttestation { .. } => "set_runner_attestation",
            Self::ClearRunnerAttestation => "clear_runner_attestation",
        }
    }
}

/// Refuse a change sent to a route that does not serve it.
pub fn require_route(
    change: &EnvironmentConfigChange,
    resource: ConfigResource,
    clears: bool,
    path_window: Option<&str>,
) -> Result<()> {
    if change.resource() != resource || change.clears() != clears {
        bail!(
            "configuration change {} is not valid on this route",
            change.action()
        );
    }
    if change.window_name() != path_window {
        bail!("maintenance window in the body does not match the path");
    }
    Ok(())
}

pub fn require_reason(reason: &str) -> Result<()> {
    let reason = reason.trim();
    if reason.is_empty() {
        bail!("an environment configuration reason must not be empty");
    }
    if reason.len() > MAX_REASON_BYTES {
        bail!("an environment configuration reason exceeds {MAX_REASON_BYTES} bytes");
    }
    Ok(())
}

/// Validate a change without touching state, with the CLI's own checks, so
/// a malformed request is refused before the fence or any write.
pub fn validate(change: &EnvironmentConfigChange) -> Result<()> {
    use EnvironmentConfigChange as Change;
    match change {
        Change::SetFact { key, value } => {
            crate::environment::validate_fact_key(key)?;
            crate::environment::validate_fact_value(key, value)
        }
        Change::ClearFact { key } => crate::environment::validate_fact_key(key),
        Change::SetConstraint {
            constraint,
            name,
            value,
        } => crate::environment::constraint_property(constraint, name, value).map(drop),
        Change::ClearConstraint { constraint, .. } => match constraint.as_str() {
            "version_pin" | "version_range" | "require_fact" => Ok(()),
            other => bail!("unknown constraint kind {other:?}"),
        },
        Change::SetMaintenanceWindow {
            name,
            timezone,
            weekdays,
            start,
            duration_minutes,
        } => crate::maintenance::Window::new(
            name.as_str(),
            timezone.as_str(),
            weekdays.clone(),
            start.as_str(),
            *duration_minutes,
        )
        .map(drop),
        Change::RemoveMaintenanceWindow { name } => {
            validate_identifier("maintenance-window identity", name)
        }
        Change::SetWebhook {
            url,
            secret_env,
            events,
            operational,
        } => WebhookEndpoint {
            url: url.clone(),
            secret_env: secret_env.clone(),
            events: events.clone(),
            operational: operational.clone(),
        }
        .validate(),
        Change::ClearWebhooks { .. }
        | Change::ClearApprovalPolicy
        | Change::ClearRunnerAttestation => Ok(()),
        Change::SetRunnerAttestation { max_age_ms } => {
            crate::runner_attestation::RunnerAttestationPolicy::required(*max_age_ms).map(drop)
        }
        Change::SetApprovalPolicy { path } => {
            crate::approval_policy::validate_policy_file_path(std::path::Path::new(path))
        }
    }
}

/// Register `environment` as `tenkaictl env add` does, then set its
/// connectivity class when one is given. Audited like [`apply`]: the
/// request before the write, the outcome after it.
pub async fn register(
    ctx: &mut Ctx,
    request: &RegisterEnvironmentRequest,
    actor: &str,
) -> Result<String> {
    require_reason(&request.reason)?;
    let (environment, reason) = (request.environment.as_str(), request.reason.as_str());
    append_audit(ctx, environment, "register", "requested", actor, reason).await?;
    let result = async {
        let mut message =
            crate::environment::env_add(ctx, environment, &request.description).await?;
        if let Some(class) = request.connectivity_class {
            message = format!(
                "{message}; {}",
                initialize_connectivity(ctx, environment, class).await?
            );
        }
        Ok::<_, anyhow::Error>(message)
    }
    .await;
    let outcome = if result.is_ok() {
        "completed"
    } else {
        "failed"
    };
    append_audit(ctx, environment, "register", outcome, actor, reason).await?;
    result
}

/// Set the connectivity class of a newly registered environment under the
/// environment apply lease. A retry with the same class is a no-op; one that
/// would change an existing class is refused, so registration never edits
/// configuration without a fence.
async fn initialize_connectivity(
    ctx: &mut Ctx,
    environment: &str,
    class: ConnectivityClass,
) -> Result<String> {
    let owner = format!("environment-register:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = async {
        let current = crate::environment::environment(ctx, environment)
            .await?
            .properties
            .get(crate::connectivity::CONNECTIVITY_CLASS_PROPERTY)
            .map(|value| ConnectivityClass::parse(value))
            .transpose()?;
        match current {
            None => crate::connectivity::set_connectivity_class(ctx, environment, class).await,
            Some(current) if current == class => Ok(format!(
                "{environment} connectivity class is already {}",
                class.as_str()
            )),
            Some(current) => bail!(
                "environment {environment} is already registered with connectivity class {}",
                current.as_str()
            ),
        }
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing the environment registration lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing the environment registration lease")),
    }
}

/// Apply one change with the embedded function behind the matching CLI
/// command.
///
/// The change runs under the environment apply lease, so concurrent changes
/// and an active apply are serialized. `fence` runs inside the lease with the
/// generation that claiming it superseded, the one `env inspect` showed, and
/// refuses a stale generation before any write (#703). A `requested` audit event
/// with the actor and reason is durable before the write, and a `completed`
/// or `failed` event follows it, so no effective change is unaudited.
pub async fn apply(
    ctx: &mut Ctx,
    environment: &str,
    change: &EnvironmentConfigChange,
    reason: &str,
    actor: &str,
    fence: impl FnOnce(u64) -> Result<()>,
) -> Result<String> {
    require_reason(reason)?;
    validate_identifier("environment", environment)?;
    let owner = format!("environment-config:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = async {
        fence(lease.generation.saturating_sub(1))?;
        let action = change.action();
        append_audit(ctx, environment, action, "requested", actor, reason).await?;
        let result = mutate(ctx, environment, change).await;
        let outcome = if result.is_ok() {
            "completed"
        } else {
            "failed"
        };
        append_audit(ctx, environment, action, outcome, actor, reason).await?;
        result
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing the environment configuration lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing the environment configuration lease")),
    }
}

async fn mutate(
    ctx: &mut Ctx,
    environment: &str,
    change: &EnvironmentConfigChange,
) -> Result<String> {
    use EnvironmentConfigChange as Change;
    Ok(match change {
        Change::SetFact { key, value } => {
            crate::environment::set_environment_fact(ctx, environment, key, value).await?
        }
        Change::ClearFact { key } => {
            crate::environment::clear_environment_fact(ctx, environment, key).await?
        }
        Change::SetConstraint {
            constraint,
            name,
            value,
        } => {
            crate::environment::set_environment_constraint(
                ctx,
                environment,
                constraint,
                name,
                value,
            )
            .await?
        }
        Change::ClearConstraint { constraint, name } => {
            crate::environment::clear_environment_constraint(ctx, environment, constraint, name)
                .await?
        }
        Change::SetMaintenanceWindow {
            name,
            timezone,
            weekdays,
            start,
            duration_minutes,
        } => {
            let window = crate::maintenance::Window::new(
                name.as_str(),
                timezone.as_str(),
                weekdays.clone(),
                start.as_str(),
                *duration_minutes,
            )?;
            crate::maintenance::set_claimed(ctx, environment, window).await?
        }
        Change::RemoveMaintenanceWindow { name } => {
            crate::maintenance::remove_claimed(ctx, environment, name).await?
        }
        Change::SetWebhook {
            url,
            secret_env,
            events,
            operational,
        } => {
            crate::deploy_webhook::set_environment_webhook(
                ctx,
                environment,
                WebhookEndpoint {
                    url: url.clone(),
                    secret_env: secret_env.clone(),
                    events: events.clone(),
                    operational: operational.clone(),
                },
            )
            .await?
        }
        Change::ClearWebhooks { url } => {
            crate::deploy_webhook::clear_environment_webhooks(ctx, environment, url.as_deref())
                .await?
        }
        Change::SetApprovalPolicy { path } => {
            // Loader and parser errors can quote the file; a remote caller
            // names any server path, so only a fixed message leaves here.
            crate::environment::set_plan_approval_policy(
                ctx,
                environment,
                std::path::Path::new(path),
            )
            .await
            .map_err(|error| {
                eprintln!("approval policy {path} for {environment} refused: {error:#}");
                anyhow::anyhow!(
                    "approval policy {path} is not a readable, valid policy file; see the server log"
                )
            })?
        }
        Change::ClearApprovalPolicy => {
            crate::environment::clear_plan_approval_policy(ctx, environment).await?
        }
        Change::SetRunnerAttestation { max_age_ms } => {
            crate::runner_attestation::set_policy(ctx, environment, *max_age_ms).await?
        }
        Change::ClearRunnerAttestation => {
            crate::runner_attestation::clear_policy(ctx, environment).await?
        }
    })
}

/// One registration or configuration change, as audited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigAuditEvent {
    pub action: String,
    /// `requested` before a change is written, then `completed` or `failed`.
    pub outcome: String,
    pub actor: String,
    pub reason: String,
    pub at: i64,
}

/// Audited changes to `environment`, oldest first.
pub async fn audit(ctx: &mut Ctx, environment: &str) -> Result<Vec<ConfigAuditEvent>> {
    let mut objects = ctx.list_kind(CONFIG_AUDIT_KIND).await?;
    // Ids end in `<at>:<sequence>`; order by both so a request and its
    // outcome in the same millisecond keep their order.
    let order = |object: &Object| {
        let mut parts = object.id.rsplit(':');
        let sequence = parts.next().and_then(|part| part.parse::<u16>().ok());
        let at = parts.next().and_then(|part| part.parse::<i64>().ok());
        (at, sequence)
    };
    objects.sort_by_key(order);
    let mut events = Vec::new();
    for object in objects {
        if object.properties.get("environment").map(String::as_str) != Some(environment) {
            continue;
        }
        let field = |key: &str| object.properties.get(key).cloned().unwrap_or_default();
        events.push(ConfigAuditEvent {
            action: field("action"),
            outcome: field("outcome"),
            actor: field("actor"),
            reason: field("reason"),
            at: field("at").parse()?,
        });
    }
    Ok(events)
}

async fn append_audit(
    ctx: &mut Ctx,
    environment: &str,
    action: &str,
    outcome: &str,
    actor: &str,
    reason: &str,
) -> Result<()> {
    validate_identifier("environment", environment)?;
    let at = crate::now_millis();
    for sequence in 0..1024_u16 {
        let id = format!("tenkai:environment_config_audit:{environment}:{at}:{sequence}");
        let object = Object {
            id: id.clone(),
            kind: CONFIG_AUDIT_KIND.into(),
            name: format!("{action} {environment}"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("environment".into(), environment.into()),
                ("action".into(), action.into()),
                ("outcome".into(), outcome.into()),
                ("actor".into(), actor.into()),
                ("reason".into(), reason.trim().into()),
                ("at".into(), at.to_string()),
            ]),
            created: at,
            updated: at,
        };
        match ctx.create_once(object).await {
            Ok(_) => return Ok(()),
            Err(status) if crate::client::is_unique_conflict(&status) => {}
            Err(status) => return Err(status.into()),
        }
    }
    bail!("could not allocate an environment configuration audit event for {environment}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(raw: serde_json::Value) -> Result<EnvironmentConfigChange> {
        Ok(serde_json::from_value(raw)?)
    }

    #[test]
    fn changes_map_to_their_routes_and_refuse_others() {
        let set = change(serde_json::json!({"kind": "set_fact", "key": "arch", "value": "arm64"}))
            .unwrap();
        assert_eq!(set.path("prod"), "/v1/environments/prod/facts");
        require_route(&set, ConfigResource::Facts, false, None).unwrap();
        assert!(require_route(&set, ConfigResource::Facts, true, None).is_err());
        assert!(require_route(&set, ConfigResource::Webhooks, false, None).is_err());

        let window = change(serde_json::json!({
            "kind": "remove_maintenance_window", "name": "nightly"
        }))
        .unwrap();
        assert_eq!(
            window.path("prod"),
            "/v1/environments/prod/maintenance-windows/nightly"
        );
        require_route(
            &window,
            ConfigResource::MaintenanceWindow,
            true,
            Some("nightly"),
        )
        .unwrap();
        assert!(
            require_route(
                &window,
                ConfigResource::MaintenanceWindow,
                true,
                Some("weekly")
            )
            .is_err()
        );

        assert!(change(serde_json::json!({"kind": "clear_fact", "key": "a", "extra": 1})).is_err());
        assert!(change(serde_json::json!({"kind": "delete_everything"})).is_err());
        assert!(require_reason("  ").is_err());
        assert!(require_reason(&"x".repeat(MAX_REASON_BYTES + 1)).is_err());
    }
}
