//! Issue runtime enrollments and revoke runtime credentials (#630), and the
//! runner registry that lists them with their activity (#673).

use serde::{Deserialize, Serialize};

use super::*;
use crate::runtime_credentials::{
    DEFAULT_ENROLLMENT_TTL_SECONDS, ENROLLMENT_TOKEN_PREFIX, MAX_ENROLLMENT_TTL_SECONDS,
};
use crate::storage::{
    RuntimeActivityRecord, RuntimeEnrollmentRecord, RuntimeRevocation, StoreError,
};

/// Longest revocation reason accepted.
const MAX_REVOKE_REASON: usize = 512;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEnrollmentRequest {
    /// How long the token may be redeemed; default 15 minutes, at most 24 hours.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

/// A new enrollment. `token` is shown only here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RuntimeEnrollmentIssued {
    pub environment: String,
    pub token: String,
    pub expires_at: i64,
}

/// Why a runner is revoked; recorded and shown on inspect.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRevokeRequest {
    pub reason: String,
}

/// How a runner authenticates (#809), from what the server issued it, not
/// from what a request presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunnerAuth {
    /// The runner CA issued this runner a certificate, at enrollment with a
    /// CSR or at a renewal. Such an agent never uses its bearer for work;
    /// the bearer stays valid for renewal after the certificate expires.
    ClientCertificate,
    /// A static token, or an enrolled credential never issued a certificate.
    Bearer,
}

/// One runner of the registry: an enrolled credential, or a static token
/// configured on the server. Never carries a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RuntimeRunner {
    /// `sha256:` digest of the credential or token; what revoke takes.
    pub id: String,
    pub environment: String,
    /// `active`, `revoked`, or `static` for a configured token, which only
    /// server configuration changes.
    pub state: String,
    /// Always sent; optional so a newer client still reads an older server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub auth: Option<RunnerAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub created_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub created_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub revoked_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub revoked_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub revoke_reason: Option<String>,
    /// Instances that presented this runner's credential, most recent first.
    pub instances: Vec<RuntimeRunnerInstance>,
}

/// What one instance of a runner last did. Activity is recorded at most
/// every 30 seconds per kind, so times can trail by that much.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RuntimeRunnerInstance {
    pub instance_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub runtime_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_work_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_heartbeat_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_inventory_at: Option<i64>,
    /// Holds an unexpired runtime plan lease now.
    pub holds_lease: bool,
    /// The instance's version against this server: `current`, `behind`
    /// (one minor release, supported), `unsupported` or `ahead` (#761).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub skew: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RuntimeRunnerList {
    pub runners: Vec<RuntimeRunner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RuntimeCredentialRevoked {
    pub credential_id: String,
    pub environment: String,
    pub revoked_at: i64,
}

impl ManagementOperations {
    /// Enrollment and revocation use the host's store, which tenant mode
    /// does not partition by tenant, so tenant mode refuses them.
    fn require_host_runtime_credentials(&self) -> Result<(), ManagementError> {
        if self.tenant_mode {
            return Err(ManagementError::Forbidden(
                "runtime enrollment is not available in tenant mode".into(),
            ));
        }
        Ok(())
    }

    /// A single-use enrollment token for one environment's runtime agent.
    pub async fn create_runtime_enrollment(
        &self,
        credential: &CredentialMaterial,
        environment: &str,
        request: RuntimeEnrollmentRequest,
    ) -> Result<RuntimeEnrollmentIssued, ManagementError> {
        let context = self.authenticate(credential)?;
        self.require_host_runtime_credentials()?;
        self.refuse_agent(&context, "runtime.enrollment.create")?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        self.require_environment_grant(
            credential,
            &context,
            Some(environment),
            "runtime enrollment",
        )?;
        crate::ontology::validate_identifier("environment", environment)
            .map_err(|error| ManagementError::BadRequest(error.to_string()))?;
        let ttl = request
            .ttl_seconds
            .unwrap_or(DEFAULT_ENROLLMENT_TTL_SECONDS);
        if ttl == 0 || ttl > MAX_ENROLLMENT_TTL_SECONDS {
            return Err(ManagementError::BadRequest(format!(
                "enrollment ttl_seconds must be 1..={MAX_ENROLLMENT_TTL_SECONDS}"
            )));
        }
        crate::clock_guard::require_trusted_time("runtime enrollment")
            .map_err(|error| ManagementError::Unavailable(error.to_string()))?;
        let actor = context.audit_principal();
        // The environment is handed to its runtime before any credential can
        // exist, and stays so: the server never runs its plans again.
        let mut ctx = self.application_ctx()?;
        crate::runtime_credentials::mark_runtime_managed(&mut ctx, environment)
            .await
            .map_err(|error| ManagementError::Unavailable(error.to_string()))?;
        let token = crate::runtime_credentials::mint(ENROLLMENT_TOKEN_PREFIX)
            .map_err(|error| ManagementError::Unavailable(error.to_string()))?;
        let expires_at = crate::now_millis() + (ttl as i64) * 1_000;
        self.store
            .create_runtime_enrollment(&RuntimeEnrollmentRecord {
                token_digest: crate::runtime_credentials::digest(&token),
                environment_id: environment.into(),
                expires_at,
                created_by: actor.clone(),
            })
            .map_err(|error| ManagementError::Unavailable(error.to_string()))?;
        self.audit(&actor, "runtime.enrollment.create.completed")?;
        Ok(RuntimeEnrollmentIssued {
            environment: environment.into(),
            token,
            expires_at,
        })
    }

    /// Revoke the runtime credential `credential_id` (its digest) for
    /// `request.reason`; its agent is refused from the next request on. A
    /// static token is refused: only server configuration removes it.
    pub async fn revoke_runtime_credential(
        &self,
        credential: &CredentialMaterial,
        credential_id: &str,
        request: RuntimeRevokeRequest,
    ) -> Result<RuntimeCredentialRevoked, ManagementError> {
        let context = self.authenticate(credential)?;
        self.require_host_runtime_credentials()?;
        self.refuse_agent(&context, "runtime.credential.revoke")?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        let reason = request.reason.trim();
        if reason.is_empty() || reason.len() > MAX_REVOKE_REASON {
            return Err(ManagementError::BadRequest(format!(
                "a revocation reason of 1..={MAX_REVOKE_REASON} bytes is required"
            )));
        }
        if self
            .static_runtime_runners
            .iter()
            .any(|(id, _)| id == credential_id)
        {
            return Err(ManagementError::BadRequest(
                "a static runner is removed from TENKAI_RUNTIME_TOKENS, not revoked".into(),
            ));
        }
        let unknown = || ManagementError::NotFound("runtime credential not found".into());
        let record = self
            .store
            .runtime_credential(credential_id)
            .map_err(|error| ManagementError::Unavailable(error.to_string()))?
            .ok_or_else(unknown)?;
        self.require_environment_grant(
            credential,
            &context,
            Some(&record.environment_id),
            "runtime credential revocation",
        )?;
        let now = crate::now_millis();
        let actor = context.audit_principal();
        let revocation = RuntimeRevocation {
            reason: reason.into(),
            revoked_by: actor.clone(),
        };
        match self
            .store
            .revoke_runtime_credential(credential_id, now, &revocation)
        {
            Ok(()) => {}
            Err(StoreError::NotFound { .. }) => return Err(unknown()),
            Err(error) => return Err(ManagementError::Unavailable(error.to_string())),
        }
        self.audit(&actor, "runtime.credential.revoke.completed")?;
        Ok(RuntimeCredentialRevoked {
            credential_id: credential_id.into(),
            environment: record.environment_id,
            revoked_at: record.revoked_at.unwrap_or(now),
        })
    }

    /// The runner registry: every enrolled credential and static token with
    /// its instances' activity. An environment-scoped credential sees only
    /// its environment's runners.
    pub async fn list_runtime_runners(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<RuntimeRunnerList, ManagementError> {
        let context = self.authenticate(credential)?;
        self.require_host_runtime_credentials()?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        let granted = self.granted_environment(credential, &context);
        let unavailable = |error: StoreError| ManagementError::Unavailable(error.to_string());
        let enrolled = self.store.runtime_runners().map_err(unavailable)?;
        let activity = self.store.runtime_activity().map_err(unavailable)?;
        let certified: std::collections::BTreeSet<String> = self
            .store
            .certified_runtime_runners()
            .map_err(unavailable)?
            .into_iter()
            .collect();
        let leases: std::collections::BTreeSet<String> = self
            .store
            .live_runtime_claim_owners(crate::now_millis())
            .map_err(unavailable)?
            .into_iter()
            .collect();
        let instances = |id: &str| -> Vec<RuntimeRunnerInstance> {
            let mut instances: Vec<&RuntimeActivityRecord> = activity
                .iter()
                .filter(|record| record.runner_id == id)
                .collect();
            instances.sort_by_key(|record| {
                std::cmp::Reverse(
                    record
                        .last_work_at
                        .max(record.last_heartbeat_at)
                        .max(record.last_inventory_at),
                )
            });
            instances
                .into_iter()
                .map(|record| RuntimeRunnerInstance {
                    instance_id: record.instance_id.clone(),
                    runtime_version: record.runtime_version.clone(),
                    last_work_at: record.last_work_at,
                    last_heartbeat_at: record.last_heartbeat_at,
                    last_inventory_at: record.last_inventory_at,
                    holds_lease: leases.contains(&record.owner),
                    skew: record.runtime_version.as_deref().and_then(|version| {
                        crate::version_skew::skew(crate::version_skew::SERVER_VERSION, version)
                            .map(str::to_string)
                    }),
                })
                .collect()
        };
        let mut runners: Vec<RuntimeRunner> = enrolled
            .into_iter()
            .map(|runner| {
                let id = runner.credential.credential_digest;
                RuntimeRunner {
                    instances: instances(&id),
                    auth: Some(if certified.contains(&id) {
                        RunnerAuth::ClientCertificate
                    } else {
                        RunnerAuth::Bearer
                    }),
                    state: if runner.credential.revoked_at.is_some() {
                        "revoked"
                    } else {
                        "active"
                    }
                    .into(),
                    id,
                    environment: runner.credential.environment_id,
                    created_by: Some(runner.created_by).filter(|by| !by.is_empty()),
                    created_at: Some(runner.credential.created_at),
                    revoked_at: runner.credential.revoked_at,
                    revoked_by: runner
                        .revocation
                        .as_ref()
                        .map(|revocation| revocation.revoked_by.clone()),
                    revoke_reason: runner.revocation.map(|revocation| revocation.reason),
                }
            })
            .collect();
        runners.extend(
            self.static_runtime_runners
                .iter()
                .map(|(id, environment)| RuntimeRunner {
                    instances: instances(id),
                    id: id.clone(),
                    environment: environment.clone(),
                    state: "static".into(),
                    auth: Some(RunnerAuth::Bearer),
                    created_by: None,
                    created_at: None,
                    revoked_at: None,
                    revoked_by: None,
                    revoke_reason: None,
                }),
        );
        runners.retain(|runner| granted.is_none_or(|granted| granted == runner.environment));
        runners.sort_by(|left, right| {
            (&left.environment, &left.id).cmp(&(&right.environment, &right.id))
        });
        Ok(RuntimeRunnerList { runners })
    }

    /// One runner of [`Self::list_runtime_runners`]; outside the caller's
    /// view it is not found.
    pub async fn inspect_runtime_runner(
        &self,
        credential: &CredentialMaterial,
        runner_id: &str,
    ) -> Result<RuntimeRunner, ManagementError> {
        self.list_runtime_runners(credential)
            .await?
            .runners
            .into_iter()
            .find(|runner| runner.id == runner_id)
            .ok_or_else(|| ManagementError::NotFound("runner not found".into()))
    }
}
