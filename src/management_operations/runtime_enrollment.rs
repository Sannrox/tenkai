//! Issue runtime enrollments and revoke runtime credentials (#630).

use serde::{Deserialize, Serialize};

use super::*;
use crate::runtime_credentials::{
    DEFAULT_ENROLLMENT_TTL_SECONDS, ENROLLMENT_TOKEN_PREFIX, MAX_ENROLLMENT_TTL_SECONDS,
};
use crate::storage::{RuntimeEnrollmentRecord, StoreError};

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

    /// Revoke the runtime credential `credential_id` (its digest); its agent
    /// is refused from the next request on.
    pub async fn revoke_runtime_credential(
        &self,
        credential: &CredentialMaterial,
        credential_id: &str,
    ) -> Result<RuntimeCredentialRevoked, ManagementError> {
        let context = self.authenticate(credential)?;
        self.require_host_runtime_credentials()?;
        self.refuse_agent(&context, "runtime.credential.revoke")?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
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
        match self.store.revoke_runtime_credential(credential_id, now) {
            Ok(()) => {}
            Err(StoreError::NotFound { .. }) => return Err(unknown()),
            Err(error) => return Err(ManagementError::Unavailable(error.to_string())),
        }
        self.audit(
            &context.audit_principal(),
            "runtime.credential.revoke.completed",
        )?;
        Ok(RuntimeCredentialRevoked {
            credential_id: credential_id.into(),
            environment: record.environment_id,
            revoked_at: record.revoked_at.unwrap_or(now),
        })
    }
}
