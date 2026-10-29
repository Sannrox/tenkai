//! Manage the grant rules stored in the hub's store over HTTP (#837).
//!
//! Listing and every change need fleet management: the management token
//! (used for that request only, recorded as its principal, never stored or
//! logged) or a principal whose grants give management with no environment
//! binding. Environment-scoped credentials, tenant credentials and agents
//! are refused, and a refused request writes nothing. Each change is
//! conditional on the generation the caller read, and is audited with its
//! principal and reason before and after it is written.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::*;
use crate::grant_rules::{GrantRuleError, StoredGrantRule, StoredGrants};
use crate::oidc_verifier::OidcGrantRule;

/// `GET /v1/grant-rules`: the stored rules and their generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct GrantRuleList {
    /// Pass it back with a change; a change against another generation is
    /// refused.
    pub generation: i64,
    pub rules: Vec<GrantRuleView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct GrantRuleView {
    #[serde(flatten)]
    pub stored: StoredGrantRule,
    /// The configuration file declares this claim value, so the stored
    /// rule is ignored.
    pub declared_by_config: bool,
}

/// `POST /v1/grant-rules`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateGrantRuleRequest {
    pub rule: OidcGrantRule,
    /// Why; recorded with the rule and in the audit log.
    pub reason: String,
    /// The generation the caller listed.
    pub generation: i64,
}

/// `DELETE /v1/grant-rules`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoveGrantRuleRequest {
    /// The claim value of the rule to remove.
    pub value: String,
    pub reason: String,
    pub generation: i64,
}

fn grant_rule_error(error: GrantRuleError) -> ManagementError {
    match error {
        GrantRuleError::Invalid(_) | GrantRuleError::DeclaredByConfig(_) => {
            ManagementError::BadRequest(error.to_string())
        }
        GrantRuleError::Exists(_) | GrantRuleError::StaleGeneration { .. } => {
            ManagementError::Conflict(error.to_string())
        }
        GrantRuleError::Store(error) => ManagementError::Unavailable(error.to_string()),
    }
}

impl ManagementOperations {
    /// Fleet management, as a human or the management token: management
    /// with no environment binding and no tenant. Returns the audit
    /// principal.
    fn require_fleet_administrator(
        &self,
        credential: &CredentialMaterial,
        operation: &str,
    ) -> Result<String, ManagementError> {
        let context = self.authenticate(credential)?;
        self.refuse_agent(&context, operation)?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        if self.granted_environment(credential, &context).is_some() || context.tenant().is_some() {
            return Err(ManagementError::Forbidden(
                "stored grant rules need fleet management".into(),
            ));
        }
        Ok(context.audit_principal())
    }

    fn grant_rule_list(stored: &StoredGrants) -> Result<GrantRuleList, ManagementError> {
        let (generation, rules) = stored
            .stored()
            .map_err(|error| ManagementError::Unavailable(error.to_string()))?;
        Ok(GrantRuleList {
            generation,
            rules: rules
                .into_iter()
                .map(|stored_rule| GrantRuleView {
                    declared_by_config: stored.declared_by_config(&stored_rule.rule.value),
                    stored: stored_rule,
                })
                .collect(),
        })
    }

    fn audit_grant_rule(
        &self,
        principal: &str,
        operation: &str,
        value: &str,
        reason: &str,
    ) -> Result<(), ManagementError> {
        self.store
            .append_audit(&AuditRecord {
                id: uuid::Uuid::new_v4().to_string(),
                occurred_at: crate::now_millis(),
                principal: principal.into(),
                operation: operation.into(),
                // The reason travels in the resource: audit records carry no
                // field of their own for it.
                resource: format!("grant-rule/{value} reason={}", reason.trim()),
                outcome: operation.rsplit('.').next().unwrap_or(operation).into(),
            })
            .map_err(|error| ManagementError::Unavailable(error.to_string()))
    }

    /// `GET /v1/grant-rules`.
    pub async fn list_grant_rules(
        &self,
        credential: &CredentialMaterial,
        stored: Arc<StoredGrants>,
    ) -> Result<GrantRuleList, ManagementError> {
        self.require_fleet_administrator(credential, "grant_rule.list")?;
        tokio::task::spawn_blocking(move || Self::grant_rule_list(&stored))
            .await
            .map_err(|error| ManagementError::Internal(error.to_string()))?
    }

    /// `POST /v1/grant-rules`: store one rule; the list after it.
    pub async fn create_grant_rule(
        &self,
        credential: &CredentialMaterial,
        stored: Arc<StoredGrants>,
        request: CreateGrantRuleRequest,
    ) -> Result<GrantRuleList, ManagementError> {
        let principal = self.require_fleet_administrator(credential, "grant_rule.create")?;
        let value = request.rule.value.clone();
        self.audit_grant_rule(
            &principal,
            "grant_rule.create.requested",
            &value,
            &request.reason,
        )?;
        let created = {
            let (stored, principal) = (stored.clone(), principal.clone());
            tokio::task::spawn_blocking(move || {
                stored.create(
                    request.rule,
                    &principal,
                    &request.reason,
                    crate::now_millis(),
                    Some(request.generation),
                )
            })
            .await
            .map_err(|error| ManagementError::Internal(error.to_string()))?
        };
        let created = match created {
            Ok(created) => created,
            Err(error) => {
                let error = grant_rule_error(error);
                self.audit_grant_rule(
                    &principal,
                    "grant_rule.create.refused",
                    &value,
                    &error.to_string(),
                )?;
                return Err(error);
            }
        };
        self.audit_grant_rule(
            &principal,
            "grant_rule.create.completed",
            &value,
            &created.reason,
        )?;
        tokio::task::spawn_blocking(move || Self::grant_rule_list(&stored))
            .await
            .map_err(|error| ManagementError::Internal(error.to_string()))?
    }

    /// `DELETE /v1/grant-rules`: remove one stored rule; the list after it.
    pub async fn remove_grant_rule(
        &self,
        credential: &CredentialMaterial,
        stored: Arc<StoredGrants>,
        request: RemoveGrantRuleRequest,
    ) -> Result<GrantRuleList, ManagementError> {
        let principal = self.require_fleet_administrator(credential, "grant_rule.remove")?;
        let reason = request.reason.trim().to_string();
        if reason.is_empty() || reason.len() > 1024 {
            return Err(ManagementError::BadRequest(
                "a reason of 1..=1024 bytes is required".into(),
            ));
        }
        self.audit_grant_rule(
            &principal,
            "grant_rule.remove.requested",
            &request.value,
            &reason,
        )?;
        let removed = {
            let (stored, value) = (stored.clone(), request.value.clone());
            tokio::task::spawn_blocking(move || stored.remove(&value, Some(request.generation)))
                .await
                .map_err(|error| ManagementError::Internal(error.to_string()))?
        };
        match removed {
            Ok(true) => {}
            Ok(false) => {
                self.audit_grant_rule(
                    &principal,
                    "grant_rule.remove.refused",
                    &request.value,
                    &reason,
                )?;
                return Err(ManagementError::NotFound(format!(
                    "no stored grant rule for claim value {:?}",
                    request.value
                )));
            }
            Err(error) => {
                let error = grant_rule_error(error);
                self.audit_grant_rule(
                    &principal,
                    "grant_rule.remove.refused",
                    &request.value,
                    &error.to_string(),
                )?;
                return Err(error);
            }
        }
        self.audit_grant_rule(
            &principal,
            "grant_rule.remove.completed",
            &request.value,
            &reason,
        )?;
        tokio::task::spawn_blocking(move || Self::grant_rule_list(&stored))
            .await
            .map_err(|error| ManagementError::Internal(error.to_string()))?
    }
}
