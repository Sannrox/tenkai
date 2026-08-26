//! Authenticated management operations shared by network adapters.
//!
//! This deep module owns management authentication, tenant-aware application
//! dispatch, reconciliation audit ordering, and public failure classification.
//! Transport adapters retain credential extraction and response encoding.

use std::sync::Arc;

use crate::auth_context::{
    AuthMode, AuthStack, AuthenticatedRequestContext, CredentialMaterial, DeliveryCapability,
};
use crate::plan::{EnvironmentInspectReport, EnvironmentListEntry, FleetStatusReport, StatusRow};
use crate::providers::TerminalOutcomeProjection;
use crate::reconciler::TickReport;
use crate::runtime_delivery::ReconcilePort;
use crate::storage::{AuditRecord, OperationalStore};
use crate::tenant_environment::{
    TenantEnvironmentError, TenantEnvironmentFuture, TenantEnvironmentOperations,
    TenantEnvironmentView,
};
use crate::tenant_isolation::NON_DISCLOSING_DENY;
use crate::tenant_store::TenantOperationalStore;

struct ReconcileTenantEnvironmentView {
    reconciler: Arc<dyn ReconcilePort>,
}

impl TenantEnvironmentView for ReconcileTenantEnvironmentView {
    fn inspect_without_outcome_export(
        &self,
        environment: String,
    ) -> TenantEnvironmentFuture<'_, EnvironmentInspectReport> {
        self.reconciler
            .inspect_environment_without_outcome_export(environment)
    }

    fn status(&self, environment: String) -> TenantEnvironmentFuture<'_, Vec<StatusRow>> {
        self.reconciler.environment_status(environment)
    }

    fn fleet_without_outcome_export(&self) -> TenantEnvironmentFuture<'_, FleetStatusReport> {
        self.reconciler.fleet_status_without_outcome_export()
    }

    fn reconcile_bounded(
        &self,
        environments: Vec<String>,
    ) -> TenantEnvironmentFuture<'_, TickReport> {
        self.reconciler.reconcile_environments(environments)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ManagementError {
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Internal(String),
}

pub(crate) struct ManagementOperations {
    auth: AuthStack,
    tenant_mode: bool,
    reconciler: Arc<dyn ReconcilePort>,
    store: Arc<dyn OperationalStore>,
    tenant_environments: Option<TenantEnvironmentOperations>,
}

impl ManagementOperations {
    pub(crate) fn new(
        auth: AuthStack,
        tenant_mode: bool,
        reconciler: Arc<dyn ReconcilePort>,
        store: Arc<dyn OperationalStore>,
        tenant_store: Option<Arc<dyn TenantOperationalStore>>,
    ) -> Self {
        let tenant_environments = tenant_store.map(|tenant_store| {
            TenantEnvironmentOperations::new(
                tenant_store,
                Arc::new(ReconcileTenantEnvironmentView {
                    reconciler: reconciler.clone(),
                }),
            )
        });
        Self {
            auth,
            tenant_mode,
            reconciler,
            store,
            tenant_environments,
        }
    }

    pub(crate) fn authenticate(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<AuthenticatedRequestContext, ManagementError> {
        match self.auth.authenticate(credential) {
            Ok(context) => {
                if self.auth.mode() == AuthMode::Community && context.tenant().is_some() {
                    return Err(ManagementError::Internal(
                        "community auth stack produced tenant context".into(),
                    ));
                }
                Ok(context)
            }
            Err(crate::auth_context::AuthError::Unauthorized(_)) => Err(
                ManagementError::Forbidden("invalid management credential".into()),
            ),
            Err(crate::auth_context::AuthError::InvalidCredential(_)) => Err(
                ManagementError::Unauthorized("invalid management credential".into()),
            ),
            Err(error) => {
                eprintln!("management authentication failed: {error}");
                Err(ManagementError::Forbidden(
                    "invalid management credential".into(),
                ))
            }
        }
    }

    fn require_capability(
        context: &AuthenticatedRequestContext,
        required: DeliveryCapability,
    ) -> Result<(), ManagementError> {
        if context.has_delivery_capability(required) {
            Ok(())
        } else {
            Err(ManagementError::Forbidden(
                "insufficient delivery capability".into(),
            ))
        }
    }

    pub(crate) async fn fleet_status(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<FleetStatusReport, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Read)?;
        if self.tenant_mode {
            return self
                .tenant_operations()?
                .fleet_status(&context)
                .await
                .map_err(map_tenant_error);
        }
        self.reconciler.fleet_status().await.map_err(internal)
    }

    pub(crate) async fn list_environments(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<Vec<EnvironmentListEntry>, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Read)?;
        if self.tenant_mode {
            return self
                .tenant_operations()?
                .list(&context)
                .await
                .map_err(map_tenant_error);
        }
        self.reconciler.list_environments().await.map_err(internal)
    }

    pub(crate) async fn inspect_environment(
        &self,
        credential: &CredentialMaterial,
        environment: &str,
    ) -> Result<EnvironmentInspectReport, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Read)?;
        if self.tenant_mode {
            return self
                .tenant_operations()?
                .inspect(&context, environment)
                .await
                .map_err(map_tenant_error);
        }
        let mut report = self
            .reconciler
            .inspect_environment(environment.to_string())
            .await
            .map_err(map_environment_error)?;
        if report.terminal_outcomes.is_empty() {
            report.terminal_outcomes =
                terminal_outcomes_from_store(self.store.as_ref(), environment).map_err(internal)?;
        }
        Ok(report)
    }

    pub(crate) async fn environment_status(
        &self,
        credential: &CredentialMaterial,
        environment: &str,
    ) -> Result<Vec<StatusRow>, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Read)?;
        if self.tenant_mode {
            return self
                .tenant_operations()?
                .status(&context, environment)
                .await
                .map_err(map_tenant_error);
        }
        self.reconciler
            .environment_status(environment.to_string())
            .await
            .map_err(map_environment_error)
    }

    pub(crate) async fn reconcile(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<TickReport, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        let tenant_operations = if self.tenant_mode {
            if context.tenant().is_none() {
                return Err(ManagementError::Forbidden("unauthenticated".into()));
            }
            Some(self.tenant_operations()?)
        } else {
            None
        };
        let actor = context.principal_id();
        self.audit(actor, "reconcile.requested")?;
        let result = if let Some(tenant_operations) = tenant_operations {
            tenant_operations
                .reconcile(&context)
                .await
                .map_err(map_tenant_error)
        } else {
            self.reconciler.reconcile().await.map_err(internal)
        };
        match result {
            Ok(report) => {
                let outcome = if report.failures() == 0 {
                    "reconcile.completed"
                } else {
                    "reconcile.failed"
                };
                self.audit(actor, outcome)?;
                Ok(report)
            }
            Err(error) => match self.audit(actor, "reconcile.failed") {
                Ok(()) => Err(error),
                Err(audit_error) => Err(ManagementError::Unavailable(format!(
                    "reconciliation failed: {error}; recording failure audit also failed: {audit_error}"
                ))),
            },
        }
    }

    fn tenant_operations(&self) -> Result<&TenantEnvironmentOperations, ManagementError> {
        self.tenant_environments
            .as_ref()
            .ok_or_else(|| ManagementError::Unavailable("tenant store unavailable".into()))
    }

    fn audit(&self, principal: &str, operation: &str) -> Result<(), ManagementError> {
        self.store
            .append_audit(&AuditRecord {
                id: uuid::Uuid::new_v4().to_string(),
                occurred_at: crate::now_millis(),
                principal: principal.into(),
                operation: operation.into(),
                resource: "*".into(),
                outcome: operation.rsplit('.').next().unwrap_or(operation).into(),
            })
            .map_err(|error| ManagementError::Unavailable(error.to_string()))
    }
}

fn terminal_outcomes_from_store(
    store: &dyn OperationalStore,
    environment: &str,
) -> anyhow::Result<Vec<TerminalOutcomeProjection>> {
    let records =
        store.list_provider_events(crate::providers::OUTCOME_PROVIDER_KIND, environment, 128)?;
    crate::providers::project_terminal_outcomes(&records, environment, crate::now_millis())
        .map_err(anyhow::Error::from)
}

fn map_tenant_error(error: TenantEnvironmentError) -> ManagementError {
    match error {
        TenantEnvironmentError::StoreUnavailable => {
            ManagementError::Unavailable("tenant store unavailable".into())
        }
        TenantEnvironmentError::NotFound => ManagementError::NotFound(NON_DISCLOSING_DENY.into()),
        TenantEnvironmentError::Denied(message) => ManagementError::Forbidden(message),
        TenantEnvironmentError::Internal(message) => ManagementError::Internal(message),
    }
}

fn map_environment_error(error: anyhow::Error) -> ManagementError {
    let message = format!("{error:#}");
    if message.contains("not registered") {
        ManagementError::NotFound(message)
    } else {
        ManagementError::Internal(message)
    }
}

fn internal(error: anyhow::Error) -> ManagementError {
    ManagementError::Internal(format!("{error:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assertion_verifier::{
        JwtAssertionVerifier, JwtEnterpriseAuthExtension, JwtTrustedKey, JwtVerifierConfig,
    };
    use crate::auth_context::{
        AUTH_CONTEXT_CONTRACT_VERSION, AuthHostConfig, CommunityTokenAuthenticator,
        PrincipalIdentity, PrincipalKind, build_auth_stack,
    };
    use crate::runtime_delivery::{
        CompletionFuture, FleetStatusFuture, HealthFuture, InspectEnvFuture, InventoryFuture,
        ListEnvFuture, ReconcileFuture, StatusEnvFuture, WorkFuture,
    };
    use crate::storage::SqliteStore;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    struct FixedReconciler;

    impl ReconcilePort for FixedReconciler {
        fn reconcile(&self) -> ReconcileFuture<'_> {
            Box::pin(async {
                Ok(TickReport {
                    environments: vec![crate::reconciler::EnvironmentResult {
                        environment: "prod".into(),
                        status: crate::reconciler::EnvironmentStatus::Current,
                    }],
                })
            })
        }

        fn pending_work(&self, environment: String) -> WorkFuture<'_> {
            Box::pin(async move {
                Ok(Some(crate::plan::Plan {
                    format_version: 1,
                    id: "plan-1".into(),
                    content_id: "sha256:plan".into(),
                    environment,
                    created_at: 1,
                    inputs: Vec::new(),
                    steps: Vec::new(),
                    state: crate::plan::PlanState::Computed,
                    gates_skipped: None,
                    status_detail: String::new(),
                    maintenance_blocked: false,
                    prior_warnings: Vec::new(),
                    recalled_recovery_reason: None,
                }))
            })
        }

        fn check_health(&self) -> HealthFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn complete_work(
            &self,
            _environment: String,
            _completion: crate::runtime_delivery::RuntimeCompletion,
        ) -> CompletionFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn validate_completion(
            &self,
            _environment: String,
            _completion: crate::runtime_delivery::RuntimeCompletion,
        ) -> CompletionFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn list_environments(&self) -> ListEnvFuture<'_> {
            Box::pin(async {
                Ok(vec![EnvironmentListEntry {
                    name: "prod".into(),
                    id: "tenkai:env:prod".into(),
                    description: "fixture".into(),
                    subscription_count: 0,
                    deployed_product_count: 0,
                    lease_held: false,
                }])
            })
        }

        fn inspect_environment(&self, environment: String) -> InspectEnvFuture<'_> {
            Box::pin(async move {
                Ok(EnvironmentInspectReport {
                    name: environment,
                    id: "tenkai:env:prod".into(),
                    description: "fixture".into(),
                    subscriptions: Vec::new(),
                    facts: Default::default(),
                    overlays: Default::default(),
                    lease: crate::apply::EnvironmentLeaseInspect {
                        held: false,
                        owner: None,
                        generation: None,
                        expires_at_ms: None,
                        status: "absent".into(),
                    },
                    latest_plan: None,
                    terminal_outcomes: Vec::new(),
                    execution_note: "fixture".into(),
                    observed_type_digest: None,
                    observed_runtime_digest: None,
                    module_activations: Vec::new(),
                })
            })
        }

        fn environment_status(&self, _environment: String) -> StatusEnvFuture<'_> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn fleet_status(&self) -> FleetStatusFuture<'_> {
            Box::pin(async {
                Ok(FleetStatusReport {
                    environments: Vec::new(),
                    environment_count: 0,
                    environments_current: 0,
                    environments_behind: 0,
                    environments_unhealthy: 0,
                    environments_empty: 0,
                })
            })
        }

        fn apply_inventory_facts(
            &self,
            _environment: String,
            _facts: BTreeMap<String, String>,
        ) -> InventoryFuture<'_> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn diagnostics_snapshot(&self) -> crate::reconciler::ReconcileDiagnostics {
            crate::reconciler::ReconcileDiagnostics {
                ticks_total: 0,
                ticks_failed: 0,
                last_outcome: "ok".into(),
                last_environments_total: 0,
                last_environments_failed: 0,
                environments_busy_total: 0,
            }
        }
    }

    fn keypair() -> (SigningKey, String) {
        let signing = SigningKey::from_bytes(&[11_u8; 32]);
        let public_b64 =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().as_bytes());
        (signing, public_b64)
    }

    fn mint_jwt(signing_key: &SigningKey, claims: &BTreeMap<String, serde_json::Value>) -> String {
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": "k1" });
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    fn enterprise_ops(public_b64: &str) -> ManagementOperations {
        let verifier = JwtAssertionVerifier::new(JwtVerifierConfig {
            issuer: "https://idp.example.test/".into(),
            audience: "tenkai-control-plane".into(),
            keys: vec![JwtTrustedKey {
                key_id: Some("k1".into()),
                public_key: public_b64.into(),
            }],
            clock_skew_secs: 60,
        })
        .unwrap();
        let extension = Arc::new(JwtEnterpriseAuthExtension::from_jwt_verifier(
            "jwt-ref", verifier, false,
        ));
        let community = Arc::new(
            CommunityTokenAuthenticator::new(
                "auth.community",
                [(
                    "management-secret".into(),
                    PrincipalIdentity {
                        id: "management".into(),
                        kind: PrincipalKind::Management,
                    },
                )],
            )
            .unwrap(),
        );
        let auth = build_auth_stack(
            &AuthHostConfig {
                required_extension_id: Some("jwt-ref".into()),
                expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
                expected_audience: Some("tenkai-control-plane".into()),
            },
            Some(extension),
            community,
        )
        .unwrap();
        ManagementOperations::new(
            auth,
            false,
            Arc::new(FixedReconciler),
            Arc::new(SqliteStore::open_in_memory().unwrap()),
            None,
        )
    }

    fn human_claims(
        now: i64,
        capabilities: Option<Vec<&str>>,
    ) -> BTreeMap<String, serde_json::Value> {
        let mut claims = BTreeMap::from([
            (
                "iss".into(),
                serde_json::Value::String("https://idp.example.test/".into()),
            ),
            (
                "aud".into(),
                serde_json::Value::String("tenkai-control-plane".into()),
            ),
            ("sub".into(), serde_json::Value::String("user-42".into())),
            ("exp".into(), serde_json::json!(now + 3600)),
            (
                "principal_kind".into(),
                serde_json::Value::String("human".into()),
            ),
        ]);
        if let Some(capabilities) = capabilities {
            claims.insert(
                "tenkai_capabilities".into(),
                serde_json::Value::Array(
                    capabilities
                        .into_iter()
                        .map(|value| serde_json::Value::String(value.into()))
                        .collect(),
                ),
            );
        }
        claims
    }

    #[tokio::test]
    async fn jwt_without_management_capability_cannot_reconcile_or_read_fleet() {
        let (signing, public_b64) = keypair();
        let ops = enterprise_ops(&public_b64);
        let now = crate::assertion_verifier::now_unix_secs();
        let token = mint_jwt(&signing, &human_claims(now, None));
        let credential = CredentialMaterial {
            request_id: "req-human".into(),
            bearer_token: None,
            assertion: Some(token.into_bytes()),
        };

        let reconcile = ops.reconcile(&credential).await.unwrap_err();
        assert!(
            matches!(reconcile, ManagementError::Forbidden(ref msg) if msg.contains("capability")),
            "{reconcile:?}"
        );
        let fleet = ops.fleet_status(&credential).await.unwrap_err();
        assert!(
            matches!(fleet, ManagementError::Forbidden(ref msg) if msg.contains("capability")),
            "{fleet:?}"
        );
    }

    #[tokio::test]
    async fn jwt_with_read_only_capability_cannot_reconcile() {
        let (signing, public_b64) = keypair();
        let ops = enterprise_ops(&public_b64);
        let now = crate::assertion_verifier::now_unix_secs();
        let token = mint_jwt(&signing, &human_claims(now, Some(vec!["read"])));
        let credential = CredentialMaterial {
            request_id: "req-read".into(),
            bearer_token: None,
            assertion: Some(token.into_bytes()),
        };

        ops.fleet_status(&credential).await.unwrap();
        let reconcile = ops.reconcile(&credential).await.unwrap_err();
        assert!(
            matches!(reconcile, ManagementError::Forbidden(ref msg) if msg.contains("capability")),
            "{reconcile:?}"
        );
    }

    #[tokio::test]
    async fn jwt_with_management_capability_can_reconcile() {
        let (signing, public_b64) = keypair();
        let ops = enterprise_ops(&public_b64);
        let now = crate::assertion_verifier::now_unix_secs();
        let token = mint_jwt(
            &signing,
            &human_claims(now, Some(vec!["read", "management"])),
        );
        let credential = CredentialMaterial {
            request_id: "req-mgmt".into(),
            bearer_token: None,
            assertion: Some(token.into_bytes()),
        };
        let report = ops.reconcile(&credential).await.unwrap();
        assert_eq!(report.environments.len(), 1);
    }

    #[tokio::test]
    async fn community_management_token_remains_usable_under_enterprise_dual_stack() {
        let (_, public_b64) = keypair();
        let ops = enterprise_ops(&public_b64);
        let credential = CredentialMaterial {
            request_id: "req-community".into(),
            bearer_token: Some("management-secret".into()),
            assertion: None,
        };
        let report = ops.reconcile(&credential).await.unwrap();
        assert_eq!(report.environments[0].environment, "prod");
        ops.fleet_status(&credential).await.unwrap();
    }
}
