//! Authenticated management operations shared by network adapters.
//!
//! This deep module owns management authentication, tenant-aware application
//! dispatch, reconciliation audit ordering, and public failure classification.
//! Transport adapters retain credential extraction and response encoding.

use std::sync::Arc;

use crate::auth_context::{AuthMode, AuthStack, AuthenticatedRequestContext, CredentialMaterial};
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

    pub(crate) async fn fleet_status(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<FleetStatusReport, ManagementError> {
        let context = self.authenticate(credential)?;
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
