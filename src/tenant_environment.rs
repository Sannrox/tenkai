//! Tenant-only Environment application operations.
//!
//! This deep module resolves authenticated tenant visibility before reads or
//! bounded reconciliation. It also hides synchronous tenant-store adaptation,
//! development-fixture projections, tenant-free outcome suppression, and
//! non-disclosing failures from transport adapters.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::auth_context::AuthenticatedRequestContext;
use crate::plan::{EnvironmentInspectReport, EnvironmentListEntry, FleetStatusReport, StatusRow};
use crate::reconciler::TickReport;
use crate::tenant_isolation::IsolationError;
use crate::tenant_store::TenantOperationalStore;

pub type TenantEnvironmentFuture<'a, T> =
    Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

/// Narrow view of shared Environment behavior needed by tenant operations.
pub trait TenantEnvironmentView: Send + Sync {
    fn inspect_without_outcome_export(
        &self,
        environment: String,
    ) -> TenantEnvironmentFuture<'_, EnvironmentInspectReport>;
    fn status(&self, environment: String) -> TenantEnvironmentFuture<'_, Vec<StatusRow>>;
    fn fleet_without_outcome_export(&self) -> TenantEnvironmentFuture<'_, FleetStatusReport>;
    fn reconcile_bounded(
        &self,
        environments: Vec<String>,
    ) -> TenantEnvironmentFuture<'_, TickReport>;
}

#[derive(Debug, thiserror::Error)]
pub enum TenantEnvironmentError {
    #[error("tenant store unavailable")]
    StoreUnavailable,
    #[error("tenant environment not found")]
    NotFound,
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    Internal(String),
}

/// Deep tenant-only Environment operations used after host authentication.
pub struct TenantEnvironmentOperations {
    store: Arc<dyn TenantOperationalStore>,
    view: Arc<dyn TenantEnvironmentView>,
}

impl TenantEnvironmentOperations {
    pub fn new(
        store: Arc<dyn TenantOperationalStore>,
        view: Arc<dyn TenantEnvironmentView>,
    ) -> Self {
        Self { store, view }
    }

    pub async fn list(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<Vec<EnvironmentListEntry>, TenantEnvironmentError> {
        let store = self.store.clone();
        let context = context.clone();
        run_store(move || {
            let ids = store.list_environment_ids_for(&context)?;
            let mut entries = Vec::with_capacity(ids.len());
            for name in ids {
                match store.development_fixture_environment_for(&context, &name)? {
                    Some(projection) => entries.push(projection.list_entry()),
                    None => entries.push(EnvironmentListEntry {
                        name: name.clone(),
                        id: format!("tenkai:env:{name}"),
                        description: String::new(),
                        subscription_count: 0,
                        deployed_product_count: 0,
                        lease_held: false,
                    }),
                }
            }
            Ok(entries)
        })
        .await
    }

    pub async fn fleet_status(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<FleetStatusReport, TenantEnvironmentError> {
        let store = self.store.clone();
        let context = context.clone();
        let (fixture_rows, reconciler_ids) = run_store(move || {
            let allowed = store.list_environment_ids_for(&context)?;
            let mut fixture_rows = Vec::new();
            let mut reconciler_ids = Vec::new();
            for id in allowed {
                match store.development_fixture_environment_for(&context, &id)? {
                    Some(projection) => fixture_rows.push(projection.fleet_row()),
                    None => reconciler_ids.push(id),
                }
            }
            Ok((fixture_rows, reconciler_ids))
        })
        .await?;
        let mut report = self
            .view
            .fleet_without_outcome_export()
            .await
            .map_err(internal)?;
        report
            .environments
            .retain(|row| reconciler_ids.iter().any(|id| id == &row.name));
        report.environments.extend(fixture_rows);
        report
            .environments
            .sort_by(|left, right| left.name.cmp(&right.name));
        Ok(crate::plan::fleet_status_from_rows(report.environments))
    }

    pub async fn inspect(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &str,
    ) -> Result<EnvironmentInspectReport, TenantEnvironmentError> {
        let fixture = self.visible_fixture(context, environment).await?;
        if let Some(projection) = fixture {
            return Ok(projection.inspect_report());
        }
        self.view
            .inspect_without_outcome_export(environment.to_string())
            .await
            .map_err(map_environment_error)
    }

    pub async fn status(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &str,
    ) -> Result<Vec<StatusRow>, TenantEnvironmentError> {
        let fixture = self.visible_fixture(context, environment).await?;
        if let Some(projection) = fixture {
            return Ok(projection.status_rows());
        }
        self.view
            .status(environment.to_string())
            .await
            .map_err(map_environment_error)
    }

    pub async fn reconcile(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<TickReport, TenantEnvironmentError> {
        let store = self.store.clone();
        let context = context.clone();
        let environments = run_store(move || store.list_environment_ids_for(&context)).await?;
        self.view
            .reconcile_bounded(environments)
            .await
            .map_err(internal)
    }

    async fn visible_fixture(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &str,
    ) -> Result<
        Option<crate::development_fixtures::FixtureEnvironmentProjection>,
        TenantEnvironmentError,
    > {
        let store = self.store.clone();
        let context = context.clone();
        let environment = environment.to_string();
        run_store(move || {
            store.get_environment_for(&context, &environment)?;
            store.development_fixture_environment_for(&context, &environment)
        })
        .await
    }
}

async fn run_store<T, F>(operation: F) -> Result<T, TenantEnvironmentError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, IsolationError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            eprintln!("tenant store blocking task failed: {error}");
            TenantEnvironmentError::StoreUnavailable
        })?
        .map_err(map_isolation_error)
}

fn map_isolation_error(error: IsolationError) -> TenantEnvironmentError {
    match error {
        IsolationError::NotFound => TenantEnvironmentError::NotFound,
        IsolationError::Unauthenticated | IsolationError::InvalidCredential(_) => {
            TenantEnvironmentError::Denied(error.public_message())
        }
        IsolationError::Contract(_) => TenantEnvironmentError::Internal(error.public_message()),
    }
}

fn map_environment_error(error: anyhow::Error) -> TenantEnvironmentError {
    let message = format!("{error:#}");
    if message.contains("not registered") {
        TenantEnvironmentError::NotFound
    } else {
        TenantEnvironmentError::Internal(message)
    }
}

fn internal(error: anyhow::Error) -> TenantEnvironmentError {
    TenantEnvironmentError::Internal(format!("{error:#}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };
    use crate::storage::EnvironmentRecord;
    use crate::tenant_store::InMemoryTenantOperationalStore;

    #[derive(Default)]
    struct View {
        reconciled: Mutex<Vec<String>>,
    }

    impl TenantEnvironmentView for View {
        fn inspect_without_outcome_export(
            &self,
            environment: String,
        ) -> TenantEnvironmentFuture<'_, EnvironmentInspectReport> {
            Box::pin(async move { anyhow::bail!("environment {environment} not registered") })
        }

        fn status(&self, environment: String) -> TenantEnvironmentFuture<'_, Vec<StatusRow>> {
            Box::pin(async move { anyhow::bail!("environment {environment} not registered") })
        }

        fn fleet_without_outcome_export(&self) -> TenantEnvironmentFuture<'_, FleetStatusReport> {
            Box::pin(async { Ok(crate::plan::fleet_status_from_rows(Vec::new())) })
        }

        fn reconcile_bounded(
            &self,
            environments: Vec<String>,
        ) -> TenantEnvironmentFuture<'_, TickReport> {
            *self.reconciled.lock().unwrap() = environments.clone();
            Box::pin(async move {
                Ok(TickReport {
                    environments: environments
                        .into_iter()
                        .map(|environment| crate::reconciler::EnvironmentResult {
                            environment,
                            status: crate::reconciler::EnvironmentStatus::Current,
                        })
                        .collect(),
                })
            })
        }
    }

    fn context(tenant: &str) -> AuthenticatedRequestContext {
        AuthenticatedRequestContextBuilder::new(
            format!("request-{tenant}"),
            PrincipalIdentity {
                id: format!("principal-{tenant}"),
                kind: PrincipalKind::Human,
            },
            "auth.test",
        )
        .with_tenant(tenant, &TenantDerivationAuthority::new("auth.test"))
        .unwrap()
        .build()
        .unwrap()
    }

    #[tokio::test]
    async fn list_and_reconcile_use_only_authenticated_tenant_environments() {
        let store = Arc::new(InMemoryTenantOperationalStore::new());
        let tenant_a = context("tenant-a");
        let tenant_b = context("tenant-b");
        store
            .put_environment_for(
                &tenant_a,
                &EnvironmentRecord {
                    id: "env-a".into(),
                    revision: 0,
                    configuration_json: "{}".into(),
                },
            )
            .unwrap();
        store
            .put_environment_for(
                &tenant_b,
                &EnvironmentRecord {
                    id: "env-b".into(),
                    revision: 0,
                    configuration_json: "{}".into(),
                },
            )
            .unwrap();
        let view = Arc::new(View::default());
        let operations = TenantEnvironmentOperations::new(store, view.clone());

        let listed = operations.list(&tenant_a).await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["env-a"]
        );
        let report = operations.reconcile(&tenant_a).await.unwrap();
        assert_eq!(report.environments[0].environment, "env-a");
        assert_eq!(*view.reconciled.lock().unwrap(), vec!["env-a"]);
    }

    #[tokio::test]
    async fn inspection_rejects_foreign_environment_before_shared_view() {
        let store = Arc::new(InMemoryTenantOperationalStore::new());
        let tenant_a = context("tenant-a");
        let tenant_b = context("tenant-b");
        store
            .put_environment_for(
                &tenant_b,
                &EnvironmentRecord {
                    id: "env-b".into(),
                    revision: 0,
                    configuration_json: "{}".into(),
                },
            )
            .unwrap();
        let operations = TenantEnvironmentOperations::new(store, Arc::new(View::default()));

        let error = operations.inspect(&tenant_a, "env-b").await.unwrap_err();
        assert!(matches!(error, TenantEnvironmentError::NotFound));
    }
}
