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
    Conflict(String),
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
            let ids = store.list_active_environment_ids_for(&context)?;
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
                        delivery_held: false,
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
        let mut rows = run_store(move || {
            let allowed = store.list_active_environment_ids_for(&context)?;
            let mut rows = Vec::with_capacity(allowed.len());
            for id in allowed {
                match store.development_fixture_environment_for(&context, &id)? {
                    Some(projection) => rows.push(projection.fleet_row()),
                    None => rows.push(partition_local_fleet_row(&id)),
                }
            }
            Ok(rows)
        })
        .await?;
        rows.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(crate::plan::fleet_status_from_rows(rows))
    }

    pub async fn inspect(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &str,
    ) -> Result<EnvironmentInspectReport, TenantEnvironmentError> {
        let retirement = self.retirement(context, environment).await?;
        let fixture = self.visible_fixture(context, environment).await?;
        if let Some(projection) = fixture {
            let mut report = projection.inspect_report();
            report.retirement = retirement;
            return Ok(report);
        }
        let mut report = partition_local_inspect(environment);
        report.retirement = retirement;
        Ok(report)
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
        Ok(Vec::new())
    }

    pub async fn reconcile(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<TickReport, TenantEnvironmentError> {
        let store = self.store.clone();
        let context = context.clone();
        let environments =
            run_store(move || store.list_active_environment_ids_for(&context)).await?;
        self.view
            .reconcile_bounded(environments)
            .await
            .map_err(internal)
    }

    pub async fn retire(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &str,
        reason: &str,
        actor: &str,
    ) -> Result<crate::environment::EnvironmentRetirement, TenantEnvironmentError> {
        if reason.trim().is_empty() {
            return Err(TenantEnvironmentError::Denied(
                "retirement reason must not be empty".into(),
            ));
        }
        if reason.trim().len() > 1024 {
            return Err(TenantEnvironmentError::Denied(
                "retirement reason exceeds 1024 bytes".into(),
            ));
        }
        let store = self.store.clone();
        let context = context.clone();
        let environment = environment.to_owned();
        let reason = reason.trim().to_owned();
        let actor = actor.to_owned();
        let result = run_store(move || {
            let mut record = store.get_environment_for(&context, &environment)?;
            if let Some(retirement) =
                crate::environment::retirement_from_configuration_json(&record.configuration_json)
            {
                return Ok(retirement);
            }
            if store
                .development_fixture_environment_for(&context, &environment)?
                .is_some()
            {
                return Err(IsolationError::Contract(
                    "development fixture environments are immutable".into(),
                ));
            }
            if store
                .current_lease_for(&context, &environment)?
                .is_some_and(|lease| lease.expires_at > crate::now_millis())
            {
                return Err(IsolationError::Contract(format!(
                    "environment {environment} has an apply in progress; unlock it before retiring"
                )));
            }
            let retirement = crate::environment::EnvironmentRetirement {
                reason,
                actor,
                retired_at: crate::now_millis(),
            };
            record.configuration_json =
                crate::environment::with_tenant_retirement(&record.configuration_json, &retirement)
                    .map_err(|error| IsolationError::Contract(error.to_string()))?;
            match store.put_environment_for(&context, &record) {
                Ok(_) => Ok(retirement),
                Err(error) => match store.get_environment_for(&context, &environment) {
                    Ok(current) => crate::environment::retirement_from_configuration_json(
                        &current.configuration_json,
                    )
                    .ok_or(error),
                    Err(_) => Err(error),
                },
            }
        })
        .await;
        result.map_err(|error| match error {
            TenantEnvironmentError::Internal(message)
                if message.contains("apply in progress")
                    || message.contains("active delivery work") =>
            {
                TenantEnvironmentError::Conflict(message)
            }
            error => error,
        })
    }

    async fn retirement(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &str,
    ) -> Result<Option<crate::environment::EnvironmentRetirement>, TenantEnvironmentError> {
        let store = self.store.clone();
        let context = context.clone();
        let environment = environment.to_owned();
        run_store(move || {
            let record = store.get_environment_for(&context, &environment)?;
            Ok(crate::environment::retirement_from_configuration_json(
                &record.configuration_json,
            ))
        })
        .await
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

fn internal(error: anyhow::Error) -> TenantEnvironmentError {
    TenantEnvironmentError::Internal(format!("{error:#}"))
}

fn partition_local_fleet_row(name: &str) -> crate::plan::FleetEnvironmentRow {
    crate::plan::FleetEnvironmentRow {
        name: name.to_string(),
        id: format!("tenkai:env:{name}"),
        description: String::new(),
        subscription_count: 0,
        products_current: 0,
        products_behind: 0,
        products_missing: 0,
        unhealthy: false,
        health_summary: "n/a".into(),
        lease_held: false,
        latest_plan_state: None,
        posture: "empty".into(),
    }
}

fn partition_local_inspect(name: &str) -> EnvironmentInspectReport {
    EnvironmentInspectReport {
        name: name.to_string(),
        id: format!("tenkai:env:{name}"),
        description: String::new(),
        subscriptions: Vec::new(),
        facts: Default::default(),
        overlays: Default::default(),
        lease: crate::apply::EnvironmentLeaseInspect {
            held: false,
            owner: None,
            generation: None,
            expires_at_ms: None,
            status: "partition_local".into(),
        },
        latest_plan: None,
        maintenance: None,
        constraints: Vec::new(),
        terminal_outcomes: Vec::new(),
        execution_note: "Tenant partition projection; process-global reconciler rows are not joined by environment name.".into(),
        observed_type_digest: None,
        observed_runtime_digest: None,
        module_activations: Vec::new(),
        preview: None,
        retirement: None,
        delivery_hold: None,
    }
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
    async fn retirement_is_tenant_scoped_and_keeps_inspection_evidence() {
        let store = Arc::new(InMemoryTenantOperationalStore::new());
        let tenant_a = context("tenant-a");
        let tenant_b = context("tenant-b");
        for (context, environment) in [(&tenant_a, "prod"), (&tenant_b, "prod")] {
            store
                .put_environment_for(
                    context,
                    &EnvironmentRecord {
                        id: environment.into(),
                        revision: 0,
                        configuration_json: "{}".into(),
                    },
                )
                .unwrap();
        }
        let view = Arc::new(View::default());
        let operations = TenantEnvironmentOperations::new(store.clone(), view.clone());
        let retirement = operations
            .retire(&tenant_a, "prod", "service ended", "principal-tenant-a")
            .await
            .unwrap();
        assert_eq!(
            operations
                .retire(&tenant_a, "prod", "ignored", "another-principal")
                .await
                .unwrap(),
            retirement
        );
        assert!(operations.list(&tenant_a).await.unwrap().is_empty());
        assert_eq!(
            operations
                .fleet_status(&tenant_a)
                .await
                .unwrap()
                .environment_count,
            0
        );
        assert!(
            operations
                .reconcile(&tenant_a)
                .await
                .unwrap()
                .environments
                .is_empty()
        );
        assert_eq!(
            operations
                .inspect(&tenant_a, "prod")
                .await
                .unwrap()
                .retirement,
            Some(retirement.clone())
        );
        assert_eq!(operations.list(&tenant_b).await.unwrap().len(), 1);
        assert_eq!(
            operations
                .inspect(&tenant_b, "prod")
                .await
                .unwrap()
                .retirement,
            None
        );
        let mut updated = store.get_environment_for(&tenant_a, "prod").unwrap();
        updated.configuration_json = "{}".into();
        assert!(store.put_environment_for(&tenant_a, &updated).is_err());
        let partition = store.partition_for(&tenant_a).unwrap();
        assert!(
            crate::storage::OperationalStore::claim_runtime_plan(
                &partition,
                "prod",
                "plan-1",
                "runtime",
                crate::now_millis() + 60_000,
            )
            .unwrap_err()
            .to_string()
            .contains("retired")
        );
        assert!(view.reconciled.lock().unwrap().is_empty());
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

    struct SharedNameView;

    fn foreign_prod_inspect() -> EnvironmentInspectReport {
        EnvironmentInspectReport {
            name: "prod".into(),
            id: "tenkai:env:prod".into(),
            description: "foreign delivery".into(),
            subscriptions: vec![crate::plan::EnvironmentSubscriptionView {
                product: "secret-app".into(),
                channel: "stable".into(),
                head: "9.9.9".into(),
                deployed: Some("9.9.9".into()),
                health: Some("ok".into()),
                error: None,
                overlay_digest: None,
                applied_overlay: None,
                state: "current".into(),
                delivery_hold: None,
            }],
            facts: Default::default(),
            overlays: Default::default(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: true,
                owner: Some("foreign-controller".into()),
                generation: Some(7),
                expires_at_ms: None,
                status: "held".into(),
            },
            latest_plan: None,
            maintenance: None,
            constraints: Vec::new(),
            terminal_outcomes: Vec::new(),
            execution_note: "foreign".into(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
            retirement: None,
            preview: None,
            delivery_hold: None,
        }
    }

    impl TenantEnvironmentView for SharedNameView {
        fn inspect_without_outcome_export(
            &self,
            _environment: String,
        ) -> TenantEnvironmentFuture<'_, EnvironmentInspectReport> {
            Box::pin(async { Ok(foreign_prod_inspect()) })
        }

        fn status(&self, _environment: String) -> TenantEnvironmentFuture<'_, Vec<StatusRow>> {
            Box::pin(async {
                Ok(vec![StatusRow {
                    product: "secret-app".into(),
                    channel: "stable".into(),
                    deployed: Some("9.9.9".into()),
                    health: Some("ok".into()),
                    error: None,
                    head: "9.9.9".into(),
                    overlay_stale: false,
                    delivery_hold: None,
                }])
            })
        }

        fn fleet_without_outcome_export(&self) -> TenantEnvironmentFuture<'_, FleetStatusReport> {
            Box::pin(async {
                Ok(crate::plan::fleet_status_from_inspects(vec![
                    foreign_prod_inspect(),
                ]))
            })
        }

        fn reconcile_bounded(
            &self,
            environments: Vec<String>,
        ) -> TenantEnvironmentFuture<'_, TickReport> {
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

    #[tokio::test]
    async fn colliding_environment_names_do_not_join_process_global_reconciler() {
        let store = Arc::new(InMemoryTenantOperationalStore::new());
        let tenant_a = context("tenant-a");
        let tenant_b = context("tenant-b");
        for context in [&tenant_a, &tenant_b] {
            store
                .put_environment_for(
                    context,
                    &EnvironmentRecord {
                        id: "prod".into(),
                        revision: 0,
                        configuration_json: "{}".into(),
                    },
                )
                .unwrap();
        }
        let operations = TenantEnvironmentOperations::new(store, Arc::new(SharedNameView));

        let fleet = operations.fleet_status(&tenant_b).await.unwrap();
        assert_eq!(fleet.environments.len(), 1);
        assert_eq!(fleet.environments[0].name, "prod");
        assert_eq!(fleet.environments[0].posture, "empty");
        assert_eq!(fleet.environments[0].subscription_count, 0);
        assert!(!fleet.environments[0].lease_held);
        assert!(
            !serde_json::to_string(&fleet)
                .unwrap()
                .contains("secret-app"),
            "{fleet:?}"
        );

        let inspect = operations.inspect(&tenant_b, "prod").await.unwrap();
        assert!(inspect.subscriptions.is_empty(), "{inspect:?}");
        assert!(!inspect.lease.held);
        assert!(
            inspect.execution_note.contains("process-global"),
            "{}",
            inspect.execution_note
        );

        let status = operations.status(&tenant_b, "prod").await.unwrap();
        assert!(status.is_empty(), "{status:?}");
    }
}
