use crate::auth_context::AuthenticatedRequestContext;
use crate::runtime_capabilities::ComponentCapabilities;
use crate::storage::EnvironmentRecord;
#[cfg(feature = "postgres")]
use crate::storage::Result;
use crate::tenant_isolation::IsolationError;

#[cfg(feature = "postgres")]
use super::PostgresReconcileFence;
#[cfg(feature = "postgres")]
use super::PostgresTenantConfig;
use super::PostgresTenantPartition;
#[cfg(feature = "postgres")]
use super::postgres_imp;
use super::tenant_postgres_store_capabilities;
use super::tenant_schema_name;

/// Multi-tenant Postgres operational store factory (hub).
///
/// Each authenticated tenant gets an isolated schema with the full Tenkai
/// operational table set. Cross-tenant access is non-disclosing.
#[derive(Clone)]
pub struct PostgresTenantOperationalStore {
    #[cfg(feature = "postgres")]
    pub(crate) inner: std::sync::Arc<postgres_imp::Inner>,
    #[cfg(not(feature = "postgres"))]
    _private: (),
}

impl PostgresTenantOperationalStore {
    pub fn runtime_capabilities(&self) -> ComponentCapabilities {
        tenant_postgres_store_capabilities()
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn connect(config: &PostgresTenantConfig) -> Result<Self> {
        Ok(Self {
            inner: std::sync::Arc::new(postgres_imp::Inner::connect(&config.url)?),
        })
    }

    /// Durable multi-host reconcile tick fence backed by hub Postgres (#135).
    #[cfg(feature = "postgres")]
    pub fn reconcile_tick_fence(
        &self,
    ) -> std::sync::Arc<dyn crate::reconcile_fence::ReconcileTickFence> {
        std::sync::Arc::new(PostgresReconcileFence {
            inner: self.inner.clone(),
        })
    }

    pub fn partition_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<PostgresTenantPartition, IsolationError> {
        context
            .validate()
            .map_err(|error| IsolationError::InvalidCredential(error.to_string()))?;
        let tenant_id = context
            .tenant()
            .map(|tenant| tenant.tenant_id().to_string())
            .ok_or(IsolationError::Unauthenticated)?;
        self.partition_by_id(&tenant_id)
    }

    fn partition_by_id(
        &self,
        tenant_id: &str,
    ) -> std::result::Result<PostgresTenantPartition, IsolationError> {
        let schema = tenant_schema_name(tenant_id)
            .map_err(|error| IsolationError::Contract(error.to_string()))?;
        #[cfg(feature = "postgres")]
        {
            self.inner
                .ensure_tenant_schema(&schema)
                .map_err(|error| IsolationError::Contract(error.to_string()))?;
            Ok(PostgresTenantPartition {
                tenant_id: tenant_id.to_string(),
                schema,
                inner: self.inner.clone(),
            })
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = schema;
            Err(IsolationError::Contract(
                "postgres feature is not enabled in this binary".into(),
            ))
        }
    }

    pub fn get_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        let partition = self.partition_for(context)?;
        match partition.get_environment(environment_id) {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(IsolationError::NotFound),
            Err(error) => Err(IsolationError::Contract(error.to_string())),
        }
    }

    pub fn put_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &EnvironmentRecord,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        let partition = self.partition_for(context)?;
        if partition
            .get_environment(&environment.id)
            .map_err(|error| IsolationError::Contract(error.to_string()))?
            .is_some_and(|stored| {
                crate::environment::retirement_from_configuration_json(&stored.configuration_json)
                    .is_some()
            })
        {
            return Err(IsolationError::Contract(format!(
                "environment {} is retired; registering it again requires a new environment name",
                environment.id
            )));
        }
        partition
            .put_environment_record(environment)
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    pub fn list_environment_ids_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<Vec<String>, IsolationError> {
        let partition = self.partition_for(context)?;
        partition
            .list_environment_ids()
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    pub fn current_lease_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &str,
    ) -> std::result::Result<Option<crate::storage::LeaseRecord>, IsolationError> {
        let partition = self.partition_for(context)?;
        #[cfg(feature = "postgres")]
        {
            use crate::storage::OperationalStore as _;
            partition
                .current_lease(environment)
                .map_err(|error| IsolationError::Contract(error.to_string()))
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (partition, environment);
            Err(IsolationError::Contract(
                "postgres feature is disabled".into(),
            ))
        }
    }

    pub fn import_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
    ) -> std::result::Result<crate::development_fixtures::FixtureMap, IsolationError> {
        let partition = self.partition_for(context)?;
        partition
            .import_development_fixture(fixture, context.principal_id(), &context.request_id)
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    pub fn reset_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture_id: &str,
    ) -> std::result::Result<crate::development_fixtures::FixtureResetResult, IsolationError> {
        let partition = self.partition_for(context)?;
        partition
            .reset_development_fixture(fixture_id, context.principal_id(), &context.request_id)
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    pub fn development_fixture_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<
        Option<crate::development_fixtures::FixtureEnvironmentProjection>,
        IsolationError,
    > {
        self.partition_for(context)?
            .development_fixture_environment(environment_id)
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }
}
