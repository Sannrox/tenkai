use crate::auth_context::AuthenticatedRequestContext;
use crate::runtime_capabilities::ComponentCapabilities;
use crate::storage::EnvironmentRecord;
use crate::tenant_isolation::IsolationError;
use crate::tenant_store::TenantOperationalStore;

use super::PostgresTenantOperationalStore;
use super::tenant_postgres_store_capabilities;

impl TenantOperationalStore for PostgresTenantOperationalStore {
    fn runtime_capabilities(&self) -> ComponentCapabilities {
        tenant_postgres_store_capabilities()
    }

    fn check_health(&self) -> crate::storage::Result<()> {
        #[cfg(feature = "postgres")]
        {
            self.inner.check_health()
        }
        #[cfg(not(feature = "postgres"))]
        {
            Err(crate::storage::StoreError::AdapterUnavailable(
                "postgres feature is disabled".into(),
            ))
        }
    }

    fn get_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        PostgresTenantOperationalStore::get_environment_for(self, context, environment_id)
    }

    fn put_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &EnvironmentRecord,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        PostgresTenantOperationalStore::put_environment_for(self, context, environment)
    }

    fn list_environment_ids_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<Vec<String>, IsolationError> {
        PostgresTenantOperationalStore::list_environment_ids_for(self, context)
    }

    fn import_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
    ) -> std::result::Result<crate::development_fixtures::FixtureMap, IsolationError> {
        PostgresTenantOperationalStore::import_development_fixture_for(self, context, fixture)
    }

    fn reset_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture_id: &str,
    ) -> std::result::Result<crate::development_fixtures::FixtureResetResult, IsolationError> {
        PostgresTenantOperationalStore::reset_development_fixture_for(self, context, fixture_id)
    }

    fn development_fixture_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<
        Option<crate::development_fixtures::FixtureEnvironmentProjection>,
        IsolationError,
    > {
        PostgresTenantOperationalStore::development_fixture_environment_for(
            self,
            context,
            environment_id,
        )
    }
}

impl PostgresTenantOperationalStore {
    /// Isolation checks when a live Postgres is available; no-op structure when feature off.
    pub fn run_partition_isolation_check(
        &self,
        ctx_a: &AuthenticatedRequestContext,
        ctx_b: &AuthenticatedRequestContext,
        env_a: &str,
        env_b: &str,
    ) -> std::result::Result<(), IsolationError> {
        self.put_environment_for(
            ctx_a,
            &EnvironmentRecord {
                id: env_a.into(),
                revision: 0,
                configuration_json: r#"{"tenant":"a"}"#.into(),
            },
        )?;
        self.put_environment_for(
            ctx_b,
            &EnvironmentRecord {
                id: env_b.into(),
                revision: 0,
                configuration_json: r#"{"tenant":"b"}"#.into(),
            },
        )?;
        let listed = self.list_environment_ids_for(ctx_a)?;
        if listed != vec![env_a.to_string()] {
            return Err(IsolationError::Contract(
                "postgres tenant list leaked or missed environments".into(),
            ));
        }
        match self.get_environment_for(ctx_a, env_b) {
            Err(IsolationError::NotFound) => Ok(()),
            Ok(_) => Err(IsolationError::Contract(
                "cross-tenant environment get succeeded".into(),
            )),
            Err(other) => Err(other),
        }
    }
}
