#[cfg(not(feature = "postgres"))]
use crate::storage::StoreError;
use crate::storage::{EnvironmentRecord, Result};

#[cfg(feature = "postgres")]
use super::postgres_imp;

/// One tenant's Postgres schema partition implementing
/// [`OperationalStore`](crate::storage::OperationalStore).
#[derive(Clone)]
pub struct PostgresTenantPartition {
    pub(crate) tenant_id: String,
    pub(crate) schema: String,
    #[cfg(feature = "postgres")]
    pub(crate) inner: std::sync::Arc<postgres_imp::Inner>,
    #[cfg(not(feature = "postgres"))]
    _private: (),
}

impl PostgresTenantPartition {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn expire_lease_for_conformance(&self, environment: &str) -> Result<()> {
        self.inner
            .expire_lease_for_conformance(&self.schema, environment)
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn cleanup_conformance_schema(&self) -> Result<()> {
        self.inner.cleanup_conformance_schema(&self.schema)
    }

    pub fn get_environment(&self, id: &str) -> Result<Option<EnvironmentRecord>> {
        #[cfg(feature = "postgres")]
        {
            self.inner.get_environment(&self.schema, id)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = id;
            Err(StoreError::AdapterUnavailable(
                "postgres feature disabled".into(),
            ))
        }
    }

    pub fn put_environment_record(
        &self,
        environment: &EnvironmentRecord,
    ) -> Result<EnvironmentRecord> {
        #[cfg(feature = "postgres")]
        {
            self.inner.put_environment(&self.schema, environment)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = environment;
            Err(StoreError::AdapterUnavailable(
                "postgres feature disabled".into(),
            ))
        }
    }

    pub fn list_environment_ids(&self) -> Result<Vec<String>> {
        #[cfg(feature = "postgres")]
        {
            self.inner.list_environment_ids(&self.schema)
        }
        #[cfg(not(feature = "postgres"))]
        {
            Err(StoreError::AdapterUnavailable(
                "postgres feature disabled".into(),
            ))
        }
    }

    pub fn import_development_fixture(
        &self,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureMap> {
        #[cfg(feature = "postgres")]
        {
            self.inner
                .import_development_fixture(&self.schema, fixture, actor, request_id)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (fixture, actor, request_id);
            Err(StoreError::AdapterUnavailable(
                "postgres feature disabled".into(),
            ))
        }
    }

    pub fn reset_development_fixture(
        &self,
        fixture_id: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureResetResult> {
        #[cfg(feature = "postgres")]
        {
            self.inner
                .reset_development_fixture(&self.schema, fixture_id, actor, request_id)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (fixture_id, actor, request_id);
            Err(StoreError::AdapterUnavailable(
                "postgres feature disabled".into(),
            ))
        }
    }

    pub fn development_fixture_environment(
        &self,
        environment_id: &str,
    ) -> Result<Option<crate::development_fixtures::FixtureEnvironmentProjection>> {
        #[cfg(feature = "postgres")]
        {
            self.inner
                .development_fixture_environment(&self.schema, environment_id)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = environment_id;
            Err(StoreError::AdapterUnavailable(
                "postgres feature disabled".into(),
            ))
        }
    }
}
