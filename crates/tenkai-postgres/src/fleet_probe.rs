//! Store probe for the `ci-hub-postgres` fleet profile (#1084).

use anyhow::Result;
use tenkai::fleet_budget::{DatabaseLoad, StoreProbe};

use crate::{PostgresTenantOperationalStore, tenant_schema_name};

/// Reads one tenant's schema size and the database's load counters through
/// the same store connection the measured fleet uses.
pub struct HubTenantProbe {
    store: PostgresTenantOperationalStore,
    schema: String,
}

impl HubTenantProbe {
    pub fn new(store: PostgresTenantOperationalStore, tenant: &str) -> Result<Self> {
        Ok(Self {
            store,
            schema: tenant_schema_name(tenant)?,
        })
    }
}

impl StoreProbe for HubTenantProbe {
    fn storage_bytes(&self) -> Result<u64> {
        Ok(self.store.inner.schema_bytes(&self.schema)?)
    }

    fn database_load(&self) -> Result<Option<DatabaseLoad>> {
        Ok(Some(self.store.inner.database_counters()?))
    }
}
