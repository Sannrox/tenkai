use postgres::{Client, Transaction};
use std::sync::Mutex;

pub(crate) use crate::storage::{
    AuditRecord, ChannelRecord, EnvironmentRecord, LeaseRecord, OfflineImportRecord,
    OfflineStepImportRecord, PlanRecord, PlanStatus, ProviderEventRecord, ReceiptRecord,
    ReleaseRecord, Result, RollbackRecord, RollbackStatus, RuntimeClaim, SCHEMA_VERSION,
    StoreError, provider_event_payloads_match, rollback_intent_digest,
};

pub struct Inner {
    pub(crate) client: Mutex<Client>,
}

pub(crate) fn pg(err: postgres::Error) -> StoreError {
    let message = err
        .as_db_error()
        .map(|database| format!("{} ({})", database.message(), database.code().code()))
        .unwrap_or_else(|| err.to_string());
    StoreError::Postgres(message)
}

mod catalog;
mod channels;
mod connect;
mod fixtures;
mod fixtures_reset;
mod leases;
mod plans;
mod provider_claim;
mod provider_lifecycle;
mod provider_queue;
mod receipts;
mod reconcile;
mod rollbacks;
mod runtime;
mod schema;

pub(crate) use leases::{lock_lease, require_lease, require_plan_environment};
pub(crate) use schema::migrate_tenant_schema;

impl Inner {
    pub(crate) fn with_schema<T>(
        &self,
        schema: &str,
        f: impl FnOnce(&mut Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut client = self.client.lock().map_err(|_| StoreError::Poisoned)?;
        let mut tx = client.transaction().map_err(pg)?;
        // Identifier is sanitized by tenant_schema_name (alnum + underscore only).
        tx.batch_execute(&format!("SET LOCAL search_path TO {schema}, public"))
            .map_err(pg)?;
        let out = f(&mut tx)?;
        tx.commit().map_err(pg)?;
        Ok(out)
    }
}

impl Inner {
    pub fn check_health(&self) -> Result<()> {
        let mut client = self.client.lock().map_err(|_| StoreError::Poisoned)?;
        client.query_one("SELECT 1", &[]).map_err(pg)?;
        Ok(())
    }
}
