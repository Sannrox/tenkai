use postgres::{Client, Transaction};
use std::sync::Mutex;

pub(crate) use crate::storage::{
    AuditRecord, ChannelRecord, EnvironmentRecord, LeaseRecord, OfflineImportRecord,
    OfflineStepImportRecord, PlanRecord, PlanStatus, ProviderEventRecord, ReceiptRecord,
    ReleaseRecord, Result, RollbackRecord, RollbackStatus, RuntimeClaim, SCHEMA_VERSION,
    StoreError, provider_event_payloads_match, rollback_intent_digest,
};

pub struct Inner {
    pub(crate) client: Mutex<Option<Client>>,
}

pub(crate) fn pg(err: postgres::Error) -> StoreError {
    let message = err
        .as_db_error()
        .map(|database| format!("{} ({})", database.message(), database.code().code()))
        .unwrap_or_else(|| err.to_string());
    StoreError::Postgres(message)
}

/// Run blocking `postgres::Client` work off any Tokio worker.
///
/// `postgres 0.19`'s synchronous facade builds an inner runtime and `block_on`s
/// it. `tokio::task::spawn_blocking` still has a `Handle`, so connect/query
/// from that path panics with "Cannot start a runtime from within a runtime".
pub(crate) fn without_tokio_err<T: Send, E: Send>(
    work: impl FnOnce() -> std::result::Result<T, E> + Send,
    panicked: E,
) -> std::result::Result<T, E> {
    if tokio::runtime::Handle::try_current().is_err() {
        return work();
    }
    std::thread::scope(|scope| match scope.spawn(work).join() {
        Ok(value) => value,
        Err(_) => Err(panicked),
    })
}

pub(crate) fn without_tokio<T: Send>(work: impl FnOnce() -> Result<T> + Send) -> Result<T> {
    without_tokio_err(
        work,
        StoreError::Postgres("postgres worker thread panicked".into()),
    )
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
    pub(crate) fn with_schema<T: Send>(
        &self,
        schema: &str,
        f: impl FnOnce(&mut Transaction<'_>) -> Result<T> + Send,
    ) -> Result<T> {
        without_tokio(|| {
            let mut guard = self.client.lock().map_err(|_| StoreError::Poisoned)?;
            let client = guard.as_mut().ok_or(StoreError::Poisoned)?;
            let mut tx = client.transaction().map_err(pg)?;
            // Identifier is sanitized by tenant_schema_name (alnum + underscore only).
            tx.batch_execute(&format!("SET LOCAL search_path TO {schema}, public"))
                .map_err(pg)?;
            let out = f(&mut tx)?;
            tx.commit().map_err(pg)?;
            Ok(out)
        })
    }
}

impl Inner {
    pub fn check_health(&self) -> Result<()> {
        without_tokio(|| {
            let mut guard = self.client.lock().map_err(|_| StoreError::Poisoned)?;
            let client = guard.as_mut().ok_or(StoreError::Poisoned)?;
            client.query_one("SELECT 1", &[]).map_err(pg)?;
            Ok(())
        })
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = without_tokio(|| {
            if let Ok(mut guard) = self.client.lock() {
                drop(guard.take());
            }
            Ok(())
        });
    }
}
