//! SQLite catalog and operational adapter for community Tenkai hosts.
//!
//! `tenkai` talks to [`tenkai::storage::CatalogGraph`] and
//! [`tenkai::storage::OperationalStore`]. This crate owns `rusqlite` and the
//! bundled libsqlite3, file open, WAL, busy timeout, pre-migration copy, and
//! file backup. Composition crates (`tenkaictl`, `tenkai-server`) wire it.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use tenkai::environment::retirement_from_configuration_json;
use tenkai::ontology::env_id;
use tenkai::storage::{
    AuditRecord, CatalogGraph, ChannelRecord, EnvironmentRecord, LeaseRecord, LeaseRefresh,
    OfflineImportRecord, OfflineStepImportRecord, OperationalStore, PlanRecord, PlanStatus,
    ProviderEventPosition, ProviderEventRecord, ReceiptRecord, ReleaseRecord, RollbackRecord,
    RollbackStatus, RuntimeActivityRecord, RuntimeAttestationRecord, RuntimeClaim,
    RuntimeCredentialRecord, RuntimeEnrollmentRecord, RuntimeRevocation, RuntimeRunnerRecord,
    RuntimeSealingKeyRecord, SCHEMA_VERSION, StoreError, provider_event_environment_id,
    provider_event_observed_at,
};

#[derive(Debug)]
pub enum Error {
    Store(StoreError),
    Sqlite(rusqlite::Error),
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<Error> for StoreError {
    fn from(error: Error) -> Self {
        match error {
            Error::Store(error) => error,
            Error::Sqlite(error) => Self::Database(error.to_string()),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "{error}"),
            Self::Sqlite(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

mod audit;
mod catalog;
mod catalog_graph;
mod change_events;
mod fixture_matching;
mod fixtures;
mod grant_rules;
mod legacy;
mod migrate;
mod objects;
mod plans;
mod premigration;
mod provider_claims;
mod provider_event_schema;
mod provider_lifecycle;
mod receipts;
mod rollbacks;
mod runtime_certificates;
mod runtime_enrollment;
mod runtime_plans;
mod sqlite_operational_store;
mod sqlite_store;
#[cfg(test)]
mod tests;

pub use legacy::EmbeddedStore;
pub use sqlite_store::SqliteStore;
pub(crate) use sqlite_store::immediate_transactions;

/// Open a community embedded session on the SQLite file at `path`.
pub fn embedded_ctx(path: impl AsRef<Path>) -> anyhow::Result<tenkai::client::Ctx> {
    let principal = std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "tenkai".into());
    let store = std::sync::Arc::new(SqliteStore::open_embedded(path, principal)?);
    let backup_store = std::sync::Arc::clone(&store);
    Ok(tenkai::client::Ctx::from_embedded(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn CatalogGraph>,
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn OperationalStore>,
        move |destination: &Path| backup_store.backup(destination),
    ))
}

/// Open a hub control-plane session; `TENKAI_POSTGRES_URL` is allowed.
pub fn hub_ctx(path: impl AsRef<Path>) -> anyhow::Result<tenkai::client::Ctx> {
    let principal = std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "tenkai".into());
    let store = std::sync::Arc::new(SqliteStore::open_control_plane(path, principal)?);
    let backup_store = std::sync::Arc::clone(&store);
    Ok(tenkai::client::Ctx::from_embedded(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn CatalogGraph>,
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn OperationalStore>,
        move |destination: &Path| backup_store.backup(destination),
    ))
}

/// Restore a SQLite backup into `destination` (integrity-checked copy).
pub fn restore(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> anyhow::Result<()> {
    SqliteStore::restore(source, destination)
}

/// [`tenkai::storage::CopyStoreFile`] adapter for community hosts.
pub fn copy_store_file(source: &Path, destination: &Path) -> anyhow::Result<()> {
    restore(source, destination)
}

/// Open a throwaway copy and drop it; used by `--check-store`.
pub fn open_scratch(path: &Path) -> anyhow::Result<()> {
    SqliteStore::open_scratch(path)
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

/// Inspect a restored scratch store for a backup drill.
pub fn inspect_restored(path: &Path) -> anyhow::Result<tenkai::backup::DrillInspect> {
    open_scratch(path)?;
    let connection = Connection::open(path)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let count = |table: &str| -> anyhow::Result<u64> {
        Ok(
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })? as u64,
        )
    };
    Ok(tenkai::backup::DrillInspect {
        integrity,
        environments: count("environments")?,
        releases: count("releases")?,
        plans: count("plans")?,
    })
}

/// Open one SQLite file as both catalog/operational ports and a backup handle.
pub fn open_spoke(
    path: &Path,
) -> anyhow::Result<(
    std::sync::Arc<dyn OperationalStore>,
    std::sync::Arc<dyn tenkai::storage::StoreBackup>,
)> {
    let store = std::sync::Arc::new(SqliteStore::open(path)?);
    Ok((
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn OperationalStore>,
        store as std::sync::Arc<dyn tenkai::storage::StoreBackup>,
    ))
}

use fixture_matching::*;
pub(crate) use migrate::*;
pub(crate) use objects::*;
use plans::*;
pub(crate) use premigration::copy_before_migrate;
pub(crate) use provider_claims::*;
pub(crate) use provider_event_schema::*;
pub(crate) use rollbacks::*;

pub(crate) fn ensure_environment_active_in(
    tx: &Transaction<'_>,
    environment: &str,
    operation: &str,
) -> Result<()> {
    let id = if environment.starts_with("tenkai:env:") {
        environment.to_owned()
    } else {
        env_id(environment)
    };
    let configuration_json = tx
        .query_row(
            "SELECT configuration_json FROM environments WHERE id=?1",
            [&id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let configuration_json = match configuration_json {
        Some(configuration) => Some(configuration),
        None if id != environment => tx
            .query_row(
                "SELECT configuration_json FROM environments WHERE id=?1",
                [environment],
                |row| row.get::<_, String>(0),
            )
            .optional()?,
        None => None,
    };
    if configuration_json
        .as_deref()
        .and_then(retirement_from_configuration_json)
        .is_some()
    {
        return Err((StoreError::InvalidData {
            kind: "environment",
            detail: format!("retired environment {environment} cannot accept {operation}"),
        })
        .into());
    }
    Ok(())
}
