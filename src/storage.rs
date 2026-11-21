//! Tenkai-owned durable operational state.
//!
//! Domain code depends on [`OperationalStore`] and [`CatalogGraph`], not a
//! driver. Community hosts open SQLite through the `tenkai-sqlite` crate.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 14;

/// Retention cutoff for environment-execution claim change rows (#874).
pub const CATALOG_HISTORY_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

mod catalog_graph;
mod error;
mod object_codec;
mod operational_store;
mod records;

pub use catalog_graph::{
    CatalogGraph, LeaseRefresh, MemoryCatalogGraph, skip_execution_claim_heartbeat,
    stamp_claim_expiry,
};
pub use error::*;
pub use object_codec::{
    channel_record_to_object, encode_object, environment_record_to_object, plan_record_to_object,
    release_record_to_object,
};
pub use operational_store::OperationalStore;
pub use records::*;

/// Consistent file copy of operational state. Community hosts implement this
/// with the SQLite backup API in `tenkai-sqlite`.
pub trait StoreBackup: Send + Sync {
    fn backup(&self, destination: &std::path::Path) -> anyhow::Result<()>;
}

/// Copy one store file onto another with the engine's consistent-backup API.
pub type CopyStoreFile = fn(&std::path::Path, &std::path::Path) -> anyhow::Result<()>;

/// Read `PRAGMA user_version` from the SQLite file header (offset 60).
pub fn sqlite_user_version(path: &std::path::Path) -> anyhow::Result<u32> {
    use std::io::Read as _;
    let mut header = [0_u8; 100];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(anyhow::Error::from)?;
    anyhow::ensure!(
        header[..16] == *b"SQLite format 3\0",
        "{} is not a SQLite database",
        path.display()
    );
    Ok(u32::from_be_bytes(
        header[60..64].try_into().expect("header slice is 4 bytes"),
    ))
}

/// Spoke and embedded hosts refuse a process-level Postgres URL (ADR 0029).
pub fn refuse_postgres_on_embedded() -> Result<()> {
    if crate::secret_source::is_configured("TENKAI_POSTGRES_URL") {
        return Err(StoreError::AdapterUnavailable(
            "TENKAI_POSTGRES_URL is not valid on embedded or spoke hosts; SQLite is the sole operational store (ADR 0029)".into(),
        ));
    }
    Ok(())
}
