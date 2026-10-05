//! Tenkai-owned durable operational state.
//!
//! Domain code depends on [`OperationalStore`], not SQLite rows. The SQLite
//! adapter is the complete solo-mode implementation; a production database
//! adapter must preserve the same transaction and fencing semantics.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 12;

mod audit;
mod catalog;
mod error;
mod fixture_matching;
mod fixtures;
mod migrate;
mod operational_store;
mod plans;
mod provider_claims;
mod provider_event_schema;
mod provider_lifecycle;
mod receipts;
mod records;
mod rollbacks;
mod runtime_plans;
mod sqlite_objects;
mod sqlite_operational_store;
mod sqlite_store;
#[cfg(test)]
mod tests;

pub use error::*;
pub use operational_store::OperationalStore;
pub use provider_claims::provider_event_payloads_match;
pub use provider_event_schema::{provider_event_environment_id, provider_event_observed_at};
pub use records::*;
pub use rollbacks::rollback_intent_digest;
pub use sqlite_store::*;

use fixture_matching::*;
pub(crate) use migrate::*;
use plans::*;
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
        crate::ontology::env_id(environment)
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
        .and_then(crate::environment::retirement_from_configuration_json)
        .is_some()
    {
        return Err(StoreError::InvalidData {
            kind: "environment",
            detail: format!("retired environment {environment} cannot accept {operation}"),
        });
    }
    Ok(())
}
