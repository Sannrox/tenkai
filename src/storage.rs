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

pub const SCHEMA_VERSION: u32 = 11;

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
pub use records::*;
pub use sqlite_store::*;

use fixture_matching::*;
pub(crate) use migrate::*;
use plans::*;
pub(crate) use provider_claims::*;
pub(crate) use provider_event_schema::*;
pub(crate) use rollbacks::*;
