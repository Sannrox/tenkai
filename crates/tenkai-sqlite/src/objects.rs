//! Object/link/lease codec over typed schema records (`SCHEMA_VERSION`) plus a catalog sidecar.
//!
//! Plan, environment, release, channel, and apply-lease identities live in
//! typed tables. Leftover `embedded_*` graph rows are imported once and dropped
//! so they cannot authorize apply.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result as AnyResult, bail};
use prost::Message;
use rusqlite::{
    Connection, DatabaseName, OptionalExtension, Transaction, params, params_from_iter,
    types::Value,
};

use tenkai::embedded::PropertyIndexQuery;
use tenkai::ontology::{
    CHANNEL_REVISION_FLOOR, KIND_CHANNEL, KIND_ENVIRONMENT, KIND_PLAN, KIND_RELEASE, NS, env_id,
    release_id,
};
use tenkai::pb::graph_action::{ActionResult, ActionTypeDef};
use tenkai::pb::record::{Decision, Lease, Link, Object, ObjectChange, ObjectType};
use tenkai::plan::{Plan, PlanState};
use tenkai::storage::{
    ActionWrite, ActionWrites, CatalogWrite, ChannelRecord, EnvironmentRecord, PlanRecord,
    PlanStatus, ProviderEventRecord, ReleaseRecord, StoreError,
};

use crate::Result;

const ENVIRONMENT_LEASE_NAMESPACE: &str = "tenkai/environment-execution";

use crate::{SqliteStore, enqueue_provider_event_in};

const STRICT_AUTHORITY_KINDS: &[&str] = &[KIND_PLAN, KIND_ENVIRONMENT, KIND_RELEASE];

mod actions;
mod backup;
mod codec;
mod legacy_import;
mod links;
mod listings;
mod namespaced_leases;
mod object_writes;
mod schema;
#[cfg(test)]
mod tests;
mod upserts;
mod write_log;

use actions::*;
use codec::*;
pub use codec::{
    encode_object, environment_record_to_object, plan_record_to_object, release_record_to_object,
};
pub(super) use legacy_import::*;
use namespaced_leases::*;
pub(super) use schema::*;
pub(crate) use upserts::channel_revision_floor;
use upserts::*;
pub(crate) use write_log::record_write;
use write_log::*;
