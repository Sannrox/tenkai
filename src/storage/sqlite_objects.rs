//! Object/link/lease codec over typed schema 11 records plus a catalog sidecar.
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

use crate::embedded::PropertyIndexQuery;
use crate::ontology::{
    KIND_CHANNEL, KIND_ENVIRONMENT, KIND_PLAN, KIND_RELEASE, NS, env_id, release_id,
};
use crate::pb::graph_action::{ActionResult, ActionTypeDef};
use crate::pb::sekai::{Decision, Lease, Link, Object, ObjectChange, ObjectType};
use crate::plan::Plan;
use crate::storage::{
    ChannelRecord, EnvironmentRecord, OperationalStore, PlanRecord, PlanStatus,
    ProviderEventRecord, ReleaseRecord, Result, SqliteStore, StoreError, enqueue_provider_event_in,
};

const STRICT_AUTHORITY_KINDS: &[&str] = &[KIND_PLAN, KIND_ENVIRONMENT, KIND_RELEASE];

type DecisionRow = (String, i64, String, String, Vec<u8>);
type ChangeRow = (String, String, i64, Vec<u8>);

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

use actions::*;
use codec::*;
pub(super) use legacy_import::*;
use namespaced_leases::*;
pub(super) use schema::*;
use upserts::*;
