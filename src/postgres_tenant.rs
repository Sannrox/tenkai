//! Optional PostgreSQL multi-tenant operational store for the **control-plane hub**.
//!
//! Community hosts keep SQLite (`SqliteStore`). Enterprise hubs that need durable
//! multi-tenant recovery can enable this adapter behind Cargo feature `postgres`.
//!
//! Model: **schema-per-tenant** inside one Tenkai-owned database (never co-located
//! with the identity plane). Claims `shared_replica_state` under the
//! single-active-writer model and durable tick fencing. Does **not** claim
//! `high_availability` until ADR 0009's remaining HA drills and criteria land.
//!
//! Connection strings come from env/config only — never argv secrets.
//!
//! Enable:
//! ```text
//! cargo build --features postgres
//! export TENKAI_POSTGRES_URL=postgres://tenkai:tenkai@127.0.0.1:5432/tenkai
//! ```

mod capabilities;
mod config;
mod fence;
mod partition;
#[cfg(feature = "postgres")]
mod partition_store;
#[cfg(feature = "postgres")]
mod postgres_imp;
mod store;
mod tenant_store;

pub use capabilities::{
    POSTGRES_SHARED_REPLICA_WRITER_MODEL, SharedReplicaWriterModel,
    enterprise_postgres_hub_profile, postgres_feature_enabled, tenant_postgres_store_capabilities,
};
pub use config::{PostgresTenantConfig, resolve_server_tenant_store, tenant_schema_name};
#[cfg(feature = "postgres")]
pub use fence::PostgresReconcileFence;
pub use fence::{open_postgres_reconcile_fence, resolve_reconcile_fence_for_replicas};
pub use partition::PostgresTenantPartition;
pub use store::PostgresTenantOperationalStore;

#[cfg(test)]
mod tests;
