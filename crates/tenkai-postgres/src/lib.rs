//! Optional PostgreSQL multi-tenant operational store for the **control-plane hub**.
//!
//! Community hosts keep SQLite (`SqliteStore`). Enterprise hubs open PostgreSQL
//! as the sole authoritative store behind Cargo feature `postgres`.
//!
//! Model: **schema-per-tenant** plus hub schema `tenkai_hub` inside one
//! Tenkai-owned database (never co-located with the identity plane). Claims
//! `shared_replica_state` under the single-active-writer model and durable tick
//! fencing. Does **not** claim `high_availability` until ADR 0009's remaining HA
//! drills and criteria land. SQLite is not opened in this profile.
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
mod writer_lease;

pub use capabilities::{
    AuthoritativeSurface, POSTGRES_SHARED_REPLICA_WRITER_MODEL, SharedReplicaWriterModel,
    compiled_host_feature_report, compiled_host_feature_report_with,
    enterprise_authoritative_surfaces, enterprise_postgres_hub_profile, postgres_feature_enabled,
    require_enterprise_profile, tenant_postgres_store_capabilities,
};
pub use config::{
    EnterpriseHub, HUB_SCHEMA, PostgresTenantConfig, refuse_mixed_store_configuration,
    require_hub_tenant_mode, resolve_enterprise_hub, resolve_fenced_enterprise_hub,
    resolve_server_tenant_store, tenant_schema_name,
};
#[cfg(feature = "postgres")]
pub use fence::PostgresReconcileFence;
pub use fence::{open_postgres_reconcile_fence, resolve_reconcile_fence_for_replicas};
pub use partition::PostgresTenantPartition;
pub use store::PostgresTenantOperationalStore;
#[cfg(feature = "postgres")]
pub use writer_lease::PostgresHubWriterLease;
pub use writer_lease::{HubWriterLease, open_hub_writer_lease};

#[cfg(test)]
mod tests;

pub mod delivery_conformance;
