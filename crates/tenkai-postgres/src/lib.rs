//! Optional PostgreSQL multi-tenant operational store for the **control-plane hub**.
//!
//! Community hosts keep SQLite (`SqliteStore`). Enterprise hubs open PostgreSQL
//! as the sole authoritative store behind Cargo feature `postgres`.
//!
//! Model: **schema-per-tenant** plus hub schema `tenkai_hub` inside one
//! Tenkai-owned database (never co-located with the identity plane). Claims
//! `shared_replica_state` under the single-active-writer model and durable tick
//! fencing. Does **not** claim `high_availability`; the qualification drill
//! (#903) is the gate before a release advertises it. SQLite is not opened
//! in this profile.
//!
//! Connection strings come from env/config only — never argv secrets.
//!
//! Enable:
//! ```text
//! cargo build --features postgres
//! export TENKAI_POSTGRES_URL=postgres://tenkai:tenkai@127.0.0.1:5432/tenkai
//! ```

mod capabilities;
mod catalog_graph;
mod config;
mod partition;
#[cfg(feature = "postgres")]
mod partition_store;
#[cfg(feature = "postgres")]
mod postgres_imp;
mod store;
#[cfg(any(test, feature = "postgres"))]
mod tenant_schema;
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
pub use partition::PostgresTenantPartition;
pub use store::PostgresTenantOperationalStore;
#[cfg(feature = "postgres")]
pub use writer_lease::PostgresHubWriterLease;
pub use writer_lease::{HubWriterLease, open_hub_writer_lease};

#[cfg(test)]
mod tests;

pub mod delivery_conformance;
