use crate::runtime_capabilities::{
    Capability, CapabilityName, ComponentCapabilities, RUNTIME_CAPABILITY_CONTRACT_VERSION,
};
use crate::storage::SCHEMA_VERSION;

/// Writer model claimed with `shared_replica_state` for the Postgres hub store.
///
/// First slice (#128): shared durable DB with **at most one active control-plane
/// writer** (failover / cold standby). Multi-active concurrent reconcile
/// still requires tick fencing (#129) and must not be assumed from this claim alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedReplicaWriterModel {
    /// One active writer; standbys share the same Postgres URL for failover.
    SingleActiveWriter,
}

/// Contract description for operators and capability honesty checks.
pub const POSTGRES_SHARED_REPLICA_WRITER_MODEL: SharedReplicaWriterModel =
    SharedReplicaWriterModel::SingleActiveWriter;

/// Capability advertisement for the optional Postgres tenant store.
///
/// Claims `tenant_isolation`, migration level, and `shared_replica_state` under
/// the single-active-writer model (#128). Does **not** claim `high_availability`.
pub fn tenant_postgres_store_capabilities() -> ComponentCapabilities {
    ComponentCapabilities::new(
        "store.tenant_postgres",
        [
            Capability::named(
                CapabilityName::TenantIsolation,
                RUNTIME_CAPABILITY_CONTRACT_VERSION,
            ),
            Capability::named(
                CapabilityName::SharedReplicaState,
                RUNTIME_CAPABILITY_CONTRACT_VERSION,
            ),
            Capability::migration(SCHEMA_VERSION),
        ],
    )
}

/// Compose a host capability profile: community auth + Postgres tenant hub store.
pub fn enterprise_postgres_hub_profile(
    auth: ComponentCapabilities,
) -> crate::runtime_capabilities::ProvidedCapabilities {
    crate::runtime_capabilities::ProvidedCapabilities::assemble(
        "enterprise-tenant-postgres",
        [tenant_postgres_store_capabilities(), auth],
    )
}

/// Whether this binary was compiled with the `postgres` feature.
pub fn postgres_feature_enabled() -> bool {
    cfg!(feature = "postgres")
}
