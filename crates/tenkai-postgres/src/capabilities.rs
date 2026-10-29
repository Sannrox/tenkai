use tenkai::runtime_capabilities::{
    Capability, CapabilityName, ComponentCapabilities, RUNTIME_CAPABILITY_CONTRACT_VERSION,
};
use tenkai::storage::SCHEMA_VERSION;

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

/// Compose the enterprise hub profile: PostgreSQL is the sole store.
pub fn enterprise_postgres_hub_profile(
    auth: ComponentCapabilities,
) -> tenkai::runtime_capabilities::ProvidedCapabilities {
    tenkai::runtime_capabilities::ProvidedCapabilities::assemble(
        "enterprise-experimental",
        [tenant_postgres_store_capabilities(), auth],
    )
}

/// One authoritative surface the supported `enterprise-experimental` profile
/// needs PostgreSQL to own (ADR 0010), and whether this build has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthoritativeSurface {
    pub name: &'static str,
    pub available: bool,
    /// The issue that delivers it, while it is missing.
    pub tracked_by: Option<&'static str>,
}

/// Every surface the enterprise profile requires, in a fixed order (#747).
/// An entry becomes available when its PostgreSQL implementation lands.
pub fn enterprise_authoritative_surfaces() -> [AuthoritativeSurface; 5] {
    let available = |name| AuthoritativeSurface {
        name,
        available: true,
        tracked_by: None,
    };
    [
        available("operational store"),
        available("tenant isolation"),
        available("shared replica state"),
        available("catalog object graph"),
        available("terminal-outcome export"),
    ]
}

/// Refuse the supported enterprise profile while any required surface is
/// missing, naming each one; the diagnostic lab profile does not ask.
pub fn require_enterprise_profile(surfaces: &[AuthoritativeSurface]) -> anyhow::Result<()> {
    let missing: Vec<String> = surfaces
        .iter()
        .filter(|surface| !surface.available)
        .map(|surface| match surface.tracked_by {
            Some(issue) => format!("{} ({issue})", surface.name),
            None => surface.name.to_string(),
        })
        .collect();
    if !missing.is_empty() {
        anyhow::bail!(
            "the enterprise-experimental profile needs PostgreSQL to own every authoritative surface; missing: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

/// Whether this binary was compiled with the `postgres` feature.
pub fn postgres_feature_enabled() -> bool {
    cfg!(feature = "postgres")
}

/// Cargo features compiled into this crate, reported by `tenkai-server --help`.
pub fn compiled_host_feature_report() -> &'static str {
    compiled_host_feature_report_with(cfg!(feature = "postgres"), false)
}

/// Host feature report for a composition crate that forwards `postgres` and `ui`.
pub fn compiled_host_feature_report_with(postgres: bool, ui: bool) -> &'static str {
    match (postgres, ui) {
        (true, true) => "Compiled features: postgres, ui",
        (true, false) => "Compiled features: postgres",
        (false, true) => "Compiled features: ui",
        (false, false) => "Compiled features: (none)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_enterprise_profile_names_every_missing_surface() {
        require_enterprise_profile(&enterprise_authoritative_surfaces()).unwrap();
        assert!(
            enterprise_authoritative_surfaces()
                .iter()
                .all(|surface| surface.available)
        );
        let missing = [AuthoritativeSurface {
            name: "terminal-outcome export",
            available: false,
            tracked_by: Some("#765"),
        }];
        let error = require_enterprise_profile(&missing)
            .unwrap_err()
            .to_string();
        assert!(error.contains("terminal-outcome export (#765)"), "{error}");
        assert!(!error.contains("tenant isolation"), "{error}");
    }
}
