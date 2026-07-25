//! Runtime capability advertisement and startup negotiation.
//!
//! Storage adapters and host extensions report versioned capabilities. Hosts
//! validate the required capability set before accepting traffic so tenant
//! isolation, replica safety, high availability, and enterprise authentication
//! cannot be requested from components that cannot provide them.
//!
//! Community embedded SQLite advertises a tenant-free profile. This module does
//! not implement PostgreSQL, tenant lifecycle, or high availability.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::storage::SCHEMA_VERSION;

/// Version of the runtime-capability negotiation contract.
pub const RUNTIME_CAPABILITY_CONTRACT_VERSION: u32 = 1;

/// Well-known capability names advertised by storage and extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityName {
    /// Component can enforce tenant isolation boundaries.
    TenantIsolation,
    /// Operational state is safe for multiple concurrent writer replicas.
    SharedReplicaState,
    /// Component provides high-availability semantics beyond a single process.
    HighAvailability,
    /// Host can verify enterprise authentication assertions.
    EnterpriseAuthentication,
    /// Operational store schema / migration level the component supports.
    OperationalStoreMigration,
}

impl CapabilityName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TenantIsolation => "tenant_isolation",
            Self::SharedReplicaState => "shared_replica_state",
            Self::HighAvailability => "high_availability",
            Self::EnterpriseAuthentication => "enterprise_authentication",
            Self::OperationalStoreMigration => "operational_store_migration",
        }
    }
}

/// A single versioned capability claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Capability {
    pub name: CapabilityName,
    /// Capability protocol version (not the store schema level).
    pub version: u32,
    /// For [`CapabilityName::OperationalStoreMigration`], the supported schema level.
    pub level: Option<u32>,
}

impl Capability {
    pub fn named(name: CapabilityName, version: u32) -> Self {
        Self {
            name,
            version,
            level: None,
        }
    }

    pub fn migration(level: u32) -> Self {
        Self {
            name: CapabilityName::OperationalStoreMigration,
            version: RUNTIME_CAPABILITY_CONTRACT_VERSION,
            level: Some(level),
        }
    }

    /// Public diagnostic token. Never includes secrets or tenant data.
    pub fn diagnostic_name(&self) -> String {
        match (self.name, self.level) {
            (CapabilityName::OperationalStoreMigration, Some(level)) => {
                format!("{}:v{}:level{level}", self.name.as_str(), self.version)
            }
            _ => format!("{}:v{}", self.name.as_str(), self.version),
        }
    }
}

/// Capabilities reported by one component (store, auth extension, host).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentCapabilities {
    pub component_id: String,
    pub capabilities: BTreeSet<Capability>,
}

impl ComponentCapabilities {
    pub fn new(
        component_id: impl Into<String>,
        capabilities: impl IntoIterator<Item = Capability>,
    ) -> Self {
        Self {
            component_id: component_id.into(),
            capabilities: capabilities.into_iter().collect(),
        }
    }

    pub fn names(&self) -> Vec<String> {
        self.capabilities
            .iter()
            .map(Capability::diagnostic_name)
            .collect()
    }
}

/// Union of all capabilities available to a host process after composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProvidedCapabilities {
    pub contract_version: u32,
    pub profile: String,
    pub components: Vec<ComponentCapabilities>,
}

impl ProvidedCapabilities {
    pub fn assemble(
        profile: impl Into<String>,
        components: impl IntoIterator<Item = ComponentCapabilities>,
    ) -> Self {
        Self {
            contract_version: RUNTIME_CAPABILITY_CONTRACT_VERSION,
            profile: profile.into(),
            components: components.into_iter().collect(),
        }
    }

    pub fn all_capabilities(&self) -> BTreeSet<Capability> {
        self.components
            .iter()
            .flat_map(|component| component.capabilities.iter().cloned())
            .collect()
    }

    /// Public capability names for health/diagnostics (no secrets or tenants).
    pub fn diagnostic_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .all_capabilities()
            .iter()
            .map(Capability::diagnostic_name)
            .collect();
        names.sort();
        names.dedup();
        names
    }

    pub fn supports(&self, name: CapabilityName) -> bool {
        self.all_capabilities()
            .iter()
            .any(|capability| capability.name == name)
    }

    pub fn migration_level(&self) -> Option<u32> {
        self.all_capabilities()
            .iter()
            .filter_map(|capability| {
                (capability.name == CapabilityName::OperationalStoreMigration)
                    .then_some(capability.level)
                    .flatten()
            })
            .max()
    }
}

/// Host requirements validated before the process accepts traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRequirements {
    pub tenant_mode: bool,
    /// Total planned control-plane replicas for this deployment. Values greater
    /// than 1 require [`CapabilityName::SharedReplicaState`].
    pub replica_count: u32,
    pub require_high_availability: bool,
    pub require_enterprise_authentication: bool,
    pub min_migration_level: u32,
}

impl Default for RuntimeRequirements {
    fn default() -> Self {
        Self {
            tenant_mode: false,
            replica_count: 1,
            require_high_availability: false,
            require_enterprise_authentication: false,
            min_migration_level: 1,
        }
    }
}

impl RuntimeRequirements {
    /// Documented community defaults: single replica, tenant-free, no HA.
    pub fn community() -> Self {
        Self::default()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapabilityError {
    #[error(
        "tenant mode requires the `{needed}` capability, but the composed runtime only provides: {provided}"
    )]
    TenantModeUnsupported { needed: String, provided: String },
    #[error(
        "replica_count {replica_count} requires `{needed}` for shared replica-safe state; provided: {provided}"
    )]
    SharedReplicaRequired {
        replica_count: u32,
        needed: String,
        provided: String,
    },
    #[error("high availability requires the `{needed}` capability; provided: {provided}")]
    HighAvailabilityRequired { needed: String, provided: String },
    #[error("enterprise authentication requires the `{needed}` capability; provided: {provided}")]
    EnterpriseAuthenticationRequired { needed: String, provided: String },
    #[error("operational store migration level {found} is below required minimum {required}")]
    MigrationLevelTooLow { found: u32, required: u32 },
    #[error("operational store migration capability is missing")]
    MigrationCapabilityMissing,
    #[error("replica_count must be at least 1")]
    InvalidReplicaCount,
    #[error("incompatible runtime capability contract version {found}, expected {expected}")]
    IncompatibleContract { found: u32, expected: u32 },
}

/// Documented capability set for the embedded SQLite operational store.
///
/// Tenant-free, single-process, not shared-replica-safe, not HA. Reports the
/// current schema migration level only.
pub fn sqlite_store_capabilities() -> ComponentCapabilities {
    ComponentCapabilities::new("store.sqlite", [Capability::migration(SCHEMA_VERSION)])
}

/// Community authentication reports no enterprise authentication capability.
pub fn community_auth_capabilities() -> ComponentCapabilities {
    ComponentCapabilities::new("auth.community", [])
}

/// Enterprise auth extension capability (assertion verification available).
pub fn enterprise_auth_capabilities() -> ComponentCapabilities {
    ComponentCapabilities::new(
        "auth.enterprise",
        [Capability::named(
            CapabilityName::EnterpriseAuthentication,
            RUNTIME_CAPABILITY_CONTRACT_VERSION,
        )],
    )
}

/// Assemble the community embedded SQLite profile used by default hosts.
pub fn community_sqlite_profile(auth: ComponentCapabilities) -> ProvidedCapabilities {
    ProvidedCapabilities::assemble("community-sqlite", [sqlite_store_capabilities(), auth])
}

/// Validate required capabilities against what the composed runtime provides.
///
/// Call this at startup before the server listens or the embedded host accepts
/// enterprise-only configuration.
pub fn validate_runtime_capabilities(
    provided: &ProvidedCapabilities,
    required: &RuntimeRequirements,
) -> Result<(), CapabilityError> {
    if provided.contract_version != RUNTIME_CAPABILITY_CONTRACT_VERSION {
        return Err(CapabilityError::IncompatibleContract {
            found: provided.contract_version,
            expected: RUNTIME_CAPABILITY_CONTRACT_VERSION,
        });
    }
    if required.replica_count < 1 {
        return Err(CapabilityError::InvalidReplicaCount);
    }

    let diagnostic = provided.diagnostic_names().join(", ");
    let diagnostic = if diagnostic.is_empty() {
        "(none)".into()
    } else {
        diagnostic
    };

    if required.tenant_mode && !provided.supports(CapabilityName::TenantIsolation) {
        return Err(CapabilityError::TenantModeUnsupported {
            needed: CapabilityName::TenantIsolation.as_str().into(),
            provided: diagnostic.clone(),
        });
    }

    if required.replica_count > 1 && !provided.supports(CapabilityName::SharedReplicaState) {
        return Err(CapabilityError::SharedReplicaRequired {
            replica_count: required.replica_count,
            needed: CapabilityName::SharedReplicaState.as_str().into(),
            provided: diagnostic.clone(),
        });
    }

    if required.require_high_availability && !provided.supports(CapabilityName::HighAvailability) {
        return Err(CapabilityError::HighAvailabilityRequired {
            needed: CapabilityName::HighAvailability.as_str().into(),
            provided: diagnostic.clone(),
        });
    }

    if required.require_enterprise_authentication
        && !provided.supports(CapabilityName::EnterpriseAuthentication)
    {
        return Err(CapabilityError::EnterpriseAuthenticationRequired {
            needed: CapabilityName::EnterpriseAuthentication.as_str().into(),
            provided: diagnostic.clone(),
        });
    }

    let migration_level = provided
        .migration_level()
        .ok_or(CapabilityError::MigrationCapabilityMissing)?;
    if migration_level < required.min_migration_level {
        return Err(CapabilityError::MigrationLevelTooLow {
            found: migration_level,
            required: required.min_migration_level,
        });
    }

    Ok(())
}

/// Compatibility matrix rows used by tests and documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityRow {
    pub profile: &'static str,
    pub requirements: RuntimeRequirements,
    pub expect_ok: bool,
}

/// Documented positive and negative combinations for community SQLite.
pub fn community_sqlite_compatibility_matrix() -> Vec<(ProvidedCapabilities, CompatibilityRow)> {
    let community = community_sqlite_profile(community_auth_capabilities());
    let with_enterprise_auth = community_sqlite_profile(enterprise_auth_capabilities());
    vec![
        (
            community.clone(),
            CompatibilityRow {
                profile: "community defaults",
                requirements: RuntimeRequirements::community(),
                expect_ok: true,
            },
        ),
        (
            community.clone(),
            CompatibilityRow {
                profile: "tenant mode on tenant-free store",
                requirements: RuntimeRequirements {
                    tenant_mode: true,
                    ..RuntimeRequirements::community()
                },
                expect_ok: false,
            },
        ),
        (
            community.clone(),
            CompatibilityRow {
                profile: "multi-replica without shared state",
                requirements: RuntimeRequirements {
                    replica_count: 2,
                    ..RuntimeRequirements::community()
                },
                expect_ok: false,
            },
        ),
        (
            community.clone(),
            CompatibilityRow {
                profile: "HA without HA capability",
                requirements: RuntimeRequirements {
                    require_high_availability: true,
                    ..RuntimeRequirements::community()
                },
                expect_ok: false,
            },
        ),
        (
            community.clone(),
            CompatibilityRow {
                profile: "enterprise auth without auth capability",
                requirements: RuntimeRequirements {
                    require_enterprise_authentication: true,
                    ..RuntimeRequirements::community()
                },
                expect_ok: false,
            },
        ),
        (
            with_enterprise_auth.clone(),
            CompatibilityRow {
                profile: "enterprise auth capability present",
                requirements: RuntimeRequirements {
                    require_enterprise_authentication: true,
                    ..RuntimeRequirements::community()
                },
                expect_ok: true,
            },
        ),
        (
            community,
            CompatibilityRow {
                profile: "migration floor above schema",
                requirements: RuntimeRequirements {
                    min_migration_level: SCHEMA_VERSION + 1,
                    ..RuntimeRequirements::community()
                },
                expect_ok: false,
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_sqlite_is_tenant_free() {
        let provided = community_sqlite_profile(community_auth_capabilities());
        assert_eq!(provided.profile, "community-sqlite");
        assert!(!provided.supports(CapabilityName::TenantIsolation));
        assert!(!provided.supports(CapabilityName::SharedReplicaState));
        assert!(!provided.supports(CapabilityName::HighAvailability));
        assert!(!provided.supports(CapabilityName::EnterpriseAuthentication));
        assert_eq!(provided.migration_level(), Some(SCHEMA_VERSION));
        validate_runtime_capabilities(&provided, &RuntimeRequirements::community()).unwrap();
    }

    #[test]
    fn tenant_mode_fails_on_tenant_free_store() {
        let provided = community_sqlite_profile(community_auth_capabilities());
        let error = validate_runtime_capabilities(
            &provided,
            &RuntimeRequirements {
                tenant_mode: true,
                ..RuntimeRequirements::community()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CapabilityError::TenantModeUnsupported { .. }
        ));
        assert!(error.to_string().contains("tenant_isolation"));
    }

    #[test]
    fn multi_replica_without_shared_state_fails() {
        let provided = community_sqlite_profile(community_auth_capabilities());
        let error = validate_runtime_capabilities(
            &provided,
            &RuntimeRequirements {
                replica_count: 3,
                ..RuntimeRequirements::community()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CapabilityError::SharedReplicaRequired {
                replica_count: 3,
                ..
            }
        ));
    }

    #[test]
    fn diagnostics_expose_names_without_secrets() {
        let provided = community_sqlite_profile(community_auth_capabilities());
        let names = provided.diagnostic_names();
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("operational_store_migration:"))
        );
        let joined = names.join(",");
        assert!(!joined.contains("token"));
        assert!(!joined.contains("secret"));
        assert!(!joined.contains("tenant-a"));
        assert!(!joined.contains("password"));
    }

    #[test]
    fn compatibility_matrix_matches_expectations() {
        for (provided, row) in community_sqlite_compatibility_matrix() {
            let result = validate_runtime_capabilities(&provided, &row.requirements);
            assert_eq!(
                result.is_ok(),
                row.expect_ok,
                "row `{}` expected ok={} got {result:?}",
                row.profile,
                row.expect_ok
            );
        }
    }

    #[test]
    fn enterprise_auth_capability_satisfies_requirement() {
        let provided = community_sqlite_profile(enterprise_auth_capabilities());
        validate_runtime_capabilities(
            &provided,
            &RuntimeRequirements {
                require_enterprise_authentication: true,
                ..RuntimeRequirements::community()
            },
        )
        .unwrap();
    }

    #[test]
    fn zero_replicas_rejected() {
        let provided = community_sqlite_profile(community_auth_capabilities());
        assert!(matches!(
            validate_runtime_capabilities(
                &provided,
                &RuntimeRequirements {
                    replica_count: 0,
                    ..RuntimeRequirements::community()
                },
            ),
            Err(CapabilityError::InvalidReplicaCount)
        ));
    }
}
