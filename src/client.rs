//! Embedded and tenant-hub `Ctx` facade plus object, relation, lease, and action
//! lifecycle ports.

mod action_lifecycle;
mod ctx_actions;
mod ctx_objects;
mod ctx_queries;
mod ctx_schema;
mod ctx_session;
mod helpers;
mod lease_lifecycle;
mod object_lifecycle;
mod plan_kind_list;
mod relation_lifecycle;
mod release_reads;
mod schema_register;
mod transport;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use tokio::sync::OnceCell;
use tonic::Status;

pub(crate) use helpers::{action_actor_from_changes, apply_property_index};
pub(crate) use plan_kind_list::{PlanKindListSnapshot, PlanKindListTick, PlanRetargetTickGuard};
pub use schema_register::{
    known_action, known_actions, known_object_types, register, require_canary_schema,
    require_connectivity_upgrade_schema, require_package_migration_schema, require_wave_schema,
};
pub(crate) use transport::{block_catalog, block_catalog_status, block_operational};

/// A lease a plan execution must keep, refreshed with the environment apply
/// fence so a long run cannot outlast its wave or topology (#834).
#[derive(Clone, Debug)]
pub(crate) struct HeldExecutionLease {
    pub namespace: String,
    pub key: String,
    pub fencing_token: String,
    pub ttl_ms: i64,
    /// Known expiry; `0` means unknown, so the next fence refreshes it.
    pub expires_at_ms: i64,
}

impl HeldExecutionLease {
    pub(crate) fn new(
        namespace: impl Into<String>,
        key: impl Into<String>,
        fencing_token: impl Into<String>,
        ttl_ms: i64,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
            fencing_token: fencing_token.into(),
            ttl_ms,
            expires_at_ms: 0,
        }
    }

    pub(crate) fn until(mut self, expires_at_ms: i64) -> Self {
        self.expires_at_ms = expires_at_ms;
        self
    }

    /// Wave/topology leases refresh when less than a third of TTL remains (#874).
    pub(crate) fn due_for_refresh(&self, now: i64) -> bool {
        self.expires_at_ms == 0 || self.expires_at_ms.saturating_sub(now) < self.ttl_ms / 3
    }
}

#[derive(Clone)]
pub struct Ctx {
    pub(crate) release_trust_roots: Option<std::path::PathBuf>,
    pub(crate) require_host_release_trust: bool,
    backend: Backend,
    canary_schema_preflight: Arc<OnceCell<()>>,
    outcome_inspection_enabled: bool,
    plan_kind_list: Arc<PlanKindListTick>,
    health_metrics: Option<Arc<dyn crate::health_gate::HealthMetricsSource>>,
    trust_sources: Option<Arc<crate::trust_posture::TrustSources>>,
    execution_capabilities:
        Option<Arc<dyn crate::execution_capabilities::ExecutionCapabilitySource>>,
    pub(crate) held_execution_leases: Vec<HeldExecutionLease>,
    plan_proposer: Option<crate::plan::PlanProposer>,
    /// Open while a planning call shares its release reads (#1575).
    release_reads: std::sync::Weak<release_reads::ReleaseReads>,
}

type EmbeddedBackup = Arc<dyn Fn(&std::path::Path) -> anyhow::Result<()> + Send + Sync>;

#[derive(Clone)]
enum Backend {
    Embedded {
        catalog: Arc<dyn crate::storage::CatalogGraph>,
        operational: Arc<dyn crate::storage::OperationalStore>,
        backup: EmbeddedBackup,
    },
    /// Enterprise hub catalog. Writes fail closed until a catalog and tenant are bound.
    TenantHub {
        catalog: Option<Arc<dyn crate::storage::CatalogGraph>>,
        tenant: Option<String>,
    },
}

/// A read on a tenant hub whose catalog is configured but whose tenant is
/// not bound yet; an unbound hub must not look like an empty catalog.
pub(super) const TENANT_NOT_BOUND: &str =
    "tenant not bound: this hub serves catalog reads only for an authenticated tenant";

pub(super) const TENANT_HUB_UNAVAILABLE: &str =
    "the enterprise hub does not open SQLite; catalog lifecycle is not available in tenant mode";

impl Backend {
    fn object_lifecycle(&self) -> object_lifecycle::ObjectLifecycle {
        match self {
            Self::Embedded { catalog, .. } => object_lifecycle::ObjectLifecycle::Catalog {
                catalog: Arc::clone(catalog),
                tenant: None,
            },
            Self::TenantHub {
                catalog: Some(catalog),
                tenant: Some(tenant),
            } => object_lifecycle::ObjectLifecycle::Catalog {
                catalog: Arc::clone(catalog),
                tenant: Some(tenant.clone()),
            },
            Self::TenantHub { catalog, .. } => object_lifecycle::ObjectLifecycle::Unavailable {
                tenant_unbound: catalog.is_some(),
            },
        }
    }

    fn relation_lifecycle(&self) -> relation_lifecycle::RelationLifecycle {
        match self {
            Self::Embedded { catalog, .. } => relation_lifecycle::RelationLifecycle::Catalog {
                catalog: Arc::clone(catalog),
                tenant: None,
            },
            Self::TenantHub {
                catalog: Some(catalog),
                tenant: Some(tenant),
            } => relation_lifecycle::RelationLifecycle::Catalog {
                catalog: Arc::clone(catalog),
                tenant: Some(tenant.clone()),
            },
            Self::TenantHub { catalog, .. } => relation_lifecycle::RelationLifecycle::Unavailable {
                tenant_unbound: catalog.is_some(),
            },
        }
    }

    fn lease_lifecycle(&self) -> lease_lifecycle::LeaseLifecycle {
        match self {
            Self::Embedded { catalog, .. } => lease_lifecycle::LeaseLifecycle::Catalog {
                catalog: Arc::clone(catalog),
                tenant: None,
            },
            Self::TenantHub {
                catalog: Some(catalog),
                tenant: Some(tenant),
            } => lease_lifecycle::LeaseLifecycle::Catalog {
                catalog: Arc::clone(catalog),
                tenant: Some(tenant.clone()),
            },
            Self::TenantHub { catalog, .. } => lease_lifecycle::LeaseLifecycle::Unavailable {
                tenant_unbound: catalog.is_some(),
            },
        }
    }

    fn action_lifecycle(&self) -> action_lifecycle::ActionLifecycle {
        match self {
            Self::Embedded { catalog, .. } => action_lifecycle::ActionLifecycle::Catalog {
                catalog: Arc::clone(catalog),
                tenant: None,
            },
            Self::TenantHub {
                catalog: Some(catalog),
                tenant: Some(tenant),
            } => action_lifecycle::ActionLifecycle::Catalog {
                catalog: Arc::clone(catalog),
                tenant: Some(tenant.clone()),
            },
            Self::TenantHub { catalog, .. } => action_lifecycle::ActionLifecycle::Unavailable {
                tenant_unbound: catalog.is_some(),
            },
        }
    }
}

/// Application-level client failure. Transport adapters map `tonic::Status` here
/// so domain code does not name gRPC types.
#[derive(Debug)]
pub enum ClientError {
    UniqueConflict,
    NotFound,
    Failed(anyhow::Error),
}

impl ClientError {
    pub(crate) fn from_status(status: Status) -> Self {
        match status.code() {
            tonic::Code::AlreadyExists => Self::UniqueConflict,
            tonic::Code::NotFound => Self::NotFound,
            tonic::Code::Internal if status.message().contains("UNIQUE") => Self::UniqueConflict,
            _ => Self::Failed(status.into()),
        }
    }
}

impl From<Status> for ClientError {
    fn from(status: Status) -> Self {
        Self::from_status(status)
    }
}

impl From<crate::storage::StoreError> for ClientError {
    fn from(error: crate::storage::StoreError) -> Self {
        match error {
            crate::storage::StoreError::AlreadyExists { .. } => Self::UniqueConflict,
            crate::storage::StoreError::NotFound { .. } => Self::NotFound,
            other => Self::Failed(other.into()),
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UniqueConflict => write!(f, "identity already exists"),
            Self::NotFound => write!(f, "object not found"),
            Self::Failed(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UniqueConflict | Self::NotFound => None,
            Self::Failed(error) => Some(error.as_ref()),
        }
    }
}

/// True when create-once (or register) failed because the identity already exists.
pub(crate) fn is_unique_conflict(error: &ClientError) -> bool {
    matches!(error, ClientError::UniqueConflict)
}

/// Typed lease admission failure. The client translates tonic already-exists
/// into [`LeaseError::AlreadyExists`] so domain code does not name gRPC types.
#[derive(Debug)]
pub enum LeaseError {
    AlreadyExists,
    Failed(anyhow::Error),
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "lease already exists"),
            Self::Failed(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LeaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AlreadyExists => None,
            Self::Failed(error) => Some(error.as_ref()),
        }
    }
}

impl LeaseError {
    pub(crate) fn from_anyhow(error: anyhow::Error) -> Self {
        if error
            .downcast_ref::<crate::storage::StoreError>()
            .is_some_and(crate::storage::StoreError::is_already_exists)
        {
            Self::AlreadyExists
        } else {
            Self::Failed(error)
        }
    }
}
