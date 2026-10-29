//! Embedded and remote `Ctx` facade plus object, relation, lease, and action
//! lifecycle ports.

mod action_governed;
mod action_lifecycle;
mod action_remote;
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
mod schema_register;
mod transport;

#[cfg(test)]
mod tests;

use anyhow::{Context as _, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tonic::Status;

use sekai_client::{ClientConfig, RetryPolicy, SdkErrorCode};

pub(crate) use helpers::{
    action_actor_from_changes, apply_remote_property_index, canonical_create_request,
    canonical_update_request, lease_precondition,
};
pub(crate) use plan_kind_list::{PlanKindListSnapshot, PlanKindListTick, PlanRetargetTickGuard};
pub use schema_register::{
    known_action, known_actions, register, require_canary_schema,
    require_connectivity_upgrade_schema, require_package_migration_schema, require_wave_schema,
};
pub(crate) use transport::{
    RemoteClient, block_embedded, block_embedded_status, remote_unary, remote_unary_with_options,
    token_transport_is_safe,
};

/// A lease a plan execution must keep, refreshed with the environment apply
/// fence so a long run cannot outlast its wave or topology (#834).
#[derive(Clone, Debug)]
pub(crate) struct HeldExecutionLease {
    pub namespace: String,
    pub key: String,
    pub fencing_token: String,
    pub ttl_ms: i64,
}

#[derive(Clone)]
pub struct Ctx {
    pub(crate) release_trust_roots: Option<std::path::PathBuf>,
    pub(crate) require_host_release_trust: bool,
    backend: Backend,
    canary_schema_preflight: Arc<OnceCell<()>>,
    outcome_export_enabled: bool,
    outcome_inspection_enabled: bool,
    plan_kind_list: Arc<PlanKindListTick>,
    health_metrics: Option<Arc<dyn crate::health_gate::HealthMetricsSource>>,
    trust_sources: Option<Arc<crate::trust_posture::TrustSources>>,
    pub(crate) held_execution_leases: Vec<HeldExecutionLease>,
}

#[derive(Clone)]
enum Backend {
    Remote {
        client: Arc<RemoteClient>,
        action_defs: action_lifecycle::RemoteActionDefs,
    },
    Embedded(Arc<crate::storage::SqliteStore>),
    /// Enterprise hub: PostgreSQL owns authority; no SQLite catalog is opened.
    TenantHub,
}

pub(super) const TENANT_HUB_UNAVAILABLE: &str =
    "the enterprise hub does not open SQLite; catalog lifecycle is not available in tenant mode";

impl Backend {
    fn object_lifecycle(&self) -> object_lifecycle::ObjectLifecycle<'_> {
        match self {
            Self::Remote { client, .. } => object_lifecycle::ObjectLifecycle::Remote(client),
            Self::Embedded(store) => object_lifecycle::ObjectLifecycle::Embedded(Arc::clone(store)),
            Self::TenantHub => object_lifecycle::ObjectLifecycle::Unavailable,
        }
    }

    fn relation_lifecycle(&self) -> relation_lifecycle::RelationLifecycle<'_> {
        match self {
            Self::Remote { client, .. } => relation_lifecycle::RelationLifecycle::Remote(client),
            Self::Embedded(store) => {
                relation_lifecycle::RelationLifecycle::Embedded(Arc::clone(store))
            }
            Self::TenantHub => relation_lifecycle::RelationLifecycle::Unavailable,
        }
    }

    fn lease_lifecycle(&self) -> lease_lifecycle::LeaseLifecycle<'_> {
        match self {
            Self::Remote { client, .. } => lease_lifecycle::LeaseLifecycle::Remote(client),
            Self::Embedded(store) => lease_lifecycle::LeaseLifecycle::Embedded(Arc::clone(store)),
            Self::TenantHub => lease_lifecycle::LeaseLifecycle::Unavailable,
        }
    }

    fn action_lifecycle(&self) -> action_lifecycle::ActionLifecycle<'_> {
        match self {
            Self::Remote {
                client,
                action_defs,
            } => action_lifecycle::ActionLifecycle::Remote {
                client,
                action_defs,
            },
            Self::Embedded(store) => action_lifecycle::ActionLifecycle::Embedded(Arc::clone(store)),
            Self::TenantHub => action_lifecycle::ActionLifecycle::Unavailable,
        }
    }
}

/// Connect to sekai-chisei. Honors `TENKAI_SEKAI_URL`, `GRPC_PORT`,
/// `SEKAI_AUTH_TOKEN`, and `TENKAI_PRINCIPAL` (default `tenkai`).
pub async fn connect() -> Result<Ctx> {
    let port = std::env::var("GRPC_PORT").unwrap_or_else(|_| "50051".into());
    let url =
        std::env::var("TENKAI_SEKAI_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"));
    let token = crate::secret_source::read("SEKAI_AUTH_TOKEN")?;
    if token.is_some() && !token_transport_is_safe(&url) {
        anyhow::bail!(
            "refusing to send SEKAI_AUTH_TOKEN to non-loopback plaintext endpoint {url}; use HTTPS"
        );
    }
    let principal = std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "tenkai".into());
    let mut config = ClientConfig::new(url.clone(), principal).with_retry_policy(RetryPolicy {
        max_attempts: 2,
        initial_backoff: Duration::from_millis(0),
        max_backoff: Duration::from_millis(0),
        retryable_codes: vec![SdkErrorCode::Unavailable, SdkErrorCode::DeadlineExceeded],
    });
    if let Some(token) = token {
        config = config.with_token(token).map_err(anyhow::Error::new)?;
    }
    let trust = crate::outbound_tls::OutboundTrust::from_env()?;
    if crate::outbound_tls::is_tls_url(&url) && !trust.system_roots {
        // The backend SDK always trusts its built-in roots; refuse rather
        // than trust more than TENKAI_TLS_SYSTEM_ROOTS=false allows.
        anyhow::bail!(
            "{}=false cannot be honored for the remote backend at {url} yet: its client always trusts the built-in roots",
            crate::outbound_tls::SYSTEM_ROOTS_ENV
        );
    }
    if let Some(pem) = trust.bundle_pem {
        config = config.with_tls_ca_certificate(pem);
    }
    let client = RemoteClient::connect(config)
        .await
        .map_err(anyhow::Error::new)
        .with_context(|| {
            format!(
                "connecting to sekai-chisei at {url} — is the server running? (SEKAI_INSECURE=1 cargo run)"
            )
        })?;
    Ok(Ctx {
        release_trust_roots: None,
        require_host_release_trust: false,
        backend: Backend::Remote {
            client: Arc::new(client),
            action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        },
        canary_schema_preflight: Arc::new(OnceCell::new()),
        outcome_export_enabled: false,
        outcome_inspection_enabled: false,
        plan_kind_list: Arc::new(PlanKindListTick::default()),
        health_metrics: None,
        trust_sources: None,
        held_execution_leases: Vec::new(),
    })
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

    /// True when create reused a deleted id whose audit history is still stored.
    pub(crate) fn is_retired_identity(&self) -> bool {
        match self {
            Self::Failed(error) => error.to_string().contains("object IDs with audit history"),
            _ => false,
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
