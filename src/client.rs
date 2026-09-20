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
pub(crate) use transport::{
    RemoteClient, block_embedded, block_embedded_status, remote_unary, remote_unary_with_options,
    token_transport_is_safe,
};

#[derive(Clone)]
pub struct Ctx {
    backend: Backend,
    canary_schema_preflight: Arc<OnceCell<()>>,
    outcome_export_enabled: bool,
    outcome_inspection_enabled: bool,
    plan_kind_list: Arc<PlanKindListTick>,
}

#[derive(Clone)]
enum Backend {
    Remote {
        client: Arc<RemoteClient>,
        action_defs: action_lifecycle::RemoteActionDefs,
    },
    Embedded(Arc<crate::storage::SqliteStore>),
}

impl Backend {
    fn object_lifecycle(&self) -> object_lifecycle::ObjectLifecycle<'_> {
        match self {
            Self::Remote { client, .. } => object_lifecycle::ObjectLifecycle::Remote(client),
            Self::Embedded(store) => object_lifecycle::ObjectLifecycle::Embedded(Arc::clone(store)),
        }
    }

    fn relation_lifecycle(&self) -> relation_lifecycle::RelationLifecycle<'_> {
        match self {
            Self::Remote { client, .. } => relation_lifecycle::RelationLifecycle::Remote(client),
            Self::Embedded(store) => {
                relation_lifecycle::RelationLifecycle::Embedded(Arc::clone(store))
            }
        }
    }

    fn lease_lifecycle(&self) -> lease_lifecycle::LeaseLifecycle<'_> {
        match self {
            Self::Remote { client, .. } => lease_lifecycle::LeaseLifecycle::Remote(client),
            Self::Embedded(store) => lease_lifecycle::LeaseLifecycle::Embedded(Arc::clone(store)),
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
        }
    }
}

/// Connect to sekai-chisei. Honors `TENKAI_SEKAI_URL`, `GRPC_PORT`,
/// `SEKAI_AUTH_TOKEN`, and `TENKAI_PRINCIPAL` (default `tenkai`).
pub async fn connect() -> Result<Ctx> {
    let port = std::env::var("GRPC_PORT").unwrap_or_else(|_| "50051".into());
    let url =
        std::env::var("TENKAI_SEKAI_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"));
    let token = std::env::var("SEKAI_AUTH_TOKEN").ok();
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
    let client = RemoteClient::connect(config)
        .await
        .map_err(anyhow::Error::new)
        .with_context(|| {
            format!(
                "connecting to sekai-chisei at {url} — is the server running? (SEKAI_INSECURE=1 cargo run)"
            )
        })?;
    Ok(Ctx {
        backend: Backend::Remote {
            client: Arc::new(client),
            action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        },
        canary_schema_preflight: Arc::new(OnceCell::new()),
        outcome_export_enabled: false,
        outcome_inspection_enabled: false,
        plan_kind_list: Arc::new(PlanKindListTick::default()),
    })
}

/// True when create-once (or register) failed because the identity already exists.
pub(crate) fn is_unique_conflict(status: &Status) -> bool {
    status.code() == tonic::Code::AlreadyExists
        || (status.code() == tonic::Code::Internal && status.message().contains("UNIQUE"))
}
