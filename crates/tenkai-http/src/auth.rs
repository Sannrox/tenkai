use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use tenkai::auth_context::{
    AuthenticatedRequestContext, CredentialMaterial, PeerCredentials, PrincipalKind,
};
use tenkai::development_fixtures::DevelopmentFixture;
use tenkai::federated_identity::reject_caller_selected_tenant;
use tenkai::host_identity::{is_loopback_console_origin, is_loopback_host};
use tenkai::management_operations::ManagementError;
use tenkai::tenant_isolation::NON_DISCLOSING_DENY;

use super::router::AppState;
use super::runtime::{bearer, error_response, management_error};

fn authorize_development_fixture(
    state: &AppState,
    context: &AuthenticatedRequestContext,
    operation: &str,
) -> Result<(), Box<Response>> {
    let Some(config) = &state.config.development_fixtures else {
        return Err(Box::new(error_response(StatusCode::NOT_FOUND, "not found")));
    };
    state
        .management
        .refuse_agent(context, operation)
        .map_err(|error| Box::new(management_error(error)))?;
    if context.tenant().is_none()
        || !matches!(
            context.principal.kind,
            PrincipalKind::Service | PrincipalKind::Management
        )
        || !config.allowed_principals.contains(context.principal_id())
    {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            NON_DISCLOSING_DENY,
        )));
    }
    Ok(())
}

pub(super) async fn import_development_fixture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(fixture): Json<DevelopmentFixture>,
) -> Response {
    let context = match authenticate_management(&state, &headers) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Err(response) = require_tenant_scope(&state, &context, None).await {
        return *response;
    }
    if let Err(response) =
        authorize_development_fixture(&state, &context, "development_fixture.import")
    {
        return *response;
    }
    let prepared = match fixture.prepare() {
        Ok(prepared) => prepared,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid fixture document"),
    };
    let Some(store) = state.tenant_store.clone() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "fixture store unavailable");
    };
    let result = match run_blocking_tenant_store(move || {
        store.import_development_fixture_for(&context, &prepared)
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(map) => (StatusCode::OK, Json(map)).into_response(),
        Err(tenkai::tenant_isolation::IsolationError::NotFound)
        | Err(tenkai::tenant_isolation::IsolationError::Unauthenticated) => {
            error_response(StatusCode::NOT_FOUND, NON_DISCLOSING_DENY)
        }
        Err(error) => {
            eprintln!("development fixture import failed: {error}");
            error_response(StatusCode::CONFLICT, "fixture import conflict")
        }
    }
}

pub(super) async fn reset_development_fixture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(fixture_id): Path<String>,
) -> Response {
    let context = match authenticate_management(&state, &headers) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Err(response) = require_tenant_scope(&state, &context, None).await {
        return *response;
    }
    if let Err(response) =
        authorize_development_fixture(&state, &context, "development_fixture.reset")
    {
        return *response;
    }
    let Some(store) = state.tenant_store.clone() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "fixture store unavailable");
    };
    let result = match run_blocking_tenant_store(move || {
        store.reset_development_fixture_for(&context, &fixture_id)
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(error) => {
            eprintln!("development fixture reset failed: {error}");
            error_response(StatusCode::CONFLICT, "fixture reset conflict")
        }
    }
}

/// When tenant mode is enabled, require authenticated tenant membership and
/// optionally verify an environment id is visible to that tenant.
async fn require_tenant_scope(
    state: &AppState,
    context: &AuthenticatedRequestContext,
    environment: Option<&str>,
) -> Result<(), Box<Response>> {
    if !state.config.requirements.tenant_mode {
        return Ok(());
    }
    let Some(tenant_store) = state.tenant_store.as_ref() else {
        return Err(Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant mode is enabled but no tenant store is configured",
        )));
    };
    if context.tenant().is_none() {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "unauthenticated",
        )));
    }
    if let Some(environment) = environment {
        let tenant_store = tenant_store.clone();
        let context = context.clone();
        let environment = environment.to_string();
        let result = run_blocking_tenant_store(move || {
            tenant_store.get_environment_for(&context, &environment)
        })
        .await
        .map_err(Box::new)?;
        match result {
            Ok(_) => Ok(()),
            Err(tenkai::tenant_isolation::IsolationError::NotFound)
            | Err(tenkai::tenant_isolation::IsolationError::Unauthenticated) => Err(Box::new(
                error_response(StatusCode::NOT_FOUND, NON_DISCLOSING_DENY),
            )),
            Err(error) => Err(Box::new(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                error.public_message(),
            ))),
        }
    } else {
        let _ = tenant_store;
        Ok(())
    }
}

pub(super) async fn run_blocking_tenant_store<T, F>(operation: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            eprintln!("tenant store blocking task failed: {error}");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "tenant store unavailable")
        })
}

/// Authenticate a management HTTP request through the composed [`AuthStack`].
///
/// Caller-selected tenant headers are intentionally ignored: only the
/// authenticator may attach tenant context after credential verification.
fn authenticate_management(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedRequestContext, Box<Response>> {
    let credential =
        management_credential(headers).map_err(|error| Box::new(management_error(error)))?;
    state
        .management
        .authenticate(&credential)
        .map_err(|error| Box::new(management_error(error)))
}

fn management_credential(headers: &HeaderMap) -> Result<CredentialMaterial, ManagementError> {
    // Caller-selected tenant metadata cannot select federation/tenant authority.
    if reject_caller_selected_tenant(
        headers
            .get("x-tenkai-tenant")
            .or_else(|| headers.get("x-tenant-id"))
            .and_then(|value| value.to_str().ok()),
    )
    .is_err()
    {
        return Err(ManagementError::Forbidden(
            "caller metadata cannot select tenant authority".into(),
        ));
    }
    let bearer_token = bearer(headers).map(str::to_string);
    // A compact-JWS bearer (for example an OIDC access token) is also offered
    // to the enterprise extension; configured community tokens still win.
    let assertion = headers
        .get("x-tenkai-assertion")
        .and_then(|value| value.to_str().ok())
        .map(|raw| raw.as_bytes().to_vec())
        .filter(|bytes| !bytes.is_empty())
        .or_else(|| {
            bearer_token
                .as_deref()
                .filter(|token| is_compact_jws(token))
                .map(|token| token.as_bytes().to_vec())
        });
    let peer_credentials = match current_unix_peer() {
        UnixPeerState::Uid(uid) => Some(PeerCredentials { uid }),
        UnixPeerState::Unavailable => {
            return Err(ManagementError::Unauthorized(
                "peer credentials unavailable".into(),
            ));
        }
        UnixPeerState::Tcp => None,
    };
    if bearer_token.is_none() && assertion.is_none() && peer_credentials.is_none() {
        return Err(ManagementError::Unauthorized(
            tenkai::management_operations::MISSING_CREDENTIAL.into(),
        ));
    }
    if peer_credentials.is_some() && bearer_token.is_none() && assertion.is_none() {
        refuse_peer_csrf(headers)?;
    }
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    Ok(CredentialMaterial {
        request_id,
        bearer_token,
        assertion,
        peer_credentials,
    })
}

/// Connection identity set by [`crate::opening::HotSwap`] for this request.
#[derive(Debug, Clone, Copy)]
pub(crate) enum UnixPeerState {
    Tcp,
    Uid(u32),
    Unavailable,
}

tokio::task_local! {
    static UNIX_PEER: UnixPeerState;
}

pub(crate) fn current_unix_peer() -> UnixPeerState {
    UNIX_PEER
        .try_with(|state| *state)
        .unwrap_or(UnixPeerState::Tcp)
}

pub(crate) async fn with_unix_peer<F, T>(state: UnixPeerState, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    UNIX_PEER.scope(state, fut).await
}

fn refuse_peer_csrf(headers: &HeaderMap) -> Result<(), ManagementError> {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !is_loopback_host(host) {
        return Err(ManagementError::Forbidden(
            "host identity requires a loopback Host".into(),
        ));
    }
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get(axum::http::header::REFERER)
                .and_then(|value| value.to_str().ok())
        });
    if let Some(origin) = origin
        && !is_loopback_console_origin(origin)
    {
        return Err(ManagementError::Forbidden(
            "host identity Origin is not a loopback console origin".into(),
        ));
    }
    Ok(())
}

fn is_compact_jws(token: &str) -> bool {
    let mut parts = token.split('.');
    let segment_ok = |part: Option<&str>| {
        part.is_some_and(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
    };
    segment_ok(parts.next())
        && segment_ok(parts.next())
        && segment_ok(parts.next())
        && parts.next().is_none()
}

pub(super) fn require_management(headers: &HeaderMap) -> Result<CredentialMaterial, Box<Response>> {
    management_credential(headers).map_err(|error| Box::new(management_error(error)))
}

pub(super) fn manage_result<T: Serialize>(result: Result<T, ManagementError>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => management_error(error),
    }
}

pub(super) fn parse_management_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, Box<Response>> {
    parse_migration_json(body)
}
fn parse_migration_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, Box<Response>> {
    serde_json::from_slice(body).map_err(|error| {
        Box::new(error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid package migration request: {error}"),
        ))
    })
}
