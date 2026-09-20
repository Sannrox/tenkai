use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::auth_context::{AuthenticatedRequestContext, CredentialMaterial, PrincipalKind};
use crate::development_fixtures::DevelopmentFixture;
use crate::federated_identity::reject_caller_selected_tenant;
use crate::management_operations::ManagementError;
use crate::tenant_isolation::NON_DISCLOSING_DENY;

use super::router::AppState;
use super::runtime::{bearer, error_response, management_error};

fn authorize_development_fixture(
    state: &AppState,
    context: &AuthenticatedRequestContext,
) -> Result<(), Box<Response>> {
    let Some(config) = &state.config.development_fixtures else {
        return Err(Box::new(error_response(StatusCode::NOT_FOUND, "not found")));
    };
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
    if let Err(response) = authorize_development_fixture(&state, &context) {
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
        Err(crate::tenant_isolation::IsolationError::NotFound)
        | Err(crate::tenant_isolation::IsolationError::Unauthenticated) => {
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
    if let Err(response) = authorize_development_fixture(&state, &context) {
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
            Err(crate::tenant_isolation::IsolationError::NotFound)
            | Err(crate::tenant_isolation::IsolationError::Unauthenticated) => Err(Box::new(
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
    let assertion = headers
        .get("x-tenkai-assertion")
        .and_then(|value| value.to_str().ok())
        .map(|raw| raw.as_bytes().to_vec())
        .filter(|bytes| !bytes.is_empty());
    if bearer_token.is_none() && assertion.is_none() {
        return Err(ManagementError::Unauthorized("missing bearer token".into()));
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
    })
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
