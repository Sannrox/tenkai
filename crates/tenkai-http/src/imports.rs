//! Offline bundle import and content inventory routes (#680).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

use super::auth::{manage_result, parse_management_json, require_management};
use super::router::AppState;
use super::runtime::error_response;

fn not_configured() -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "bundle import is not configured on this server",
    )
}

pub(super) async fn staged_imports(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let Some(settings) = &state.config.imports else {
        return not_configured();
    };
    manage_result(state.management.staged_imports(&credential, settings).await)
}

pub(super) async fn import_bundle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let Some(settings) = &state.config.imports else {
        return not_configured();
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .import_bundle(&credential, settings, request)
            .await,
    )
}

pub(super) async fn import_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let Some(settings) = &state.config.imports else {
        return not_configured();
    };
    manage_result(
        state
            .management
            .import_job(&credential, settings, &id)
            .await,
    )
}

pub(super) async fn content_inventory(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.content_inventory(&credential).await)
}

pub(super) async fn environment_webhook_deliveries(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .webhook_deliveries(&credential, Some(&environment))
            .await,
    )
}

pub(super) async fn host_webhook_deliveries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.webhook_deliveries(&credential, None).await)
}
