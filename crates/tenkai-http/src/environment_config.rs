//! Environment registration and configuration routes (#679).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method};
use axum::response::Response;
use tenkai::environment_config::ConfigResource;

use super::auth::{manage_result, parse_management_json, require_management};
use super::router::AppState;

pub(super) async fn register_environment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .register_environment(&credential, request)
            .await,
    )
}

pub(super) async fn configure_bindings(
    state: State<Arc<AppState>>,
    method: Method,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    configure(
        state,
        method,
        environment,
        None,
        ConfigResource::Bindings,
        headers,
        body,
    )
    .await
}

/// Sealed secret values (ADR 0045): `GET` lists them, `PUT` stores one
/// sealed by the client, `DELETE` removes one.
pub(super) async fn list_sealed_secrets(
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
            .list_sealed_secrets(&credential, &environment)
            .await,
    )
}

pub(super) async fn configure_sealed_secrets(
    state: State<Arc<AppState>>,
    method: Method,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    configure(
        state,
        method,
        environment,
        None,
        ConfigResource::SealedSecrets,
        headers,
        body,
    )
    .await
}

pub(super) async fn configure_facts(
    state: State<Arc<AppState>>,
    method: Method,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    configure(
        state,
        method,
        environment,
        None,
        ConfigResource::Facts,
        headers,
        body,
    )
    .await
}

pub(super) async fn configure_constraints(
    state: State<Arc<AppState>>,
    method: Method,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    configure(
        state,
        method,
        environment,
        None,
        ConfigResource::Constraints,
        headers,
        body,
    )
    .await
}

pub(super) async fn configure_maintenance_window(
    state: State<Arc<AppState>>,
    method: Method,
    Path((environment, window)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    configure(
        state,
        method,
        environment,
        Some(window),
        ConfigResource::MaintenanceWindow,
        headers,
        body,
    )
    .await
}

pub(super) async fn configure_webhooks(
    state: State<Arc<AppState>>,
    method: Method,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    configure(
        state,
        method,
        environment,
        None,
        ConfigResource::Webhooks,
        headers,
        body,
    )
    .await
}

pub(super) async fn configure_approval_policy(
    state: State<Arc<AppState>>,
    method: Method,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    configure(
        state,
        method,
        environment,
        None,
        ConfigResource::ApprovalPolicy,
        headers,
        body,
    )
    .await
}

/// Declared environment criticality (#694): `PUT` sets it, `DELETE` clears it.
pub(super) async fn configure_criticality(
    state: State<Arc<AppState>>,
    method: Method,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    configure(
        state,
        method,
        environment,
        None,
        ConfigResource::Criticality,
        headers,
        body,
    )
    .await
}

/// The runner attestation policy (#675): `PUT` requires it, `DELETE` clears it.
pub(super) async fn configure_runner_attestation(
    state: State<Arc<AppState>>,
    method: Method,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    configure(
        state,
        method,
        environment,
        None,
        ConfigResource::RunnerAttestation,
        headers,
        body,
    )
    .await
}

/// Shared body of every configuration route: `PUT` sets, `DELETE` clears.
async fn configure(
    State(state): State<Arc<AppState>>,
    method: Method,
    environment: String,
    window: Option<String>,
    resource: ConfigResource,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .configure_environment(
                &credential,
                &environment,
                (resource, method == Method::DELETE, window.as_deref()),
                request,
            )
            .await,
    )
}
