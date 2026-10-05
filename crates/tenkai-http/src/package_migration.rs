use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;

use super::auth::{manage_result, parse_management_json, require_management};
use super::router::AppState;

pub(super) async fn preview_package_migration(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
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
            .preview_package_migration(&credential, &name, request)
            .await,
    )
}

pub(super) async fn apply_package_migration(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
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
            .apply_package_migration(&credential, &name, request)
            .await,
    )
}

pub(super) async fn package_migration_status(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .package_migration_status(&credential, &name)
            .await,
    )
}

pub(super) async fn resume_package_migration(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
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
            .resume_package_migration(&credential, &name, request)
            .await,
    )
}

pub(super) async fn rollback_package_migration(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
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
            .rollback_package_migration(&credential, &name, request)
            .await,
    )
}
