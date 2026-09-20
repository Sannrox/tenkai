use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;

use super::auth::{manage_result, parse_management_json, require_management};
use super::router::AppState;

pub(super) async fn publish_release(
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
    manage_result(state.management.publish_release(&credential, request).await)
}

pub(super) async fn promote_release(
    State(state): State<Arc<AppState>>,
    Path(channel): Path<String>,
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
            .promote_release(&credential, &channel, request)
            .await,
    )
}

pub(super) async fn recall_release(
    State(state): State<Arc<AppState>>,
    Path(release): Path<String>,
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
            .recall_release(&credential, &release, request)
            .await,
    )
}

pub(super) async fn subscribe_environment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
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
            .subscribe_environment(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn plan_environment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
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
            .plan_environment(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn approve_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
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
            .approve_plan(&credential, &plan_id, request)
            .await,
    )
}

pub(super) async fn apply_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
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
            .apply_plan(&credential, &plan_id, request)
            .await,
    )
}

pub(super) async fn rollback_environment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
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
            .rollback_environment(&credential, &environment, request)
            .await,
    )
}
