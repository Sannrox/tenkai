//! `/v1/debug-sessions` (ADR 0061, #1556): open, list, inspect and close
//! debug sessions. The management operations hold every check.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::auth::{manage_result, parse_management_json, require_management};
use super::router::AppState;
use super::runtime::management_error;
use tenkai::management_operations::DebugSessionQuery;

pub(super) async fn open_debug_session(
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
    match state
        .management
        .open_debug_session(&credential, request)
        .await
    {
        Ok(session) => (StatusCode::CREATED, Json(session)).into_response(),
        Err(error) => management_error(error),
    }
}

pub(super) async fn list_debug_sessions(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DebugSessionQuery>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .list_debug_sessions(&credential, query)
            .await,
    )
}

pub(super) async fn inspect_debug_session(
    State(state): State<Arc<AppState>>,
    Path(session): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .inspect_debug_session(&credential, &session)
            .await,
    )
}

pub(super) async fn close_debug_session(
    State(state): State<Arc<AppState>>,
    Path(session): Path<String>,
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
            .close_debug_session(&credential, &session, request)
            .await,
    )
}
