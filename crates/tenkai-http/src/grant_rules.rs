//! `/v1/grant-rules` (#837): list, create and remove the OIDC grant rules
//! stored in the hub's store. Fleet management only; see
//! `tenkai::management_operations` for the authorization.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::auth::{manage_result, parse_management_json, require_management};
use super::router::AppState;
use super::runtime::{error_response, management_error};

/// Every route answers 404 on a host without OIDC, which has no stored rules.
fn configured(state: &AppState) -> Result<Arc<tenkai::grant_rules::StoredGrants>, Box<Response>> {
    state.config.stored_grants.clone().ok_or_else(|| {
        Box::new(error_response(
            StatusCode::NOT_FOUND,
            "stored grant rules need OIDC authentication",
        ))
    })
}

pub(super) async fn list_grant_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let stored = match configured(&state) {
        Ok(stored) => stored,
        Err(error) => return *error,
    };
    manage_result(state.management.list_grant_rules(&credential, stored).await)
}

pub(super) async fn create_grant_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let stored = match configured(&state) {
        Ok(stored) => stored,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    match state
        .management
        .create_grant_rule(&credential, stored, request)
        .await
    {
        Ok(list) => (StatusCode::CREATED, axum::Json(list)).into_response(),
        Err(error) => management_error(error),
    }
}

pub(super) async fn remove_grant_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let stored = match configured(&state) {
        Ok(stored) => stored,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .remove_grant_rule(&credential, stored, request)
            .await,
    )
}
