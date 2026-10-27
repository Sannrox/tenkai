//! `/v1/exports` (#682): create, list, inspect and download exports.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::auth::{manage_result, parse_management_json, require_management};
use super::router::AppState;
use super::runtime::{error_response, management_error};

/// Every route answers 404 when the host has no export directory.
fn configured(state: &AppState) -> Result<Arc<tenkai::exports::Exports>, Box<Response>> {
    state.config.exports.clone().ok_or_else(|| {
        Box::new(error_response(
            StatusCode::NOT_FOUND,
            "exports are not configured",
        ))
    })
}

pub(super) async fn create_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let exports = match configured(&state) {
        Ok(exports) => exports,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    match state
        .management
        .create_export(&credential, exports, request)
        .await
    {
        Ok(entry) => (StatusCode::CREATED, axum::Json(entry)).into_response(),
        Err(error) => management_error(error),
    }
}

pub(super) async fn list_exports(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let exports = match configured(&state) {
        Ok(exports) => exports,
        Err(error) => return *error,
    };
    manage_result(state.management.list_exports(&credential, exports).await)
}

pub(super) async fn inspect_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let exports = match configured(&state) {
        Ok(exports) => exports,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .inspect_export(&credential, exports, id)
            .await,
    )
}

#[derive(Deserialize)]
pub(super) struct DownloadQuery {
    #[serde(default)]
    reason: String,
}

/// The artifact as an attachment under the name the CLI would give it.
pub(super) async fn download_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<DownloadQuery>,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let exports = match configured(&state) {
        Ok(exports) => exports,
        Err(error) => return *error,
    };
    match state
        .management
        .download_export(&credential, exports, id, &query.reason)
        .await
    {
        Ok((export, artifact)) => {
            // The stored name holds only `[A-Za-z0-9._-]`.
            let disposition =
                HeaderValue::from_str(&format!("attachment; filename=\"{}\"", export.file_name))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment"));
            (
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    ),
                    (header::CONTENT_DISPOSITION, disposition),
                ],
                artifact,
            )
                .into_response()
        }
        Err(error) => management_error(error),
    }
}
