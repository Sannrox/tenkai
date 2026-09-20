use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::management_operations::ManagementError;
use crate::runtime_delivery::{RuntimeDeliveryError, RuntimeHeartbeat, RuntimeInventoryReport};

use super::router::{AppState, ErrorBody};

pub(super) async fn runtime_work(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Response {
    match state
        .runtime_delivery
        .claim_work(bearer(&headers), runtime_instance(&headers), &environment)
        .await
    {
        Ok(work) => Json(work).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

pub(super) async fn runtime_complete(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    Json(completion): Json<crate::runtime_delivery::RuntimeCompletion>,
) -> Response {
    match state
        .runtime_delivery
        .complete(
            bearer(&headers),
            runtime_instance(&headers),
            &environment,
            completion,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

pub(super) async fn runtime_heartbeat(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    Json(heartbeat): Json<RuntimeHeartbeat>,
) -> Response {
    match state.runtime_delivery.renew(
        bearer(&headers),
        runtime_instance(&headers),
        &environment,
        &heartbeat,
    ) {
        Ok(claim) => Json(claim).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// Runtime inventory report: write admitted capability facts for the assigned env (#136).
pub(super) async fn runtime_inventory(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    Json(report): Json<RuntimeInventoryReport>,
) -> Response {
    match state
        .runtime_delivery
        .report_inventory(
            bearer(&headers),
            runtime_instance(&headers),
            &environment,
            report,
        )
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

fn runtime_instance(headers: &HeaderMap) -> Option<&str> {
    let instance = headers.get("x-tenkai-runtime-instance")?.to_str().ok()?;
    (!instance.is_empty() && instance.len() <= 128 && instance.is_ascii()).then_some(instance)
}

pub(super) fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

pub(super) fn error_response(status: StatusCode, error: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: error.into(),
        }),
    )
        .into_response()
}

fn runtime_delivery_error(error: RuntimeDeliveryError) -> Response {
    let status = match error {
        RuntimeDeliveryError::MissingCredential => StatusCode::UNAUTHORIZED,
        RuntimeDeliveryError::InvalidCredential | RuntimeDeliveryError::ForeignEnvironment => {
            StatusCode::FORBIDDEN
        }
        RuntimeDeliveryError::InvalidInstance | RuntimeDeliveryError::InvalidRequest(_) => {
            StatusCode::BAD_REQUEST
        }
        RuntimeDeliveryError::Conflict(_) => StatusCode::CONFLICT,
        RuntimeDeliveryError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        RuntimeDeliveryError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_response(status, error.to_string())
}

pub(super) fn management_error(error: ManagementError) -> Response {
    match error {
        ManagementError::Unauthorized(message) => error_response(StatusCode::UNAUTHORIZED, message),
        ManagementError::Forbidden(message) => error_response(StatusCode::FORBIDDEN, message),
        ManagementError::NotFound(message) => error_response(StatusCode::NOT_FOUND, message),
        ManagementError::BadRequest(message) => error_response(StatusCode::BAD_REQUEST, message),
        ManagementError::Conflict(message) => error_response(StatusCode::CONFLICT, message),
        ManagementError::Unavailable(message) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, message)
        }
        ManagementError::Internal(message) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

pub(super) fn encode_plan_path(plan_id: &str) -> String {
    plan_id
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
