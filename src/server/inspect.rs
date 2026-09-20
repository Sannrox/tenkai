use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::auth::{manage_result, require_management};
use super::config::ServerConfig;
use super::router::{AppState, ServiceStatus};
use super::runtime::error_response;

pub(super) async fn fleet_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.fleet_status(&credential).await)
}

pub(super) async fn list_environments(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.list_environments(&credential).await)
}

pub(super) async fn inspect_environment(
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
            .inspect_environment(&credential, &environment)
            .await,
    )
}

pub(super) async fn environment_status(
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
            .environment_status(&credential, &environment)
            .await,
    )
}

fn service_status(status: &'static str, config: &ServerConfig) -> ServiceStatus {
    ServiceStatus {
        status,
        profile: config.capabilities.profile.clone(),
        capabilities: config.capabilities.diagnostic_names(),
    }
}

/// Unauthenticated OpenMetrics scrape when `metrics_enabled` (#137).
/// No bearer required: intended for loopback Prometheus scrapes only.
pub(super) async fn openmetrics(State(state): State<Arc<AppState>>) -> Response {
    if !state.config.metrics_enabled {
        return error_response(StatusCode::NOT_FOUND, "metrics disabled");
    }
    let body =
        crate::metrics::render_reconcile_openmetrics(&state.reconciler.diagnostics_snapshot());
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub(super) async fn health(State(state): State<Arc<AppState>>) -> Json<ServiceStatus> {
    Json(service_status("ok", &state.config))
}

pub(super) async fn ready(State(state): State<Arc<AppState>>) -> Response {
    let operational_store = state.store.clone();
    match tokio::task::spawn_blocking(move || operational_store.check_health()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("operational store readiness check failed: {error}");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "service is not ready");
        }
        Err(error) => {
            eprintln!("operational store readiness task failed: {error}");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "service is not ready");
        }
    }
    if let Some(tenant_store) = state.tenant_store.clone() {
        match tokio::task::spawn_blocking(move || tenant_store.check_health()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!("tenant store readiness check failed: {error}");
                return error_response(StatusCode::SERVICE_UNAVAILABLE, "service is not ready");
            }
            Err(error) => {
                eprintln!("tenant store readiness task failed: {error}");
                return error_response(StatusCode::SERVICE_UNAVAILABLE, "service is not ready");
            }
        }
    }
    match state.reconciler.check_health().await {
        Ok(()) => Json(service_status("ready", &state.config)).into_response(),
        Err(error) => error_response(StatusCode::SERVICE_UNAVAILABLE, {
            eprintln!("required provider readiness check failed: {error:#}");
            "service is not ready"
        }),
    }
}

pub(super) async fn reconcile(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.reconcile(&credential).await)
}
