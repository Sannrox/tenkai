use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::auth::{manage_result, require_management};
use super::config::ServerConfig;
use super::router::{AppState, ServiceStatus};
use super::runtime::error_response;

pub(super) async fn change_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .list_change_events(
                &credential,
                query_param(&uri, "cursor").as_deref(),
                query_param(&uri, "limit").as_deref(),
            )
            .await,
    )
}

fn query_param(uri: &axum::http::Uri, key: &str) -> Option<String> {
    let query = uri.query()?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if parts.next() == Some(key) {
            return parts.next().map(|value| value.replace('+', " "));
        }
    }
    None
}

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

pub(super) async fn list_releases(
    State(state): State<Arc<AppState>>,
    Query(query): Query<tenkai::page::PageQuery>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.list_releases(&credential, query).await)
}

pub(super) async fn query_exposures(
    State(state): State<Arc<AppState>>,
    Query(query): Query<tenkai::exposure::ExposureQueryRequest>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.query_exposures(&credential, query).await)
}

pub(super) async fn list_channels(
    State(state): State<Arc<AppState>>,
    Query(query): Query<tenkai::page::PageQuery>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.list_channels(&credential, query).await)
}

pub(super) async fn list_migrations(
    State(state): State<Arc<AppState>>,
    Query(query): Query<tenkai::page::PageQuery>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.list_migrations(&credential, query).await)
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

pub(super) async fn plan_approvals(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(state.management.plan_approvals(&credential, &plan_id).await)
}

pub(super) async fn environment_approval_policy(
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
            .environment_approval_policy(&credential, &environment)
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

pub(super) async fn observed_runtime(
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
            .observed_runtime(&credential, &environment)
            .await,
    )
}

fn service_status(status: &'static str, config: &ServerConfig) -> ServiceStatus {
    ServiceStatus {
        status,
        version: tenkai::version_skew::SERVER_VERSION,
        trust: config
            .trust_status
            .read()
            .ok()
            .and_then(|snapshot| snapshot.map(|snapshot| snapshot.status)),
        profile: config.capabilities.profile.clone(),
        capabilities: config.capabilities.diagnostic_names(),
        contracts: super::contract::SERVED_CONTRACTS.to_vec(),
        first_administrator: Some(config.stored_grants.as_ref().map_or(
            config.first_administrator,
            |stored| {
                config
                    .first_administrator
                    .either(stored.first_administrator())
            },
        )),
        backup: config
            .backups
            .as_ref()
            .map(|backups| backups.health(tenkai::now_millis())),
        clock: tenkai::clock_guard::installed().map(|guard| guard.health()),
    }
}

pub(super) async fn take_backup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let Some(backups) = state.config.backups.clone() else {
        return error_response(StatusCode::NOT_FOUND, "backups are not configured");
    };
    manage_result(state.management.take_backup(&credential, backups).await)
}

pub(super) async fn backup_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let Some(backups) = state.config.backups.clone() else {
        return error_response(StatusCode::NOT_FOUND, "backups are not configured");
    };
    manage_result(state.management.backup_status(&credential, backups).await)
}

/// Unauthenticated OpenMetrics scrape when `metrics_enabled` (#137).
/// No bearer required: intended for loopback Prometheus scrapes only.
pub(super) async fn openmetrics(State(state): State<Arc<AppState>>) -> Response {
    if !state.config.metrics_enabled {
        return error_response(StatusCode::NOT_FOUND, "metrics disabled");
    }
    let body =
        tenkai::metrics::render_reconcile_openmetrics(&state.reconciler.diagnostics_snapshot());
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

/// Unauthenticated OIDC client discovery for browsers (#468). 404 when the
/// host has no OIDC public client configured.
pub(super) async fn oidc_client(State(state): State<Arc<AppState>>) -> Response {
    match &state.config.oidc_client {
        Some(client) => Json(client).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "OIDC is not configured"),
    }
}

pub(super) async fn ready(State(state): State<Arc<AppState>>) -> Response {
    // A standby is alive (/healthz) but must not take writes (#748).
    if state
        .config
        .writer_fence
        .as_ref()
        .is_some_and(|fence| !fence.is_leader())
    {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "standby: another replica holds the hub writer lease",
        );
    }
    // Stored grant rules (#836) this replica cannot keep current are
    // suspended; it is not ready until a check succeeds.
    if state
        .config
        .stored_grants
        .as_ref()
        .is_some_and(|stored| stored.is_stale())
    {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "stored grant rules are stale: the store has not answered recent checks",
        );
    }
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
