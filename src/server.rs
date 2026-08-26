//! Authenticated network host for the shared Tenkai application core.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::auth_context::{
    AuthHostConfig, AuthStack, AuthenticatedRequestContext, CommunityTokenAuthenticator,
    CredentialMaterial, EnterpriseAuthExtension, PrincipalIdentity, PrincipalKind,
    build_auth_stack,
};
use crate::development_fixtures::DevelopmentFixture;
use crate::federated_identity::{
    FederatingAuthExtension, FederationConfig, IdentityDirectory, reject_caller_selected_tenant,
};
use crate::management_operations::{ManagementError, ManagementOperations};
use crate::reconciler::TickReport;
use crate::runtime_capabilities::{
    ProvidedCapabilities, RuntimeRequirements, community_auth_capabilities,
    community_sqlite_profile, validate_runtime_capabilities,
};
pub use crate::runtime_delivery::{
    CompletionFuture, FleetStatusFuture, HealthFuture, InspectEnvFuture, InventoryFuture,
    ListEnvFuture, ReconcileFuture, ReconcilePort, RuntimeHeartbeat, RuntimeInventoryReport,
    RuntimeInventoryResponse, RuntimeWork, StatusEnvFuture, WorkFuture,
};
use crate::runtime_delivery::{RuntimeDeliveryError, RuntimeDeliveryOperations};
use crate::storage::OperationalStore;
use crate::tenant_isolation::NON_DISCLOSING_DENY;
use crate::tenant_store::TenantOperationalStore;

#[derive(Clone)]
pub struct ServerConfig {
    pub management_token: String,
    /// Maps a runtime bearer token to its one assigned environment.
    pub runtime_assignments: HashMap<String, String>,
    /// Host capability requirements validated before the router accepts traffic.
    pub requirements: RuntimeRequirements,
    /// Composed capabilities advertised by storage and extensions.
    pub capabilities: ProvidedCapabilities,
    /// Auth host composition (community default; set required extension for enterprise).
    pub auth_host: AuthHostConfig,
    /// Optional enterprise auth extension. Required when `auth_host` demands one
    /// or when `requirements.require_enterprise_authentication` is set.
    pub enterprise_auth: Option<Arc<dyn EnterpriseAuthExtension>>,
    /// Federation accept rules (issuer/audience/replay). Community hosts leave
    /// the enterprise issuer unset so federation is not required.
    pub federation: FederationConfig,
    /// Local correlation + replay directory (never shared with an identity plane DB).
    pub identity_directory: Arc<IdentityDirectory>,
    /// Optional tenant-isolating operational store. Required when `tenant_mode` is on.
    /// In-memory for tests; Postgres hub adapter for durable multi-tenant recovery.
    pub tenant_store: Option<Arc<dyn TenantOperationalStore>>,
    /// When true, expose unauthenticated `GET /metrics` OpenMetrics (#137).
    /// Intended for loopback scrapes only (server already binds loopback).
    pub metrics_enabled: bool,
    /// Explicitly enabled, development-only authenticated fixture surface.
    pub development_fixtures: Option<DevelopmentFixtureConfig>,
}

#[derive(Clone, Debug)]
pub struct DevelopmentFixtureConfig {
    pub allowed_principals: std::collections::BTreeSet<String>,
}

impl ServerConfig {
    /// Community server defaults: SQLite store profile and community auth.
    pub fn community(
        management_token: impl Into<String>,
        runtime_assignments: HashMap<String, String>,
    ) -> Self {
        Self {
            management_token: management_token.into(),
            runtime_assignments,
            requirements: RuntimeRequirements::community(),
            capabilities: community_sqlite_profile(community_auth_capabilities()),
            auth_host: AuthHostConfig::community(),
            enterprise_auth: None,
            federation: FederationConfig::community(),
            identity_directory: Arc::new(IdentityDirectory::new()),
            tenant_store: None,
            metrics_enabled: false,
            development_fixtures: None,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.management_token.is_empty(),
            "management token must not be empty"
        );
        anyhow::ensure!(
            self.runtime_assignments
                .iter()
                .all(|(token, environment)| !token.is_empty() && !environment.is_empty()),
            "runtime tokens and environment assignments must not be empty"
        );
        anyhow::ensure!(
            !self
                .runtime_assignments
                .contains_key(&self.management_token),
            "management and runtime credentials must be distinct"
        );
        validate_runtime_capabilities(&self.capabilities, &self.requirements)
            .map_err(|error| anyhow::anyhow!("runtime capability negotiation failed: {error}"))?;
        if self.requirements.tenant_mode && self.tenant_store.is_none() {
            anyhow::bail!(
                "tenant mode requires a tenant-isolating operational store adapter (tenant_store)"
            );
        }
        if let Some(fixtures) = &self.development_fixtures {
            anyhow::ensure!(
                self.requirements.tenant_mode
                    && self.requirements.require_enterprise_authentication
                    && self.enterprise_auth.is_some(),
                "development fixtures require tenant mode and enterprise authentication"
            );
            anyhow::ensure!(
                !fixtures.allowed_principals.is_empty()
                    && fixtures
                        .allowed_principals
                        .iter()
                        .all(|principal| !principal.trim().is_empty()),
                "development fixtures require at least one non-empty allowed principal"
            );
        }
        // Compose AuthStack at validation time so missing required enterprise
        // extensions fail before the router accepts traffic.
        let _ = self.build_auth_stack()?;
        Ok(())
    }

    fn resolved_auth_host(&self) -> AuthHostConfig {
        let mut host = self.auth_host.clone();
        if self.requirements.require_enterprise_authentication
            && host.required_extension_id.is_none()
        {
            host.required_extension_id = Some(
                self.enterprise_auth
                    .as_ref()
                    .map(|extension| extension.extension_id().to_string())
                    .unwrap_or_else(|| "auth.enterprise".into()),
            );
        }
        host
    }

    fn build_auth_stack(&self) -> anyhow::Result<AuthStack> {
        let community = CommunityTokenAuthenticator::new(
            "auth.community",
            [(
                self.management_token.clone(),
                PrincipalIdentity {
                    id: "management".into(),
                    kind: PrincipalKind::Management,
                },
            )],
        )
        .map_err(|error| anyhow::anyhow!("community management authenticator: {error}"))?;
        let enterprise = self.enterprise_auth.clone().map(|extension| {
            if self.federation.required_enterprise_issuer.is_some() {
                Arc::new(FederatingAuthExtension::new(
                    extension,
                    self.identity_directory.clone(),
                    self.federation.clone(),
                )) as Arc<dyn EnterpriseAuthExtension>
            } else {
                extension
            }
        });
        build_auth_stack(&self.resolved_auth_host(), enterprise, Arc::new(community))
            .map_err(|error| anyhow::anyhow!("auth stack composition failed: {error}"))
    }
}

struct AppState {
    config: ServerConfig,
    reconciler: Arc<dyn ReconcilePort>,
    store: Arc<dyn OperationalStore>,
    tenant_store: Option<Arc<dyn TenantOperationalStore>>,
    management: Arc<ManagementOperations>,
    runtime_delivery: Arc<RuntimeDeliveryOperations>,
}

#[derive(Debug, Serialize)]
struct ServiceStatus {
    status: &'static str,
    profile: String,
    capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn router(
    config: ServerConfig,
    reconciler: Arc<dyn ReconcilePort>,
    store: Arc<dyn OperationalStore>,
) -> anyhow::Result<Router> {
    config.validate()?;
    let auth = config.build_auth_stack()?;
    let metrics_enabled = config.metrics_enabled;
    let development_fixtures_enabled = config.development_fixtures.is_some();
    let runtime_delivery = Arc::new(RuntimeDeliveryOperations::new(
        config.runtime_assignments.clone(),
        reconciler.clone(),
        store.clone(),
    ));
    let management = Arc::new(ManagementOperations::new(
        auth,
        config.requirements.tenant_mode,
        reconciler.clone(),
        store.clone(),
        config.tenant_store.clone(),
    ));
    let mut router = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/reconcile", post(reconcile))
        .route("/v1/fleet/status", get(fleet_status))
        .route("/v1/environments", get(list_environments))
        .route("/v1/environments/{environment}", get(inspect_environment))
        .route(
            "/v1/environments/{environment}/status",
            get(environment_status),
        )
        .route(
            "/v1/runtime/environments/{environment}/work",
            get(runtime_work),
        )
        .route(
            "/v1/runtime/environments/{environment}/complete",
            post(runtime_complete),
        )
        .route(
            "/v1/runtime/environments/{environment}/heartbeat",
            post(runtime_heartbeat),
        )
        .route(
            "/v1/runtime/environments/{environment}/inventory",
            post(runtime_inventory),
        );
    if metrics_enabled {
        router = router.route("/metrics", get(openmetrics));
    }
    if development_fixtures_enabled {
        router = router
            .route(
                "/v1/development/fixtures/import",
                post(import_development_fixture),
            )
            .route(
                "/v1/development/fixtures/{fixture_id}",
                axum::routing::delete(reset_development_fixture),
            );
    }
    Ok(router.with_state(Arc::new(AppState {
        tenant_store: config.tenant_store.clone(),
        management,
        config,
        reconciler,
        store,
        runtime_delivery,
    })))
}

fn authorize_development_fixture(
    state: &AppState,
    context: &AuthenticatedRequestContext,
) -> Result<(), Box<Response>> {
    let Some(config) = &state.config.development_fixtures else {
        return Err(Box::new(error_response(StatusCode::NOT_FOUND, "not found")));
    };
    if context.tenant().is_none()
        || !matches!(
            context.principal.kind,
            PrincipalKind::Service | PrincipalKind::Management
        )
        || !config.allowed_principals.contains(context.principal_id())
    {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            NON_DISCLOSING_DENY,
        )));
    }
    Ok(())
}

async fn import_development_fixture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(fixture): Json<DevelopmentFixture>,
) -> Response {
    let context = match authenticate_management(&state, &headers) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Err(response) = require_tenant_scope(&state, &context, None).await {
        return *response;
    }
    if let Err(response) = authorize_development_fixture(&state, &context) {
        return *response;
    }
    let prepared = match fixture.prepare() {
        Ok(prepared) => prepared,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid fixture document"),
    };
    let Some(store) = state.tenant_store.clone() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "fixture store unavailable");
    };
    let result = match run_blocking_tenant_store(move || {
        store.import_development_fixture_for(&context, &prepared)
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(map) => (StatusCode::OK, Json(map)).into_response(),
        Err(crate::tenant_isolation::IsolationError::NotFound)
        | Err(crate::tenant_isolation::IsolationError::Unauthenticated) => {
            error_response(StatusCode::NOT_FOUND, NON_DISCLOSING_DENY)
        }
        Err(error) => {
            eprintln!("development fixture import failed: {error}");
            error_response(StatusCode::CONFLICT, "fixture import conflict")
        }
    }
}

async fn reset_development_fixture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(fixture_id): Path<String>,
) -> Response {
    let context = match authenticate_management(&state, &headers) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Err(response) = require_tenant_scope(&state, &context, None).await {
        return *response;
    }
    if let Err(response) = authorize_development_fixture(&state, &context) {
        return *response;
    }
    let Some(store) = state.tenant_store.clone() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "fixture store unavailable");
    };
    let result = match run_blocking_tenant_store(move || {
        store.reset_development_fixture_for(&context, &fixture_id)
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(error) => {
            eprintln!("development fixture reset failed: {error}");
            error_response(StatusCode::CONFLICT, "fixture reset conflict")
        }
    }
}

/// When tenant mode is enabled, require authenticated tenant membership and
/// optionally verify an environment id is visible to that tenant.
async fn require_tenant_scope(
    state: &AppState,
    context: &AuthenticatedRequestContext,
    environment: Option<&str>,
) -> Result<(), Box<Response>> {
    if !state.config.requirements.tenant_mode {
        return Ok(());
    }
    let Some(tenant_store) = state.tenant_store.as_ref() else {
        return Err(Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant mode is enabled but no tenant store is configured",
        )));
    };
    if context.tenant().is_none() {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "unauthenticated",
        )));
    }
    if let Some(environment) = environment {
        let tenant_store = tenant_store.clone();
        let context = context.clone();
        let environment = environment.to_string();
        let result = run_blocking_tenant_store(move || {
            tenant_store.get_environment_for(&context, &environment)
        })
        .await
        .map_err(Box::new)?;
        match result {
            Ok(_) => Ok(()),
            Err(crate::tenant_isolation::IsolationError::NotFound)
            | Err(crate::tenant_isolation::IsolationError::Unauthenticated) => Err(Box::new(
                error_response(StatusCode::NOT_FOUND, NON_DISCLOSING_DENY),
            )),
            Err(error) => Err(Box::new(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                error.public_message(),
            ))),
        }
    } else {
        let _ = tenant_store;
        Ok(())
    }
}

async fn run_blocking_tenant_store<T, F>(operation: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            eprintln!("tenant store blocking task failed: {error}");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "tenant store unavailable")
        })
}

/// Authenticate a management HTTP request through the composed [`AuthStack`].
///
/// Caller-selected tenant headers are intentionally ignored: only the
/// authenticator may attach tenant context after credential verification.
fn authenticate_management(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedRequestContext, Box<Response>> {
    let credential =
        management_credential(headers).map_err(|error| Box::new(management_error(error)))?;
    state
        .management
        .authenticate(&credential)
        .map_err(|error| Box::new(management_error(error)))
}

fn management_credential(headers: &HeaderMap) -> Result<CredentialMaterial, ManagementError> {
    // Caller-selected tenant metadata cannot select federation/tenant authority.
    if reject_caller_selected_tenant(
        headers
            .get("x-tenkai-tenant")
            .or_else(|| headers.get("x-tenant-id"))
            .and_then(|value| value.to_str().ok()),
    )
    .is_err()
    {
        return Err(ManagementError::Forbidden(
            "caller metadata cannot select tenant authority".into(),
        ));
    }
    let bearer_token = bearer(headers).map(str::to_string);
    let assertion = headers
        .get("x-tenkai-assertion")
        .and_then(|value| value.to_str().ok())
        .map(|raw| raw.as_bytes().to_vec())
        .filter(|bytes| !bytes.is_empty());
    if bearer_token.is_none() && assertion.is_none() {
        return Err(ManagementError::Unauthorized("missing bearer token".into()));
    }
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    Ok(CredentialMaterial {
        request_id,
        bearer_token,
        assertion,
    })
}

async fn fleet_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let credential = match management_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return management_error(error),
    };
    match state.management.fleet_status(&credential).await {
        Ok(report) => Json(report).into_response(),
        Err(error) => management_error(error),
    }
}

async fn list_environments(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let credential = match management_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return management_error(error),
    };
    match state.management.list_environments(&credential).await {
        Ok(entries) => Json(entries).into_response(),
        Err(error) => management_error(error),
    }
}

async fn inspect_environment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match management_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return management_error(error),
    };
    match state
        .management
        .inspect_environment(&credential, &environment)
        .await
    {
        Ok(report) => Json(report).into_response(),
        Err(error) => management_error(error),
    }
}

async fn environment_status(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match management_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return management_error(error),
    };
    match state
        .management
        .environment_status(&credential, &environment)
        .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(error) => management_error(error),
    }
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
async fn openmetrics(State(state): State<Arc<AppState>>) -> Response {
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

async fn health(State(state): State<Arc<AppState>>) -> Json<ServiceStatus> {
    Json(service_status("ok", &state.config))
}

async fn ready(State(state): State<Arc<AppState>>) -> Response {
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

async fn reconcile(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let credential = match management_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return management_error(error),
    };
    match state.management.reconcile(&credential).await {
        Ok(report) => Json(report).into_response(),
        Err(error) => management_error(error),
    }
}

async fn runtime_work(
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

async fn runtime_complete(
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

async fn runtime_heartbeat(
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
async fn runtime_inventory(
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

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn error_response(status: StatusCode, error: impl Into<String>) -> Response {
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

fn management_error(error: ManagementError) -> Response {
    match error {
        ManagementError::Unauthorized(message) => error_response(StatusCode::UNAUTHORIZED, message),
        ManagementError::Forbidden(message) => error_response(StatusCode::FORBIDDEN, message),
        ManagementError::NotFound(message) => error_response(StatusCode::NOT_FOUND, message),
        ManagementError::Unavailable(message) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, message)
        }
        ManagementError::Internal(message) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

#[derive(Clone)]
pub struct RemoteClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl RemoteClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> anyhow::Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        anyhow::ensure!(!base_url.is_empty(), "server URL must not be empty");
        let parsed = url::Url::parse(&base_url)?;
        let secure = parsed.scheme() == "https";
        let loopback_http = parsed.scheme() == "http"
            && parsed.host().is_some_and(|host| match host {
                url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
                url::Host::Ipv4(address) => address.is_loopback(),
                url::Host::Ipv6(address) => address.is_loopback(),
            });
        anyhow::ensure!(
            secure || loopback_http,
            "remote management tokens require HTTPS or an HTTP loopback URL"
        );
        let token = token.into();
        anyhow::ensure!(!token.is_empty(), "management token must not be empty");
        Ok(Self {
            base_url,
            token,
            http: reqwest::Client::new(),
        })
    }

    pub async fn reconcile(&self) -> anyhow::Result<TickReport> {
        self.request_json(reqwest::Method::POST, "/v1/reconcile")
            .await
    }

    pub async fn list_environments(
        &self,
    ) -> anyhow::Result<Vec<crate::plan::EnvironmentListEntry>> {
        self.request_json(reqwest::Method::GET, "/v1/environments")
            .await
    }

    pub async fn inspect_environment(
        &self,
        environment: &str,
    ) -> anyhow::Result<crate::plan::EnvironmentInspectReport> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/v1/environments/{environment}"),
        )
        .await
    }

    pub async fn environment_status(
        &self,
        environment: &str,
    ) -> anyhow::Result<Vec<crate::plan::StatusRow>> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/v1/environments/{environment}/status"),
        )
        .await
    }

    pub async fn fleet_status(&self) -> anyhow::Result<crate::plan::FleetStatusReport> {
        self.request_json(reqwest::Method::GET, "/v1/fleet/status")
            .await
    }

    async fn request_json<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> anyhow::Result<T> {
        let response = self
            .http
            .request(method, format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            anyhow::bail!("remote server returned {status}: {detail}");
        }
        Ok(response.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn tenant_store_work_can_run_a_synchronous_runtime() {
        let value = run_blocking_tenant_store(|| {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async { 42 })
        })
        .await
        .unwrap();

        assert_eq!(value, 42);
    }

    struct FixedReconciler;

    impl ReconcilePort for FixedReconciler {
        fn reconcile(&self) -> ReconcileFuture<'_> {
            Box::pin(async {
                Ok(TickReport {
                    environments: vec![crate::reconciler::EnvironmentResult {
                        environment: "prod".into(),
                        status: crate::reconciler::EnvironmentStatus::Current,
                    }],
                })
            })
        }

        fn reconcile_environments(&self, environments: Vec<String>) -> ReconcileFuture<'_> {
            Box::pin(async move {
                Ok(TickReport {
                    environments: environments
                        .into_iter()
                        .map(|environment| crate::reconciler::EnvironmentResult {
                            environment,
                            status: crate::reconciler::EnvironmentStatus::Current,
                        })
                        .collect(),
                })
            })
        }

        fn pending_work(&self, environment: String) -> WorkFuture<'_> {
            Box::pin(async move {
                Ok(Some(crate::plan::Plan {
                    format_version: 1,
                    id: "plan-1".into(),
                    content_id: "sha256:plan".into(),
                    environment,
                    created_at: 1,
                    inputs: Vec::new(),
                    steps: Vec::new(),
                    state: crate::plan::PlanState::Computed,
                    gates_skipped: None,
                    status_detail: String::new(),
                    maintenance_blocked: false,
                    prior_warnings: Vec::new(),
                    recalled_recovery_reason: None,
                }))
            })
        }

        fn check_health(&self) -> HealthFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn complete_work(
            &self,
            _environment: String,
            _completion: crate::runtime_delivery::RuntimeCompletion,
        ) -> CompletionFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn validate_completion(
            &self,
            _environment: String,
            _completion: crate::runtime_delivery::RuntimeCompletion,
        ) -> CompletionFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn list_environments(&self) -> ListEnvFuture<'_> {
            Box::pin(async {
                Ok(vec![crate::plan::EnvironmentListEntry {
                    name: "prod".into(),
                    id: "tenkai:env:prod".into(),
                    description: "fixture".into(),
                    subscription_count: 0,
                    deployed_product_count: 0,
                    lease_held: false,
                }])
            })
        }

        fn inspect_environment(&self, environment: String) -> InspectEnvFuture<'_> {
            Box::pin(async move {
                Ok(crate::plan::EnvironmentInspectReport {
                    name: environment,
                    id: "tenkai:env:prod".into(),
                    description: "fixture".into(),
                    subscriptions: Vec::new(),
                    facts: Default::default(),
                    overlays: Default::default(),
                    lease: crate::apply::EnvironmentLeaseInspect {
                        held: false,
                        owner: None,
                        generation: None,
                        expires_at_ms: None,
                        status: "absent".into(),
                    },
                    latest_plan: None,
                    terminal_outcomes: Vec::new(),
                    execution_note: "fixture".into(),
                    observed_type_digest: None,
                    observed_runtime_digest: None,
                    module_activations: Vec::new(),
                })
            })
        }

        fn environment_status(&self, _environment: String) -> StatusEnvFuture<'_> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn fleet_status(&self) -> FleetStatusFuture<'_> {
            Box::pin(async {
                Ok(crate::plan::FleetStatusReport {
                    environments: vec![crate::plan::FleetEnvironmentRow {
                        name: "prod".into(),
                        id: "tenkai:env:prod".into(),
                        description: "fixture".into(),
                        subscription_count: 0,
                        products_current: 0,
                        products_behind: 0,
                        products_missing: 0,
                        unhealthy: false,
                        health_summary: "n/a".into(),
                        lease_held: false,
                        latest_plan_state: None,
                        posture: "empty".into(),
                    }],
                    environment_count: 1,
                    environments_current: 0,
                    environments_behind: 0,
                    environments_unhealthy: 0,
                    environments_empty: 1,
                })
            })
        }

        fn fleet_status_without_outcome_export(&self) -> FleetStatusFuture<'_> {
            self.fleet_status()
        }

        fn apply_inventory_facts(
            &self,
            _environment: String,
            facts: std::collections::BTreeMap<String, String>,
        ) -> InventoryFuture<'_> {
            Box::pin(async move {
                // Fixture: accept admitted keys only (mirror plan validation lightly).
                for key in facts.keys() {
                    if !crate::plan::ENVIRONMENT_FACT_KEYS.contains(&key.as_str()) {
                        anyhow::bail!("unknown environment fact {key:?}");
                    }
                }
                let mut applied: Vec<String> = facts.into_keys().collect();
                applied.sort();
                Ok(applied)
            })
        }

        fn diagnostics_snapshot(&self) -> crate::reconciler::ReconcileDiagnostics {
            crate::reconciler::ReconcileDiagnostics {
                ticks_total: 1,
                ticks_failed: 0,
                last_outcome: "ok".into(),
                last_environments_total: 1,
                last_environments_failed: 0,
                environments_busy_total: 0,
            }
        }
    }

    fn app() -> (Router, Arc<crate::storage::SqliteStore>) {
        let store = Arc::new(crate::storage::SqliteStore::open_in_memory().unwrap());
        store
            .put_environment(&crate::storage::EnvironmentRecord {
                id: "prod".into(),
                revision: 0,
                configuration_json: "{}".into(),
            })
            .unwrap();
        let app = router(
            ServerConfig::community(
                "management-secret",
                HashMap::from([("runtime-secret".into(), "prod".into())]),
            ),
            Arc::new(FixedReconciler),
            store.clone(),
        )
        .unwrap();
        (app, store)
    }

    #[tokio::test]
    async fn openmetrics_enabled_exposes_series_without_secrets() {
        let store = Arc::new(crate::storage::SqliteStore::open_in_memory().unwrap());
        let mut config = ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "prod".into())]),
        );
        config.metrics_enabled = true;
        let app = router(config, Arc::new(FixedReconciler), store).unwrap();
        let response = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("tenkai_reconcile_ticks_total"));
        assert!(body.contains("tenkai_reconcile_ticks_failed_total"));
        assert!(!crate::metrics::body_leaks_secret(
            &body,
            &["management-secret", "runtime-secret", "Bearer "]
        ));
        assert!(!body.contains("tenant_id"));
    }

    #[tokio::test]
    async fn openmetrics_disabled_by_default() {
        let (app, _store) = app();
        let response = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn runtime_inventory_accepts_admitted_facts_and_rejects_foreign_env() {
        let (app, _store) = app();
        let body = serde_json::json!({
            "facts": { "architecture": "arm64", "memory_gib": "32" },
            "source": "runtime-probe"
        });
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/runtime/environments/prod/inventory")
                    .header("authorization", "Bearer runtime-secret")
                    .header("x-tenkai-runtime-instance", "rt-1")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: RuntimeInventoryResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report.environment, "prod");
        assert_eq!(report.source, "runtime-probe");
        assert_eq!(
            report.applied,
            vec!["architecture".to_string(), "memory_gib".to_string()]
        );

        let forbidden = app
            .clone()
            .oneshot(
                Request::post("/v1/runtime/environments/other/inventory")
                    .header("authorization", "Bearer runtime-secret")
                    .header("x-tenkai-runtime-instance", "rt-1")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let bad_key = serde_json::json!({
            "facts": { "token": "x" },
            "source": "runtime-probe"
        });
        let rejected = app
            .oneshot(
                Request::post("/v1/runtime/environments/prod/inventory")
                    .header("authorization", "Bearer runtime-secret")
                    .header("x-tenkai-runtime-instance", "rt-1")
                    .header("content-type", "application/json")
                    .body(Body::from(bad_key.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn embedded_and_http_reconciliation_share_the_same_contract() {
        let embedded = FixedReconciler.reconcile().await.unwrap();
        let (app, store) = app();
        let response = app
            .oneshot(
                Request::post("/v1/reconcile")
                    .header("authorization", "Bearer management-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let remote: TickReport = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(remote, embedded);
        assert_eq!(store.audit_events().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn runtime_credentials_are_environment_scoped() {
        let (app, _) = app();
        let denied = app
            .clone()
            .oneshot(
                Request::get("/v1/runtime/environments/staging/work")
                    .header("authorization", "Bearer runtime-secret")
                    .header("x-tenkai-runtime-instance", "instance-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let allowed = app
            .clone()
            .oneshot(
                Request::get("/v1/runtime/environments/prod/work")
                    .header("authorization", "Bearer runtime-secret")
                    .header("x-tenkai-runtime-instance", "instance-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(allowed.into_body(), usize::MAX)
            .await
            .unwrap();
        let first: RuntimeWork = serde_json::from_slice(&bytes).unwrap();
        assert!(first.plan.is_some());
        let generation = first.claim.unwrap().generation;
        assert_eq!(generation, 1);

        let overlapping = app
            .clone()
            .oneshot(
                Request::get("/v1/runtime/environments/prod/work")
                    .header("authorization", "Bearer runtime-secret")
                    .header("x-tenkai-runtime-instance", "instance-b")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(overlapping.into_body(), usize::MAX)
            .await
            .unwrap();
        let overlapping: RuntimeWork = serde_json::from_slice(&bytes).unwrap();
        assert!(overlapping.plan.is_none());
        assert!(overlapping.claim.is_none());

        let completed = app
            .clone()
            .oneshot(
                Request::post("/v1/runtime/environments/prod/complete")
                    .header("authorization", "Bearer runtime-secret")
                    .header("x-tenkai-runtime-instance", "instance-a")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&crate::runtime_delivery::RuntimeCompletion {
                            plan_id: "plan-1".into(),
                            generation,
                            succeeded: true,
                            detail: "deployed".into(),
                            receipts: Vec::new(),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(completed.status(), StatusCode::NO_CONTENT);

        let repeated = app
            .oneshot(
                Request::get("/v1/runtime/environments/prod/work")
                    .header("authorization", "Bearer runtime-secret")
                    .header("x-tenkai-runtime-instance", "instance-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(repeated.into_body(), usize::MAX)
            .await
            .unwrap();
        let second: RuntimeWork = serde_json::from_slice(&bytes).unwrap();
        assert!(second.plan.is_some());
        assert!(second.claim.unwrap().completion_json.is_some());
    }

    #[test]
    fn rejects_credential_reuse_across_trust_scopes() {
        let config =
            ServerConfig::community("same", HashMap::from([("same".into(), "prod".into())]));
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_tenant_mode_without_tenant_isolation_capability() {
        let mut config = ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "prod".into())]),
        );
        config.requirements.tenant_mode = true;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("runtime capability negotiation failed"));
        assert!(error.contains("tenant_isolation"));
    }

    #[test]
    fn rejects_tenant_mode_without_tenant_store_adapter() {
        let mut config = ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "prod".into())]),
        );
        config.requirements.tenant_mode = true;
        config.capabilities = crate::runtime_capabilities::ProvidedCapabilities::assemble(
            "enterprise-tenant-memory",
            [
                crate::tenant_store::tenant_memory_store_capabilities(),
                community_auth_capabilities(),
            ],
        );
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("tenant-isolating operational store"),
            "{error}"
        );
    }

    /// Enterprise extension that maps a JSON assertion `{"tenant":"...","principal":"..."}`
    /// into authenticated tenant context for router isolation tests.
    struct TenantAssertionExtension;

    impl EnterpriseAuthExtension for TenantAssertionExtension {
        fn extension_id(&self) -> &str {
            "auth.enterprise"
        }
        fn contract_version(&self) -> u32 {
            crate::auth_context::AUTH_CONTEXT_CONTRACT_VERSION
        }
        fn expected_audience(&self) -> &str {
            "tenkai-server"
        }
        fn authenticate(
            &self,
            credential: &CredentialMaterial,
            authority: &crate::auth_context::TenantDerivationAuthority,
        ) -> Result<AuthenticatedRequestContext, crate::auth_context::AuthError> {
            let raw = credential.assertion.as_ref().ok_or_else(|| {
                crate::auth_context::AuthError::InvalidCredential("assertion required".into())
            })?;
            let value: serde_json::Value = serde_json::from_slice(raw).map_err(|error| {
                crate::auth_context::AuthError::InvalidCredential(error.to_string())
            })?;
            let tenant = value
                .get("tenant")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    crate::auth_context::AuthError::InvalidCredential(
                        "tenant claim required".into(),
                    )
                })?;
            let principal = value
                .get("principal")
                .and_then(|v| v.as_str())
                .unwrap_or("enterprise-user");
            let kind = match value.get("kind").and_then(|value| value.as_str()) {
                Some("service") => PrincipalKind::Service,
                Some("management") => PrincipalKind::Management,
                _ => PrincipalKind::Human,
            };
            let mut builder = crate::auth_context::AuthenticatedRequestContextBuilder::new(
                credential.request_id.clone(),
                PrincipalIdentity {
                    id: principal.into(),
                    kind,
                },
                self.extension_id(),
            );
            if let Some(capabilities) = value.get("capabilities").and_then(|value| value.as_array())
            {
                let mut parsed = std::collections::BTreeSet::new();
                for capability in capabilities {
                    match capability.as_str() {
                        Some("read") => {
                            parsed.insert(crate::auth_context::DeliveryCapability::Read);
                        }
                        Some("management") => {
                            parsed.insert(crate::auth_context::DeliveryCapability::Management);
                        }
                        _ => {
                            return Err(crate::auth_context::AuthError::Unauthorized(
                                "unsupported capability claim".into(),
                            ));
                        }
                    }
                }
                builder = builder.with_delivery_capabilities(parsed);
            }
            builder.with_tenant(tenant, authority)?.build()
        }
    }

    #[tokio::test]
    async fn tenant_mode_management_apis_isolate_environments() {
        use crate::runtime_capabilities::enterprise_auth_capabilities;
        use crate::storage::EnvironmentRecord;
        use crate::tenant_store::tenant_memory_store_capabilities;

        let tenant_store = Arc::new(crate::tenant_store::InMemoryTenantOperationalStore::new());
        let mut config = ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "prod".into())]),
        );
        config.requirements.tenant_mode = true;
        config.requirements.require_enterprise_authentication = true;
        config.capabilities = crate::runtime_capabilities::ProvidedCapabilities::assemble(
            "enterprise-tenant-memory",
            [
                tenant_memory_store_capabilities(),
                enterprise_auth_capabilities(),
            ],
        );
        config.auth_host = AuthHostConfig {
            required_extension_id: Some("auth.enterprise".into()),
            expected_contract_version: crate::auth_context::AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some("tenkai-server".into()),
        };
        // No federation issuer: wrap not applied; pure enterprise extension.
        config.enterprise_auth = Some(Arc::new(TenantAssertionExtension));
        config.tenant_store = Some(tenant_store.clone());

        // Seed partitions via authenticated contexts.
        let authority = crate::auth_context::TenantDerivationAuthority::new("auth.enterprise");
        let ctx_a = TenantAssertionExtension
            .authenticate(
                &CredentialMaterial {
                    request_id: "seed-a".into(),
                    bearer_token: None,
                    assertion: Some(br#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#.to_vec()),
                },
                &authority,
            )
            .unwrap();
        let ctx_b = TenantAssertionExtension
            .authenticate(
                &CredentialMaterial {
                    request_id: "seed-b".into(),
                    bearer_token: None,
                    assertion: Some(br#"{"tenant":"tenant-b","principal":"user-b","capabilities":["read","management"]}"#.to_vec()),
                },
                &authority,
            )
            .unwrap();
        tenant_store
            .put_environment_for(
                &ctx_a,
                &EnvironmentRecord {
                    id: "env-a".into(),
                    revision: 0,
                    configuration_json: "{}".into(),
                },
            )
            .unwrap();
        tenant_store
            .put_environment_for(
                &ctx_b,
                &EnvironmentRecord {
                    id: "env-b".into(),
                    revision: 0,
                    configuration_json: "{}".into(),
                },
            )
            .unwrap();

        let store = Arc::new(crate::storage::SqliteStore::open_in_memory().unwrap());
        let tenant_app = router(config, Arc::new(FixedReconciler), store).unwrap();

        let list_a = tenant_app
            .clone()
            .oneshot(
                Request::get("/v1/environments")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_a.status(), StatusCode::OK);
        let body = String::from_utf8(
            axum::body::to_bytes(list_a.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("env-a"));
        assert!(!body.contains("env-b"));
        assert!(!body.contains("tenant-b"));

        let cross = tenant_app
            .clone()
            .oneshot(
                Request::get("/v1/environments/env-b")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross.status(), StatusCode::NOT_FOUND);
        let cross_body = String::from_utf8(
            axum::body::to_bytes(cross.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(cross_body.contains(NON_DISCLOSING_DENY));
        assert!(!cross_body.contains("tenant-b"));
        assert!(!cross_body.contains("env-b"));

        // environment.status is HTTP-exposed and must use the same non-disclosing deny.
        let status_cross = tenant_app
            .clone()
            .oneshot(
                Request::get("/v1/environments/env-b/status")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status_cross.status(), StatusCode::NOT_FOUND);
        let status_body = String::from_utf8(
            axum::body::to_bytes(status_cross.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(status_body.contains(NON_DISCLOSING_DENY));
        assert!(!status_body.contains("tenant-b"));
        assert!(!status_body.contains("env-b"));

        let fleet_a = tenant_app
            .clone()
            .oneshot(
                Request::get("/v1/fleet/status")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fleet_a.status(), StatusCode::OK);
        let fleet_body = String::from_utf8(
            axum::body::to_bytes(fleet_a.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!fleet_body.contains("env-b"));
        assert!(!fleet_body.contains("tenant-b"));

        let reconcile_a = tenant_app
            .clone()
            .oneshot(
                Request::post("/v1/reconcile")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reconcile_a.status(), StatusCode::OK);
        let reconcile_body = String::from_utf8(
            axum::body::to_bytes(reconcile_a.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        // The fake global reconcile path returns `prod`; seeing only the
        // tenant-store identity proves selection used the bounded application
        // operation before any reconciler work, rather than filtering a global
        // report afterward.
        assert!(reconcile_body.contains("env-a"));
        assert!(!reconcile_body.contains("prod"));
        assert!(!reconcile_body.contains("env-b"));
        assert!(!reconcile_body.contains("tenant-b"));
        assert!(!reconcile_body.contains("management-secret"));

        // Community profile still starts without tenant mode.
        let (community_app, _) = app();
        let health = community_app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        tenant_store.set_healthy(false);
        let unavailable = tenant_app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn development_fixture_surface_is_explicit_authorized_and_tenant_scoped() {
        use crate::runtime_capabilities::enterprise_auth_capabilities;
        use crate::tenant_store::tenant_memory_store_capabilities;

        let tenant_store = Arc::new(crate::tenant_store::InMemoryTenantOperationalStore::new());
        let mut config = ServerConfig::community("management-secret", HashMap::new());
        config.requirements.tenant_mode = true;
        config.requirements.require_enterprise_authentication = true;
        config.capabilities = crate::runtime_capabilities::ProvidedCapabilities::assemble(
            "enterprise-tenant-memory",
            [
                tenant_memory_store_capabilities(),
                enterprise_auth_capabilities(),
            ],
        );
        config.auth_host = AuthHostConfig {
            required_extension_id: Some("auth.enterprise".into()),
            expected_contract_version: crate::auth_context::AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some("tenkai-server".into()),
        };
        config.enterprise_auth = Some(Arc::new(TenantAssertionExtension));
        config.tenant_store = Some(tenant_store);
        config.development_fixtures = Some(DevelopmentFixtureConfig {
            allowed_principals: std::collections::BTreeSet::from(["seed-service".into()]),
        });
        let store = Arc::new(crate::storage::SqliteStore::open_in_memory().unwrap());
        let fixture_app = router(config, Arc::new(FixedReconciler), store).unwrap();
        let fixture = serde_json::json!({
            "contract_version": 1,
            "fixture_id": "buyer-demo",
            "releases": [{
                "name": "app",
                "product": "app",
                "version": "1.0.0",
                "content_digest": "a".repeat(64)
            }, {
                "name": "worker",
                "product": "worker",
                "version": "2.0.0",
                "content_digest": "b".repeat(64)
            }],
            "channels": [{
                "name": "stable",
                "product": "app",
                "release": "app"
            }, {
                "name": "canary",
                "product": "worker",
                "release": "worker"
            }],
            "environments": [{
                "name": "prod-eu",
                "posture": "awaiting_approval",
                "description": "sanitized"
            }],
            "plans": [{
                "name": "approval",
                "environment": "prod-eu",
                "blocked_reason": "awaiting approval"
            }]
        });

        let import = fixture_app
            .clone()
            .oneshot(
                Request::post("/v1/development/fixtures/import")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-a","principal":"seed-service","kind":"service"}"#,
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&fixture).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(import.status(), StatusCode::OK);
        let body = String::from_utf8(
            axum::body::to_bytes(import.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("fx-62757965722d64656d6f-environment-prod-eu"));
        assert!(!body.contains("management-secret"));

        let repeated = fixture_app
            .clone()
            .oneshot(
                Request::post("/v1/development/fixtures/import")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-a","principal":"seed-service","kind":"service"}"#,
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&fixture).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(repeated.status(), StatusCode::OK);

        for (path, expected) in [
            (
                "/v1/environments",
                "fx-62757965722d64656d6f-environment-prod-eu",
            ),
            (
                "/v1/environments/fx-62757965722d64656d6f-environment-prod-eu",
                "\"state\":\"missing\"",
            ),
            (
                "/v1/environments/fx-62757965722d64656d6f-environment-prod-eu/status",
                "\"channel\":\"fixture-buyer-demo-canary\"",
            ),
            ("/v1/fleet/status", "\"posture\":\"behind\""),
        ] {
            let response = fixture_app
                .clone()
                .oneshot(
                    Request::get(path)
                        .header(
                            "x-tenkai-assertion",
                            r#"{"tenant":"tenant-a","principal":"seed-service","kind":"service"}"#,
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let response_body = String::from_utf8(
                axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(response_body.contains(expected), "{path}: {response_body}");
            if path == "/v1/environments/fx-62757965722d64656d6f-environment-prod-eu" {
                assert!(response_body.contains("\"state\":\"blocked\""));
                assert!(response_body.contains(
                    "\"status_detail\":\"blocked development fixture; execution is disabled\""
                ));
                assert!(response_body.contains("\"steps\":[]"));
            }
            assert!(!response_body.contains("management-secret"));
        }

        for assertion in [
            r#"{"tenant":"tenant-a","principal":"human-user"}"#,
            r#"{"tenant":"tenant-a","principal":"other-service","kind":"service"}"#,
        ] {
            let denied = fixture_app
                .clone()
                .oneshot(
                    Request::post("/v1/development/fixtures/import")
                        .header("x-tenkai-assertion", assertion)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&fixture).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        }

        let tenant_b = fixture_app
            .clone()
            .oneshot(
                Request::get("/v1/environments")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-b","principal":"seed-service","kind":"service"}"#,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let tenant_b_body = String::from_utf8(
            axum::body::to_bytes(tenant_b.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!tenant_b_body.contains("prod-eu"));
        assert!(!tenant_b_body.contains("buyer-demo"));
        let tenant_b_deep_link = fixture_app
            .clone()
            .oneshot(
                Request::get("/v1/environments/fx-62757965722d64656d6f-environment-prod-eu")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-b","principal":"seed-service","kind":"service"}"#,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tenant_b_deep_link.status(), StatusCode::NOT_FOUND);
        let tenant_b_deep_link_body = String::from_utf8(
            axum::body::to_bytes(tenant_b_deep_link.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!tenant_b_deep_link_body.contains("blocked development fixture"));
        assert!(!tenant_b_deep_link_body.contains("buyer-demo"));

        let reset = fixture_app
            .oneshot(
                Request::delete("/v1/development/fixtures/buyer-demo")
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-a","principal":"seed-service","kind":"service"}"#,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reset.status(), StatusCode::OK);

        let (community_app, _) = app();
        let absent = community_app
            .oneshot(
                Request::post("/v1/development/fixtures/import")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(absent.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn http_exposed_tenant_rpcs_are_subset_of_registry() {
        use crate::tenant_isolation::{http_exposed_tenant_rpc_ids, tenant_visible_rpcs};
        let registered: std::collections::BTreeSet<_> =
            tenant_visible_rpcs().iter().map(|rpc| rpc.id).collect();
        for id in http_exposed_tenant_rpc_ids() {
            assert!(
                registered.contains(id),
                "http-exposed rpc {id} must appear in tenant_visible_rpcs()"
            );
        }
        // Catalog/plan/aggregate registry entries stay non-HTTP until routes exist.
        assert!(!http_exposed_tenant_rpc_ids().contains(&"catalog.list_products"));
        assert!(!http_exposed_tenant_rpc_ids().contains(&"plan.list"));
        assert!(!http_exposed_tenant_rpc_ids().contains(&"aggregate.audit_list"));
    }

    #[test]
    fn rejects_multi_replica_without_shared_replica_capability() {
        let mut config = ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "prod".into())]),
        );
        config.requirements.replica_count = 2;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("shared_replica_state"));
    }

    #[tokio::test]
    async fn health_and_ready_advertise_capability_names() {
        let (app, _) = app();
        for path in ["/healthz", "/readyz"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(body.contains("community-sqlite"));
            assert!(body.contains("operational_store_migration"));
            assert!(!body.contains("management-secret"));
            assert!(!body.contains("runtime-secret"));
            assert!(!body.contains("tenant-a"));
        }
    }

    #[tokio::test]
    async fn fleet_status_requires_auth_and_returns_report() {
        let (app, _) = app();
        let denied = app
            .clone()
            .oneshot(
                Request::get("/v1/fleet/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let allowed = app
            .oneshot(
                Request::get("/v1/fleet/status")
                    .header("authorization", "Bearer management-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(allowed.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("prod"));
        assert!(body.contains("environment_count"));
        assert!(!body.contains("management-secret"));
        assert!(!body.contains("runtime-secret"));
    }

    #[tokio::test]
    async fn management_env_list_requires_auth_and_returns_rows() {
        let (app, _) = app();
        let denied = app
            .clone()
            .oneshot(
                Request::get("/v1/environments")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let bad = app
            .clone()
            .oneshot(
                Request::get("/v1/environments")
                    .header("authorization", "Bearer wrong-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::FORBIDDEN);

        let allowed = app
            .oneshot(
                Request::get("/v1/environments")
                    .header("authorization", "Bearer management-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(allowed.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("prod"));
        assert!(!body.contains("management-secret"));
        assert!(!body.contains("runtime-secret"));
    }

    #[test]
    fn enterprise_auth_required_fails_closed_without_extension() {
        let mut config = ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "prod".into())]),
        );
        config.requirements.require_enterprise_authentication = true;
        config.capabilities =
            community_sqlite_profile(crate::runtime_capabilities::enterprise_auth_capabilities());
        config.auth_host.required_extension_id = Some("auth.enterprise".into());
        // Capability claim is present, but no extension is wired — AuthStack
        // composition must still fail before accepting traffic.
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("auth stack composition failed")
                || error.contains("required auth extension"),
            "{error}"
        );
        assert!(!error.contains("management-secret"));
    }

    #[tokio::test]
    async fn forged_tenant_header_does_not_select_authority() {
        let (app, store) = app();
        // Caller-selected tenant headers are rejected; they cannot select authority.
        let denied = app
            .clone()
            .oneshot(
                Request::post("/v1/reconcile")
                    .header("authorization", "Bearer management-secret")
                    .header("x-tenkai-tenant", "forged-tenant")
                    .header("x-tenant-id", "forged-tenant")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(
                Request::post("/v1/reconcile")
                    .header("authorization", "Bearer management-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let events = store.audit_events().unwrap();
        let encoded = serde_json::to_string(&events).unwrap();
        assert!(encoded.contains("management"));
        assert!(!encoded.contains("forged-tenant"));
        assert!(!encoded.contains("management-secret"));
    }

    #[test]
    fn remote_client_requires_tls_except_on_loopback() {
        assert!(RemoteClient::new("https://tenkai.example.test", "secret").is_ok());
        assert!(RemoteClient::new("http://127.0.0.1:8080", "secret").is_ok());
        assert!(RemoteClient::new("http://[::1]:8080", "secret").is_ok());
        assert!(RemoteClient::new("http://tenkai.example.test", "secret").is_err());
    }
}
