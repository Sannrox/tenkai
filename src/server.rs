//! Authenticated network host for the shared Tenkai application core.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth_context::{
    AuthHostConfig, AuthMode, AuthStack, AuthenticatedRequestContext, CommunityTokenAuthenticator,
    CredentialMaterial, EnterpriseAuthExtension, PrincipalIdentity, PrincipalKind,
    build_auth_stack,
};
use crate::development_fixtures::DevelopmentFixture;
use crate::federated_identity::{
    FederatingAuthExtension, FederationConfig, IdentityDirectory, reject_caller_selected_tenant,
};
use crate::reconciler::{Reconciler, TickReport};
use crate::runtime_capabilities::{
    ProvidedCapabilities, RuntimeRequirements, community_auth_capabilities,
    community_sqlite_profile, validate_runtime_capabilities,
};
use crate::storage::{AuditRecord, OperationalStore};
use crate::tenant_isolation::NON_DISCLOSING_DENY;
use crate::tenant_store::TenantOperationalStore;

pub type ReconcileFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<TickReport>> + Send + 'a>>;

/// Transport-independent application operation used by embedded and remote hosts.
pub trait ReconcilePort: Send + Sync {
    fn reconcile(&self) -> ReconcileFuture<'_>;
    /// Reconcile only environments selected by a verified host authority.
    ///
    /// The fail-closed default preserves compatibility for community-only
    /// implementers without ever substituting global reconciliation in tenant
    /// mode.
    fn reconcile_environments(&self, _environments: Vec<String>) -> ReconcileFuture<'_> {
        Box::pin(async {
            anyhow::bail!("tenant-bounded reconciliation is not supported by this host")
        })
    }
    fn pending_work(&self, environment: String) -> WorkFuture<'_>;
    fn check_health(&self) -> HealthFuture<'_>;
    fn complete_work(
        &self,
        environment: String,
        completion: crate::reconciler::RuntimeCompletion,
    ) -> CompletionFuture<'_>;
    fn validate_completion(
        &self,
        environment: String,
        completion: crate::reconciler::RuntimeCompletion,
    ) -> CompletionFuture<'_>;
    fn list_environments(&self) -> ListEnvFuture<'_>;
    fn inspect_environment(&self, environment: String) -> InspectEnvFuture<'_>;
    fn environment_status(&self, environment: String) -> StatusEnvFuture<'_>;
    fn fleet_status(&self) -> FleetStatusFuture<'_>;
    /// Apply admitted inventory facts from a scoped environment runtime (#136).
    fn apply_inventory_facts(
        &self,
        environment: String,
        facts: std::collections::BTreeMap<String, String>,
    ) -> InventoryFuture<'_>;
    /// Cumulative reconcile diagnostics for OpenMetrics (#137).
    fn diagnostics_snapshot(&self) -> crate::reconciler::ReconcileDiagnostics;
}

pub type WorkFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Option<crate::plan::Plan>>> + Send + 'a>>;
pub type HealthFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
pub type CompletionFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
pub type ListEnvFuture<'a> = Pin<
    Box<dyn Future<Output = anyhow::Result<Vec<crate::plan::EnvironmentListEntry>>> + Send + 'a>,
>;
pub type InspectEnvFuture<'a> = Pin<
    Box<dyn Future<Output = anyhow::Result<crate::plan::EnvironmentInspectReport>> + Send + 'a>,
>;
pub type StatusEnvFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Vec<crate::plan::StatusRow>>> + Send + 'a>>;
pub type FleetStatusFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<crate::plan::FleetStatusReport>> + Send + 'a>>;
pub type InventoryFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Vec<String>>> + Send + 'a>>;

impl ReconcilePort for Reconciler {
    fn reconcile(&self) -> ReconcileFuture<'_> {
        Box::pin(self.run_once())
    }

    fn reconcile_environments(&self, environments: Vec<String>) -> ReconcileFuture<'_> {
        Box::pin(async move { self.run_once_for(&environments).await })
    }

    fn pending_work(&self, environment: String) -> WorkFuture<'_> {
        Box::pin(async move { self.pending_work(&environment).await })
    }

    fn check_health(&self) -> HealthFuture<'_> {
        Box::pin(self.check_provider_health())
    }

    fn complete_work(
        &self,
        environment: String,
        completion: crate::reconciler::RuntimeCompletion,
    ) -> CompletionFuture<'_> {
        Box::pin(async move { self.complete_runtime_work(&environment, &completion).await })
    }

    fn validate_completion(
        &self,
        environment: String,
        completion: crate::reconciler::RuntimeCompletion,
    ) -> CompletionFuture<'_> {
        Box::pin(async move {
            self.validate_runtime_completion(&environment, &completion)
                .await
        })
    }

    fn list_environments(&self) -> ListEnvFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::list_environments(&mut ctx).await
        })
    }

    fn inspect_environment(&self, environment: String) -> InspectEnvFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::inspect_environment(&mut ctx, &environment).await
        })
    }

    fn environment_status(&self, environment: String) -> StatusEnvFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::status(&mut ctx, &environment).await
        })
    }

    fn apply_inventory_facts(
        &self,
        environment: String,
        facts: std::collections::BTreeMap<String, String>,
    ) -> InventoryFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::apply_runtime_inventory_facts(&mut ctx, &environment, &facts).await
        })
    }

    fn diagnostics_snapshot(&self) -> crate::reconciler::ReconcileDiagnostics {
        Reconciler::diagnostics_snapshot(self)
    }

    fn fleet_status(&self) -> FleetStatusFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::fleet_status(&mut ctx).await
        })
    }
}

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
    auth: AuthStack,
    reconciler: Arc<dyn ReconcilePort>,
    store: Arc<dyn OperationalStore>,
    tenant_store: Option<Arc<dyn TenantOperationalStore>>,
}

#[derive(Debug, Serialize)]
struct ServiceStatus {
    status: &'static str,
    profile: String,
    capabilities: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeWork {
    pub environment: String,
    pub plan: Option<crate::plan::Plan>,
    pub claim: Option<crate::storage::RuntimeClaim>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeHeartbeat {
    pub plan_id: String,
    pub generation: u64,
}

/// Inventory fact report from a scoped environment runtime (#136).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeInventoryReport {
    /// Admitted fact keys only (`architecture`, `memory_gib`, …).
    pub facts: std::collections::BTreeMap<String, String>,
    /// Provenance token (e.g. `runtime-probe`); not stored as a fact key.
    #[serde(default = "default_inventory_source")]
    pub source: String,
}

fn default_inventory_source() -> String {
    crate::inventory::RUNTIME_INVENTORY_SOURCE.into()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeInventoryResponse {
    pub environment: String,
    pub source: String,
    pub applied: Vec<String>,
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
        config,
        auth,
        reconciler,
        store,
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
    // Caller-selected tenant metadata cannot select federation/tenant authority.
    if reject_caller_selected_tenant(
        headers
            .get("x-tenkai-tenant")
            .or_else(|| headers.get("x-tenant-id"))
            .and_then(|value| value.to_str().ok()),
    )
    .is_err()
    {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "caller metadata cannot select tenant authority",
        )));
    }
    let bearer_token = bearer(headers).map(str::to_string);
    let assertion = headers
        .get("x-tenkai-assertion")
        .and_then(|value| value.to_str().ok())
        .map(|raw| raw.as_bytes().to_vec())
        .filter(|bytes| !bytes.is_empty());
    if bearer_token.is_none() && assertion.is_none() {
        return Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "missing bearer token",
        )));
    }
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let credential = CredentialMaterial {
        request_id,
        bearer_token,
        assertion,
    };
    match state.auth.authenticate(&credential) {
        Ok(context) => {
            if state.auth.mode() == AuthMode::Community && context.tenant().is_some() {
                // Community stack must never surface tenant authority.
                return Err(Box::new(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "community auth stack produced tenant context",
                )));
            }
            Ok(context)
        }
        Err(crate::auth_context::AuthError::Unauthorized(_)) => Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "invalid management credential",
        ))),
        Err(crate::auth_context::AuthError::InvalidCredential(_)) => Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid management credential",
        ))),
        Err(error) => {
            eprintln!("management authentication failed: {error}");
            Err(Box::new(error_response(
                StatusCode::FORBIDDEN,
                "invalid management credential",
            )))
        }
    }
}

async fn fleet_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let context = match authenticate_management(&state, &headers) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Err(response) = require_tenant_scope(&state, &context, None).await {
        return *response;
    }
    if state.config.requirements.tenant_mode {
        let Some(tenant_store) = state.tenant_store.clone() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant mode is enabled but no tenant store is configured",
            );
        };
        // Tenant mode: only environments in the tenant partition (non-leaking).
        let projections = match run_blocking_tenant_store(move || {
            let allowed = tenant_store.list_environment_ids_for(&context)?;
            let mut fixture_rows = Vec::new();
            let mut reconciler_ids = Vec::new();
            for id in &allowed {
                match tenant_store.development_fixture_environment_for(&context, id)? {
                    Some(projection) => fixture_rows.push(projection.fleet_row()),
                    None => reconciler_ids.push(id.clone()),
                }
            }
            Ok::<_, crate::tenant_isolation::IsolationError>((fixture_rows, reconciler_ids))
        })
        .await
        {
            Ok(Ok(rows)) => rows,
            Ok(Err(error)) => {
                return error_response(StatusCode::FORBIDDEN, error.public_message());
            }
            Err(response) => return response,
        };
        let (fixture_rows, reconciler_ids) = projections;
        return match state.reconciler.fleet_status().await {
            Ok(mut report) => {
                report
                    .environments
                    .retain(|row| reconciler_ids.iter().any(|id| id == &row.name));
                report.environments.extend(fixture_rows);
                report
                    .environments
                    .sort_by(|left, right| left.name.cmp(&right.name));
                let rebuilt = crate::plan::fleet_status_from_rows(report.environments);
                Json(rebuilt).into_response()
            }
            Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")),
        };
    }
    match state.reconciler.fleet_status().await {
        Ok(report) => Json(report).into_response(),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")),
    }
}

async fn list_environments(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let context = match authenticate_management(&state, &headers) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Err(response) = require_tenant_scope(&state, &context, None).await {
        return *response;
    }
    if state.config.requirements.tenant_mode {
        let Some(tenant_store) = state.tenant_store.clone() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant mode is enabled but no tenant store is configured",
            );
        };
        let result = match run_blocking_tenant_store(move || {
            let ids = tenant_store.list_environment_ids_for(&context)?;
            let mut entries = Vec::with_capacity(ids.len());
            for name in ids {
                match tenant_store.development_fixture_environment_for(&context, &name)? {
                    Some(projection) => entries.push(projection.list_entry()),
                    None => entries.push(crate::plan::EnvironmentListEntry {
                        name: name.clone(),
                        id: format!("tenkai:env:{name}"),
                        description: String::new(),
                        subscription_count: 0,
                        deployed_product_count: 0,
                        lease_held: false,
                    }),
                }
            }
            Ok::<_, crate::tenant_isolation::IsolationError>(entries)
        })
        .await
        {
            Ok(result) => result,
            Err(response) => return response,
        };
        return match result {
            Ok(ids) => {
                // Non-leakage: foreign tenant markers never appear.
                Json(ids).into_response()
            }
            Err(error) => error_response(StatusCode::FORBIDDEN, error.public_message()),
        };
    }
    match state.reconciler.list_environments().await {
        Ok(entries) => Json(entries).into_response(),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")),
    }
}

async fn inspect_environment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Response {
    let context = match authenticate_management(&state, &headers) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Err(response) = require_tenant_scope(&state, &context, Some(&environment)).await {
        return *response;
    }
    if state.config.requirements.tenant_mode {
        let Some(tenant_store) = state.tenant_store.clone() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant mode is enabled but no tenant store is configured",
            );
        };
        let fixture_environment_id = environment.clone();
        let fixture_environment = match run_blocking_tenant_store(move || {
            tenant_store.development_fixture_environment_for(&context, &fixture_environment_id)
        })
        .await
        {
            Ok(result) => result,
            Err(response) => return response,
        };
        match fixture_environment {
            Ok(Some(projection)) => return Json(projection.inspect_report()).into_response(),
            Ok(None) => {}
            Err(error) => {
                return error_response(StatusCode::FORBIDDEN, error.public_message());
            }
        }
    }
    match state.reconciler.inspect_environment(environment).await {
        Ok(report) => Json(report).into_response(),
        Err(error) => {
            let message = format!("{error:#}");
            if message.contains("not registered") {
                // Preserve non-disclosing posture under tenant mode.
                if state.config.requirements.tenant_mode {
                    error_response(StatusCode::NOT_FOUND, NON_DISCLOSING_DENY)
                } else {
                    error_response(StatusCode::NOT_FOUND, message)
                }
            } else {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
            }
        }
    }
}

async fn environment_status(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Response {
    let context = match authenticate_management(&state, &headers) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Err(response) = require_tenant_scope(&state, &context, Some(&environment)).await {
        return *response;
    }
    if state.config.requirements.tenant_mode {
        let Some(tenant_store) = state.tenant_store.clone() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant mode is enabled but no tenant store is configured",
            );
        };
        let fixture_environment_id = environment.clone();
        let fixture_environment = match run_blocking_tenant_store(move || {
            tenant_store.development_fixture_environment_for(&context, &fixture_environment_id)
        })
        .await
        {
            Ok(result) => result,
            Err(response) => return response,
        };
        match fixture_environment {
            Ok(Some(projection)) => return Json(projection.status_rows()).into_response(),
            Ok(None) => {}
            Err(error) => {
                return error_response(StatusCode::FORBIDDEN, error.public_message());
            }
        }
    }
    match state.reconciler.environment_status(environment).await {
        Ok(rows) => Json(rows).into_response(),
        Err(error) => {
            let message = format!("{error:#}");
            if message.contains("not registered") {
                if state.config.requirements.tenant_mode {
                    error_response(StatusCode::NOT_FOUND, NON_DISCLOSING_DENY)
                } else {
                    error_response(StatusCode::NOT_FOUND, message)
                }
            } else {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
            }
        }
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
    if let Err(error) = state.store.check_health() {
        eprintln!("operational store readiness check failed: {error}");
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "service is not ready");
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
    let context = match authenticate_management(&state, &headers) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Err(response) = require_tenant_scope(&state, &context, None).await {
        return *response;
    }
    let actor = context.principal_id().to_string();
    if let Err(error) = audit(&*state.store, &actor, "reconcile.requested", "*") {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string());
    }
    let allowed_environments = if state.config.requirements.tenant_mode {
        let Some(tenant_store) = state.tenant_store.clone() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant mode is enabled but no tenant store is configured",
            );
        };
        let tenant_context = context.clone();
        match run_blocking_tenant_store(move || {
            tenant_store.list_environment_ids_for(&tenant_context)
        })
        .await
        {
            Ok(Ok(ids)) => Some(ids),
            Ok(Err(error)) => {
                return error_response(StatusCode::FORBIDDEN, error.public_message());
            }
            Err(response) => return response,
        }
    } else {
        None
    };
    let result = match allowed_environments {
        Some(environments) => state.reconciler.reconcile_environments(environments).await,
        None => state.reconciler.reconcile().await,
    };
    match result {
        Ok(report) => {
            let outcome = if report.failures() == 0 {
                "reconcile.completed"
            } else {
                "reconcile.failed"
            };
            if let Err(error) = audit(&*state.store, &actor, outcome, "*") {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string());
            }
            Json(report).into_response()
        }
        Err(error) => match audit(&*state.store, &actor, "reconcile.failed", "*") {
            Ok(()) => error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")),
            Err(audit_error) => error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "reconciliation failed: {error:#}; recording failure audit also failed: {audit_error}"
                ),
            ),
        },
    }
}

async fn runtime_work(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    let Some(assigned) = runtime_assignment(&state.config, token) else {
        return error_response(StatusCode::FORBIDDEN, "invalid runtime credential");
    };
    let Some(instance) = runtime_instance(&headers) else {
        return error_response(StatusCode::BAD_REQUEST, "missing runtime instance identity");
    };
    if assigned != environment {
        return error_response(
            StatusCode::FORBIDDEN,
            "runtime credential is not assigned to this environment",
        );
    }
    match state.reconciler.pending_work(environment.clone()).await {
        Ok(Some(plan)) => {
            let owner = runtime_owner(token, instance);
            let expires_at = crate::now_millis().saturating_add(2 * 60 * 1000);
            match state
                .store
                .claim_runtime_plan(&environment, &plan.id, &owner, expires_at)
            {
                Ok(Some(claim)) => Json(RuntimeWork {
                    environment,
                    plan: Some(plan),
                    claim: Some(claim),
                })
                .into_response(),
                Ok(None) => Json(RuntimeWork {
                    environment,
                    plan: None,
                    claim: None,
                })
                .into_response(),
                Err(error) => error_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
            }
        }
        Ok(None) => Json(RuntimeWork {
            environment,
            plan: None,
            claim: None,
        })
        .into_response(),
        Err(error) => error_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
    }
}

async fn runtime_complete(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    Json(completion): Json<crate::reconciler::RuntimeCompletion>,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    let Some(assigned) = runtime_assignment(&state.config, token) else {
        return error_response(StatusCode::FORBIDDEN, "invalid runtime credential");
    };
    let Some(instance) = runtime_instance(&headers) else {
        return error_response(StatusCode::BAD_REQUEST, "missing runtime instance identity");
    };
    if assigned != environment {
        return error_response(
            StatusCode::FORBIDDEN,
            "runtime credential is not assigned to this environment",
        );
    }
    let completion_json = match serde_json::to_string(&completion) {
        Ok(json) => json,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error.to_string()),
    };
    if let Err(error) = state
        .reconciler
        .validate_completion(environment.clone(), completion.clone())
        .await
    {
        return error_response(StatusCode::BAD_REQUEST, format!("{error:#}"));
    }
    if let Err(error) = state.store.complete_runtime_plan(
        &completion.plan_id,
        &runtime_owner(token, instance),
        completion.generation,
        &completion_json,
    ) {
        return error_response(StatusCode::CONFLICT, error.to_string());
    }
    match state
        .reconciler
        .complete_work(environment, completion)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")),
    }
}

async fn runtime_heartbeat(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    Json(heartbeat): Json<RuntimeHeartbeat>,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    let Some(assigned) = runtime_assignment(&state.config, token) else {
        return error_response(StatusCode::FORBIDDEN, "invalid runtime credential");
    };
    let Some(instance) = runtime_instance(&headers) else {
        return error_response(StatusCode::BAD_REQUEST, "missing runtime instance identity");
    };
    if assigned != environment {
        return error_response(
            StatusCode::FORBIDDEN,
            "runtime credential is not assigned to this environment",
        );
    }
    let expires_at = crate::now_millis().saturating_add(2 * 60 * 1000);
    match state.store.renew_runtime_plan(
        &heartbeat.plan_id,
        &runtime_owner(token, instance),
        heartbeat.generation,
        expires_at,
    ) {
        Ok(Some(claim)) => Json(claim).into_response(),
        Ok(_) => error_response(StatusCode::CONFLICT, "runtime claim is no longer active"),
        Err(error) => error_response(StatusCode::CONFLICT, error.to_string()),
    }
}

/// Runtime inventory report: write admitted capability facts for the assigned env (#136).
async fn runtime_inventory(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    Json(report): Json<RuntimeInventoryReport>,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    let Some(assigned) = runtime_assignment(&state.config, token) else {
        return error_response(StatusCode::FORBIDDEN, "invalid runtime credential");
    };
    let Some(_instance) = runtime_instance(&headers) else {
        return error_response(StatusCode::BAD_REQUEST, "missing runtime instance identity");
    };
    if assigned != environment {
        return error_response(
            StatusCode::FORBIDDEN,
            "runtime credential is not assigned to this environment",
        );
    }
    if report.source.trim().is_empty() || report.source.len() > 64 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "inventory source must be 1..=64 characters",
        );
    }
    // Reject secret-like source labels without treating source as a fact key.
    let source_lower = report.source.to_ascii_lowercase();
    for needle in ["bearer ", "password=", "secret=", "token="] {
        if source_lower.contains(needle) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "inventory source must not contain credential material",
            );
        }
    }
    match state
        .reconciler
        .apply_inventory_facts(environment.clone(), report.facts)
        .await
    {
        Ok(applied) => Json(RuntimeInventoryResponse {
            environment,
            source: report.source,
            applied,
        })
        .into_response(),
        Err(error) => error_response(StatusCode::BAD_REQUEST, format!("{error:#}")),
    }
}

fn runtime_owner(token: &str, instance: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(token.as_bytes());
    digest.update([0]);
    digest.update(instance.as_bytes());
    format!("runtime:{:x}", digest.finalize())
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(*left.get(index).unwrap_or(&0) ^ *right.get(index).unwrap_or(&0));
    }
    difference == 0
}

/// Match a runtime bearer against configured assignments without short-circuiting
/// on the first unequal length comparison alone.
fn runtime_assignment(config: &ServerConfig, token: &str) -> Option<String> {
    let mut matched = None;
    for (candidate, environment) in &config.runtime_assignments {
        if constant_time_eq(candidate.as_bytes(), token.as_bytes()) {
            matched = Some(environment.clone());
        }
    }
    matched
}

fn audit(
    store: &dyn OperationalStore,
    principal: &str,
    operation: &str,
    resource: &str,
) -> crate::storage::Result<()> {
    store.append_audit(&AuditRecord {
        id: uuid::Uuid::new_v4().to_string(),
        occurred_at: crate::now_millis(),
        principal: principal.into(),
        operation: operation.into(),
        resource: resource.into(),
        outcome: operation.rsplit('.').next().unwrap_or(operation).into(),
    })
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
                }))
            })
        }

        fn check_health(&self) -> HealthFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn complete_work(
            &self,
            _environment: String,
            _completion: crate::reconciler::RuntimeCompletion,
        ) -> CompletionFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn validate_completion(
            &self,
            _environment: String,
            _completion: crate::reconciler::RuntimeCompletion,
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
                    lease: crate::apply::EnvironmentLeaseInspect {
                        held: false,
                        owner: None,
                        generation: None,
                        expires_at_ms: None,
                        status: "absent".into(),
                    },
                    latest_plan: None,
                    execution_note: "fixture".into(),
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
                        serde_json::to_vec(&crate::reconciler::RuntimeCompletion {
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
            crate::auth_context::AuthenticatedRequestContextBuilder::new(
                credential.request_id.clone(),
                PrincipalIdentity {
                    id: principal.into(),
                    kind,
                },
                self.extension_id(),
            )
            .with_tenant(tenant, authority)?
            .build()
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
                    assertion: Some(br#"{"tenant":"tenant-a","principal":"user-a"}"#.to_vec()),
                },
                &authority,
            )
            .unwrap();
        let ctx_b = TenantAssertionExtension
            .authenticate(
                &CredentialMaterial {
                    request_id: "seed-b".into(),
                    bearer_token: None,
                    assertion: Some(br#"{"tenant":"tenant-b","principal":"user-b"}"#.to_vec()),
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
                        r#"{"tenant":"tenant-a","principal":"user-a"}"#,
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
                        r#"{"tenant":"tenant-a","principal":"user-a"}"#,
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
                        r#"{"tenant":"tenant-a","principal":"user-a"}"#,
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
                        r#"{"tenant":"tenant-a","principal":"user-a"}"#,
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
                        r#"{"tenant":"tenant-a","principal":"user-a"}"#,
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
