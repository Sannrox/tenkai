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
use crate::federated_identity::{
    FederatingAuthExtension, FederationConfig, IdentityDirectory, reject_caller_selected_tenant,
};
use crate::reconciler::{Reconciler, TickReport};
use crate::runtime_capabilities::{
    ProvidedCapabilities, RuntimeRequirements, community_auth_capabilities,
    community_sqlite_profile, validate_runtime_capabilities,
};
use crate::storage::{AuditRecord, OperationalStore};

pub type ReconcileFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<TickReport>> + Send + 'a>>;

/// Transport-independent application operation used by embedded and remote hosts.
pub trait ReconcilePort: Send + Sync {
    fn reconcile(&self) -> ReconcileFuture<'_>;
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

impl ReconcilePort for Reconciler {
    fn reconcile(&self) -> ReconcileFuture<'_> {
        Box::pin(self.run_once())
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
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/reconcile", post(reconcile))
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
        .with_state(Arc::new(AppState {
            config,
            auth,
            reconciler,
            store,
        })))
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
    let Some(token) = bearer(headers) else {
        return Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "missing bearer token",
        )));
    };
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let credential = CredentialMaterial {
        request_id,
        bearer_token: Some(token.to_string()),
        assertion: None,
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

async fn list_environments(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate_management(&state, &headers) {
        return *response;
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
    if let Err(response) = authenticate_management(&state, &headers) {
        return *response;
    }
    match state.reconciler.inspect_environment(environment).await {
        Ok(report) => Json(report).into_response(),
        Err(error) => {
            let message = format!("{error:#}");
            if message.contains("not registered") {
                error_response(StatusCode::NOT_FOUND, message)
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
    if let Err(response) = authenticate_management(&state, &headers) {
        return *response;
    }
    match state.reconciler.environment_status(environment).await {
        Ok(rows) => Json(rows).into_response(),
        Err(error) => {
            let message = format!("{error:#}");
            if message.contains("not registered") {
                error_response(StatusCode::NOT_FOUND, message)
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
    let actor = context.principal_id();
    if let Err(error) = audit(&*state.store, actor, "reconcile.requested", "*") {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string());
    }
    match state.reconciler.reconcile().await {
        Ok(report) => {
            let outcome = if report.failures() == 0 {
                "reconcile.completed"
            } else {
                "reconcile.failed"
            };
            if let Err(error) = audit(&*state.store, actor, outcome, "*") {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string());
            }
            Json(report).into_response()
        }
        Err(error) => match audit(&*state.store, actor, "reconcile.failed", "*") {
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
