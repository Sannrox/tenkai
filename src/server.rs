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

use crate::reconciler::{Reconciler, TickReport};
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
}

pub type WorkFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Option<crate::plan::Plan>>> + Send + 'a>>;
pub type HealthFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
pub type CompletionFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;

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
}

#[derive(Clone)]
pub struct ServerConfig {
    pub management_token: String,
    /// Maps a runtime bearer token to its one assigned environment.
    pub runtime_assignments: HashMap<String, String>,
}

impl ServerConfig {
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
        Ok(())
    }
}

struct AppState {
    config: ServerConfig,
    reconciler: Arc<dyn ReconcilePort>,
    store: Arc<dyn OperationalStore>,
}

#[derive(Debug, Serialize)]
struct ServiceStatus {
    status: &'static str,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeWork {
    pub environment: String,
    pub plan: Option<crate::plan::Plan>,
    pub claim: Option<crate::storage::RuntimeClaim>,
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
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/reconcile", post(reconcile))
        .route(
            "/v1/runtime/environments/{environment}/work",
            get(runtime_work),
        )
        .route(
            "/v1/runtime/environments/{environment}/complete",
            post(runtime_complete),
        )
        .with_state(Arc::new(AppState {
            config,
            reconciler,
            store,
        })))
}

async fn health() -> Json<ServiceStatus> {
    Json(ServiceStatus { status: "ok" })
}

async fn ready(State(state): State<Arc<AppState>>) -> Response {
    if let Err(error) = state.store.check_health() {
        eprintln!("operational store readiness check failed: {error}");
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "service is not ready");
    }
    match state.reconciler.check_health().await {
        Ok(()) => Json(ServiceStatus { status: "ready" }).into_response(),
        Err(error) => error_response(StatusCode::SERVICE_UNAVAILABLE, {
            eprintln!("required provider readiness check failed: {error:#}");
            "service is not ready"
        }),
    }
}

async fn reconcile(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    if !constant_time_eq(token.as_bytes(), state.config.management_token.as_bytes()) {
        return error_response(StatusCode::FORBIDDEN, "invalid management credential");
    }
    if let Err(error) = audit(&*state.store, "management", "reconcile.requested", "*") {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string());
    }
    match state.reconciler.reconcile().await {
        Ok(report) => {
            let outcome = if report.failures() == 0 {
                "reconcile.completed"
            } else {
                "reconcile.failed"
            };
            if let Err(error) = audit(&*state.store, "management", outcome, "*") {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string());
            }
            Json(report).into_response()
        }
        Err(error) => match audit(&*state.store, "management", "reconcile.failed", "*") {
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
    let Some(assigned) = state.config.runtime_assignments.get(token) else {
        return error_response(StatusCode::FORBIDDEN, "invalid runtime credential");
    };
    if assigned != &environment {
        return error_response(
            StatusCode::FORBIDDEN,
            "runtime credential is not assigned to this environment",
        );
    }
    match state.reconciler.pending_work(environment.clone()).await {
        Ok(Some(plan)) => {
            let owner = runtime_owner(token);
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
    let Some(assigned) = state.config.runtime_assignments.get(token) else {
        return error_response(StatusCode::FORBIDDEN, "invalid runtime credential");
    };
    if assigned != &environment {
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
        &runtime_owner(token),
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

fn runtime_owner(token: &str) -> String {
    format!("runtime:{:x}", Sha256::digest(token.as_bytes()))
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
        let response = self
            .http
            .post(format!("{}/v1/reconcile", self.base_url))
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
            ServerConfig {
                management_token: "management-secret".into(),
                runtime_assignments: HashMap::from([("runtime-secret".into(), "prod".into())]),
            },
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

        let completed = app
            .clone()
            .oneshot(
                Request::post("/v1/runtime/environments/prod/complete")
                    .header("authorization", "Bearer runtime-secret")
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
        let config = ServerConfig {
            management_token: "same".into(),
            runtime_assignments: HashMap::from([("same".into(), "prod".into())]),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn remote_client_requires_tls_except_on_loopback() {
        assert!(RemoteClient::new("https://tenkai.example.test", "secret").is_ok());
        assert!(RemoteClient::new("http://127.0.0.1:8080", "secret").is_ok());
        assert!(RemoteClient::new("http://[::1]:8080", "secret").is_ok());
        assert!(RemoteClient::new("http://tenkai.example.test", "secret").is_err());
    }
}
