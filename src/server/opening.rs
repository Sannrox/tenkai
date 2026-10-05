//! HTTP surface served after the listener binds and before the store is open.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::serve::IncomingStream;
use tower::Service;

use super::contract::SERVED_CONTRACTS;
use super::router::ServiceStatus;
use super::runtime::error_response;

#[derive(Clone)]
struct OpeningState {
    live: ServiceStatus,
}

/// Liveness plus `/readyz` 503 while the operational store is still opening.
pub fn opening_router(profile: impl Into<String>, capabilities: Vec<String>) -> Router {
    let live = ServiceStatus {
        status: "ok",
        profile: profile.into(),
        capabilities,
        contracts: SERVED_CONTRACTS.to_vec(),
    };
    Router::new()
        .route("/healthz", get(opening_health))
        .route("/readyz", get(not_ready))
        .fallback(not_ready)
        .with_state(OpeningState { live })
}

async fn opening_health(State(state): State<OpeningState>) -> Json<ServiceStatus> {
    Json(state.live)
}

async fn not_ready() -> Response {
    error_response(StatusCode::SERVICE_UNAVAILABLE, "service is not ready")
}

/// Cloneable service that swaps the served [`Router`] after startup completes.
#[derive(Clone)]
pub struct HotSwap {
    current: Arc<RwLock<Router>>,
}

impl HotSwap {
    pub fn new(router: Router) -> Self {
        Self {
            current: Arc::new(RwLock::new(router)),
        }
    }

    pub fn replace(&self, router: Router) {
        *self
            .current
            .write()
            .expect("opening router slot is not poisoned") = router;
    }
}

impl Service<IncomingStream<'_, tokio::net::TcpListener>> for HotSwap {
    type Response = Self;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _stream: IncomingStream<'_, tokio::net::TcpListener>) -> Self::Future {
        std::future::ready(Ok(self.clone()))
    }
}

impl Service<Request> for HotSwap {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let mut router = self
            .current
            .read()
            .expect("opening router slot is not poisoned")
            .clone();
        Box::pin(async move {
            Ok(Service::call(&mut router, req)
                .await
                .unwrap_or_else(|err| match err {}))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn opening_router_is_live_and_not_ready() {
        let app = opening_router("community-sqlite", vec!["opening".into()]);
        let health = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        let body = axum::body::to_bytes(health.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status["status"], "ok");
        assert_eq!(status["profile"], "community-sqlite");

        let ready = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        let ready_body = axum::body::to_bytes(ready.into_body(), usize::MAX)
            .await
            .unwrap();
        let ready_status: serde_json::Value = serde_json::from_slice(&ready_body).unwrap();
        assert_eq!(ready_status["error"], "service is not ready");
    }

    #[tokio::test]
    async fn hot_swap_serves_opening_router_until_replaced() {
        let swap = HotSwap::new(opening_router("community-sqlite", Vec::new()));
        let not_ready = swap
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);

        swap.replace(Router::new().route(
            "/readyz",
            get(|| async { (StatusCode::OK, Json(serde_json::json!({"status": "ready"}))) }),
        ));
        let ready = swap
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);
    }
}
