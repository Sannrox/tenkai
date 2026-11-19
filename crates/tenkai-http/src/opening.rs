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
        version: tenkai::version_skew::SERVER_VERSION,
        trust: None,
        status: "ok",
        profile: profile.into(),
        capabilities,
        contracts: SERVED_CONTRACTS.to_vec(),
        backup: None,
        clock: None,
        first_administrator: None,
        stored_grant_rules_withheld: None,
        replica_executors_differ: Vec::new(),
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
///
/// Each connection gets its own clone, which records whether the client
/// presented a verified certificate (#671). That fact reaches handlers as the
/// [`ClientCertificate`](crate::tls::ClientCertificate) extension, and when
/// runtime client certificates are required, `/v1/runtime/*` without one is
/// refused before routing.
#[derive(Clone)]
pub struct HotSwap {
    current: Arc<RwLock<Router>>,
    runtime_client_certificate_required: bool,
    client_certificate: Option<Arc<[u8]>>,
    unix_peer: super::auth::UnixPeerState,
}

impl HotSwap {
    pub fn new(router: Router) -> Self {
        Self {
            current: Arc::new(RwLock::new(router)),
            runtime_client_certificate_required: false,
            client_certificate: None,
            unix_peer: super::auth::UnixPeerState::Tcp,
        }
    }

    /// Refuse runtime routes on connections without a client certificate.
    pub fn requiring_runtime_client_certificates(mut self) -> Self {
        self.runtime_client_certificate_required = true;
        self
    }

    pub fn replace(&self, router: Router) {
        *self
            .current
            .write()
            .expect("opening router slot is not poisoned") = router;
    }
}

impl<L> Service<IncomingStream<'_, L>> for HotSwap
where
    L: axum::serve::Listener,
    L::Io: crate::tls::ConnectionIdentity,
{
    type Response = Self;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, stream: IncomingStream<'_, L>) -> Self::Future {
        use crate::tls::{ConnectionIdentity as _, PeerCertificate as _};
        let mut connection = self.clone();
        connection.client_certificate = stream.io().client_certificate();
        connection.unix_peer = stream.io().unix_peer();
        std::future::ready(Ok(connection))
    }
}

/// Whether `path` is exactly the enrollment or renewal route,
/// `/v1/runtime/environments/{environment}/enroll` or `.../certificate`.
/// They are how a runner gets a certificate (#674): a first one, and a new
/// one once its own has expired, so they alone skip the client-certificate
/// requirement. Matching the whole pattern keeps a future route that merely
/// ends the same way from inheriting the exemption.
fn is_certificate_bootstrap(path: &str) -> bool {
    matches!(
        path.split('/').collect::<Vec<_>>().as_slice(),
        ["", "v1", "runtime", "environments", environment, "enroll" | "certificate"]
            if !environment.is_empty()
    )
}

impl Service<Request> for HotSwap {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let enrollment = is_certificate_bootstrap(req.uri().path());
        if self.runtime_client_certificate_required
            && self.client_certificate.is_none()
            && req.uri().path().starts_with("/v1/runtime/")
            && !enrollment
        {
            return Box::pin(std::future::ready(Ok(crate::runtime::error_response(
                StatusCode::FORBIDDEN,
                "runtime routes require a client certificate",
            ))));
        }
        req.extensions_mut().insert(crate::tls::ClientCertificate(
            self.client_certificate.clone(),
        ));
        let mut router = self
            .current
            .read()
            .expect("opening router slot is not poisoned")
            .clone();
        let unix_peer = self.unix_peer;
        if matches!(unix_peer, super::auth::UnixPeerState::Unavailable) {
            return Box::pin(std::future::ready(Ok(crate::runtime::error_response(
                StatusCode::UNAUTHORIZED,
                "peer credentials unavailable",
            ))));
        }
        Box::pin(async move {
            Ok(super::auth::with_unix_peer(unix_peer, async move {
                Service::call(&mut router, req)
                    .await
                    .unwrap_or_else(|err| match err {})
            })
            .await)
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

    #[tokio::test]
    async fn only_the_enrollment_and_renewal_routes_skip_the_client_certificate() {
        let swap = HotSwap::new(Router::new().fallback(|| async { StatusCode::OK }))
            .requiring_runtime_client_certificates();
        for (path, status) in [
            ("/v1/runtime/environments/prod/enroll", StatusCode::OK),
            ("/v1/runtime/environments/prod/certificate", StatusCode::OK),
            ("/v1/runtime/environments/prod/work", StatusCode::FORBIDDEN),
            (
                "/v1/runtime/environments/prod/x/enroll",
                StatusCode::FORBIDDEN,
            ),
            ("/v1/runtime/issuers/certificate", StatusCode::FORBIDDEN),
            ("/v1/runtime/environments//enroll", StatusCode::FORBIDDEN),
        ] {
            let response = swap
                .clone()
                .oneshot(Request::post(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{path}");
        }
    }
}
