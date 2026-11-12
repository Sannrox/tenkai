use super::*;
use tenkai::auth_context::AuthError;
use tenkai::host_identity::{
    HostAccount, HostAccountLookup, HostGrantMapping, HostIdentityAuthenticator, VIEWER_GROUP,
};
use tenkai::oidc_verifier::OidcGrantRule;

use crate::auth::{UnixPeerState, with_unix_peer};
use crate::opening::HotSwap;

struct FixedLookup(HostAccount);

impl HostAccountLookup for FixedLookup {
    fn lookup(&self, uid: u32) -> Result<HostAccount, AuthError> {
        if uid == self.0.uid {
            Ok(self.0.clone())
        } else {
            Err(AuthError::Unauthorized(
                "peer uid has no passwd entry".into(),
            ))
        }
    }
}

fn grant(value: &str, capability: &str) -> OidcGrantRule {
    OidcGrantRule {
        value: value.into(),
        capabilities: vec![capability.into()],
        environment: None,
        channels: Vec::new(),
        products: Vec::new(),
        kind: None,
    }
}

fn host_app(account: HostAccount, rules: Vec<OidcGrantRule>) -> Router {
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    config.host_identity = Some(Arc::new(HostIdentityAuthenticator::new(
        Arc::new(FixedLookup(account)),
        HostGrantMapping::from_rules(rules).unwrap(),
    )));
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    store
        .put_environment(&tenkai::storage::EnvironmentRecord {
            id: "prod".into(),
            revision: 0,
            configuration_json: "{}".into(),
        })
        .unwrap();
    router(
        config,
        Arc::new(super::support::FixedReconciler::default()),
        store,
    )
    .unwrap()
}

fn operator(uid: u32) -> HostAccount {
    HostAccount {
        uid,
        name: "raphael".into(),
        groups: vec![VIEWER_GROUP.into(), "tenkai-operator".into()],
    }
}

#[tokio::test]
async fn unix_peer_operator_lists_environments() {
    let app = host_app(
        operator(1000),
        vec![
            grant(VIEWER_GROUP, "read"),
            grant("tenkai-operator", "management"),
        ],
    );
    let response = with_unix_peer(UnixPeerState::Uid(1000), async {
        app.oneshot(
            Request::get("/v1/environments")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = with_unix_peer(UnixPeerState::Uid(1000), async {
        host_app(
            operator(1000),
            vec![
                grant(VIEWER_GROUP, "read"),
                grant("tenkai-operator", "management"),
            ],
        )
        .oneshot(
            Request::get("/v1/auth/me")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(session.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(session.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["principal"], "host:uid:1000");
    assert_eq!(body["user"], "raphael");
    assert_eq!(body["source"], "host");
}

#[tokio::test]
async fn unix_peer_unmapped_group_is_refused() {
    let app = host_app(
        HostAccount {
            uid: 1002,
            name: "nobody".into(),
            groups: vec!["wheel".into()],
        },
        vec![grant("tenkai-operator", "management")],
    );
    let response = with_unix_peer(UnixPeerState::Uid(1002), async {
        app.oneshot(
            Request::get("/v1/environments")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unix_peer_missing_passwd_is_refused() {
    let app = host_app(operator(1), vec![grant("tenkai-operator", "management")]);
    let response = with_unix_peer(UnixPeerState::Uid(65534), async {
        app.oneshot(
            Request::get("/v1/environments")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unix_peer_nss_failure_is_refused() {
    struct Fail;
    impl HostAccountLookup for Fail {
        fn lookup(&self, _uid: u32) -> Result<HostAccount, AuthError> {
            Err(AuthError::Unauthorized("NSS group lookup failed".into()))
        }
    }
    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config.host_identity = Some(Arc::new(HostIdentityAuthenticator::new(
        Arc::new(Fail),
        HostGrantMapping::from_rules(vec![grant("tenkai-operator", "management")]).unwrap(),
    )));
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    let app = router(
        config,
        Arc::new(super::support::FixedReconciler::default()),
        store,
    )
    .unwrap();
    let response = with_unix_peer(UnixPeerState::Uid(9), async {
        app.oneshot(
            Request::get("/v1/environments")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unix_peer_requires_loopback_host() {
    let app = host_app(operator(1000), vec![grant("tenkai-operator", "management")]);
    let response = with_unix_peer(UnixPeerState::Uid(1000), async {
        app.oneshot(
            Request::get("/v1/environments")
                .header("host", "example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unix_peer_refuses_foreign_origin() {
    let app = host_app(operator(1000), vec![grant("tenkai-operator", "management")]);
    let response = with_unix_peer(UnixPeerState::Uid(1000), async {
        app.oneshot(
            Request::get("/v1/environments")
                .header("host", "127.0.0.1")
                .header("origin", "http://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tcp_still_requires_bearer() {
    let app = host_app(operator(1000), vec![grant("tenkai-operator", "management")]);
    let denied = app
        .clone()
        .oneshot(
            Request::get("/v1/environments")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
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
}

#[cfg(unix)]
#[tokio::test]
async fn unix_listener_uses_kernel_peer_credentials() {
    let uid = {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    };
    // Short and process-unique: `dir/tenkai.sock` must stay under the Unix
    // socket path limit (104 bytes on macOS) with a per-user `TMPDIR`.
    let dir = std::env::temp_dir().join(format!("ths-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tenkai.sock");
    let app = host_app(operator(uid), vec![grant("tenkai-operator", "management")]);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let swap = HotSwap::new(app);
    let server = tokio::spawn(async move {
        axum::serve(listener, swap).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .unix_socket(&*path)
        .build()
        .unwrap();
    let response = client
        .get("http://127.0.0.1/v1/environments")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let session: serde_json::Value = client
        .get("http://127.0.0.1/v1/auth/me")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["principal"], format!("host:uid:{uid}"));
    assert_eq!(session["source"], "host");
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn management_token_over_peer_still_works() {
    let app = host_app(operator(1000), vec![grant("tenkai-operator", "management")]);
    let response = with_unix_peer(UnixPeerState::Uid(1000), async {
        app.oneshot(
            Request::get("/v1/environments")
                .header("host", "127.0.0.1")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}
