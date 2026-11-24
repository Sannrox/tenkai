//! `/v1/debug-sessions` (#1556): durable, bounded, audited debug sessions.

use super::lifecycle_support::signed_catalog_fixture;
use super::support::current_generation;
use super::*;
use tenkai::oidc_verifier::test_support::{Signer, jwks};
use tenkai::oidc_verifier::{
    JwksCache, KeySource, OIDC_AUTH_EXTENSION_ID, OidcAuthExtension, OidcConfig,
};

const ISSUER: &str = "https://idp.example.test/realms/ops";

/// `debuggers` hold `debug` everywhere; `prod-debuggers` only on prod.
fn oidc_config() -> OidcConfig {
    toml::from_str(&format!(
        r#"
issuer = "{ISSUER}"
audience = "tenkai"
[grants]
claim = "groups"
[[grants.rules]]
value = "debuggers"
capabilities = ["read", "debug"]
[[grants.rules]]
value = "prod-debuggers"
capabilities = ["read", "debug"]
environment = "prod"
"#
    ))
    .unwrap()
}

struct Fixture {
    root: std::path::PathBuf,
    signer: Signer,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    /// A server over the fixture's database; a second call is a restart.
    async fn server(&self) -> (Router, Arc<tenkai_sqlite::SqliteStore>) {
        let database = self.root.join("tenkai.db");
        let ctx = tenkai_sqlite::embedded_ctx(&database, false).unwrap();
        let reconciler =
            tenkai::reconciler::Reconciler::new(ctx, tenkai::reconciler::Config::default())
                .unwrap();
        let store = Arc::new(tenkai_sqlite::SqliteStore::open(&database).unwrap());
        let raw = jwks(&[&self.signer]);
        let source: Arc<dyn KeySource> = Arc::new(move || Ok(raw.clone()));
        let extension = OidcAuthExtension::new(
            oidc_config(),
            Arc::new(JwksCache::load(source).unwrap()),
            None,
            false,
        )
        .unwrap();
        let mut config = ServerConfig::community("management-secret", HashMap::new());
        config.release_trust_roots = Some(self.root.join("trust-roots.toml"));
        config.capabilities = tenkai::runtime_capabilities::community_sqlite_profile(
            tenkai::runtime_capabilities::enterprise_auth_capabilities(),
        );
        config.auth_host = AuthHostConfig {
            required_extension_id: Some(OIDC_AUTH_EXTENSION_ID.into()),
            expected_contract_version: tenkai::auth_context::AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some("tenkai".into()),
        };
        config.enterprise_auth = Some(Arc::new(extension));
        let app = router(config, Arc::new(reconciler), store.clone()).unwrap();
        (app, store)
    }

    fn token(&self, groups: &[&str], act: Option<&str>) -> String {
        let now = tenkai::assertion_verifier::now_unix_secs();
        let mut claims = serde_json::json!({
            "iss": ISSUER, "sub": "user-1", "aud": "tenkai",
            "exp": now + 300, "groups": groups,
        });
        if let Some(act) = act {
            claims["act"] = act.into();
        }
        String::from_utf8(self.signer.sign(&claims)).unwrap()
    }
}

/// `stage` and `prod` each run instance `api`; stage allows read sessions
/// of at most an hour, prod has no approval policy.
async fn fixture(label: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "tenkai-debug-sessions-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mut ctx = tenkai_sqlite::embedded_ctx(root.join("tenkai.db"), false).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    for name in ["stage", "prod"] {
        tenkai::plan::env_add(&mut ctx, name, "fixture")
            .await
            .unwrap();
    }
    drop(ctx);
    let fixture = Fixture {
        root,
        signer: Signer::new("k1"),
    };
    let (app, _) = fixture.server().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = RemoteClient::new(format!("http://{addr}"), "management-secret").unwrap();
    client
        .publish_release(&signed_catalog_fixture(&fixture.root, "1.0.0"))
        .await
        .unwrap();
    client.promote_release("api@1.0.0", "stable").await.unwrap();
    for name in ["stage", "prod"] {
        let generation = current_generation(&client, name).await;
        client
            .subscribe_environment(name, "api=stable", generation, None)
            .await
            .unwrap();
    }
    server.abort();
    let policy = fixture.root.join("stage-policy.toml");
    std::fs::write(
        &policy,
        "version = 1\nmode = \"manual\"\nttl_ms = 60000\ndebug_sessions = \"read\"\ndebug_session_max_ms = 3600000\n",
    )
    .unwrap();
    let mut ctx = tenkai_sqlite::embedded_ctx(fixture.root.join("tenkai.db"), false).unwrap();
    tenkai::plan::set_plan_approval_policy(&mut ctx, "stage", &policy)
        .await
        .unwrap();
    fixture
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    bearer: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn open(environment: &str, duration_ms: Option<i64>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "environment": environment, "instance": "api", "reason": "pod restarts",
    });
    if let Some(duration) = duration_ms {
        body["duration_ms"] = duration.into();
    }
    body
}

fn audited(store: &tenkai_sqlite::SqliteStore, operation: &str) -> usize {
    tenkai::storage::OperationalStore::audit_events(store)
        .unwrap()
        .iter()
        .filter(|record| record.operation == operation)
        .count()
}

/// A human with `debug` opens a session bounded by the policy maximum; it
/// survives a restart, closes once, and every step is audited.
#[tokio::test]
async fn a_session_opens_survives_a_restart_and_closes() {
    let fixture = fixture("lifecycle").await;
    let (app, store) = fixture.server().await;
    let human = fixture.token(&["debuggers"], None);
    let (code, opened) = call(
        &app,
        "POST",
        "/v1/debug-sessions",
        &human,
        Some(open("stage", None)),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{opened}");
    assert_eq!(opened["state"], "open");
    assert_eq!(opened["mode"], "read");
    assert_eq!(opened["subject"], format!("user-1@{ISSUER}"));
    let bound = opened["not_after"].as_i64().unwrap() - opened["opened_at"].as_i64().unwrap();
    assert_eq!(bound, 3_600_000, "the policy maximum is the default");
    assert_eq!(audited(&store, "debug_session.open.completed"), 1);
    drop(app);

    let (app, store) = fixture.server().await;
    let id = opened["id"].as_str().unwrap();
    let (code, listed) = call(
        &app,
        "GET",
        "/v1/debug-sessions?environment=stage",
        "management-secret",
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{listed}");
    assert_eq!(listed["sessions"][0]["id"], id);
    let close = serde_json::json!({"reason": "found it"});
    let path = format!("/v1/debug-sessions/{id}/close");
    let (code, closed) = call(&app, "POST", &path, &human, Some(close.clone())).await;
    assert_eq!(code, StatusCode::OK, "{closed}");
    assert_eq!(closed["state"], "closed");
    assert_eq!(closed["close_reason"], "found it");
    let (code, again) = call(&app, "POST", &path, "management-secret", Some(close)).await;
    assert_eq!(code, StatusCode::OK, "{again}");
    assert_eq!(again["closed_at"], closed["closed_at"]);
    assert_eq!(audited(&store, "debug_session.close.completed"), 1);
}

/// Each refusal names its reason and is audited; nothing opens.
#[tokio::test]
async fn refused_opens_are_audited_and_open_nothing() {
    let fixture = fixture("refusals").await;
    let (app, store) = fixture.server().await;
    let human = fixture.token(&["debuggers"], None);
    let cases = [
        (
            "management-secret".to_string(),
            open("stage", None),
            StatusCode::FORBIDDEN,
        ),
        (
            fixture.token(&["debuggers"], Some("assistant-7")),
            open("stage", None),
            StatusCode::FORBIDDEN,
        ),
        (human.clone(), open("prod", None), StatusCode::FORBIDDEN),
        (
            fixture.token(&["prod-debuggers"], None),
            open("stage", None),
            StatusCode::FORBIDDEN,
        ),
        (
            human.clone(),
            open("stage", Some(3_600_001)),
            StatusCode::BAD_REQUEST,
        ),
        (
            human.clone(),
            serde_json::json!({"environment": "stage", "instance": "web", "reason": "x"}),
            StatusCode::NOT_FOUND,
        ),
        (
            human.clone(),
            serde_json::json!({"environment": "stage", "instance": "api", "reason": " "}),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (bearer, body, expected) in &cases {
        let (code, refused) = call(
            &app,
            "POST",
            "/v1/debug-sessions",
            bearer,
            Some(body.clone()),
        )
        .await;
        assert_eq!(code, *expected, "{body} {refused}");
    }
    let (code, refused) = call(
        &app,
        "POST",
        "/v1/debug-sessions",
        &human,
        Some(open("prod", None)),
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert!(
        refused
            .to_string()
            .contains("forbidden in this environment"),
        "{refused}"
    );
    // The agent refusal is audited under `debug_session.open.refused` too.
    assert_eq!(
        audited(&store, "debug_session.open.refused"),
        cases.len() + 1
    );
    assert_eq!(audited(&store, "debug_session.open.completed"), 0);
    let (_, listed) = call(&app, "GET", "/v1/debug-sessions", "management-secret", None).await;
    assert_eq!(listed["sessions"], serde_json::json!([]));
}

/// A session past its bound reads as expired, and the expiry is audited once.
#[tokio::test]
async fn a_session_past_its_bound_is_expired() {
    let fixture = fixture("expiry").await;
    let (app, store) = fixture.server().await;
    let human = fixture.token(&["debuggers"], None);
    let (code, opened) = call(
        &app,
        "POST",
        "/v1/debug-sessions",
        &human,
        Some(open("stage", Some(1))),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{opened}");
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let path = format!("/v1/debug-sessions/{}", opened["id"].as_str().unwrap());
    for _ in 0..2 {
        let (code, read) = call(&app, "GET", &path, &human, None).await;
        assert_eq!(code, StatusCode::OK, "{read}");
        assert_eq!(read["state"], "expired");
        assert_eq!(read["closed_at"], opened["not_after"]);
    }
    assert_eq!(audited(&store, "debug_session.expire.completed"), 1);
}
