//! `/v1/debug-sessions` (#1556): durable, bounded, audited debug sessions.

use super::lifecycle_support::signed_catalog_fixture;
use super::support::current_generation;
use super::*;
use tenkai::oidc_verifier::test_support::{Signer, jwks};
use tenkai::oidc_verifier::{
    JwksCache, KeySource, OIDC_AUTH_EXTENSION_ID, OidcAuthExtension, OidcConfig,
};

pub(super) const ISSUER: &str = "https://idp.example.test/realms/ops";

/// `debuggers` hold `debug` everywhere; `prod-debuggers` only on prod.
fn oidc_config() -> OidcConfig {
    toml::from_str(&format!(
        r#"
issuer = "{ISSUER}"
audience = "tenkai"
clock_skew_secs = 0
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

pub(super) struct Fixture {
    pub(super) root: std::path::PathBuf,
    signer: Signer,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    /// A server over the fixture's database; a second call is a restart.
    pub(super) async fn server(&self) -> (Router, Arc<tenkai_sqlite::SqliteStore>) {
        let database = self.root.join("tenkai.db");
        let ctx = tenkai_sqlite::embedded_ctx(&database, false).unwrap();
        // Plan-approval roots, when a test wrote them; elevation approvals
        // verify against them.
        let roots = self.root.join("approval-roots.toml");
        let config = tenkai::reconciler::Config {
            approval_trust_roots: roots.exists().then_some(roots),
            ..tenkai::reconciler::Config::default()
        };
        let reconciler = tenkai::reconciler::Reconciler::new(ctx, config).unwrap();
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
        let mut config = ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "stage".into())]),
        );
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

    pub(super) fn token(&self, groups: &[&str], act: Option<&str>) -> String {
        self.token_for(groups, act, 300)
    }

    /// A token that expires `ttl_secs` from now.
    fn token_for(&self, groups: &[&str], act: Option<&str>, ttl_secs: i64) -> String {
        let now = tenkai::assertion_verifier::now_unix_secs();
        let mut claims = serde_json::json!({
            "iss": ISSUER, "sub": "user-1", "aud": "tenkai",
            "exp": now + ttl_secs, "groups": groups,
        });
        if let Some(act) = act {
            claims["act"] = act.into();
        }
        String::from_utf8(self.signer.sign(&claims)).unwrap()
    }
}

/// `stage` and `prod` each run instance `api`; stage allows read sessions
/// of at most an hour, prod has no approval policy.
pub(super) async fn fixture(label: &str) -> Fixture {
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

pub(super) async fn call(
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

/// A runtime request on `stage` from runtime instance `instance`, naming
/// the `debug_session` and `debug_elevation` capabilities when `capable`.
pub(super) async fn runtime(
    app: &Router,
    method: &str,
    path: &str,
    instance: &str,
    capable: bool,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", "Bearer runtime-secret")
        .header("x-tenkai-runtime-instance", instance);
    if capable {
        request = request.header(
            "x-tenkai-runtime-capabilities",
            "instance_health,debug_session,debug_elevation",
        );
    }
    let response = app
        .clone()
        .oneshot(
            request
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

pub(super) const WORK: &str = "/v1/runtime/environments/stage/work";

pub(super) fn open(environment: &str, duration_ms: Option<i64>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "environment": environment, "instance": "api", "reason": "pod restarts",
    });
    if let Some(duration) = duration_ms {
        body["duration_ms"] = duration.into();
    }
    body
}

pub(super) fn audited(store: &tenkai_sqlite::SqliteStore, operation: &str) -> usize {
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

/// #1557: only a runtime naming `debug_session` is handed a session, the
/// first such instance owns it, and its close is recorded and audited once.
#[tokio::test]
async fn the_first_capable_runtime_owns_a_session_and_reports_its_close() {
    let fixture = fixture("runtime").await;
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
    let id = opened["id"].as_str().unwrap();
    let inspect = format!("/v1/debug-sessions/{id}");

    let (code, work) = runtime(&app, "GET", WORK, "older", false, None).await;
    assert_eq!(code, StatusCode::OK, "{work}");
    assert!(work.get("debug_sessions").is_none(), "{work}");
    let (_, unattached) = call(&app, "GET", &inspect, &human, None).await;
    assert!(unattached.get("runtime").is_none(), "{unattached}");

    let (_, work) = runtime(&app, "GET", WORK, "first", true, None).await;
    assert_eq!(work["debug_sessions"][0]["id"], id, "{work}");
    assert_eq!(work["debug_sessions"][0]["not_after"], opened["not_after"]);
    let (_, work) = runtime(&app, "GET", WORK, "second", true, None).await;
    assert!(work.get("debug_sessions").is_none(), "{work}");
    let (_, attached) = call(&app, "GET", &inspect, &human, None).await;
    assert_eq!(attached["runtime"]["instance"], "first", "{attached}");
    assert_eq!(audited(&store, "debug_session.attach.completed"), 1);

    let close = format!("/v1/runtime/environments/stage/debug-sessions/{id}/close");
    let report = serde_json::json!({"closed_at": tenkai::now_millis()});
    let (code, _) = runtime(&app, "POST", &close, "second", true, Some(report.clone())).await;
    assert_eq!(code, StatusCode::CONFLICT);
    for recorded in [true, false] {
        let (code, body) = runtime(&app, "POST", &close, "first", true, Some(report.clone())).await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert_eq!(body["recorded"], recorded);
    }
    let (_, closed) = call(&app, "GET", &inspect, &human, None).await;
    assert_eq!(closed["state"], "closed", "{closed}");
    assert_eq!(closed["closed_by"], "runtime:first");
    assert!(closed["runtime"]["closed_at"].is_i64(), "{closed}");
    assert_eq!(audited(&store, "debug_session.runtime_close.completed"), 1);
    let (_, work) = runtime(&app, "GET", WORK, "first", true, None).await;
    assert!(work.get("debug_sessions").is_none(), "{work}");
}

/// #1559: the owning runtime records each command before it runs, a write
/// as refused, and its exit; only a read may start, and none once the
/// session ends.
#[tokio::test]
async fn the_owning_runtime_records_each_command_in_the_session_audit() {
    let fixture = fixture("commands").await;
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
    let id = opened["id"].as_str().unwrap();
    let (_, work) = runtime(&app, "GET", WORK, "first", true, None).await;
    assert_eq!(work["debug_sessions"][0]["id"], id, "{work}");
    // Nothing is deployed on stage yet, so there is no release to read.
    assert!(work["debug_sessions"][0].get("target").is_none(), "{work}");

    let commands = format!("/v1/runtime/environments/stage/debug-sessions/{id}/commands");
    let record = |argv: &[&str], access: &str, outcome: &str| serde_json::json!({"argv": argv, "access": access, "outcome": outcome});
    let started = record(&["logs", "--tail", "5"], "read", "started");
    let (code, _) = runtime(
        &app,
        "POST",
        &commands,
        "second",
        true,
        Some(started.clone()),
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT, "only the owner records");
    let mut refused = record(&["delete", "pod", "x"], "write", "refused");
    refused["reason"] = "a read session runs only read commands".into();
    let mut completed = record(&["logs", "--tail", "5"], "read", "completed");
    completed["exit_code"] = 0.into();
    for body in [started.clone(), refused, completed] {
        let (code, answer) = runtime(&app, "POST", &commands, "first", true, Some(body)).await;
        assert_eq!(code, StatusCode::NO_CONTENT, "{answer}");
    }
    let write = record(&["restart"], "write", "started");
    let (code, _) = runtime(&app, "POST", &commands, "first", true, Some(write)).await;
    assert_eq!(code, StatusCode::CONFLICT, "no write starts unelevated");

    let events = tenkai::storage::OperationalStore::audit_events(&*store).unwrap();
    let of = |operation: &str| {
        events
            .iter()
            .filter(|record| record.operation == operation)
            .collect::<Vec<_>>()
    };
    let started = of("debug_session.command.started");
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].principal, "runtime:first");
    assert_eq!(
        started[0].resource,
        format!(
            "debug-session/{id} environment=stage instance=api access=read argv=[\"logs\",\"--tail\",\"5\"]"
        )
    );
    let refused = of("debug_session.command.refused");
    assert_eq!(refused.len(), 1);
    assert!(
        refused[0].resource.contains("access=write")
            && refused[0]
                .resource
                .ends_with("reason=\"a read session runs only read commands\""),
        "{}",
        refused[0].resource
    );
    let completed = of("debug_session.command.completed");
    assert_eq!(completed.len(), 1);
    assert!(
        completed[0].resource.ends_with(" exit=0"),
        "{}",
        completed[0].resource
    );

    let close = format!("/v1/runtime/environments/stage/debug-sessions/{id}/close");
    let report = serde_json::json!({"closed_at": tenkai::now_millis()});
    let (code, _) = runtime(&app, "POST", &close, "first", true, Some(report)).await;
    assert_eq!(code, StatusCode::OK);
    let late = record(&["get"], "read", "started");
    let (code, _) = runtime(&app, "POST", &commands, "first", true, Some(late)).await;
    assert_eq!(
        code,
        StatusCode::CONFLICT,
        "no command starts after the end"
    );
}

/// A runtime that ended a session at its bound while cut off reports it on
/// reconnecting: the server records the session as already expired.
#[tokio::test]
async fn a_close_reported_after_the_bound_records_the_session_expired() {
    let fixture = fixture("late-close").await;
    let (app, store) = fixture.server().await;
    let human = fixture.token(&["debuggers"], None);
    let (code, opened) = call(
        &app,
        "POST",
        "/v1/debug-sessions",
        &human,
        Some(open("stage", Some(200))),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{opened}");
    let id = opened["id"].as_str().unwrap();
    let (_, work) = runtime(&app, "GET", WORK, "first", true, None).await;
    assert_eq!(work["debug_sessions"][0]["id"], id, "{work}");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let close = format!("/v1/runtime/environments/stage/debug-sessions/{id}/close");
    let report = serde_json::json!({"closed_at": opened["not_after"]});
    let (code, body) = runtime(&app, "POST", &close, "first", true, Some(report)).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let (_, expired) = call(
        &app,
        "GET",
        &format!("/v1/debug-sessions/{id}"),
        &human,
        None,
    )
    .await;
    assert_eq!(expired["state"], "expired", "{expired}");
    assert_eq!(expired["closed_at"], opened["not_after"]);
    // The runtime's own close time, not when the report arrived.
    assert_eq!(expired["runtime"]["closed_at"], opened["not_after"]);
    assert_eq!(audited(&store, "debug_session.runtime_close.completed"), 1);
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
use tokio_tungstenite::tungstenite::Message;

/// Serve `app` on a loopback port; the router clone keeps sharing its relay.
async fn serve(app: &Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Open a stream WebSocket at `path`; a runtime end names `instance`.
async fn connect(
    addr: std::net::SocketAddr,
    path: &str,
    bearer: &str,
    instance: Option<&str>,
) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    let mut request = format!("ws://{addr}{path}").into_client_request().unwrap();
    let headers = request.headers_mut();
    headers.insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    headers.insert(
        "sec-websocket-protocol",
        tenkai::debug_stream::STREAM_PROTOCOL.parse().unwrap(),
    );
    if let Some(instance) = instance {
        headers.insert("x-tenkai-runtime-instance", instance.parse().unwrap());
    }
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(ws, _)| ws)
}

/// The next data frame, within ten seconds.
async fn next(ws: &mut Ws) -> Message {
    use futures_util::StreamExt as _;
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await
            .expect("a frame within ten seconds")
            .expect("the stream is open")
            .unwrap();
        if !matches!(message, Message::Ping(_) | Message::Pong(_)) {
            return message;
        }
    }
}

/// The next frame as a control message.
async fn control(ws: &mut Ws) -> serde_json::Value {
    match next(ws).await {
        Message::Text(text) => serde_json::from_str(&text).unwrap(),
        other => panic!("expected a control frame, got {other:?}"),
    }
}

/// A session on `stage` owned by runtime instance `first`, with both ends
/// attached.
async fn attached(
    fixture: &Fixture,
    app: &Router,
    addr: std::net::SocketAddr,
    operator: &str,
    duration_ms: Option<i64>,
) -> (String, Ws, Ws) {
    let human = fixture.token(&["debuggers"], None);
    let (code, opened) = call(
        app,
        "POST",
        "/v1/debug-sessions",
        &human,
        Some(open("stage", duration_ms)),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{opened}");
    let id = opened["id"].as_str().unwrap().to_owned();
    let (_, work) = runtime(app, "GET", WORK, "first", true, None).await;
    assert_eq!(work["debug_sessions"][0]["id"], id.as_str(), "{work}");
    let mut runtime_end = connect(
        addr,
        &format!("/v1/runtime/environments/stage/debug-sessions/{id}/stream"),
        "runtime-secret",
        Some("first"),
    )
    .await
    .unwrap();
    let mut operator_end = connect(
        addr,
        &format!("/v1/debug-sessions/{id}/stream"),
        operator,
        None,
    )
    .await
    .unwrap();
    for end in [&mut runtime_end, &mut operator_end] {
        assert_eq!(control(end).await["type"], "attached");
    }
    (id, operator_end, runtime_end)
}

/// #1558: frames pass both ways unchanged, the store keeps none of them,
/// and a side that closes ends the other with the reason.
#[tokio::test]
async fn the_relay_passes_frames_both_ways_and_stores_none() {
    use futures_util::SinkExt as _;
    let fixture = fixture("stream").await;
    let (app, store) = fixture.server().await;
    let addr = serve(&app).await;
    let human = fixture.token(&["debuggers"], None);
    let (_, mut operator, mut runtime_end) = attached(&fixture, &app, addr, &human, None).await;
    assert_eq!(audited(&store, "debug_session.stream.attached"), 2);

    let marker = b"terminal-bytes-7f3a9c".to_vec();
    operator
        .send(Message::Binary(marker.clone().into()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut runtime_end).await,
        Message::Binary(marker.clone().into())
    );
    let resize = r#"{"type":"resize","cols":120,"rows":40}"#;
    operator.send(Message::text(resize)).await.unwrap();
    assert_eq!(next(&mut runtime_end).await, Message::text(resize));
    let output = b"\x1b[1moutput-5e2b\x1b[0m\r\n".to_vec();
    runtime_end
        .send(Message::Binary(output.clone().into()))
        .await
        .unwrap();
    assert_eq!(next(&mut operator).await, Message::Binary(output.into()));
    // Frames sent just before a close still arrive ahead of it.
    let exit = r#"{"type":"exit","code":3}"#;
    runtime_end.send(Message::text(exit)).await.unwrap();
    runtime_end
        .send(Message::text(r#"{"type":"close","reason":"peer_closed"}"#))
        .await
        .unwrap();
    assert_eq!(next(&mut operator).await, Message::text(exit));
    assert_eq!(control(&mut operator).await["reason"], "peer_closed");

    let mut dirs = vec![fixture.root.clone()];
    let mut files = Vec::new();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                files.push(path);
            }
        }
    }
    assert!(files.iter().any(|file| file.ends_with("tenkai.db")));
    for file in files {
        let bytes = std::fs::read(file).unwrap();
        for payload in [&marker[..], b"output-5e2b"] {
            assert!(
                !bytes.windows(payload.len()).any(|window| window == payload),
                "a frame payload reached the store"
            );
        }
    }
}

/// #1558: the bound, a management close, and an expired operator grant each
/// end both ends with the reason.
#[tokio::test]
async fn each_end_is_told_why_the_stream_ended() {
    let fixture = fixture("stream-ends").await;
    let (app, _) = fixture.server().await;
    let addr = serve(&app).await;
    let human = fixture.token(&["debuggers"], None);

    let (_, mut operator, mut runtime_end) =
        attached(&fixture, &app, addr, &human, Some(1_500)).await;
    for end in [&mut operator, &mut runtime_end] {
        assert_eq!(control(end).await["reason"], "bound_reached");
    }

    let (id, mut operator, mut runtime_end) = attached(&fixture, &app, addr, &human, None).await;
    let (code, closed) = call(
        &app,
        "POST",
        &format!("/v1/debug-sessions/{id}/close"),
        &human,
        Some(serde_json::json!({"reason": "done"})),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{closed}");
    for end in [&mut operator, &mut runtime_end] {
        assert_eq!(control(end).await["reason"], "session_closed");
    }

    // The first session above holds `first`; a closed one frees nothing,
    // so this one goes to the same instance through the next pull.
    let expiring = fixture.token_for(&["debuggers"], None, 3);
    let (_, mut operator, mut runtime_end) = attached(&fixture, &app, addr, &expiring, None).await;
    for end in [&mut operator, &mut runtime_end] {
        assert_eq!(control(end).await["reason"], "grant_revoked");
    }
}

/// #1558: an upgrade without valid credentials for its side is refused
/// before any frame.
#[tokio::test]
async fn an_upgrade_without_valid_credentials_is_refused() {
    let fixture = fixture("stream-refusals").await;
    let (app, store) = fixture.server().await;
    let addr = serve(&app).await;
    let human = fixture.token(&["debuggers"], None);
    let (_, opened) = call(
        &app,
        "POST",
        "/v1/debug-sessions",
        &human,
        Some(open("stage", None)),
    )
    .await;
    let id = opened["id"].as_str().unwrap();
    let (_, work) = runtime(&app, "GET", WORK, "first", true, None).await;
    assert_eq!(work["debug_sessions"][0]["id"], id, "{work}");
    let operator = format!("/v1/debug-sessions/{id}/stream");
    let runtime_path = format!("/v1/runtime/environments/stage/debug-sessions/{id}/stream");
    let cases = [
        (
            operator.as_str(),
            "wrong-token",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            operator.as_str(),
            "management-secret",
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            runtime_path.as_str(),
            "wrong-token",
            Some("first"),
            StatusCode::FORBIDDEN,
        ),
        (
            runtime_path.as_str(),
            "runtime-secret",
            Some("second"),
            StatusCode::CONFLICT,
        ),
    ];
    for (path, bearer, instance, expected) in cases {
        match connect(addr, path, bearer, instance).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(
                    response.status().as_u16(),
                    expected.as_u16(),
                    "{path} {bearer}"
                );
            }
            other => panic!("{path} {bearer}: expected a refusal, got {other:?}"),
        }
    }
    assert_eq!(audited(&store, "debug_session.stream.attached"), 0);
}

/// #1558: the runtime agent keeps a stream for the session it holds and
/// answers an attaching operator that its executor cannot attach yet.
#[tokio::test]
async fn the_runtime_agent_answers_unsupported() {
    let fixture = fixture("stream-agent").await;
    let (app, _) = fixture.server().await;
    let addr = serve(&app).await;
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
    let id = opened["id"].as_str().unwrap();
    let agent = tenkai::runtime_agent::RuntimeClient::new_with_options(
        format!("http://{addr}"),
        "stage",
        "runtime-secret",
        std::path::PathBuf::from("/bin/true"),
        false,
    )
    .unwrap();
    agent.run_once().await.unwrap();
    let mut operator = connect(
        addr,
        &format!("/v1/debug-sessions/{id}/stream"),
        &human,
        None,
    )
    .await
    .unwrap();
    // The agent's stream connects on its own task; it may land after ours.
    assert_eq!(control(&mut operator).await["type"], "attached");
    let close = control(&mut operator).await;
    assert_eq!(close["reason"], "unsupported", "{close}");
    assert_eq!(close["message"], tenkai::debug_stream::UNSUPPORTED_MESSAGE);
}
