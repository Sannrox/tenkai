use super::support::{FixedReconciler, app};
use super::*;
use tenkai::oidc_verifier::test_support::{Signer, jwks};
use tenkai::oidc_verifier::{
    JwksCache, KeySource, OIDC_AUTH_EXTENSION_ID, OidcAuthExtension, OidcClientDiscovery,
    OidcConfig,
};

const ISSUER: &str = "https://idp.example.test/realms/ops";

fn oidc_config() -> OidcConfig {
    toml::from_str(&format!(
        r#"
issuer = "{ISSUER}"
audience = "tenkai"
[client]
client_id = "tenkai-console"
display_name = "Example Org"
scopes = ["openid", "groups"]
[grants]
claim = "groups"
[[grants.rules]]
value = "viewers"
capabilities = ["read"]
[[grants.rules]]
value = "prod-operators"
capabilities = ["read", "management"]
environment = "prod"
[[grants.rules]]
value = "stage-operators"
capabilities = ["management"]
environment = "stage"
"#
    ))
    .unwrap()
}

fn oidc_app(signer: &Signer) -> Router {
    let raw = jwks(&[signer]);
    let source: Arc<dyn KeySource> = Arc::new(move || Ok(raw.clone()));
    let config = oidc_config();
    let extension = OidcAuthExtension::new(
        config.clone(),
        Arc::new(JwksCache::load(source).unwrap()),
        None,
        false,
    )
    .unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    let mut server = ServerConfig::community("management-secret", HashMap::new());
    server.capabilities = tenkai::runtime_capabilities::community_sqlite_profile(
        tenkai::runtime_capabilities::enterprise_auth_capabilities(),
    );
    server.auth_host = AuthHostConfig {
        required_extension_id: Some(OIDC_AUTH_EXTENSION_ID.into()),
        expected_contract_version: tenkai::auth_context::AUTH_CONTEXT_CONTRACT_VERSION,
        expected_audience: Some("tenkai".into()),
    };
    server.enterprise_auth = Some(Arc::new(extension));
    server.oidc_client = OidcClientDiscovery::from_config(&config);
    router(server, Arc::new(FixedReconciler::default()), store).unwrap()
}

fn token(signer: &Signer, groups: &[&str]) -> String {
    let now = tenkai::assertion_verifier::now_unix_secs();
    String::from_utf8(signer.sign(&serde_json::json!({
        "iss": ISSUER, "sub": "user-1", "aud": "tenkai",
        "exp": now + 300, "groups": groups,
    })))
    .unwrap()
}

async fn status(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn get(path: &str, bearer: &str) -> Request<Body> {
    Request::get(path)
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn discovery_serves_public_client_settings_only_when_configured() {
    let oidc = oidc_app(&Signer::new("k1"));
    let (code, body) = status(
        &oidc,
        Request::get("/v1/auth/oidc").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["issuer"], ISSUER);
    assert_eq!(body["client_id"], "tenkai-console");
    assert_eq!(body["scopes"], serde_json::json!(["openid", "groups"]));
    assert_eq!(body["display_name"], "Example Org");

    let mut unnamed = oidc_config();
    unnamed.client.as_mut().unwrap().display_name = None;
    let discovery = serde_json::to_value(OidcClientDiscovery::from_config(&unnamed)).unwrap();
    assert!(
        discovery.get("display_name").is_none(),
        "unset display_name is omitted: {discovery}"
    );

    let (community, _) = app();
    let (code, _) = status(
        &community,
        Request::get("/v1/auth/oidc").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bearer_access_tokens_authorize_reads_by_group() {
    let signer = Signer::new("k1");
    let app = oidc_app(&signer);
    let (code, _) = status(&app, get("/v1/fleet/status", &token(&signer, &["viewers"]))).await;
    assert_eq!(code, StatusCode::OK);

    let (code, _) = status(
        &app,
        get("/v1/fleet/status", &token(&signer, &["strangers"])),
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);

    let forged = token(&Signer::new("k1"), &["viewers"]);
    let (code, _) = status(&app, get("/v1/fleet/status", &forged)).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);

    let (code, _) = status(&app, get("/v1/fleet/status", "management-secret")).await;
    assert_eq!(code, StatusCode::OK, "community tokens keep working");
}

#[tokio::test]
async fn environment_bound_tokens_cannot_manage_other_environments() {
    let signer = Signer::new("k1");
    let app = oidc_app(&signer);
    let request = serde_json::to_vec(&tenkai::management_lifecycle::RetireEnvironmentRequest {
        version: 1,
        operation: "retire".into(),
        reason: "service ended".into(),
    })
    .unwrap();
    let (code, body) = status(
        &app,
        Request::post("/v1/environments/stage/retire")
            .header(
                "authorization",
                format!("Bearer {}", token(&signer, &["prod-operators"])),
            )
            .header("content-type", "application/json")
            .body(Body::from(request))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("another environment"), "{body}");

    let (code, body) = status(
        &app,
        Request::post("/v1/reconcile")
            .header(
                "authorization",
                format!("Bearer {}", token(&signer, &["prod-operators"])),
            )
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("fleet-wide reconcile"), "{body}");
}

/// Rejected tokens are 401 with an RFC 6750 challenge so clients ask the user
/// to sign in again; a valid token without a matching grant stays 403.
#[tokio::test]
async fn rejected_tokens_are_401_and_missing_grants_are_403() {
    let signer = Signer::new("k1");
    let app = oidc_app(&signer);
    let now = tenkai::assertion_verifier::now_unix_secs();
    let signed = |signer: &Signer, claims: serde_json::Value| {
        String::from_utf8(signer.sign(&claims)).unwrap()
    };
    let claims = |overrides: serde_json::Value| {
        let mut claims = serde_json::json!({
            "iss": ISSUER, "sub": "user-1", "aud": "tenkai",
            "exp": now + 300, "groups": ["viewers"],
        });
        for (key, value) in overrides.as_object().unwrap() {
            claims[key] = value.clone();
        }
        claims
    };
    for (case, bearer) in [
        (
            "expired",
            signed(&signer, claims(serde_json::json!({"exp": now - 600}))),
        ),
        (
            "not yet valid",
            signed(&signer, claims(serde_json::json!({"nbf": now + 600}))),
        ),
        (
            "wrong issuer",
            signed(
                &signer,
                claims(serde_json::json!({"iss": "https://other.example/realms/ops"})),
            ),
        ),
        (
            "wrong audience",
            signed(&signer, claims(serde_json::json!({"aud": "account"}))),
        ),
        (
            "unknown key",
            signed(&Signer::new("k2"), claims(serde_json::json!({}))),
        ),
        (
            "unknown community token",
            "not-a-configured-token".to_string(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(get("/v1/fleet/status", &bearer))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{case}");
        assert_eq!(
            response.headers()["www-authenticate"],
            "Bearer error=\"invalid_token\"",
            "{case}"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"invalid management credential"}"#,
            "{case}: body must not disclose which check failed"
        );
    }

    let response = app
        .clone()
        .oneshot(get("/v1/fleet/status", &token(&signer, &["strangers"])))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get("www-authenticate").is_none());

    // Valid token, but its groups confine management to two environments:
    // a grant conflict the user cannot fix by signing in again.
    let response = app
        .clone()
        .oneshot(get(
            "/v1/fleet/status",
            &token(&signer, &["prod-operators", "stage-operators"]),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get("www-authenticate").is_none());
}
