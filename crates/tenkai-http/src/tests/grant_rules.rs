//! `/v1/grant-rules` (#837): stored grant rules managed over HTTP, by the
//! management token or a fleet administrator only.

use super::support::FixedReconciler;
use super::*;
use tenkai::grant_rules::StoredGrants;
use tenkai::oidc_verifier::test_support::{Signer, jwks};
use tenkai::oidc_verifier::{
    JwksCache, KeySource, OIDC_AUTH_EXTENSION_ID, OidcAuthExtension, OidcConfig,
};

const ISSUER: &str = "https://idp.example.test/realms/ops";

/// A file with no management rule: `viewers` read, `prod-operators`
/// manage one environment.
fn oidc_config() -> OidcConfig {
    toml::from_str(&format!(
        r#"
issuer = "{ISSUER}"
audience = "tenkai"
[grants]
claim = "groups"
[[grants.rules]]
value = "viewers"
capabilities = ["read"]
[[grants.rules]]
value = "prod-operators"
capabilities = ["read", "management"]
environment = "prod"
"#
    ))
    .unwrap()
}

struct Hub {
    app: Router,
    store: Arc<tenkai::storage::SqliteStore>,
    dir: std::path::PathBuf,
}

impl Drop for Hub {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn hub(signer: &Signer) -> Hub {
    let dir = std::env::temp_dir().join(format!(
        "tenkai-http-grant-rules-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(dir.join("tenkai.db")).unwrap());
    let raw = jwks(&[signer]);
    let source: Arc<dyn KeySource> = Arc::new(move || Ok(raw.clone()));
    let config = oidc_config();
    let stored = StoredGrants::load(
        store.clone(),
        config.grants.rules.iter().map(|rule| rule.value.clone()),
    )
    .unwrap();
    let extension = OidcAuthExtension::new(
        config.clone(),
        Arc::new(JwksCache::load(source).unwrap()),
        None,
        false,
    )
    .unwrap()
    .with_stored_grants(stored.clone());
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
    server.first_administrator = config.first_administrator();
    server.stored_grants = Some(stored);
    let app = router(server, Arc::new(FixedReconciler::default()), store.clone()).unwrap();
    Hub { app, store, dir }
}

fn token(signer: &Signer, groups: &[&str]) -> String {
    let now = tenkai::assertion_verifier::now_unix_secs();
    String::from_utf8(signer.sign(&serde_json::json!({
        "iss": ISSUER, "sub": "user-1", "aud": "tenkai",
        "exp": now + 300, "groups": groups,
    })))
    .unwrap()
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
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

fn admins_rule(generation: i64) -> serde_json::Value {
    serde_json::json!({
        "rule": {"value": "tenkai-admins", "capabilities": ["read", "management"]},
        "reason": "first administrator",
        "generation": generation,
    })
}

/// The acceptance path: the management token creates the first
/// administrator rule, `/healthz` reports it, and a member of the group can
/// do a management read and manage stored rules from then on. Each change is
/// audited with its principal and reason, and the token is never recorded.
#[tokio::test]
async fn the_management_token_sets_up_the_first_administrator() {
    let signer = Signer::new("k1");
    let hub = hub(&signer);
    let (code, health) = call(&hub.app, "GET", "/healthz", None, None).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(health["first_administrator"], "missing");
    let (code, list) = call(
        &hub.app,
        "GET",
        "/v1/grant-rules",
        Some("management-secret"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{list}");
    assert_eq!(list["rules"], serde_json::json!([]));
    let generation = list["generation"].as_i64().unwrap();

    let (code, created) = call(
        &hub.app,
        "POST",
        "/v1/grant-rules",
        Some("management-secret"),
        Some(admins_rule(generation)),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{created}");
    assert_eq!(created["rules"][0]["rule"]["value"], "tenkai-admins");
    assert_eq!(created["rules"][0]["created_by"], "management");
    assert_eq!(created["rules"][0]["declared_by_config"], false);
    let (_, health) = call(&hub.app, "GET", "/healthz", None, None).await;
    assert_eq!(health["first_administrator"], "configured");

    let admin = token(&signer, &["tenkai-admins"]);
    let (code, _) = call(&hub.app, "GET", "/v1/fleet/status", Some(&admin), None).await;
    assert_eq!(code, StatusCode::OK);
    // The administrator now manages stored rules too.
    let (code, removed) = call(
        &hub.app,
        "DELETE",
        "/v1/grant-rules",
        Some(&admin),
        Some(serde_json::json!({
            "value": "tenkai-admins",
            "reason": "moved to the config file",
            "generation": created["generation"],
        })),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{removed}");
    assert_eq!(removed["rules"], serde_json::json!([]));
    let (_, health) = call(&hub.app, "GET", "/healthz", None, None).await;
    assert_eq!(health["first_administrator"], "missing");

    let audit = tenkai::storage::OperationalStore::audit_events(hub.store.as_ref()).unwrap();
    let completed: Vec<_> = audit
        .iter()
        .filter(|record| {
            record.operation.starts_with("grant_rule.") && record.outcome == "completed"
        })
        .map(|record| {
            (
                record.principal.as_str(),
                record.operation.as_str(),
                record.resource.as_str(),
            )
        })
        .collect();
    assert_eq!(
        completed,
        [
            (
                "management",
                "grant_rule.create.completed",
                "grant-rule/tenkai-admins reason=first administrator"
            ),
            (
                &*format!("user-1@{ISSUER}"),
                "grant_rule.remove.completed",
                "grant-rule/tenkai-admins reason=moved to the config file"
            ),
        ]
    );
    let recorded = format!("{audit:?}");
    assert!(!recorded.contains("management-secret"), "{recorded}");
}

/// Without fleet management nothing is written: a signed-in reader, an
/// environment-scoped manager and an anonymous caller are refused, and the
/// rules and their generation stay as they were.
#[tokio::test]
async fn a_signed_in_user_without_management_cannot_create_a_rule() {
    let signer = Signer::new("k1");
    let hub = hub(&signer);
    for (bearer, expected) in [
        (Some(token(&signer, &["viewers"])), StatusCode::FORBIDDEN),
        (
            Some(token(&signer, &["prod-operators"])),
            StatusCode::FORBIDDEN,
        ),
        (Some(token(&signer, &["strangers"])), StatusCode::FORBIDDEN),
        (None, StatusCode::UNAUTHORIZED),
    ] {
        let (code, body) = call(
            &hub.app,
            "POST",
            "/v1/grant-rules",
            bearer.as_deref(),
            Some(admins_rule(0)),
        )
        .await;
        assert_eq!(code, expected, "{bearer:?}: {body}");
        let (code, _) = call(&hub.app, "GET", "/v1/grant-rules", bearer.as_deref(), None).await;
        assert_eq!(code, expected, "{bearer:?} listing");
    }
    let (_, list) = call(
        &hub.app,
        "GET",
        "/v1/grant-rules",
        Some("management-secret"),
        None,
    )
    .await;
    assert_eq!(list["rules"], serde_json::json!([]));
    assert_eq!(list["generation"], 0, "nothing was written");
    let (_, health) = call(&hub.app, "GET", "/healthz", None, None).await;
    assert_eq!(health["first_administrator"], "missing");
}

/// A config-declared claim value is refused, and so is a change against a
/// generation that moved.
#[tokio::test]
async fn config_values_and_stale_generations_are_refused() {
    let signer = Signer::new("k1");
    let hub = hub(&signer);
    let mut escalate = admins_rule(0);
    escalate["rule"]["value"] = "viewers".into();
    let (code, body) = call(
        &hub.app,
        "POST",
        "/v1/grant-rules",
        Some("management-secret"),
        Some(escalate),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");

    let (code, _) = call(
        &hub.app,
        "POST",
        "/v1/grant-rules",
        Some("management-secret"),
        Some(admins_rule(0)),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED);
    let mut readers = admins_rule(0);
    readers["rule"] = serde_json::json!({"value": "readers", "capabilities": ["read"]});
    let (code, body) = call(
        &hub.app,
        "POST",
        "/v1/grant-rules",
        Some("management-secret"),
        Some(readers),
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT, "{body}");
    let (code, _) = call(
        &hub.app,
        "DELETE",
        "/v1/grant-rules",
        Some("management-secret"),
        Some(serde_json::json!({"value": "tenkai-admins", "reason": "stale", "generation": 0})),
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT);
    let (_, list) = call(
        &hub.app,
        "GET",
        "/v1/grant-rules",
        Some("management-secret"),
        None,
    )
    .await;
    assert_eq!(list["generation"], 1);
    assert_eq!(list["rules"].as_array().unwrap().len(), 1);
}
