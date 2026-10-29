use base64::Engine as _;

use super::*;
use std::future::Future;
use std::pin::Pin;

const SEED: [u8; 32] = [9; 32];

/// Trust roots naming the export seed's public key under `key_id`, the id
/// the signed artifact carries.
fn trust_roots(key_id: &str) -> tenkai::release_signing::TrustRoots {
    let public = ed25519_dalek::SigningKey::from_bytes(&SEED)
        .verifying_key()
        .to_bytes();
    tenkai::release_signing::TrustRoots {
        version: tenkai::release_signing::TRUST_ROOT_VERSION,
        signers: vec![tenkai::release_signing::TrustedSigner {
            key_id: key_id.into(),
            identity: "export signer".into(),
            public_key: base64::engine::general_purpose::STANDARD.encode(public),
        }],
    }
}

fn exports(root: &std::path::Path) -> Arc<tenkai::exports::Exports> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(root.join("seed"), SEED).unwrap();
    std::fs::set_permissions(root.join("seed"), std::fs::Permissions::from_mode(0o600)).unwrap();
    Arc::new(tenkai::exports::Exports::new(root.join("exports"), root.join("seed"), None).unwrap())
}

type Call = Pin<Box<dyn Future<Output = (StatusCode, Vec<u8>)> + Send>>;

fn caller(app: Router) -> impl Fn(&str, &str, &str, Option<serde_json::Value>) -> Call {
    move |method, path, token, body| {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(
                body.map(|body| body.to_string()).unwrap_or_default(),
            ))
            .unwrap();
        let app = app.clone();
        Box::pin(async move {
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, bytes.to_vec())
        })
    }
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap()
}

/// Downloads verify with the CLI verifiers, every creation and download is
/// recorded with its actor and reason, and an environment-scoped token sees
/// and creates only its own environment's exports (#682).
#[tokio::test]
async fn exports_download_verifiably_and_stay_inside_their_scope() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-http-exports-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("tenkai.db");
    let mut ctx = tenkai::client::Ctx::embedded(&database).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    let mut plans = HashMap::new();
    for environment in ["prod", "site-c"] {
        tenkai::plan::env_add(&mut ctx, environment, "isolated")
            .await
            .unwrap();
        let plan = tenkai::plan::create_from_steps(&mut ctx, environment, Vec::new())
            .await
            .unwrap();
        plans.insert(environment, plan.id);
    }
    let reconciler =
        tenkai::reconciler::Reconciler::new(ctx, tenkai::reconciler::Config::default()).unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(&database).unwrap());
    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config
        .environment_management_assignments
        .insert("prod-secret".into(), "prod".into());
    config.exports = Some(exports(&root));
    let app = router(config, Arc::new(reconciler), store.clone()).unwrap();
    let call = caller(app);
    let create = |kind: &str, environment: Option<&str>| {
        let mut body = serde_json::json!({"kind": kind, "reason": "case 42"});
        if let Some(environment) = environment {
            body["environment"] = environment.into();
            body["plan_id"] = plans[environment].clone().into();
        }
        body
    };

    let (status, _) = call(
        "POST",
        "/v1/exports",
        "management-secret",
        Some(serde_json::json!({"kind": "support-bundle", "reason": " "})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a reason is required");
    let (status, support) = call(
        "POST",
        "/v1/exports",
        "management-secret",
        Some(create("support-bundle", None)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&support)
    );
    let support = json(&support);
    let download = format!(
        "/v1/exports/{}/download?reason=ticket+7",
        support["id"].as_str().unwrap()
    );
    let (status, bytes) = call("GET", &download, "management-secret", None).await;
    assert_eq!(status, StatusCode::OK);
    let bundle: tenkai::support_bundle::SupportBundle = serde_json::from_slice(&bytes).unwrap();
    tenkai::support_bundle::verify(&bundle, &trust_roots(&bundle.key_id)).unwrap();

    let (status, audit) = call(
        "POST",
        "/v1/exports",
        "management-secret",
        Some(create("audit-export", None)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, bytes) = call(
        "GET",
        &format!(
            "/v1/exports/{}/download?reason=review",
            json(&audit)["id"].as_str().unwrap()
        ),
        "management-secret",
        None,
    )
    .await;
    let export: tenkai::audit_export::AuditExport = serde_json::from_slice(&bytes).unwrap();
    let roots = trust_roots(&export.key_id);
    tenkai::audit_export::verify_chain(std::slice::from_ref(&export), &roots, None).unwrap();
    assert_eq!(
        json(&audit)["audit_range"],
        serde_json::json!({"from": 1, "to": 1})
    );

    // #825: a second entry, then a ranged export of both. The next-entry
    // export is not advanced by it, and the download verifies offline.
    let (status, _) = call(
        "POST",
        "/v1/exports",
        "management-secret",
        Some(create("audit-export", None)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let mut ranged = create("audit-export", None);
    ranged["from_sequence"] = 1.into();
    ranged["to_sequence"] = 2.into();
    let (status, range) = call("POST", "/v1/exports", "management-secret", Some(ranged)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&range)
    );
    let range = json(&range);
    assert_eq!(
        range["audit_range"],
        serde_json::json!({"from": 1, "to": 2})
    );
    let (_, bytes) = call(
        "GET",
        &format!(
            "/v1/exports/{}/download?reason=review",
            range["id"].as_str().unwrap()
        ),
        "management-secret",
        None,
    )
    .await;
    let range: tenkai::audit_export::AuditRange = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(range.exports[0], export);
    tenkai::audit_export::verify_range(&range, &roots, None).unwrap();
    let mut beyond = create("audit-export", None);
    beyond["from_sequence"] = 2.into();
    beyond["to_sequence"] = 3.into();
    let (status, _) = call("POST", "/v1/exports", "management-secret", Some(beyond)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the chain holds no export 3"
    );
    let mut half = create("support-bundle", None);
    half["from_sequence"] = 1.into();
    let (status, _) = call("POST", "/v1/exports", "management-secret", Some(half)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The environment-scoped token: hub-wide exports and other environments
    // are refused or invisible; its own environment's recovery bundle is not.
    let (status, _) = call(
        "POST",
        "/v1/exports",
        "prod-secret",
        Some(create("support-bundle", None)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        "POST",
        "/v1/exports",
        "prod-secret",
        Some(create("recovery-bundle", Some("site-c"))),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Its own environment with another environment's plan discloses nothing.
    let mut body = create("recovery-bundle", Some("prod"));
    body["plan_id"] = plans["site-c"].clone().into();
    let (status, foreign) = call("POST", "/v1/exports", "prod-secret", Some(body)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        json(&foreign)["error"],
        format!("plan {} not found in environment prod", plans["site-c"]),
        "the refusal carries nothing of the other plan"
    );
    let (status, recovery) = call(
        "POST",
        "/v1/exports",
        "prod-secret",
        Some(create("recovery-bundle", Some("prod"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&recovery)
    );
    let (status, _) = call("GET", &download, "prod-secret", None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a hub-wide export is not disclosed"
    );
    let (_, listed) = call("GET", "/v1/exports", "prod-secret", None).await;
    let listed = json(&listed);
    assert_eq!(listed["exports"].as_array().unwrap().len(), 1);
    assert_eq!(listed["exports"][0]["environment"], "prod");
    let (_, listed) = call("GET", "/v1/exports", "management-secret", None).await;
    assert_eq!(json(&listed)["exports"].as_array().unwrap().len(), 5);

    let (status, inspected) = call(
        "GET",
        &format!("/v1/exports/{}", support["id"].as_str().unwrap()),
        "management-secret",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = json(&inspected)["events"].clone();
    assert_eq!(events[0]["action"], "created");
    assert_eq!(events[0]["reason"], "case 42");
    assert_eq!(events[1]["action"], "downloaded");
    assert_eq!(events[1]["reason"], "ticket 7");
    let audited: Vec<String> = store
        .audit_events()
        .unwrap()
        .into_iter()
        .map(|record| record.operation)
        .collect();
    assert!(
        audited.contains(&"export.support-bundle.downloaded".to_string()),
        "{audited:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// Exports are management only: a read-only credential can neither create
/// nor list them, and a tenant-mode host serves none at all.
#[tokio::test]
async fn read_only_and_tenant_credentials_get_no_exports() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-http-exports-read-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config.requirements.tenant_mode = true;
    config.requirements.require_enterprise_authentication = true;
    config.capabilities = tenkai::runtime_capabilities::ProvidedCapabilities::assemble(
        "enterprise-tenant-memory",
        [
            tenkai::tenant_store::tenant_memory_store_capabilities(),
            tenkai::runtime_capabilities::enterprise_auth_capabilities(),
        ],
    );
    config.auth_host = AuthHostConfig {
        required_extension_id: Some("auth.enterprise".into()),
        expected_contract_version: tenkai::auth_context::AUTH_CONTEXT_CONTRACT_VERSION,
        expected_audience: Some("tenkai-server".into()),
    };
    config.enterprise_auth = Some(Arc::new(super::auth_support::TenantAssertionExtension));
    config.tenant_store = Some(Arc::new(
        tenkai::tenant_store::InMemoryTenantOperationalStore::new(),
    ));
    config.exports = Some(exports(&root));
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    let app = router(
        config,
        Arc::new(super::support::FixedReconciler::default()),
        store,
    )
    .unwrap();
    let assertion = r#"{"tenant":"tenant-a","principal":"viewer","capabilities":["read"]}"#;
    for (method, body) in [
        ("POST", r#"{"kind":"support-bundle","reason":"look"}"#),
        ("GET", ""),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/v1/exports")
                    .header("content-type", "application/json")
                    .header("x-tenkai-assertion", assertion)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method}");
    }
    // Even with the management capability, a tenant-mode host serves no
    // export: the directory is not partitioned by tenant.
    let manager =
        r#"{"tenant":"tenant-a","principal":"admin","capabilities":["read","management"]}"#;
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/exports")
                .header("x-tenkai-assertion", manager)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        std::fs::read_dir(root.join("exports"))
            .unwrap()
            .next()
            .is_none()
    );
    let _ = std::fs::remove_dir_all(root);
}
