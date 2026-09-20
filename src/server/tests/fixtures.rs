use super::auth_support::TenantAssertionExtension;
use super::support::{FixedReconciler, app};
use super::*;

#[tokio::test]
async fn development_fixture_surface_is_explicit_authorized_and_tenant_scoped() {
    use crate::runtime_capabilities::enterprise_auth_capabilities;
    use crate::tenant_store::tenant_memory_store_capabilities;

    let tenant_store = Arc::new(crate::tenant_store::InMemoryTenantOperationalStore::new());
    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config.requirements.tenant_mode = true;
    config.requirements.require_enterprise_authentication = true;
    config.capabilities = crate::runtime_capabilities::ProvidedCapabilities::assemble(
        "enterprise-tenant-memory",
        [
            tenant_memory_store_capabilities(),
            enterprise_auth_capabilities(),
        ],
    );
    config.auth_host = AuthHostConfig {
        required_extension_id: Some("auth.enterprise".into()),
        expected_contract_version: crate::auth_context::AUTH_CONTEXT_CONTRACT_VERSION,
        expected_audience: Some("tenkai-server".into()),
    };
    config.enterprise_auth = Some(Arc::new(TenantAssertionExtension));
    config.tenant_store = Some(tenant_store);
    config.development_fixtures = Some(DevelopmentFixtureConfig {
        allowed_principals: std::collections::BTreeSet::from(["seed-service".into()]),
    });
    let store = Arc::new(crate::storage::SqliteStore::open_in_memory().unwrap());
    let fixture_app = router(config, Arc::new(FixedReconciler), store).unwrap();
    let fixture = serde_json::json!({
        "contract_version": 1,
        "fixture_id": "buyer-demo",
        "releases": [{
            "name": "app",
            "product": "app",
            "version": "1.0.0",
            "content_digest": "a".repeat(64)
        }, {
            "name": "worker",
            "product": "worker",
            "version": "2.0.0",
            "content_digest": "b".repeat(64)
        }],
        "channels": [{
            "name": "stable",
            "product": "app",
            "release": "app"
        }, {
            "name": "canary",
            "product": "worker",
            "release": "worker"
        }],
        "environments": [{
            "name": "prod-eu",
            "posture": "awaiting_approval",
            "description": "sanitized"
        }],
        "plans": [{
            "name": "approval",
            "environment": "prod-eu",
            "blocked_reason": "awaiting approval"
        }]
    });

    let import = fixture_app
        .clone()
        .oneshot(
            Request::post("/v1/development/fixtures/import")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-a","principal":"seed-service","kind":"service"}"#,
                )
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&fixture).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(import.status(), StatusCode::OK);
    let body = String::from_utf8(
        axum::body::to_bytes(import.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("fx-62757965722d64656d6f-environment-prod-eu"));
    assert!(!body.contains("management-secret"));

    let repeated = fixture_app
        .clone()
        .oneshot(
            Request::post("/v1/development/fixtures/import")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-a","principal":"seed-service","kind":"service"}"#,
                )
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&fixture).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::OK);

    for (path, expected) in [
        (
            "/v1/environments",
            "fx-62757965722d64656d6f-environment-prod-eu",
        ),
        (
            "/v1/environments/fx-62757965722d64656d6f-environment-prod-eu",
            "\"state\":\"missing\"",
        ),
        (
            "/v1/environments/fx-62757965722d64656d6f-environment-prod-eu/status",
            "\"channel\":\"fixture-buyer-demo-canary\"",
        ),
        ("/v1/fleet/status", "\"posture\":\"behind\""),
    ] {
        let response = fixture_app
            .clone()
            .oneshot(
                Request::get(path)
                    .header(
                        "x-tenkai-assertion",
                        r#"{"tenant":"tenant-a","principal":"seed-service","kind":"service"}"#,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let response_body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(response_body.contains(expected), "{path}: {response_body}");
        if path == "/v1/environments/fx-62757965722d64656d6f-environment-prod-eu" {
            assert!(response_body.contains("\"state\":\"blocked\""));
            assert!(response_body.contains(
                "\"status_detail\":\"blocked development fixture; execution is disabled\""
            ));
            assert!(response_body.contains("\"steps\":[]"));
        }
        assert!(!response_body.contains("management-secret"));
    }

    for assertion in [
        r#"{"tenant":"tenant-a","principal":"human-user"}"#,
        r#"{"tenant":"tenant-a","principal":"other-service","kind":"service"}"#,
    ] {
        let denied = fixture_app
            .clone()
            .oneshot(
                Request::post("/v1/development/fixtures/import")
                    .header("x-tenkai-assertion", assertion)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&fixture).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }

    let tenant_b = fixture_app
        .clone()
        .oneshot(
            Request::get("/v1/environments")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-b","principal":"seed-service","kind":"service"}"#,
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let tenant_b_body = String::from_utf8(
        axum::body::to_bytes(tenant_b.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!tenant_b_body.contains("prod-eu"));
    assert!(!tenant_b_body.contains("buyer-demo"));
    let tenant_b_deep_link = fixture_app
        .clone()
        .oneshot(
            Request::get("/v1/environments/fx-62757965722d64656d6f-environment-prod-eu")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-b","principal":"seed-service","kind":"service"}"#,
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tenant_b_deep_link.status(), StatusCode::NOT_FOUND);
    let tenant_b_deep_link_body = String::from_utf8(
        axum::body::to_bytes(tenant_b_deep_link.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!tenant_b_deep_link_body.contains("blocked development fixture"));
    assert!(!tenant_b_deep_link_body.contains("buyer-demo"));

    let reset = fixture_app
        .oneshot(
            Request::delete("/v1/development/fixtures/buyer-demo")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-a","principal":"seed-service","kind":"service"}"#,
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reset.status(), StatusCode::OK);

    let (community_app, _) = app();
    let absent = community_app
        .oneshot(
            Request::post("/v1/development/fixtures/import")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(absent.status(), StatusCode::NOT_FOUND);
}
