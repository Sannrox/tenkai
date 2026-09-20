use super::auth_support::TenantAssertionExtension;
use super::support::{FixedReconciler, app};
use super::*;

#[tokio::test]
async fn tenant_mode_management_apis_isolate_environments() {
    use crate::runtime_capabilities::enterprise_auth_capabilities;
    use crate::storage::EnvironmentRecord;
    use crate::tenant_store::tenant_memory_store_capabilities;

    let tenant_store = Arc::new(crate::tenant_store::InMemoryTenantOperationalStore::new());
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
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
    // No federation issuer: wrap not applied; pure enterprise extension.
    config.enterprise_auth = Some(Arc::new(TenantAssertionExtension));
    config.tenant_store = Some(tenant_store.clone());

    // Seed partitions via authenticated contexts.
    let authority = crate::auth_context::TenantDerivationAuthority::new("auth.enterprise");
    let ctx_a = TenantAssertionExtension
        .authenticate(
            &CredentialMaterial {
                request_id: "seed-a".into(),
                bearer_token: None,
                assertion: Some(br#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#.to_vec()),
            },
            &authority,
        )
        .unwrap();
    let ctx_b = TenantAssertionExtension
        .authenticate(
            &CredentialMaterial {
                request_id: "seed-b".into(),
                bearer_token: None,
                assertion: Some(br#"{"tenant":"tenant-b","principal":"user-b","capabilities":["read","management"]}"#.to_vec()),
            },
            &authority,
        )
        .unwrap();
    tenant_store
        .put_environment_for(
            &ctx_a,
            &EnvironmentRecord {
                id: "env-a".into(),
                revision: 0,
                configuration_json: "{}".into(),
            },
        )
        .unwrap();
    tenant_store
        .put_environment_for(
            &ctx_b,
            &EnvironmentRecord {
                id: "env-b".into(),
                revision: 0,
                configuration_json: "{}".into(),
            },
        )
        .unwrap();

    let store = Arc::new(crate::storage::SqliteStore::open_in_memory().unwrap());
    let tenant_app = router(config, Arc::new(FixedReconciler), store).unwrap();

    let list_a = tenant_app
        .clone()
        .oneshot(
            Request::get("/v1/environments")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_a.status(), StatusCode::OK);
    let body = String::from_utf8(
        axum::body::to_bytes(list_a.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("env-a"));
    assert!(!body.contains("env-b"));
    assert!(!body.contains("tenant-b"));

    let cross = tenant_app
        .clone()
        .oneshot(
            Request::get("/v1/environments/env-b")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross.status(), StatusCode::NOT_FOUND);
    let cross_body = String::from_utf8(
        axum::body::to_bytes(cross.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(cross_body.contains(NON_DISCLOSING_DENY));
    assert!(!cross_body.contains("tenant-b"));
    assert!(!cross_body.contains("env-b"));

    // environment.status is HTTP-exposed and must use the same non-disclosing deny.
    let status_cross = tenant_app
        .clone()
        .oneshot(
            Request::get("/v1/environments/env-b/status")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_cross.status(), StatusCode::NOT_FOUND);
    let status_body = String::from_utf8(
        axum::body::to_bytes(status_cross.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(status_body.contains(NON_DISCLOSING_DENY));
    assert!(!status_body.contains("tenant-b"));
    assert!(!status_body.contains("env-b"));

    let fleet_a = tenant_app
        .clone()
        .oneshot(
            Request::get("/v1/fleet/status")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fleet_a.status(), StatusCode::OK);
    let fleet_body = String::from_utf8(
        axum::body::to_bytes(fleet_a.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!fleet_body.contains("env-b"));
    assert!(!fleet_body.contains("tenant-b"));

    let reconcile_a = tenant_app
        .clone()
        .oneshot(
            Request::post("/v1/reconcile")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reconcile_a.status(), StatusCode::OK);
    let reconcile_body = String::from_utf8(
        axum::body::to_bytes(reconcile_a.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    // The fake global reconcile path returns `prod`; seeing only the
    // tenant-store identity proves selection used the bounded application
    // operation before any reconciler work, rather than filtering a global
    // report afterward.
    assert!(reconcile_body.contains("env-a"));
    assert!(!reconcile_body.contains("prod"));
    assert!(!reconcile_body.contains("env-b"));
    assert!(!reconcile_body.contains("tenant-b"));
    assert!(!reconcile_body.contains("management-secret"));

    // Community profile still starts without tenant mode.
    let (community_app, _) = app();
    let health = community_app
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    tenant_store.set_healthy(false);
    let unavailable = tenant_app
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
}
