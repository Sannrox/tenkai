use super::auth_support::TenantAssertionExtension;
use super::lifecycle_support::{MigrationFixture, migration_fixture, migration_preview_body};
use super::support::FixedReconciler;
use super::*;

#[tokio::test]
async fn package_migration_preview_matches_embedded_identity() {
    let MigrationFixture {
        root,
        database,
        mut ctx,
        declaration,
    } = migration_fixture("http").await;
    let embedded =
        crate::package_migration::preview(&mut ctx, "cutover", "local", declaration.clone(), None)
            .await
            .unwrap();
    let reconciler =
        crate::reconciler::Reconciler::new(ctx.clone(), crate::reconciler::Config::default())
            .unwrap();
    let store = Arc::new(crate::storage::SqliteStore::open(&database).unwrap());
    let app = router(
        ServerConfig::community("management-secret", HashMap::new()),
        Arc::new(reconciler),
        store,
    )
    .unwrap();
    let response = app
        .oneshot(
            Request::post("/v1/migrations/cutover/preview")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&crate::package_migration::PackageMigrationPreviewRequest {
                        version: crate::package_migration::MIGRATION_API_VERSION,
                        environment: "local".into(),
                        declaration,
                        backup_receipt_digest: None,
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: crate::package_migration::PackageMigrationResult =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(
        result.version,
        crate::package_migration::MIGRATION_API_VERSION
    );
    assert_eq!(result.record.identity_digest, embedded.identity_digest);
    assert_eq!(result.record.environment, "local");
    assert_eq!(
        result.record.status,
        crate::package_migration::MigrationStatus::Admitted
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn package_migration_preview_hides_cross_tenant_environment() {
    use crate::runtime_capabilities::enterprise_auth_capabilities;
    use crate::storage::EnvironmentRecord;
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
    config.tenant_store = Some(tenant_store.clone());

    let authority = crate::auth_context::TenantDerivationAuthority::new("auth.enterprise");
    let ctx_b = TenantAssertionExtension
        .authenticate(
            &CredentialMaterial {
                request_id: "seed-b".into(),
                bearer_token: None,
                assertion: Some(
                    br#"{"tenant":"tenant-b","principal":"user-b","capabilities":["read","management"]}"#
                        .to_vec(),
                ),
            },
            &authority,
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
    let cross = tenant_app
        .oneshot(
            Request::post("/v1/migrations/cutover/preview")
                .header(
                    "x-tenkai-assertion",
                    r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#,
                )
                .header("content-type", "application/json")
                .body(Body::from(migration_preview_body("env-b", 1)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross.status(), StatusCode::NOT_FOUND);
    let body = String::from_utf8(
        axum::body::to_bytes(cross.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains(NON_DISCLOSING_DENY));
    assert!(!body.contains("tenant-b"));
}
