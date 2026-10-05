use super::lifecycle_support::{MigrationFixture, migration_fixture};
use super::*;

fn approval_body(environment: &str) -> serde_json::Value {
    serde_json::json!({
        "approval": {
            "schema": "tenkai.package-migration-approval.v1",
            "key_id": "k",
            "statement": {
                "identity_digest": format!("sha256:{}", "a".repeat(64)),
                "environment": environment,
                "purpose": "execute_package_migration",
                "issued_at": 1,
                "expires_at": 2
            },
            "signature": "c2ln"
        },
        "trust_roots": {
            "version": 1,
            "signers": [{"key_id": "k", "identity": "approver", "public_key": "cA=="}]
        }
    })
}

async fn post(
    app: &Router,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn environment_scoped_management_cannot_reconcile_or_migrate_other_environments() {
    let MigrationFixture {
        root,
        database,
        mut ctx,
        declaration,
    } = migration_fixture("scope").await;
    tenkai::package_migration::create(&mut ctx, "cutover", "local", declaration.clone(), None)
        .await
        .unwrap();
    let reconciler =
        tenkai::reconciler::Reconciler::new(ctx.clone(), tenkai::reconciler::Config::default())
            .unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(&database).unwrap());
    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config.environment_management_assignments = HashMap::from([
        ("prod-secret".to_string(), "prod".to_string()),
        ("local-secret".to_string(), "local".to_string()),
    ]);
    let app = router(config, Arc::new(reconciler), store).unwrap();

    let (code, body) = post(&app, "/v1/reconcile", "prod-secret", serde_json::json!({})).await;
    assert_eq!(code, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("fleet-wide reconcile"), "{body}");

    let mut apply = approval_body("local");
    apply["version"] = 1.into();
    apply["environment"] = "local".into();
    apply["expected_generation"] = 0.into();
    apply["declaration"] = serde_json::to_value(&declaration).unwrap();
    let (code, body) = post(&app, "/v1/migrations/cutover/apply", "prod-secret", apply).await;
    assert_eq!(code, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("another environment"), "{body}");

    let mut mutate = approval_body("local");
    mutate["version"] = 1.into();
    mutate["expected_generation"] = 0.into();
    for route in ["resume", "rollback"] {
        let path = format!("/v1/migrations/cutover/{route}");
        let (code, body) = post(&app, &path, "prod-secret", mutate.clone()).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{route}: {body}");
        assert!(body.contains("another environment"), "{route}: {body}");

        // The bound environment passes the grant and reaches approval evidence.
        let (code, body) = post(&app, &path, "local-secret", mutate.clone()).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{route}: {body}");
        assert!(
            body.contains("trust roots are not configured"),
            "{route}: {body}"
        );
    }

    let (code, body) = post(
        &app,
        "/v1/reconcile",
        "management-secret",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        code,
        StatusCode::OK,
        "fleet management still reconciles: {body}"
    );
    let _ = std::fs::remove_dir_all(root);
}
