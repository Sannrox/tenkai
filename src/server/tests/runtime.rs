use super::support::{FixedReconciler, app};
use super::*;

#[tokio::test]
async fn tenant_store_work_can_run_a_synchronous_runtime() {
    let value = run_blocking_tenant_store(|| {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { 42 })
    })
    .await
    .unwrap();

    assert_eq!(value, 42);
}

#[tokio::test]
async fn openmetrics_enabled_exposes_series_without_secrets() {
    let store = Arc::new(crate::storage::SqliteStore::open_in_memory().unwrap());
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    config.metrics_enabled = true;
    let app = router(config, Arc::new(FixedReconciler), store).unwrap();
    let response = app
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(body.contains("tenkai_reconcile_ticks_total"));
    assert!(body.contains("tenkai_reconcile_ticks_failed_total"));
    assert!(!crate::metrics::body_leaks_secret(
        &body,
        &["management-secret", "runtime-secret", "Bearer "]
    ));
    assert!(!body.contains("tenant_id"));
}

#[tokio::test]
async fn openmetrics_disabled_by_default() {
    let (app, _store) = app();
    let response = app
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn runtime_inventory_accepts_admitted_facts_and_rejects_foreign_env() {
    let (app, _store) = app();
    let body = serde_json::json!({
        "facts": { "architecture": "arm64", "memory_gib": "32" },
        "source": "runtime-probe"
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/runtime/environments/prod/inventory")
                .header("authorization", "Bearer runtime-secret")
                .header("x-tenkai-runtime-instance", "rt-1")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let report: RuntimeInventoryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report.environment, "prod");
    assert_eq!(report.source, "runtime-probe");
    assert_eq!(
        report.applied,
        vec!["architecture".to_string(), "memory_gib".to_string()]
    );

    let forbidden = app
        .clone()
        .oneshot(
            Request::post("/v1/runtime/environments/other/inventory")
                .header("authorization", "Bearer runtime-secret")
                .header("x-tenkai-runtime-instance", "rt-1")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let bad_key = serde_json::json!({
        "facts": { "token": "x" },
        "source": "runtime-probe"
    });
    let rejected = app
        .oneshot(
            Request::post("/v1/runtime/environments/prod/inventory")
                .header("authorization", "Bearer runtime-secret")
                .header("x-tenkai-runtime-instance", "rt-1")
                .header("content-type", "application/json")
                .body(Body::from(bad_key.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn embedded_and_http_reconciliation_share_the_same_contract() {
    let embedded = FixedReconciler.reconcile().await.unwrap();
    let (app, store) = app();
    let response = app
        .oneshot(
            Request::post("/v1/reconcile")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let remote: TickReport = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(remote, embedded);
    assert_eq!(store.audit_events().unwrap().len(), 2);
}

#[tokio::test]
async fn runtime_credentials_are_environment_scoped() {
    let (app, _) = app();
    let denied = app
        .clone()
        .oneshot(
            Request::get("/v1/runtime/environments/staging/work")
                .header("authorization", "Bearer runtime-secret")
                .header("x-tenkai-runtime-instance", "instance-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let allowed = app
        .clone()
        .oneshot(
            Request::get("/v1/runtime/environments/prod/work")
                .header("authorization", "Bearer runtime-secret")
                .header("x-tenkai-runtime-instance", "instance-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(allowed.into_body(), usize::MAX)
        .await
        .unwrap();
    let first: RuntimeWork = serde_json::from_slice(&bytes).unwrap();
    assert!(first.plan.is_some());
    let generation = first.claim.unwrap().generation;
    assert_eq!(generation, 1);

    let overlapping = app
        .clone()
        .oneshot(
            Request::get("/v1/runtime/environments/prod/work")
                .header("authorization", "Bearer runtime-secret")
                .header("x-tenkai-runtime-instance", "instance-b")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(overlapping.into_body(), usize::MAX)
        .await
        .unwrap();
    let overlapping: RuntimeWork = serde_json::from_slice(&bytes).unwrap();
    assert!(overlapping.plan.is_none());
    assert!(overlapping.claim.is_none());

    let completed = app
        .clone()
        .oneshot(
            Request::post("/v1/runtime/environments/prod/complete")
                .header("authorization", "Bearer runtime-secret")
                .header("x-tenkai-runtime-instance", "instance-a")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&crate::runtime_delivery::RuntimeCompletion {
                        plan_id: "plan-1".into(),
                        generation,
                        succeeded: true,
                        detail: "deployed".into(),
                        receipts: Vec::new(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::NO_CONTENT);

    let repeated = app
        .oneshot(
            Request::get("/v1/runtime/environments/prod/work")
                .header("authorization", "Bearer runtime-secret")
                .header("x-tenkai-runtime-instance", "instance-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(repeated.into_body(), usize::MAX)
        .await
        .unwrap();
    let second: RuntimeWork = serde_json::from_slice(&bytes).unwrap();
    assert!(second.plan.is_some());
    assert!(second.claim.unwrap().completion_json.is_some());
}
