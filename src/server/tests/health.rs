use super::support::app;
use super::*;

#[tokio::test]
async fn health_and_ready_advertise_capability_names() {
    let (app, _) = app();
    for path in ["/healthz", "/readyz"] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("community-sqlite"));
        assert!(body.contains("operational_store_migration"));
        assert!(!body.contains("management-secret"));
        assert!(!body.contains("runtime-secret"));
        assert!(!body.contains("tenant-a"));
    }
}

#[tokio::test]
async fn fleet_status_requires_auth_and_returns_report() {
    let (app, _) = app();
    let denied = app
        .clone()
        .oneshot(
            Request::get("/v1/fleet/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let allowed = app
        .oneshot(
            Request::get("/v1/fleet/status")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(allowed.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(body.contains("prod"));
    assert!(body.contains("environment_count"));
    assert!(!body.contains("management-secret"));
    assert!(!body.contains("runtime-secret"));
}

#[tokio::test]
async fn management_env_list_requires_auth_and_returns_rows() {
    let (app, _) = app();
    let denied = app
        .clone()
        .oneshot(
            Request::get("/v1/environments")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let bad = app
        .clone()
        .oneshot(
            Request::get("/v1/environments")
                .header("authorization", "Bearer wrong-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::FORBIDDEN);

    let allowed = app
        .oneshot(
            Request::get("/v1/environments")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(allowed.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(body.contains("prod"));
    assert!(!body.contains("management-secret"));
    assert!(!body.contains("runtime-secret"));
}

#[tokio::test]
async fn forged_tenant_header_does_not_select_authority() {
    let (app, store) = app();
    // Caller-selected tenant headers are rejected; they cannot select authority.
    let denied = app
        .clone()
        .oneshot(
            Request::post("/v1/reconcile")
                .header("authorization", "Bearer management-secret")
                .header("x-tenkai-tenant", "forged-tenant")
                .header("x-tenant-id", "forged-tenant")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

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
    let events = store.audit_events().unwrap();
    let encoded = serde_json::to_string(&events).unwrap();
    assert!(encoded.contains("management"));
    assert!(!encoded.contains("forged-tenant"));
    assert!(!encoded.contains("management-secret"));
}
