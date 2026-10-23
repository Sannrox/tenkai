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
        let status: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            status["contracts"],
            serde_json::json!(["tenkai.http.v1", "tenkai.management-lifecycle.v1"])
        );
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
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        bad.headers()["www-authenticate"],
        "Bearer error=\"invalid_token\""
    );

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

#[tokio::test]
async fn backups_are_fleet_management_and_their_age_shows_in_health() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-http-backup-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(root.join("tenkai.db")).unwrap());
    let backups = Arc::new(
        tenkai::backup::Backups::new(
            store.clone(),
            tenkai::backup::BackupPolicy {
                dir: root.join("backups"),
                retain: 3,
                max_age_ms: 3_600_000,
            },
        )
        .unwrap(),
    );
    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config
        .environment_management_assignments
        .insert("prod-secret".into(), "prod".into());
    config.backups = Some(backups);
    let app = router(
        config,
        Arc::new(super::support::FixedReconciler::default()),
        store,
    )
    .unwrap();
    let call = |method: &str, path: &str, token: Option<&str>| {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let app = app.clone();
        let request = request.body(Body::empty()).unwrap();
        async move {
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
        }
    };

    let (_, health) = call("GET", "/readyz", None).await;
    assert_eq!(health["backup"]["state"], "missing");
    assert_eq!(
        call("POST", "/v1/backups", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Backups cover the whole hub: an environment-scoped token is refused.
    assert_eq!(
        call("POST", "/v1/backups", Some("prod-secret")).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, manifest) = call("POST", "/v1/backups", Some("management-secret")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(manifest["sha256"].as_str().unwrap().starts_with("sha256:"));
    let (_, backup_status) = call("GET", "/v1/backups", Some("management-secret")).await;
    assert_eq!(backup_status["last_success"]["file"], manifest["file"]);
    let (status, health) = call("GET", "/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health["backup"]["state"], "ok");
    let _ = std::fs::remove_dir_all(root);
}
