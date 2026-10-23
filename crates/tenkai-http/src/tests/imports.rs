use super::*;

#[tokio::test]
async fn import_routes_take_staged_names_and_record_refusals() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-http-import-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let staging = root.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("site-c.json"), b"not a bundle").unwrap();
    // Any valid trust roots: this test never gets as far as a signature.
    super::lifecycle_support::signed_catalog_fixture(&root, "1.0.0");
    let database = root.join("tenkai.db");
    let mut ctx = tenkai::client::Ctx::embedded(&database).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    tenkai::plan::env_add(&mut ctx, "site-c", "isolated")
        .await
        .unwrap();
    let reconciler =
        tenkai::reconciler::Reconciler::new(ctx, tenkai::reconciler::Config::default()).unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(&database).unwrap());
    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config
        .environment_management_assignments
        .insert("other-secret".into(), "site-d".into());
    config.imports = Some(tenkai::offline_import::ImportSettings {
        staging: staging.clone(),
        trust_roots: root.join("trust-roots.toml"),
    });
    let app = router(config, Arc::new(reconciler), store).unwrap();
    let call = |method: &str, path: &str, token: Option<&str>, body: Option<serde_json::Value>| {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let body = body.map(|body| body.to_string()).unwrap_or_default();
        let request = request.body(Body::from(body)).unwrap();
        let app = app.clone();
        async move {
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
            )
        }
    };
    let import = |bundle: &str| {
        serde_json::json!({
            "version": 1, "operation": "import", "bundle": bundle,
            "upgrade": "fleet-1", "environment": "site-c", "dry_run": true
        })
    };

    assert_eq!(
        call("GET", "/v1/imports/staged", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, staged) = call("GET", "/v1/imports/staged", Some("management-secret"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(staged[0]["file"], "site-c.json");
    assert!(staged[0]["unreadable"].is_string());
    // A token scoped to another environment cannot import for site-c.
    assert_eq!(
        call(
            "POST",
            "/v1/imports",
            Some("other-secret"),
            Some(import("site-c.json"))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // A path is never accepted: the refusal is recorded on the job.
    let (status, job) = call(
        "POST",
        "/v1/imports",
        Some("management-secret"),
        Some(import("../tenkai.db.json")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(job["state"], "failed");
    assert!(
        job["refusal"].as_str().unwrap().contains("not a path"),
        "{job}"
    );
    let (status, fetched) = call(
        "GET",
        &format!("/v1/imports/{}", job["id"].as_str().unwrap()),
        Some("management-secret"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched, job);
    assert_eq!(
        call(
            "GET",
            "/v1/imports/imp-unknown",
            Some("management-secret"),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (status, inventory) = call(
        "GET",
        "/v1/content/inventory",
        Some("management-secret"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(inventory["releases"].is_array());
    let _ = std::fs::remove_dir_all(root);
}
