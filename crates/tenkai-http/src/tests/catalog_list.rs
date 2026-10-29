use super::lifecycle_support::{catalog_router, migration_fixture, signed_catalog_fixture};
use super::*;

async fn get_json(
    app: &Router,
    path: &str,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::get(path);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
        })
    };
    (status, body)
}

async fn publish(app: &Router, request: &tenkai::management_lifecycle::PublishRequest) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/releases")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn promote(app: &Router, spec: &str, channel: &str) {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!("/v1/channels/{channel}/promote"))
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&tenkai::management_lifecycle::PromoteRequest {
                        version: 1,
                        operation: "promote".into(),
                        spec: spec.into(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "promote {spec} {channel}"
    );
}

#[tokio::test]
async fn catalog_lists_require_read_and_empty_catalog_is_an_empty_page() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-catalog-list-empty-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _) = catalog_router(&root).await;

    for path in ["/v1/releases", "/v1/channels", "/v1/migrations"] {
        let (status, _) = get_json(&app, path, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        let (status, body) = get_json(&app, path, Some("management-secret")).await;
        assert_eq!(status, StatusCode::OK, "{path} {body}");
        assert_eq!(body["items"], serde_json::json!([]), "{path}");
        assert!(body.get("next_cursor").is_none(), "{path} {body}");
    }
    let (status, _) = get_json(
        &app,
        "/v1/exposures?component=openssl&range=%3E%3D1.0.0",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = get_json(
        &app,
        "/v1/exposures?component=openssl&range=%3E%3D1.0.0",
        Some("management-secret"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["matches"], serde_json::json!([]), "{body}");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn release_list_pages_identifying_digest_and_version() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-catalog-list-releases-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _) = catalog_router(&root).await;
    for version in ["1.0.0", "1.1.0", "1.2.0"] {
        publish(&app, &signed_catalog_fixture(&root, version)).await;
    }

    let (status, first) = get_json(&app, "/v1/releases?limit=1", Some("management-secret")).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let items = first["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["product"], "api");
    assert_eq!(items[0]["version"], "1.0.0");
    assert!(!items[0]["digest"].as_str().unwrap_or_default().is_empty());
    assert_eq!(items[0]["id"], "tenkai:release:api@1.0.0");
    let cursor = first["next_cursor"].as_str().expect("next_cursor");

    let (status, second) = get_json(
        &app,
        &format!("/v1/releases?limit=1&cursor={cursor}"),
        Some("management-secret"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["items"][0]["version"], "1.1.0");
    let cursor = second["next_cursor"].as_str().expect("next_cursor");

    let (status, last) = get_json(
        &app,
        &format!("/v1/releases?limit=1&cursor={cursor}"),
        Some("management-secret"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{last}");
    assert_eq!(last["items"][0]["version"], "1.2.0");
    assert!(last.get("next_cursor").is_none(), "{last}");

    let (status, all) = get_json(&app, "/v1/releases", Some("management-secret")).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert_eq!(all["items"].as_array().unwrap().len(), 3);
    assert!(all.get("next_cursor").is_none());
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn channel_list_pages_head_and_holds() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-catalog-list-channels-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _) = catalog_router(&root).await;
    publish(&app, &signed_catalog_fixture(&root, "1.0.0")).await;
    promote(&app, "api@1.0.0", "beta").await;
    promote(&app, "api@1.0.0", "stable").await;

    let held = app
        .clone()
        .oneshot(
            Request::post("/v1/products/api/channels/stable/hold")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&tenkai::management_lifecycle::ChannelHoldRequest {
                        version: 1,
                        operation: "channel_hold".into(),
                        reason: Some("pause stable".into()),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(held.status(), StatusCode::OK);

    let (status, first) = get_json(&app, "/v1/channels?limit=1", Some("management-secret")).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    let cursor = first["next_cursor"].as_str().expect("next_cursor");
    let (status, second) = get_json(
        &app,
        &format!("/v1/channels?limit=1&cursor={cursor}"),
        Some("management-secret"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert!(second.get("next_cursor").is_none(), "{second}");

    let (status, all) = get_json(&app, "/v1/channels", Some("management-secret")).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    let items = all["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let stable = items
        .iter()
        .find(|item| item["name"] == "stable")
        .expect("stable");
    let beta = items
        .iter()
        .find(|item| item["name"] == "beta")
        .expect("beta");
    assert_eq!(stable["product"], "api");
    assert_eq!(stable["head"], "tenkai:release:api@1.0.0");
    assert_eq!(stable["hold"]["reason"], "pause stable");
    assert_eq!(beta["head"], "tenkai:release:api@1.0.0");
    assert!(beta.get("hold").is_none(), "{beta}");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn migration_list_pages_current_state() {
    let mut fixture = migration_fixture("list").await;
    for name in ["alpha", "beta"] {
        tenkai::package_migration::create(
            &mut fixture.ctx,
            name,
            "local",
            fixture.declaration.clone(),
            None,
        )
        .await
        .unwrap();
    }
    let reconciler = tenkai::reconciler::Reconciler::new(
        fixture.ctx.clone(),
        tenkai::reconciler::Config::default(),
    )
    .unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(&fixture.database).unwrap());
    let app = router(
        ServerConfig::community("management-secret", HashMap::new()),
        Arc::new(reconciler),
        store,
    )
    .unwrap();

    let (status, first) = get_json(&app, "/v1/migrations?limit=1", Some("management-secret")).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["items"][0]["status"], "admitted");
    let cursor = first["next_cursor"].as_str().expect("next_cursor");
    let (status, last) = get_json(
        &app,
        &format!("/v1/migrations?limit=1&cursor={cursor}"),
        Some("management-secret"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{last}");
    assert_eq!(last["items"].as_array().unwrap().len(), 1);
    assert!(last.get("next_cursor").is_none(), "{last}");
    let names: std::collections::BTreeSet<_> = [
        first["items"][0]["name"].as_str(),
        last["items"][0]["name"].as_str(),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert_eq!(names, ["alpha", "beta"].into_iter().collect());
    let _ = std::fs::remove_dir_all(fixture.root);
}

#[tokio::test]
async fn catalog_lists_refuse_tenant_mode() {
    use super::auth_support::TenantAssertionExtension;
    use super::support::FixedReconciler;
    use tenkai::runtime_capabilities::enterprise_auth_capabilities;
    use tenkai::tenant_store::tenant_memory_store_capabilities;

    let tenant_store = Arc::new(tenkai::tenant_store::InMemoryTenantOperationalStore::new());
    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config.requirements.tenant_mode = true;
    config.requirements.require_enterprise_authentication = true;
    config.capabilities = tenkai::runtime_capabilities::ProvidedCapabilities::assemble(
        "enterprise-tenant-memory",
        [
            tenant_memory_store_capabilities(),
            enterprise_auth_capabilities(),
        ],
    );
    config.auth_host = AuthHostConfig {
        required_extension_id: Some("auth.enterprise".into()),
        expected_contract_version: tenkai::auth_context::AUTH_CONTEXT_CONTRACT_VERSION,
        expected_audience: Some("tenkai-server".into()),
    };
    config.enterprise_auth = Some(Arc::new(TenantAssertionExtension));
    config.tenant_store = Some(tenant_store);
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    let app = router(config, Arc::new(FixedReconciler::default()), store).unwrap();
    let assertion =
        r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#;

    for path in ["/v1/releases", "/v1/channels"] {
        let response = app
            .clone()
            .oneshot(
                Request::get(path)
                    .header("x-tenkai-assertion", assertion)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body.contains("remote catalog lifecycle is not available in tenant mode"),
            "{path} {body}"
        );
    }
}

#[tokio::test]
async fn catalog_lists_serve_bound_tenant_catalog() {
    use super::auth_support::TenantAssertionExtension;
    use super::support::FixedReconciler;
    use tenkai::ontology::{KIND_CHANNEL, KIND_RELEASE};
    use tenkai::pb::sekai::Object;
    use tenkai::runtime_capabilities::enterprise_auth_capabilities;
    use tenkai::storage::{CatalogGraph, MemoryCatalogGraph};
    use tenkai::tenant_store::tenant_memory_store_capabilities;

    let graph = Arc::new(MemoryCatalogGraph::new());
    graph
        .create(
            Some("tenant-a"),
            Object {
                id: "tenkai:release:api@1.0.0".into(),
                kind: KIND_RELEASE.into(),
                name: "api@1.0.0".into(),
                properties: [
                    ("product".into(), "api".into()),
                    ("version".into(), "1.0.0".into()),
                    ("digest".into(), "sha256:test".into()),
                ]
                .into_iter()
                .collect(),
                ..Object::default()
            },
        )
        .unwrap();
    graph
        .create(
            Some("tenant-a"),
            Object {
                id: "tenkai:channel:api/stable".into(),
                kind: KIND_CHANNEL.into(),
                name: "stable".into(),
                properties: [
                    ("product".into(), "api".into()),
                    ("name".into(), "stable".into()),
                    ("current_release".into(), "tenkai:release:api@1.0.0".into()),
                ]
                .into_iter()
                .collect(),
                ..Object::default()
            },
        )
        .unwrap();

    let tenant_store = Arc::new(tenkai::tenant_store::InMemoryTenantOperationalStore::new());
    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config.requirements.tenant_mode = true;
    config.requirements.require_enterprise_authentication = true;
    config.capabilities = tenkai::runtime_capabilities::ProvidedCapabilities::assemble(
        "enterprise-tenant-memory",
        [
            tenant_memory_store_capabilities(),
            enterprise_auth_capabilities(),
        ],
    );
    config.auth_host = AuthHostConfig {
        required_extension_id: Some("auth.enterprise".into()),
        expected_contract_version: tenkai::auth_context::AUTH_CONTEXT_CONTRACT_VERSION,
        expected_audience: Some("tenkai-server".into()),
    };
    config.enterprise_auth = Some(Arc::new(TenantAssertionExtension));
    config.tenant_store = Some(tenant_store);
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    let app = router(
        config,
        Arc::new(FixedReconciler::with_ctx(
            tenkai::client::Ctx::tenant_hub_catalog(graph),
        )),
        store,
    )
    .unwrap();
    let tenant_a =
        r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#;
    let tenant_b =
        r#"{"tenant":"tenant-b","principal":"user-b","capabilities":["read","management"]}"#;

    let (status, body) = get_json_assertion(&app, "/v1/releases", tenant_a).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["items"][0]["id"], "tenkai:release:api@1.0.0");
    assert_eq!(body["items"][0]["product"], "api");

    let (status, body) = get_json_assertion(&app, "/v1/channels", tenant_a).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["items"][0]["name"], "stable");

    let (status, body) = get_json_assertion(&app, "/v1/releases", tenant_b).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"], serde_json::json!([]), "{body}");
}

async fn get_json_assertion(
    app: &Router,
    path: &str,
    assertion: &str,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::get(path)
                .header("x-tenkai-assertion", assertion)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
        })
    };
    (status, body)
}

#[tokio::test]
async fn catalog_list_rejects_invalid_limit() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-catalog-list-limit-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _) = catalog_router(&root).await;
    let (status, body) = get_json(&app, "/v1/releases?limit=0", Some("management-secret")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let _ = std::fs::remove_dir_all(root);
}
