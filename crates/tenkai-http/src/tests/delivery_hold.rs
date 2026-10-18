use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::*;

fn hold_body(environment: &str, operation: &str, generation: u64, reason: Option<&str>) -> Vec<u8> {
    let mut body = serde_json::json!({
        "version": 1,
        "operation": operation,
        "environment": environment,
        "expected_generation": generation
    });
    if let Some(reason) = reason {
        body["reason"] = reason.into();
    }
    serde_json::to_vec(&body).unwrap()
}

#[tokio::test]
async fn hold_set_release_and_retry_require_auth_and_management() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-hold-auth-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config, _) = lifecycle_router(&root).await;
    let body = hold_body("stage", "hold", 0, Some("freeze"));
    let unauthenticated = app
        .clone()
        .oneshot(
            Request::post("/v1/environments/stage/hold")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let runtime = app
        .clone()
        .oneshot(
            Request::post("/v1/environments/stage/hold")
                .header("authorization", "Bearer runtime-secret")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(runtime.status(), StatusCode::FORBIDDEN);

    let retry_body = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "operation": "retry",
        "environment": "stage",
        "expected_generation": 0,
        "product": "api",
        "reason": "retry"
    }))
    .unwrap();
    let retry_unauthenticated = app
        .clone()
        .oneshot(
            Request::post("/v1/environments/stage/failed-targets/api/retry")
                .header("content-type", "application/json")
                .body(Body::from(retry_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retry_unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let retry = app
        .clone()
        .oneshot(
            Request::post("/v1/environments/stage/failed-targets/api/retry")
                .header("authorization", "Bearer runtime-secret")
                .header("content-type", "application/json")
                .body(Body::from(retry_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::FORBIDDEN);

    let release = hold_body("stage", "release", 0, None);
    let release_unauthenticated = app
        .clone()
        .oneshot(
            Request::post("/v1/environments/stage/hold/release")
                .header("content-type", "application/json")
                .body(Body::from(release.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(release_unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let release_runtime = app
        .clone()
        .oneshot(
            Request::post("/v1/environments/stage/hold/release")
                .header("authorization", "Bearer runtime-secret")
                .header("content-type", "application/json")
                .body(Body::from(release))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(release_runtime.status(), StatusCode::FORBIDDEN);
    let other_env = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/prod/hold")
                .header("authorization", "Bearer runtime-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other_env.status(), StatusCode::FORBIDDEN);
    let channel = app
        .oneshot(
            Request::get("/v1/products/api/channels/stable/hold")
                .header("authorization", "Bearer runtime-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(channel.status(), StatusCode::FORBIDDEN);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn remote_hold_set_release_retry_and_stale_generation() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-hold-remote-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config, store) = lifecycle_router(&root).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");
    let client = RemoteClient::new(&base, "management-secret").unwrap();
    let first = signed_catalog_fixture(&root, "1.0.0");
    client.publish_release(&first).await.unwrap();
    client.promote_release("api@1.0.0", "stable").await.unwrap();
    client
        .subscribe_environment("stage", "api=stable", 0)
        .await
        .unwrap();

    let held = client
        .set_environment_hold("stage", "change freeze", 0)
        .await
        .unwrap();
    assert!(held.message.contains("change freeze"), "{}", held.message);
    let view = client.environment_hold("stage").await.unwrap();
    assert_eq!(view.hold.as_ref().unwrap().reason, "change freeze");
    assert_eq!(view.audit.len(), 1);
    assert_eq!(view.audit[0].action, "set");

    let inspect = client.inspect_environment("stage").await.unwrap();
    assert_eq!(
        inspect.delivery_hold.as_ref().unwrap().reason,
        "change freeze"
    );

    store
        .acquire_lease("stage", "hold-fence", tenkai::now_millis() + 60_000)
        .unwrap();
    let current = store.current_lease("stage").unwrap().unwrap().generation;
    let stale = client
        .release_environment_hold("stage", 0)
        .await
        .unwrap_err()
        .to_string();
    assert!(stale.contains("stale fencing generation"), "{stale}");

    let cleared = client
        .release_environment_hold("stage", current)
        .await
        .unwrap();
    assert!(cleared.message.contains("cleared"), "{}", cleared.message);
    assert!(
        client
            .environment_hold("stage")
            .await
            .unwrap()
            .hold
            .is_none()
    );

    let channel_hold = client
        .set_channel_hold("api", "stable", "pause stable")
        .await
        .unwrap();
    assert!(
        channel_hold.message.contains("pause stable"),
        "{}",
        channel_hold.message
    );
    let channel_view = client.channel_hold("api", "stable").await.unwrap();
    assert_eq!(channel_view.hold.unwrap().reason, "pause stable");
    client.release_channel_hold("api", "stable").await.unwrap();

    let missing = client
        .retry_failed_target("stage", "api", "retry after fix", current)
        .await
        .unwrap_err()
        .to_string();
    assert!(missing.contains("no held failed target"), "{missing}");
    let stale_retry = client
        .retry_failed_target("stage", "api", "retry after fix", 0)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        stale_retry.contains("stale fencing generation"),
        "{stale_retry}"
    );
    let _ = std::fs::remove_dir_all(root);
}
