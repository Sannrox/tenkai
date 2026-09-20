use super::lifecycle_support::{catalog_router, signed_catalog_fixture};
use super::*;

#[tokio::test]
async fn remote_catalog_lifecycle_publish_promote_subscribe_and_recall() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-remote-catalog-{}-{}",
        std::process::id(),
        crate::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config) = catalog_router(&root).await;
    let first = signed_catalog_fixture(&root, "1.0.0");

    let published = app
        .clone()
        .oneshot(
            Request::post("/v1/releases")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&first).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(published.status(), StatusCode::OK,);
    let replay = app
        .clone()
        .oneshot(
            Request::post("/v1/releases")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&first).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_body = String::from_utf8(
        axum::body::to_bytes(replay.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(replay_body.contains("already published"), "{replay_body}");

    let conflict_root = root.join("conflict");
    std::fs::create_dir_all(&conflict_root).unwrap();
    std::fs::write(
        conflict_root.join("tenkai.toml"),
        "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"false\"\n",
    )
    .unwrap();
    let conflict = {
        let keys = conflict_root.join("keys");
        let signature = conflict_root.join("signature.json");
        let trust = conflict_root.join("trust-roots.toml");
        crate::dev_sign::sign_release(
            &keys,
            &conflict_root.join("tenkai.toml"),
            &signature,
            &trust,
        )
        .unwrap();
        crate::management_lifecycle::load_publish_request(
            &conflict_root.join("tenkai.toml"),
            &signature,
            &trust,
        )
        .unwrap()
    };
    let conflicting = app
        .clone()
        .oneshot(
            Request::post("/v1/releases")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&conflict).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflicting.status(), StatusCode::CONFLICT);

    let promoted = app
        .clone()
        .oneshot(
            Request::post("/v1/channels/stable/promote")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&crate::management_lifecycle::PromoteRequest {
                        version: 1,
                        operation: "promote".into(),
                        spec: "api@1.0.0".into(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(promoted.status(), StatusCode::OK);

    let subscribed = app
        .clone()
        .oneshot(
            Request::post("/v1/environments/stage/subscriptions")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&crate::management_lifecycle::SubscribeRequest {
                        version: 1,
                        operation: "subscribe".into(),
                        environment: "stage".into(),
                        expected_generation: 0,
                        spec: "api=stable".into(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(subscribed.status(), StatusCode::OK);

    let recalled = app
        .clone()
        .oneshot(
            Request::post("/v1/releases/api@1.0.0/recall")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&crate::management_lifecycle::RecallRequest {
                        version: 1,
                        operation: "recall".into(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recalled.status(), StatusCode::OK);

    let scoped_promote = app
        .clone()
        .oneshot(
            Request::post("/v1/channels/stable/promote")
                .header("authorization", "Bearer stage-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&crate::management_lifecycle::PromoteRequest {
                        version: 1,
                        operation: "promote".into(),
                        spec: "api@1.0.0".into(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scoped_promote.status(), StatusCode::FORBIDDEN);

    let scoped_other = app
        .clone()
        .oneshot(
            Request::post("/v1/environments/prod/subscriptions")
                .header("authorization", "Bearer stage-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&crate::management_lifecycle::SubscribeRequest {
                        version: 1,
                        operation: "subscribe".into(),
                        environment: "prod".into(),
                        expected_generation: 0,
                        spec: "api=stable".into(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scoped_other.status(), StatusCode::FORBIDDEN);

    let runtime = app
        .clone()
        .oneshot(
            Request::post("/v1/releases")
                .header("authorization", "Bearer runtime-secret")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&first).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(runtime.status(), StatusCode::FORBIDDEN);

    let bypass = app
        .oneshot(
            Request::post("/v1/releases")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "version": 1,
                        "operation": "publish",
                        "manifest": "[product]",
                        "allow_unsigned_development": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bypass.status(), StatusCode::BAD_REQUEST);
    let _ = std::fs::remove_dir_all(root);
}
