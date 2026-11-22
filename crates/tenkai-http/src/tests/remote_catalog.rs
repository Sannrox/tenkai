use super::lifecycle_support::{catalog_router, signed_catalog_fixture, signed_plan_requests};
use super::support::{current_generation, router_generation};
use super::*;

#[tokio::test]
async fn remote_catalog_lifecycle_publish_promote_subscribe_and_recall() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-remote-catalog-{}-{}",
        std::process::id(),
        tenkai::now_millis()
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
        tenkai::dev_sign::sign_release(
            &keys,
            &conflict_root.join("tenkai.toml"),
            &signature,
            &trust,
        )
        .unwrap();
        tenkai::management_lifecycle::load_publish_request(
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
                    serde_json::to_vec(&tenkai::management_lifecycle::PromoteRequest {
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

    let generation = router_generation(&app, "stage").await;
    let subscribed = app
        .clone()
        .oneshot(
            Request::post("/v1/environments/stage/subscriptions")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&tenkai::management_lifecycle::SubscribeRequest {
                        version: 1,
                        operation: "subscribe".into(),
                        environment: "stage".into(),
                        expected_generation: generation,
                        spec: "api=stable".into(),
                        instance: None,
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
                    serde_json::to_vec(&tenkai::management_lifecycle::RecallRequest {
                        version: 1,
                        operation: "recall".into(),
                        environments: Vec::new(),
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
                    serde_json::to_vec(&tenkai::management_lifecycle::PromoteRequest {
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
                    serde_json::to_vec(&tenkai::management_lifecycle::SubscribeRequest {
                        version: 1,
                        operation: "subscribe".into(),
                        environment: "prod".into(),
                        expected_generation: 0,
                        spec: "api=stable".into(),
                        instance: None,
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

    // The signed publish that succeeded above, plus the development bypass
    // flag: the flag is the only reason it is refused.
    let mut with_bypass = serde_json::to_value(&first).unwrap();
    with_bypass["allow_unsigned_development"] = serde_json::Value::Bool(true);
    let bypass = app
        .oneshot(
            Request::post("/v1/releases")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(with_bypass.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bypass.status(), StatusCode::BAD_REQUEST);
    let refusal = String::from_utf8(
        axum::body::to_bytes(bypass.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(refusal.contains("allow_unsigned_development"), "{refusal}");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn remote_publish_uploads_declared_deploy_inputs() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = std::env::temp_dir().join(format!(
        "tenkai-remote-publish-inputs-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(root.join("manifests")).unwrap();
    std::fs::write(
        root.join("tenkai.toml"),
        "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"deploy.sh\", \"manifests\"]\n",
    )
    .unwrap();
    let script = root.join("deploy.sh");
    std::fs::write(&script, b"#!/bin/sh\ntrue\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(root.join("manifests/app.yaml"), "kind: ConfigMap\n").unwrap();
    let (app, _config) = catalog_router(&root).await;
    let keys = root.join("keys");
    let signature = root.join("signature.json");
    let trust_roots = root.join("trust-roots.toml");
    tenkai::dev_sign::sign_release(&keys, &root.join("tenkai.toml"), &signature, &trust_roots)
        .unwrap();
    let request = tenkai::management_lifecycle::load_publish_request(
        &root.join("tenkai.toml"),
        &signature,
        &trust_roots,
    )
    .unwrap();
    assert!(!request.inputs.is_empty());

    let published = app
        .clone()
        .oneshot(
            Request::post("/v1/releases")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(published.status(), StatusCode::OK);

    let mut missing = request;
    missing.inputs.clear();
    let refused = app
        .oneshot(
            Request::post("/v1/releases")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&missing).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        axum::body::to_bytes(refused.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("missing declared deploy input"), "{body}");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn remote_environment_retirement_hides_listing_and_stops_runtime_polling() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-remote-environment-retirement-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _) = catalog_router(&root).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = app.clone();
    tokio::spawn(async move {
        axum::serve(listener, served).await.unwrap();
    });
    let client = RemoteClient::new(format!("http://{addr}"), "management-secret").unwrap();

    // Both environments get the same approved work. `prod` is the control:
    // its runtime is offered the plan. Polling `stage` first would claim its
    // plan, and a live claim refuses the retirement (#1294).
    client
        .publish_release(&signed_catalog_fixture(&root, "1.0.0"))
        .await
        .unwrap();
    client.promote_release("api@1.0.0", "stable").await.unwrap();
    let mut approved = Vec::new();
    for environment in ["stage", "prod"] {
        let generation = current_generation(&client, environment).await;
        client
            .subscribe_environment(environment, "api=stable", generation, None)
            .await
            .unwrap();
        let plan = client
            .plan_environment(environment, generation)
            .await
            .unwrap();
        let plan_id = plan.resource.clone().unwrap();
        let (approve, _) = signed_plan_requests(
            &root,
            &format!("approve-{environment}"),
            environment,
            &plan.digest.unwrap(),
            generation,
        );
        client.approve_plan(&plan_id, &approve).await.unwrap();
        approved.push(plan_id);
    }
    let work = |environment: &'static str, token: &'static str| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::get(format!("/v1/runtime/environments/{environment}/work"))
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-tenkai-runtime-instance", "runtime-test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<RuntimeWork>(&bytes).unwrap()
        }
    };

    let request = tenkai::management_lifecycle::RetireEnvironmentRequest {
        version: 1,
        operation: "retire".into(),
        reason: "service ended".into(),
    };
    let retire = || {
        Request::post("/v1/environments/stage/retire")
            .header("authorization", "Bearer management-secret")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&request).unwrap()))
            .unwrap()
    };
    let first = app.clone().oneshot(retire()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = axum::body::to_bytes(first.into_body(), usize::MAX)
        .await
        .unwrap();
    let repeat = app.clone().oneshot(retire()).await.unwrap();
    assert_eq!(repeat.status(), StatusCode::OK);
    let repeat_body = axum::body::to_bytes(repeat.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(first_body, repeat_body);

    let names = client
        .list_environments()
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect::<Vec<_>>();
    assert!(!names.iter().any(|name| name == "stage"), "{names:?}");
    assert!(names.iter().any(|name| name == "prod"), "{names:?}");

    let inspect = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/stage")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inspect.status(), StatusCode::OK);
    let inspect_body = String::from_utf8(
        axum::body::to_bytes(inspect.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(inspect_body.contains("service ended"), "{inspect_body}");
    assert!(
        inspect_body.contains("\"actor\":\"management\""),
        "{inspect_body}"
    );

    // The control environment's runtime is offered its approved plan; the
    // retired one, with the same approved work, is offered nothing.
    let control = work("prod", "runtime-prod-secret").await;
    assert_eq!(
        control.plan.as_ref().map(|plan| plan.id.as_str()),
        Some(approved[1].as_str())
    );
    let retired = work("stage", "runtime-secret").await;
    assert!(retired.plan.is_none(), "{:?}", retired.plan);
    assert!(retired.claim.is_none(), "{:?}", retired.claim);
    let _ = std::fs::remove_dir_all(root);
}
