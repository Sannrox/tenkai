use super::lifecycle_support::catalog_router;
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

#[tokio::test]
async fn runtime_get_requires_read_and_returns_docker_and_model_runtime_fixtures() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-http-runtime-{}-{}-{}",
        std::process::id(),
        tenkai::now_millis(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _) = catalog_router(&root).await;
    let (status, _) = get_json(&app, "/v1/environments/stage/runtime", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut ctx = tenkai::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    tenkai::observed_runtime::persist(
        &mut ctx,
        "stage",
        &tenkai::observed_runtime::ObservedRuntimeComponent {
            product: "edge-app".into(),
            executor_kind: "docker".into(),
            health: None,
            units: vec![tenkai::observed_runtime::ObservedRuntimeUnit {
                name: "api".into(),
                image_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                restart_policy: "unless-stopped".into(),
                running: true,
                health: Some("healthy".into()),
            }],
            last_init_job: Some(tenkai::observed_runtime::ObservedInitJob {
                name: "init".into(),
                status: "exited".into(),
                exit_code: Some(0),
            }),
            model_runtime: None,
        },
    )
    .await
    .unwrap();
    tenkai::observed_runtime::persist(
        &mut ctx,
        "stage",
        &tenkai::observed_runtime::ObservedRuntimeComponent {
            product: "qwen".into(),
            executor_kind: "model_runtime".into(),
            health: None,
            units: Vec::new(),
            last_init_job: None,
            model_runtime: Some(tenkai::observed_runtime::ObservedModelRuntime {
                variant: "qwen@1.0.0".into(),
                accelerator: None,
                verified_weight_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
            }),
        },
    )
    .await
    .unwrap();
    tenkai::plan::set_environment_fact(&mut ctx, "stage", "accelerator", "nvidia")
        .await
        .unwrap();
    tenkai::environment::record_observed_health(&mut ctx, "stage", "qwen", true, "")
        .await
        .unwrap();

    let (status, body) = get_json(
        &app,
        "/v1/environments/stage/runtime",
        Some("management-secret"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["environment"], "stage");
    let components = body["components"].as_array().expect("components");
    assert_eq!(components.len(), 2, "{body}");
    assert_eq!(components[0]["product"], "edge-app");
    assert_eq!(components[0]["executor_kind"], "docker");
    assert_eq!(components[0]["units"][0]["name"], "api");
    assert_eq!(
        components[0]["units"][0]["image_digest"],
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(
        components[0]["units"][0]["restart_policy"],
        "unless-stopped"
    );
    assert_eq!(components[0]["units"][0]["running"], true);
    assert_eq!(components[0]["last_init_job"]["name"], "init");
    assert_eq!(components[0]["last_init_job"]["exit_code"], 0);
    assert_eq!(components[1]["product"], "qwen");
    assert_eq!(components[1]["executor_kind"], "model_runtime");
    assert_eq!(components[1]["health"], "healthy");
    assert_eq!(components[1]["model_runtime"]["variant"], "qwen@1.0.0");
    assert_eq!(components[1]["model_runtime"]["accelerator"], "nvidia");
    assert_eq!(
        components[1]["model_runtime"]["verified_weight_digest"],
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    let (status, empty) = get_json(
        &app,
        "/v1/environments/prod/runtime",
        Some("management-secret"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{empty}");
    assert_eq!(empty["environment"], "prod");
    assert_eq!(empty["components"], serde_json::json!([]));
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn runtime_get_unknown_environment_is_not_found() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-http-runtime-missing-{}-{}-{}",
        std::process::id(),
        tenkai::now_millis(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _) = catalog_router(&root).await;
    let (status, body) = get_json(
        &app,
        "/v1/environments/missing/runtime",
        Some("management-secret"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let _ = std::fs::remove_dir_all(root);
}
