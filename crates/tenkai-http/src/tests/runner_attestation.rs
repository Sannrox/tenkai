//! Runner attestation over HTTP (#675): the policy has its own route and
//! audit event; a server that requires attestation answers an enrollment
//! without evidence with 428 and keeps the token, and binds evidence the
//! runner signed with its CSR key.

use super::lifecycle_support::lifecycle_router;
use super::support::router_generation;
use super::*;

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn an_environment_requiring_attestation_enrolls_only_attested_runners() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-runner-attestation-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (_, mut config, store) = lifecycle_router(&root).await;
    let (cert, key) = tenkai::runner_ca::RunnerCa::generate("runner CA").unwrap();
    config.runner_ca = Some(Arc::new(
        tenkai::runner_ca::RunnerCa::from_pem(&cert, &key).unwrap(),
    ));
    // Behind a TLS-terminating proxy no runner certificate reaches the
    // server, so the policy cannot be enabled there.
    {
        let proxied = router(
            config.clone(),
            Arc::new(
                tenkai::reconciler::Reconciler::new(
                    tenkai::client::Ctx::embedded(root.join("tenkai.db")).unwrap(),
                    tenkai::reconciler::Config::default(),
                )
                .unwrap(),
            ),
            store.clone(),
        )
        .unwrap();
        let generation = router_generation(&proxied, "stage").await;
        let (status, body) = call(
            &proxied,
            "PUT",
            "/v1/environments/stage/runner-attestation",
            Some("stage-secret"),
            serde_json::json!({
                "version": 1, "operation": "configure", "environment": "stage",
                "expected_generation": generation, "reason": "bind runners",
                "change": {"kind": "set_runner_attestation", "max_age_ms": 600_000},
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("TLS-terminating proxy")
        );
    }
    config.runner_certificates_admitted = true;
    let mut ctx = tenkai::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    let reconciler =
        tenkai::reconciler::Reconciler::new(ctx.clone(), tenkai::reconciler::Config::default())
            .unwrap();
    let app = router(config, Arc::new(reconciler), store.clone()).unwrap();

    let policy = "/v1/environments/stage/runner-attestation";
    let change = |kind: serde_json::Value, generation: u64| {
        serde_json::json!({
            "version": 1,
            "operation": "configure",
            "environment": "stage",
            "expected_generation": generation,
            "reason": "bind runners to their hosts",
            "change": kind,
        })
    };
    let generation = router_generation(&app, "stage").await;
    let set = serde_json::json!({"kind": "set_runner_attestation", "max_age_ms": 600_000});
    let (status, _) = call(&app, "PUT", policy, None, change(set.clone(), generation)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let bad = serde_json::json!({"kind": "set_runner_attestation", "max_age_ms": 0});
    let (status, _) = call(
        &app,
        "PUT",
        policy,
        Some("stage-secret"),
        change(bad, generation),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = call(
        &app,
        "PUT",
        policy,
        Some("stage-secret"),
        change(set, generation),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, issued) = call(
        &app,
        "POST",
        "/v1/environments/stage/runtime-enrollments",
        Some("management-secret"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["token"].as_str().unwrap();
    let runner_key = rcgen::KeyPair::generate().unwrap();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(&runner_key)
        .unwrap()
        .pem()
        .unwrap();
    let enroll = "/v1/runtime/environments/stage/enroll";
    let (status, body) = call(
        &app,
        "POST",
        enroll,
        None,
        serde_json::json!({"token": token, "csr": csr}),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("attestation_missing")
    );
    let attestation = tenkai::runner_attestation::sign(
        "stage",
        Vec::new(),
        Default::default(),
        &runner_key.serialize_pem(),
        &csr,
        tenkai::now_millis(),
    )
    .unwrap();
    let (status, enrolled) = call(
        &app,
        "POST",
        enroll,
        None,
        serde_json::json!({"token": token, "csr": csr, "attestation": attestation}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the refusal kept the token: {enrolled}"
    );
    let (status, listed) = call(
        &app,
        "GET",
        "/v1/runners",
        Some("management-secret"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let runner = listed["runners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|runner| runner["id"] == enrolled["credential_id"])
        .unwrap();
    assert_eq!(
        runner["attestation"]["key_fingerprint"],
        tenkai::runner_attestation::csr_fingerprint(&csr).unwrap()
    );

    let generation = router_generation(&app, "stage").await;
    let (status, _) = call(
        &app,
        "DELETE",
        policy,
        Some("stage-secret"),
        change(
            serde_json::json!({"kind": "clear_runner_attestation"}),
            generation,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let actions: Vec<String> = tenkai::environment_config::audit(&mut ctx, "stage")
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.outcome == "completed")
        .map(|event| event.action)
        .collect();
    assert_eq!(
        actions,
        ["set_runner_attestation", "clear_runner_attestation"]
    );
    let _ = std::fs::remove_dir_all(&root);
}
