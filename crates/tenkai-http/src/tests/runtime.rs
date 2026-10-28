use super::support::{FixedReconciler, app, app_with_reconciler};
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
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    config.metrics_enabled = true;
    let app = router(config, Arc::new(FixedReconciler::default()), store).unwrap();
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
    assert!(!tenkai::metrics::body_leaks_secret(
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
    let embedded = FixedReconciler::default().reconcile().await.unwrap();
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
    let (app, _) = app_with_reconciler(FixedReconciler::for_runtime());
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
    let claim = first.claim.unwrap();
    let generation = claim.generation;
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
                    serde_json::to_vec(&tenkai::runtime_delivery::RuntimeCompletion {
                        plan_id: claim.plan_id.clone(),
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

/// The runner registry lists the enrolled agent with its instance and
/// version, and the static token read-only, never a secret; revocation
/// needs a reason, which inspect shows (#673).
#[tokio::test]
async fn an_agent_enrolls_once_works_with_its_credential_and_stops_when_revoked() {
    // Issuing an enrollment marks the environment in the application core.
    let (app, _store) = app_with_reconciler(FixedReconciler::for_runtime());
    let call = |method: &str, path: &str, bearer: Option<&str>, body: serde_json::Value| {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("x-tenkai-runtime-instance", "rt-1")
            .header("x-tenkai-runtime-version", "0.5.0");
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        let app = app.clone();
        async move {
            let response = app
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
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
    let enrollments = "/v1/environments/prod/runtime-enrollments";
    let (status, _) = call("POST", enrollments, None, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, issued) = call(
        "POST",
        enrollments,
        Some("management-secret"),
        serde_json::json!({"ttl_seconds": 60}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["token"].as_str().unwrap().to_string();

    let enroll = "/v1/runtime/environments/prod/enroll";
    let (status, enrolled) = call("POST", enroll, None, serde_json::json!({"token": token})).await;
    assert_eq!(status, StatusCode::CREATED, "{enrolled}");
    let credential = enrolled["credential"].as_str().unwrap().to_string();
    let (status, _) = call("POST", enroll, None, serde_json::json!({"token": token})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a spent token is refused");

    let inventory = "/v1/runtime/environments/prod/inventory";
    let facts = serde_json::json!({"facts": {"architecture": "arm64"}, "source": "runtime-probe"});
    let (status, _) = call("POST", inventory, Some(&credential), facts.clone()).await;
    assert_eq!(status, StatusCode::OK);

    let id = enrolled["credential_id"].as_str().unwrap().to_string();
    let (status, listed) = call(
        "GET",
        "/v1/runners",
        Some("management-secret"),
        serde_json::json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let text = listed.to_string();
    assert!(
        !text.contains(&credential) && !text.contains(&token) && !text.contains("runtime-secret"),
        "the registry leaks a secret: {text}"
    );
    let runners = listed["runners"].as_array().unwrap();
    let agent = runners
        .iter()
        .find(|runner| runner["id"] == id.as_str())
        .unwrap();
    assert_eq!(agent["state"], "active");
    assert_eq!(agent["environment"], "prod");
    assert_eq!(agent["instances"][0]["instance_id"], "rt-1");
    assert_eq!(agent["instances"][0]["runtime_version"], "0.5.0");
    // Its skew against this server's version (#761).
    assert_eq!(
        agent["instances"][0]["skew"],
        tenkai::version_skew::skew(tenkai::version_skew::SERVER_VERSION, "0.5.0").unwrap()
    );
    assert!(agent["instances"][0]["last_inventory_at"].is_i64());
    let static_id = tenkai::runtime_credentials::digest("runtime-secret");
    let fixed = runners
        .iter()
        .find(|runner| runner["id"] == static_id.as_str())
        .unwrap();
    assert_eq!(fixed["state"], "static");

    let revoke = format!("/v1/runners/{id}/revoke");
    for body in [serde_json::json!(null), serde_json::json!({"reason": "  "})] {
        let (status, _) = call("POST", &revoke, Some("management-secret"), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a reason is required");
    }
    let (status, _) = call(
        "POST",
        &format!("/v1/runners/{static_id}/revoke"),
        Some("management-secret"),
        serde_json::json!({"reason": "rotate"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "static runners are configuration"
    );
    let (status, revoked) = call(
        "POST",
        &revoke,
        Some("management-secret"),
        serde_json::json!({"reason": "host retired"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    let (status, inspected) = call(
        "GET",
        &format!("/v1/runners/{id}"),
        Some("management-secret"),
        serde_json::json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{inspected}");
    assert_eq!(inspected["state"], "revoked");
    assert_eq!(inspected["revoke_reason"], "host retired");
    let (status, _) = call("POST", inventory, Some(&credential), facts).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a revoked credential is refused"
    );
}

/// #809: a runner enrolled with a CSR, which the runner CA certified,
/// reports `client_certificate`; one enrolled without a CSR and a static
/// token report `bearer`.
#[tokio::test]
async fn the_registry_reports_how_each_runner_authenticates() {
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    store
        .put_environment(&tenkai::storage::EnvironmentRecord {
            id: "prod".into(),
            revision: 0,
            configuration_json: "{}".into(),
        })
        .unwrap();
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    let (ca_cert, ca_key) = tenkai::runner_ca::RunnerCa::generate("test runner CA").unwrap();
    config.runner_ca = Some(Arc::new(
        tenkai::runner_ca::RunnerCa::from_pem(&ca_cert, &ca_key).unwrap(),
    ));
    let app = router(
        config,
        Arc::new(FixedReconciler::for_runtime()),
        store.clone(),
    )
    .unwrap();
    let call = |method: &str, path: &str, bearer: Option<&str>, body: serde_json::Value| {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        let app = app.clone();
        async move {
            let response = app
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
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
    let enroll = async |csr: Option<String>| {
        let (status, issued) = call(
            "POST",
            "/v1/environments/prod/runtime-enrollments",
            Some("management-secret"),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{issued}");
        let (status, enrolled) = call(
            "POST",
            "/v1/runtime/environments/prod/enroll",
            None,
            serde_json::json!({"token": issued["token"], "csr": csr}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{enrolled}");
        enrolled["credential_id"].as_str().unwrap().to_string()
    };
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let certified = enroll(Some(csr)).await;
    let bearer = enroll(None).await;

    let (status, listed) = call(
        "GET",
        "/v1/runners",
        Some("management-secret"),
        serde_json::json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let auth = |id: &str| {
        listed["runners"]
            .as_array()
            .unwrap()
            .iter()
            .find(|runner| runner["id"] == id)
            .map(|runner| runner["auth"].clone())
            .unwrap()
    };
    assert_eq!(auth(&certified), "client_certificate");
    assert_eq!(auth(&bearer), "bearer");
    assert_eq!(
        auth(&tenkai::runtime_credentials::digest("runtime-secret")),
        "bearer"
    );
}
