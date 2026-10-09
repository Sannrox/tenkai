use super::lifecycle_support::{catalog_router, signed_catalog_fixture};
use super::*;

#[tokio::test]
async fn software_compatibility_routes_preserve_scope_and_return_bounded_reports() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-http-compatibility-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _) = catalog_router(&root).await;
    let _ = signed_catalog_fixture(&root, "1.0.0");
    let manifest = root.join("tenkai.toml");
    let raw = std::fs::read_to_string(&manifest).unwrap()
        + &format!(
            "\n[compatibility]\nversion = 1\nmax_evidence_age_ms = 60000\n[compatibility.components.web.pin]\nkind = \"revision\"\nvalue = \"{}\"\n",
            "a".repeat(40)
        );
    std::fs::write(&manifest, &raw).unwrap();
    tenkai::dev_sign::sign_release(
        &root.join("keys"),
        &manifest,
        &root.join("signature.json"),
        &root.join("trust-roots.toml"),
    )
    .unwrap();
    let request = tenkai::management_lifecycle::load_publish_request(
        &manifest,
        &root.join("signature.json"),
        &root.join("trust-roots.toml"),
    )
    .unwrap();
    let response = app
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
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/stage/compatibility/api@1.0.0")
                .header("authorization", "Bearer stage-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let report: tenkai::software_compatibility::CompatibilityReport =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(
        report.failures,
        vec![tenkai::software_compatibility::CompatibilityFailure::MissingEvidence]
    );
    let evidence = serde_json::json!({
        "version": 1, "environment": "stage", "release_digest": tenkai::manifest::digest(&raw), "observed_at_ms": tenkai::now_millis(),
        "components": { "web": { "pin": { "kind": "revision", "value": "a".repeat(40) }, "provides": {} } },
        "contracts": {}, "capabilities": [], "schema_version": null, "migration": "stable"
    });
    for (token, environment, expected) in [
        ("stage-secret", "stage", StatusCode::OK),
        ("stage-secret", "prod", StatusCode::FORBIDDEN),
        ("runtime-secret", "stage", StatusCode::FORBIDDEN),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/v1/environments/{environment}/compatibility/evidence"
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&evidence).unwrap()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/stage/compatibility/api@1.0.0")
                .header("authorization", "Bearer stage-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let report: tenkai::software_compatibility::CompatibilityReport =
        serde_json::from_slice(&body).unwrap();
    assert!(report.failures.is_empty());
    assert_eq!(report.release_digest, tenkai::manifest::digest(&raw));
    let response = app
        .oneshot(
            Request::get("/v1/environments/prod/compatibility/api@1.0.0")
                .header("authorization", "Bearer stage-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    std::fs::remove_dir_all(root).unwrap();
}
