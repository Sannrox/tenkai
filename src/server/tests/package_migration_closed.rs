use super::lifecycle_support::migration_preview_body;
use super::support::app;
use super::*;

#[tokio::test]
async fn package_migration_routes_fail_closed_without_application_ctx() {
    let (app, _store) = app();
    let unauthenticated = app
        .clone()
        .oneshot(
            Request::post("/v1/migrations/cutover/preview")
                .header("content-type", "application/json")
                .body(Body::from(migration_preview_body("local", 1)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let unknown_version = app
        .clone()
        .oneshot(
            Request::post("/v1/migrations/cutover/preview")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(migration_preview_body("local", 99)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_version.status(), StatusCode::BAD_REQUEST);
    let unknown_body = String::from_utf8(
        axum::body::to_bytes(unknown_version.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        unknown_body.contains("unsupported package migration API version 99"),
        "{unknown_body}"
    );

    let mut bypass =
        serde_json::from_slice::<serde_json::Value>(&migration_preview_body("local", 1)).unwrap();
    bypass.as_object_mut().unwrap().insert(
        "allow_unapproved_development".into(),
        serde_json::json!(true),
    );
    let bypassed = app
        .clone()
        .oneshot(
            Request::post("/v1/migrations/cutover/preview")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&bypass).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bypassed.status(), StatusCode::BAD_REQUEST);
    let bypass_body = String::from_utf8(
        axum::body::to_bytes(bypassed.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(bypass_body.contains("unknown field"), "{bypass_body}");
    assert!(!bypass_body.contains("management-secret"));

    let unavailable = app
        .clone()
        .oneshot(
            Request::post("/v1/migrations/cutover/preview")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(migration_preview_body("local", 1)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

    let apply = app
        .oneshot(
            Request::post("/v1/migrations/cutover/apply")
                .header("authorization", "Bearer management-secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "version": 1,
                        "environment": "local",
                        "expected_generation": 0,
                        "declaration": serde_json::from_slice::<serde_json::Value>(
                            &migration_preview_body("local", 1)
                        ).unwrap()["declaration"],
                        "approval": {
                            "schema": "tenkai.package-migration-approval.v1",
                            "key_id": "k",
                            "statement": {
                                "identity_digest": format!("sha256:{}", "a".repeat(64)),
                                "environment": "local",
                                "purpose": "execute_package_migration",
                                "issued_at": 1,
                                "expires_at": 2
                            },
                            "signature": "c2ln"
                        },
                        "trust_roots": {
                            "version": 1,
                            "signers": [{
                                "key_id": "k",
                                "identity": "approver",
                                "public_key": "cA=="
                            }]
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(apply.status(), StatusCode::FORBIDDEN);
    let apply_body = String::from_utf8(
        axum::body::to_bytes(apply.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        apply_body.contains("trust roots are not configured"),
        "{apply_body}"
    );
}
