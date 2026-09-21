use super::support::app;
use super::*;

async fn post_runtime(app: Router, route: &str, body: serde_json::Value) -> StatusCode {
    app.oneshot(
        Request::post(format!("/v1/runtime/environments/prod/{route}"))
            .header("authorization", "Bearer runtime-secret")
            .header("x-tenkai-runtime-instance", "rt-1")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

#[tokio::test]
async fn runtime_http_bodies_reject_unknown_fields() {
    let (app, _store) = app();
    let completion = serde_json::json!({
        "plan_id": "plan-1",
        "generation": 1,
        "succeeded": true,
        "detail": "deployed",
        "receipts": [],
        "extension": true
    });
    let heartbeat = serde_json::json!({
        "plan_id": "plan-1",
        "generation": 1,
        "extension": true
    });
    let inventory = serde_json::json!({
        "facts": { "architecture": "arm64" },
        "source": "runtime-probe",
        "extension": true
    });
    let nested_receipt = serde_json::json!({
        "plan_id": "plan-1",
        "generation": 1,
        "succeeded": true,
        "detail": "deployed",
        "receipts": [{
            "step_id": "step-1",
            "succeeded": true,
            "detail": "ok",
            "extension": true
        }]
    });

    for (route, body) in [
        ("complete", completion),
        ("complete", nested_receipt),
        ("heartbeat", heartbeat),
        ("inventory", inventory),
    ] {
        let status = post_runtime(app.clone(), route, body).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{route} must reject an unknown field at decode, before any claim check"
        );
    }
}

#[tokio::test]
async fn runtime_http_bodies_still_accept_the_documented_fields() {
    let (app, _store) = app();
    let inventory = serde_json::json!({
        "facts": { "architecture": "arm64" },
        "source": "runtime-probe"
    });
    let status = post_runtime(app, "inventory", inventory).await;
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn runtime_work_rejects_unknown_fields() {
    let known = serde_json::json!({
        "environment": "prod",
        "plan": null,
        "claim": null
    });
    assert!(serde_json::from_value::<RuntimeWork>(known.clone()).is_ok());

    let mut widened = known;
    widened["extension"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RuntimeWork>(widened).is_err());
}
