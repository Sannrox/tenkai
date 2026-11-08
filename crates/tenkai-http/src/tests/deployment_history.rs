use super::support::{FixedReconciler, app_with_reconciler};
use super::*;

use tenkai::ontology::{KIND_DEPLOYMENT, NS, deployment_id};
use tenkai::pb::sekai::Object;

fn attempt(env: &str, instance: &str, created: i64, status: &str, detail: &str) -> Object {
    Object {
        id: deployment_id(env, instance, created),
        kind: KIND_DEPLOYMENT.into(),
        name: format!("{instance} ({env})"),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("environment".into(), env.into()),
            ("product".into(), instance.into()),
            ("instance".into(), instance.into()),
            ("from_version".into(), "1.0.0".into()),
            ("to_version".into(), "1.1.0".into()),
            ("status".into(), status.into()),
            ("detail".into(), detail.into()),
            ("action".into(), "upgrade".into()),
            ("plan_id".into(), "tenkai:plan:prod:1".into()),
        ]),
        created,
        updated: created,
    }
}

#[tokio::test]
async fn history_route_returns_newest_first_and_filters_product() {
    let database = std::env::temp_dir().join(format!(
        "tenkai-http-history-{}-{}.db",
        std::process::id(),
        tenkai::now_millis()
    ));
    let _ = std::fs::remove_file(&database);
    let mut ctx = tenkai::client::Ctx::embedded(&database).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    tenkai::environment::env_add(&mut ctx, "prod", "prod")
        .await
        .unwrap();
    ctx.put(attempt("prod", "api", 1_000, "failed", "probe failed"))
        .await
        .unwrap();
    ctx.put(attempt("prod", "web", 2_000, "succeeded", ""))
        .await
        .unwrap();
    let (app, _store) = app_with_reconciler(FixedReconciler::with_ctx(ctx));
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/prod/history?limit=10")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page: tenkai::deployment_history::DeploymentHistoryPage = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        page.items
            .iter()
            .map(|item| (
                item.instance.as_str(),
                item.status.as_str(),
                item.detail.as_str()
            ))
            .collect::<Vec<_>>(),
        [("web", "succeeded", ""), ("api", "failed", "probe failed")]
    );

    let filtered = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/prod/history?product=api")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(filtered.status(), StatusCode::OK);
    let api: tenkai::deployment_history::DeploymentHistoryPage = serde_json::from_slice(
        &axum::body::to_bytes(filtered.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(api.items.len(), 1);
    assert_eq!(api.items[0].instance, "api");
    assert_eq!(api.items[0].detail, "probe failed");

    let missing = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/absent/history")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let bad_limit = app
        .oneshot(
            Request::get("/v1/environments/prod/history?limit=0")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_limit.status(), StatusCode::BAD_REQUEST);
    let _ = std::fs::remove_file(&database);
}
