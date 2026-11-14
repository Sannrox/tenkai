use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::support::current_generation;
use super::*;
use tenkai::spec_drift::{TargetChange, TargetFieldChange};

#[tokio::test]
async fn plan_step_target_changes_are_readable_over_http() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-plan-target-changes-http-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config, _store) = lifecycle_router(&root).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");
    let client = RemoteClient::new(&base, "management-secret").unwrap();
    client
        .publish_release(&signed_catalog_fixture(&root, "1.0.0"))
        .await
        .unwrap();
    client.promote_release("api@1.0.0", "stable").await.unwrap();
    let generation = current_generation(&client, "stage").await;
    client
        .subscribe_environment("stage", "api=stable", generation, None)
        .await
        .unwrap();
    let planned = client.plan_environment("stage", generation).await.unwrap();
    let plan_id = planned.resource.clone().expect("plan id");

    let secret = "s3cret-value-must-not-appear";
    let hashed_from = format!("sha256:{}", "a".repeat(64));
    let hashed_to = format!("sha256:{}", "b".repeat(64));
    let mut ctx = tenkai::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    let mut stored = tenkai::plan::load(&mut ctx, &plan_id).await.unwrap();
    stored.created_at = stored.created_at.saturating_add(1);
    stored.steps[0].target_changes = vec![
        TargetChange {
            kind: "Service".into(),
            name: "api".into(),
            fields: vec![TargetFieldChange {
                field: "ports".into(),
                from: Some("80".into()),
                to: Some("8080".into()),
            }],
            field_count: None,
            live_digest: "sha256:planned-live".into(),
        },
        TargetChange {
            kind: "Secret".into(),
            name: "creds".into(),
            fields: vec![TargetFieldChange {
                field: "data.password".into(),
                from: Some(hashed_from.clone()),
                to: Some(hashed_to.clone()),
            }],
            field_count: None,
            live_digest: "sha256:secret-live".into(),
        },
        TargetChange {
            kind: "ConfigMap".into(),
            name: "cfg".into(),
            fields: vec![TargetFieldChange {
                field: "data".into(),
                from: Some(format!("sha256:{}", "c".repeat(64))),
                to: Some(format!("sha256:{}", "d".repeat(64))),
            }],
            field_count: None,
            live_digest: "sha256:cm-live".into(),
        },
    ];
    stored.bind_content_identity().unwrap();
    tenkai::plan::store(&mut ctx, &stored).await.unwrap();
    let plan_id = stored.id.clone();
    let digest = format!("sha256:{}", stored.executable_digest().unwrap());
    drop(ctx);

    let unauthenticated = reqwest::Client::new()
        .get(format!("{base}/v1/plans/{}", encode_plan_path(&plan_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let inspected = client.inspect_environment("stage").await.unwrap();
    let latest = inspected.latest_plan.expect("latest plan");
    assert_eq!(latest.id, plan_id);
    assert_eq!(latest.steps.len(), 1);
    let capped = &latest.steps[0].target_changes;
    assert_eq!(capped.len(), 3, "{capped:?}");
    assert_eq!(capped[0].kind, "Service");
    assert_eq!(capped[0].name, "api");
    assert_eq!(capped[0].field_count, Some(1));
    assert!(capped[0].fields.is_empty(), "{capped:?}");
    assert_eq!(capped[1].kind, "Secret");
    assert_eq!(capped[1].field_count, Some(1));
    assert!(capped[1].fields.is_empty(), "{capped:?}");
    assert_eq!(capped[2].kind, "ConfigMap");
    assert_eq!(capped[2].field_count, Some(1));

    let full = client.inspect_plan(&plan_id).await.unwrap();
    assert_eq!(full.id, plan_id);
    assert_eq!(full.digest.as_deref(), Some(digest.as_str()));
    let changes = &full.steps[0].target_changes;
    assert_eq!(changes.len(), 3, "{changes:?}");
    assert_eq!(changes[0].kind, "Service");
    assert_eq!(changes[0].name, "api");
    assert_eq!(changes[0].fields[0].field, "ports");
    assert_eq!(changes[0].fields[0].from.as_deref(), Some("80"));
    assert_eq!(changes[0].fields[0].to.as_deref(), Some("8080"));
    assert_eq!(changes[0].field_count, Some(1));
    assert_eq!(changes[1].kind, "Secret");
    assert_eq!(
        changes[1].fields[0].from.as_deref(),
        Some(hashed_from.as_str())
    );
    assert_eq!(changes[1].fields[0].to.as_deref(), Some(hashed_to.as_str()));
    assert_eq!(changes[2].kind, "ConfigMap");
    assert_eq!(changes[2].fields.len(), 1);
    let encoded = serde_json::to_string(&full).unwrap();
    assert!(!encoded.contains(secret), "{encoded}");

    let _ = std::fs::remove_dir_all(root);
}
