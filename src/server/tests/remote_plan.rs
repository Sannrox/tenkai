use super::lifecycle_support::{
    deployed_version, lifecycle_router, signed_catalog_fixture, signed_plan_requests,
};
use super::*;

#[tokio::test]
async fn remote_plan_apply_rollback_a_to_b_through_a_real_hub() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-remote-plan-apply-{}-{}",
        std::process::id(),
        crate::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config, store) = lifecycle_router(&root).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");
    let client = RemoteClient::new(&base, "management-secret").unwrap();
    let stage_client = RemoteClient::new(&base, "stage-secret").unwrap();
    let first = signed_catalog_fixture(&root, "1.0.0");
    client.publish_release(&first).await.unwrap();
    client.promote_release("api@1.0.0", "stable").await.unwrap();
    client
        .subscribe_environment("stage", "api=stable", 0)
        .await
        .unwrap();

    let plan_a = client.plan_environment("stage", 0).await.unwrap();
    let plan_a_id = plan_a.resource.clone().expect("plan id");
    let plan_a_digest = plan_a.digest.clone().expect("plan digest");
    assert!(plan_a_digest.starts_with("sha256:"));
    let (approve_a, apply_a) = signed_plan_requests(&root, "approve-a", "stage", &plan_a_digest, 0);
    let approved = client.approve_plan(&plan_a_id, &approve_a).await.unwrap();
    assert_eq!(approved.digest.as_deref(), Some(plan_a_digest.as_str()));

    let missing = reqwest::Client::new()
        .post(format!(
            "{base}/v1/plans/{}/apply",
            encode_plan_path(&plan_a_id)
        ))
        .bearer_auth("management-secret")
        .json(&serde_json::json!({
            "version": 1,
            "operation": "apply",
            "environment": "stage",
            "expected_generation": 0
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    let bypass = reqwest::Client::new()
        .post(format!(
            "{base}/v1/plans/{}/apply",
            encode_plan_path(&plan_a_id)
        ))
        .bearer_auth("management-secret")
        .json(&serde_json::json!({
            "version": 1,
            "operation": "apply",
            "environment": "stage",
            "expected_generation": 0,
            "allow_unapproved_development": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bypass.status(), StatusCode::BAD_REQUEST);

    store
        .acquire_lease("stage", "fence-test", crate::now_millis() + 60_000)
        .unwrap();
    let current = store.current_lease("stage").unwrap().unwrap().generation;
    assert_ne!(current, 0);
    let stale_err = client
        .apply_plan(&plan_a_id, &apply_a)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        stale_err.contains("stale fencing generation"),
        "{stale_err}"
    );

    let mut apply_a = apply_a;
    apply_a.expected_generation = current;
    let applied_a = client.apply_plan(&plan_a_id, &apply_a).await.unwrap();
    assert_eq!(applied_a.digest.as_deref(), Some(plan_a_digest.as_str()));
    assert_eq!(deployed_version(&client, "stage", "api").await, "1.0.0");

    let second_root = root.join("v2");
    std::fs::create_dir_all(&second_root).unwrap();
    let second = signed_catalog_fixture(&second_root, "1.1.0");
    client.publish_release(&second).await.unwrap();
    client.promote_release("api@1.1.0", "stable").await.unwrap();
    let plan_b = client.plan_environment("stage", current).await.unwrap();
    let plan_b_id = plan_b.resource.clone().expect("upgrade plan id");
    let plan_b_digest = plan_b.digest.clone().expect("upgrade digest");
    let (approve_b, mut apply_b) =
        signed_plan_requests(&root, "approve-b", "stage", &plan_b_digest, current);
    client.approve_plan(&plan_b_id, &approve_b).await.unwrap();
    apply_b.expected_generation = current;
    client.apply_plan(&plan_b_id, &apply_b).await.unwrap();
    assert_eq!(deployed_version(&client, "stage", "api").await, "1.1.0");

    let rollback = client
        .rollback_environment("stage", "api", current, None)
        .await
        .unwrap();
    let rollback_id = rollback.resource.clone().expect("rollback plan id");
    let rollback_digest = rollback.digest.clone().expect("rollback digest");
    assert!(rollback.message.contains("requires signed approval"));
    let (approve_r, mut apply_r) =
        signed_plan_requests(&root, "approve-r", "stage", &rollback_digest, current);
    client.approve_plan(&rollback_id, &approve_r).await.unwrap();
    apply_r.expected_generation = current;
    client.apply_plan(&rollback_id, &apply_r).await.unwrap();
    assert_eq!(deployed_version(&client, "stage", "api").await, "1.0.0");
    assert_eq!(
        crate::management_lifecycle::plan_environment_from_id(&rollback_id).unwrap(),
        "stage"
    );

    let crossed = stage_client
        .plan_environment("prod", 0)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        crossed.contains("cannot act on another environment"),
        "{crossed}"
    );

    let runtime = reqwest::Client::new()
        .post(format!("{base}/v1/environments/stage/plans"))
        .bearer_auth("runtime-secret")
        .json(&serde_json::json!({
            "version": 1,
            "operation": "plan",
            "environment": "stage",
            "expected_generation": current
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(runtime.status(), StatusCode::FORBIDDEN);
    let _ = std::fs::remove_dir_all(root);
}
