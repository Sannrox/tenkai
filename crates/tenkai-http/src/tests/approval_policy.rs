use super::lifecycle_support::lifecycle_router;
use super::*;
use crate::RemoteFailure;

#[tokio::test]
async fn approval_policy_read_requires_auth_and_environment_grant() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-approval-policy-auth-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config, _) = lifecycle_router(&root).await;
    let unauthenticated = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/stage/approval-policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let runtime = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/stage/approval-policy")
                .header("authorization", "Bearer runtime-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(runtime.status(), StatusCode::FORBIDDEN);

    let other_env = app
        .clone()
        .oneshot(
            Request::get("/v1/environments/prod/approval-policy")
                .header("authorization", "Bearer stage-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other_env.status(), StatusCode::FORBIDDEN);

    let allowed = app
        .oneshot(
            Request::get("/v1/environments/stage/approval-policy")
                .header("authorization", "Bearer stage-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let body = axum::body::to_bytes(allowed.into_body(), 65536)
        .await
        .unwrap();
    let view: tenkai::approval_policy::EffectiveApprovalPolicy =
        serde_json::from_slice(&body).unwrap();
    assert!(!view.configured);
    assert_eq!(view.mode, "manual");
    assert_eq!(
        view.require_human,
        vec!["all plans require a human-signed envelope"]
    );
    let encoded = String::from_utf8(body.to_vec()).unwrap();
    assert!(!encoded.contains("auto_signer_key"), "{encoded}");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn plan_approvals_read_requires_auth() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-plan-approvals-auth-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config, _) = lifecycle_router(&root).await;
    let unauthenticated = app
        .clone()
        .oneshot(
            Request::get("/v1/plans/missing/approvals")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn remote_approval_policy_round_trip_reports_configured_auto_view() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-approval-policy-remote-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config, _) = lifecycle_router(&root).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = RemoteClient::new(format!("http://{addr}"), "management-secret").unwrap();
    let unconfigured = client.environment_approval_policy("stage").await.unwrap();
    assert!(!unconfigured.configured);
    assert_eq!(unconfigured.mode, "manual");

    let key = root.join("auto-approver.ed25519");
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key)
            .unwrap();
        file.write_all(&[7_u8; 32]).unwrap();
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&key, [7_u8; 32]).unwrap();
    }
    let policy = root.join("policy.toml");
    std::fs::write(
        &policy,
        format!(
            "version = 1\nmode = \"auto\"\nttl_ms = 60000\nauto_signer_key = \"{}\"\n\n[[require_human]]\nproduct = \"payments\"\n",
            key.display()
        ),
    )
    .unwrap();
    let mut ctx = tenkai::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    tenkai::plan::set_plan_approval_policy(&mut ctx, "stage", &policy)
        .await
        .unwrap();
    drop(ctx);

    let view = client.environment_approval_policy("stage").await.unwrap();
    assert!(view.configured);
    assert_eq!(view.mode, "auto");
    assert_eq!(view.ttl_ms, Some(60_000));
    assert_eq!(view.auto_signers.len(), 1);
    assert!(
        view.require_human
            .iter()
            .any(|rule| rule == "product payments")
    );
    assert!(view.digest.is_some());
    let encoded = serde_json::to_string(&view).unwrap();
    assert!(!encoded.contains(&key.display().to_string()), "{encoded}");

    std::fs::write(
        &policy,
        "not toml\nauto_signer_key = \"/secret/path/leaked.ed25519\"\n",
    )
    .unwrap();
    let failed = client
        .environment_approval_policy("stage")
        .await
        .unwrap_err();
    let remote = failed.downcast_ref::<RemoteFailure>().unwrap();
    match remote {
        RemoteFailure::Rejected { status, detail } => {
            assert_eq!(*status, 503);
            assert!(detail.contains("approval policy is unreadable"), "{detail}");
            assert!(!detail.contains("/secret/path/leaked.ed25519"), "{detail}");
            assert!(!detail.contains("not toml"), "{detail}");
        }
        other => panic!("expected rejected unreadable policy, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(root);
}
