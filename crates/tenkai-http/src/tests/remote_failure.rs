use super::lifecycle_support::{
    lifecycle_router, signed_catalog_fixture_installing, signed_plan_requests,
};
use super::*;
use crate::RemoteFailure;

fn failure(error: &anyhow::Error) -> &RemoteFailure {
    error
        .downcast_ref::<RemoteFailure>()
        .unwrap_or_else(|| panic!("expected a RemoteFailure, got {error:#}"))
}

#[tokio::test]
async fn transport_failures_distinguish_unsent_from_unknown() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = closed.local_addr().unwrap();
    drop(closed);
    let error = RemoteClient::new(format!("http://{closed_addr}"), "token")
        .unwrap()
        .fleet_status()
        .await
        .unwrap_err();
    assert!(
        matches!(failure(&error), RemoteFailure::NotSent(_)),
        "{error:#}"
    );

    // The server reads the request, then drops the connection without answering.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt as _;
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 1024];
        let _ = socket.read(&mut buffer).await;
    });
    let error = RemoteClient::new(format!("http://{addr}"), "token")
        .unwrap()
        .promote_release("api@1.0.0", "stable")
        .await
        .unwrap_err();
    assert!(
        matches!(failure(&error), RemoteFailure::ResponseLost(_)),
        "{error:#}"
    );
}

#[tokio::test]
async fn failed_apply_steps_are_rejected_not_reported_as_applied() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-remote-failed-apply-{}-{}",
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
    let client = RemoteClient::new(format!("http://{addr}"), "management-secret").unwrap();

    let published = client
        .publish_release(&signed_catalog_fixture_installing(&root, "1.0.0", "false"))
        .await
        .unwrap();
    assert_eq!(published.resource.as_deref(), Some("api@1.0.0"));
    client.promote_release("api@1.0.0", "stable").await.unwrap();
    client
        .subscribe_environment("stage", "api=stable", 0)
        .await
        .unwrap();
    let plan = client.plan_environment("stage", 0).await.unwrap();
    let plan_id = plan.resource.clone().unwrap();
    let (approve, apply) =
        signed_plan_requests(&root, "approve", "stage", &plan.digest.unwrap(), 0);
    client.approve_plan(&plan_id, &approve).await.unwrap();

    let error = client.apply_plan(&plan_id, &apply).await.unwrap_err();
    assert!(
        matches!(failure(&error), RemoteFailure::Rejected { status: 422, .. }),
        "{error:#}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
