use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::support::current_generation;
use super::*;
use tenkai::management_lifecycle::{
    ExposureWaiverClearRequest, ExposureWaiverRequest, MANAGEMENT_LIFECYCLE_API_VERSION,
    ManagementLifecycleOperation,
};

fn waiver_set() -> ExposureWaiverRequest {
    ExposureWaiverRequest {
        version: MANAGEMENT_LIFECYCLE_API_VERSION,
        operation: ManagementLifecycleOperation::WaiverSet.as_str().into(),
        advisory_id: "TENKAI-2026-1".into(),
        scope: "release".into(),
        category: "false_positive".into(),
        reason: "scanner noise".into(),
        expires: "7d".into(),
        release_id: Some("tenkai:release:api@1.0.0".into()),
        product: None,
        component: None,
    }
}

fn waiver_clear() -> ExposureWaiverClearRequest {
    ExposureWaiverClearRequest {
        version: MANAGEMENT_LIFECYCLE_API_VERSION,
        operation: ManagementLifecycleOperation::WaiverClear.as_str().into(),
        advisory_id: "TENKAI-2026-1".into(),
        scope: "release".into(),
        reason: "fixed".into(),
        release_id: Some("tenkai:release:api@1.0.0".into()),
        product: None,
        component: None,
    }
}

#[tokio::test]
async fn remote_waiver_and_grace_require_management() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-waiver-http-{}-{}",
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
    let management = RemoteClient::new(&base, "management-secret").unwrap();
    let runtime = RemoteClient::new(&base, "runtime-secret").unwrap();
    let scoped = RemoteClient::new(&base, "stage-secret").unwrap();
    let first = signed_catalog_fixture(&root, "1.0.0");
    management.publish_release(&first).await.unwrap();
    management
        .promote_release("api@1.0.0", "stable")
        .await
        .unwrap();

    let runtime_err = runtime
        .set_exposure_waiver(waiver_set())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        runtime_err.contains("403") || runtime_err.contains("runtime"),
        "{runtime_err}"
    );
    let scoped_err = scoped
        .set_exposure_waiver(waiver_set())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        scoped_err.contains("catalog-wide") || scoped_err.contains("403"),
        "{scoped_err}"
    );

    let set = management.set_exposure_waiver(waiver_set()).await.unwrap();
    assert!(set.message.contains("TENKAI-2026-1"), "{}", set.message);
    let cleared = management
        .clear_exposure_waiver(waiver_clear())
        .await
        .unwrap();
    assert!(
        cleared.message.contains("TENKAI-2026-1"),
        "{}",
        cleared.message
    );

    let runtime_grace = runtime
        .configure_environment_exposure_grace("stage", "24h", 0)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        runtime_grace.contains("403") || runtime_grace.contains("runtime"),
        "{runtime_grace}"
    );
    let generation = current_generation(&management, "stage").await;
    let env_grace = scoped
        .configure_environment_exposure_grace("stage", "24h", generation)
        .await
        .unwrap();
    assert!(
        env_grace.message.contains("86400000") || env_grace.message.contains("exposure grace"),
        "{}",
        env_grace.message
    );
    let scoped_channel = scoped
        .configure_channel_exposure_grace("api", "stable", "24h")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        scoped_channel.contains("catalog-wide") || scoped_channel.contains("403"),
        "{scoped_channel}"
    );
    let channel_grace = management
        .configure_channel_exposure_grace("api", "stable", "24h")
        .await
        .unwrap();
    assert!(
        channel_grace.message.contains("86400000")
            || channel_grace.message.contains("exposure grace"),
        "{}",
        channel_grace.message
    );
    let _ = std::fs::remove_dir_all(root);
}
