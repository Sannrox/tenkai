use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::support::current_generation;
use super::*;

#[tokio::test]
async fn remote_channel_pace_and_admit_require_management() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-pace-http-{}-{}",
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
        .configure_channel_pace("api", "stable", "3h")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        runtime_err.contains("403") || runtime_err.contains("runtime"),
        "{runtime_err}"
    );
    let scoped_err = scoped
        .configure_channel_pace("api", "stable", "3h")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        scoped_err.contains("catalog-wide") || scoped_err.contains("403"),
        "{scoped_err}"
    );

    let configured = management
        .configure_channel_pace("api", "stable", "3h")
        .await
        .unwrap();
    assert!(
        configured.message.contains("10800000") || configured.message.contains("upgrade pace"),
        "{}",
        configured.message
    );
    let generation = current_generation(&management, "stage").await;
    management
        .subscribe_environment("stage", "api=stable", generation, None)
        .await
        .unwrap();
    let admitted = management
        .admit_channel_instance("api", "stable", "stage", "api", "canary host")
        .await
        .unwrap();
    assert!(
        admitted.message.contains("canary host"),
        "{}",
        admitted.message
    );
    let _ = std::fs::remove_dir_all(root);
}
