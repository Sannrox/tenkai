use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::*;

#[tokio::test]
async fn remote_release_labels_require_management() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-release-labels-http-{}-{}",
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

    let runtime_err = runtime
        .set_release_label("api", "1.0.0", "tier", "stable", "grouping")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        runtime_err.contains("403") || runtime_err.contains("runtime"),
        "{runtime_err}"
    );
    let scoped_err = scoped
        .set_release_label("api", "1.0.0", "tier", "stable", "grouping")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        scoped_err.contains("catalog-wide") || scoped_err.contains("403"),
        "{scoped_err}"
    );

    let set = management
        .set_release_label("api", "1.0.0", "tier", "stable", "grouping")
        .await
        .unwrap();
    assert!(set.message.contains("tier=stable"), "{}", set.message);
    let listed = management
        .list_release_labels("api", "1.0.0")
        .await
        .unwrap();
    assert_eq!(listed.get("tier").map(String::as_str), Some("stable"));
    let cleared = management
        .clear_release_label("api", "1.0.0", "tier", "grouping")
        .await
        .unwrap();
    assert!(cleared.message.contains("tier"), "{}", cleared.message);
    let empty = management
        .list_release_labels("api", "1.0.0")
        .await
        .unwrap();
    assert!(empty.is_empty(), "{empty:?}");
    let _ = std::fs::remove_dir_all(root);
}
