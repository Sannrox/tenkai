use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::support::{CATALOG_WIDE_DENIED, RUNTIME_DENIED, assert_forbidden};
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
        .unwrap_err();
    assert_forbidden(runtime_err, RUNTIME_DENIED);
    let scoped_err = scoped
        .set_release_label("api", "1.0.0", "tier", "stable", "grouping")
        .await
        .unwrap_err();
    assert_forbidden(scoped_err, CATALOG_WIDE_DENIED);

    let set = management
        .set_release_label("api", "1.0.0", "tier", "stable", "grouping")
        .await
        .unwrap();
    assert!(set.message.contains("tier=stable"), "{}", set.message);
    let listed = management
        .list_release_labels("api", "1.0.0")
        .await
        .unwrap();
    let tier = listed.get("tier").unwrap();
    assert_eq!(tier.value, "stable");
    let actor = tier.set_by.clone().expect("label read names who set it");
    assert!(tier.set_at.is_some(), "{tier:?}");
    management
        .set_release_label("api", "1.0.0", "tier", "edge", "regroup")
        .await
        .unwrap();
    let changed = management
        .list_release_labels("api", "1.0.0")
        .await
        .unwrap();
    assert_eq!(changed["tier"].value, "edge");
    assert!(changed["tier"].set_at >= tier.set_at, "{changed:?}");
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

    let history = management
        .release_label_history("api", "1.0.0")
        .await
        .unwrap();
    let summary: Vec<_> = history
        .iter()
        .map(|change| {
            (
                change.action,
                change.value.as_deref(),
                change.actor.as_str(),
                change.reason.as_deref(),
            )
        })
        .collect();
    use tenkai::labels::LabelAction::{Clear, Set};
    assert_eq!(
        summary,
        [
            (Set, Some("stable"), actor.as_str(), Some("grouping")),
            (Set, Some("edge"), actor.as_str(), Some("regroup")),
            (Clear, None, actor.as_str(), Some("grouping")),
        ]
    );
    let _ = std::fs::remove_dir_all(root);
}
