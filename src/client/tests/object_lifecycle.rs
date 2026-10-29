use crate::client::{Ctx, block_embedded};
use crate::pb::sekai::Object;

use super::mock_router::remote_ctx;
use super::mock_state::MockSekaiState;

async fn assert_object_lifecycle(mut ctx: Ctx) {
    let id = "tenkai:conformance:object";
    assert_eq!(ctx.get(id).await.unwrap(), None);

    let original = Object {
        id: id.into(),
        kind: "tenkai.conformance".into(),
        name: "original".into(),
        properties: [("environment".into(), "test".into())]
            .into_iter()
            .collect(),
        ..Default::default()
    };
    assert_eq!(ctx.create_once(original.clone()).await.unwrap(), original);
    assert_eq!(ctx.get(id).await.unwrap(), Some(original.clone()));

    let mut conflicting = original.clone();
    conflicting.name = "must-not-replace".into();
    let error = ctx.create_once(conflicting).await.unwrap_err();
    assert!(crate::client::is_unique_conflict(&error), "{error}");
    assert_eq!(ctx.get(id).await.unwrap(), Some(original.clone()));

    let mut updated = original;
    updated.name = "updated".into();
    updated.properties.insert("status".into(), "ready".into());
    assert_eq!(ctx.put(updated.clone()).await.unwrap(), updated);
    assert_eq!(ctx.get(id).await.unwrap(), Some(updated));

    ctx.delete(id).await.unwrap();
    assert_eq!(ctx.get(id).await.unwrap(), None);
}

#[tokio::test]
async fn embedded_blocking_join_failure_is_explicit() {
    let path = std::env::temp_dir().join(format!("tenkai-block-join-{}.db", uuid::Uuid::new_v4()));
    let ctx = Ctx::embedded(&path).unwrap();
    let store = ctx.embedded_arc().unwrap();
    let error = block_embedded(store, |_| -> anyhow::Result<()> {
        panic!("forced blocking panic");
    })
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("embedded store blocking task failed"),
        "{error}"
    );
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn embedded_ctx_conforms_to_object_lifecycle() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-ctx-conformance-{}.db",
        uuid::Uuid::new_v4()
    ));
    let ctx = Ctx::embedded(&path).unwrap();
    assert_object_lifecycle(ctx).await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn remote_ctx_conforms_to_object_lifecycle() {
    let (ctx, server) = remote_ctx(MockSekaiState::default()).await;
    assert_object_lifecycle(ctx).await;
    server.abort();
}

#[tokio::test]
async fn tenant_hub_ctx_reads_empty_and_writes_fail_closed() {
    let mut ctx = Ctx::tenant_hub();
    assert!(!ctx.is_embedded());
    assert!(ctx.is_tenant_hub());
    assert_eq!(ctx.get("tenkai:conformance:object").await.unwrap(), None);
    assert!(
        ctx.list_kind("tenkai.conformance")
            .await
            .unwrap()
            .is_empty()
    );

    let object = Object {
        id: "tenkai:conformance:object".into(),
        kind: "tenkai.conformance".into(),
        name: "original".into(),
        ..Default::default()
    };
    let create = ctx.create_once(object.clone()).await.unwrap_err();
    assert!(
        create
            .to_string()
            .contains("enterprise hub does not open SQLite"),
        "{create}"
    );
    let put = ctx.put(object).await.unwrap_err();
    assert!(
        put.to_string()
            .contains("enterprise hub does not open SQLite"),
        "{put}"
    );
}

#[tokio::test]
async fn tenant_hub_catalog_serves_bound_tenant() {
    use crate::storage::{CatalogGraph, MemoryCatalogGraph};
    use std::sync::Arc;

    let graph = Arc::new(MemoryCatalogGraph::new());
    let object = Object {
        id: "tenkai:conformance:object".into(),
        kind: "tenkai.conformance".into(),
        name: "original".into(),
        ..Default::default()
    };
    graph.create(Some("tenant-a"), object.clone()).unwrap();
    let mut ctx = Ctx::tenant_hub_catalog(graph).with_catalog_tenant("tenant-a");
    assert_eq!(ctx.get(&object.id).await.unwrap(), Some(object.clone()));
    assert_eq!(ctx.list_kind(&object.kind).await.unwrap(), vec![object]);
}
