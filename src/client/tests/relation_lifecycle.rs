use crate::client::Ctx;
use crate::pb::sekai::{Link, Object};

use super::mock_router::remote_ctx;
use super::mock_state::MockSekaiState;

async fn assert_relation_lifecycle(mut ctx: Ctx) {
    let source = Object {
        id: "tenkai:conformance:source".into(),
        kind: "tenkai.conformance".into(),
        name: "source".into(),
        ..Default::default()
    };
    let target = Object {
        id: "tenkai:conformance:target".into(),
        kind: "tenkai.conformance".into(),
        name: "target".into(),
        ..Default::default()
    };
    ctx.create_once(source.clone()).await.unwrap();
    ctx.create_once(target.clone()).await.unwrap();

    assert!(
        ctx.links(&source.id, "depends_on")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        ctx.linked(&source.id, "depends_on", "out")
            .await
            .unwrap()
            .is_empty()
    );

    ctx.link(&source.id, &target.id, "depends_on")
        .await
        .unwrap();
    ctx.link(&source.id, &target.id, "depends_on")
        .await
        .unwrap();
    let links = ctx.links(&source.id, "depends_on").await.unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(
        links[0].id,
        format!("{}--depends_on--{}", source.id, target.id)
    );
    assert_eq!(links[0].from_id, source.id);
    assert_eq!(links[0].to_id, target.id);
    assert_eq!(links[0].relation, "depends_on");
    assert!(links[0].created > 0);
    assert_eq!(
        ctx.linked(&source.id, "depends_on", "out").await.unwrap(),
        vec![target.clone()]
    );
    assert_eq!(
        ctx.linked(&target.id, "depends_on", "in").await.unwrap(),
        vec![source.clone()]
    );

    let strict = Link {
        id: "tenkai:conformance:strict-link".into(),
        from_id: source.id.clone(),
        to_id: target.id.clone(),
        relation: "locked_by".into(),
        created: 42,
    };
    ctx.create_link_once(strict.clone()).await.unwrap();
    let error = ctx.create_link_once(strict).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::AlreadyExists);

    ctx.unlink(&source.id, &target.id, "depends_on")
        .await
        .unwrap();
    ctx.unlink(&source.id, &target.id, "depends_on")
        .await
        .unwrap();
    assert!(
        ctx.links(&source.id, "depends_on")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        ctx.linked(&source.id, "depends_on", "out")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        ctx.linked(&target.id, "depends_on", "in")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn embedded_ctx_conforms_to_relation_lifecycle() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-ctx-relation-conformance-{}.db",
        uuid::Uuid::new_v4()
    ));
    let ctx = Ctx::embedded(&path).unwrap();
    assert_relation_lifecycle(ctx).await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn remote_ctx_conforms_to_relation_lifecycle() {
    let (ctx, server) = remote_ctx(MockSekaiState::default()).await;
    assert_relation_lifecycle(ctx).await;
    server.abort();
}
