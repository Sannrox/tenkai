use crate::client::Ctx;
use crate::pb::graph_action::{ActionOp, ActionTypeDef};
use crate::pb::sekai::Object;

use super::mock_router::remote_ctx;
use super::mock_state::MockSekaiState;

async fn assert_action_lifecycle(mut ctx: Ctx) {
    let target = Object {
        id: "tenkai:conformance:action-target".into(),
        kind: "tenkai.conformance".into(),
        name: "action-target".into(),
        ..Default::default()
    };
    ctx.create_once(target.clone()).await.unwrap();

    let action = ActionTypeDef {
        name: "tenkai.conformance.set_status".into(),
        description: "set status".into(),
        params: vec![],
        ops: vec![ActionOp {
            op: "set_property".into(),
            property: "status".into(),
            value_from: "status".into(),
            relation: String::new(),
        }],
        target_kind: "tenkai.conformance".into(),
        created: 1,
        required_purpose: "delivery".into(),
    };
    ctx.register_action(action).await.unwrap();

    let params = std::collections::HashMap::from([
        ("id".into(), target.id.clone()),
        ("status".into(), "ready".into()),
    ]);
    let preview = ctx
        .preview_action_result("tenkai.conformance.set_status", params.clone())
        .await
        .unwrap();
    assert_eq!(preview.decision, "allow");
    assert!(preview.dry_run);
    assert_eq!(
        ctx.get(&target.id)
            .await
            .unwrap()
            .unwrap()
            .properties
            .get("status"),
        None
    );

    let executed = ctx
        .execute_action_result("tenkai.conformance.set_status", params)
        .await
        .unwrap();
    assert_eq!(executed.decision, "allow");
    assert!(!executed.dry_run);
    assert_eq!(
        ctx.get(&target.id)
            .await
            .unwrap()
            .unwrap()
            .properties
            .get("status")
            .map(String::as_str),
        Some("ready")
    );

    let decisions = ctx
        .action_decisions("", "tenkai.conformance.set_status", 0)
        .await
        .unwrap();
    assert!(!decisions.is_empty());
    assert!(
        decisions
            .iter()
            .any(|decision| decision.target_id == target.id)
    );

    let deny = ctx.deny_action("approval-conformance", "blocked").await;
    if ctx.is_embedded() {
        assert!(deny.is_err());
    } else {
        deny.unwrap();
    }
}

#[tokio::test]
async fn embedded_ctx_conforms_to_action_lifecycle() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-ctx-action-conformance-{}.db",
        uuid::Uuid::new_v4()
    ));
    let ctx = Ctx::embedded(&path).unwrap();
    assert_action_lifecycle(ctx).await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn remote_ctx_conforms_to_action_lifecycle() {
    let (ctx, server) = remote_ctx(MockSekaiState::default()).await;
    assert_action_lifecycle(ctx).await;
    server.abort();
}
