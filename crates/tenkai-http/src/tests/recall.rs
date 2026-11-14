use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::support::current_generation;
use super::*;
use tenkai::auth_context::{
    AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, PrincipalIdentity,
    PrincipalKind,
};
use tenkai::channel_promotion::{ChannelPromotionEvidence, ChannelPromotionPolicy};
use tenkai::ontology::{env_id, release_id};

fn management_actor() -> AuthenticatedRequestContext {
    AuthenticatedRequestContextBuilder::new(
        "http-recall",
        PrincipalIdentity {
            id: "management".into(),
            kind: PrincipalKind::Management,
        },
        "test-auth",
    )
    .build()
    .unwrap()
}

async fn observe(
    ctx: &mut tenkai::client::Ctx,
    env: &str,
    product: &str,
    version: &str,
    healthy: bool,
) {
    tenkai::environment::record_observed_health(
        ctx,
        env,
        product,
        healthy,
        if healthy { "" } else { "boom" },
    )
    .await
    .unwrap();
    let mut object = ctx.get(&env_id(env)).await.unwrap().unwrap();
    object.properties.insert(
        format!("deployed_release.{product}"),
        release_id(product, version),
    );
    ctx.put(object).await.unwrap();
}

async fn backdate_soak(database: &std::path::Path, ago_ms: i64) {
    let mut ctx = tenkai::client::Ctx::embedded(database).unwrap();
    let id = "tenkai:channel-promotion-soak:api/stable";
    let mut object = ctx.get(id).await.unwrap().unwrap();
    let last = object
        .properties
        .get("last_tick_at")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    object.properties.insert(
        "last_tick_at".into(),
        last.saturating_sub(ago_ms).to_string(),
    );
    ctx.put(object).await.unwrap();
}

#[tokio::test]
async fn health_triggered_recall_is_readable_over_http() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-recall-http-{}-{}",
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
    let base = format!("http://{addr}");
    let management = RemoteClient::new(&base, "management-secret").unwrap();
    let first = signed_catalog_fixture(&root, "1.0.0");
    management.publish_release(&first).await.unwrap();
    management
        .promote_release("api@1.0.0", "candidate")
        .await
        .unwrap();
    let generation = current_generation(&management, "stage").await;
    management
        .subscribe_environment("stage", "api=candidate", generation, None)
        .await
        .unwrap();
    let database = root.join("tenkai.db");
    let mut ctx = tenkai::client::Ctx::embedded(&database).unwrap();
    observe(&mut ctx, "stage", "api", "1.0.0", true).await;
    let actor = management_actor();
    tenkai::channel_promotion::configure(
        &mut ctx,
        &actor,
        ChannelPromotionPolicy {
            product: "api".into(),
            target_channel: "stable".into(),
            source_channel: "candidate".into(),
            soak_duration_ms: 60_000,
            stale_after_ms: 60_000,
            evidence: ChannelPromotionEvidence {
                recall_on_failing: true,
                ..ChannelPromotionEvidence::default()
            },
        },
    )
    .await
    .unwrap();
    drop(ctx);

    let unauthenticated = reqwest::Client::new()
        .get(format!("{base}/v1/releases/api@1.0.0/recall"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status().as_u16(), 401);

    let policy = management
        .channel_promotion_policy("api", "stable")
        .await
        .unwrap();
    assert!(policy.evidence.recall_on_failing, "{policy:?}");
    assert_eq!(policy.evidence.failing_max_share, 0.0, "{policy:?}");
    assert_eq!(policy.soak_duration_ms, 60_000, "{policy:?}");

    management.reconcile().await.unwrap();
    let mut ctx = tenkai::client::Ctx::embedded(&database).unwrap();
    observe(&mut ctx, "stage", "api", "1.0.0", false).await;
    drop(ctx);
    backdate_soak(&database, 5_000).await;
    management.reconcile().await.unwrap();

    let view = management.inspect_recall("api@1.0.0").await.unwrap();
    assert_eq!(view.release, "api@1.0.0");
    assert!(
        view.policy_id
            .as_ref()
            .is_some_and(|id| id.contains("channel-promotion-policy")),
        "{view:?}"
    );
    assert_eq!(view.policy_version.as_deref(), Some("1"), "{view:?}");
    assert!(
        view.policy_id.as_ref().is_some_and(|id| {
            view.recalled_by
                .as_ref()
                .is_some_and(|actor| actor.contains(id))
        }),
        "{view:?}"
    );
    assert!(
        view.reason
            .as_ref()
            .is_some_and(|reason| reason.contains("failing share")),
        "{view:?}"
    );
    assert!(
        view.removal_progress
            .iter()
            .any(|row| row.environment == "stage" && row.remaining),
        "{view:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn open_recall_range_covers_future_and_close_is_audited() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-recall-range-http-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config, store) = lifecycle_router(&root).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");
    let management = RemoteClient::new(&base, "management-secret").unwrap();
    management
        .publish_release(&signed_catalog_fixture(&root, "1.0.0"))
        .await
        .unwrap();
    let unauthenticated = reqwest::Client::new()
        .get(format!("{base}/v1/products/api/recall-ranges"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status().as_u16(), 401);
    management
        .record_recall_range("api", "1.0.0", None, "open defect")
        .await
        .unwrap();
    let ranges = management.list_recall_ranges("api").await.unwrap();
    assert_eq!(ranges.items.len(), 1, "{ranges:?}");
    assert!(ranges.items[0].covers_future, "{ranges:?}");
    assert_eq!(ranges.items[0].from, "1.0.0");
    assert!(ranges.items[0].before.is_none());
    let view = management.inspect_recall("api@1.0.0").await.unwrap();
    assert_eq!(view.range.as_deref(), Some("api [1.0.0, ∞)"));
    assert!(view.covers_future, "{view:?}");

    let closed = management
        .close_recall_range("api", "1.0.0", "1.2.0")
        .await
        .unwrap();
    assert!(closed.message.contains("closed"), "{}", closed.message);
    let events = store.audit_events().unwrap();
    assert!(
        events.iter().any(|event| {
            event.operation.contains("catalog.recall.range")
                && event.principal.contains("management")
        }),
        "{events:?}"
    );
    let ranges = management.list_recall_ranges("api").await.unwrap();
    assert!(!ranges.items[0].covers_future, "{ranges:?}");
    assert_eq!(ranges.items[0].before.as_deref(), Some("1.2.0"));
    let view = management.inspect_recall("api@1.0.0").await.unwrap();
    assert!(!view.covers_future, "{view:?}");
    let _ = std::fs::remove_dir_all(root);
}
