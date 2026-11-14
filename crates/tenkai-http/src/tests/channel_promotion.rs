use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::support::current_generation;
use super::*;
use tenkai::auth_context::{
    AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, PrincipalIdentity,
    PrincipalKind,
};
use tenkai::change_stream::ChangeEventKind;
use tenkai::channel_promotion::{ChannelPromotionEvidence, ChannelPromotionPolicy};
use tenkai::ontology::{env_id, release_id};
use tenkai::storage::OperationalStore;

fn management_actor() -> AuthenticatedRequestContext {
    AuthenticatedRequestContextBuilder::new(
        "http-channel-policy",
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

async fn configure_policy(database: &std::path::Path, soak_ms: i64) {
    let mut ctx = tenkai::client::Ctx::embedded(database).unwrap();
    let actor = management_actor();
    tenkai::channel_promotion::configure(
        &mut ctx,
        &actor,
        ChannelPromotionPolicy {
            product: "api".into(),
            target_channel: "stable".into(),
            source_channel: "candidate".into(),
            soak_duration_ms: soak_ms,
            stale_after_ms: soak_ms,
            evidence: ChannelPromotionEvidence::default(),
        },
    )
    .await
    .unwrap();
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
async fn pause_without_management_is_refused_and_pause_records_the_actor() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-channel-policy-http-{}-{}",
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
    let runtime = RemoteClient::new(&base, "runtime-secret").unwrap();
    let first = signed_catalog_fixture(&root, "1.0.0");
    management.publish_release(&first).await.unwrap();
    management
        .promote_release("api@1.0.0", "candidate")
        .await
        .unwrap();
    configure_policy(&root.join("tenkai.db"), 60_000).await;

    let unauthenticated = reqwest::Client::new()
        .post(format!(
            "{base}/v1/products/api/channels/stable/policy/pause"
        ))
        .json(&tenkai::management_lifecycle::ChannelPolicyPauseRequest {
            version: 1,
            operation: "channel_policy_pause".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status().as_u16(), 401);

    let runtime_err = runtime
        .pause_channel_policy("api", "stable")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        runtime_err.contains("403") || runtime_err.contains("runtime"),
        "{runtime_err}"
    );

    let paused = management
        .pause_channel_policy("api", "stable")
        .await
        .unwrap();
    assert!(paused.message.contains("paused"), "{}", paused.message);
    let events = store.audit_events().unwrap();
    assert!(
        events.iter().any(|event| {
            event.operation.contains("channel_policy_pause")
                && event.principal.contains("management")
        }),
        "{events:?}"
    );
    let view = management
        .channel_promotion_policy("api", "stable")
        .await
        .unwrap();
    assert!(view.paused, "{view:?}");
    assert!(view.paused_by.is_some(), "{view:?}");
    assert!(view.paused_at.is_some(), "{view:?}");
    assert_eq!(view.soak_duration_ms, 60_000, "{view:?}");
    assert!(!view.evidence.canary, "{view:?}");

    let resumed = management
        .resume_channel_policy("api", "stable")
        .await
        .unwrap();
    assert!(resumed.message.contains("resumed"), "{}", resumed.message);
    let view = management
        .channel_promotion_policy("api", "stable")
        .await
        .unwrap();
    assert!(!view.paused, "{view:?}");
    assert!(view.paused_by.is_none(), "{view:?}");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn soak_reset_and_policy_promotion_are_visible_over_http() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-channel-policy-http-soak-{}-{}",
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
    drop(ctx);
    configure_policy(&database, 60_000).await;

    management.reconcile().await.unwrap();
    let soaking = management
        .channel_promotion_policy("api", "stable")
        .await
        .unwrap();
    assert_eq!(soaking.state, "soaking", "{soaking:?}");
    assert_eq!(soaking.soaking_release.as_deref(), Some("api@1.0.0"));

    backdate_soak(&database, 5_000).await;
    let mut ctx = tenkai::client::Ctx::embedded(&database).unwrap();
    observe(&mut ctx, "stage", "api", "1.0.0", false).await;
    drop(ctx);
    management.reconcile().await.unwrap();
    let reset = management
        .channel_promotion_policy("api", "stable")
        .await
        .unwrap();
    assert_eq!(reset.state, "reset", "{reset:?}");
    assert!(
        reset
            .last_reset_cause
            .as_ref()
            .is_some_and(|cause| cause.starts_with("reset:")),
        "{reset:?}"
    );
    assert!(reset.last_reset_at.is_some(), "{reset:?}");

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
            soak_duration_ms: 1,
            stale_after_ms: 60_000,
            evidence: ChannelPromotionEvidence::default(),
        },
    )
    .await
    .unwrap();
    drop(ctx);
    management.reconcile().await.unwrap();
    backdate_soak(&database, 5_000).await;
    management.reconcile().await.unwrap();
    let promoted = management
        .channel_promotion_policy("api", "stable")
        .await
        .unwrap();
    assert_eq!(promoted.state, "promoted", "{promoted:?}");
    assert_eq!(
        promoted.promoted_by_kind.as_deref(),
        Some("channel_promotion_policy"),
        "{promoted:?}"
    );
    assert!(
        promoted
            .promoted_by
            .as_ref()
            .is_some_and(|actor| actor.contains("channel-promotion-policy")),
        "{promoted:?}"
    );
    let events = management.list_change_events().await.unwrap();
    assert!(
        events.events.iter().any(|event| {
            event.kind == ChangeEventKind::ReleasePromoted
                && event.resource.contains("channel-promotion-policy")
        }),
        "{events:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}
