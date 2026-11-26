use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::support::current_generation;
use super::*;
use tenkai::auth_context::{
    AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, PrincipalIdentity,
    PrincipalKind,
};
use tenkai::channel_promotion::{ChannelPromotionEvidence, ChannelPromotionPolicy};
use tenkai::management_lifecycle::{
    ChannelRecallRuleRequest, MANAGEMENT_LIFECYCLE_API_VERSION, ManagementLifecycleOperation,
};
use tenkai::ontology::{env_id, release_id};

fn recall_rule(
    expected_generation: u64,
    soak_duration_ms: i64,
    failing_max_share: f64,
    recall_on_failing: bool,
    failing_max_instances: Option<u32>,
) -> ChannelRecallRuleRequest {
    ChannelRecallRuleRequest {
        version: MANAGEMENT_LIFECYCLE_API_VERSION,
        operation: ManagementLifecycleOperation::ChannelConfigure
            .as_str()
            .into(),
        expected_generation,
        soak_duration_ms,
        failing_max_share,
        failing_max_instances,
        recall_on_failing,
    }
}

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
    let mut ctx = tenkai_sqlite::embedded_ctx(database).unwrap();
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
async fn remote_recall_rule_triggers_a_recall_with_typed_measures() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-recall-http-{}-{}",
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
    let mut ctx = tenkai_sqlite::embedded_ctx(&database).unwrap();
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
            evidence: ChannelPromotionEvidence::default(),
        },
    )
    .await
    .unwrap();
    // prod also holds the release, so removal progress spans two environments.
    let mut prod = ctx.get(&env_id("prod")).await.unwrap().unwrap();
    prod.properties
        .insert("deployed_release.api".into(), release_id("api", "1.0.0"));
    ctx.put(prod).await.unwrap();
    drop(ctx);

    // The recall rule is a catalog-wide channel_configure write.
    let wrong_operation = reqwest::Client::new()
        .put(format!("{base}/v1/products/api/channels/stable/policy"))
        .bearer_auth("management-secret")
        .json(&serde_json::json!({
            "version": tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
            "operation": "channel_policy_pause",
            "expected_generation": 1,
            "soak_duration_ms": 60_000,
            "failing_max_share": 0.25,
            "recall_on_failing": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_operation.status().as_u16(), 400);
    let scoped = RemoteClient::new(&base, "stage-secret").unwrap();
    let scoped_err = scoped
        .set_channel_recall_rule("api", "stable", &recall_rule(1, 60_000, 0.25, true, None))
        .await
        .unwrap_err()
        .to_string();
    assert!(scoped_err.contains("403"), "{scoped_err}");
    let stale = management
        .set_channel_recall_rule("api", "stable", &recall_rule(0, 60_000, 0.25, true, None))
        .await
        .unwrap_err()
        .to_string();
    assert!(stale.contains("409"), "{stale}");
    management
        .set_channel_recall_rule("api", "stable", &recall_rule(1, 60_000, 0.25, true, None))
        .await
        .unwrap();
    let events = store.audit_events().unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.operation == "catalog.channel_policy_configure.completed"),
        "{events:?}"
    );

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
    assert_eq!(policy.policy_version, 2, "{policy:?}");
    assert!(policy.evidence.recall_on_failing, "{policy:?}");
    assert_eq!(policy.evidence.failing_max_share, 0.25, "{policy:?}");
    assert_eq!(policy.soak_duration_ms, 60_000, "{policy:?}");

    management.reconcile().await.unwrap();
    let mut ctx = tenkai_sqlite::embedded_ctx(&database).unwrap();
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
    assert_eq!(view.policy_version.as_deref(), Some("2"), "{view:?}");
    assert_eq!(view.healthy_share, Some(0.0), "{view:?}");
    assert_eq!(view.failing_share, Some(1.0), "{view:?}");
    assert_eq!(view.failing_max_share, Some(0.25), "{view:?}");
    assert_eq!(view.failing_max_instances, None, "{view:?}");
    assert_eq!(view.failing_instance_count, None, "{view:?}");
    assert!(
        view.removal_progress
            .iter()
            .any(|row| row.environment == "stage" && row.remaining),
        "{view:?}"
    );
    let removal = |view: &tenkai::catalog::RecallView| {
        view.removal_environments
            .iter()
            .map(|row| (row.environment.clone(), row.done, row.total))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        removal(&view),
        [("prod".to_string(), 0, 1), ("stage".to_string(), 0, 1)]
    );

    let mut ctx = tenkai_sqlite::embedded_ctx(&database).unwrap();
    let mut prod = ctx.get(&env_id("prod")).await.unwrap().unwrap();
    prod.properties.remove("deployed_release.api");
    ctx.put(prod).await.unwrap();
    drop(ctx);
    let view = management.inspect_recall("api@1.0.0").await.unwrap();
    assert_eq!(
        removal(&view),
        [("prod".to_string(), 1, 1), ("stage".to_string(), 0, 1)]
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn remote_recall_rule_count_threshold_fires_before_share() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-recall-count-http-{}-{}",
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
    let mut ctx = tenkai_sqlite::embedded_ctx(&database).unwrap();
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
            evidence: ChannelPromotionEvidence::default(),
        },
    )
    .await
    .unwrap();
    drop(ctx);

    let zero = management
        .set_channel_recall_rule("api", "stable", &recall_rule(1, 60_000, 0.9, true, Some(0)))
        .await
        .unwrap_err()
        .to_string();
    assert!(zero.contains("failing_max_instances"), "{zero}");
    let stale = management
        .set_channel_recall_rule("api", "stable", &recall_rule(0, 60_000, 0.9, true, Some(1)))
        .await
        .unwrap_err()
        .to_string();
    assert!(stale.contains("409"), "{stale}");
    management
        .set_channel_recall_rule("api", "stable", &recall_rule(1, 60_000, 0.9, true, Some(1)))
        .await
        .unwrap();
    let policy = management
        .channel_promotion_policy("api", "stable")
        .await
        .unwrap();
    assert_eq!(policy.policy_version, 2, "{policy:?}");
    assert_eq!(policy.evidence.failing_max_instances, Some(1), "{policy:?}");
    assert_eq!(policy.evidence.failing_max_share, 0.9, "{policy:?}");
    assert!(policy.evidence.recall_on_failing, "{policy:?}");

    management.reconcile().await.unwrap();
    backdate_soak(&database, 30_000).await;
    management.reconcile().await.unwrap();
    let mut ctx = tenkai_sqlite::embedded_ctx(&database).unwrap();
    observe(&mut ctx, "stage", "api", "1.0.0", false).await;
    drop(ctx);
    backdate_soak(&database, 1_000).await;
    management.reconcile().await.unwrap();

    let view = management.inspect_recall("api@1.0.0").await.unwrap();
    assert_eq!(view.release, "api@1.0.0");
    assert_eq!(view.failing_max_instances, Some(1), "{view:?}");
    assert_eq!(view.failing_instance_count, Some(1), "{view:?}");
    assert_eq!(view.failing_max_share, None, "{view:?}");
    assert!(
        view.reason
            .as_ref()
            .is_some_and(|reason| reason.contains("failing instances")),
        "{view:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn scoped_recall_and_widen_are_on_the_versioned_http_contract() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-recall-scope-http-{}-{}",
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
    let database = root.join("tenkai.db");
    let mut ctx = tenkai_sqlite::embedded_ctx(&database).unwrap();
    for env in ["stage", "prod"] {
        observe(&mut ctx, env, "api", "1.0.0", true).await;
    }
    drop(ctx);

    let unknown = reqwest::Client::new()
        .post(format!("{base}/v1/releases/api@1.0.0/recall/widen"))
        .bearer_auth("management-secret")
        .json(&serde_json::json!({
            "version": tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
            "operation": "not_a_verb",
            "reason": "try",
            "environments": ["prod"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unknown.status().as_u16(),
        400,
        "{}",
        unknown.text().await.unwrap()
    );

    management
        .recall_release_scoped("api@1.0.0", vec!["stage".into()])
        .await
        .unwrap();
    let view = management.inspect_recall("api@1.0.0").await.unwrap();
    assert_eq!(
        view.removal_scope.as_deref(),
        Some(["stage".to_string()].as_slice()),
        "{view:?}"
    );
    assert_eq!(
        view.out_of_scope
            .iter()
            .map(|row| (row.environment.as_str(), row.status.as_str()))
            .collect::<Vec<_>>(),
        vec![("prod", tenkai::catalog::REMOVAL_NOT_IN_SCOPE)]
    );

    let scoped = RemoteClient::new(&base, "stage-secret").unwrap();
    let denied = scoped
        .widen_recall("api@1.0.0", vec!["prod".into()], false, "roll off prod")
        .await
        .unwrap_err()
        .to_string();
    assert!(denied.contains("403"), "{denied}");

    management
        .widen_recall("api@1.0.0", vec!["prod".into()], false, "roll off prod")
        .await
        .unwrap();
    let view = management.inspect_recall("api@1.0.0").await.unwrap();
    assert!(view.out_of_scope.is_empty(), "{view:?}");
    assert_eq!(view.widenings.len(), 1, "{view:?}");
    assert_eq!(view.widenings[0].reason, "roll off prod");

    let retry = management
        .widen_recall("api@1.0.0", vec!["prod".into()], false, "roll off prod")
        .await
        .unwrap();
    assert!(
        retry.message.contains("already covers"),
        "{}",
        retry.message
    );
    let view = management.inspect_recall("api@1.0.0").await.unwrap();
    assert_eq!(view.widenings.len(), 1, "{view:?}");
    let events = store.audit_events().unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.operation == "catalog.recall.widen.completed"),
        "{events:?}"
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

#[tokio::test]
async fn recall_range_exclusion_is_on_the_versioned_http_contract() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-recall-range-exclude-http-{}-{}",
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
    management
        .publish_release(&signed_catalog_fixture(&root, "1.1.0"))
        .await
        .unwrap();
    management
        .record_recall_range("api", "1.0.0", None, "open defect")
        .await
        .unwrap();

    let scoped = RemoteClient::new(&base, "stage-secret").unwrap();
    let denied = scoped
        .exclude_from_recall_range("api", "1.0.0", "1.1.0", "keep serving")
        .await
        .unwrap_err()
        .to_string();
    assert!(denied.contains("403"), "{denied}");

    management
        .exclude_from_recall_range("api", "1.0.0", "1.1.0", "keep serving")
        .await
        .unwrap();
    let ranges = management.list_recall_ranges("api").await.unwrap();
    assert_eq!(ranges.items.len(), 1, "{ranges:?}");
    assert_eq!(
        ranges.items[0]
            .exclusions
            .iter()
            .map(|exclusion| exclusion.version.as_str())
            .collect::<Vec<_>>(),
        ["1.1.0"]
    );
    let still_recalled = management.inspect_recall("api@1.0.0").await.unwrap();
    assert_eq!(still_recalled.range.as_deref(), Some("api [1.0.0, ∞)"));
    let excluded = management.inspect_recall("api@1.1.0").await.unwrap_err();
    assert!(
        excluded.to_string().contains("not recalled") || excluded.to_string().contains("404"),
        "{excluded}"
    );

    management
        .remove_recall_range_exclusion("api", "1.0.0", "1.1.0", "put 1.1.0 back")
        .await
        .unwrap();
    let view = management.inspect_recall("api@1.1.0").await.unwrap();
    assert_eq!(view.range.as_deref(), Some("api [1.0.0, ∞)"));
    let ranges = management.list_recall_ranges("api").await.unwrap();
    assert!(ranges.items[0].exclusions.is_empty(), "{ranges:?}");
    let events = store.audit_events().unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.operation == "catalog.recall.range.exclude.completed"),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event.operation == "catalog.recall.range.exclude.remove.completed"),
        "{events:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}
