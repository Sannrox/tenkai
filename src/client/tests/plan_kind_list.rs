use crate::client::{Ctx, PlanKindListTick};
use crate::pb::record::Object;

#[test]
fn plan_kind_list_tick_is_inactive_outside_begin() {
    let tick = PlanKindListTick::default();
    assert!(tick.tick_cell().is_none());
    tick.begin();
    assert!(tick.tick_cell().is_some());
    tick.end();
    assert!(tick.tick_cell().is_none());
}

fn mock_plan_object(env: &str, created_at: i64) -> Object {
    crate::plan::Plan {
        format_version: crate::plan::PLAN_FORMAT_VERSION,
        id: format!("tenkai:plan:{env}:{created_at}:fixture"),
        content_id: format!("sha256:{created_at}"),
        environment: env.into(),
        created_at,
        inputs: Vec::new(),
        steps: Vec::new(),
        state: crate::plan::PlanState::Computed,
        gates_skipped: None,
        status_detail: String::new(),
        maintenance_blocked: false,
        prior_warnings: Vec::new(),
        recalled_recovery_reason: None,
        recalled_upgrade: Vec::new(),
        credential_runway: None,
        artifact_availability: Vec::new(),
        config_presets: Vec::new(),
        approval_brief: None,
    }
    .to_object()
    .unwrap()
}

#[tokio::test]
async fn shared_retarget_tick_fails_closed_when_later_env_index_omits_after_snapshot() {
    let env_a = mock_plan_object("env-a", 10);
    let env_b = mock_plan_object("env-b", 20);
    let path = std::env::temp_dir().join(format!(
        "tenkai-plan-retarget-{}-{}.db",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut ctx = Ctx::embedded(&path).unwrap();
    ctx.put(env_a).await.unwrap();
    let mut retargeted = ctx.put(env_b).await.unwrap();
    let (mut tick_ctx, _guard) = ctx.with_shared_plan_retarget_tick();

    crate::plan::require_environment_indexes_match_payloads(&mut tick_ctx, "env-a")
        .await
        .unwrap();

    retargeted
        .properties
        .insert("environment".into(), "other".into());
    ctx.put(retargeted).await.unwrap();

    let error = crate::plan::require_environment_indexes_match_payloads(&mut tick_ctx, "env-b")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("omitted from environment env-b after shared retarget snapshot"),
        "{error}"
    );
    let _ = std::fs::remove_file(path);
}
