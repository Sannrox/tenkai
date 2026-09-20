use std::sync::Arc;

use crate::client::PlanKindListTick;
use crate::pb::sekai::Object;

use super::mock_router::remote_ctx;
use super::mock_state::MockSekaiState;

#[test]
fn plan_kind_list_tick_is_inactive_outside_begin() {
    let tick = PlanKindListTick::default();
    assert!(tick.tick_cell().is_none());
    tick.begin();
    assert!(tick.tick_cell().is_some());
    tick.end();
    assert!(tick.tick_cell().is_none());
}

#[tokio::test]
async fn plan_kind_list_tick_loads_once_while_active() {
    let tick = PlanKindListTick::default();
    tick.begin();
    let loads = std::sync::atomic::AtomicUsize::new(0);
    let load = || {
        loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async {
            Ok(vec![Object {
                id: "plan-1".into(),
                ..Default::default()
            }])
        }
    };
    let first = tick.get_or_load(load).await.unwrap();
    let second = tick.get_or_load(load).await.unwrap();
    assert_eq!(loads.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(first[0].id, "plan-1");
    tick.end();
    let _ = tick.get_or_load(load).await.unwrap();
    assert_eq!(loads.load(std::sync::atomic::Ordering::SeqCst), 2);
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
    }
    .to_object()
    .unwrap()
}

#[tokio::test]
async fn shared_retarget_tick_fails_closed_when_later_env_index_omits_after_snapshot() {
    let env_a = mock_plan_object("env-a", 10);
    let env_b = mock_plan_object("env-b", 20);
    let env_b_id = env_b.id.clone();
    let state = MockSekaiState::default();
    state
        .objects
        .lock()
        .unwrap()
        .insert(env_a.id.clone(), env_a);
    state
        .objects
        .lock()
        .unwrap()
        .insert(env_b.id.clone(), env_b);
    let (ctx, server) = remote_ctx(state.clone()).await;
    let (mut tick_ctx, _guard) = ctx.with_shared_plan_retarget_tick();

    crate::plan::require_environment_indexes_match_payloads(&mut tick_ctx, "env-a")
        .await
        .unwrap();

    {
        let mut objects = state.objects.lock().unwrap();
        let mut retargeted = objects.get(&env_b_id).cloned().unwrap();
        retargeted
            .properties
            .insert("environment".into(), "other".into());
        objects.insert(env_b_id, retargeted);
    }

    let error = crate::plan::require_environment_indexes_match_payloads(&mut tick_ctx, "env-b")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("omitted from environment env-b after shared retarget snapshot"),
        "{error}"
    );
    server.abort();
}
