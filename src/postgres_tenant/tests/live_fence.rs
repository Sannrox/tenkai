use super::super::*;

/// Live durable fence drill. Requires feature `postgres` and `TENKAI_POSTGRES_URL`.
#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_reconcile_fence_claim_and_busy() {
    use crate::reconcile_fence::FenceAdmission;

    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let fence = store.reconcile_tick_fence();
    let env = format!("fence-test-{}", uuid::Uuid::new_v4());
    let a = fence.try_begin(&env, "host-a", 1_000_000, 60_000).unwrap();
    assert!(matches!(a, FenceAdmission::Started { generation: 1 }));
    let b = fence.try_begin(&env, "host-b", 1_000_100, 60_000).unwrap();
    assert!(matches!(b, FenceAdmission::Busy { .. }));
    fence.release(&env, "host-a", 1, 1_000_200).unwrap();
    let c = fence.try_begin(&env, "host-b", 1_000_300, 60_000).unwrap();
    assert!(matches!(c, FenceAdmission::Started { generation: 2 }));
    fence.release(&env, "host-a", 1, 1_000_400).unwrap();
    assert!(matches!(
        fence.try_begin(&env, "host-c", 1_000_500, 60_000).unwrap(),
        FenceAdmission::Busy { .. }
    ));
    // Expired takeover bumps generation.
    fence.release(&env, "host-b", 2, 1_000_600).unwrap();
    assert!(matches!(
        fence.try_begin(&env, "host-a", 2_000_000, 100).unwrap(),
        FenceAdmission::Started { generation: 3 }
    ));
    let takeover = fence.try_begin(&env, "host-b", 2_000_200, 60_000).unwrap();
    assert_eq!(takeover, FenceAdmission::Started { generation: 4 });
    fence.release(&env, "host-b", 4, 2_000_300).unwrap();
}
