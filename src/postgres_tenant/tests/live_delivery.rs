use super::super::*;

/// Two-replica delivery-effect conformance. Every mutation uses a stable
/// identity, and execution/rollback commits are rejected after lease handoff.
#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_delivery_effects_are_idempotent_and_fenced() {
    use crate::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };
    use crate::runtime_capabilities::CapabilityName;
    use crate::storage::{
        ChannelRecord, EnvironmentRecord, OperationalStore as _, PlanRecord, PlanStatus,
        ReceiptRecord, ReleaseRecord, RollbackRecord, RollbackStatus, StoreError,
    };
    use std::sync::{Arc, Barrier};

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let replica_a = config.open().expect("connect replica a");
    let replica_b = config.open().expect("connect replica b");
    let authority = TenantDerivationAuthority::new("test");
    let context = AuthenticatedRequestContextBuilder::new(
        format!("delivery-effects-{suffix}"),
        PrincipalIdentity {
            id: "ha-conformance".into(),
            kind: PrincipalKind::Service,
        },
        "test",
    )
    .with_tenant(format!("ha-{suffix}"), &authority)
    .unwrap()
    .build()
    .unwrap();
    let a = replica_a.partition_for(&context).unwrap();
    let b = replica_b.partition_for(&context).unwrap();

    let release = ReleaseRecord {
        id: format!("release-{suffix}"),
        product: "api".into(),
        version: "1.0.0".into(),
        content_digest: format!("sha256:{suffix}"),
        descriptor_json: "{}".into(),
    };
    let barrier = Arc::new(Barrier::new(2));
    let (publish_a, publish_b) = std::thread::scope(|scope| {
        let left = {
            let a = a.clone();
            let release = release.clone();
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                a.publish_release(&release)
            })
        };
        let right = {
            let b = b.clone();
            let release = release.clone();
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                b.publish_release(&release)
            })
        };
        (left.join().unwrap(), right.join().unwrap())
    });
    publish_a.unwrap();
    publish_b.unwrap();

    let channel = ChannelRecord {
        id: format!("channel-{suffix}"),
        product: "api".into(),
        name: "stable".into(),
        release_id: release.id.clone(),
        revision: 0,
    };
    let barrier = Arc::new(Barrier::new(2));
    let (promotion_a, promotion_b) = std::thread::scope(|scope| {
        let left = {
            let a = a.clone();
            let channel = channel.clone();
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                a.promote_channel(&channel)
            })
        };
        let right = {
            let b = b.clone();
            let channel = channel.clone();
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                b.promote_channel(&channel)
            })
        };
        (left.join().unwrap(), right.join().unwrap())
    });
    assert_eq!(promotion_a.unwrap().revision, 1);
    assert_eq!(promotion_b.unwrap().revision, 1);

    let environment = EnvironmentRecord {
        id: format!("environment-{suffix}"),
        revision: 0,
        configuration_json: "{}".into(),
    };
    a.put_environment(&environment).unwrap();
    let plan = PlanRecord {
        id: format!("plan-{suffix}"),
        environment_id: environment.id.clone(),
        format_version: 1,
        content_digest: format!("sha256:plan-{suffix}"),
        plan_json: "{}".into(),
        status: PlanStatus::Computed,
        status_detail: String::new(),
    };
    a.create_plan(&plan).unwrap();
    b.create_plan(&plan).unwrap();

    let lease_a = a
        .acquire_lease(
            &environment.id,
            "replica-a",
            crate::now_millis().saturating_add(60_000),
        )
        .unwrap();
    a.transition_plan(
        &plan.id,
        "replica-a",
        lease_a.generation,
        PlanStatus::Running,
        "started",
    )
    .unwrap();
    let receipt = ReceiptRecord {
        id: format!("receipt-{suffix}"),
        environment_id: environment.id.clone(),
        plan_id: plan.id.clone(),
        step_id: "apply-api".into(),
        lease_generation: lease_a.generation,
        payload_json: r#"{"outcome":"succeeded"}"#.into(),
    };
    a.record_receipt("replica-a", &receipt).unwrap();

    // Simulate process loss after the authoritative receipt commit. A fresh
    // replica reuses the recorded outcome instead of repeating the effect.
    let restarted = config.open().expect("connect restarted replica");
    let restarted = restarted.partition_for(&context).unwrap();
    restarted
        .record_receipt("replacement-owner", &receipt)
        .unwrap();
    assert_eq!(restarted.get_receipt(&receipt.id).unwrap(), Some(receipt));

    let rollback = RollbackRecord {
        id: format!("rollback-{suffix}"),
        environment_id: environment.id.clone(),
        plan_id: plan.id.clone(),
        lease_generation: lease_a.generation,
        checkpoint_json: r#"{"step":0}"#.into(),
        status: RollbackStatus::Pending,
        status_detail: "prepared".into(),
    };
    a.create_rollback("replica-a", &rollback).unwrap();
    restarted
        .create_rollback("replacement-owner", &rollback)
        .unwrap();
    let mut conflicting_rollback = rollback.clone();
    conflicting_rollback.checkpoint_json = r#"{"step":1}"#.into();
    assert!(matches!(
        restarted.create_rollback("replacement-owner", &conflicting_rollback),
        Err(StoreError::ImmutableConflict {
            kind: "rollback",
            ..
        })
    ));

    a.inner
        .expire_lease_for_test(a.schema(), &environment.id)
        .unwrap();
    let lease_b = b
        .acquire_lease(
            &environment.id,
            "replica-b",
            crate::now_millis().saturating_add(60_000),
        )
        .unwrap();
    assert_eq!(lease_b.generation, lease_a.generation + 1);

    let mut stale_rejections = 0;
    for result in [
        a.transition_plan(
            &plan.id,
            "replica-a",
            lease_a.generation,
            PlanStatus::Succeeded,
            "stale",
        )
        .map(|_| ()),
        a.record_receipt(
            "replica-a",
            &ReceiptRecord {
                id: format!("stale-receipt-{suffix}"),
                ..restarted
                    .get_receipt(&format!("receipt-{suffix}"))
                    .unwrap()
                    .unwrap()
            },
        ),
        a.transition_rollback(
            &rollback.id,
            "replica-a",
            lease_a.generation,
            RollbackStatus::Running,
            r#"{"step":1}"#,
            "stale",
        )
        .map(|_| ()),
    ] {
        assert!(matches!(result, Err(StoreError::StaleLease { .. })));
        stale_rejections += 1;
    }
    assert_eq!(stale_rejections, 3);

    b.transition_rollback(
        &rollback.id,
        "replica-b",
        lease_b.generation,
        RollbackStatus::Running,
        r#"{"step":1}"#,
        "resumed",
    )
    .unwrap();
    b.transition_rollback(
        &rollback.id,
        "replica-b",
        lease_b.generation,
        RollbackStatus::Succeeded,
        r#"{"step":2}"#,
        "completed",
    )
    .unwrap();
    // A delayed retry of the original creation intent remains idempotent
    // after lease handoff and mutable rollback progress.
    b.create_rollback("replica-b", &rollback).unwrap();
    b.transition_plan(
        &plan.id,
        "replica-b",
        lease_b.generation,
        PlanStatus::Succeeded,
        "completed",
    )
    .unwrap();

    assert_eq!(
        a.inner.delivery_effect_counts_for_test(a.schema()).unwrap(),
        (1, 1, 1, 1)
    );
    assert!(
        !tenant_postgres_store_capabilities()
            .capabilities
            .iter()
            .any(|capability| capability.name == CapabilityName::HighAvailability)
    );
}
