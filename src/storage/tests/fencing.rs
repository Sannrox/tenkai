use super::*;

#[test]
fn generations_fence_receipts_and_rollback_updates() {
    let store = SqliteStore::open_in_memory().unwrap();
    environment(&store);
    plan(&store);
    let now = crate::now_millis();
    let first = store.acquire_lease("prod", "worker-a", now + 50).unwrap();
    let rollback = RollbackRecord {
        id: "rollback-1".into(),
        environment_id: "prod".into(),
        plan_id: "plan-1".into(),
        lease_generation: first.generation,
        checkpoint_json: "{}".into(),
        status: RollbackStatus::Pending,
        status_detail: String::new(),
    };
    store.create_rollback("worker-a", &rollback).unwrap();
    assert!(matches!(
        store.acquire_lease("prod", "worker-b", now + 10_000),
        Err(StoreError::LeaseHeld { .. })
    ));
    std::thread::sleep(std::time::Duration::from_millis(60));
    let second = store
        .acquire_lease("prod", "worker-b", now + 10_000)
        .unwrap();
    assert!(matches!(
        store.record_receipt(
            "worker-a",
            &ReceiptRecord {
                id: "receipt-1".into(),
                environment_id: "prod".into(),
                plan_id: "plan-1".into(),
                step_id: "step-1".into(),
                lease_generation: first.generation,
                payload_json: "{}".into()
            }
        ),
        Err(StoreError::StaleLease { .. })
    ));
    assert!(matches!(
        store.transition_rollback(
            "rollback-1",
            "worker-a",
            first.generation,
            RollbackStatus::Running,
            "{}",
            "retry"
        ),
        Err(StoreError::StaleLease { .. })
    ));
    let resumed = store
        .transition_rollback(
            "rollback-1",
            "worker-b",
            second.generation,
            RollbackStatus::Running,
            "{\"resumed\":true}",
            "recovered after takeover",
        )
        .unwrap();
    assert_eq!(resumed.lease_generation, second.generation);
    store.create_rollback("worker-a", &rollback).unwrap();
    let mut collision = rollback.clone();
    collision.checkpoint_json = "{\"different\":true}".into();
    assert!(matches!(
        store.create_rollback("worker-a", &collision),
        Err(StoreError::ImmutableConflict { .. })
    ));
    let mut detail_collision = rollback.clone();
    detail_collision.status_detail = "different intent".into();
    assert!(matches!(
        store.create_rollback("worker-a", &detail_collision),
        Err(StoreError::ImmutableConflict { .. })
    ));
}

#[test]
fn pending_rollback_survives_restart_and_receipts_are_idempotent() {
    let path = std::env::temp_dir().join(format!("tenkai-recovery-{}.db", uuid::Uuid::new_v4()));
    let receipt = ReceiptRecord {
        id: "receipt-1".into(),
        environment_id: "prod".into(),
        plan_id: "plan-1".into(),
        step_id: "step-1".into(),
        lease_generation: 1,
        payload_json: "{\"ok\":true}".into(),
    };
    {
        let store = SqliteStore::open(&path).unwrap();
        environment(&store);
        plan(&store);
        let now = crate::now_millis();
        let lease = store.acquire_lease("prod", "worker", now + 10_000).unwrap();
        assert_eq!(lease.generation, receipt.lease_generation);
        store.record_receipt("worker", &receipt).unwrap();
        store.record_receipt("worker", &receipt).unwrap();
        store
            .create_rollback(
                "worker",
                &RollbackRecord {
                    id: "rollback-1".into(),
                    environment_id: "prod".into(),
                    plan_id: "plan-1".into(),
                    lease_generation: receipt.lease_generation,
                    checkpoint_json: "{\"next\":1}".into(),
                    status: RollbackStatus::Pending,
                    status_detail: String::new(),
                },
            )
            .unwrap();
    }
    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(reopened.get_receipt("receipt-1").unwrap(), Some(receipt));
    assert_eq!(reopened.pending_rollbacks().unwrap().len(), 1);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn revisions_prevent_stale_environment_and_channel_writes() {
    let store = SqliteStore::open_in_memory().unwrap();
    let first = store
        .put_environment(&EnvironmentRecord {
            id: "prod".into(),
            revision: 0,
            configuration_json: "{}".into(),
        })
        .unwrap();
    let updated = store
        .put_environment(&EnvironmentRecord {
            configuration_json: "{\"region\":\"eu\"}".into(),
            ..first.clone()
        })
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert!(matches!(
        store.put_environment(&first),
        Err(StoreError::RevisionConflict { .. })
    ));

    store
        .publish_release(&ReleaseRecord {
            id: "release-1".into(),
            product: "api".into(),
            version: "1.0.0".into(),
            content_digest: "sha256:a".into(),
            descriptor_json: "{}".into(),
        })
        .unwrap();
    let channel = store
        .promote_channel(&ChannelRecord {
            id: "api/stable".into(),
            product: "api".into(),
            name: "stable".into(),
            release_id: "release-1".into(),
            revision: 0,
        })
        .unwrap();
    store
        .publish_release(&ReleaseRecord {
            id: "release-other".into(),
            product: "other".into(),
            version: "1.0.0".into(),
            content_digest: "sha256:other".into(),
            descriptor_json: "{}".into(),
        })
        .unwrap();
    assert!(matches!(
        store.promote_channel(&ChannelRecord {
            product: "other".into(),
            release_id: "release-other".into(),
            ..channel
        }),
        Err(StoreError::ImmutableConflict { .. })
    ));
    assert!(matches!(
        store.promote_channel(&ChannelRecord {
            id: "api/dev".into(),
            product: "api".into(),
            name: "dev".into(),
            release_id: "release-other".into(),
            revision: 0,
        }),
        Err(StoreError::InvalidData {
            kind: "channel",
            ..
        })
    ));
}

#[test]
fn execution_records_cannot_cross_environment_boundaries() {
    let store = SqliteStore::open_in_memory().unwrap();
    environment(&store);
    plan(&store);
    store
        .put_environment(&EnvironmentRecord {
            id: "other".into(),
            revision: 0,
            configuration_json: "{}".into(),
        })
        .unwrap();
    let now = crate::now_millis();
    let lease = store
        .acquire_lease("other", "worker", now + 10_000)
        .unwrap();
    assert!(matches!(
        store.record_receipt(
            "worker",
            &ReceiptRecord {
                id: "receipt-other".into(),
                environment_id: "other".into(),
                plan_id: "plan-1".into(),
                step_id: "step-1".into(),
                lease_generation: lease.generation,
                payload_json: "{}".into(),
            }
        ),
        Err(StoreError::EnvironmentMismatch { .. })
    ));
}
