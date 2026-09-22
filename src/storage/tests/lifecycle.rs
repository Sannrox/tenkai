use super::*;

#[test]
fn schema_is_created_and_reopened_without_optional_provider() {
    let path = std::env::temp_dir().join(format!("tenkai-storage-{}.db", uuid::Uuid::new_v4()));
    {
        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        store
            .publish_release(&ReleaseRecord {
                id: "release-1".into(),
                product: "api".into(),
                version: "1.0.0".into(),
                content_digest: "sha256:a".into(),
                descriptor_json: "{}".into(),
            })
            .unwrap();
    }
    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(
        reopened.get_release("release-1").unwrap().unwrap().version,
        "1.0.0"
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn audit_events_are_durable_and_append_only() {
    let path = std::env::temp_dir().join(format!("tenkai-audit-{}.db", uuid::Uuid::new_v4()));
    let event = AuditRecord {
        id: "audit-1".into(),
        occurred_at: 42,
        principal: "operator".into(),
        operation: "reconcile.requested".into(),
        resource: "prod".into(),
        outcome: "requested".into(),
    };
    SqliteStore::open(&path)
        .unwrap()
        .append_audit(&event)
        .unwrap();
    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(reopened.audit_events().unwrap(), vec![event.clone()]);
    assert!(reopened.append_audit(&event).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn runtime_plan_claims_are_durable_and_exclusive() {
    let path = std::env::temp_dir().join(format!("tenkai-claim-{}.db", uuid::Uuid::new_v4()));
    let expiry = crate::now_millis() + 10_000;
    let first = SqliteStore::open(&path)
        .unwrap()
        .claim_runtime_plan("prod", "plan-1", "runtime-a", expiry)
        .unwrap()
        .unwrap();
    assert_eq!(first.generation, 1);
    assert_eq!(first.completion_json, None);
    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .claim_runtime_plan("prod", "plan-1", "runtime-a", expiry + 1)
            .unwrap()
            .unwrap()
            .generation,
        1
    );
    assert_eq!(
        reopened
            .claim_runtime_plan("prod", "plan-1", "runtime-b", expiry + 1)
            .unwrap(),
        None
    );
    assert_eq!(
        reopened
            .renew_runtime_plan("plan-1", "runtime-b", 1, expiry + 2)
            .unwrap(),
        None
    );
    let renewed = reopened
        .renew_runtime_plan("plan-1", "runtime-a", 1, expiry + 2)
        .unwrap()
        .unwrap();
    assert_eq!(renewed.generation, 1);
    assert_eq!(renewed.expires_at, expiry + 2);
    reopened
        .complete_runtime_plan("plan-1", "runtime-a", 1, "{\"ok\":true}")
        .unwrap();
    assert_eq!(
        reopened
            .claim_runtime_plan("prod", "plan-1", "runtime-a", expiry + 2)
            .unwrap()
            .unwrap()
            .completion_json
            .as_deref(),
        Some("{\"ok\":true}")
    );
    reopened
        .complete_runtime_plan("plan-1", "runtime-a", 1, "{\"ok\":true}")
        .unwrap();
    assert!(
        reopened
            .complete_runtime_plan("plan-1", "runtime-a", 1, "{\"ok\":false}")
            .is_err()
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn offline_imports_are_durable_idempotent_and_conflict_safe() {
    let path = std::env::temp_dir().join(format!("tenkai-offline-{}.db", uuid::Uuid::new_v4()));
    let record = OfflineImportRecord {
        bundle_digest: "sha256:bundle".into(),
        environment_id: "prod".into(),
        plan_id: "plan-1".into(),
        receipt_json: "{\"result\":\"succeeded\"}".into(),
    };
    let step = OfflineStepImportRecord {
        receipt_id: "receipt-1".into(),
        environment_id: "prod".into(),
        plan_id: "plan-1".into(),
        step_id: "step-1".into(),
        attempt: 1,
        result_digest: "sha256:result".into(),
        succeeded: true,
    };
    {
        let store = SqliteStore::open(&path).unwrap();
        environment(&store);
        plan(&store);
        store
            .record_offline_import(&record, std::slice::from_ref(&step))
            .unwrap();
        store
            .record_offline_import(&record, std::slice::from_ref(&step))
            .unwrap();
    }
    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(
        reopened.get_offline_import(&record.bundle_digest).unwrap(),
        Some(record.clone())
    );
    let mut conflict = record.clone();
    conflict.receipt_json = "{\"result\":\"failed\"}".into();
    assert!(matches!(
        reopened.record_offline_import(&conflict, std::slice::from_ref(&step)),
        Err(StoreError::ImmutableConflict {
            kind: "offline import",
            ..
        })
    ));
    let mut reexport = record;
    reexport.bundle_digest = "sha256:other-bundle".into();
    reexport.receipt_json = "{\"result\":\"other\"}".into();
    let mut conflicting_step = step;
    conflicting_step.result_digest = "sha256:different".into();
    assert!(matches!(
        reopened.record_offline_import(&reexport, &[conflicting_step]),
        Err(StoreError::ImmutableConflict {
            kind: "offline step receipt",
            ..
        })
    ));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn release_content_and_plan_content_are_immutable() {
    let store = SqliteStore::open_in_memory().unwrap();
    let mut release = ReleaseRecord {
        id: "release-1".into(),
        product: "api".into(),
        version: "1.0.0".into(),
        content_digest: "sha256:a".into(),
        descriptor_json: "{}".into(),
    };
    store.publish_release(&release).unwrap();
    store.publish_release(&release).unwrap();
    release.content_digest = "sha256:b".into();
    assert!(matches!(
        store.publish_release(&release),
        Err(StoreError::ImmutableConflict { .. })
    ));
    environment(&store);
    let mut created = plan(&store);
    created.plan_json = "{\"changed\":true}".into();
    assert!(matches!(
        store.create_plan(&created),
        Err(StoreError::ImmutableConflict { .. })
    ));
}

#[test]
fn plan_lifecycle_is_transactionally_constrained() {
    let store = SqliteStore::open_in_memory().unwrap();
    environment(&store);
    plan(&store);
    let now = crate::now_millis();
    let lease = store.acquire_lease("prod", "worker", now + 10_000).unwrap();
    store
        .transition_plan(
            "plan-1",
            "worker",
            lease.generation,
            PlanStatus::Running,
            "started",
        )
        .unwrap();
    store
        .transition_plan(
            "plan-1",
            "worker",
            lease.generation,
            PlanStatus::Succeeded,
            "done",
        )
        .unwrap();
    assert!(matches!(
        store.transition_plan(
            "plan-1",
            "worker",
            lease.generation,
            PlanStatus::Running,
            "retry"
        ),
        Err(StoreError::InvalidPlanTransition { .. })
    ));
}
