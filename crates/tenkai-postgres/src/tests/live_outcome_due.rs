use super::super::*;
use tenkai::providers::OUTCOME_PROVIDER_KIND;
use tenkai::storage::{OperationalStore as _, ProviderEventRecord};

fn event(id: &str, provider_kind: &str, next_attempt_at: i64) -> ProviderEventRecord {
    ProviderEventRecord {
        id: id.into(),
        provider_kind: provider_kind.into(),
        binding_digest: "sha256:binding".into(),
        payload_json: "{}".into(),
        attempts: 0,
        next_attempt_at,
        delivered_at: None,
        last_error: String::new(),
        claim_token: None,
        claim_until: None,
    }
}

/// The export sweep visits only schemas with an outcome a claim would take
/// (#872): due, unclaimed or past its claim, and undelivered. Kinds not
/// asked for and quiet tenants are skipped. Other tests share the database, so this
/// checks only its own schemas.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_export_sweep_visits_only_tenants_with_an_outcome_due() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let tenants = super::LiveTenants::new(&config);
    let store = config.open().expect("connect");
    let suffix = format!(
        "{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let (busy, quiet) = (format!("od{suffix}"), format!("oq{suffix}"));
    tenants.adopt(&busy);
    tenants.adopt(&quiet);
    let busy = store.partition_by_id(&busy).unwrap();
    let quiet = store.partition_by_id(&quiet).unwrap();
    busy.enqueue_provider_event(&event("outcome-1", OUTCOME_PROVIDER_KIND, 1_000))
        .unwrap();
    quiet
        .enqueue_provider_event(&event("feedback-1", "feedback", 1_000))
        .unwrap();
    let due_any = |kinds: &[&str], now| store.inner.due_provider_event_schemas(kinds, now).unwrap();
    let due = |now| due_any(&[OUTCOME_PROVIDER_KIND], now);

    let at_due = due(1_000);
    assert!(at_due.contains(&busy.schema), "{at_due:?}");
    assert!(!at_due.contains(&quiet.schema), "another kind is not due");
    assert!(!due(999).contains(&busy.schema), "not yet due");
    // One query covers every enabled kind (#877).
    let either = due_any(&[OUTCOME_PROVIDER_KIND, "feedback"], 1_000);
    assert!(
        either.contains(&busy.schema) && either.contains(&quiet.schema),
        "{either:?}"
    );

    let claimed = busy
        .claim_provider_events_for_kind(OUTCOME_PROVIDER_KIND, 1_000, 10, "worker-a", 5_000)
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert!(
        !due(1_000).contains(&busy.schema),
        "a live claim is not due"
    );
    assert!(due(5_000).contains(&busy.schema), "an expired claim is due");

    let reclaimed = busy
        .claim_provider_events_for_kind(OUTCOME_PROVIDER_KIND, 5_000, 10, "worker-b", 9_000)
        .unwrap();
    busy.mark_provider_event_delivered(OUTCOME_PROVIDER_KIND, &reclaimed[0].id, "worker-b", 5_001)
        .unwrap();
    assert!(!due(10_000).contains(&busy.schema), "delivered is not due");
}
