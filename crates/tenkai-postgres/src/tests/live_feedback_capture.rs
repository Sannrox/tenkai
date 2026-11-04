use super::super::*;
use tenkai::feedback_observation::{Capture, FeedbackObservation, Operation, Reason};
use tenkai::pb::sekai::Object;
use tenkai::storage::{CatalogGraph, ProviderEventRecord};

fn observation(id: &str, status: &str) -> FeedbackObservation {
    FeedbackObservation::capture(Capture {
        id,
        operation: Operation::ApplyStep,
        environment: "prod",
        product: "api",
        plan_id: "plan-1",
        step_id: "step-1",
        action: Some(tenkai::plan::Action::Upgrade),
        release_id: "release:api:1.1.0",
        status,
        reason: Reason::None,
        started_at_ms: Some(1_000),
        lease_generation: 1,
        observed_at_ms: 2_000,
        context: Default::default(),
    })
}

fn named(object: &Object, name: &str) -> Object {
    Object {
        name: name.into(),
        ..object.clone()
    }
}

/// A tenant partition keeps the feedback observation committed with its
/// write, isolated from other tenants, immutable on replay, rolled back with
/// a refused write, and never fails the write when it cannot be stored (#868).
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_tenant_partition_captures_feedback_observations() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let suffix = format!(
        "{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let (tenant_a, tenant_b) = (format!("fa{suffix}"), format!("fb{suffix}"));
    let (a, b) = (Some(tenant_a.as_str()), Some(tenant_b.as_str()));
    let object = Object {
        id: format!("tenkai:conformance:observed:{suffix}"),
        kind: "tenkai.conformance".into(),
        name: "original".into(),
        ..Default::default()
    };
    store.create(a, object.clone()).unwrap();

    let first = observation(&format!("deployment:prod:api:{suffix}"), "succeeded");
    store
        .put_with_provider_events(
            a,
            named(&object, "terminal"),
            &[],
            std::slice::from_ref(&first),
        )
        .unwrap();
    assert_eq!(
        store.feedback_observations(a, "prod").unwrap(),
        std::slice::from_ref(&first)
    );
    assert!(store.feedback_observations(b, "prod").unwrap().is_empty());

    // A conflicting replay keeps the stored record; the write still commits.
    store
        .put_with_provider_events(
            a,
            named(&object, "replayed"),
            &[],
            &[observation(&first.id, "failed")],
        )
        .unwrap();
    assert_eq!(store.get(a, &object.id).unwrap().unwrap().name, "replayed");
    assert_eq!(
        store.feedback_observations(a, "prod").unwrap(),
        std::slice::from_ref(&first)
    );

    // A refused write takes its observation with it.
    let invalid = ProviderEventRecord {
        id: String::new(),
        provider_kind: "outcome".into(),
        binding_digest: "digest".into(),
        payload_json: r#"{"binding":{"environment_id":"prod"},"payload_json":"{}"}"#.into(),
        attempts: 0,
        next_attempt_at: 1,
        delivered_at: None,
        last_error: String::new(),
        claim_token: None,
        claim_until: None,
    };
    assert!(
        store
            .put_with_provider_events(
                a,
                named(&object, "must-roll-back"),
                &[invalid],
                &[observation(&format!("{}:rolled", first.id), "failed")],
            )
            .is_err()
    );
    assert_eq!(store.get(a, &object.id).unwrap().unwrap().name, "replayed");
    assert_eq!(store.feedback_observations(a, "prod").unwrap(), [first]);

    // A capture that cannot be stored rolls back alone.
    let schema_a = tenant_schema_name(&tenant_a).unwrap();
    let schema_b = tenant_schema_name(&tenant_b).unwrap();
    let mut raw = postgres::Client::connect(&config.url, postgres::NoTls).expect("raw connect");
    // Every catalog call re-runs the idempotent tenant migration, so refuse
    // inserts with a constraint rather than dropping the table.
    raw.batch_execute(&format!(
        "ALTER TABLE {schema_a}.feedback_observations
         ADD CONSTRAINT refuse_capture CHECK (false) NOT VALID"
    ))
    .unwrap();
    store
        .put_with_provider_events(
            a,
            named(&object, "uncaptured"),
            &[],
            &[observation(&format!("{suffix}:lost"), "succeeded")],
        )
        .unwrap();
    assert_eq!(
        store.get(a, &object.id).unwrap().unwrap().name,
        "uncaptured"
    );
    assert_eq!(store.feedback_observations(a, "prod").unwrap().len(), 1);
    raw.batch_execute(&format!(
        "DROP SCHEMA {schema_a} CASCADE; DROP SCHEMA {schema_b} CASCADE"
    ))
    .unwrap();
}
