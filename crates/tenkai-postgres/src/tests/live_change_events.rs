use super::super::*;

/// A kind written by a newer replica is skipped by this version's reader, so a
/// rolling deploy or rollback never fails a change-event page (#775).
#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_change_events_skip_unknown_kinds() {
    use tenkai::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };
    use tenkai::change_stream::ChangeEventKind;

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let store = PostgresTenantConfig::from_env()
        .expect("TENKAI_POSTGRES_URL")
        .open()
        .expect("connect");
    let authority = TenantDerivationAuthority::new("test");
    let context = AuthenticatedRequestContextBuilder::new(
        format!("events-{suffix}"),
        PrincipalIdentity {
            id: "events-conformance".into(),
            kind: PrincipalKind::Service,
        },
        "test",
    )
    .with_tenant(format!("events-{suffix}"), &authority)
    .unwrap()
    .build()
    .unwrap();
    let partition = store.partition_for(&context).unwrap();

    partition
        .append_change_event(1, "plan_created", "plan/a", "")
        .unwrap();
    partition
        .insert_raw_change_event_for_conformance("from_a_newer_version")
        .unwrap();
    partition
        .append_change_event(3, "plan_applied", "plan/a", "")
        .unwrap();
    let kinds: Vec<_> = partition
        .list_change_events_after(0, 10)
        .unwrap()
        .into_iter()
        .map(|event| event.kind)
        .collect();
    assert_eq!(
        kinds,
        [ChangeEventKind::PlanCreated, ChangeEventKind::PlanApplied]
    );
}
