use super::super::*;
use std::collections::HashMap;
use tenkai::ontology::ACTION_SUBSCRIBE;
use tenkai::pb::sekai::{Link, Object};
use tenkai::storage::{CatalogGraph, StoreError};

/// Live catalog object-graph drill. Requires feature `postgres` and `TENKAI_POSTGRES_URL`.
#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_catalog_matches_sqlite_contract_and_isolates_tenants() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let suffix = format!(
        "{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let tenant_a = format!("ca{suffix}");
    let tenant_b = format!("cb{suffix}");
    assert_graph(&store, Some(&tenant_a));

    let isolated = Object {
        id: format!("tenkai:catalog:{suffix}"),
        kind: "tenkai.conformance".into(),
        name: "a".into(),
        ..Object::default()
    };
    store.create(Some(&tenant_a), isolated.clone()).unwrap();
    assert!(store.get(Some(&tenant_b), &isolated.id).unwrap().is_none());
    assert_eq!(
        store
            .list_kind(Some(&tenant_a), "tenkai.conformance")
            .unwrap()
            .iter()
            .filter(|object| object.id == isolated.id)
            .count(),
        1
    );
    assert!(
        store
            .list_kind(Some(&tenant_b), "tenkai.conformance")
            .unwrap()
            .is_empty()
    );
    let missing = store.get(None, &isolated.id).unwrap_err();
    let message = missing.to_string();
    assert!(
        message.contains("missing tenant")
            || missing
                .downcast_ref::<StoreError>()
                .is_some_and(|error| matches!(error, StoreError::AdapterUnavailable(_))),
        "{message}"
    );

    let missing_target = store
        .execute_action(
            Some(&tenant_a),
            ACTION_SUBSCRIBE,
            HashMap::from([("id".into(), "tenkai:env:missing".into())]),
            true,
        )
        .unwrap_err();
    assert!(
        missing_target.downcast_ref::<StoreError>().is_some_and(
            |error| matches!(error, StoreError::NotFound { kind, .. } if *kind == "object")
        ),
        "{}",
        missing_target
    );
}

fn sample(id: &str, kind: &str, name: &str) -> Object {
    Object {
        id: id.into(),
        kind: kind.into(),
        name: name.into(),
        properties: [("environment".into(), "lab".into())].into_iter().collect(),
        ..Object::default()
    }
}

fn assert_graph(graph: &dyn CatalogGraph, tenant: Option<&str>) {
    let id = "tenkai:conformance:object";
    let _ = graph.delete(tenant, id);
    assert_eq!(graph.get(tenant, id).unwrap(), None);
    let original = sample(id, "tenkai.conformance", "original");
    assert_eq!(graph.create(tenant, original.clone()).unwrap(), original);
    assert_eq!(graph.get(tenant, id).unwrap(), Some(original.clone()));
    let mut conflicting = original.clone();
    conflicting.name = "must-not-replace".into();
    assert!(
        graph
            .create(tenant, conflicting)
            .unwrap_err()
            .is_already_exists()
    );
    let mut updated = original.clone();
    updated.name = "updated".into();
    updated.properties.insert("status".into(), "ready".into());
    assert_eq!(graph.put(tenant, updated.clone()).unwrap(), updated);
    assert_eq!(
        graph
            .find_by_property(tenant, "tenkai.conformance", "status", "ready")
            .unwrap()
            .iter()
            .map(|object| object.id.as_str())
            .collect::<Vec<_>>(),
        [id]
    );
    let link = Link {
        id: format!("{id}--uses--tenkai:conformance:other"),
        from_id: id.into(),
        to_id: "tenkai:conformance:other".into(),
        relation: "uses".into(),
        created: 1,
    };
    graph.create_link(tenant, link.clone(), true).unwrap();
    assert!(
        graph
            .create_link(tenant, link.clone(), true)
            .unwrap_err()
            .is_already_exists()
    );
    graph.create_link(tenant, link.clone(), false).unwrap();
    assert_eq!(graph.links(tenant, id, "uses", "out").unwrap().len(), 1);
    let lease = graph
        .acquire_lease(tenant, "tenkai/test", "lock", "owner", 60_000)
        .unwrap();
    assert!(
        graph
            .acquire_lease(tenant, "tenkai/test", "lock", "other", 60_000)
            .unwrap_err()
            .downcast_ref::<StoreError>()
            .is_some_and(StoreError::is_already_exists)
    );
    graph
        .refresh_lease(tenant, "tenkai/test", "lock", &lease.fencing_token, 60_000)
        .unwrap();
    graph
        .guarded_put(
            tenant,
            updated.clone(),
            "tenkai/test",
            "lock",
            &lease.fencing_token,
            false,
        )
        .unwrap();
    graph
        .release_lease(tenant, "tenkai/test", "lock", &lease.fencing_token)
        .unwrap();
    graph.delete(tenant, id).unwrap();
    assert_eq!(graph.get(tenant, id).unwrap(), None);
}

fn sample_event(id: &str, environment: &str) -> tenkai::storage::ProviderEventRecord {
    tenkai::storage::ProviderEventRecord {
        id: id.into(),
        provider_kind: "outcome".into(),
        binding_digest: "digest".into(),
        payload_json: format!(
            r#"{{"binding":{{"environment_id":"{environment}"}},"payload_json":"{{}}" }}"#
        ),
        attempts: 0,
        next_attempt_at: 1,
        delivered_at: None,
        last_error: String::new(),
        claim_token: None,
        claim_until: None,
    }
}

/// Live outbox drill. Requires feature `postgres` and `TENKAI_POSTGRES_URL`.
#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
async fn live_postgres_catalog_enqueues_provider_events_atomically_and_exports() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let suffix = format!(
        "{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let tenant_a = format!("oa{suffix}");
    let tenant_b = format!("ob{suffix}");
    let id = format!("tenkai:conformance:outbox:{suffix}");
    let original = sample(&id, "tenkai.conformance", "original");
    store.create(Some(&tenant_a), original.clone()).unwrap();
    let mut updated = original.clone();
    updated.name = "terminal".into();
    let event = sample_event(&format!("event-{suffix}"), "prod");
    store
        .put_with_provider_events(
            Some(&tenant_a),
            updated.clone(),
            std::slice::from_ref(&event),
        )
        .unwrap();
    let partition_a = store.partition_by_id(&tenant_a).unwrap();
    assert_eq!(
        partition_a
            .list_provider_events("outcome", "prod", 8)
            .unwrap()
            .len(),
        1
    );
    let partition_b = store.partition_by_id(&tenant_b).unwrap();
    assert!(
        partition_b
            .list_provider_events("outcome", "prod", 8)
            .unwrap()
            .is_empty()
    );

    let mut conflicting = event.clone();
    conflicting.payload_json =
        r#"{"binding":{"environment_id":"prod"},"payload_json":"{\"different\":true}"}"#.into();
    let mut rolled = updated.clone();
    rolled.name = "must-roll-back".into();
    assert!(
        store
            .put_with_provider_events(Some(&tenant_a), rolled.clone(), &[conflicting])
            .is_err()
    );
    assert_eq!(
        store.get(Some(&tenant_a), &id).unwrap().unwrap().name,
        "terminal"
    );

    let mut invalid = event;
    invalid.id.clear();
    rolled.name = "invalid-must-roll-back".into();
    assert!(
        store
            .put_with_provider_events(Some(&tenant_a), rolled, &[invalid])
            .is_err()
    );
    assert_eq!(
        store.get(Some(&tenant_a), &id).unwrap().unwrap().name,
        "terminal"
    );

    let tenant_export = format!("oe{suffix}");
    let export_id = format!("tenkai:conformance:export:{suffix}");
    let export_object = sample(&export_id, "tenkai.conformance", "export");
    store
        .create(Some(&tenant_export), export_object.clone())
        .unwrap();
    let provider_event = tenkai::providers::terminal_outcome_event(
        &format!("tenkai:deployment:{suffix}"),
        &format!("tenkai:plan:{suffix}"),
        "sha256:plan",
        "tenkai:release:api@2.0.0",
        "sha256:release",
        "api",
        "prod",
        "tenkai:environment:prod",
        "sha256:config",
        tenkai::providers::TerminalOutcomeState::DeploymentSucceeded,
        100,
    )
    .unwrap();
    let export_event =
        tenkai::providers::provider_event_record("outcome", &provider_event, 100).unwrap();
    store
        .put_with_provider_events(
            Some(&tenant_export),
            export_object,
            std::slice::from_ref(&export_event),
        )
        .unwrap();
    let partition_export = store.partition_by_id(&tenant_export).unwrap();
    let stored_export = partition_export
        .list_provider_events("outcome", "prod", 8)
        .unwrap();
    assert_eq!(stored_export.len(), 1);
    assert_ne!(stored_export[0].id, export_event.id);
    let sink = tenkai::providers::LocalEventSink::default();
    assert_eq!(
        tenkai::providers::deliver_outcome_batch(
            &partition_export,
            &sink,
            std::time::Duration::from_secs(1),
            100,
            10,
        )
        .await
        .unwrap(),
        (1, 0)
    );
    let tenant_export_b = format!("of{suffix}");
    let export_b_id = format!("tenkai:conformance:export-b:{suffix}");
    let export_b_object = sample(&export_b_id, "tenkai.conformance", "export-b");
    store
        .create(Some(&tenant_export_b), export_b_object.clone())
        .unwrap();
    let provider_event_b = tenkai::providers::terminal_outcome_event(
        &format!("tenkai:deployment:{suffix}-b"),
        &format!("tenkai:plan:{suffix}-b"),
        "sha256:plan",
        "tenkai:release:api@2.0.0",
        "sha256:release",
        "api",
        "prod",
        "tenkai:environment:prod",
        "sha256:config",
        tenkai::providers::TerminalOutcomeState::DeploymentSucceeded,
        100,
    )
    .unwrap();
    let export_event_b =
        tenkai::providers::provider_event_record("outcome", &provider_event_b, 100).unwrap();
    store
        .put_with_provider_events(
            Some(&tenant_export_b),
            export_b_object,
            std::slice::from_ref(&export_event_b),
        )
        .unwrap();
    let partition_export_b = store.partition_by_id(&tenant_export_b).unwrap();
    assert_eq!(
        tenkai::providers::deliver_outcome_batch(
            &partition_export_b,
            &sink,
            std::time::Duration::from_secs(1),
            100,
            10,
        )
        .await
        .unwrap(),
        (1, 0)
    );
    let sequences = sink
        .received()
        .into_iter()
        .filter_map(|event| event.source_sequence)
        .collect::<Vec<_>>();
    assert_eq!(sequences.len(), 2);
    assert!(
        sequences[0] > 0 && sequences[1] > sequences[0],
        "{sequences:?}"
    );
    assert_eq!(
        tenkai::providers::deliver_outcome_batch(
            &partition_export,
            &sink,
            std::time::Duration::from_secs(1),
            100,
            10,
        )
        .await
        .unwrap(),
        (0, 0)
    );
}
