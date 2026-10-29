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
