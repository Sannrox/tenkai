use super::super::*;
use super::live_property_lookup::{plan_object, plan_with_steps};
use tenkai::ontology::KIND_PLAN;
use tenkai::storage::CatalogGraph;

/// #873 drill: a catalog put rewrites only what changed. A plan status
/// change leaves the plan body's property row and typed body untouched
/// (same `xmin`), a removed property is deleted, an added one is inserted,
/// and lookups still see the result. Requires feature `postgres` and
/// `TENKAI_POSTGRES_URL`.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_catalog_put_rewrites_only_changed_rows() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let tenant = format!(
        "put{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let schema = tenant_schema_name(&tenant).unwrap();
    let tenant = Some(tenant.as_str());
    let mut raw = postgres::Client::connect(&config.url, postgres::NoTls).expect("raw connect");
    let mut xmin = |sql: &str, id: &str| -> String {
        raw.query_one(&format!("SELECT xmin::text FROM {schema}.{sql}"), &[&id])
            .unwrap()
            .get(0)
    };

    let plan = plan_with_steps("tenkai:plan:put", "lab", 8);
    let mut object = plan_object(&plan);
    object
        .properties
        .insert("retired_note".into(), "drop me".into());
    store.put(tenant, object.clone()).unwrap();
    let property = "catalog_object_properties WHERE object_id=$1 AND key=";
    let body_row = xmin(&format!("{property}'plan'"), &plan.id);
    let status_row = xmin(&format!("{property}'status'"), &plan.id);
    let typed_row = xmin("plans WHERE id=$1", &plan.id);

    // An identical put writes nothing.
    store.put(tenant, object.clone()).unwrap();
    assert_eq!(xmin(&format!("{property}'status'"), &plan.id), status_row);
    assert_eq!(xmin("plans WHERE id=$1", &plan.id), typed_row);

    // A status change rewrites the status row and the typed row only; one
    // key goes and one arrives.
    object.properties.insert("status".into(), "blocked".into());
    object.properties.remove("retired_note");
    object.properties.insert("note".into(), "added".into());
    store.put(tenant, object.clone()).unwrap();
    assert_eq!(xmin(&format!("{property}'plan'"), &plan.id), body_row);
    assert_ne!(xmin(&format!("{property}'status'"), &plan.id), status_row);
    assert_ne!(xmin("plans WHERE id=$1", &plan.id), typed_row);

    let keys: Vec<String> = raw
        .query(
            &format!(
                "SELECT key FROM {schema}.catalog_object_properties WHERE object_id=$1 ORDER BY key"
            ),
            &[&plan.id],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    let mut expected: Vec<String> = object.properties.keys().cloned().collect();
    expected.sort();
    assert_eq!(keys, expected);
    let stored = store.get(tenant, &plan.id).unwrap().unwrap();
    assert_eq!(stored.properties["status"], "blocked");
    let found: Vec<String> = store
        .find_by_property(tenant, KIND_PLAN, "status", "blocked")
        .unwrap()
        .into_iter()
        .map(|object| object.id)
        .collect();
    assert_eq!(found, std::slice::from_ref(&plan.id));
}
