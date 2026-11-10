use super::super::*;
use std::collections::HashMap;
use tenkai::ontology::KIND_PLAN;
use tenkai::pb::sekai::Object;
use tenkai::plan::{Action, PLAN_FORMAT_VERSION, Plan, PlanState, Step};
use tenkai::storage::CatalogGraph;

/// A plan whose JSON is far over the btree row limit (about 2.7 KB).
fn plan_with_steps(id: &str, environment: &str, steps: u32) -> Plan {
    let digest = |n: u32| format!("sha256:{:0>64}", format!("{n:x}"));
    Plan {
        format_version: PLAN_FORMAT_VERSION,
        id: id.into(),
        content_id: uuid::Uuid::new_v4().to_string(),
        environment: environment.into(),
        created_at: 1,
        inputs: Vec::new(),
        steps: (0..steps)
            .map(|order| Step {
                id: uuid::Uuid::new_v4().to_string(),
                order,
                product: format!("product-{order}"),
                instance: String::new(),
                action: Action::Install,
                from: None,
                to: "1.0.0".into(),
                release_id: digest(order),
                release_digest: digest(order + 1000),
                artifact_digest: digest(order + 2000),
                workdir: format!("/srv/product-{order}"),
                host: None,
                sealed: Vec::new(),
                restore: None,
                rewrap: None,
                issuer: None,
            })
            .collect(),
        state: PlanState::Computed,
        gates_skipped: None,
        status_detail: String::new(),
        maintenance_blocked: false,
        prior_warnings: Vec::new(),
        recalled_recovery_reason: None,
        credential_runway: None,
    }
}

fn plan_object(plan: &Plan) -> Object {
    Object {
        id: plan.id.clone(),
        kind: KIND_PLAN.into(),
        name: format!("{} plan", plan.environment),
        properties: HashMap::from([
            ("environment".into(), plan.environment.clone()),
            ("content_digest".into(), plan.executable_digest().unwrap()),
            ("plan".into(), serde_json::to_string(plan).unwrap()),
            ("status".into(), plan.state.to_string()),
        ]),
        ..Object::default()
    }
}

fn ids(objects: Vec<Object>) -> Vec<String> {
    objects.into_iter().map(|object| object.id).collect()
}

/// #879 drill: a tenant schema with the pre-#879 full-value lookup index is
/// migrated on first use, then stores and finds a 64-step plan and long
/// values that share an indexed prefix. An older binary's DDL and lookup stay
/// valid against the migrated schema. Requires feature `postgres` and a
/// loopback `TENKAI_POSTGRES_URL`.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_property_lookup_stores_large_values_after_migration() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let tenant = format!(
        "prop{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let schema = tenant_schema_name(&tenant).unwrap();
    let tenant = Some(tenant.as_str());
    assert_eq!(store.get(tenant, "tenkai:plan:none").unwrap(), None);

    // Put the schema back to the pre-#879 index shape.
    let mut raw = postgres::Client::connect(&config.url, postgres::NoTls).expect("raw connect");
    let old_index = "CREATE INDEX IF NOT EXISTS catalog_object_properties_lookup
         ON catalog_object_properties(kind, key, value, object_id)";
    raw.batch_execute(&format!(
        "SET search_path TO {schema};
         DROP INDEX catalog_object_properties_lookup;
         {old_index};"
    ))
    .unwrap();
    super::invalidate_tenant_schema_stamp(&store, &mut raw, &schema);

    let plan = plan_with_steps("tenkai:plan:large", "lab", 64);
    let object = plan_object(&plan);
    let plan_json = object.properties["plan"].clone();
    assert!(plan_json.len() > 3 * 2704, "{}", plan_json.len());
    store.put(tenant, object.clone()).unwrap();
    assert_eq!(
        store.get(tenant, &plan.id).unwrap().unwrap().properties["plan"],
        plan_json
    );
    let index_has_prefix: bool = raw
        .query_one(
            r#"SELECT pg_get_indexdef(c.oid) LIKE '%"left"(value, 256)%'
               FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = $1 AND c.relname = 'catalog_object_properties_lookup'"#,
            &[&schema],
        )
        .unwrap()
        .get(0);
    assert!(index_has_prefix);
    for (key, value) in [("environment", "lab"), ("plan", plan_json.as_str())] {
        assert_eq!(
            ids(store
                .find_by_property(tenant, KIND_PLAN, key, value)
                .unwrap()),
            [plan.id.as_str()],
            "{key}"
        );
    }

    // Long values sharing the indexed prefix match only on the full value.
    let shared = "x".repeat(4096);
    for (id, tail) in [("tenkai:large:a", "a"), ("tenkai:large:b", "b")] {
        store
            .put(
                tenant,
                Object {
                    id: id.into(),
                    kind: "tenkai.conformance".into(),
                    properties: HashMap::from([("detail".into(), format!("{shared}{tail}"))]),
                    ..Object::default()
                },
            )
            .unwrap();
    }
    assert_eq!(
        ids(store
            .find_by_property(
                tenant,
                "tenkai.conformance",
                "detail",
                &format!("{shared}b")
            )
            .unwrap()),
        ["tenkai:large:b"]
    );
    assert!(
        store
            .find_by_property(tenant, "tenkai.conformance", "detail", &shared)
            .unwrap()
            .is_empty()
    );

    // An older binary's DDL is a no-op and its full-value lookup still works.
    raw.batch_execute(&format!("SET search_path TO {schema}; {old_index};"))
        .unwrap();
    let old_lookup = raw
        .query(
            "SELECT object_id FROM catalog_object_properties
             WHERE kind = $1 AND key = 'plan' AND value = $2",
            &[&KIND_PLAN, &plan_json],
        )
        .unwrap();
    assert_eq!(old_lookup.len(), 1);
    // The migration is idempotent on the next use.
    assert!(store.get(tenant, &plan.id).unwrap().is_some());
    raw.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .unwrap();
    raw.execute(
        "DELETE FROM public.tenkai_tenant_schema_versions WHERE schema_name = $1",
        &[&schema],
    )
    .unwrap();
}
