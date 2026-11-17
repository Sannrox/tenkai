use super::super::*;
use super::live_property_lookup::{plan_object, plan_with_steps};
use std::collections::HashMap;
use tenkai::ontology::{KIND_CHANNEL, KIND_ENVIRONMENT, KIND_PLAN, KIND_RELEASE};
use tenkai::pb::sekai::Object;
use tenkai::storage::CatalogGraph;

/// #869 drill: set-based kind listings return exactly what a per-id `get`
/// returns, for typed rows with and without a sidecar payload and for
/// catalog-only channels; id listings match them; and a plan property lookup
/// returns each plan of the environment once. Requires feature `postgres` and
/// `TENKAI_POSTGRES_URL`.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_kind_listing_matches_per_id_reads() {
    use tenkai::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };
    use tenkai::development_fixtures::{
        DevelopmentFixture, FixtureChannel, FixtureEnvironment, FixtureRelease,
    };

    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let tenant = format!(
        "list{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let authority = TenantDerivationAuthority::new("test");
    let ctx = AuthenticatedRequestContextBuilder::new(
        "listing-request",
        PrincipalIdentity {
            id: "seed-service".into(),
            kind: PrincipalKind::Service,
        },
        "test",
    )
    .with_tenant(&tenant, &authority)
    .unwrap()
    .build()
    .unwrap();
    let release = |name: &str, version: &str, digest: u32| FixtureRelease {
        name: name.into(),
        product: "api".into(),
        version: version.into(),
        content_digest: format!("{digest:0>64}"),
    };
    let channel = |name: &str, release: &str| FixtureChannel {
        name: name.into(),
        product: "api".into(),
        release: release.into(),
    };
    let fixture = DevelopmentFixture {
        contract_version: 1,
        fixture_id: format!("listing-{tenant}"),
        releases: vec![release("one", "1.0.0", 1), release("two", "2.0.0", 2)],
        channels: vec![channel("stable", "one"), channel("edge", "two")],
        environments: vec![FixtureEnvironment {
            name: "prod".into(),
            posture: "awaiting_approval".into(),
            description: String::new(),
        }],
        plans: Vec::new(),
    }
    .prepare()
    .unwrap();
    let map = store
        .import_development_fixture_for(&ctx, &fixture)
        .unwrap();
    let schema = tenant_schema_name(&tenant).unwrap();
    let tenant = Some(tenant.as_str());

    // Plans a and b target prod, c targets staging; both environments come
    // from the plan puts (fixture names are namespaced). c keeps only its
    // typed row. One channel gets a sidecar payload, and one channel exists
    // only as a catalog object.
    let plans = [("a", "prod"), ("b", "prod"), ("c", "staging")]
        .map(|(name, environment)| plan_with_steps(&format!("tenkai:plan:{name}"), environment, 2));
    for plan in &plans {
        store.put(tenant, plan_object(plan)).unwrap();
    }
    let mut raw = postgres::Client::connect(&config.url, postgres::NoTls).expect("raw connect");
    raw.execute(
        &format!("DELETE FROM {schema}.catalog_objects WHERE id=$1"),
        &[&plans[2].id],
    )
    .unwrap();
    let mut sidecar = store.get(tenant, &map.channels[0]).unwrap().unwrap();
    sidecar.name = "sidecar channel".into();
    store.put(tenant, sidecar).unwrap();
    store
        .put(
            tenant,
            Object {
                id: "tenkai:channel:catalog-only".into(),
                kind: KIND_CHANNEL.into(),
                name: "catalog only".into(),
                properties: HashMap::from([("product".into(), "api".into())]),
                ..Object::default()
            },
        )
        .unwrap();

    for (kind, count) in [
        (KIND_PLAN, 3),
        (KIND_RELEASE, 2),
        (KIND_ENVIRONMENT, 3),
        (KIND_CHANNEL, 3),
    ] {
        let listed = store.list_kind(tenant, kind).unwrap();
        assert_eq!(listed.len(), count, "{kind}: {listed:?}");
        let ids: Vec<String> = listed.iter().map(|object| object.id.clone()).collect();
        assert_eq!(store.list_kind_ids(tenant, kind).unwrap(), ids, "{kind}");
        // A typed-only plan stamps `updated` from the clock on every read.
        let settled = |object: Object| Object {
            updated: 0,
            ..object
        };
        for object in listed {
            let read = store.get(tenant, &object.id).unwrap().map(settled);
            assert_eq!(read, Some(settled(object)), "{kind}");
        }
    }

    for (environment, expected) in [("prod", &plans[..2]), ("staging", &plans[2..])] {
        let found: Vec<String> = store
            .find_by_property(tenant, KIND_PLAN, "environment", environment)
            .unwrap()
            .into_iter()
            .map(|object| object.id)
            .collect();
        let expected: Vec<String> = expected.iter().map(|plan| plan.id.clone()).collect();
        assert_eq!(found, expected, "{environment}");
    }
}
