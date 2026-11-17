use super::super::*;
use tenkai::storage::CatalogGraph;

/// Two tenant ids that name one schema never share it: the first to open it
/// owns it, on every replica, and a schema without an owner row (created
/// before owners were recorded) is claimed by its first opener.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_colliding_tenant_ids_never_share_a_schema() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let suffix = format!(
        "{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let owner = format!("own-{suffix}");
    let rival = format!("OWN_{suffix}");
    let schema = tenant_schema_name(&owner).unwrap();
    assert_eq!(tenant_schema_name(&rival).unwrap(), schema);

    let store = config.open().expect("connect");
    assert_eq!(store.get(Some(&owner), "tenkai:none").unwrap(), None);
    let refused = store.get(Some(&rival), "tenkai:none").unwrap_err();
    assert!(
        refused.to_string().contains("another tenant id owns"),
        "{refused:#}"
    );
    assert!(!refused.to_string().contains(&owner), "{refused:#}");

    // Another replica, with no process memo, reads the same owner.
    let replica = config.open().expect("connect");
    assert!(replica.get(Some(&rival), "tenkai:none").is_err());
    assert_eq!(replica.get(Some(&owner), "tenkai:none").unwrap(), None);

    // An existing schema without an owner row is claimed once.
    let mut raw = postgres::Client::connect(&config.url, postgres::NoTls).expect("raw connect");
    raw.execute(
        "DELETE FROM public.tenkai_tenant_schema_owners WHERE schema_name = $1",
        &[&schema],
    )
    .unwrap();
    let upgraded = config.open().expect("connect");
    assert_eq!(upgraded.get(Some(&owner), "tenkai:none").unwrap(), None);
    assert!(upgraded.get(Some(&rival), "tenkai:none").is_err());

    raw.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .unwrap();
    for table in [
        "tenkai_tenant_schema_owners",
        "tenkai_tenant_schema_versions",
    ] {
        raw.execute(
            &format!("DELETE FROM public.{table} WHERE schema_name = $1"),
            &[&schema],
        )
        .unwrap();
    }
}
