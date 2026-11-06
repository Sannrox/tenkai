use super::super::*;
use std::time::Duration;
use tenkai::storage::CatalogGraph;

/// #870: a current tenant stamp must not run `CREATE INDEX` (SHARE) on the
/// request path. A held insert on `catalog_objects` would block that DDL.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_tenant_schema_ensure_skips_ddl_once_current() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let tenant = format!(
        "ens{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let schema = tenant_schema_name(&tenant).unwrap();
    assert_eq!(store.get(Some(&tenant), "tenkai:none").unwrap(), None);

    let mut raw = postgres::Client::connect(&config.url, postgres::NoTls).expect("raw connect");
    let stored: i32 = raw
        .query_one(
            "SELECT version FROM public.tenkai_tenant_schema_versions WHERE schema_name = $1",
            &[&schema],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        stored,
        i32::try_from(crate::tenant_schema::TENANT_SCHEMA_VERSION).unwrap()
    );
    // Drop the process memo so this call takes the stamp SELECT, not the
    // in-memory hit. A current stamp must still skip CREATE INDEX.
    store.inner.forget_ensured_schema(&schema);

    raw.batch_execute("BEGIN").unwrap();
    raw.execute(
        &format!("INSERT INTO {schema}.catalog_objects(id, kind, payload) VALUES ($1, $2, $3)"),
        &[&"hold", &"tenkai.conformance", &vec![0_u8]],
    )
    .unwrap();

    let (done_sender, done_receiver) = std::sync::mpsc::channel();
    let lookup = store.clone();
    let tenant_for_lookup = tenant.clone();
    std::thread::spawn(move || {
        let result = lookup.get(Some(&tenant_for_lookup), "tenkai:none");
        let _ = done_sender.send(result);
    });
    match done_receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => {
            result.unwrap();
        }
        Err(_) => {
            let _ = raw.batch_execute("ROLLBACK");
            panic!("ensure blocked on CREATE INDEX SHARE lock while the stamp is current");
        }
    }
    raw.batch_execute("ROLLBACK").unwrap();
    raw.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .unwrap();
    raw.execute(
        "DELETE FROM public.tenkai_tenant_schema_versions WHERE schema_name = $1",
        &[&schema],
    )
    .unwrap();
}
