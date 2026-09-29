use super::super::*;

/// Live schema-12 backfill drill (#457). Requires feature `postgres` and a
/// loopback `TENKAI_POSTGRES_URL` (the drill degrades the schema over plaintext).
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_retirement_column_backfills_and_filters() {
    use crate::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };

    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let tenant = format!("retire-{}", crate::now_millis());
    let schema = tenant_schema_name(&tenant).unwrap();
    let ctx = AuthenticatedRequestContextBuilder::new(
        "r-retire",
        PrincipalIdentity {
            id: "user-retire".into(),
            kind: PrincipalKind::Human,
        },
        "test",
    )
    .with_tenant(&tenant, &TenantDerivationAuthority::new("test"))
    .unwrap()
    .build()
    .unwrap();
    assert!(
        store
            .list_active_environment_ids_for(&ctx)
            .unwrap()
            .is_empty()
    );

    let mut raw = postgres::Client::connect(&config.url, postgres::NoTls).expect("raw connect");
    raw.batch_execute(&format!(
        r#"SET search_path TO {schema};
           DROP INDEX environments_active;
           ALTER TABLE environments DROP COLUMN retired_at;
           INSERT INTO environments(id,revision,configuration_json) VALUES
             ('active',1,'{{}}'),
             ('by-properties',1,'{{"properties":{{"tenkai.retirement.reason":"r","tenkai.retirement.actor":"a","tenkai.retirement.at":"7"}}}}'),
             ('by-tenant-key',1,'{{"_tenkai_retirement":{{"reason":"r","actor":"a","retired_at":9}}}}');"#
    ))
    .unwrap();

    assert_eq!(
        store.list_active_environment_ids_for(&ctx).unwrap(),
        vec!["active"]
    );
    assert_eq!(store.list_environment_ids_for(&ctx).unwrap().len(), 3);
    let backfilled: Vec<(String, Option<i64>)> = raw
        .query(
            &format!("SELECT id, retired_at FROM {schema}.environments ORDER BY id"),
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        backfilled,
        vec![
            ("active".into(), None),
            ("by-properties".into(), Some(7)),
            ("by-tenant-key".into(), Some(9)),
        ]
    );
    raw.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .unwrap();
}
