use super::super::*;

/// Live isolation drill. Requires feature `postgres` and `TENKAI_POSTGRES_URL`.
#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_tenant_isolation() {
    use crate::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };
    use crate::storage::{OperationalStore as _, ReleaseRecord};

    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let authority = TenantDerivationAuthority::new("test");
    let ctx_a = AuthenticatedRequestContextBuilder::new(
        "r-a",
        PrincipalIdentity {
            id: "user-a".into(),
            kind: PrincipalKind::Human,
        },
        "test",
    )
    .with_tenant("tenant-a", &authority)
    .unwrap()
    .build()
    .unwrap();
    let ctx_b = AuthenticatedRequestContextBuilder::new(
        "r-b",
        PrincipalIdentity {
            id: "user-b".into(),
            kind: PrincipalKind::Human,
        },
        "test",
    )
    .with_tenant("tenant-b", &authority)
    .unwrap()
    .build()
    .unwrap();
    store
        .run_partition_isolation_check(&ctx_a, &ctx_b, "env-a", "env-b")
        .unwrap();
    let part = store.partition_for(&ctx_a).unwrap();
    part.check_health().unwrap();
    part.publish_release(&ReleaseRecord {
        id: "rel-1".into(),
        product: "api".into(),
        version: "1.0.0".into(),
        content_digest: "sha256:a".into(),
        descriptor_json: "{}".into(),
    })
    .unwrap();
    assert!(part.get_release("rel-1").unwrap().is_some());
}
