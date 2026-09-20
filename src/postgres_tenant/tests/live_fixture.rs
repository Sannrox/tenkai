use super::super::*;

/// Live atomic fixture drill. Requires feature `postgres` and `TENKAI_POSTGRES_URL`.
#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_development_fixture_is_atomic_and_tenant_scoped() {
    use crate::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };
    use crate::development_fixtures::{DevelopmentFixture, FixtureEnvironment, FixturePlan};

    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let authority = TenantDerivationAuthority::new("test");
    let context = |tenant: &str, request: &str| {
        AuthenticatedRequestContextBuilder::new(
            request,
            PrincipalIdentity {
                id: "seed-service".into(),
                kind: PrincipalKind::Service,
            },
            "test",
        )
        .with_tenant(tenant, &authority)
        .unwrap()
        .build()
        .unwrap()
    };
    let ctx_a = context(&format!("fixture-a-{suffix}"), "fixture-request-a");
    let ctx_b = context(&format!("fixture-b-{suffix}"), "fixture-request-b");
    let fixture = DevelopmentFixture {
        contract_version: 1,
        fixture_id: format!("demo-{suffix}"),
        releases: Vec::new(),
        channels: Vec::new(),
        environments: vec![FixtureEnvironment {
            name: "prod".into(),
            posture: "awaiting_approval".into(),
            description: "sanitized".into(),
        }],
        plans: vec![FixturePlan {
            name: "approval".into(),
            environment: "prod".into(),
            blocked_reason: "awaiting approval".into(),
        }],
    }
    .prepare()
    .unwrap();
    let first = store
        .import_development_fixture_for(&ctx_a, &fixture)
        .unwrap();
    assert_eq!(
        store
            .import_development_fixture_for(&ctx_a, &fixture)
            .unwrap(),
        first
    );
    assert!(
        !store
            .list_environment_ids_for(&ctx_b)
            .unwrap()
            .contains(&first.environments[0])
    );
    let reset = store
        .reset_development_fixture_for(&ctx_a, &fixture.map.fixture_id)
        .unwrap();
    assert_eq!(reset.removed, 2);
}
