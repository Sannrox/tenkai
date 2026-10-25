use super::super::*;
use tenkai::storage::{AuditRecord, OperationalStore as _, SCHEMA_VERSION};

/// PostgreSQL-only recovery rehearsal. Requires feature `postgres` and
/// `TENKAI_POSTGRES_URL`. SQLite is not opened.
#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_sole_store_survives_reconnect() {
    use tenkai::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };
    use tenkai::runtime_capabilities::{
        RuntimeRequirements, enterprise_auth_capabilities, validate_runtime_capabilities,
    };
    use tenkai::storage::EnvironmentRecord;

    let provided = enterprise_postgres_hub_profile(enterprise_auth_capabilities());
    validate_runtime_capabilities(
        &provided,
        &RuntimeRequirements {
            tenant_mode: true,
            replica_count: 2,
            require_enterprise_authentication: true,
            min_migration_level: SCHEMA_VERSION,
            ..RuntimeRequirements::community()
        },
    )
    .expect("ADR 0010 enterprise capability check passes with PostgreSQL only");

    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let hub = store.hub_partition().expect("hub schema");
    let audit_id = format!("audit-{}", uuid::Uuid::new_v4());
    hub.append_audit(&AuditRecord {
        id: audit_id.clone(),
        occurred_at: 1,
        principal: "operator".into(),
        operation: "recovery.rehearse".into(),
        resource: "*".into(),
        outcome: "ok".into(),
    })
    .unwrap();

    let authority = TenantDerivationAuthority::new("test");
    let ctx = AuthenticatedRequestContextBuilder::new(
        "r-recover",
        PrincipalIdentity {
            id: "user-a".into(),
            kind: PrincipalKind::Human,
        },
        "test",
    )
    .with_tenant("sole-store", &authority)
    .unwrap()
    .build()
    .unwrap();
    let environment_id = format!("env-{}", uuid::Uuid::new_v4());
    store
        .put_environment_for(
            &ctx,
            &EnvironmentRecord {
                id: environment_id.clone(),
                revision: 0,
                configuration_json: r#"{"rehearsal":true}"#.into(),
            },
        )
        .unwrap();

    drop(hub);
    drop(store);

    let restored = config.open().expect("reconnect");
    let hub = restored.hub_partition().expect("restored hub schema");
    let events = hub.audit_events().unwrap();
    assert!(
        events.iter().any(|event| event.id == audit_id),
        "hub audit must survive reconnect"
    );
    let environment = restored
        .get_environment_for(&ctx, &environment_id)
        .expect("tenant environment must survive reconnect");
    assert_eq!(environment.id, environment_id);
}
