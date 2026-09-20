use super::*;

#[test]
fn schema_names_are_safe() {
    assert_eq!(tenant_schema_name("tenant-a").unwrap(), "tenkai_t_tenant_a");
    assert!(tenant_schema_name("").is_err());
    assert!(tenant_schema_name("evil;drop").is_err());
    assert!(tenant_schema_name(&"x".repeat(65)).is_err());
}

#[test]
fn config_rejects_non_postgres_urls() {
    assert!(PostgresTenantConfig::new("postgres://localhost/tenkai").is_ok());
    assert!(PostgresTenantConfig::new("postgresql://localhost/tenkai").is_ok());
    assert!(PostgresTenantConfig::new("mysql://localhost/tenkai").is_err());
    assert!(PostgresTenantConfig::new("").is_err());
}

#[test]
fn open_without_feature_fails_closed() {
    if postgres_feature_enabled() {
        return;
    }
    let config = PostgresTenantConfig::new("postgres://localhost/tenkai").unwrap();
    let err = match config.open() {
        Ok(_) => panic!("open should fail without postgres feature"),
        Err(error) => error.to_string(),
    };
    assert!(err.contains("features postgres") || err.contains("postgres"));
}

#[test]
fn capabilities_advertise_tenant_and_shared_replica_not_ha() {
    let caps = tenant_postgres_store_capabilities();
    let names = caps.names().join(",");
    assert!(names.contains("tenant_isolation"));
    assert!(names.contains("operational_store_migration"));
    assert!(names.contains("shared_replica_state"));
    assert!(!names.contains("high_availability"));
    assert_eq!(
        POSTGRES_SHARED_REPLICA_WRITER_MODEL,
        SharedReplicaWriterModel::SingleActiveWriter
    );
}

#[test]
fn multi_replica_requirement_accepts_postgres_hub_profile() {
    use crate::runtime_capabilities::{
        RuntimeRequirements, community_auth_capabilities, community_sqlite_profile,
        validate_runtime_capabilities,
    };

    // SQLite still fails closed for replica_count > 1.
    let sqlite = community_sqlite_profile(community_auth_capabilities());
    assert!(
        validate_runtime_capabilities(
            &sqlite,
            &RuntimeRequirements {
                replica_count: 2,
                ..RuntimeRequirements::community()
            },
        )
        .is_err()
    );

    // Postgres hub profile satisfies shared_replica_state (single-active-writer).
    let postgres = enterprise_postgres_hub_profile(community_auth_capabilities());
    validate_runtime_capabilities(
        &postgres,
        &RuntimeRequirements {
            replica_count: 2,
            tenant_mode: true,
            ..RuntimeRequirements::community()
        },
    )
    .expect("postgres hub must allow multi-replica capability gate");
    // HA product flag still requires separate high_availability capability.
    assert!(
        validate_runtime_capabilities(
            &postgres,
            &RuntimeRequirements {
                replica_count: 2,
                tenant_mode: true,
                require_high_availability: true,
                ..RuntimeRequirements::community()
            },
        )
        .is_err()
    );
}

#[test]
fn resolve_server_tenant_store_community_is_none() {
    let resolved = resolve_server_tenant_store(false).unwrap();
    assert!(resolved.is_none());
}

#[test]
fn resolve_server_tenant_store_fails_closed_without_feature_or_url() {
    let err = match resolve_server_tenant_store(true) {
        Ok(_) => panic!("tenant mode without config must fail closed"),
        Err(error) => error.to_string(),
    };
    assert!(
        err.contains("features postgres")
            || err.contains("TENKAI_POSTGRES_URL")
            || err.contains("postgres"),
        "{err}"
    );
}

#[test]
fn open_postgres_reconcile_fence_fails_closed_without_feature_or_url() {
    let err = match open_postgres_reconcile_fence() {
        Ok(_) => {
            // Live URL may be set in developer env; only assert when feature off
            // or when open failed path was expected.
            if !postgres_feature_enabled() {
                panic!("open should fail without postgres feature");
            }
            return;
        }
        Err(error) => error.to_string(),
    };
    assert!(
        err.contains("features postgres")
            || err.contains("TENKAI_POSTGRES_URL")
            || err.contains("postgres"),
        "{err}"
    );
}

#[test]
fn resolve_reconcile_fence_none_for_single_replica() {
    assert!(resolve_reconcile_fence_for_replicas(1).unwrap().is_none());
}

#[test]
fn resolve_reconcile_fence_some_for_multi_replica() {
    // Always returns a fence (durable or process-shared fallback).
    assert!(resolve_reconcile_fence_for_replicas(2).unwrap().is_some());
}

#[cfg(feature = "postgres")]
mod live_delivery;
#[cfg(feature = "postgres")]
mod live_fence;
#[cfg(feature = "postgres")]
mod live_fixture;
#[cfg(feature = "postgres")]
mod live_isolation;
