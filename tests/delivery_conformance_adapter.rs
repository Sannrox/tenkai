use tenkai::delivery_conformance::{
    MAX_CHECKS, Report, SCHEMA_JSON, VERSION, require_version, run_from_env,
};

#[test]
fn contract_fixture_is_versioned_and_bounded() {
    let fixture: serde_json::Value = serde_json::from_str(SCHEMA_JSON).unwrap();
    assert_eq!(fixture["version"], VERSION);
    assert_eq!(fixture["max_checks"], MAX_CHECKS as u64);
    assert!(require_version(VERSION).is_ok());
    assert!(require_version("unknown/v2").is_err());
}

#[test]
fn disabled_or_unconfigured_adapter_fails_closed_without_details() {
    if std::env::var_os("TENKAI_CONFORMANCE_POSTGRES_URL").is_some() {
        return;
    }
    let report = run_from_env();
    let encoded = serde_json::to_string(&report).unwrap();
    let round_trip: Report = serde_json::from_str(&encoded).unwrap();
    assert_eq!(round_trip, report);
    assert!(!report.passed);
    assert!(encoded.len() < 4_096);
    assert!(!encoded.contains("postgres://"));
    assert!(!encoded.contains("credential"));
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires TENKAI_CONFORMANCE_POSTGRES_URL for an isolated local *_test database"]
fn live_postgres_adapter_exercises_real_delivery_authority() {
    let report = run_from_env();
    assert!(report.passed, "{report:?}");
    assert_eq!(report.runtime_instances, 2);
    assert!(report.capabilities.shared_replica_state);
    assert!(!report.capabilities.high_availability);
    assert_eq!(report.checks.len(), MAX_CHECKS);
    let encoded = serde_json::to_string(&report).unwrap();
    assert!(encoded.len() < 8_192);
    assert!(!encoded.contains("postgres://"));
    assert!(!encoded.contains("postgresql://"));
    assert!(!encoded.contains("payload_json"));
    assert!(!encoded.contains("tenant_id"));
}
