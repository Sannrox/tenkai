//! The tenkai ontology: schema kinds and deterministic ids.
//!
//! Live plan, environment, release, channel, and lease identities live in
//! typed SQLite or Postgres rows. This module names those kinds and ids; it
//! is not the operational store.

use anyhow::{Result, bail};

pub const NS: &str = "tenkai";

pub const KIND_PRODUCT: &str = "tenkai.product";
pub const KIND_RELEASE: &str = "tenkai.release";
pub const KIND_RELEASE_VERIFICATION: &str = "tenkai.release_verification";
pub const KIND_RELEASE_RECALL: &str = "tenkai.release_recall";
pub const KIND_CHANNEL: &str = "tenkai.channel";
pub const KIND_ENVIRONMENT: &str = "tenkai.environment";
pub const KIND_MAINTENANCE_CONFIG: &str = "tenkai.maintenance_config";
pub const KIND_PRODUCT_MAINTENANCE_CONFIG: &str = "tenkai.product_maintenance_config";
pub const KIND_PLAN: &str = "tenkai.plan";
pub const KIND_PLAN_APPROVAL_VERIFICATION: &str = "tenkai.plan_approval_verification";
pub const KIND_ENVIRONMENT_EXECUTION: &str = "tenkai.environment_execution";
pub const KIND_DEPLOYMENT: &str = "tenkai.deployment";
pub const KIND_CANARY_DESIGNATION: &str = "tenkai.canary_designation";
pub const KIND_CANARY_POLICY: &str = "tenkai.canary_policy";
pub const KIND_CANARY_POLICY_POINTER: &str = "tenkai.canary_policy_pointer";
pub const KIND_CANARY_ATTEMPT: &str = "tenkai.canary_attempt";
pub const KIND_CANARY_OUTCOME: &str = "tenkai.canary_outcome";
pub const KIND_PROMOTION_AUDIT: &str = "tenkai.promotion_audit";
pub const KIND_PROMOTION_LOCK: &str = "tenkai.promotion_lock";
pub const KIND_WAVE: &str = "tenkai.wave";
pub const KIND_CONNECTIVITY_UPGRADE: &str = "tenkai.connectivity_upgrade";
pub const KIND_PACKAGE_MIGRATION: &str = "tenkai.package_migration";
pub const KIND_PACKAGE_MIGRATION_LOCK: &str = "tenkai.package_migration_lock";

pub const REL_RELEASE_OF: &str = "release_of";
pub const REL_HAS_RELEASE_VERIFICATION: &str = "has_release_verification";
pub const REL_PROMOTES: &str = "promotes";
pub const REL_SUBSCRIBES: &str = "subscribes";
pub const REL_DEPLOYED_RELEASE: &str = "deployed_release";
pub const REL_IN_ENVIRONMENT: &str = "in_environment";
pub const REL_PART_OF_PLAN: &str = "part_of_plan";
pub const REL_GOVERNS_RELEASE: &str = "governs_release";
pub const REL_EVIDENCE_FOR_POLICY: &str = "evidence_for_policy";
pub const REL_ATTEMPT_FOR_POLICY: &str = "attempt_for_policy";
pub const REL_AUDITS_PROMOTION: &str = "audits_promotion";
pub const ACTION_SUBSCRIBE: &str = "tenkai.subscribe";
pub const ACTION_REPLACE_SUBSCRIPTION: &str = "tenkai.replace_subscription";
pub const ACTION_CONFIGURE_MAINTENANCE: &str = "tenkai.configure_maintenance_windows";
pub const ACTION_CONFIGURE_PRODUCT_MAINTENANCE: &str =
    "tenkai.configure_product_maintenance_windows";
pub const ACTION_EMERGENCY_OVERRIDE: &str = "tenkai.emergency_maintenance_override";

pub const MAX_OPAQUE_IDENTIFIER_BYTES: usize = 256;

pub fn validate_identifier(label: &str, value: &str) -> Result<()> {
    let mut chars = value.chars();
    if !matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+'))
    {
        bail!(
            "{label} must start with an ASCII letter or digit and contain only letters, digits, '.', '_', '-', or '+'"
        );
    }
    Ok(())
}

pub fn validate_opaque_identifier(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.contains("://")
        || value.contains('/')
        || value.contains('\\')
    {
        bail!("{label} is empty, oversized, or not an opaque identifier");
    }
    Ok(())
}

pub use crate::client::{
    known_action, known_actions, register, require_canary_schema,
    require_connectivity_upgrade_schema, require_package_migration_schema, require_wave_schema,
};

pub fn product_id(name: &str) -> String {
    format!("tenkai:product:{name}")
}
pub fn release_id(product: &str, version: &str) -> String {
    format!("tenkai:release:{product}@{version}")
}
pub fn release_verification_id(release_id: &str) -> String {
    format!("{release_id}:verification")
}
pub fn release_recall_id(release_id: &str) -> String {
    format!("{release_id}:recall")
}
pub fn channel_id(product: &str, channel: &str) -> String {
    format!("tenkai:channel:{product}/{channel}")
}
pub fn env_id(name: &str) -> String {
    format!("tenkai:env:{name}")
}
pub fn wave_id(name: &str) -> String {
    format!("tenkai:wave:{name}")
}
pub fn connectivity_upgrade_id(name: &str) -> String {
    format!("tenkai:connectivity-upgrade:{name}")
}
pub fn package_migration_id(name: &str) -> String {
    package_migration_id_in(None, name)
}
pub fn package_migration_id_in(partition: Option<&str>, name: &str) -> String {
    match partition.filter(|value| !value.is_empty()) {
        Some(partition) => format!("tenkai:package-migration:{partition}:{name}"),
        None => format!("tenkai:package-migration:{name}"),
    }
}
pub fn package_migration_lock_id(environment: &str) -> String {
    package_migration_lock_id_in(None, environment)
}
pub fn package_migration_lock_id_in(partition: Option<&str>, environment: &str) -> String {
    match partition.filter(|value| !value.is_empty()) {
        Some(partition) => format!("tenkai:package-migration-lock:{partition}:{environment}"),
        None => format!("tenkai:package-migration-lock:{environment}"),
    }
}
pub fn plan_id(env: &str, ts: i64, content_id: &str) -> String {
    format!("tenkai:plan:{env}:{ts}:{content_id}")
}
pub fn deployment_id(env: &str, product: &str, ts: i64) -> String {
    format!("tenkai:deployment:{env}:{product}:{ts}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_identifier_components_reject_delimiters() {
        assert!(validate_identifier("product", "api-service_2.0").is_ok());
        assert!(validate_identifier("product", "api@1").is_err());
        assert!(validate_identifier("environment", "prod:eu").is_err());
        assert!(validate_identifier("channel", "stable/eu").is_err());
    }

    #[test]
    fn opaque_identifiers_reject_paths_and_controls() {
        assert!(validate_opaque_identifier("id", "acme").is_ok());
        assert!(validate_opaque_identifier("id", "").is_err());
        assert!(validate_opaque_identifier("id", "a".repeat(257).as_str()).is_err());
        assert!(validate_opaque_identifier("id", "acme/types").is_err());
        assert!(validate_opaque_identifier("id", "https://example").is_err());
        assert!(validate_opaque_identifier("id", "acme\\types").is_err());
        assert!(validate_opaque_identifier("id", "acme\n").is_err());
        let error = validate_opaque_identifier("change-set pin namespace", "acme/types")
            .expect_err("path must fail closed");
        assert_eq!(
            error.to_string(),
            "change-set pin namespace is empty, oversized, or not an opaque identifier"
        );
    }
}
