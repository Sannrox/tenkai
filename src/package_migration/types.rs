//! Package migration constants, records, and request types.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ontology::{package_migration_id_in, package_migration_lock_id_in};

pub const MIGRATION_PROFILE: &str = "tenkai.package_migration.v1";
pub const MIGRATION_DOCUMENT_VERSION: u32 = 1;
pub const COMPATIBILITY_VERSION: u32 = 1;
pub const MIGRATION_API_VERSION: u32 = 1;
pub const APPROVAL_SCHEMA: &str = "tenkai.package-migration-approval.v1";
pub(super) const APPROVAL_DOMAIN: &[u8] = b"TENKAI-PACKAGE-MIGRATION-APPROVAL-V1\0";
pub const APPROVAL_PURPOSE: &str = "execute_package_migration";
pub(super) const TRUST_ROOT_VERSION: u32 = 1;
pub(super) const MIGRATION_EXEC_NAMESPACE: &str = "tenkai.package-migration";
pub(super) const MIGRATION_EXEC_TTL_MS: i64 = 2 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointClass {
    Reversible,
    Compensating,
    Irreversible,
}

impl CheckpointClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::Compensating => "compensating",
            Self::Irreversible => "irreversible",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Compatible,
    Incompatible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    Admitted,
    Running,
    Succeeded,
    Failed,
    RolledBack,
    RecoveryRequired,
}

impl MigrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePin {
    pub product: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointDecl {
    pub id: String,
    pub class: CheckpointClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_admission: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidence {
    pub version: u32,
    pub status: CompatibilityStatus,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationDeclaration {
    pub version: u32,
    pub profile: String,
    pub source: PackagePin,
    pub target: PackagePin,
    pub compatibility: CompatibilityEvidence,
    pub checkpoints: Vec<CheckpointDecl>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReceipt {
    pub checkpoint_id: String,
    pub class: CheckpointClass,
    pub effect: String,
    pub result: String,
    pub fence_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRecord {
    pub name: String,
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    pub identity_digest: String,
    pub declaration: MigrationDeclaration,
    pub approval_digest: String,
    pub fence_generation: u64,
    pub status: MigrationStatus,
    pub receipts: Vec<CheckpointReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_receipt_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_plan_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_rollback_plan_id: Option<String>,
}

pub(super) fn catalog_id(partition: Option<&str>, name: &str) -> String {
    package_migration_id_in(partition, name)
}

pub(super) fn record_catalog_id(record: &MigrationRecord) -> String {
    catalog_id(record.partition.as_deref(), &record.name)
}

pub(super) fn record_lock_id(record: &MigrationRecord) -> String {
    package_migration_lock_id_in(record.partition.as_deref(), &record.environment)
}

pub(super) fn exec_lease_name(partition: Option<&str>, name: &str) -> String {
    match partition.filter(|value| !value.is_empty()) {
        Some(partition) => format!("{partition}:{name}"),
        None => name.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationAuthorization<'a> {
    LocalDevelopment {
        reason: &'a str,
    },
    Signed {
        approval: &'a Path,
        trust_roots: &'a Path,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationApprovalStatement {
    pub identity_digest: String,
    pub environment: String,
    pub purpose: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationApprovalEnvelope {
    pub schema: String,
    pub key_id: String,
    pub statement: MigrationApprovalStatement,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTrustRoots {
    pub version: u32,
    pub signers: Vec<ApprovalTrustedSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTrustedSigner {
    pub key_id: String,
    pub identity: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageMigrationPreviewRequest {
    pub version: u32,
    pub environment: String,
    pub declaration: MigrationDeclaration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_receipt_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageMigrationApplyRequest {
    pub version: u32,
    pub environment: String,
    pub declaration: MigrationDeclaration,
    pub expected_generation: u64,
    pub approval: MigrationApprovalEnvelope,
    pub trust_roots: ApprovalTrustRoots,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_receipt_digest: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub plan_approvals: BTreeMap<String, crate::plan_approval::ApprovalEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageMigrationMutateRequest {
    pub version: u32,
    pub expected_generation: u64,
    pub approval: MigrationApprovalEnvelope,
    pub trust_roots: ApprovalTrustRoots,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub plan_approvals: BTreeMap<String, crate::plan_approval::ApprovalEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageMigrationResult {
    pub version: u32,
    pub record: MigrationRecord,
}

impl PackageMigrationResult {
    pub fn from_record(record: MigrationRecord) -> Self {
        Self {
            version: MIGRATION_API_VERSION,
            record,
        }
    }
}
