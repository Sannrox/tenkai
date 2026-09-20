//! Tenkai-owned package migration plans (ADR 0024).
//!
//! Package definitions and compatibility classification stay with their
//! external authorities. Tenkai binds source, target, evidence, and ordered
//! checkpoints into one immutable plan, then executes, resumes, rolls back,
//! or records recovery-required state under the environment fence.

mod admit;
mod approval;
mod approval_files;
mod checkpoint;
mod compensate;
mod declaration;
mod execute;
mod leases;
mod persist;
mod preview;
mod rollback;
mod types;

#[cfg(test)]
mod tests;

pub use approval::{canonical_approval_bytes, verify_approval_envelope, verify_authorization};
pub use approval_files::{RemoteApprovalFiles, load_trust_roots, require_migration_api_version};
pub use execute::{approve, execute, resume, resume_in};
pub use preview::{
    create, create_in, format_migration, preview, preview_in, run_until_blocked,
    run_until_blocked_in,
};
pub use rollback::{load, load_in, rollback, rollback_in};
pub use types::{
    APPROVAL_PURPOSE, APPROVAL_SCHEMA, ApprovalTrustRoots, ApprovalTrustedSigner,
    COMPATIBILITY_VERSION, CheckpointClass, CheckpointDecl, CheckpointReceipt,
    CompatibilityEvidence, CompatibilityStatus, MIGRATION_API_VERSION, MIGRATION_DOCUMENT_VERSION,
    MIGRATION_PROFILE, MigrationApprovalEnvelope, MigrationApprovalStatement,
    MigrationAuthorization, MigrationDeclaration, MigrationRecord, MigrationStatus,
    PackageMigrationApplyRequest, PackageMigrationMutateRequest, PackageMigrationPreviewRequest,
    PackageMigrationResult, PackagePin,
};
