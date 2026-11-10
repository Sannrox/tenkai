//! Fail-closed package-migration approval digest and signature checks.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

use crate::ontology::validate_identifier;
use crate::plan_approval::SignedApproval;
use crate::signature_verification::{self, TrustRootKind, TrustRoots};

use super::types::{
    APPROVAL_DOMAIN, APPROVAL_PURPOSE, APPROVAL_SCHEMA, MigrationApprovalStatement,
    MigrationAuthorization, MigrationRecord,
};

pub fn verify_authorization(
    record: &MigrationRecord,
    authorization: MigrationAuthorization<'_>,
) -> Result<()> {
    let _ = approval_digest(record, authorization)?;
    Ok(())
}

pub(super) fn approval_digest(
    record: &MigrationRecord,
    authorization: MigrationAuthorization<'_>,
) -> Result<String> {
    match authorization {
        MigrationAuthorization::LocalDevelopment { reason } => {
            crate::plan_approval::require_local_bypass(&record.environment, reason)?;
            let mut output = b"TENKAI-PACKAGE-MIGRATION-DEV-APPROVAL-V1\0".to_vec();
            signature_verification::push_len_prefixed(
                &mut output,
                record.identity_digest.as_bytes(),
            );
            signature_verification::push_len_prefixed(&mut output, reason.as_bytes());
            Ok(format!("sha256:{:x}", Sha256::digest(output)))
        }
        MigrationAuthorization::Signed {
            approval,
            trust_roots,
        } => {
            verify_signed_approval(record, approval, trust_roots, crate::now_millis())?;
            Ok(identity_approval_binding(record))
        }
    }
}

pub(super) fn require_approval(
    record: &MigrationRecord,
    authorization: MigrationAuthorization<'_>,
) -> Result<()> {
    if record.approval_digest.is_empty() {
        bail!("package migration {} is not approved", record.name);
    }
    let expected = approval_digest(record, authorization)?;
    if expected != record.approval_digest {
        bail!(
            "package migration {} approval does not match the stored digest",
            record.name
        );
    }
    Ok(())
}

/// The signing bytes and time window of a package migration approval. The
/// bytes are frozen: stored approvals were signed over them.
impl SignedApproval for MigrationApprovalStatement {
    const SCHEMA: &'static str = APPROVAL_SCHEMA;
    const KIND: TrustRootKind = TrustRootKind::PackageMigration;

    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.purpose != APPROVAL_PURPOSE {
            bail!("package migration approval purpose must be {APPROVAL_PURPOSE}");
        }
        signature_verification::validate_prefixed_digest(
            "migration identity digest",
            &self.identity_digest,
        )?;
        validate_identifier("approval environment", &self.environment)?;
        if self.expires_at <= self.issued_at {
            bail!("package migration approval expiry must be after its issue time");
        }
        let mut bytes = APPROVAL_DOMAIN.to_vec();
        for value in [
            self.identity_digest.as_bytes(),
            self.environment.as_bytes(),
            self.purpose.as_bytes(),
        ] {
            signature_verification::push_len_prefixed(&mut bytes, value);
        }
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(bytes)
    }

    fn issued_at(&self) -> i64 {
        self.issued_at
    }

    fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Verify a signed package migration approval file against trust roots for
/// the given migration identity and environment.
pub fn verify_approval_envelope(
    identity_digest: &str,
    environment: &str,
    approval: &Path,
    trust_roots: &Path,
    now: i64,
) -> Result<()> {
    let raw = std::fs::read(approval)
        .with_context(|| format!("reading package migration approval {}", approval.display()))?;
    let envelope: super::types::MigrationApprovalEnvelope =
        serde_json::from_slice(&raw).context("parsing package migration approval envelope")?;
    if envelope.statement.identity_digest != identity_digest
        || envelope.statement.environment != environment
    {
        bail!("package migration approval is bound to a different identity or environment");
    }
    let roots = TrustRoots::load(trust_roots, TrustRootKind::PackageMigration)?;
    envelope.verify_signature(&roots, now)?;
    Ok(())
}

fn verify_signed_approval(
    record: &MigrationRecord,
    approval: &Path,
    trust_roots: &Path,
    now: i64,
) -> Result<String> {
    verify_approval_envelope(
        &record.identity_digest,
        &record.environment,
        approval,
        trust_roots,
        now,
    )?;
    Ok(identity_approval_binding(record))
}

fn identity_approval_binding(record: &MigrationRecord) -> String {
    let mut output = b"TENKAI-PACKAGE-MIGRATION-APPROVED-V1\0".to_vec();
    signature_verification::push_len_prefixed(&mut output, record.identity_digest.as_bytes());
    signature_verification::push_len_prefixed(&mut output, record.environment.as_bytes());
    format!("sha256:{:x}", Sha256::digest(output))
}
