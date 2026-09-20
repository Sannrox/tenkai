//! Fail-closed package-migration approval digest and signature checks.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

use crate::ontology::validate_identifier;
use crate::signature_verification;

use super::types::{
    APPROVAL_DOMAIN, APPROVAL_PURPOSE, APPROVAL_SCHEMA, ApprovalTrustRoots,
    MigrationApprovalStatement, MigrationAuthorization, MigrationRecord, TRUST_ROOT_VERSION,
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
    if let MigrationAuthorization::LocalDevelopment { .. } = authorization
        && record.environment != "local"
    {
        bail!("unapproved development execution is restricted to the built-in local environment");
    }
    match authorization {
        MigrationAuthorization::LocalDevelopment { reason } => {
            if reason.trim().is_empty() {
                bail!("package migration development approval requires a non-empty reason");
            }
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

pub fn canonical_approval_bytes(statement: &MigrationApprovalStatement) -> Result<Vec<u8>> {
    if statement.purpose != APPROVAL_PURPOSE {
        bail!("package migration approval purpose must be {APPROVAL_PURPOSE}");
    }
    signature_verification::validate_prefixed_digest(
        "migration identity digest",
        &statement.identity_digest,
    )?;
    validate_identifier("approval environment", &statement.environment)?;
    if statement.expires_at <= statement.issued_at {
        bail!("package migration approval expiry must be after its issue time");
    }
    let mut bytes = APPROVAL_DOMAIN.to_vec();
    for value in [
        statement.identity_digest.as_bytes(),
        statement.environment.as_bytes(),
        statement.purpose.as_bytes(),
    ] {
        signature_verification::push_len_prefixed(&mut bytes, value);
    }
    bytes.extend_from_slice(&statement.issued_at.to_be_bytes());
    bytes.extend_from_slice(&statement.expires_at.to_be_bytes());
    Ok(bytes)
}

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
    if envelope.schema != APPROVAL_SCHEMA {
        bail!(
            "unsupported package migration approval schema {}",
            envelope.schema
        );
    }
    if envelope.statement.identity_digest != identity_digest
        || envelope.statement.environment != environment
    {
        bail!("package migration approval is bound to a different identity or environment");
    }
    if now < envelope.statement.issued_at {
        bail!("package migration approval is not valid yet");
    }
    if now >= envelope.statement.expires_at {
        bail!(
            "package migration approval expired at {}",
            envelope.statement.expires_at
        );
    }
    let roots_raw = std::fs::read_to_string(trust_roots).with_context(|| {
        format!(
            "reading package migration approval trust roots {}",
            trust_roots.display()
        )
    })?;
    let roots: ApprovalTrustRoots = toml::from_str(&roots_raw).with_context(|| {
        format!(
            "parsing package migration approval trust roots {}",
            trust_roots.display()
        )
    })?;
    if roots.version != TRUST_ROOT_VERSION || roots.signers.is_empty() {
        bail!(
            "package migration approval trust roots must use version {TRUST_ROOT_VERSION} and contain at least one signer"
        );
    }
    let signer = roots
        .signers
        .iter()
        .find(|signer| signer.key_id == envelope.key_id)
        .with_context(|| {
            format!(
                "package migration approval signer {} is not currently trusted",
                envelope.key_id
            )
        })?;
    let public_key = signature_verification::trusted_key(
        "package migration approval public key",
        &signer.public_key,
        &signer.key_id,
    )?;
    signature_verification::verify_strict(
        &public_key,
        "package migration approval signature",
        &envelope.signature,
        &canonical_approval_bytes(&envelope.statement)?,
    )?;
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
