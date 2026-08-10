//! Registered, immutable, payload-free release provenance envelopes.
//!
//! These envelopes retain authoritative references from external systems. They
//! are not release signatures, plan approvals, gate decisions, or execution
//! authorization.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::release_signing::TrustRoots;

pub const GOVERNED_SUBJECT_PROFILE: &str = "example.governed-subject-receipt/v1";
pub const BUILD_ATTESTATION_PROFILE: &str = "example.build-attestation/v1";
pub const MAX_ENVELOPES: usize = 4;
const MAX_ENVELOPE_BYTES: u64 = 16 * 1024;
const MAX_REFERENCES: usize = 8;
const MAX_TEXT_BYTES: usize = 256;
const MAX_FRESHNESS_MS: i64 = 31 * 24 * 60 * 60 * 1_000;
const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedReference {
    pub kind: String,
    pub id: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceEnvelope {
    pub profile: String,
    pub issuer: String,
    pub issuer_key_id: String,
    pub subject: String,
    pub content_digest: String,
    pub decision: String,
    pub receipt_schema: String,
    pub receipt_digest: String,
    pub governed_references: Vec<GovernedReference>,
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceProjection {
    pub profile: String,
    pub issuer: String,
    pub issuer_key_id: String,
    pub subject: String,
    pub envelope_digest: String,
    pub decision: String,
    pub receipt_schema: String,
    pub receipt_digest: String,
    pub governed_references: Vec<GovernedReference>,
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Copy)]
struct Profile {
    id: &'static str,
    issuer: &'static str,
    receipt_schema: &'static str,
    reference_kinds: &'static [&'static str],
}

const PROFILES: &[Profile] = &[
    Profile {
        id: GOVERNED_SUBJECT_PROFILE,
        issuer: "sekai-chisei",
        receipt_schema: "chisei.governed-subject-receipt/v1",
        reference_kinds: &["operation", "evidence"],
    },
    Profile {
        id: BUILD_ATTESTATION_PROFILE,
        issuer: "example-builder",
        receipt_schema: "example.build-attestation-receipt/v1",
        reference_kinds: &["build", "material"],
    },
];

fn profile(id: &str) -> Result<Profile> {
    PROFILES
        .iter()
        .copied()
        .find(|profile| profile.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown release provenance profile {id:?}"))
}

fn validate_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
        || value.contains("://")
        || value.contains('/')
        || value.contains('\\')
    {
        bail!("{label} is empty, oversized, or not an opaque identifier");
    }
    Ok(())
}

fn validate_schema_id(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
        || value.contains("://")
        || value.contains('\\')
        || value.starts_with('/')
        || value.contains("../")
    {
        bail!("{label} is empty, oversized, or not a versioned schema identifier");
    }
    Ok(())
}

impl ProvenanceEnvelope {
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        if !file.metadata()?.is_file() {
            bail!("release provenance envelope must be a regular file");
        }
        let mut raw = Vec::new();
        file.take(MAX_ENVELOPE_BYTES + 1).read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_ENVELOPE_BYTES {
            bail!("release provenance envelope exceeds {MAX_ENVELOPE_BYTES} bytes");
        }
        let envelope: Self = serde_json::from_slice(&raw)?;
        envelope.validate_structure()?;
        Ok(envelope)
    }

    pub fn validate(&self, now_unix_ms: i64) -> Result<()> {
        self.validate_structure()?;
        if self.observed_at_unix_ms > now_unix_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            bail!("release provenance observation time is in the future");
        }
        if self.expires_at_unix_ms < now_unix_ms {
            bail!("release provenance evidence is stale");
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<()> {
        let profile = profile(&self.profile)?;
        self.validate_stored_structure()?;
        if self.issuer != profile.issuer {
            bail!(
                "release provenance profile {:?} does not admit issuer {:?}",
                self.profile,
                self.issuer
            );
        }
        if self.receipt_schema != profile.receipt_schema {
            bail!(
                "release provenance profile {:?} requires receipt schema {:?}",
                self.profile,
                profile.receipt_schema
            );
        }
        for reference in &self.governed_references {
            if !profile.reference_kinds.contains(&reference.kind.as_str()) {
                bail!(
                    "release provenance profile {:?} does not admit reference kind {:?}",
                    self.profile,
                    reference.kind
                );
            }
        }
        Ok(())
    }

    fn validate_stored_structure(&self) -> Result<()> {
        validate_schema_id("release provenance profile", &self.profile)?;
        validate_text("release provenance issuer", &self.issuer)?;
        crate::signature_verification::validate_key_id(
            "release provenance issuer_key_id",
            &self.issuer_key_id,
        )?;
        validate_text("release provenance subject", &self.subject)?;
        crate::signature_verification::validate_prefixed_digest(
            "release provenance content_digest",
            &self.content_digest,
        )?;
        if self.decision != "allow" {
            bail!("release provenance decision must be allow");
        }
        validate_schema_id("release provenance receipt_schema", &self.receipt_schema)?;
        crate::signature_verification::validate_prefixed_digest(
            "release provenance receipt_digest",
            &self.receipt_digest,
        )?;
        if self.governed_references.len() > MAX_REFERENCES {
            bail!("release provenance has too many governed references");
        }
        let mut previous: Option<(&str, &str)> = None;
        for reference in &self.governed_references {
            validate_schema_id("release provenance reference kind", &reference.kind)?;
            validate_text("release provenance reference id", &reference.id)?;
            crate::signature_verification::validate_prefixed_digest(
                "release provenance reference digest",
                &reference.digest,
            )?;
            let current = (reference.kind.as_str(), reference.id.as_str());
            if previous.is_some_and(|value| value >= current) {
                bail!("release provenance references must be unique and canonically sorted");
            }
            previous = Some(current);
        }
        if self.observed_at_unix_ms <= 0
            || self.expires_at_unix_ms < self.observed_at_unix_ms
            || self.expires_at_unix_ms - self.observed_at_unix_ms > MAX_FRESHNESS_MS
        {
            bail!("release provenance freshness interval is invalid");
        }
        crate::signature_verification::decode_exact::<64>(
            "release provenance signature",
            &self.signature,
        )?;
        Ok(())
    }

    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        Ok(self.canonical_signed_bytes())
    }

    fn canonical_signed_bytes(&self) -> Vec<u8> {
        let mut output = b"TENKAI-RELEASE-PROVENANCE-V1\0".to_vec();
        for value in [
            &self.profile,
            &self.issuer,
            &self.issuer_key_id,
            &self.subject,
            &self.content_digest,
            &self.decision,
            &self.receipt_schema,
            &self.receipt_digest,
        ] {
            crate::signature_verification::push_len_prefixed(&mut output, value.as_bytes());
        }
        output.extend_from_slice(&(self.governed_references.len() as u64).to_be_bytes());
        for reference in &self.governed_references {
            crate::signature_verification::push_len_prefixed(
                &mut output,
                reference.kind.as_bytes(),
            );
            crate::signature_verification::push_len_prefixed(&mut output, reference.id.as_bytes());
            crate::signature_verification::push_len_prefixed(
                &mut output,
                reference.digest.as_bytes(),
            );
        }
        output.extend_from_slice(&self.observed_at_unix_ms.to_be_bytes());
        output.extend_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        output
    }

    pub fn digest(&self) -> Result<String> {
        let mut canonical = self.signed_bytes()?;
        crate::signature_verification::push_len_prefixed(&mut canonical, self.signature.as_bytes());
        Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
    }

    pub fn verify_issuer(&self, roots: &TrustRoots) -> Result<()> {
        roots.validate()?;
        let signer = roots.resolve(&self.issuer_key_id).map_err(|_| {
            anyhow::anyhow!(
                "release provenance issuer key {} is not trusted",
                self.issuer_key_id
            )
        })?;
        if signer.identity != self.issuer {
            bail!("release provenance issuer does not match its trusted key identity");
        }
        crate::signature_verification::verify_strict(
            &signer.verifying_key,
            "release provenance issuer signature",
            &self.signature,
            &self.signed_bytes()?,
        )
    }

    pub fn projection(&self) -> Result<ProvenanceProjection> {
        Ok(ProvenanceProjection {
            profile: self.profile.clone(),
            issuer: self.issuer.clone(),
            issuer_key_id: self.issuer_key_id.clone(),
            subject: self.subject.clone(),
            envelope_digest: self.digest()?,
            decision: self.decision.clone(),
            receipt_schema: self.receipt_schema.clone(),
            receipt_digest: self.receipt_digest.clone(),
            governed_references: self.governed_references.clone(),
            observed_at_unix_ms: self.observed_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        })
    }

    pub fn stored_digest(&self) -> Result<String> {
        self.validate_stored_structure()?;
        let mut canonical = self.canonical_signed_bytes();
        crate::signature_verification::push_len_prefixed(&mut canonical, self.signature.as_bytes());
        Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
    }

    pub fn stored_projection(&self) -> Result<ProvenanceProjection> {
        self.validate_stored_structure()?;
        Ok(ProvenanceProjection {
            profile: self.profile.clone(),
            issuer: self.issuer.clone(),
            issuer_key_id: self.issuer_key_id.clone(),
            subject: self.subject.clone(),
            envelope_digest: self.stored_digest()?,
            decision: self.decision.clone(),
            receipt_schema: self.receipt_schema.clone(),
            receipt_digest: self.receipt_digest.clone(),
            governed_references: self.governed_references.clone(),
            observed_at_unix_ms: self.observed_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        })
    }
}

pub fn load_all(
    paths: &[std::path::PathBuf],
    trust_roots_path: Option<&Path>,
) -> Result<Vec<ProvenanceEnvelope>> {
    if paths.len() > MAX_ENVELOPES {
        bail!("at most {MAX_ENVELOPES} release provenance envelopes are supported");
    }
    let mut envelopes = paths
        .iter()
        .map(|path| ProvenanceEnvelope::load(path))
        .collect::<Result<Vec<_>>>()?;
    if envelopes.is_empty() {
        if trust_roots_path.is_some() {
            bail!("--provenance-trust-roots requires at least one --provenance envelope");
        }
    } else {
        let path = trust_roots_path.ok_or_else(|| {
            anyhow::anyhow!(
                "release provenance requires --provenance-trust-roots for issuer authentication"
            )
        })?;
        let roots = TrustRoots::load(path)?;
        for envelope in &envelopes {
            envelope.verify_issuer(&roots)?;
        }
    }
    envelopes.sort_by(|left, right| left.profile.cmp(&right.profile));
    if envelopes
        .windows(2)
        .any(|pair| pair[0].profile == pair[1].profile)
    {
        bail!("duplicate release provenance profile");
    }
    Ok(envelopes)
}

pub fn release_content_digest(manifest_digest: &str, artifact_digest: &str) -> Result<String> {
    crate::signature_verification::validate_hex_digest("manifest digest", manifest_digest)?;
    crate::signature_verification::validate_hex_digest("artifact digest", artifact_digest)?;
    let mut canonical = b"TENKAI-RELEASE-PROVENANCE-CONTENT-V1\0".to_vec();
    crate::signature_verification::push_len_prefixed(&mut canonical, manifest_digest.as_bytes());
    crate::signature_verification::push_len_prefixed(&mut canonical, artifact_digest.as_bytes());
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

pub fn validate_release_binding(
    envelopes: &[ProvenanceEnvelope],
    manifest_digest: &str,
    artifact_digest: &str,
) -> Result<()> {
    let expected = release_content_digest(manifest_digest, artifact_digest)?;
    for envelope in envelopes {
        if envelope.content_digest != expected {
            bail!(
                "release provenance profile {:?} is not bound to the published manifest and artifacts",
                envelope.profile
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    fn envelope(profile: &str) -> ProvenanceEnvelope {
        let (issuer, receipt_schema, kind) = if profile == GOVERNED_SUBJECT_PROFILE {
            (
                "sekai-chisei",
                "chisei.governed-subject-receipt/v1",
                "operation",
            )
        } else {
            (
                "example-builder",
                "example.build-attestation-receipt/v1",
                "build",
            )
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let mut envelope = ProvenanceEnvelope {
            profile: profile.into(),
            issuer: issuer.into(),
            issuer_key_id: crate::release_signing::key_id(&signing_key.verifying_key().to_bytes()),
            subject: "subject-1".into(),
            content_digest: format!("sha256:{}", "1".repeat(64)),
            decision: "allow".into(),
            receipt_schema: receipt_schema.into(),
            receipt_digest: format!("sha256:{}", "2".repeat(64)),
            governed_references: vec![GovernedReference {
                kind: kind.into(),
                id: "receipt-1".into(),
                digest: format!("sha256:{}", "3".repeat(64)),
            }],
            observed_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            signature: base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
        };
        envelope.signature = base64::engine::general_purpose::STANDARD.encode(
            signing_key
                .sign(&envelope.signed_bytes().unwrap())
                .to_bytes(),
        );
        envelope
    }

    #[test]
    fn two_registered_profiles_use_the_same_canonical_contract() {
        let first = envelope(GOVERNED_SUBJECT_PROFILE);
        let second = envelope(BUILD_ATTESTATION_PROFILE);
        assert!(first.validate(1_500).is_ok());
        assert!(second.validate(1_500).is_ok());
        assert_ne!(first.digest().unwrap(), second.digest().unwrap());
        assert_eq!(first.digest().unwrap(), first.digest().unwrap());
    }

    #[test]
    fn governed_subject_receipt_fails_closed() {
        let original = envelope(GOVERNED_SUBJECT_PROFILE);
        for mutate in [
            |value: &mut ProvenanceEnvelope| value.issuer = "other".into(),
            |value: &mut ProvenanceEnvelope| value.decision = "deny".into(),
            |value: &mut ProvenanceEnvelope| value.receipt_schema = "other/v1".into(),
        ] {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert!(changed.validate(1_500).is_err());
        }
        assert!(original.validate(2_001).is_err());
        let mut future = original;
        future.observed_at_unix_ms = 1_000_000;
        future.expires_at_unix_ms = 1_001_000;
        assert!(future.validate(1_500).is_err());
    }

    #[test]
    fn release_binding_is_content_addressed() {
        let manifest = "a".repeat(64);
        let artifacts = "b".repeat(64);
        let changed_artifacts = "c".repeat(64);
        assert_ne!(
            release_content_digest(&manifest, &artifacts).unwrap(),
            release_content_digest(&manifest, &changed_artifacts).unwrap()
        );
    }

    #[test]
    fn issuer_signature_authenticates_the_registered_authority() {
        let envelope = envelope(GOVERNED_SUBJECT_PROFILE);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let roots = TrustRoots {
            version: crate::release_signing::TRUST_ROOT_VERSION,
            signers: vec![crate::release_signing::TrustedSigner {
                key_id: envelope.issuer_key_id.clone(),
                identity: envelope.issuer.clone(),
                public_key: base64::engine::general_purpose::STANDARD
                    .encode(signing_key.verifying_key().to_bytes()),
            }],
        };
        assert!(envelope.verify_issuer(&roots).is_ok());

        let mut tampered = envelope;
        tampered.subject = "other-subject".into();
        assert!(tampered.verify_issuer(&roots).is_err());
    }

    #[test]
    fn issuer_trust_root_is_bound_to_its_public_key() {
        let mut envelope = envelope(GOVERNED_SUBJECT_PROFILE);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let mismatched_key_id = format!("sha256:{}", "a".repeat(64));
        envelope.issuer_key_id = mismatched_key_id.clone();
        envelope.signature = base64::engine::general_purpose::STANDARD.encode(
            signing_key
                .sign(&envelope.signed_bytes().unwrap())
                .to_bytes(),
        );
        let roots = TrustRoots {
            version: crate::release_signing::TRUST_ROOT_VERSION,
            signers: vec![crate::release_signing::TrustedSigner {
                key_id: mismatched_key_id,
                identity: envelope.issuer.clone(),
                public_key: base64::engine::general_purpose::STANDARD
                    .encode(signing_key.verifying_key().to_bytes()),
            }],
        };

        let error = envelope.verify_issuer(&roots).unwrap_err().to_string();
        assert!(error.contains("does not match its public key"));
    }

    #[test]
    fn unknown_fields_and_oversized_files_fail_closed() {
        let envelope = envelope(GOVERNED_SUBJECT_PROFILE);
        let mut value = serde_json::to_value(&envelope).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("arbitrary_metadata".into(), serde_json::json!("secret"));
        assert!(serde_json::from_value::<ProvenanceEnvelope>(value).is_err());

        let path = std::env::temp_dir().join(format!(
            "tenkai-provenance-oversized-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::write(&path, vec![b'x'; MAX_ENVELOPE_BYTES as usize + 1]).unwrap();
        assert!(ProvenanceEnvelope::load(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn every_content_binding_changes_the_digest() {
        let original = envelope(GOVERNED_SUBJECT_PROFILE);
        let original_digest = original.digest().unwrap();
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.subject = "subject-2".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.content_digest = format!("sha256:{}", "4".repeat(64));
        variants.push(changed);
        let mut changed = original.clone();
        changed.governed_references[0].digest = format!("sha256:{}", "5".repeat(64));
        variants.push(changed);
        let mut changed = original.clone();
        changed.expires_at_unix_ms += 1;
        variants.push(changed);
        assert!(
            variants
                .iter()
                .all(|value| value.digest().unwrap() != original_digest)
        );
    }
}
