//! Shared signed-format primitives for Tenkai's content-bound evidence.
//!
//! This module is the deep seam for encoding and Ed25519 mechanics used by
//! release signatures, plan approvals, offline bundles, and provenance
//! envelopes. Domain modules keep statement shapes, domain tags, and policy
//! rules; they must not re-encode length-prefixing, digest grammar, key-id
//! derivation, or strict signature verification.

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

/// Append a big-endian u64 length prefix and the raw bytes that follow.
///
/// Every content-bound Tenkai signature domain uses this framing so signed
/// bytes stay independent of JSON/TOML serializers.
pub(crate) fn push_len_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

/// Accept exactly 64 lowercase hexadecimal characters (bare sha256 hex).
pub(crate) fn validate_hex_digest(label: &str, value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} must be a 64-character hexadecimal sha256 digest");
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("{label} must use lowercase hexadecimal");
    }
    Ok(())
}

/// Accept `sha256:` followed by 64 lowercase hexadecimal characters.
pub(crate) fn validate_prefixed_digest(label: &str, value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{label} must use sha256:<hex>");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{label} must contain 64 lowercase hexadecimal characters");
    }
    Ok(())
}

/// Accept a content-bound key id in `sha256:<hex>` form.
pub(crate) fn validate_key_id(label: &str, value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{label} must use the sha256:<hex> format");
    };
    validate_hex_digest(label, hex)
}

pub(crate) fn key_id(public_key: &[u8; 32]) -> String {
    format!("sha256:{:x}", Sha256::digest(public_key))
}

pub(crate) fn decode_exact<const N: usize>(label: &str, value: &str) -> Result<[u8; N]> {
    let bytes = STANDARD
        .decode(value)
        .with_context(|| format!("{label} is not valid base64"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("{label} must decode to {N} bytes, got {}", bytes.len())
    })
}

pub(crate) fn verifying_key(label: &str, value: &str) -> Result<VerifyingKey> {
    let bytes = decode_exact::<32>(label, value)?;
    let key = VerifyingKey::from_bytes(&bytes)
        .with_context(|| format!("{label} is not a valid Ed25519 public key"))?;
    if key.is_weak() {
        bail!("{label} is weak and cannot be trusted");
    }
    Ok(key)
}

/// How far a signed artifact's signed time may run ahead of the verifier's
/// clock, for replicas and signers whose clocks drift apart.
pub(crate) const SIGNED_AT_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

/// Optional validity window on a trust-root signer, Unix milliseconds.
///
/// Absent fields mean the window is not recorded: the signer is trusted
/// until removed or revoked. Load still accepts an expired window so the
/// rest of the file keeps working; verification refuses it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SignerValidityWindow {
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

impl SignerValidityWindow {
    pub(crate) fn new(not_before: Option<i64>, not_after: Option<i64>) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("not_before", self.not_before),
            ("not_after", self.not_after),
        ] {
            if let Some(value) = value
                && value <= 0
            {
                bail!("signer {name} must be a positive Unix millisecond timestamp");
            }
        }
        if let (Some(not_before), Some(not_after)) = (self.not_before, self.not_after)
            && not_before >= not_after
        {
            bail!("signer not_before must be before not_after");
        }
        Ok(())
    }

    /// Refuse a signature when `at_ms` is outside this window. The reason
    /// names `not_before` or `not_after`. A window that is not recorded
    /// never refuses.
    pub(crate) fn check(&self, identity: &str, at_ms: i64) -> Result<()> {
        if let Some(not_before) = self.not_before
            && at_ms < not_before
        {
            bail!("trusted signer {identity} is not yet valid (not_before)");
        }
        if let Some(not_after) = self.not_after
            && at_ms > not_after
        {
            bail!("trusted signer {identity} is no longer valid (not_after)");
        }
        Ok(())
    }

    /// Check a signed artifact (ADR 0042): its signed time must not be
    /// after `now_ms` (beyond [`SIGNED_AT_CLOCK_SKEW_MS`]), and the window is
    /// checked at the signed time, so a key's later `not_after` does not
    /// invalidate what it already signed.
    pub(crate) fn check_signed_at(
        &self,
        identity: &str,
        signed_at_ms: i64,
        now_ms: i64,
    ) -> Result<()> {
        if signed_at_ms > now_ms.saturating_add(SIGNED_AT_CLOCK_SKEW_MS) {
            bail!("artifact signed by {identity} carries a signed time in the future");
        }
        self.check(identity, signed_at_ms)
    }
}

/// The one trust-roots file version every kind uses.
pub const TRUST_ROOT_VERSION: u32 = 1;

/// What a trust-roots file pins signers for. Each kind has its own file,
/// label and signing domain; the shape and the structural checks are shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRootKind {
    Release,
    PlanApproval,
    PackageMigration,
    ModelEvaluation,
}

impl TrustRootKind {
    /// How errors name the kind, such as `plan approval`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::PlanApproval => "plan approval",
            Self::PackageMigration => "package migration approval",
            Self::ModelEvaluation => "model evaluation",
        }
    }

    /// Model evaluation signers are keys only; every other kind names who
    /// holds each key.
    fn names_signers(self) -> bool {
        !matches!(self, Self::ModelEvaluation)
    }
}

/// Signer keys an operator pins for one [`TrustRootKind`], as read from its
/// TOML file or a request body.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct TrustRoots {
    pub version: u32,
    pub signers: Vec<TrustedSigner>,
}

/// One pinned Ed25519 signer key.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct TrustedSigner {
    /// `sha256:<hex>` of the public key.
    pub key_id: String,
    /// Who holds the key. Empty only for model evaluation signers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity: String,
    /// Standard base64 of the 32-byte Ed25519 public key.
    pub public_key: String,
    /// Plan approval only: environments this signer may approve for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environments: Vec<String>,
    /// Plan approval only: approval policy providers it may sign for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    /// Plan approval only: approver groups it counts toward.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Unix milliseconds. Absent: validity is not recorded (#812).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub not_before: Option<i64>,
    /// Unix milliseconds. Absent: validity is not recorded (#812).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub not_after: Option<i64>,
}

impl TrustedSigner {
    /// An unscoped signer with no recorded validity window.
    pub fn new(
        key_id: impl Into<String>,
        identity: impl Into<String>,
        public_key: impl Into<String>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            identity: identity.into(),
            public_key: public_key.into(),
            environments: Vec::new(),
            providers: Vec::new(),
            groups: Vec::new(),
            not_before: None,
            not_after: None,
        }
    }

    pub(crate) fn validity(&self) -> SignerValidityWindow {
        SignerValidityWindow::new(self.not_before, self.not_after)
    }

    fn scoped(&self) -> bool {
        !(self.environments.is_empty() && self.providers.is_empty() && self.groups.is_empty())
    }
}

impl TrustRoots {
    /// Read and [`validate`](Self::validate) a `kind` trust-roots TOML file.
    pub fn load(path: &std::path::Path, kind: TrustRootKind) -> Result<Self> {
        let label = kind.label();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {label} trust roots {}", path.display()))?;
        let roots: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing {label} trust roots {}", path.display()))?;
        roots.validate(kind)?;
        Ok(roots)
    }

    /// The structural checks every kind shares: version, at least one
    /// signer, well-formed and unique keys, well-formed windows, and
    /// unique named identities. Scopes are refused outside plan approval,
    /// whose own scope rules apply on top. Revocation is checked when a
    /// key verifies, not here, so a file keeps loading until rollover.
    pub fn validate(&self, kind: TrustRootKind) -> Result<()> {
        let label = kind.label();
        if self.version != TRUST_ROOT_VERSION {
            bail!(
                "unsupported {label} trust-root version {}; expected {TRUST_ROOT_VERSION}",
                self.version
            );
        }
        if self.signers.is_empty() {
            bail!("{label} trust roots contain no signers");
        }
        let mut key_ids = std::collections::BTreeSet::new();
        let mut identities = std::collections::BTreeSet::new();
        for signer in &self.signers {
            validate_key_id(&format!("{label} signer key id"), &signer.key_id)?;
            if !key_ids.insert(&signer.key_id) {
                bail!(
                    "{label} trust roots contain duplicate key id {}",
                    signer.key_id
                );
            }
            if kind.names_signers() || !signer.identity.is_empty() {
                validate_signer_text("trusted signer identity", &signer.identity)?;
                if !identities.insert(&signer.identity) {
                    bail!(
                        "{label} trust roots contain duplicate signer identity {}",
                        signer.identity
                    );
                }
            }
            well_formed_key(
                &format!("{label} public key"),
                &signer.public_key,
                &signer.key_id,
            )?;
            signer.validity().validate()?;
            if kind == TrustRootKind::PlanApproval {
                crate::plan_approval::check_signer_scopes(signer)?;
            } else if signer.scoped() {
                bail!(
                    "{label} signer {} has environments, providers or groups; only plan approval signers are scoped",
                    signer.key_id
                );
            }
        }
        Ok(())
    }

    /// The `kind` signer with `key_id`, whatever its validity window.
    pub(crate) fn signer(&self, kind: TrustRootKind, key_id: &str) -> Result<&TrustedSigner> {
        self.signers
            .iter()
            .find(|signer| signer.key_id == key_id)
            .with_context(|| format!("{} signer {key_id} is not trusted", kind.label()))
    }
}

/// Non-empty, trimmed, at most 512 bytes, no NUL: a signer identity or
/// scope as trust roots and approval statements carry it.
pub(crate) fn validate_signer_text(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value != value.trim() || value.len() > 512 || value.contains('\0')
    {
        bail!("{name} is empty, non-canonical, or too long");
    }
    Ok(())
}

/// Key to verify a signature with now: well formed and not revoked
/// ([`crate::key_revocation`]).
pub(crate) fn trusted_key(
    label: &str,
    public_key: &str,
    expected_key_id: &str,
) -> Result<VerifyingKey> {
    if crate::key_revocation::is_revoked(expected_key_id) {
        bail!("{label} {expected_key_id} is revoked");
    }
    well_formed_key(label, public_key, expected_key_id)
}

/// Structural check for loading trust roots: the id matches the key and the
/// key is not weak. Revoked keys still load, so a trust file keeps working
/// until rollover removes them.
pub(crate) fn well_formed_key(
    label: &str,
    public_key: &str,
    expected_key_id: &str,
) -> Result<VerifyingKey> {
    let bytes = decode_exact::<32>(label, public_key)?;
    let derived = key_id(&bytes);
    if expected_key_id != derived {
        bail!("{label} id {expected_key_id} does not match its public key ({derived})");
    }
    verifying_key(label, public_key)
}

/// Strict Ed25519 verification over raw signature bytes.
///
/// Used by JWT assertions (base64url payload + raw 64-byte signature) and by
/// the base64 signature path below so every domain shares one fail-closed rule.
pub(crate) fn verify_strict_bytes(
    key: &VerifyingKey,
    signature_label: &str,
    signature: &[u8; 64],
    message: &[u8],
) -> Result<()> {
    let signature = Signature::from_bytes(signature);
    key.verify_strict(message, &signature)
        .with_context(|| format!("{signature_label} verification failed"))
}

/// Strict Ed25519 verification over a standard-base64 signature string.
pub(crate) fn verify_strict(
    key: &VerifyingKey,
    signature_label: &str,
    signature: &str,
    message: &[u8],
) -> Result<()> {
    let signature = decode_exact::<64>(signature_label, signature)?;
    verify_strict_bytes(key, signature_label, &signature, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn validates_key_identity_and_strict_signature() {
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let encoded_key = STANDARD.encode(public_key);
        let key = verifying_key("test key", &encoded_key).unwrap();
        let derived = key_id(&public_key);
        assert!(derived.starts_with("sha256:"));
        assert_eq!(derived.len(), 71);
        trusted_key("test key", &encoded_key, &derived).unwrap();
        assert!(trusted_key("test key", &encoded_key, "sha256:wrong").is_err());

        let message = b"content-bound message";
        let signature_bytes = signing_key.sign(message).to_bytes();
        verify_strict_bytes(&key, "test signature", &signature_bytes, message).unwrap();
        assert!(verify_strict_bytes(&key, "test signature", &signature_bytes, b"changed").is_err());
        let signature = STANDARD.encode(signature_bytes);
        verify_strict(&key, "test signature", &signature, message).unwrap();
        assert!(verify_strict(&key, "test signature", &signature, b"changed").is_err());
    }

    #[test]
    fn signer_validity_window_refuses_outside_named_bounds() {
        let open = SignerValidityWindow::default();
        open.validate().unwrap();
        open.check("release@example.com", 50).unwrap();
        assert!(open.not_before.is_none() && open.not_after.is_none());

        let window = SignerValidityWindow::new(Some(10), Some(20));
        window.validate().unwrap();
        window.check("release@example.com", 10).unwrap();
        window.check("release@example.com", 20).unwrap();
        let early = window.check("release@example.com", 9).unwrap_err();
        assert!(early.to_string().contains("not_before"), "{early:#}");
        let late = window.check("release@example.com", 21).unwrap_err();
        assert!(late.to_string().contains("not_after"), "{late:#}");
        assert!(
            SignerValidityWindow::new(Some(20), Some(10))
                .validate()
                .is_err()
        );
        assert!(SignerValidityWindow::new(Some(0), None).validate().is_err());
    }

    #[test]
    fn signed_artifact_window_is_checked_at_its_signed_time() {
        let window = SignerValidityWindow::new(Some(10), Some(20));
        window
            .check_signed_at("backup@example.com", 15, 100)
            .unwrap();
        let early = window
            .check_signed_at("backup@example.com", 9, 100)
            .unwrap_err();
        assert!(early.to_string().contains("not_before"), "{early:#}");
        let late = window
            .check_signed_at("backup@example.com", 21, 100)
            .unwrap_err();
        assert!(late.to_string().contains("not_after"), "{late:#}");
        window
            .check_signed_at("backup@example.com", 15, 15 - SIGNED_AT_CLOCK_SKEW_MS)
            .unwrap();
        let future = window
            .check_signed_at("backup@example.com", 15, 14 - SIGNED_AT_CLOCK_SKEW_MS)
            .unwrap_err();
        assert!(future.to_string().contains("future"), "{future:#}");
    }

    #[test]
    fn rejects_malformed_lengths_and_weak_keys() {
        assert!(decode_exact::<32>("test key", &STANDARD.encode([0; 31])).is_err());
        assert!(verifying_key("test key", &STANDARD.encode([0; 32])).is_err());
        assert!(
            verify_strict(
                &SigningKey::from_bytes(&[18; 32]).verifying_key(),
                "test signature",
                &STANDARD.encode([0; 63]),
                b"message"
            )
            .is_err()
        );
    }

    #[test]
    fn length_prefix_framing_is_stable() {
        let mut out = Vec::new();
        push_len_prefixed(&mut out, b"ab");
        assert_eq!(out[..8], 2u64.to_be_bytes());
        assert_eq!(&out[8..], b"ab");
        push_len_prefixed(&mut out, b"");
        assert_eq!(&out[10..], &0u64.to_be_bytes());
    }

    #[test]
    fn digest_forms_reject_case_and_prefix_drift() {
        let hex = "a".repeat(64);
        validate_hex_digest("bare", &hex).unwrap();
        assert!(validate_hex_digest("bare", &hex.to_uppercase()).is_err());
        assert!(validate_hex_digest("bare", &format!("sha256:{hex}")).is_err());

        validate_prefixed_digest("pref", &format!("sha256:{hex}")).unwrap();
        assert!(validate_prefixed_digest("pref", &hex).is_err());
        assert!(
            validate_prefixed_digest("pref", &format!("sha256:{}", hex.to_uppercase())).is_err()
        );

        validate_key_id("key", &format!("sha256:{hex}")).unwrap();
        assert!(validate_key_id("key", &hex).is_err());
    }

    /// The four trust-root files that existed before they shared one type,
    /// in the shapes operators have on disk, each with a second signer.
    #[test]
    fn existing_trust_root_files_still_load() {
        let signer = |seed: u8| {
            let public = SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes();
            (key_id(&public), STANDARD.encode(public))
        };
        let ((a_id, a_key), (b_id, b_key)) = (signer(3), signer(4));
        let release = format!(
            "version = 1\n[[signers]]\nkey_id = \"{a_id}\"\nidentity = \"release@example.com\"\npublic_key = \"{a_key}\"\nnot_before = 1\n[[signers]]\nkey_id = \"{b_id}\"\nidentity = \"ci@example.com\"\npublic_key = \"{b_key}\"\n"
        );
        let plan = format!(
            "version = 1\n[[signers]]\nkey_id = \"{a_id}\"\nidentity = \"alice\"\npublic_key = \"{a_key}\"\nenvironments = [\"prod\"]\nproviders = [\"builtin-auto\"]\n[[signers]]\nkey_id = \"{b_id}\"\nidentity = \"bob\"\npublic_key = \"{b_key}\"\ngroups = [\"ops\"]\n"
        );
        let evaluation = format!(
            "version = 1\n[[signers]]\nkey_id = \"{a_id}\"\npublic_key = \"{a_key}\"\n[[signers]]\nkey_id = \"{b_id}\"\npublic_key = \"{b_key}\"\nnot_after = 9\n"
        );
        for (kind, raw) in [
            (TrustRootKind::Release, &release),
            (TrustRootKind::PackageMigration, &release),
            (TrustRootKind::PlanApproval, &plan),
            (TrustRootKind::ModelEvaluation, &evaluation),
        ] {
            let roots: TrustRoots = toml::from_str(raw).unwrap();
            roots.validate(kind).unwrap();
            assert_eq!(
                toml::to_string(&roots)
                    .unwrap()
                    .parse::<toml::Table>()
                    .unwrap(),
                raw.parse::<toml::Table>().unwrap()
            );
        }
        let plan: TrustRoots = toml::from_str(&plan).unwrap();
        let error = plan.validate(TrustRootKind::Release).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("only plan approval signers are scoped")
        );
        let evaluation: TrustRoots = toml::from_str(&evaluation).unwrap();
        assert!(evaluation.validate(TrustRootKind::Release).is_err());
    }
}
