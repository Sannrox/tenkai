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

pub(crate) fn trusted_key(
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
}
