//! Shared Ed25519 verification mechanics for Tenkai's signed formats.

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

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

pub(crate) fn verify_strict(
    key: &VerifyingKey,
    signature_label: &str,
    signature: &str,
    message: &[u8],
) -> Result<()> {
    let signature = Signature::from_bytes(&decode_exact::<64>(signature_label, signature)?);
    key.verify_strict(message, &signature)
        .with_context(|| format!("{signature_label} verification failed"))
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
        let signature = STANDARD.encode(signing_key.sign(message).to_bytes());
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
}
