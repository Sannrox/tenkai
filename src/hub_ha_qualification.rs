//! Hub HA qualification evidence (#903).
//!
//! A two-replica PostgreSQL hub drill signs this statement after takeover,
//! exactly-once receipts, and a repeat against the same store. Product
//! `high_availability` stays unclaimed until a release advertises it; this
//! file is the gate. Verify offline: the signature covers the statement
//! bytes, not a re-encoding. The signing key is per-run, not a Tenkai
//! release-signing key.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::signed_bytes;

/// Signed drill evidence schema.
pub const EVIDENCE_SCHEMA: &str = "tenkai.hub-ha-qualification.v1";
/// Prefix of every [`EVIDENCE_SCHEMA`] signed message.
pub const SIGNING_DOMAIN: &[u8] = b"TENKAI-HUB-HA-QUALIFICATION-V1\0";
const SIGNATURE_LABEL: &str = "hub HA qualification signature";

/// Signed qualification evidence as written by the drill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// `tenkai.hub-ha-qualification.v1`.
    pub schema: String,
    /// `sha256:` and the lowercase hex SHA-256 of the signer's Ed25519 public key.
    pub key_id: String,
    /// Standard padded base64 of the statement JSON bytes that were signed.
    pub statement: String,
    /// Standard padded base64 Ed25519 signature over
    /// `TENKAI-HUB-HA-QUALIFICATION-V1`, one NUL byte, and the statement bytes.
    pub signature: String,
}

/// What a drill signs ([`EVIDENCE_SCHEMA`]). A verifier ignores fields it
/// does not know; the signature still covers them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub passed: bool,
    pub environments: Vec<String>,
    pub takeover_ms: i64,
    pub takeover_bound_ms: i64,
    pub receipts_once: bool,
    /// Replica processes were replaced on the same store and the drill
    /// passed again. This is current-binary restart, not a previous-release
    /// host.
    pub restart_repeat: bool,
    pub fence_required: bool,
}

/// Ed25519 public key for a 32-byte seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign `statement` with a 32-byte Ed25519 seed.
pub fn sign(seed: &[u8; 32], statement: &Statement) -> Result<Evidence> {
    let signing_key = SigningKey::from_bytes(seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let signed = signed_bytes::sign(SIGNING_DOMAIN, statement, |message| {
        Ok(signing_key.sign(message).to_bytes().to_vec())
    })?;
    Ok(Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&public_key),
        statement: signed.statement,
        signature: STANDARD.encode(signed.signature),
    })
}

/// Check the signature against the signer's public key and return the statement.
pub fn verify(evidence: &Evidence, public_key: &[u8; 32]) -> Result<Statement> {
    if evidence.schema != EVIDENCE_SCHEMA {
        bail!(
            "unsupported hub HA qualification schema {:?}; this release verifies {EVIDENCE_SCHEMA}",
            evidence.schema
        );
    }
    if evidence.key_id != crate::signature_verification::key_id(public_key) {
        bail!("hub HA qualification key_id does not match the signer");
    }
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("hub HA qualification public key is invalid"))?;
    let signature =
        crate::signature_verification::decode_exact::<64>(SIGNATURE_LABEL, &evidence.signature)?;
    let verified =
        signed_bytes::verify::<Statement>(SIGNING_DOMAIN, &evidence.statement, |message| {
            crate::signature_verification::verify_strict_bytes(
                &key,
                SIGNATURE_LABEL,
                &signature,
                message,
            )
            .is_ok()
        })
        .map_err(|refusal| anyhow::anyhow!("hub HA qualification refused: {refusal}"))?;
    Ok(verified.statement)
}

/// Parse and verify a JSON evidence file.
pub fn verify_file(path: &std::path::Path, public_key: &[u8; 32]) -> Result<Statement> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let evidence: Evidence = serde_json::from_slice(&bytes)
        .context("hub HA qualification evidence is not valid JSON")?;
    verify(&evidence, public_key)
}

/// 64 lowercase hex characters of an Ed25519 public key.
pub fn parse_public_key_hex(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("hub HA qualification public key must be 64 hexadecimal characters");
    }
    let mut key = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        key[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
            .map_err(|_| anyhow::anyhow!("hub HA qualification public key is not hex"))?;
    }
    Ok(key)
}

/// Lowercase hex of an Ed25519 public key.
pub fn public_key_hex(public_key: &[u8; 32]) -> String {
    public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> Statement {
        Statement {
            passed: true,
            environments: vec!["env-a".into(), "env-b".into()],
            takeover_ms: 400,
            takeover_bound_ms: 3700,
            receipts_once: true,
            restart_repeat: true,
            fence_required: true,
        }
    }

    #[test]
    fn signed_evidence_verifies_offline() {
        let seed = [9u8; 32];
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let evidence = sign(&seed, &statement()).unwrap();
        let got = verify(&evidence, &public_key).unwrap();
        assert_eq!(got, statement());
        assert_eq!(evidence.schema, EVIDENCE_SCHEMA);
    }

    #[test]
    fn tampered_statement_is_refused() {
        let seed = [9u8; 32];
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let mut evidence = sign(&seed, &statement()).unwrap();
        let mut bytes = STANDARD.decode(&evidence.statement).unwrap();
        bytes[0] ^= 1;
        evidence.statement = STANDARD.encode(bytes);
        let error = verify(&evidence, &public_key).unwrap_err().to_string();
        assert!(error.contains("refused"), "{error}");
    }

    #[test]
    fn verify_file_round_trip() {
        let seed = [11u8; 32];
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let evidence = sign(&seed, &statement()).unwrap();
        let path = std::env::temp_dir().join(format!(
            "tenkai-hub-ha-{}-{}.json",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::write(&path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
        let got = verify_file(&path, &public_key).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(got, statement());
    }

    #[test]
    fn verify_named_evidence() {
        let Ok(path) = std::env::var("TENKAI_HA_DRILL_EVIDENCE") else {
            return;
        };
        let Ok(hex) = std::env::var("TENKAI_HA_DRILL_PUBKEY") else {
            panic!("TENKAI_HA_DRILL_PUBKEY is required to verify {path}");
        };
        let key = parse_public_key_hex(&hex).unwrap();
        let statement = verify_file(path.as_ref(), &key).unwrap();
        assert!(statement.passed, "{statement:?}");
        assert!(statement.receipts_once, "{statement:?}");
        assert!(statement.restart_repeat, "{statement:?}");
        assert!(statement.fence_required, "{statement:?}");
        assert!(
            statement.takeover_ms <= statement.takeover_bound_ms,
            "{statement:?}"
        );
    }
}
