//! Statements signed over the exact bytes their signer sent (#849).
//!
//! A signer serializes its statement once and sends those bytes as base64
//! (standard alphabet, padded). The signature covers `domain || bytes`,
//! where the domain names the schema and ends in NUL. A verifier checks the
//! signature over the received bytes and only then parses them, so neither
//! side's JSON encoder is part of the contract, and a field the verifier
//! does not know is still covered by the signature. The digest of a
//! statement is `sha256:<hex>` of the bytes as sent.
//!
//! The signature algorithm and its encoding belong to the caller.

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};

/// A statement as sent: its base64 bytes and the raw signature over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub statement: String,
    pub signature: Vec<u8>,
}

/// A statement whose signature verified over its received bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T> {
    pub statement: T,
    /// `sha256:<hex>` of the statement bytes as sent.
    pub digest: String,
}

/// Why a signed statement was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the statement is not base64")]
    Encoding,
    #[error("the signature does not verify over the statement bytes")]
    Signature,
    #[error("the signed statement does not parse: {0}")]
    Parse(String),
}

fn message(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    [domain, bytes].concat()
}

/// Serialize `statement` once and sign `domain || bytes` with `sign`.
pub fn sign<T: Serialize>(
    domain: &[u8],
    statement: &T,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<Signed> {
    let bytes = serde_json::to_vec(statement)?;
    let signature = sign(&message(domain, &bytes))?;
    Ok(Signed {
        statement: STANDARD.encode(&bytes),
        signature,
    })
}

/// Decode the base64 `statement`, check `verify` over `domain || bytes`,
/// and parse the bytes only once it holds.
pub fn verify<T: DeserializeOwned>(
    domain: &[u8],
    statement: &str,
    verify: impl FnOnce(&[u8]) -> bool,
) -> Result<Verified<T>, Refusal> {
    let bytes = STANDARD.decode(statement).map_err(|_| Refusal::Encoding)?;
    if !verify(&message(domain, &bytes)) {
        return Err(Refusal::Signature);
    }
    let statement =
        serde_json::from_slice(&bytes).map_err(|error| Refusal::Parse(error.to_string()))?;
    Ok(Verified {
        statement,
        digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &[u8] = b"TENKAI-TEST-V1\0";

    /// Signing and verifying with a keyed check of the message: the parsed
    /// statement and digest come from the bytes sent, and changing a byte
    /// of the statement or the domain fails before anything is parsed.
    #[test]
    fn the_signature_covers_the_bytes_sent() {
        let sent = sign(DOMAIN, &serde_json::json!({"a": 1}), |message| {
            Ok(Sha256::digest(message).to_vec())
        })
        .unwrap();
        let check =
            |signature: Vec<u8>| move |message: &[u8]| *Sha256::digest(message) == *signature;
        let verified: Verified<serde_json::Value> =
            verify(DOMAIN, &sent.statement, check(sent.signature.clone())).unwrap();
        assert_eq!(verified.statement, serde_json::json!({"a": 1}));
        assert_eq!(
            verified.digest,
            format!("sha256:{:x}", Sha256::digest(br#"{"a":1}"#))
        );
        // Same JSON value, other bytes: the signature does not carry over.
        let reencoded = STANDARD.encode(br#"{ "a": 1 }"#);
        assert_eq!(
            verify::<serde_json::Value>(DOMAIN, &reencoded, check(sent.signature.clone())),
            Err(Refusal::Signature)
        );
        assert_eq!(
            verify::<serde_json::Value>(
                b"TENKAI-OTHER-V1\0",
                &sent.statement,
                check(sent.signature.clone())
            ),
            Err(Refusal::Signature)
        );
        assert_eq!(
            verify::<serde_json::Value>(DOMAIN, "not base64!", |_| true),
            Err(Refusal::Encoding)
        );
        // Verified bytes that are not the expected statement are refused.
        let refusal = verify::<u32>(DOMAIN, &sent.statement, check(sent.signature)).unwrap_err();
        assert!(matches!(refusal, Refusal::Parse(_)), "{refusal}");
    }
}
