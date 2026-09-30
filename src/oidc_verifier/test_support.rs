//! Test-only ES256 signer and JWKS helpers shared with server tests.

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};

pub(crate) fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// ES256 signing key generated per test run; no private key in the repository.
pub(crate) struct Signer {
    kid: String,
    key: EcdsaKeyPair,
}

impl Signer {
    pub(crate) fn new(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        Self {
            kid: kid.into(),
            key,
        }
    }

    pub(crate) fn jwk(&self) -> serde_json::Value {
        let point = self.key.public_key().as_ref();
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": self.kid,
            "x": b64(&point[1..33]), "y": b64(&point[33..65]),
        })
    }

    pub(crate) fn sign_with_header(
        &self,
        header: serde_json::Value,
        claims: &serde_json::Value,
    ) -> Vec<u8> {
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let signature = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", b64(signature.as_ref())).into_bytes()
    }

    pub(crate) fn sign(&self, claims: &serde_json::Value) -> Vec<u8> {
        self.sign_with_header(
            serde_json::json!({"alg": "ES256", "kid": self.kid, "typ": "at+jwt"}),
            claims,
        )
    }
}

pub(crate) fn jwks(signers: &[&Signer]) -> String {
    serde_json::json!({"keys": signers.iter().map(|s| s.jwk()).collect::<Vec<_>>()}).to_string()
}
