//! Runtime agent enrollment tokens and credentials (#630).
//!
//! An operator issues a short-lived, single-use enrollment token for one
//! environment. The agent exchanges it once for its own credential and keeps
//! that. Both are random 256-bit secrets with a type prefix; Tenkai stores
//! only their SHA-256 digests, and a credential's digest is the id it is
//! revoked by.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom as _, SystemRandom};
use sha2::{Digest as _, Sha256};

pub const ENROLLMENT_TOKEN_PREFIX: &str = "tke_";
pub const CREDENTIAL_PREFIX: &str = "tkr_";
pub const DEFAULT_ENROLLMENT_TTL_SECONDS: u64 = 15 * 60;
pub const MAX_ENROLLMENT_TTL_SECONDS: u64 = 24 * 60 * 60;

/// A new secret with `prefix`.
pub fn mint(prefix: &str) -> anyhow::Result<String> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("no secure randomness for a runtime secret"))?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// `sha256:<hex>` of `secret`: what is stored, and a credential's id.
pub fn digest(secret: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(secret.as_bytes()))
}

/// The marker of an environment a runtime was enrolled for.
fn marker_id(environment: &str) -> String {
    format!("tenkai:runtime-enrollment:{environment}")
}

/// Mark `environment` runtime-managed for good, before its first enrollment
/// exists. Create-once, so a concurrent write never loses it.
pub async fn mark_runtime_managed(
    ctx: &mut crate::client::Ctx,
    environment: &str,
) -> anyhow::Result<()> {
    let now = crate::now_millis();
    let marker = crate::pb::sekai::Object {
        id: marker_id(environment),
        kind: crate::ontology::KIND_RUNTIME_ENROLLMENT.into(),
        name: format!("{environment} runtime enrollment"),
        namespace: crate::ontology::NS.into(),
        external_id: String::new(),
        properties: std::collections::HashMap::from([("environment".into(), environment.into())]),
        created: now,
        updated: now,
    };
    match ctx.create_once(marker).await {
        Ok(_) => Ok(()),
        Err(status) if crate::client::is_unique_conflict(&status) => Ok(()),
        Err(status) => Err(status.into()),
    }
}

/// Whether a runtime was ever enrolled for `environment`: then only that
/// runtime runs its plans, and the server never executes them.
pub async fn runtime_managed(
    ctx: &mut crate::client::Ctx,
    environment: &str,
) -> anyhow::Result<bool> {
    Ok(ctx.get(&marker_id(environment)).await?.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_prefixed_unique_and_stored_by_digest() {
        let first = mint(CREDENTIAL_PREFIX).unwrap();
        let second = mint(CREDENTIAL_PREFIX).unwrap();
        assert!(first.starts_with(CREDENTIAL_PREFIX) && first.len() == 47);
        assert_ne!(first, second);
        assert_eq!(digest(&first), digest(&first));
        assert!(!digest(&first).contains(&first[4..]));
    }
}
