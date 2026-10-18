//! Signed offline key revocation ([ADR 0036](../docs/decisions/0036-offline-key-revocation.md)).
//!
//! A revocation authority signs a `tenkai.key-revocations.v1` list of key ids.
//! The list travels as a file or as the `trust/key-revocations.json` entry of
//! an offline bundle, and no online check is involved. Once installed, every
//! signature verification that resolves a signer through
//! [`crate::signature_verification::trusted_key`] refuses a revoked key:
//! releases, offline bundles, plan approvals, package-migration approvals,
//! model evaluation evidence, and host preflight. Trust-root files that still list a revoked key keep
//! loading, so rollover can remove it later without downtime.
//!
//! Lists carry a sequence. A newer list must have a higher sequence and must
//! keep every key the installed list revokes, so a replayed or edited older
//! list cannot un-revoke a key.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::release_signing::TrustRoots;

pub const REVOCATIONS_SCHEMA: &str = "tenkai.key-revocations.v1";
/// Path of a revocation list inside an offline bundle.
pub const BUNDLE_ENTRY: &str = "trust/key-revocations.json";
/// Installed list, read at process start and replaced by imports.
pub const REVOCATIONS_ENV: &str = "TENKAI_KEY_REVOCATIONS";
/// Release-format trust roots naming the revocation authorities.
pub const REVOCATION_TRUST_ROOTS_ENV: &str = "TENKAI_KEY_REVOCATION_TRUST_ROOTS";
const SIGNING_DOMAIN: &[u8] = b"TENKAI-KEY-REVOCATIONS-V1\0";
const MAX_REVOKED: usize = 4_096;

/// Key ids revoked in this process. Lookups never fail open: a poisoned lock
/// still answers from the data it holds.
static REVOKED: RwLock<BTreeSet<String>> = RwLock::new(BTreeSet::new());

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedKey {
    pub key_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationStatement {
    pub sequence: u64,
    pub issued_at: i64,
    pub revoked: Vec<RevokedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationList {
    pub schema: String,
    pub key_id: String,
    pub statement: RevocationStatement,
    pub signature: String,
}

fn canonical_bytes(statement: &RevocationStatement) -> Result<Vec<u8>> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, statement)?;
    Ok(bytes)
}

/// Whether `key_id` is revoked in this process.
pub fn is_revoked(key_id: &str) -> bool {
    REVOKED
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(key_id)
}

/// Sign a list with the 32-byte Ed25519 seed at `seed_path` (mode 0600).
pub fn sign(statement: RevocationStatement, seed_path: &Path) -> Result<RevocationList> {
    let signing_key = SigningKey::from_bytes(&crate::approval_policy::load_signer_seed(seed_path)?);
    let list = RevocationList {
        schema: REVOCATIONS_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&signing_key.verifying_key().to_bytes()),
        signature: STANDARD.encode(signing_key.sign(&canonical_bytes(&statement)?).to_bytes()),
        statement,
    };
    list.validate_shape()?;
    Ok(list)
}

impl RevocationList {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)
            .with_context(|| format!("reading key revocations {}", path.display()))?;
        serde_json::from_slice(&raw)
            .with_context(|| format!("parsing key revocations {}", path.display()))
    }

    pub fn revoked_ids(&self) -> BTreeSet<String> {
        self.statement
            .revoked
            .iter()
            .map(|revoked| revoked.key_id.clone())
            .collect()
    }

    fn validate_shape(&self) -> Result<()> {
        if self.schema != REVOCATIONS_SCHEMA {
            bail!("unsupported key revocation schema {}", self.schema);
        }
        if self.statement.revoked.len() > MAX_REVOKED {
            bail!("key revocation list exceeds {MAX_REVOKED} keys");
        }
        let mut seen = BTreeSet::new();
        for revoked in &self.statement.revoked {
            crate::signature_verification::validate_key_id("revoked key id", &revoked.key_id)?;
            if revoked.reason.trim().is_empty() || revoked.reason.chars().any(char::is_control) {
                bail!("revocation of {} needs a reason", revoked.key_id);
            }
            if !seen.insert(&revoked.key_id) {
                bail!("key revocation list names {} twice", revoked.key_id);
            }
        }
        if seen.contains(&self.key_id) {
            bail!("a revocation authority cannot revoke its own signing key");
        }
        Ok(())
    }

    /// Check the shape and the signature against the revocation authorities.
    pub fn verify(&self, authorities: &TrustRoots) -> Result<()> {
        self.validate_shape()?;
        let signer = authorities.resolve(&self.key_id)?;
        crate::signature_verification::verify_strict(
            &signer.verifying_key,
            "key revocation signature",
            &self.signature,
            &canonical_bytes(&self.statement)?,
        )
    }
}

/// Verify `list`, check it supersedes the list installed at `installed`, write
/// it there atomically, and apply it to this process. The check and the
/// replacement hold an exclusive lock on `<installed>.lock`, so concurrent
/// imports cannot roll a newer list back.
pub fn install(list: &RevocationList, authorities: &TrustRoots, installed: &Path) -> Result<()> {
    list.verify(authorities)?;
    let lock = installed.with_extension("lock");
    crate::fenced_mutation::with_mutation_lock_authorized(
        &lock,
        || Ok(()),
        || replace_installed(list, installed),
    )?
}

fn replace_installed(list: &RevocationList, installed: &Path) -> Result<()> {
    if installed.exists() {
        let current = RevocationList::load(installed)?;
        if list.statement.sequence <= current.statement.sequence {
            bail!(
                "key revocation sequence {} does not supersede installed sequence {}",
                list.statement.sequence,
                current.statement.sequence
            );
        }
        let dropped: Vec<String> = current
            .revoked_ids()
            .difference(&list.revoked_ids())
            .cloned()
            .collect();
        if !dropped.is_empty() {
            bail!(
                "key revocation list would un-revoke {}; a newer list must keep every revoked key",
                dropped.join(", ")
            );
        }
    }
    let staged = installed.with_extension(format!(
        "{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&staged, serde_json::to_vec_pretty(list)?)
        .with_context(|| format!("writing key revocations {}", staged.display()))?;
    std::fs::rename(&staged, installed)
        .with_context(|| format!("installing key revocations {}", installed.display()))?;
    apply(list);
    Ok(())
}

fn apply(list: &RevocationList) {
    REVOKED
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .extend(list.revoked_ids());
}

/// Revocation configuration from the environment: the installed list path
/// and the authority trust roots. Both or neither must be set.
pub fn configured() -> Result<Option<(PathBuf, TrustRoots)>> {
    let installed = std::env::var_os(REVOCATIONS_ENV).map(PathBuf::from);
    let roots = std::env::var_os(REVOCATION_TRUST_ROOTS_ENV).map(PathBuf::from);
    match (installed, roots) {
        (None, None) => Ok(None),
        (Some(installed), Some(roots)) => Ok(Some((installed, TrustRoots::load(&roots)?))),
        _ => bail!("{REVOCATIONS_ENV} and {REVOCATION_TRUST_ROOTS_ENV} must be set together"),
    }
}

/// At process start: verify and apply the installed list, if configured.
/// A configured list that is missing applies nothing; one that fails to
/// verify stops the process.
pub fn load_configured() -> Result<()> {
    let Some((installed, authorities)) = configured()? else {
        return Ok(());
    };
    if !installed.exists() {
        return Ok(());
    }
    let list = RevocationList::load(&installed)?;
    list.verify(&authorities).with_context(|| {
        format!(
            "verifying installed key revocations {}",
            installed.display()
        )
    })?;
    apply(&list);
    Ok(())
}

/// Install the revocation list an offline bundle carries, before the bundle
/// itself is verified, so a bundle signed by a key it revokes is refused.
/// The list is authenticated by its own signature. Returns whether one was
/// installed.
pub fn import_from_bundle(bundle: &crate::offline_bundle::BundleEnvelope) -> Result<bool> {
    let Some(entry) = bundle
        .entries
        .iter()
        .find(|entry| entry.path == BUNDLE_ENTRY)
    else {
        return Ok(false);
    };
    let Some((installed, authorities)) = configured()? else {
        bail!(
            "offline bundle carries key revocations, but {REVOCATIONS_ENV} and {REVOCATION_TRUST_ROOTS_ENV} are not set"
        );
    };
    let raw = STANDARD
        .decode(&entry.content_base64)
        .context("decoding bundled key revocations")?;
    let list: RevocationList =
        serde_json::from_slice(&raw).context("parsing bundled key revocations")?;
    if installed.exists() {
        let current = RevocationList::load(&installed)?;
        // An older or equal list is covered by the installed one, which keeps
        // every key it revokes. Keep the installed list and go on without
        // needing the older list's authority, which may be retired.
        if list.statement.sequence <= current.statement.sequence {
            current.verify(&authorities)?;
            apply(&current);
            return Ok(false);
        }
    }
    install(&list, &authorities, &installed)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_bundle::{BundleEnvelope, BundleStatement};
    use crate::release_signing::TrustedSigner;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;

    // Seeds unique to these tests: revocation is process-wide.
    const OLD: [u8; 32] = [201; 32];
    const NEW: [u8; 32] = [202; 32];
    const AUTHORITY: [u8; 32] = [203; 32];

    fn signer(seed: &[u8; 32], identity: &str) -> TrustedSigner {
        let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        TrustedSigner {
            key_id: crate::signature_verification::key_id(&public),
            identity: identity.into(),
            public_key: STANDARD.encode(public),
        }
    }

    fn key_id(seed: &[u8; 32]) -> String {
        signer(seed, "x").key_id
    }

    fn roots(signers: Vec<TrustedSigner>) -> TrustRoots {
        TrustRoots {
            version: 1,
            signers,
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-revocation-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn seed_file(dir: &Path, seed: &[u8; 32]) -> PathBuf {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let path = dir.join(format!("{}.ed25519", seed[0]));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(seed).unwrap();
        path
    }

    fn bundle(exporter: &[u8; 32], identity: &str) -> BundleEnvelope {
        let plan = b"{\"plan\":\"p1\"}".to_vec();
        let approval = b"{\"approval\":\"p1\"}".to_vec();
        let digest = |bytes: &[u8]| format!("sha256:{:x}", Sha256::digest(bytes));
        let mut payloads = BTreeMap::new();
        payloads.insert(
            "releases/app-1/payload.bin".to_string(),
            ("application/octet-stream".to_string(), b"app".to_vec()),
        );
        payloads.insert(
            "plans/p1.json".to_string(),
            ("application/json".to_string(), plan.clone()),
        );
        payloads.insert(
            "approvals/p1.json".to_string(),
            ("application/json".to_string(), approval.clone()),
        );
        BundleEnvelope::create(
            BundleStatement {
                tenant_id: "tenant-1".into(),
                environment_id: "site-1".into(),
                plan_id: "p1".into(),
                plan_digest: digest(&plan),
                approval_digest: digest(&approval),
                release_ids: vec!["app-1".into()],
                exporter_identity: identity.into(),
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 10_000,
                entries: Vec::new(),
            },
            payloads,
            &SigningKey::from_bytes(exporter),
        )
        .unwrap()
    }

    fn list(dir: &Path, sequence: u64, revoked: &[&[u8; 32]]) -> RevocationList {
        sign(
            RevocationStatement {
                sequence,
                issued_at: 1,
                revoked: revoked
                    .iter()
                    .map(|seed| RevokedKey {
                        key_id: key_id(seed),
                        reason: "rolled over".into(),
                    })
                    .collect(),
            },
            &dir.join(format!("{}.ed25519", AUTHORITY[0])),
        )
        .unwrap()
    }

    /// Offline rollover without downtime: overlap old and new exporter keys,
    /// move signing to the new key, revoke the old one. Trust roots that still
    /// list the old key keep loading; only its artifacts are refused.
    #[test]
    fn rollover_rehearsal_refuses_only_the_revoked_key() {
        let dir = temp_dir();
        seed_file(&dir, &AUTHORITY);
        let authorities = roots(vec![signer(&AUTHORITY, "revocation-authority")]);
        let overlap = roots(vec![
            signer(&OLD, "exporter-old"),
            signer(&NEW, "exporter-new"),
        ]);
        let old_bundle = bundle(&OLD, "exporter-old");
        let new_bundle = bundle(&NEW, "exporter-new");
        old_bundle
            .verify(&overlap, "tenant-1", "site-1", 2_000)
            .unwrap();
        new_bundle
            .verify(&overlap, "tenant-1", "site-1", 2_000)
            .unwrap();

        let installed = dir.join("key-revocations.json");
        install(&list(&dir, 1, &[&OLD]), &authorities, &installed).unwrap();

        overlap.validate().unwrap();
        let error = old_bundle
            .verify(&overlap, "tenant-1", "site-1", 2_000)
            .unwrap_err();
        assert!(format!("{error:#}").contains("is revoked"), "{error:#}");
        new_bundle
            .verify(&overlap, "tenant-1", "site-1", 2_000)
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn installs_only_newer_superset_lists_from_an_authority() {
        // Own seeds: this test revokes keys in the process-wide set.
        const OLD: [u8; 32] = [204; 32];
        const NEW: [u8; 32] = [205; 32];
        let dir = temp_dir();
        seed_file(&dir, &AUTHORITY);
        let authorities = roots(vec![signer(&AUTHORITY, "revocation-authority")]);
        let installed = dir.join("key-revocations.json");
        install(&list(&dir, 5, &[&OLD]), &authorities, &installed).unwrap();

        let replay = install(&list(&dir, 5, &[&OLD, &NEW]), &authorities, &installed);
        assert!(format!("{:#}", replay.unwrap_err()).contains("does not supersede"));
        let dropped = install(&list(&dir, 6, &[&NEW]), &authorities, &installed);
        assert!(format!("{:#}", dropped.unwrap_err()).contains("un-revoke"));

        let mut forged = list(&dir, 7, &[&OLD, &NEW]);
        forged.statement.sequence = 8;
        assert!(install(&forged, &authorities, &installed).is_err());
        let untrusted = roots(vec![signer(&NEW, "someone-else")]);
        assert!(list(&dir, 9, &[&OLD]).verify(&untrusted).is_err());

        let self_revoking = sign(
            RevocationStatement {
                sequence: 10,
                issued_at: 1,
                revoked: vec![RevokedKey {
                    key_id: key_id(&AUTHORITY),
                    reason: "oops".into(),
                }],
            },
            &dir.join(format!("{}.ed25519", AUTHORITY[0])),
        );
        assert!(self_revoking.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
