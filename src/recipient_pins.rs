//! Per-environment recipient-key pins for sealed secrets (ADR 0045).
//!
//! The client seals only to fingerprints it has accepted. An unpinned key
//! the server offers is refused by fingerprint until `secret trust`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::sealing_key::{SealingPublicKey, normalize_fingerprint};

pub const PIN_SCHEMA: &str = "tenkai.recipient-pins.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedRecipient {
    pub runtime_id: String,
    pub fingerprint: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpinnedKey {
    pub fingerprint: String,
    pub runtime_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    /// Every offered key is already pinned.
    Trusted,
    /// No pins yet: first use should show fingerprints and ask.
    FirstUse { offered: Vec<OfferedRecipient> },
    /// At least one offered key is not pinned.
    Unpinned { keys: Vec<UnpinnedKey> },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinFile {
    schema: String,
    /// server URL → environment → fingerprints.
    #[serde(default)]
    servers: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
}

#[derive(Debug, Clone)]
pub struct RecipientPinStore {
    path: PathBuf,
}

impl RecipientPinStore {
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            path: config_dir.into().join("recipient-pins.json"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn pins(&self, server: &str, environment: &str) -> Result<BTreeSet<String>> {
        Ok(self
            .load()?
            .servers
            .get(server)
            .and_then(|envs| envs.get(environment))
            .cloned()
            .unwrap_or_default())
    }

    pub fn trust(&self, server: &str, environment: &str, fingerprint: &str) -> Result<String> {
        let fingerprint = normalize_fingerprint(fingerprint)?;
        let mut file = self.load()?;
        file.servers
            .entry(server.to_owned())
            .or_default()
            .entry(environment.to_owned())
            .or_default()
            .insert(fingerprint.clone());
        self.save(&file)?;
        Ok(fingerprint)
    }

    pub fn check(
        &self,
        server: &str,
        environment: &str,
        offered: &[OfferedRecipient],
    ) -> Result<PinCheck> {
        let pins = self.pins(server, environment)?;
        Ok(check_offered(&pins, offered))
    }

    fn load(&self) -> Result<PinFile> {
        match std::fs::read_to_string(&self.path) {
            Ok(raw) => {
                let file: PinFile = serde_json::from_str(&raw)
                    .with_context(|| format!("parsing {}", self.path.display()))?;
                if file.schema != PIN_SCHEMA {
                    bail!(
                        "unsupported recipient pin schema {} in {}",
                        file.schema,
                        self.path.display()
                    );
                }
                Ok(file)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PinFile {
                schema: PIN_SCHEMA.into(),
                servers: BTreeMap::new(),
            }),
            Err(error) => Err(error).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    fn save(&self, file: &PinFile) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let body = serde_json::to_vec_pretty(file)?;
        atomic_write(&self.path, &body)
    }
}

/// Classify offered keys against already-trusted fingerprints.
pub fn check_offered(pins: &BTreeSet<String>, offered: &[OfferedRecipient]) -> PinCheck {
    if pins.is_empty() {
        return PinCheck::FirstUse {
            offered: offered.to_vec(),
        };
    }
    let mut keys = Vec::new();
    for recipient in offered {
        if !pins.contains(&recipient.fingerprint) {
            keys.push(UnpinnedKey {
                fingerprint: recipient.fingerprint.clone(),
                runtime_id: recipient.runtime_id.clone(),
            });
        }
    }
    if keys.is_empty() {
        PinCheck::Trusted
    } else {
        PinCheck::Unpinned { keys }
    }
}

/// Refuse unpinned keys, naming each fingerprint. First use is also a
/// refusal so a non-interactive client never silently accepts a key.
pub fn refuse_unpinned(check: &PinCheck) -> Result<()> {
    match check {
        PinCheck::Trusted => Ok(()),
        PinCheck::FirstUse { offered } => {
            let fingerprints = offered
                .iter()
                .map(|recipient| recipient.fingerprint.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "unpinned recipient key{suffix}: {fingerprints}; accept with tenkaictl secret trust",
                suffix = if offered.len() == 1 { "" } else { "s" },
                fingerprints = if fingerprints.is_empty() {
                    "(none offered)".into()
                } else {
                    fingerprints
                }
            )
        }
        PinCheck::Unpinned { keys } => {
            let fingerprints = keys
                .iter()
                .map(|key| key.fingerprint.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "unpinned recipient key{}: {fingerprints}; accept with tenkaictl secret trust",
                if keys.len() == 1 { "" } else { "s" }
            )
        }
    }
}

pub fn offered_from_public_key(runtime_id: &str, public_key: &str) -> Result<OfferedRecipient> {
    let key = SealingPublicKey::from_wire(public_key)?;
    Ok(OfferedRecipient {
        runtime_id: runtime_id.into(),
        fingerprint: key.fingerprint(),
        public_key: key.to_wire(),
    })
}

fn atomic_write(path: &Path, body: &[u8]) -> Result<()> {
    crate::atomic_state::write_file(path, body, Some(0o600))
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-recipient-pins-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn offered(fp: &str) -> OfferedRecipient {
        OfferedRecipient {
            runtime_id: "runner-1".into(),
            fingerprint: fp.into(),
            public_key: "unused".into(),
        }
    }

    #[test]
    fn a_claimed_fingerprint_that_does_not_match_the_public_key_is_not_trusted() {
        let first = crate::sealing_key::SealingKey::open_or_generate(&temp_dir()).unwrap();
        let second = crate::sealing_key::SealingKey::open_or_generate(&temp_dir()).unwrap();
        let store = RecipientPinStore::new(temp_dir());
        store
            .trust("https://tenkai.example", "prod", &first.fingerprint())
            .unwrap();
        let swapped = offered_from_public_key("runner-1", &second.to_wire()).unwrap();
        assert_ne!(swapped.fingerprint, first.fingerprint());
        let check = store
            .check("https://tenkai.example", "prod", &[swapped])
            .unwrap();
        let error = refuse_unpinned(&check).unwrap_err().to_string();
        assert!(error.contains(&second.fingerprint()), "{error}");
        assert!(!error.contains(&first.fingerprint()), "{error}");
    }

    #[test]
    fn unpinned_key_is_refused_by_fingerprint() {
        let fp = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let check = check_offered(
            &BTreeSet::from([
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ]),
            &[offered(fp)],
        );
        let error = refuse_unpinned(&check).unwrap_err().to_string();
        assert!(error.contains(fp), "{error}");
        assert!(error.contains("tenkaictl secret trust"), "{error}");
    }

    #[test]
    fn first_use_is_refused_until_trust() {
        let fp = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let check = check_offered(&BTreeSet::new(), &[offered(fp)]);
        assert!(matches!(check, PinCheck::FirstUse { .. }));
        let error = refuse_unpinned(&check).unwrap_err().to_string();
        assert!(error.contains(fp), "{error}");
    }

    #[test]
    fn trust_pins_one_environment_on_one_server() {
        let dir = temp_dir();
        let store = RecipientPinStore::new(&dir);
        let fp = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        store.trust("https://tenkai.example", "prod", fp).unwrap();
        let check = store
            .check("https://tenkai.example", "prod", &[offered(fp)])
            .unwrap();
        assert_eq!(check, PinCheck::Trusted);
        let other = store
            .check("https://tenkai.example", "stage", &[offered(fp)])
            .unwrap();
        assert!(matches!(other, PinCheck::FirstUse { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
