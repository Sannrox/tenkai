//! Environment-runtime HPKE sealing keys (ADR 0045).
//!
//! DHKEM(P-256, HKDF-SHA256) public keys are uncompressed SEC1 points. The
//! private key never leaves the runtime. Hardware-backed runner keys (#675)
//! generate the sealing key in the same PKCS#11 token.

use std::path::Path;

use anyhow::{Context as _, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rcgen::PublicKeyData as _;
use sha2::{Digest as _, Sha256};

use crate::runner_key::HardwareStore;

/// File name of a file sealing key, beside the runner key.
pub const SEALING_KEY: &str = "sealing-key.pem";

/// Capability a runtime advertises once it has sent a sealing public key.
pub const SEALED_SECRETS_CAPABILITY: &str = "sealed_secrets";

/// An HPKE P-256 public key the server records and the client pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealingPublicKey {
    /// Uncompressed P-256 point (65 bytes, starts with `0x04`).
    pub point: Vec<u8>,
}

impl SealingPublicKey {
    /// Decode a standard-base64 DHKEM(P-256) public key.
    pub fn from_wire(value: &str) -> Result<Self> {
        let point = STANDARD
            .decode(value.trim())
            .context("the sealing public key is not standard base64")?;
        Self::from_point(point)
    }

    pub fn from_point(point: Vec<u8>) -> Result<Self> {
        anyhow::ensure!(
            point.len() == 65 && point[0] == 0x04,
            "the sealing public key is not an uncompressed P-256 point"
        );
        // RFC 9180 DeserializePublicKey: the SEC1 point must be on the curve.
        let peer = ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P256, &point);
        let ephemeral = ring::agreement::EphemeralPrivateKey::generate(
            &ring::agreement::ECDH_P256,
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|_| anyhow::anyhow!("checking the sealing public key"))?;
        ring::agreement::agree_ephemeral(ephemeral, &peer, |_| ())
            .map_err(|_| anyhow::anyhow!("the sealing public key is not a valid P-256 point"))?;
        Ok(Self { point })
    }

    pub fn to_wire(&self) -> String {
        STANDARD.encode(&self.point)
    }

    /// `sha256:<hex>` of the HPKE-serialized public key.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.point)
    }
}

pub fn fingerprint(point: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(point))
}

/// A runtime sealing key: file PKCS#8, or a hardware public point whose
/// private half never leaves the token.
#[derive(Debug, Clone)]
pub struct SealingKey {
    public: SealingPublicKey,
    hardware_backed: bool,
}

impl SealingKey {
    pub fn public(&self) -> &SealingPublicKey {
        &self.public
    }

    pub fn hardware_backed(&self) -> bool {
        self.hardware_backed
    }

    pub fn fingerprint(&self) -> String {
        self.public.fingerprint()
    }

    pub fn to_wire(&self) -> String {
        self.public.to_wire()
    }

    /// The key in `dir`, generating one according to the runner key store.
    /// A hardware runner locator (`key.store`) generates the sealing key in
    /// the same token; otherwise a file key is created owner-only. First
    /// provision follows [`HardwareStore::from_env`].
    pub fn open_or_generate(dir: &Path) -> Result<Self> {
        if let Some(store) = HardwareStore::from_dir(dir)? {
            return Self::from_hardware(&store);
        }
        if dir.join(crate::runner_key::RUNNER_KEY).exists() {
            return Self::open_or_generate_file(dir);
        }
        if let Some(store) = HardwareStore::from_env()? {
            return Self::from_hardware(&store);
        }
        Self::open_or_generate_file(dir)
    }

    fn from_hardware(store: &HardwareStore) -> Result<Self> {
        let point = store.open_or_generate_sealing_point()?;
        Ok(Self {
            public: SealingPublicKey::from_point(point)?,
            hardware_backed: true,
        })
    }

    fn open_or_generate_file(dir: &Path) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(SEALING_KEY);
        if path.exists() {
            return Self::open_file(&path);
        }
        let key = rcgen::KeyPair::generate()?;
        write_owner_only(&path, &key.serialize_pem())?;
        Ok(Self {
            public: public_from_key_pair(&key)?,
            hardware_backed: false,
        })
    }

    fn open_file(path: &Path) -> Result<Self> {
        let pem =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let key = rcgen::KeyPair::from_pem(&pem).context("reading the sealing key")?;
        Ok(Self {
            public: public_from_key_pair(&key)?,
            hardware_backed: false,
        })
    }
}

fn public_from_key_pair(key: &rcgen::KeyPair) -> Result<SealingPublicKey> {
    use x509_parser::prelude::FromDer as _;
    let spki = key.subject_public_key_info();
    let (_, parsed) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki.as_ref())
        .map_err(|error| anyhow::anyhow!("parsing the sealing public key: {error}"))?;
    SealingPublicKey::from_point(parsed.subject_public_key.data.to_vec())
}

/// Parse a sealing public key offered at enrollment or renewal. Empty is
/// absent (an older runtime).
pub fn parse_offered(value: Option<&str>) -> Result<Option<SealingPublicKey>> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(None),
        Some(value) => Ok(Some(SealingPublicKey::from_wire(value)?)),
    }
}

pub fn normalize_fingerprint(value: &str) -> Result<String> {
    let value = value.trim();
    let hex = value
        .strip_prefix("sha256:")
        .unwrap_or(value)
        .to_ascii_lowercase();
    anyhow::ensure!(
        hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "recipient fingerprint must be sha256:<64 hex chars>"
    );
    Ok(format!("sha256:{hex}"))
}

fn write_owner_only(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4().simple()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    let written = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::hard_link(&temporary, path));
    let _ = std::fs::remove_file(&temporary);
    written.with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-sealing-key-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn file_key_round_trips_and_keeps_its_fingerprint() {
        let dir = temp_dir();
        let generated = SealingKey::open_or_generate(&dir).unwrap();
        assert!(!generated.hardware_backed());
        assert_eq!(generated.public().point.len(), 65);
        assert_eq!(generated.public().point[0], 0x04);
        let wire = generated.to_wire();
        let parsed = SealingPublicKey::from_wire(&wire).unwrap();
        assert_eq!(parsed.fingerprint(), generated.fingerprint());
        let reopened = SealingKey::open_or_generate(&dir).unwrap();
        assert_eq!(reopened.fingerprint(), generated.fingerprint());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_wire_form_is_refused() {
        assert!(SealingPublicKey::from_wire("not-base64!").is_err());
        let short = STANDARD.encode([0x04, 0x01]);
        assert!(SealingPublicKey::from_wire(&short).is_err());
        let off_curve = STANDARD.encode({
            let mut point = [0x04_u8; 65];
            point[1..].fill(0);
            point
        });
        assert!(SealingPublicKey::from_wire(&off_curve).is_err());
    }

    #[test]
    fn fingerprint_normalization_requires_sha256_hex() {
        let fp = fingerprint(&[0x04; 65]);
        assert_eq!(normalize_fingerprint(&fp).unwrap(), fp);
        assert_eq!(
            normalize_fingerprint(fp.strip_prefix("sha256:").unwrap()).unwrap(),
            fp
        );
        assert!(normalize_fingerprint("sha256:abcd").is_err());
    }
}
