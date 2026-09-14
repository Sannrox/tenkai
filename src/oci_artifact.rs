//! Digest-bound OCI artifact references (discussion #385 / #375).
//!
//! A release names artifacts by content digest. The catalog is not a registry.
//! A registry is not a second catalog. Pull uses the environment mirror only.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const ARTIFACT_REF_SCHEMA: &str = "tenkai.oci_artifact.v1";
pub const MIRROR_PROPERTY_PREFIX: &str = "artifact_mirror.";
pub const LAYER_ENTRY_PREFIX: &str = "oci-layers/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciArtifactRef {
    pub registry: String,
    pub repository: String,
    pub digest: String,
    pub media_type: String,
}

pub fn validate_registry_host(label: &str, host: &str) -> Result<()> {
    if host.is_empty()
        || host.contains('/')
        || host.contains('\\')
        || host.contains("://")
        || host.contains('@')
        || host
            .split('.')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("{label} {host:?} must be a host name without scheme or credentials");
    }
    Ok(())
}

impl OciArtifactRef {
    pub fn validate(&self) -> Result<()> {
        validate_registry_host("artifact registry", &self.registry)?;
        if self.repository.is_empty()
            || self.repository.starts_with('/')
            || self.repository.contains("..")
        {
            bail!(
                "artifact repository {:?} must be a relative repository path",
                self.repository
            );
        }
        crate::signature_verification::validate_prefixed_digest("artifact digest", &self.digest)?;
        if self.media_type.is_empty() || self.media_type.chars().any(char::is_control) {
            bail!("artifact media type must be a non-empty media type");
        }
        Ok(())
    }

    pub fn identity_key(&self) -> String {
        format!(
            "{}/{}/{}@{}",
            self.registry, self.repository, self.media_type, self.digest
        )
    }

    pub fn layer_entry_path(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "{LAYER_ENTRY_PREFIX}{}",
            self.digest.replace(':', "-")
        ))
    }
}

/// Verify and pull digest-bound artifacts. Implementors own transport.
pub trait ArtifactRegistry: Send + Sync {
    fn verify(&self, reference: &OciArtifactRef) -> Result<OciArtifactRef>;
    fn fetch(&self, reference: &OciArtifactRef) -> Result<Vec<u8>>;
    fn store(&self, reference: &OciArtifactRef, bytes: Vec<u8>) -> Result<()>;
}

/// In-memory registry for deterministic tests.
#[derive(Default)]
pub struct MemoryArtifactRegistry {
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryArtifactRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, reference: &OciArtifactRef, bytes: Vec<u8>) -> Result<()> {
        reference.validate()?;
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        if digest != reference.digest {
            bail!(
                "stored artifact digest {digest} does not match declared {}",
                reference.digest
            );
        }
        self.blobs
            .lock()
            .expect("artifact registry mutex")
            .insert(reference.identity_key(), bytes);
        Ok(())
    }
}

impl ArtifactRegistry for MemoryArtifactRegistry {
    fn verify(&self, reference: &OciArtifactRef) -> Result<OciArtifactRef> {
        reference.validate()?;
        let blobs = self.blobs.lock().expect("artifact registry mutex");
        let Some(bytes) = blobs.get(&reference.identity_key()) else {
            bail!(
                "artifact digest {} is unresolvable at {}/{}",
                reference.digest,
                reference.registry,
                reference.repository
            );
        };
        let actual = format!("sha256:{:x}", Sha256::digest(bytes));
        if actual != reference.digest {
            bail!(
                "artifact digest {} does not match stored bytes {actual}",
                reference.digest
            );
        }
        Ok(reference.clone())
    }

    fn fetch(&self, reference: &OciArtifactRef) -> Result<Vec<u8>> {
        self.verify(reference)?;
        let blobs = self.blobs.lock().expect("artifact registry mutex");
        Ok(blobs
            .get(&reference.identity_key())
            .expect("verified artifact missing")
            .clone())
    }

    fn store(&self, reference: &OciArtifactRef, bytes: Vec<u8>) -> Result<()> {
        self.put(reference, bytes)
    }
}

/// Directory-backed registry selected by `TENKAI_OCI_STORE`.
pub struct FilesystemArtifactRegistry {
    root: PathBuf,
}

impl FilesystemArtifactRegistry {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn from_env() -> Result<Self> {
        let root = std::env::var("TENKAI_OCI_STORE").map_err(|_| {
            anyhow::anyhow!("TENKAI_OCI_STORE is required when a release names OCI artifacts")
        })?;
        Ok(Self::new(PathBuf::from(root)))
    }

    fn blob_path(&self, reference: &OciArtifactRef) -> PathBuf {
        self.root
            .join(&reference.registry)
            .join(&reference.repository)
            .join(reference.digest.replace(':', "-"))
    }

    pub fn put(&self, reference: &OciArtifactRef, bytes: Vec<u8>) -> Result<()> {
        reference.validate()?;
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        if digest != reference.digest {
            bail!(
                "stored artifact digest {digest} does not match declared {}",
                reference.digest
            );
        }
        let path = self.blob_path(reference);
        if path.exists() {
            let existing = std::fs::read(&path)?;
            let existing_digest = format!("sha256:{:x}", Sha256::digest(&existing));
            if existing_digest == reference.digest {
                return Ok(());
            }
            bail!(
                "artifact digest {} already exists with different bytes {existing_digest}",
                reference.digest
            );
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_file_name(format!(
            ".{}.part",
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow::anyhow!("artifact blob path is not UTF-8"))?
        ));
        if let Err(error) = std::fs::write(&tmp, &bytes) {
            let _ = std::fs::remove_file(&tmp);
            return Err(error.into());
        }
        if let Err(error) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(error.into());
        }
        Ok(())
    }
}

impl ArtifactRegistry for FilesystemArtifactRegistry {
    fn verify(&self, reference: &OciArtifactRef) -> Result<OciArtifactRef> {
        reference.validate()?;
        let path = self.blob_path(reference);
        let bytes = std::fs::read(&path).map_err(|_| {
            anyhow::anyhow!(
                "artifact digest {} is unresolvable at {}/{}",
                reference.digest,
                reference.registry,
                reference.repository
            )
        })?;
        let actual = format!("sha256:{:x}", Sha256::digest(bytes));
        if actual != reference.digest {
            bail!(
                "artifact digest {} does not match stored bytes {actual}",
                reference.digest
            );
        }
        Ok(reference.clone())
    }

    fn fetch(&self, reference: &OciArtifactRef) -> Result<Vec<u8>> {
        self.verify(reference)?;
        Ok(std::fs::read(self.blob_path(reference))?)
    }

    fn store(&self, reference: &OciArtifactRef, bytes: Vec<u8>) -> Result<()> {
        self.put(reference, bytes)
    }
}

pub fn validate_all(artifacts: &[OciArtifactRef]) -> Result<()> {
    for artifact in artifacts {
        artifact.validate()?;
    }
    Ok(())
}

pub fn bind_identity(hasher: &mut Sha256, artifacts: &[OciArtifactRef]) {
    hasher.update(ARTIFACT_REF_SCHEMA.as_bytes());
    hasher.update((artifacts.len() as u64).to_le_bytes());
    let mut ordered = artifacts.to_vec();
    ordered.sort_by_key(|left| left.identity_key());
    for artifact in ordered {
        for field in [
            artifact.registry.as_bytes(),
            artifact.repository.as_bytes(),
            artifact.digest.as_bytes(),
            artifact.media_type.as_bytes(),
        ] {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
    }
}

pub fn mirrors_from_properties(properties: &HashMap<String, String>) -> BTreeMap<String, String> {
    properties
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix(MIRROR_PROPERTY_PREFIX)
                .map(|registry| (registry.to_string(), value.clone()))
        })
        .collect()
}

/// Rewrite a reference onto the environment mirror. Origin pull is never used.
pub fn pull_reference(
    reference: &OciArtifactRef,
    mirrors: &BTreeMap<String, String>,
) -> Result<OciArtifactRef> {
    reference.validate()?;
    let Some(mirror) = mirrors.get(&reference.registry) else {
        bail!(
            "environment has no artifact mirror for registry {}; origin pull is refused",
            reference.registry
        );
    };
    validate_registry_host(
        &format!("artifact mirror for registry {}", reference.registry),
        mirror,
    )?;
    Ok(OciArtifactRef {
        registry: mirror.clone(),
        repository: reference.repository.clone(),
        digest: reference.digest.clone(),
        media_type: reference.media_type.clone(),
    })
}

pub fn verify_publication(
    artifacts: &[OciArtifactRef],
    registry: Option<&dyn ArtifactRegistry>,
) -> Result<()> {
    if artifacts.is_empty() {
        return Ok(());
    }
    validate_all(artifacts)?;
    let Some(registry) = registry else {
        bail!("live artifact registry required when a release names OCI artifacts");
    };
    for artifact in artifacts {
        registry.verify(artifact)?;
    }
    Ok(())
}

/// Admit environment-scoped pull refs. Tenkai never contacts the origin
/// registry at apply. Returned refs are the only authorized pull identity;
/// layer materialization stays with the executor and signed offline bundles.
pub fn verify_environment_pull(
    artifacts: &[OciArtifactRef],
    properties: &HashMap<String, String>,
    registry: Option<&dyn ArtifactRegistry>,
) -> Result<Vec<OciArtifactRef>> {
    if artifacts.is_empty() {
        return Ok(Vec::new());
    }
    validate_all(artifacts)?;
    let Some(registry) = registry else {
        bail!("live artifact registry required to pull digest-bound artifacts");
    };
    let mirrors = mirrors_from_properties(properties);
    let mut pulls = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let pull = pull_reference(artifact, &mirrors)?;
        let admitted = registry.verify(&pull).map_err(|error| {
            anyhow::anyhow!(
                "artifact digest {} failed mirror pull from {}: {error}",
                artifact.digest,
                pull.registry
            )
        })?;
        pulls.push(admitted);
    }
    Ok(pulls)
}

pub fn selected_registry() -> Result<Option<std::sync::Arc<dyn ArtifactRegistry>>> {
    match std::env::var("TENKAI_OCI_STORE") {
        Ok(path) if !path.is_empty() => {
            let _ = path;
            Ok(Some(std::sync::Arc::new(
                FilesystemArtifactRegistry::from_env()?,
            )))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_for(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    fn sample(registry: &str, bytes: &[u8]) -> OciArtifactRef {
        OciArtifactRef {
            registry: registry.into(),
            repository: "edge/app".into(),
            digest: digest_for(bytes),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
        }
    }

    #[test]
    fn registry_hosts_cannot_escape_the_filesystem_store() {
        let err = validate_registry_host("artifact registry", "..")
            .unwrap_err()
            .to_string();
        assert!(err.contains("host name"), "{err}");
        assert!(validate_registry_host("artifact registry", "ghcr.io").is_ok());
    }

    #[test]
    fn unresolvable_digest_fails_closed_with_digest_named() {
        let registry = MemoryArtifactRegistry::new();
        let reference = sample("ghcr.io", b"payload-a");
        let err = registry.verify(&reference).unwrap_err().to_string();
        assert!(err.contains(&reference.digest), "{err}");
        assert!(err.contains("unresolvable"), "{err}");
    }

    #[test]
    fn mismatched_bytes_are_rejected_before_put() {
        let registry = MemoryArtifactRegistry::new();
        let mut reference = sample("ghcr.io", b"payload-a");
        reference.digest = digest_for(b"payload-b");
        let err = registry
            .put(&reference, b"payload-a".to_vec())
            .unwrap_err()
            .to_string();
        assert!(err.contains(&reference.digest), "{err}");
    }

    #[test]
    fn missing_mirror_refuses_origin_pull() {
        let reference = sample("ghcr.io", b"payload-a");
        let err = pull_reference(&reference, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("ghcr.io"), "{err}");
        assert!(err.contains("origin pull is refused"), "{err}");
    }

    #[test]
    fn environment_pull_uses_mirror_only() {
        let registry = MemoryArtifactRegistry::new();
        let origin = sample("ghcr.io", b"payload-a");
        let mirrored = OciArtifactRef {
            registry: "mirror.internal".into(),
            ..origin.clone()
        };
        registry.put(&mirrored, b"payload-a".to_vec()).unwrap();
        let mut properties = HashMap::new();
        properties.insert(
            format!("{MIRROR_PROPERTY_PREFIX}ghcr.io"),
            "mirror.internal".into(),
        );
        let pulls = verify_environment_pull(&[origin], &properties, Some(&registry)).unwrap();
        assert_eq!(pulls, vec![mirrored]);
        let err = registry
            .verify(&sample("ghcr.io", b"payload-a"))
            .unwrap_err();
        assert!(err.to_string().contains("unresolvable"));
    }

    #[test]
    fn filesystem_store_is_idempotent_and_names_a_conflicting_digest() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-oci-fs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let registry = FilesystemArtifactRegistry::new(root.clone());
        let reference = sample("mirror.internal", b"payload-a");
        registry.put(&reference, b"payload-a".to_vec()).unwrap();
        registry.put(&reference, b"payload-a".to_vec()).unwrap();
        registry.verify(&reference).unwrap();
        let path = root
            .join("mirror.internal")
            .join("edge/app")
            .join(reference.digest.replace(':', "-"));
        std::fs::write(&path, b"tampered").unwrap();
        let err = registry
            .put(&reference, b"payload-a".to_vec())
            .unwrap_err()
            .to_string();
        assert!(err.contains(&reference.digest), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }
}
