//! Digest-bound OCI artifact references (discussion #385 / #375).
//!
//! A release names artifacts by content digest. The catalog is not a registry.
//! A registry is not a second catalog. Pull uses the environment mirror only.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
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
    /// The artifact's SBOM, declared by the release (#804). An offline
    /// bundle carries it instead of generating one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom: Option<SbomRef>,
}

/// A digest-bound SBOM document for one artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomRef {
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

/// A registry a client can pull from by name (#627): a valid host that also
/// reads as a registry, with a `.` or a port or as `localhost`. Docker reads
/// a single label such as `seed` as a Docker Hub namespace instead.
pub fn validate_pull_registry(label: &str, host: &str) -> Result<()> {
    validate_registry_host(label, host)?;
    if !(host.contains(['.', ':']) || host == "localhost") {
        bail!("{label} {host:?} must contain a '.' or a port, or be localhost");
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
        if let Some(sbom) = &self.sbom {
            let artifact = self.identity_key();
            crate::signature_verification::validate_prefixed_digest(
                &format!("SBOM digest of artifact {artifact}"),
                &sbom.digest,
            )?;
            if sbom.media_type.is_empty() || sbom.media_type.chars().any(char::is_control) {
                bail!("SBOM media type of artifact {artifact} must be a non-empty media type");
            }
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
    /// `None` when absent, `Some(true)` when stored with matching bytes,
    /// `Some(false)` when stored with other bytes. Reads, never writes.
    fn stored(&self, reference: &OciArtifactRef) -> Result<Option<bool>> {
        Ok(self.verify(reference).ok().map(|_| true))
    }
    fn verify(&self, reference: &OciArtifactRef) -> Result<OciArtifactRef>;
    fn fetch(&self, reference: &OciArtifactRef) -> Result<Vec<u8>>;
    fn store(&self, reference: &OciArtifactRef, bytes: Vec<u8>) -> Result<()>;
    /// Store the blob read from `reader`, for blobs too large to hold in
    /// memory (#684). The digest is checked before the blob is visible.
    /// Default: read it whole and [`Self::store`] it.
    fn store_reader(&self, reference: &OciArtifactRef, reader: &mut dyn Read) -> Result<()> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        self.store(reference, bytes)
    }
}

/// The `sha256:` digest of the file at `path`, read in a stream.
fn file_digest(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("sha256:{:x}", hasher.finalize()))
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
        let root = crate::host_env::var("TENKAI_OCI_STORE").map_err(|_| {
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
    fn stored(&self, reference: &OciArtifactRef) -> Result<Option<bool>> {
        reference.validate()?;
        match file_digest(&self.blob_path(reference)) {
            Ok(digest) => Ok(Some(digest == reference.digest)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn verify(&self, reference: &OciArtifactRef) -> Result<OciArtifactRef> {
        reference.validate()?;
        let path = self.blob_path(reference);
        let actual = file_digest(&path).map_err(|_| {
            anyhow::anyhow!(
                "artifact digest {} is unresolvable at {}/{}",
                reference.digest,
                reference.registry,
                reference.repository
            )
        })?;
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

    /// Streams into a temporary file beside the blob, hashing as it goes,
    /// and renames it into place only when the digest matches.
    fn store_reader(&self, reference: &OciArtifactRef, reader: &mut dyn Read) -> Result<()> {
        reference.validate()?;
        // Absolute, so the walk over created directories below never runs
        // into the empty ancestor of a relative store root.
        let path = std::path::absolute(self.blob_path(reference))?;
        if path.exists() {
            let existing = file_digest(&path)?;
            if existing == reference.digest {
                return Ok(());
            }
            bail!(
                "artifact digest {} already exists with different bytes {existing}",
                reference.digest
            );
        }
        // The highest directory this write creates: its parent is the last
        // directory whose entries must be made durable.
        let mut first_created = None;
        if let Some(parent) = path.parent() {
            let mut missing = parent;
            while !missing.exists() {
                first_created = Some(missing.to_path_buf());
                match missing.parent() {
                    Some(up) => missing = up,
                    None => break,
                }
            }
            std::fs::create_dir_all(parent)?;
        }
        // A temporary of its own, so concurrent writers never share one.
        let tmp = path.with_file_name(format!(
            ".{}.{}.part",
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow::anyhow!("artifact blob path is not UTF-8"))?,
            uuid::Uuid::new_v4().simple()
        ));
        let written = (|| -> Result<String> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0_u8; 1024 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
                std::io::Write::write_all(&mut file, &buffer[..read])?;
            }
            file.sync_all()?;
            Ok(format!("sha256:{:x}", hasher.finalize()))
        })();
        let digest = match written {
            Ok(digest) => digest,
            Err(error) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(error);
            }
        };
        if digest != reference.digest {
            let _ = std::fs::remove_file(&tmp);
            bail!(
                "stored artifact digest {digest} does not match declared {}",
                reference.digest
            );
        }
        if let Err(error) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(error.into());
        }
        // The rename, and every directory created for it, survive a crash
        // before the blob is reported stored: sync up to the parent of the
        // highest directory created, or the blob's own directory.
        let stop = first_created
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf);
        let mut dir = path.parent();
        while let Some(current) = dir {
            std::fs::File::open(current)?.sync_all()?;
            if stop.as_deref().is_none_or(|stop| current == stop) {
                break;
            }
            dir = current.parent();
        }
        Ok(())
    }
}

pub fn validate_all(artifacts: &[OciArtifactRef]) -> Result<()> {
    for artifact in artifacts {
        artifact.validate()?;
    }
    Ok(())
}

/// Bind the artifacts into a release identity. An artifact without an SBOM
/// hashes as before #804, so existing identities are unchanged. A declared
/// SBOM follows its artifact's fields behind an empty field, which no
/// artifact's registry can be, so the encoding stays unambiguous.
pub fn bind_identity(hasher: &mut Sha256, artifacts: &[OciArtifactRef]) {
    fn field(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    let mut ordered = artifacts.to_vec();
    ordered.sort_by(|left, right| {
        let key = |artifact: &OciArtifactRef| {
            (
                artifact.identity_key(),
                artifact
                    .sbom
                    .as_ref()
                    .map(|sbom| (sbom.digest.clone(), sbom.media_type.clone())),
            )
        };
        key(left).cmp(&key(right))
    });
    hasher.update(ARTIFACT_REF_SCHEMA.as_bytes());
    hasher.update((artifacts.len() as u64).to_le_bytes());
    for artifact in ordered {
        for value in [
            artifact.registry.as_bytes(),
            artifact.repository.as_bytes(),
            artifact.digest.as_bytes(),
            artifact.media_type.as_bytes(),
        ] {
            field(hasher, value);
        }
        if let Some(sbom) = &artifact.sbom {
            field(hasher, b"");
            field(hasher, sbom.digest.as_bytes());
            field(hasher, sbom.media_type.as_bytes());
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
        sbom: None,
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

/// Media types whose bytes name other blobs of the same repository.
const MANIFEST_MEDIA_TYPES: [&str; 4] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

pub fn is_manifest_media_type(media_type: &str) -> bool {
    MANIFEST_MEDIA_TYPES.contains(&media_type)
}

#[derive(Deserialize)]
struct Descriptor {
    digest: String,
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
}

/// The fields of an image manifest or index that reference other blobs.
#[derive(Deserialize)]
struct ManifestBody {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
    #[serde(default)]
    manifests: Vec<Descriptor>,
}

/// The blobs an image manifest or index references, as `(digest, media
/// type)`: its config and layers, or the manifests it lists (#627). A pull
/// of the image needs every one of them from the same repository. Empty for
/// other media types; a descriptor without a media type reads as opaque.
pub fn referenced_blobs(media_type: &str, bytes: &[u8]) -> Result<Vec<(String, String)>> {
    if !is_manifest_media_type(media_type) {
        return Ok(Vec::new());
    }
    let body: ManifestBody = serde_json::from_slice(bytes)
        .map_err(|error| anyhow::anyhow!("image manifest of type {media_type}: {error}"))?;
    body.config
        .into_iter()
        .chain(body.layers)
        .chain(body.manifests)
        .map(|descriptor| {
            crate::signature_verification::validate_prefixed_digest(
                "referenced digest",
                &descriptor.digest,
            )?;
            let media_type = descriptor
                .media_type
                .unwrap_or_else(|| "application/octet-stream".into());
            Ok((descriptor.digest, media_type))
        })
        .collect()
}

/// `artifacts` and every blob their image manifests and indexes reference,
/// read from `registry`, each once and in first-seen order (#627). Leaf
/// blobs are listed from descriptors and not fetched (#841).
pub fn image_closure(
    artifacts: &[OciArtifactRef],
    registry: &dyn ArtifactRegistry,
) -> Result<Vec<OciArtifactRef>> {
    image_closure_except(artifacts, registry, |_| false)
}

/// [`image_closure`], with artifacts `held` admits kept in the closure
/// unfetched and unexpanded: a delta's base content at the same registry
/// and repository (#635, #841). Manifests are fetched to read descriptors;
/// leaf blobs are listed without a fetch.
pub fn image_closure_except(
    artifacts: &[OciArtifactRef],
    registry: &dyn ArtifactRegistry,
    held: impl Fn(&OciArtifactRef) -> bool,
) -> Result<Vec<OciArtifactRef>> {
    let mut closure: Vec<OciArtifactRef> = Vec::new();
    let mut pending: std::collections::VecDeque<OciArtifactRef> =
        artifacts.iter().cloned().collect();
    while let Some(artifact) = pending.pop_front() {
        let seen = closure.iter().any(|known| {
            known.registry == artifact.registry
                && known.repository == artifact.repository
                && known.digest == artifact.digest
        });
        if seen {
            continue;
        }
        if held(&artifact) {
            closure.push(artifact);
            continue;
        }
        if !is_manifest_media_type(&artifact.media_type) {
            closure.push(artifact);
            continue;
        }
        for (digest, media_type) in
            referenced_blobs(&artifact.media_type, &registry.fetch(&artifact)?)?
        {
            pending.push_back(OciArtifactRef {
                registry: artifact.registry.clone(),
                repository: artifact.repository.clone(),
                digest,
                media_type,
                sbom: None,
            });
        }
        closure.push(artifact);
    }
    Ok(closure)
}

/// The content type to serve a stored manifest with: its own `mediaType`,
/// else what its fields show. `None` when the bytes are not a manifest.
pub fn manifest_content_type(bytes: &[u8]) -> Option<String> {
    let body: ManifestBody = serde_json::from_slice(bytes).ok()?;
    match body.media_type {
        Some(media_type) if is_manifest_media_type(&media_type) => Some(media_type),
        Some(_) => None,
        None if !body.manifests.is_empty() => Some(MANIFEST_MEDIA_TYPES[1].into()),
        None if body.config.is_some() => Some(MANIFEST_MEDIA_TYPES[0].into()),
        None => None,
    }
}

/// An OCI distribution repository name: lowercase `/`-separated segments of
/// alphanumerics joined by `.`, `_` or `-`.
pub fn validate_repository_name(name: &str) -> Result<()> {
    let separator = |c: char| matches!(c, '.' | '_' | '-');
    let valid = !name.is_empty()
        && name.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || separator(c))
                && !segment.starts_with(separator)
                && !segment.ends_with(separator)
        });
    if !valid {
        bail!("repository name {name:?} is not a valid OCI repository name");
    }
    Ok(())
}

impl FilesystemArtifactRegistry {
    /// Where the blob `digest` of `registry`/`repository` is stored, for
    /// serving it (#627). Every part is validated, so a request path never
    /// leaves the store.
    pub fn served_blob_path(
        &self,
        registry: &str,
        repository: &str,
        digest: &str,
    ) -> Result<PathBuf> {
        validate_registry_host("served registry", registry)?;
        validate_repository_name(repository)?;
        crate::signature_verification::validate_prefixed_digest("blob digest", digest)?;
        Ok(self
            .root
            .join(registry)
            .join(repository)
            .join(digest.replace(':', "-")))
    }
}

/// A store read through environment mirrors: each reference is looked up
/// under its mirror registry, where imports put it (#627). Verification
/// answers with the reference as asked, so release identity is unchanged.
pub struct MirroredRegistry {
    store: std::sync::Arc<dyn ArtifactRegistry>,
    mirrors: BTreeMap<String, String>,
}

impl MirroredRegistry {
    pub fn new(
        store: std::sync::Arc<dyn ArtifactRegistry>,
        mirrors: BTreeMap<String, String>,
    ) -> Self {
        Self { store, mirrors }
    }
}

impl ArtifactRegistry for MirroredRegistry {
    fn stored(&self, reference: &OciArtifactRef) -> Result<Option<bool>> {
        self.store
            .stored(&pull_reference(reference, &self.mirrors)?)
    }

    fn verify(&self, reference: &OciArtifactRef) -> Result<OciArtifactRef> {
        self.store
            .verify(&pull_reference(reference, &self.mirrors)?)?;
        Ok(reference.clone())
    }

    fn fetch(&self, reference: &OciArtifactRef) -> Result<Vec<u8>> {
        self.store.fetch(&pull_reference(reference, &self.mirrors)?)
    }

    fn store(&self, reference: &OciArtifactRef, bytes: Vec<u8>) -> Result<()> {
        self.store
            .store(&pull_reference(reference, &self.mirrors)?, bytes)
    }
}

/// The store `TENKAI_OCI_STORE` names, if set. The variable is read once,
/// so a concurrent change cannot pass the check and fail the construction.
pub fn selected_registry() -> Result<Option<std::sync::Arc<dyn ArtifactRegistry>>> {
    match crate::host_env::var("TENKAI_OCI_STORE") {
        Ok(path) if !path.is_empty() => Ok(Some(std::sync::Arc::new(
            FilesystemArtifactRegistry::new(PathBuf::from(path)),
        ))),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(sbom: Option<&str>) -> OciArtifactRef {
        OciArtifactRef {
            registry: "ghcr.io".into(),
            repository: "edge/app".into(),
            digest: format!("sha256:{}", "aa".repeat(32)),
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            sbom: sbom.map(|digest| SbomRef {
                digest: digest.into(),
                media_type: "application/spdx+json".into(),
            }),
        }
    }

    fn bound(artifacts: &[OciArtifactRef]) -> String {
        let mut hasher = Sha256::new();
        bind_identity(&mut hasher, artifacts);
        format!("{:x}", hasher.finalize())
    }

    /// An artifact without an SBOM hashes as it did before SBOMs existed, so
    /// published release identities are unchanged; a declared SBOM, and any
    /// change to it, changes the identity (#804).
    #[test]
    fn a_declared_sbom_binds_into_the_identity_and_its_absence_changes_nothing() {
        let plain = artifact(None);
        let mut legacy = Sha256::new();
        legacy.update(ARTIFACT_REF_SCHEMA.as_bytes());
        legacy.update(1_u64.to_le_bytes());
        for field in [
            &plain.registry,
            &plain.repository,
            &plain.digest,
            &plain.media_type,
        ] {
            legacy.update((field.len() as u64).to_le_bytes());
            legacy.update(field.as_bytes());
        }
        assert_eq!(
            bound(std::slice::from_ref(&plain)),
            format!("{:x}", legacy.finalize())
        );

        let first = artifact(Some(&format!("sha256:{}", "11".repeat(32))));
        let second = artifact(Some(&format!("sha256:{}", "22".repeat(32))));
        assert_ne!(bound(std::slice::from_ref(&first)), bound(&[plain]));
        assert_ne!(
            bound(std::slice::from_ref(&first)),
            bound(std::slice::from_ref(&second))
        );
        // Order does not matter, even between artifacts that differ only by
        // an SBOM field.
        assert_eq!(
            bound(&[first.clone(), second.clone()]),
            bound(&[second, first.clone()])
        );
        let mut other_media_type = first.clone();
        other_media_type.sbom.as_mut().unwrap().media_type =
            "application/vnd.cyclonedx+json".into();
        assert_eq!(
            bound(&[first.clone(), other_media_type.clone()]),
            bound(&[other_media_type, first])
        );
    }

    /// A malformed SBOM reference is refused naming its artifact.
    #[test]
    fn a_malformed_sbom_is_refused_naming_the_artifact() {
        let named = artifact(None).identity_key();
        let mut no_media_type = artifact(Some(&format!("sha256:{}", "11".repeat(32))));
        no_media_type.sbom.as_mut().unwrap().media_type.clear();
        for invalid in [artifact(Some("sha256:short")), no_media_type] {
            let error = format!("{:#}", invalid.validate().unwrap_err());
            assert!(error.contains(&named) && error.contains("SBOM"), "{error}");
        }
    }

    fn digest_for(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    fn sample(registry: &str, bytes: &[u8]) -> OciArtifactRef {
        OciArtifactRef {
            registry: registry.into(),
            repository: "edge/app".into(),
            digest: digest_for(bytes),
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            sbom: None,
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

    #[test]
    fn manifests_name_their_config_and_layers_and_indexes_their_manifests() {
        let (config, layer) = (digest_for(b"config"), digest_for(b"layer"));
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": 6},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer, "size": 5}],
        })
        .to_string();
        let media = "application/vnd.oci.image.manifest.v1+json";
        assert_eq!(
            referenced_blobs(media, manifest.as_bytes()).unwrap(),
            [
                (
                    config.clone(),
                    "application/vnd.oci.image.config.v1+json".to_string()
                ),
                (layer, "application/vnd.oci.image.layer.v1.tar".to_string())
            ]
        );
        assert_eq!(
            manifest_content_type(manifest.as_bytes()).as_deref(),
            Some(media)
        );
        let index =
            serde_json::json!({"schemaVersion": 2, "manifests": [{"digest": config}]}).to_string();
        assert_eq!(
            manifest_content_type(index.as_bytes()).as_deref(),
            Some("application/vnd.oci.image.index.v1+json")
        );
        assert!(
            referenced_blobs("application/vnd.oci.image.layer.v1.tar", b"opaque")
                .unwrap()
                .is_empty()
        );
        assert!(referenced_blobs(media, b"opaque").is_err());
        assert_eq!(manifest_content_type(b"opaque"), None);
    }

    fn image_manifest(config: &str, layer: &str) -> (OciArtifactRef, Vec<u8>) {
        let media = "application/vnd.oci.image.manifest.v1+json";
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": 1},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer, "size": 1}],
        })
        .to_string()
        .into_bytes();
        (
            OciArtifactRef {
                registry: "ghcr.io".into(),
                repository: "edge/app".into(),
                digest: digest_for(&body),
                media_type: media.into(),
                sbom: None,
            },
            body,
        )
    }

    #[test]
    fn image_closure_lists_leaves_without_fetching_them() {
        let registry = MemoryArtifactRegistry::new();
        let (config, layer) = (digest_for(b"config"), digest_for(b"layer"));
        let (manifest, bytes) = image_manifest(&config, &layer);
        registry.put(&manifest, bytes).unwrap();
        let closure = image_closure(std::slice::from_ref(&manifest), &registry).unwrap();
        let digests: Vec<&str> = closure.iter().map(|blob| blob.digest.as_str()).collect();
        assert_eq!(
            digests,
            vec![manifest.digest.as_str(), config.as_str(), layer.as_str()]
        );
        assert!(
            registry
                .verify(&OciArtifactRef {
                    digest: layer.clone(),
                    media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                    ..manifest.clone()
                })
                .is_err(),
            "the layer was never stored"
        );
    }

    #[test]
    fn image_closure_except_stops_at_a_held_manifest() {
        let registry = MemoryArtifactRegistry::new();
        let (config, layer) = (digest_for(b"config"), digest_for(b"layer"));
        let (manifest, bytes) = image_manifest(&config, &layer);
        registry.put(&manifest, bytes).unwrap();
        let closure = image_closure_except(std::slice::from_ref(&manifest), &registry, |blob| {
            blob.digest == manifest.digest
                && blob.registry == manifest.registry
                && blob.repository == manifest.repository
        })
        .unwrap();
        assert_eq!(closure, vec![manifest]);
    }

    #[test]
    fn served_paths_stay_inside_the_store() {
        let store = FilesystemArtifactRegistry::new(PathBuf::from("/store"));
        let digest = digest_for(b"x");
        assert_eq!(
            store
                .served_blob_path("seed.site:5443", "edge/app", &digest)
                .unwrap(),
            PathBuf::from(format!(
                "/store/seed.site:5443/edge/app/{}",
                digest.replace(':', "-")
            ))
        );
        for repository in [
            "../etc",
            "edge/../app",
            "edge//app",
            "/edge",
            "Edge/app",
            "edge/.app",
            "",
        ] {
            assert!(
                store
                    .served_blob_path("seed.site", repository, &digest)
                    .is_err(),
                "{repository}"
            );
        }
        assert!(
            store
                .served_blob_path("seed.site", "edge/app", "sha256:../../x")
                .is_err()
        );
        assert!(
            store
                .served_blob_path("../seed", "edge/app", &digest)
                .is_err()
        );
        assert!(validate_pull_registry("seed", "seed").is_err());
        for registry in ["seed.site", "seed:5443", "localhost"] {
            validate_pull_registry("seed", registry).unwrap();
        }
    }
}
