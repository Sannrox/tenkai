//! Model-runtime product contract and executor port.
//!
//! Tenkai governs lifecycle (publish, plan, apply, health, rollback) for
//! open-weight model deployments. Inference engines remain external plugins
//! that download weights, load models, and serve traffic. Multi-GB weight
//! payloads are never stored in Tenkai operational state—only content-addressed
//! digests and descriptors.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::manifest::{
    Manifest, ModelHealthSection, ModelRequirementsSection, ModelRuntimeSection, ModelSection,
};

/// Version of the model-runtime descriptor contract.
pub const MODEL_RUNTIME_CONTRACT_VERSION: u32 = 1;

/// Validated model-runtime release descriptor (manifest sections, normalized).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRuntimeDescriptor {
    pub contract_version: u32,
    pub product_name: String,
    pub product_version: String,
    pub model: ModelSection,
    pub runtime: ModelRuntimeSection,
    pub requirements: ModelRequirementsSection,
    pub health: ModelHealthSection,
}

impl ModelRuntimeDescriptor {
    pub fn from_manifest(manifest: &Manifest) -> Result<Self> {
        let model = manifest
            .model
            .as_ref()
            .context("model_runtime manifest needs a [model] section")?
            .clone();
        let runtime = manifest
            .runtime
            .as_ref()
            .context("model_runtime manifest needs a [runtime] section")?
            .clone();
        let requirements = manifest
            .requirements
            .as_ref()
            .context("model_runtime manifest needs a [requirements] section")?
            .clone();
        let health = manifest
            .model_health
            .as_ref()
            .context("model_runtime manifest needs a [health] section")?
            .clone();
        let descriptor = Self {
            contract_version: MODEL_RUNTIME_CONTRACT_VERSION,
            product_name: manifest.product.name.clone(),
            product_version: manifest.product.version.clone(),
            model,
            runtime,
            requirements,
            health,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract_version != MODEL_RUNTIME_CONTRACT_VERSION {
            bail!(
                "unsupported model_runtime contract version {}; expected {}",
                self.contract_version,
                MODEL_RUNTIME_CONTRACT_VERSION
            );
        }
        crate::ontology::validate_identifier("product.name", &self.product_name)?;
        crate::ontology::validate_identifier("product.version", &self.product_version)?;
        for (field, value) in [
            ("model.source", self.model.source.as_str()),
            ("model.revision", self.model.revision.as_str()),
            ("model.format", self.model.format.as_str()),
            ("model.quantization", self.model.quantization.as_str()),
            ("model.artifact_digest", self.model.artifact_digest.as_str()),
            ("model.license", self.model.license.as_str()),
            ("runtime.engine", self.runtime.engine.as_str()),
            ("health.endpoint", self.health.endpoint.as_str()),
        ] {
            if value.trim().is_empty() {
                bail!("{field} must not be empty");
            }
        }
        validate_artifact_digest(&self.model.artifact_digest)?;
        if self.runtime.port == 0 {
            bail!("runtime.port must be non-zero");
        }
        if self.runtime.context_length == 0 {
            bail!("runtime.context_length must be non-zero");
        }
        if self.requirements.architecture.is_empty() {
            bail!("requirements.architecture must not be empty");
        }
        for arch in &self.requirements.architecture {
            if arch.trim().is_empty() {
                bail!("requirements.architecture entries must not be empty");
            }
        }
        if self.requirements.memory_gib == 0 {
            bail!("requirements.memory_gib must be non-zero");
        }
        for accel in &self.requirements.accelerator {
            if accel.trim().is_empty() {
                bail!("requirements.accelerator entries must not be empty");
            }
        }
        if self.health.max_startup_seconds == 0 {
            bail!("health.max_startup_seconds must be non-zero");
        }
        // Weights stay external: source must not address Tenkai operational storage.
        if self.model.source.starts_with("sqlite:") || self.model.source.starts_with("tenkai-db:") {
            bail!("model.source cannot address Tenkai operational storage");
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(self)?)
        ))
    }
}

fn validate_artifact_digest(value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("model.artifact_digest must use sha256:<hex> form");
    };
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("model.artifact_digest must be sha256: followed by 64 hex characters");
    }
    Ok(())
}

fn artifact_digest_hex(value: &str) -> Result<&str> {
    validate_artifact_digest(value)?;
    Ok(value
        .strip_prefix("sha256:")
        .expect("validated digest has sha256: prefix"))
}

/// Content-addressed weight cache outside the operational SQLite database.
#[derive(Debug, Clone)]
pub struct WeightCache {
    root: PathBuf,
}

impl WeightCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn blob_path(&self, artifact_digest: &str) -> Result<PathBuf> {
        let hex = artifact_digest_hex(artifact_digest)?;
        Ok(self.root.join("sha256").join(hex))
    }

    /// Fetch weights from a supported source and verify `artifact_digest`.
    ///
    /// Supported sources for this release:
    /// - `file://` absolute local path
    /// - `http://` / `https://` URL (uses blocking reqwest)
    ///
    /// Unknown schemes fail closed. On digest mismatch the incomplete file is
    /// removed and the model is not considered active.
    pub fn fetch_and_verify(&self, source: &str, artifact_digest: &str) -> Result<PathBuf> {
        validate_artifact_digest(artifact_digest)?;
        let destination = self.blob_path(artifact_digest)?;
        if destination.is_file() {
            verify_file_digest(&destination, artifact_digest)?;
            return Ok(destination);
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating weight cache {}", parent.display()))?;
        }
        let temporary = destination.with_extension("partial");
        let _ = std::fs::remove_file(&temporary);
        fetch_source_to(source, &temporary)?;
        match verify_file_digest(&temporary, artifact_digest) {
            Ok(()) => {
                std::fs::rename(&temporary, &destination).with_context(|| {
                    format!("promoting verified weights to {}", destination.display())
                })?;
                Ok(destination)
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                Err(error).context("weight digest verification failed; model not activated")
            }
        }
    }

    /// Evict oldest unprotected weight blobs until at most `keep` files remain.
    ///
    /// Digests listed in `protected` are never deleted, even when that means
    /// more than `keep` blobs remain. Returns digests removed as `sha256:<hex>`.
    /// Eviction failures are actionable and never touch protected active digests.
    pub fn evict(&self, protected: &[String], keep: usize) -> Result<Vec<String>> {
        let mut protected_set = HashSet::new();
        for digest in protected {
            let hex = artifact_digest_hex(digest)?;
            protected_set.insert(hex.to_string());
        }

        let mut entries = self.list_cached_blobs()?;
        // Oldest first so eviction prefers prior generations.
        entries.sort_by_key(|entry| entry.modified);

        let mut total = entries.len();
        let mut removed = Vec::new();
        for entry in entries {
            if total <= keep {
                break;
            }
            if protected_set.contains(&entry.hex) {
                continue;
            }
            let path = self.root.join("sha256").join(&entry.hex);
            std::fs::remove_file(&path).with_context(|| {
                format!(
                    "evicting unprotected weight cache entry {} (sha256:{})",
                    path.display(),
                    entry.hex
                )
            })?;
            removed.push(format!("sha256:{}", entry.hex));
            total = total.saturating_sub(1);
        }
        Ok(removed)
    }

    fn list_cached_blobs(&self) -> Result<Vec<CachedBlob>> {
        let dir = self.root.join("sha256");
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("listing weight cache {}", dir.display()))?
        {
            let entry = entry.with_context(|| format!("reading weight cache {}", dir.display()))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) => {
                    name.to_ascii_lowercase()
                }
                _ => continue,
            };
            let modified = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            entries.push(CachedBlob {
                hex: name,
                modified,
            });
        }
        Ok(entries)
    }
}

struct CachedBlob {
    hex: String,
    modified: SystemTime,
}

fn fetch_source_to(source: &str, destination: &Path) -> Result<()> {
    if let Some(path) = source.strip_prefix("file://") {
        let path = Path::new(path);
        if !path.is_absolute() {
            bail!("file:// model.source must be an absolute path");
        }
        std::fs::copy(path, destination).with_context(|| {
            format!(
                "copying model weights from {} to {}",
                path.display(),
                destination.display()
            )
        })?;
        return Ok(());
    }
    if source.starts_with("http://") || source.starts_with("https://") {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("building weight download client")?;
        let mut response = client
            .get(source)
            .send()
            .with_context(|| format!("downloading model weights from {source}"))?
            .error_for_status()
            .with_context(|| format!("weight download from {source} failed"))?;
        let mut file = std::fs::File::create(destination)
            .with_context(|| format!("creating {}", destination.display()))?;
        std::io::copy(&mut response, &mut file)
            .with_context(|| format!("writing downloaded weights to {}", destination.display()))?;
        return Ok(());
    }
    if source.starts_with("hf://") || source.starts_with("oci://") {
        bail!(
            "model.source scheme is reserved but not implemented in this build: {source}; use file:// or http(s):// for verified fetch"
        );
    }
    bail!("unsupported model.source scheme (need file:// or http(s)://): {source}");
}

fn verify_file_digest(path: &Path, artifact_digest: &str) -> Result<()> {
    let expected = artifact_digest_hex(artifact_digest)?;
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        bail!(
            "weight digest mismatch for {}: expected sha256:{expected}, got sha256:{actual}",
            path.display()
        );
    }
    Ok(())
}

/// Pluggable inference-engine adapter. Engines download/verify weights, start
/// servers, probe health, and free resources. Tenkai never links a specific
/// engine into the core binary as a hard dependency.
pub trait ModelRuntimeExecutor: Send + Sync {
    /// Install or activate the descriptor for this environment/product.
    /// Returns the content identity of the applied descriptor.
    fn apply(&self, descriptor: &ModelRuntimeDescriptor) -> Result<String>;

    /// Remove the active model runtime for this product.
    fn remove(&self) -> Result<()>;

    /// Observe the applied descriptor identity, if any.
    fn observe(&self) -> Result<Option<String>>;
}

/// Local reference executor that stages the validated descriptor and, when a
/// [`WeightCache`] is configured, fetches and verifies weight digests.
///
/// It does **not** start an inference server. Real `tenkai-executor-*` plugins
/// implement [`ModelRuntimeExecutor`] and add start/smoke/switch steps after
/// using the same cache verify path.
pub struct LocalModelRuntimeExecutor {
    state_path: PathBuf,
    weight_cache: Option<WeightCache>,
}

impl LocalModelRuntimeExecutor {
    pub fn new(state_path: PathBuf) -> Self {
        Self {
            state_path,
            weight_cache: None,
        }
    }

    pub fn with_weight_cache(mut self, cache: WeightCache) -> Self {
        self.weight_cache = Some(cache);
        self
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }
}

impl ModelRuntimeExecutor for LocalModelRuntimeExecutor {
    fn apply(&self, descriptor: &ModelRuntimeDescriptor) -> Result<String> {
        descriptor.validate()?;
        if let Some(cache) = &self.weight_cache {
            // Fail closed before descriptor activation when digest mismatches.
            cache.fetch_and_verify(&descriptor.model.source, &descriptor.model.artifact_digest)?;
        }
        let expected = descriptor.digest()?;
        let parent = self
            .state_path
            .parent()
            .context("model runtime state path has no parent")?;
        std::fs::create_dir_all(parent)?;
        let temporary = self.state_path.with_extension("json.pending");
        std::fs::write(&temporary, serde_json::to_vec_pretty(descriptor)?)?;
        let observed: ModelRuntimeDescriptor = serde_json::from_slice(&std::fs::read(&temporary)?)?;
        observed.validate()?;
        if observed.digest()? != expected {
            let _ = std::fs::remove_file(&temporary);
            bail!("model_runtime post-mutation verification failed");
        }
        std::fs::rename(&temporary, &self.state_path)?;
        if self.observe()?.as_deref() != Some(expected.as_str()) {
            bail!("model_runtime post-mutation observation differs from requested descriptor");
        }
        Ok(expected)
    }

    fn remove(&self) -> Result<()> {
        match std::fs::remove_file(&self.state_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn observe(&self) -> Result<Option<String>> {
        match std::fs::read(&self.state_path) {
            Ok(bytes) => {
                let descriptor: ModelRuntimeDescriptor = serde_json::from_slice(&bytes)?;
                descriptor.validate()?;
                Ok(Some(descriptor.digest()?))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{DeploySection, GateSection, ProductKind, ProductSection};

    fn sample_descriptor() -> ModelRuntimeDescriptor {
        ModelRuntimeDescriptor {
            contract_version: MODEL_RUNTIME_CONTRACT_VERSION,
            product_name: "qwen-coder".into(),
            product_version: "3.2.1".into(),
            model: ModelSection {
                source: "hf://org/qwen-coder".into(),
                revision: "9bcfabc".into(),
                format: "gguf".into(),
                quantization: "Q4_K_M".into(),
                artifact_digest: format!("sha256:{}", "ab".repeat(32)),
                license: "apache-2.0".into(),
            },
            runtime: ModelRuntimeSection {
                engine: "llama.cpp".into(),
                port: 8080,
                context_length: 32768,
            },
            requirements: ModelRequirementsSection {
                architecture: vec!["arm64".into()],
                memory_gib: 32,
                accelerator: vec!["apple-metal".into()],
            },
            health: ModelHealthSection {
                endpoint: "http://127.0.0.1:8080/v1/models".into(),
                smoke_prompt: "Return exactly: OK".into(),
                max_startup_seconds: 300,
            },
        }
    }

    #[test]
    fn validates_digest_and_required_fields() {
        let mut descriptor = sample_descriptor();
        descriptor.validate().unwrap();
        descriptor.model.artifact_digest = "sha256:deadbeef".into();
        assert!(descriptor.validate().is_err());
        descriptor = sample_descriptor();
        descriptor.model.source = "sqlite://weights".into();
        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn from_manifest_builds_descriptor() {
        let sample = sample_descriptor();
        let manifest = Manifest {
            product: ProductSection {
                name: "qwen-coder".into(),
                version: "3.2.1".into(),
                description: String::new(),
                kind: ProductKind::ModelRuntime,
            },
            deploy: DeploySection::default(),
            routing: None,
            model: Some(sample.model.clone()),
            runtime: Some(sample.runtime.clone()),
            requirements: Some(sample.requirements.clone()),
            model_health: Some(sample.health.clone()),
            gate: GateSection::default(),
        };
        let descriptor = ModelRuntimeDescriptor::from_manifest(&manifest).unwrap();
        assert_eq!(descriptor.product_name, "qwen-coder");
        assert!(descriptor.digest().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn local_executor_stages_descriptor_without_weight_payloads() {
        let root = std::env::temp_dir().join(format!("tenkai-model-{}", uuid::Uuid::new_v4()));
        let executor = LocalModelRuntimeExecutor::new(root.join("active.json"));
        let descriptor = sample_descriptor();
        let applied = executor.apply(&descriptor).unwrap();
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(applied.as_str())
        );
        let bytes = std::fs::metadata(executor.state_path()).unwrap().len();
        assert!(bytes < 16 * 1024);
        executor.remove().unwrap();
        assert!(executor.observe().unwrap().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rollback_reapplies_previous_descriptor() {
        let root = std::env::temp_dir().join(format!("tenkai-model-rb-{}", uuid::Uuid::new_v4()));
        let executor = LocalModelRuntimeExecutor::new(root.join("active.json"));
        let previous = sample_descriptor();
        let mut next = sample_descriptor();
        next.product_version = "3.2.2".into();
        next.model.revision = "newer".into();
        let previous_digest = executor.apply(&previous).unwrap();
        let next_digest = executor.apply(&next).unwrap();
        assert_ne!(previous_digest, next_digest);
        assert_eq!(executor.apply(&previous).unwrap(), previous_digest);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn weight_cache_verifies_file_source_and_rejects_mismatch() {
        let root = std::env::temp_dir().join(format!("tenkai-weights-{}", uuid::Uuid::new_v4()));
        let source_dir = root.join("src");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&source_dir).unwrap();
        let payload = b"tiny-model-bytes";
        let source_file = source_dir.join("model.bin");
        std::fs::write(&source_file, payload).unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(payload));
        let cache = WeightCache::new(&cache_dir);
        let stored = cache
            .fetch_and_verify(&format!("file://{}", source_file.display()), &digest)
            .unwrap();
        assert!(stored.is_file());
        // Second fetch hits cache.
        let again = cache
            .fetch_and_verify(&format!("file://{}", source_file.display()), &digest)
            .unwrap();
        assert_eq!(stored, again);

        let bad = format!("sha256:{}", "00".repeat(32));
        let err = cache
            .fetch_and_verify(&format!("file://{}", source_file.display()), &bad)
            .unwrap_err()
            .to_string();
        assert!(err.contains("digest mismatch") || err.contains("verification failed"));
        assert!(!cache.blob_path(&bad).unwrap().exists());

        let mut descriptor = sample_descriptor();
        descriptor.model.source = format!("file://{}", source_file.display());
        descriptor.model.artifact_digest = digest;
        let executor =
            LocalModelRuntimeExecutor::new(root.join("active.json")).with_weight_cache(cache);
        executor.apply(&descriptor).unwrap();
        assert!(executor.state_path().is_file());

        descriptor.model.artifact_digest = format!("sha256:{}", "11".repeat(32));
        assert!(executor.apply(&descriptor).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn weight_cache_evicts_unprotected_oldest_first() {
        let root = std::env::temp_dir().join(format!("tenkai-evict-{}", uuid::Uuid::new_v4()));
        let cache = WeightCache::new(root.join("cache"));
        let digests = (0..3)
            .map(|i| {
                let bytes = [i as u8; 16];
                let digest = format!("sha256:{:x}", Sha256::digest(bytes));
                let path = cache.blob_path(&digest).unwrap();
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, bytes).unwrap();
                // ensure mtime ordering
                std::thread::sleep(std::time::Duration::from_millis(15));
                digest
            })
            .collect::<Vec<_>>();
        let protected = vec![digests[2].clone()];
        let removed = cache.evict(&protected, 2).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], digests[0]);
        assert!(!cache.blob_path(&digests[0]).unwrap().exists());
        assert!(cache.blob_path(&digests[1]).unwrap().exists());
        assert!(cache.blob_path(&digests[2]).unwrap().exists());
        // Protected never removed even if keep is 0.
        let removed = cache.evict(&protected, 0).unwrap();
        assert!(!removed.iter().any(|d| d == &digests[2]));
        assert!(cache.blob_path(&digests[2]).unwrap().exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
