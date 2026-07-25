//! Model-runtime product contract and executor port.
//!
//! Tenkai governs lifecycle (publish, plan, apply, health, rollback) for
//! open-weight model deployments. Inference engines remain external plugins
//! that download weights, load models, and serve traffic. Multi-GB weight
//! payloads are never stored in Tenkai operational state—only content-addressed
//! digests and descriptors.

use std::path::{Path, PathBuf};

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

/// Local reference executor that stages the validated descriptor only.
///
/// It does **not** download multi-GB weights or start an inference server.
/// Real `tenkai-executor-*` plugins implement [`ModelRuntimeExecutor`] and
/// perform download, verify, start, smoke-test, and switch steps.
pub struct LocalModelRuntimeExecutor {
    state_path: PathBuf,
}

impl LocalModelRuntimeExecutor {
    pub fn new(state_path: PathBuf) -> Self {
        Self { state_path }
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }
}

impl ModelRuntimeExecutor for LocalModelRuntimeExecutor {
    fn apply(&self, descriptor: &ModelRuntimeDescriptor) -> Result<String> {
        descriptor.validate()?;
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
}
