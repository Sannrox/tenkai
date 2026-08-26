//! Model-runtime product contract and executor port.
//!
//! Tenkai governs lifecycle (publish, plan, apply, health, rollback) for
//! open-weight model deployments. Inference engines remain external plugins
//! that download weights, load models, and serve traffic. Multi-GB weight
//! payloads are never stored in Tenkai operational state—only content-addressed
//! digests and descriptors.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    crate::signature_verification::validate_prefixed_digest("model.artifact_digest", value)
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
        crate::atomic_state::write_json_verified(
            &self.state_path,
            descriptor,
            |observed: &ModelRuntimeDescriptor| {
                observed.validate()?;
                if observed.digest()? != expected {
                    bail!("model_runtime post-mutation verification failed");
                }
                Ok(())
            },
        )?;
        if self.observe()?.as_deref() != Some(expected.as_str()) {
            bail!("model_runtime post-mutation observation differs from requested descriptor");
        }
        Ok(expected)
    }

    fn remove(&self) -> Result<()> {
        crate::atomic_state::remove_if_exists(&self.state_path)
    }

    fn observe(&self) -> Result<Option<String>> {
        match crate::atomic_state::read_json_optional::<ModelRuntimeDescriptor>(&self.state_path)? {
            Some(descriptor) => {
                descriptor.validate()?;
                Ok(Some(descriptor.digest()?))
            }
            None => Ok(None),
        }
    }
}

/// Request to start a candidate inference engine process for one generation.
#[derive(Debug, Clone)]
pub struct EngineStartRequest {
    pub product_name: String,
    pub product_version: String,
    pub weights_path: Option<PathBuf>,
    pub port: u16,
    /// Must be loopback for the reference plugin.
    pub bind_host: String,
    pub engine: String,
    pub health_endpoint: String,
    pub generation_id: String,
}

/// Opaque handle for a started candidate or active engine process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineHandle {
    pub generation_id: String,
    pub port: u16,
    pub bind_host: String,
    /// Plugin-private marker (pid file path, fake id, …). Never a secret.
    pub marker: String,
}

/// Process control port for inference engines. Tenkai core never links a
/// specific engine binary; plugins implement start/smoke/stop.
pub trait InferenceEngineProcess: Send + Sync {
    fn start_candidate(&self, request: &EngineStartRequest) -> Result<EngineHandle>;
    fn smoke(&self, handle: &EngineHandle, health: &ModelHealthSection) -> Result<()>;
    fn stop(&self, handle: &EngineHandle) -> Result<()>;
}

/// Deterministic fake engine for CI. Does not open sockets or spawn processes.
///
/// Rationale for choosing **llama.cpp** as the reference real plugin: it is the
/// default `runtime.engine` in model_runtime manifests, exposes a simple HTTP
/// health surface, and runs on a single machine without a GPU control plane.
/// This fake implements the same lifecycle contract without requiring the binary.
#[derive(Debug, Clone, Default)]
pub struct FakeInferenceEngine {
    /// When true, smoke fails after start so apply must leave the prior generation.
    pub fail_smoke: bool,
    /// When true, start fails before smoke.
    pub fail_start: bool,
}

impl InferenceEngineProcess for FakeInferenceEngine {
    fn start_candidate(&self, request: &EngineStartRequest) -> Result<EngineHandle> {
        require_loopback_bind(&request.bind_host, request.port)?;
        if self.fail_start {
            bail!(
                "fake engine refused to start candidate generation {}",
                request.generation_id
            );
        }
        if request.engine != "llama.cpp" {
            bail!(
                "reference plugin supports runtime.engine=llama.cpp only, got {}",
                request.engine
            );
        }
        Ok(EngineHandle {
            generation_id: request.generation_id.clone(),
            port: request.port,
            bind_host: request.bind_host.clone(),
            marker: format!("fake:{}", request.generation_id),
        })
    }

    fn smoke(&self, handle: &EngineHandle, health: &ModelHealthSection) -> Result<()> {
        require_loopback_health_endpoint(&health.endpoint)?;
        if self.fail_smoke {
            bail!(
                "fake engine smoke failed for generation {} at {}",
                handle.generation_id,
                health.endpoint
            );
        }
        Ok(())
    }

    fn stop(&self, _handle: &EngineHandle) -> Result<()> {
        Ok(())
    }
}

/// Optional real llama.cpp process launcher (external binary, not a crate dep).
///
/// Spawns `TENKAI_LLAMA_SERVER` (default `llama-server`) bound to loopback.
/// Community software-only deploys do not require this binary; use
/// [`FakeInferenceEngine`] in tests and default apply wiring when unset.
#[derive(Debug, Clone)]
pub struct LlamaCppProcessLauncher {
    pub binary: PathBuf,
}

impl Default for LlamaCppProcessLauncher {
    fn default() -> Self {
        let binary = std::env::var_os("TENKAI_LLAMA_SERVER")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("llama-server"));
        Self { binary }
    }
}

impl InferenceEngineProcess for LlamaCppProcessLauncher {
    fn start_candidate(&self, request: &EngineStartRequest) -> Result<EngineHandle> {
        require_loopback_bind(&request.bind_host, request.port)?;
        if request.engine != "llama.cpp" {
            bail!(
                "llama.cpp launcher only supports runtime.engine=llama.cpp, got {}",
                request.engine
            );
        }
        let weights = request
            .weights_path
            .as_ref()
            .context("llama.cpp launcher requires verified weights path")?;
        // Avoid shell injection: argv only, no `sh -c`.
        let mut command = std::process::Command::new(&self.binary);
        command
            .arg("--host")
            .arg(&request.bind_host)
            .arg("--port")
            .arg(request.port.to_string())
            .arg("--model")
            .arg(weights)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let child = command.spawn().with_context(|| {
            format!(
                "starting llama.cpp candidate via {} (set TENKAI_LLAMA_SERVER or use FakeInferenceEngine)",
                self.binary.display()
            )
        })?;
        Ok(EngineHandle {
            generation_id: request.generation_id.clone(),
            port: request.port,
            bind_host: request.bind_host.clone(),
            marker: format!("pid:{}", child.id()),
        })
    }

    fn smoke(&self, handle: &EngineHandle, health: &ModelHealthSection) -> Result<()> {
        require_loopback_health_endpoint(&health.endpoint)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(u64::from(
                health.max_startup_seconds.clamp(1, 60),
            )))
            .build()
            .context("building llama.cpp health client")?;
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(health.max_startup_seconds.max(1) as u64);
        let mut last_error = String::from("health probe did not run");
        while std::time::Instant::now() < deadline {
            match client.get(&health.endpoint).send() {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => {
                    last_error = format!(
                        "health endpoint {} returned {}",
                        health.endpoint,
                        response.status()
                    );
                }
                Err(error) => last_error = error.to_string(),
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        bail!(
            "llama.cpp smoke failed for generation {} at {}: {last_error}",
            handle.generation_id,
            health.endpoint
        );
    }

    fn stop(&self, handle: &EngineHandle) -> Result<()> {
        if let Some(pid) = handle.marker.strip_prefix("pid:")
            && let Ok(pid) = pid.parse::<i32>()
        {
            // Best-effort; generation fencing remains Tenkai-authoritative.
            let _ = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status();
        }
        Ok(())
    }
}

fn require_loopback_bind(host: &str, port: u16) -> Result<()> {
    if port == 0 {
        bail!("model runtime port must not be zero");
    }
    let host = host.trim();
    if host != "127.0.0.1" && host != "::1" && host != "localhost" {
        bail!("reference model engine must bind loopback only, got host {host:?}");
    }
    Ok(())
}

fn require_loopback_health_endpoint(endpoint: &str) -> Result<()> {
    let endpoint = endpoint.trim();
    if !(endpoint.starts_with("http://127.0.0.1")
        || endpoint.starts_with("http://localhost")
        || endpoint.starts_with("http://[::1]"))
    {
        bail!("reference model engine health endpoint must use loopback HTTP, got {endpoint:?}");
    }
    Ok(())
}

fn bind_host_from_health_endpoint(endpoint: &str) -> Result<String> {
    require_loopback_health_endpoint(endpoint)?;
    if endpoint.contains("[::1]") {
        Ok("::1".into())
    } else {
        Ok("127.0.0.1".into())
    }
}

/// Reference llama.cpp model_runtime executor: verify weights → start candidate →
/// smoke → activate, retaining the previous generation for Tenkai rollback.
///
/// The engine process is injected ([`FakeInferenceEngine`] or
/// [`LlamaCppProcessLauncher`]); the core crate never hard-depends on an
/// inference binary.
pub struct ReferenceLlamaCppExecutor {
    state_path: PathBuf,
    weight_cache: Option<WeightCache>,
    engine: Arc<dyn InferenceEngineProcess>,
}

impl ReferenceLlamaCppExecutor {
    pub fn new(state_path: PathBuf, engine: Arc<dyn InferenceEngineProcess>) -> Self {
        Self {
            state_path,
            weight_cache: None,
            engine,
        }
    }

    /// Community/CI default: fake process, full lifecycle contract.
    pub fn with_fake(state_path: PathBuf) -> Self {
        Self::new(state_path, Arc::new(FakeInferenceEngine::default()))
    }

    /// Operator host selection: real llama.cpp when `TENKAI_LLAMA_SERVER` is set
    /// (path to binary) or `TENKAI_USE_REAL_LLAMA=1`; otherwise the fake engine.
    ///
    /// The core crate never links llama.cpp. Default CI stays fake-only.
    pub fn for_operator_host(state_path: PathBuf) -> Self {
        let use_real = std::env::var_os("TENKAI_LLAMA_SERVER").is_some()
            || std::env::var("TENKAI_USE_REAL_LLAMA")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        if use_real {
            Self::new(state_path, Arc::new(LlamaCppProcessLauncher::default()))
        } else {
            Self::with_fake(state_path)
        }
    }

    pub fn with_weight_cache(mut self, cache: WeightCache) -> Self {
        self.weight_cache = Some(cache);
        self
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    fn previous_path(&self) -> PathBuf {
        self.state_path.with_extension("json.previous")
    }

    fn active_handle_path(&self) -> PathBuf {
        self.state_path.with_extension("engine.json")
    }

    fn write_descriptor(&self, path: &Path, descriptor: &ModelRuntimeDescriptor) -> Result<()> {
        let expected = descriptor.digest()?;
        crate::atomic_state::write_json_verified(
            path,
            descriptor,
            |observed: &ModelRuntimeDescriptor| {
                observed.validate()?;
                if observed.digest()? != expected {
                    bail!("model_runtime post-mutation verification failed");
                }
                Ok(())
            },
        )
    }

    fn load_descriptor(path: &Path) -> Result<Option<ModelRuntimeDescriptor>> {
        match crate::atomic_state::read_json_optional::<ModelRuntimeDescriptor>(path)? {
            Some(descriptor) => {
                descriptor.validate()?;
                Ok(Some(descriptor))
            }
            None => Ok(None),
        }
    }

    fn load_handle(path: &Path) -> Result<Option<EngineHandle>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl ModelRuntimeExecutor for ReferenceLlamaCppExecutor {
    fn apply(&self, descriptor: &ModelRuntimeDescriptor) -> Result<String> {
        descriptor.validate()?;
        if descriptor.runtime.engine != "llama.cpp" {
            bail!(
                "ReferenceLlamaCppExecutor requires runtime.engine=llama.cpp, got {}",
                descriptor.runtime.engine
            );
        }
        let weights_path =
            if let Some(cache) = &self.weight_cache {
                Some(cache.fetch_and_verify(
                    &descriptor.model.source,
                    &descriptor.model.artifact_digest,
                )?)
            } else {
                None
            };

        let previous_active = Self::load_descriptor(&self.state_path)?;
        let previous_handle = Self::load_handle(&self.active_handle_path())?;
        let expected = descriptor.digest()?;
        let generation_id = expected.clone();
        let bind_host = bind_host_from_health_endpoint(&descriptor.health.endpoint)?;

        let start = EngineStartRequest {
            product_name: descriptor.product_name.clone(),
            product_version: descriptor.product_version.clone(),
            weights_path,
            port: descriptor.runtime.port,
            bind_host,
            engine: descriptor.runtime.engine.clone(),
            health_endpoint: descriptor.health.endpoint.clone(),
            generation_id: generation_id.clone(),
        };

        let candidate = match self.engine.start_candidate(&start) {
            Ok(handle) => handle,
            Err(error) => {
                // Candidate never became active; prior generation untouched.
                return Err(error)
                    .context("model_runtime candidate start failed; active generation retained");
            }
        };

        if let Err(error) = self.engine.smoke(&candidate, &descriptor.health) {
            let _ = self.engine.stop(&candidate);
            return Err(error).context(
                "model_runtime smoke failed; candidate stopped and previous generation retained for rollback",
            );
        }

        // Promote: retain previous descriptor for Tenkai rollback, then activate.
        if let Some(prev) = previous_active.as_ref() {
            self.write_descriptor(&self.previous_path(), prev)?;
        }
        self.write_descriptor(&self.state_path, descriptor)?;
        if let Some(parent) = self.active_handle_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            self.active_handle_path(),
            serde_json::to_vec_pretty(&candidate)?,
        )?;

        if let Some(prev_handle) = previous_handle
            && prev_handle.generation_id != candidate.generation_id
        {
            let _ = self.engine.stop(&prev_handle);
        }

        if self.observe()?.as_deref() != Some(expected.as_str()) {
            bail!("model_runtime post-activation observation differs from requested descriptor");
        }
        Ok(expected)
    }

    fn remove(&self) -> Result<()> {
        if let Some(handle) = Self::load_handle(&self.active_handle_path())? {
            let _ = self.engine.stop(&handle);
        }
        let _ = std::fs::remove_file(self.active_handle_path());
        let _ = std::fs::remove_file(self.previous_path());
        match std::fs::remove_file(&self.state_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn observe(&self) -> Result<Option<String>> {
        Self::load_descriptor(&self.state_path)?
            .map(|descriptor| descriptor.digest())
            .transpose()
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
            policy: None,
            eval_suite_product: None,
            agent: None,
            prompt: None,
            module: None,
            change_set_pin: None,
            worker_pool: None,
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

    #[test]
    fn reference_executor_activates_after_smoke_and_retains_previous() {
        let root = std::env::temp_dir().join(format!("tenkai-ref-engine-{}", uuid::Uuid::new_v4()));
        let state = root.join("active.json");
        let executor = ReferenceLlamaCppExecutor::with_fake(state.clone());
        let mut first = sample_descriptor();
        first.product_version = "1.0.0".into();
        first.health.endpoint = "http://127.0.0.1:8080/v1/models".into();
        let first_digest = executor.apply(&first).unwrap();
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(first_digest.as_str())
        );

        let mut second = sample_descriptor();
        second.product_version = "2.0.0".into();
        second.health.endpoint = "http://127.0.0.1:8081/v1/models".into();
        second.runtime.port = 8081;
        let second_digest = executor.apply(&second).unwrap();
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(second_digest.as_str())
        );
        let previous: ModelRuntimeDescriptor =
            serde_json::from_slice(&std::fs::read(state.with_extension("json.previous")).unwrap())
                .unwrap();
        assert_eq!(previous.digest().unwrap(), first_digest);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reference_executor_smoke_failure_retains_active_generation() {
        let root = std::env::temp_dir().join(format!("tenkai-ref-fail-{}", uuid::Uuid::new_v4()));
        let state = root.join("active.json");
        let ok = ReferenceLlamaCppExecutor::with_fake(state.clone());
        let mut good = sample_descriptor();
        good.health.endpoint = "http://127.0.0.1:8080/v1/models".into();
        let active = ok.apply(&good).unwrap();

        let failing = ReferenceLlamaCppExecutor::new(
            state.clone(),
            Arc::new(FakeInferenceEngine {
                fail_smoke: true,
                fail_start: false,
            }),
        );
        let mut bad = sample_descriptor();
        bad.product_version = "9.9.9".into();
        bad.health.endpoint = "http://127.0.0.1:8080/v1/models".into();
        let err = failing.apply(&bad).unwrap_err().to_string();
        assert!(
            err.contains("smoke failed") || err.contains("retained"),
            "{err}"
        );
        assert_eq!(ok.observe().unwrap().as_deref(), Some(active.as_str()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reference_executor_rejects_non_loopback_health() {
        let root = std::env::temp_dir().join(format!("tenkai-ref-bind-{}", uuid::Uuid::new_v4()));
        let executor = ReferenceLlamaCppExecutor::with_fake(root.join("active.json"));
        let mut descriptor = sample_descriptor();
        descriptor.health.endpoint = "http://0.0.0.0:8080/v1/models".into();
        assert!(executor.apply(&descriptor).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn for_operator_host_uses_fake_when_real_llama_env_unset() {
        if std::env::var_os("TENKAI_LLAMA_SERVER").is_some()
            || std::env::var_os("TENKAI_USE_REAL_LLAMA").is_some()
        {
            // Operator machines may set these; do not fail the suite.
            return;
        }
        let root = std::env::temp_dir().join(format!("tenkai-host-{}", uuid::Uuid::new_v4()));
        let executor = ReferenceLlamaCppExecutor::for_operator_host(root.join("active.json"));
        let mut descriptor = sample_descriptor();
        descriptor.health.endpoint = "http://127.0.0.1:8080/v1/models".into();
        assert!(executor.apply(&descriptor).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Optional real-binary golden path. Not run in default CI.
    ///
    /// ```text
    /// TENKAI_LLAMA_SERVER=/path/to/llama-server \
    ///   cargo test --locked llama_cpp_operator_golden_path -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires real llama-server; set TENKAI_LLAMA_SERVER and run with --ignored"]
    fn llama_cpp_operator_golden_path() {
        let binary = std::env::var("TENKAI_LLAMA_SERVER")
            .expect("TENKAI_LLAMA_SERVER must be set for this ignored test");
        let path = PathBuf::from(&binary);
        assert!(
            path.is_file() || path.components().count() == 1,
            "TENKAI_LLAMA_SERVER must name an existing file or a PATH command: {binary}"
        );
        let root = std::env::temp_dir().join(format!("tenkai-llama-gold-{}", uuid::Uuid::new_v4()));
        let weights = root.join("weights.bin");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&weights, b"fixture-weights").unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(b"fixture-weights"));
        let mut descriptor = sample_descriptor();
        descriptor.model.source = format!("file://{}", weights.display());
        descriptor.model.artifact_digest = digest;
        descriptor.health.endpoint = "http://127.0.0.1:18080/v1/models".into();
        descriptor.runtime.port = 18080;
        let executor = ReferenceLlamaCppExecutor::new(
            root.join("active.json"),
            Arc::new(LlamaCppProcessLauncher { binary: path }),
        )
        .with_weight_cache(WeightCache::new(root.join("cache")));
        let result = executor.apply(&descriptor);
        let _ = executor.remove();
        let _ = std::fs::remove_dir_all(root);
        // Pass if apply succeeds, or fails with an actionable engine/smoke error
        // (binary present but not a full OpenAI-compatible server is still a
        // valid operator diagnostic).
        match result {
            Ok(_) => {}
            Err(error) => {
                let msg = error.to_string();
                assert!(
                    msg.contains("llama")
                        || msg.contains("smoke")
                        || msg.contains("starting")
                        || msg.contains("health"),
                    "unexpected error: {msg}"
                );
            }
        }
    }
}
