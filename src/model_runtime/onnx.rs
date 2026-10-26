//! Classical `model_runtime` executor for registry online scoring descriptors.
//!
//! `runtime.engine = "onnx"` verifies a signed registry descriptor and the
//! embedded version manifest against trusted registry keys, checks the artifact
//! digest, and runs an ONNX scoring runtime through [`OnnxScoringEngine`].
//! Default CI uses [`FakeOnnxEngine`]; canary and rollback stay on the ordinary
//! Tenkai release flow.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, bail};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::{
    EngineHandle, EngineStartRequest, ModelRuntimeArtifacts, ModelRuntimeDescriptor,
    ModelRuntimeExecutor, WeightCache, bind_host_from_health_endpoint, require_loopback_bind,
    require_loopback_health_endpoint,
};
use crate::manifest::ModelHealthSection;

pub const SIGNED_DESCRIPTOR_FORMAT: &str = "hinagata.signed-descriptor/v1";
pub const ONLINE_DESCRIPTOR_FORMAT: &str = "hinagata.online-descriptor/v1";
pub const VERSION_MANIFEST_FORMAT: &str = "hinagata.version-manifest/v1";
pub const SIGNATURE_ENVELOPE_FORMAT: &str = "hinagata.signature/v1";
pub const PREDICTION_SUMMARY_FORMAT: &str = "hinagata.prediction-summary/v1";
pub const SIGNED_ATTESTATION_FORMAT: &str = "hinagata.signed-attestation/v1";
pub const PROMOTION_ATTESTATION_FORMAT: &str = "hinagata.promotion-attestation/v1";
pub const TRUSTED_KEYS_ENV: &str = "TENKAI_MODEL_REGISTRY_TRUSTED_KEYS";
pub const MONITORING_BASE_ENV: &str = "TENKAI_MODEL_REGISTRY_URL";

/// Registry Ed25519 keys a classical executor will accept, keyed by `key_id`.
#[derive(Clone, Default)]
pub struct RegistryTrust {
    keys: BTreeMap<String, VerifyingKey>,
}

impl RegistryTrust {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_json(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct File {
            keys: Vec<Entry>,
        }
        #[derive(Deserialize)]
        struct Entry {
            key_id: String,
            public_key: String,
        }
        let file: File = serde_json::from_str(text).context("parsing trusted registry keys")?;
        let mut keys = BTreeMap::new();
        for entry in file.keys {
            if entry.key_id.is_empty() {
                bail!("trusted registry key_id must not be empty");
            }
            let raw = parse_hex32(&format!("public key `{}`", entry.key_id), &entry.public_key)?;
            let key = VerifyingKey::from_bytes(&raw).map_err(|_| {
                anyhow::anyhow!("public key `{}` is not a valid Ed25519 key", entry.key_id)
            })?;
            if key.is_weak() {
                bail!(
                    "public key `{}` is weak and cannot be trusted",
                    entry.key_id
                );
            }
            if keys.insert(entry.key_id.clone(), key).is_some() {
                bail!("trusted registry key `{}` is listed twice", entry.key_id);
            }
        }
        Ok(Self { keys })
    }

    pub fn from_env() -> Result<Self> {
        let Some(path) = crate::host_env::var(TRUSTED_KEYS_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(Self::empty());
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading trusted registry keys from {path}"))?;
        Self::from_json(&text)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn verifying_key(&self, key_id: &str) -> Result<&VerifyingKey> {
        self.keys
            .get(key_id)
            .with_context(|| format!("registry key `{key_id}` is not trusted"))
    }
}

fn parse_hex32(label: &str, text: &str) -> Result<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("{label} must be 64 hex characters");
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("{label} is not hexadecimal"))?;
    }
    Ok(bytes)
}

#[derive(Debug, Deserialize)]
struct SignedEnvelope {
    format: String,
    key_id: String,
    descriptor: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct SignedAttestationEnvelope {
    format: String,
    key_id: String,
    attestation: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct PromotionAttestation {
    format: String,
    namespace: String,
    model: String,
    version: u64,
    stage: String,
    approver: String,
    reference: String,
    artifact_digest: String,
}

#[derive(Debug, Deserialize)]
struct OnlineDescriptor {
    format: String,
    namespace: String,
    model: String,
    version: u64,
    artifact_digest: String,
    version_manifest: ManifestEnvelope,
    runtime: OnlineRuntime,
    resources: OnlineResources,
    health: OnlineHealth,
    monitoring: OnlineMonitoring,
}

#[derive(Debug, Deserialize)]
struct ManifestEnvelope {
    format: String,
    key_id: String,
    manifest: String,
    signature: String,
    metadata: String,
}

#[derive(Debug, Deserialize)]
struct VersionManifest {
    format: String,
    namespace: String,
    model: String,
    version: u64,
    artifact_digest: String,
    metadata_digest: String,
}

#[derive(Debug, Deserialize)]
struct OnlineRuntime {
    engine: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct OnlineResources {
    cpu_millis: u32,
    memory_mib: u32,
    replicas: u32,
}

#[derive(Debug, Deserialize)]
struct OnlineHealth {
    liveness_path: String,
    readiness_path: String,
}

#[derive(Debug, Deserialize)]
struct OnlineMonitoring {
    prediction_summaries: MonitoringEndpoint,
}

#[derive(Debug, Deserialize)]
struct MonitoringEndpoint {
    path: String,
    format: String,
}

/// Verified registry online descriptor used to start scoring.
#[derive(Debug, Clone)]
pub struct VerifiedOnlineDescriptor {
    pub namespace: String,
    pub model: String,
    pub version: u64,
    pub artifact_digest: String,
    pub resources: OnnxResources,
    pub liveness_path: String,
    pub readiness_path: String,
    pub prediction_summaries_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnnxResources {
    pub cpu_millis: u32,
    pub memory_mib: u32,
    pub replicas: u32,
}

/// Start request for one classical scoring candidate.
pub struct OnnxEngineRequest {
    pub start: EngineStartRequest,
    pub resources: OnnxResources,
    pub liveness_path: String,
    pub readiness_path: String,
}

/// Injected ONNX scoring runtime. Tenkai never links a scoring binary.
pub trait OnnxScoringEngine: Send + Sync {
    fn start_candidate(&self, request: &OnnxEngineRequest) -> Result<EngineHandle>;
    fn smoke(&self, handle: &EngineHandle, health: &ModelHealthSection) -> Result<()>;
    fn stop(&self, handle: &EngineHandle) -> Result<()>;
    fn prediction_summary(&self, handle: &EngineHandle) -> Result<serde_json::Value>;
}

/// Deterministic fake scoring runtime for CI. No sockets, no processes.
#[derive(Debug, Default)]
pub struct FakeOnnxEngine {
    pub fail_smoke: bool,
    pub fail_start: bool,
    pub last_resources: Mutex<Option<OnnxResources>>,
}

impl OnnxScoringEngine for FakeOnnxEngine {
    fn start_candidate(&self, request: &OnnxEngineRequest) -> Result<EngineHandle> {
        require_loopback_bind(&request.start.bind_host, request.start.port)?;
        if request.start.engine != "onnx" {
            bail!(
                "classical executor supports runtime.engine=onnx only, got {}",
                request.start.engine
            );
        }
        if self.fail_start {
            bail!(
                "fake onnx engine refused to start candidate generation {}",
                request.start.generation_id
            );
        }
        if request.resources.cpu_millis == 0
            || request.resources.memory_mib == 0
            || request.resources.replicas == 0
        {
            bail!("onnx scoring resources must be non-zero");
        }
        *self.last_resources.lock().expect("fake onnx resources") = Some(request.resources);
        Ok(EngineHandle {
            generation_id: request.start.generation_id.clone(),
            port: request.start.port,
            bind_host: request.start.bind_host.clone(),
            marker: format!("fake-onnx:{}", request.start.generation_id),
        })
    }

    fn smoke(&self, handle: &EngineHandle, health: &ModelHealthSection) -> Result<()> {
        require_loopback_health_endpoint(&health.endpoint)?;
        if self.fail_smoke {
            bail!(
                "fake onnx engine smoke failed for generation {} at {}",
                handle.generation_id,
                health.endpoint
            );
        }
        Ok(())
    }

    fn stop(&self, _handle: &EngineHandle) -> Result<()> {
        Ok(())
    }

    fn prediction_summary(&self, handle: &EngineHandle) -> Result<serde_json::Value> {
        Ok(json!({
            "format": PREDICTION_SUMMARY_FORMAT,
            "summary_id": format!("{}/replica-1", handle.generation_id),
            "window_start_ms": 0,
            "window_end_ms": 1,
            "prediction_count": 0,
            "latency_p50_ms": 0.0,
            "latency_p95_ms": 0.0,
            "features": {},
            "outputs": {},
        }))
    }
}

/// Where prediction summaries are exported (the descriptor monitoring path).
pub trait PredictionSummarySink: Send + Sync {
    fn export(&self, path: &str, summary: &serde_json::Value) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct RecordingSummarySink {
    pub exports: Mutex<Vec<(String, serde_json::Value)>>,
}

impl PredictionSummarySink for RecordingSummarySink {
    fn export(&self, path: &str, summary: &serde_json::Value) -> Result<()> {
        self.exports
            .lock()
            .expect("recording summary sink")
            .push((path.to_string(), summary.clone()));
        Ok(())
    }
}

struct HttpSummarySink {
    base: String,
}

impl PredictionSummarySink for HttpSummarySink {
    fn export(&self, path: &str, summary: &serde_json::Value) -> Result<()> {
        let url = format!("{}{path}", self.base.trim_end_matches('/'));
        let client = crate::outbound_tls::blocking_client()?
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("building registry monitoring client")?;
        let response = client
            .post(&url)
            .json(summary)
            .send()
            .with_context(|| format!("exporting prediction summary to {url}"))?;
        if !response.status().is_success() {
            bail!(
                "prediction summary export to {url} returned {}",
                response.status()
            );
        }
        Ok(())
    }
}

/// Verify weights → start candidate → smoke → activate, retaining the previous
/// generation for Tenkai rollback. Prediction summaries are exported to the
/// descriptor monitoring path after activation.
pub struct ClassicalOnnxExecutor {
    state_path: PathBuf,
    workdir: PathBuf,
    weight_cache: Option<WeightCache>,
    engine: Arc<dyn OnnxScoringEngine>,
    trust: RegistryTrust,
    sink: Arc<dyn PredictionSummarySink>,
}

impl ClassicalOnnxExecutor {
    pub fn new(
        state_path: PathBuf,
        workdir: PathBuf,
        engine: Arc<dyn OnnxScoringEngine>,
        trust: RegistryTrust,
        sink: Arc<dyn PredictionSummarySink>,
    ) -> Self {
        Self {
            state_path,
            workdir,
            weight_cache: None,
            engine,
            trust,
            sink,
        }
    }

    pub fn with_fake(state_path: PathBuf, workdir: PathBuf, trust: RegistryTrust) -> Self {
        Self::new(
            state_path,
            workdir,
            Arc::new(FakeOnnxEngine::default()),
            trust,
            Arc::new(RecordingSummarySink::default()),
        )
    }

    /// Operator host: fake scoring engine (CI/community default, matching
    /// [`super::ReferenceLlamaCppExecutor::for_operator_host`]), optional HTTP
    /// monitoring export, trusted keys from [`TRUSTED_KEYS_ENV`]. A malformed
    /// keys file fails here so apply never treats a parse error as "no keys
    /// configured".
    pub fn for_operator_host(
        state_path: PathBuf,
        workdir: PathBuf,
        artifacts: Option<ModelRuntimeArtifacts>,
    ) -> Result<Self> {
        let trust = RegistryTrust::from_env()?;
        let sink: Arc<dyn PredictionSummarySink> = match crate::host_env::var(MONITORING_BASE_ENV) {
            Ok(base) if !base.trim().is_empty() => Arc::new(HttpSummarySink { base }),
            _ => Arc::new(RecordingSummarySink::default()),
        };
        let mut executor = Self::new(
            state_path.clone(),
            workdir,
            Arc::new(FakeOnnxEngine::default()),
            trust,
            sink,
        );
        let cache_root = crate::host_env::var_os("TENKAI_WEIGHT_CACHE")
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| state_path.with_extension("weights"));
        let cache = match artifacts {
            Some(artifacts) => WeightCache::new(cache_root).with_environment(artifacts),
            None => WeightCache::new(cache_root),
        };
        executor.weight_cache = Some(cache);
        Ok(executor)
    }

    pub fn with_weight_cache(mut self, cache: WeightCache) -> Self {
        self.weight_cache = Some(cache);
        self
    }

    fn previous_path(&self) -> PathBuf {
        self.state_path.with_extension("json.previous")
    }

    fn active_handle_path(&self) -> PathBuf {
        self.state_path.with_extension("engine.json")
    }

    fn summary_sidecar_path(&self) -> PathBuf {
        self.state_path.with_extension("prediction-summary.json")
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

    fn write_handle(&self, handle: &EngineHandle) -> Result<()> {
        crate::atomic_state::write_json_verified(
            &self.active_handle_path(),
            handle,
            |observed: &EngineHandle| {
                if observed.generation_id != handle.generation_id {
                    bail!("model_runtime engine handle post-mutation verification failed");
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
        crate::atomic_state::read_json_optional(path)
    }

    fn verify_registry(
        &self,
        descriptor: &ModelRuntimeDescriptor,
    ) -> Result<VerifiedOnlineDescriptor> {
        if self.trust.is_empty() {
            bail!("model_runtime engine onnx requires trusted registry keys ({TRUSTED_KEYS_ENV})");
        }
        let path = self.workdir.join(&descriptor.model.registry_descriptor);
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "reading signed registry descriptor {}",
                descriptor.model.registry_descriptor
            )
        })?;
        verify_signed_online_descriptor(&bytes, &self.trust, &descriptor.model.artifact_digest)
    }
}

impl ModelRuntimeExecutor for ClassicalOnnxExecutor {
    fn apply(&self, descriptor: &ModelRuntimeDescriptor) -> Result<String> {
        descriptor.validate()?;
        if descriptor.runtime.engine != "onnx" {
            bail!(
                "ClassicalOnnxExecutor requires runtime.engine=onnx, got {}",
                descriptor.runtime.engine
            );
        }
        let verified = self.verify_registry(descriptor)?;
        require_descriptor_health(descriptor, &verified)?;

        let weights_path = if let Some(cache) = &self.weight_cache {
            Some(cache.fetch_and_verify(&descriptor.model)?)
        } else {
            None
        };

        let previous_active = Self::load_descriptor(&self.state_path)?;
        let previous_handle = Self::load_handle(&self.active_handle_path())?;
        let expected = descriptor.digest()?;
        let bind_host = bind_host_from_health_endpoint(&descriptor.health.endpoint)?;
        let start = EngineStartRequest {
            product_name: descriptor.product_name.clone(),
            product_version: descriptor.product_version.clone(),
            weights_path,
            port: descriptor.runtime.port,
            bind_host,
            engine: descriptor.runtime.engine.clone(),
            health_endpoint: descriptor.health.endpoint.clone(),
            generation_id: expected.clone(),
        };
        let request = OnnxEngineRequest {
            start,
            resources: verified.resources,
            liveness_path: verified.liveness_path.clone(),
            readiness_path: verified.readiness_path.clone(),
        };

        let candidate = match self.engine.start_candidate(&request) {
            Ok(handle) => handle,
            Err(error) => {
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

        let summary = match self.engine.prediction_summary(&candidate) {
            Ok(summary) => summary,
            Err(error) => {
                let _ = self.engine.stop(&candidate);
                return Err(error).context(
                    "model_runtime prediction summary failed; candidate stopped and previous generation retained",
                );
            }
        };
        if let Err(error) = self
            .sink
            .export(&verified.prediction_summaries_path, &summary)
            .context("exporting prediction summaries to the registry monitoring path")
        {
            let _ = self.engine.stop(&candidate);
            return Err(error).context(
                "model_runtime prediction summary export failed; candidate stopped and previous generation retained",
            );
        }
        let sidecar = json!({
            "path": verified.prediction_summaries_path,
            "summary": summary,
        });
        if let Err(error) = crate::atomic_state::write_json_verified(
            &self.summary_sidecar_path(),
            &sidecar,
            |_: &serde_json::Value| Ok(()),
        ) {
            let _ = self.engine.stop(&candidate);
            return Err(error).context(
                "model_runtime prediction summary sidecar write failed; candidate stopped and previous generation retained",
            );
        }

        if let Some(prev) = previous_active.as_ref()
            && let Err(error) = self.write_descriptor(&self.previous_path(), prev)
        {
            let _ = self.engine.stop(&candidate);
            return Err(error);
        }
        if let Err(error) = self.write_descriptor(&self.state_path, descriptor) {
            let _ = self.engine.stop(&candidate);
            return Err(error);
        }
        if let Err(error) = self.write_handle(&candidate) {
            let _ = self.engine.stop(&candidate);
            if let Some(prev) = previous_active.as_ref() {
                let _ = self.write_descriptor(&self.state_path, prev);
            } else {
                let _ = crate::atomic_state::remove_if_exists(&self.state_path);
            }
            return Err(error);
        }

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
        let _ = std::fs::remove_file(self.summary_sidecar_path());
        crate::atomic_state::remove_if_exists(&self.state_path)
    }

    fn observe(&self) -> Result<Option<String>> {
        Self::load_descriptor(&self.state_path)?
            .map(|descriptor| descriptor.digest())
            .transpose()
    }
}

fn require_descriptor_health(
    descriptor: &ModelRuntimeDescriptor,
    verified: &VerifiedOnlineDescriptor,
) -> Result<()> {
    require_loopback_health_endpoint(&descriptor.health.endpoint)?;
    if !descriptor
        .health
        .endpoint
        .ends_with(&verified.readiness_path)
    {
        bail!(
            "health.endpoint must use the registry readiness path {}, got {}",
            verified.readiness_path,
            descriptor.health.endpoint
        );
    }
    Ok(())
}

fn verify_signed_online_descriptor(
    bytes: &[u8],
    trust: &RegistryTrust,
    expected_digest: &str,
) -> Result<VerifiedOnlineDescriptor> {
    let envelope: SignedEnvelope =
        serde_json::from_slice(bytes).context("parsing signed registry descriptor")?;
    if envelope.format != SIGNED_DESCRIPTOR_FORMAT {
        bail!(
            "registry descriptor format must be {SIGNED_DESCRIPTOR_FORMAT}, got {}",
            envelope.format
        );
    }
    let key = trust.verifying_key(&envelope.key_id)?;
    crate::signature_verification::verify_strict(
        key,
        "registry descriptor signature",
        &envelope.signature,
        envelope.descriptor.as_bytes(),
    )?;
    let online: OnlineDescriptor =
        serde_json::from_str(&envelope.descriptor).context("parsing registry online descriptor")?;
    if online.format != ONLINE_DESCRIPTOR_FORMAT {
        bail!(
            "online descriptor format must be {ONLINE_DESCRIPTOR_FORMAT}, got {}",
            online.format
        );
    }
    if online.runtime.engine != "onnx" {
        bail!(
            "online descriptor runtime.engine must be onnx, got {}",
            online.runtime.engine
        );
    }
    if online.health.liveness_path != "/healthz" || online.health.readiness_path != "/readyz" {
        bail!("online descriptor health paths must be /healthz and /readyz");
    }
    if online.resources.cpu_millis == 0
        || online.resources.memory_mib == 0
        || online.resources.replicas == 0
    {
        bail!("online descriptor resources must be non-zero");
    }
    if online.artifact_digest != expected_digest {
        bail!(
            "registry descriptor artifact_digest {} does not match model.artifact_digest {expected_digest}",
            online.artifact_digest
        );
    }
    verify_version_manifest(&online, trust)?;
    if online.monitoring.prediction_summaries.format != PREDICTION_SUMMARY_FORMAT {
        bail!(
            "prediction summary format must be {PREDICTION_SUMMARY_FORMAT}, got {}",
            online.monitoring.prediction_summaries.format
        );
    }
    if !online
        .monitoring
        .prediction_summaries
        .path
        .starts_with("/v1/")
    {
        bail!(
            "prediction summary path must be a registry /v1/ path, got {}",
            online.monitoring.prediction_summaries.path
        );
    }
    Ok(VerifiedOnlineDescriptor {
        namespace: online.namespace,
        model: online.model,
        version: online.version,
        artifact_digest: online.artifact_digest,
        resources: OnnxResources {
            cpu_millis: online.resources.cpu_millis,
            memory_mib: online.resources.memory_mib,
            replicas: online.resources.replicas,
        },
        liveness_path: online.health.liveness_path,
        readiness_path: online.health.readiness_path,
        prediction_summaries_path: online.monitoring.prediction_summaries.path,
    })
}

fn verify_version_manifest(online: &OnlineDescriptor, trust: &RegistryTrust) -> Result<()> {
    let envelope = &online.version_manifest;
    if envelope.format != SIGNATURE_ENVELOPE_FORMAT {
        bail!(
            "version manifest format must be {SIGNATURE_ENVELOPE_FORMAT}, got {}",
            envelope.format
        );
    }
    let key = trust.verifying_key(&envelope.key_id)?;
    crate::signature_verification::verify_strict(
        key,
        "registry version manifest signature",
        &envelope.signature,
        envelope.manifest.as_bytes(),
    )?;
    let manifest: VersionManifest =
        serde_json::from_str(&envelope.manifest).context("parsing registry version manifest")?;
    if manifest.format != VERSION_MANIFEST_FORMAT {
        bail!(
            "version manifest format must be {VERSION_MANIFEST_FORMAT}, got {}",
            manifest.format
        );
    }
    if manifest.artifact_digest != online.artifact_digest {
        bail!("version manifest artifact_digest does not match the online descriptor");
    }
    if manifest.namespace != online.namespace
        || manifest.model != online.model
        || manifest.version != online.version
    {
        bail!("version manifest identity does not match the online descriptor");
    }
    let metadata_digest = format!("sha256:{:x}", Sha256::digest(envelope.metadata.as_bytes()));
    if metadata_digest != manifest.metadata_digest {
        bail!("version manifest metadata_digest does not match the metadata bytes");
    }
    let metadata: serde_json::Value =
        serde_json::from_str(&envelope.metadata).context("parsing version metadata")?;
    let metadata_digest_field = metadata
        .get("artifact_digest")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if metadata_digest_field != online.artifact_digest {
        bail!("version metadata artifact_digest does not match the online descriptor");
    }
    Ok(())
}

fn blocked(reason: &str) -> anyhow::Error {
    anyhow::anyhow!("classical model promotion blocked: {reason}")
}

/// Admit classical model channel promotion from a signed registry attestation.
pub fn require_classical_promotion_attestation(
    descriptor: &ModelRuntimeDescriptor,
    workdir: &Path,
    trust: &RegistryTrust,
) -> Result<()> {
    if descriptor.runtime.engine != "onnx" {
        return Ok(());
    }
    if trust.is_empty() {
        return Err(blocked(&format!(
            "trusted registry keys missing ({TRUSTED_KEYS_ENV})"
        )));
    }
    if descriptor.model.registry_attestation.is_empty() {
        return Err(blocked("registry promotion attestation missing"));
    }
    let descriptor_path = workdir.join(&descriptor.model.registry_descriptor);
    let descriptor_bytes = std::fs::read(&descriptor_path).map_err(|_| {
        blocked(&format!(
            "registry promotion attestation missing (signed descriptor {})",
            descriptor.model.registry_descriptor
        ))
    })?;
    let online = verify_signed_online_descriptor(
        &descriptor_bytes,
        trust,
        &descriptor.model.artifact_digest,
    )
    .map_err(|error| blocked(&format!("registry descriptor invalid ({error})")))?;
    let attestation_path = workdir.join(&descriptor.model.registry_attestation);
    let attestation_bytes = match std::fs::read(&attestation_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(blocked(&format!(
                "registry promotion attestation missing ({})",
                descriptor.model.registry_attestation
            )));
        }
    };
    verify_signed_promotion_attestation(&attestation_bytes, trust, &online)
}

fn verify_signed_promotion_attestation(
    bytes: &[u8],
    trust: &RegistryTrust,
    expected: &VerifiedOnlineDescriptor,
) -> Result<()> {
    let envelope: SignedAttestationEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| blocked(&format!("registry promotion attestation invalid ({error})")))?;
    if envelope.format != SIGNED_ATTESTATION_FORMAT {
        return Err(blocked(&format!(
            "registry promotion attestation invalid (format must be {SIGNED_ATTESTATION_FORMAT}, got {})",
            envelope.format
        )));
    }
    let key = trust
        .verifying_key(&envelope.key_id)
        .map_err(|error| blocked(&format!("registry promotion attestation invalid ({error})")))?;
    crate::signature_verification::verify_strict(
        key,
        "registry promotion attestation signature",
        &envelope.signature,
        envelope.attestation.as_bytes(),
    )
    .map_err(|error| blocked(&format!("registry promotion attestation invalid ({error})")))?;
    let attestation: PromotionAttestation = serde_json::from_str(&envelope.attestation)
        .map_err(|error| blocked(&format!("registry promotion attestation invalid ({error})")))?;
    if attestation.format != PROMOTION_ATTESTATION_FORMAT {
        return Err(blocked(&format!(
            "registry promotion attestation invalid (format must be {PROMOTION_ATTESTATION_FORMAT}, got {})",
            attestation.format
        )));
    }
    if attestation.approver.trim().is_empty() || attestation.reference.trim().is_empty() {
        return Err(blocked(
            "registry promotion attestation invalid (approver and reference are required)",
        ));
    }
    if attestation.stage == "archived" {
        return Err(blocked(
            "registry promotion attestation expired (stage archived)",
        ));
    }
    if attestation.stage != "production" {
        return Err(blocked(&format!(
            "registry promotion attestation mismatch: stage expected production got {}",
            attestation.stage
        )));
    }
    if attestation.namespace != expected.namespace {
        return Err(blocked(&format!(
            "registry promotion attestation mismatch: namespace expected {} got {}",
            expected.namespace, attestation.namespace
        )));
    }
    if attestation.model != expected.model {
        return Err(blocked(&format!(
            "registry promotion attestation mismatch: model expected {} got {}",
            expected.model, attestation.model
        )));
    }
    if attestation.version != expected.version {
        return Err(blocked(&format!(
            "registry promotion attestation mismatch: version expected {} got {}",
            expected.version, attestation.version
        )));
    }
    if attestation.artifact_digest != expected.artifact_digest {
        return Err(blocked(&format!(
            "registry promotion attestation mismatch: artifact_digest expected {} got {}",
            expected.artifact_digest, attestation.artifact_digest
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        ModelHealthSection, ModelRequirementsSection, ModelRuntimeSection, ModelSection,
    };
    use crate::model_runtime::MODEL_RUNTIME_CONTRACT_VERSION;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    const SEED: [u8; 32] = [7u8; 32];
    const KEY_ID: &str = "registry-1";

    fn public_hex(seed: [u8; 32]) -> String {
        SigningKey::from_bytes(&seed)
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn sign(seed: [u8; 32], bytes: &[u8]) -> String {
        let signature = SigningKey::from_bytes(&seed).sign(bytes);
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    }

    fn trust() -> RegistryTrust {
        RegistryTrust::from_json(&format!(
            r#"{{"keys":[{{"key_id":"{KEY_ID}","public_key":"{}"}}]}}"#,
            public_hex(SEED)
        ))
        .unwrap()
    }

    fn canonical(value: &serde_json::Value) -> String {
        serde_json::to_string(value).unwrap()
    }

    fn signed_online(artifact_digest: &str, version: u64) -> (Vec<u8>, serde_json::Value) {
        let metadata = json!({
            "artifact_digest": artifact_digest,
            "binding": null,
            "format": "onnx",
            "framework": "lightgbm",
            "lineage": {
                "code": {"commit": "", "digest": "", "repository": ""},
                "parameters": {},
                "run_receipt_digest": "",
                "run_receipt_id": "",
                "training_datasets": []
            },
            "metrics": {},
            "signature": {
                "inputs": [{"dtype": "float32", "name": "features", "nullable": false, "shape": [-1, 3]}],
                "outputs": [{"dtype": "float32", "name": "score", "nullable": false, "shape": [-1, 1]}]
            },
            "tags": {}
        });
        let metadata_bytes = canonical(&metadata);
        let manifest = json!({
            "artifact_digest": artifact_digest,
            "format": VERSION_MANIFEST_FORMAT,
            "metadata_digest": format!("sha256:{:x}", Sha256::digest(metadata_bytes.as_bytes())),
            "model": "churn",
            "namespace": "tenant-a",
            "version": version,
        });
        let manifest_bytes = canonical(&manifest);
        let version_manifest = json!({
            "format": SIGNATURE_ENVELOPE_FORMAT,
            "key_id": KEY_ID,
            "manifest": manifest_bytes,
            "metadata": metadata_bytes,
            "signature": sign(SEED, manifest_bytes.as_bytes()),
        });
        let online = json!({
            "artifact_digest": artifact_digest,
            "format": ONLINE_DESCRIPTOR_FORMAT,
            "health": {"liveness_path": "/healthz", "readiness_path": "/readyz"},
            "model": "churn",
            "monitoring": {
                "labeled_aggregates": {
                    "format": "hinagata.labeled-aggregate/v1",
                    "path": format!("/v1/models/churn/versions/{version}/labeled-aggregates"),
                },
                "prediction_summaries": {
                    "format": PREDICTION_SUMMARY_FORMAT,
                    "path": format!("/v1/models/churn/versions/{version}/prediction-summaries"),
                }
            },
            "namespace": "tenant-a",
            "resources": {"cpu_millis": 1000, "memory_mib": 512, "replicas": 1},
            "runtime": {"engine": "onnx", "image": ""},
            "signature": {
                "inputs": [{"dtype": "float32", "name": "features", "nullable": false, "shape": [-1, 3]}],
                "outputs": [{"dtype": "float32", "name": "score", "nullable": false, "shape": [-1, 1]}]
            },
            "version": version,
            "version_manifest": version_manifest,
        });
        let descriptor_bytes = canonical(&online);
        let envelope = json!({
            "descriptor": descriptor_bytes,
            "format": SIGNED_DESCRIPTOR_FORMAT,
            "key_id": KEY_ID,
            "signature": sign(SEED, descriptor_bytes.as_bytes()),
        });
        (serde_json::to_vec_pretty(&envelope).unwrap(), online)
    }

    fn signed_attestation(artifact_digest: &str, version: u64, stage: &str) -> Vec<u8> {
        let attestation = canonical(&json!({
            "approver": "alice@governance",
            "artifact_digest": artifact_digest,
            "format": PROMOTION_ATTESTATION_FORMAT,
            "model": "churn",
            "namespace": "tenant-a",
            "reference": "CHG-1042",
            "stage": stage,
            "version": version,
        }));
        let envelope = json!({
            "attestation": attestation,
            "format": SIGNED_ATTESTATION_FORMAT,
            "key_id": KEY_ID,
            "signature": sign(SEED, attestation.as_bytes()),
        });
        serde_json::to_vec_pretty(&envelope).unwrap()
    }

    fn onnx_descriptor(
        weights: &Path,
        digest: &str,
        version: &str,
        registry_version: u64,
        port: u16,
    ) -> ModelRuntimeDescriptor {
        ModelRuntimeDescriptor {
            contract_version: MODEL_RUNTIME_CONTRACT_VERSION,
            product_name: "churn-scorer".into(),
            product_version: version.into(),
            model: ModelSection {
                source: format!("file://{}", weights.display()),
                revision: version.into(),
                format: "onnx".into(),
                quantization: "none".into(),
                artifact_digest: digest.into(),
                license: "proprietary".into(),
                registry_descriptor: format!("signed-descriptor-v{registry_version}.json"),
                registry_attestation: format!("promotion-attestation-v{registry_version}.json"),
            },
            runtime: ModelRuntimeSection {
                engine: "onnx".into(),
                port,
                context_length: 1,
            },
            requirements: ModelRequirementsSection {
                architecture: vec!["arm64".into(), "x86_64".into()],
                memory_gib: 1,
                accelerator: vec!["cpu".into()],
                gpu: None,
            },
            health: ModelHealthSection {
                endpoint: format!("http://127.0.0.1:{port}/readyz"),
                smoke_prompt: String::new(),
                max_startup_seconds: 30,
            },
        }
    }

    fn write_fixture(root: &Path, payload: &[u8], version: u64) -> (String, PathBuf) {
        std::fs::create_dir_all(root).unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(payload));
        let weights = root.join(format!("model-v{version}.onnx"));
        std::fs::write(&weights, payload).unwrap();
        let (envelope, _) = signed_online(&digest, version);
        std::fs::write(
            root.join(format!("signed-descriptor-v{version}.json")),
            envelope,
        )
        .unwrap();
        std::fs::write(
            root.join(format!("promotion-attestation-v{version}.json")),
            signed_attestation(&digest, version, "production"),
        )
        .unwrap();
        (digest, weights)
    }

    #[test]
    fn refuses_untrusted_or_tampered_descriptors() {
        let digest = format!("sha256:{:x}", Sha256::digest(b"fixture"));
        let (mut envelope, _) = signed_online(&digest, 1);
        verify_signed_online_descriptor(&envelope, &trust(), &digest).unwrap();

        let other = RegistryTrust::from_json(&format!(
            r#"{{"keys":[{{"key_id":"{KEY_ID}","public_key":"{}"}}]}}"#,
            public_hex([9u8; 32])
        ))
        .unwrap();
        let err = verify_signed_online_descriptor(&envelope, &other, &digest)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not trusted") || err.contains("verification failed"),
            "{err}"
        );

        let mut parsed: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
        parsed["descriptor"] = json!(format!("{} ", parsed["descriptor"].as_str().unwrap()));
        envelope = serde_json::to_vec(&parsed).unwrap();
        assert!(verify_signed_online_descriptor(&envelope, &trust(), &digest).is_err());
    }

    #[test]
    fn promotion_attestation_admits_valid_and_names_refusals() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-onnx-attest-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let (digest, weights) = write_fixture(&root, b"onnx-attest", 1);
        let descriptor = onnx_descriptor(&weights, &digest, "1.0.0", 1, 18080);
        require_classical_promotion_attestation(&descriptor, &root, &trust()).unwrap();

        let mut missing = descriptor.clone();
        missing.model.registry_attestation.clear();
        let err = require_classical_promotion_attestation(&missing, &root, &trust())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("classical model promotion blocked") && err.contains("missing"),
            "{err}"
        );

        std::fs::write(
            root.join("promotion-attestation-v1.json"),
            signed_attestation(&format!("sha256:{}", "00".repeat(32)), 1, "production"),
        )
        .unwrap();
        let err = require_classical_promotion_attestation(&descriptor, &root, &trust())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("mismatch") && err.contains("artifact_digest"),
            "{err}"
        );

        std::fs::write(
            root.join("promotion-attestation-v1.json"),
            signed_attestation(&digest, 2, "production"),
        )
        .unwrap();
        let err = require_classical_promotion_attestation(&descriptor, &root, &trust())
            .unwrap_err()
            .to_string();
        assert!(err.contains("mismatch") && err.contains("version"), "{err}");

        std::fs::write(
            root.join("promotion-attestation-v1.json"),
            signed_attestation(&digest, 1, "archived"),
        )
        .unwrap();
        let err = require_classical_promotion_attestation(&descriptor, &root, &trust())
            .unwrap_err()
            .to_string();
        assert!(err.contains("expired") && err.contains("archived"), "{err}");

        let empty = RegistryTrust::empty();
        let err = require_classical_promotion_attestation(&descriptor, &root, &empty)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("trusted registry keys missing") && err.contains(TRUSTED_KEYS_ENV),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn apply_verifies_digest_exports_summary_and_rolls_back() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-onnx-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let (v1, weights_v1) = write_fixture(&root, b"onnx-v1", 1);
        let recording = Arc::new(RecordingSummarySink::default());
        let fake = Arc::new(FakeOnnxEngine::default());
        let executor = ClassicalOnnxExecutor::new(
            root.join("active.json"),
            root.clone(),
            fake.clone(),
            trust(),
            recording.clone(),
        )
        .with_weight_cache(WeightCache::new(root.join("cache")));
        let first = onnx_descriptor(&weights_v1, &v1, "1.0.0", 1, 18080);
        let first_digest = executor.apply(&first).unwrap();
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(first_digest.as_str())
        );
        assert_eq!(
            *fake.last_resources.lock().unwrap(),
            Some(OnnxResources {
                cpu_millis: 1000,
                memory_mib: 512,
                replicas: 1,
            })
        );
        let exports = recording.exports.lock().unwrap();
        assert_eq!(exports.len(), 1);
        assert_eq!(
            exports[0].0,
            "/v1/models/churn/versions/1/prediction-summaries"
        );
        assert_eq!(exports[0].1["format"], PREDICTION_SUMMARY_FORMAT);
        drop(exports);
        let sidecar: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("active.prediction-summary.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            sidecar["path"],
            "/v1/models/churn/versions/1/prediction-summaries"
        );

        let (v2, weights_v2) = write_fixture(&root, b"onnx-v2", 2);
        let second = onnx_descriptor(&weights_v2, &v2, "2.0.0", 2, 18081);
        let second_digest = executor.apply(&second).unwrap();
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(second_digest.as_str())
        );
        let previous: ModelRuntimeDescriptor =
            serde_json::from_slice(&std::fs::read(root.join("active.json.previous")).unwrap())
                .unwrap();
        assert_eq!(previous.digest().unwrap(), first_digest);
        assert_eq!(executor.apply(&first).unwrap(), first_digest);

        let mismatch = onnx_descriptor(&weights_v1, &v1, "9.9.9", 1, 18082);
        let mut bad = mismatch;
        bad.model.artifact_digest = format!("sha256:{}", "00".repeat(32));
        let err = executor.apply(&bad).unwrap_err().to_string();
        assert!(
            err.contains("artifact_digest") || err.contains("digest mismatch"),
            "{err}"
        );
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(first_digest.as_str())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn smoke_failure_retains_active_generation() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-onnx-smoke-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let (digest, weights) = write_fixture(&root, b"onnx-ok", 1);
        let ok = ClassicalOnnxExecutor::with_fake(root.join("active.json"), root.clone(), trust())
            .with_weight_cache(WeightCache::new(root.join("cache-ok")));
        let good = onnx_descriptor(&weights, &digest, "1.0.0", 1, 18080);
        let active = ok.apply(&good).unwrap();
        let failing = ClassicalOnnxExecutor::new(
            root.join("active.json"),
            root.clone(),
            Arc::new(FakeOnnxEngine {
                fail_smoke: true,
                fail_start: false,
                last_resources: Mutex::new(None),
            }),
            trust(),
            Arc::new(RecordingSummarySink::default()),
        )
        .with_weight_cache(WeightCache::new(root.join("cache-fail")));
        let mut bad = onnx_descriptor(&weights, &digest, "9.9.9", 1, 18080);
        bad.product_version = "9.9.9".into();
        let err = failing.apply(&bad).unwrap_err().to_string();
        assert!(
            err.contains("smoke failed") || err.contains("retained"),
            "{err}"
        );
        assert_eq!(ok.observe().unwrap().as_deref(), Some(active.as_str()));
        let _ = std::fs::remove_dir_all(root);
    }

    struct FailingSummarySink;

    impl PredictionSummarySink for FailingSummarySink {
        fn export(&self, _path: &str, _summary: &serde_json::Value) -> Result<()> {
            bail!("registry monitoring unavailable");
        }
    }

    #[test]
    fn export_failure_retains_active_generation() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-onnx-export-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let (digest, weights) = write_fixture(&root, b"onnx-ok", 1);
        let ok = ClassicalOnnxExecutor::with_fake(root.join("active.json"), root.clone(), trust())
            .with_weight_cache(WeightCache::new(root.join("cache-ok")));
        let good = onnx_descriptor(&weights, &digest, "1.0.0", 1, 18080);
        let active = ok.apply(&good).unwrap();
        let failing = ClassicalOnnxExecutor::new(
            root.join("active.json"),
            root.clone(),
            Arc::new(FakeOnnxEngine::default()),
            trust(),
            Arc::new(FailingSummarySink),
        )
        .with_weight_cache(WeightCache::new(root.join("cache-fail")));
        let mut next = onnx_descriptor(&weights, &digest, "9.9.9", 1, 18080);
        next.product_version = "9.9.9".into();
        let err = failing.apply(&next).unwrap_err().to_string();
        assert!(
            err.contains("prediction summary export failed") || err.contains("retained"),
            "{err}"
        );
        assert_eq!(ok.observe().unwrap().as_deref(), Some(active.as_str()));
        let _ = std::fs::remove_dir_all(root);
    }

    fn write_manifest(
        dir: &Path,
        version: &str,
        digest: &str,
        weights: &Path,
        registry_version: u64,
    ) {
        let body = format!(
            r#"[product]
name = "churn-scorer"
version = "{version}"
kind = "model_runtime"
description = "classical onnx fixture"

[model]
source = "file://{weights}"
revision = "{version}"
format = "onnx"
quantization = "none"
artifact_digest = "{digest}"
license = "proprietary"
registry_descriptor = "signed-descriptor-v{registry_version}.json"
registry_attestation = "promotion-attestation-v{registry_version}.json"

[runtime]
engine = "onnx"
port = 18080
context_length = 1

[requirements]
architecture = ["arm64", "x86_64"]
memory_gib = 1
accelerator = ["cpu"]

[health]
endpoint = "http://127.0.0.1:18080/readyz"
max_startup_seconds = 30
"#,
            weights = weights.display()
        );
        std::fs::write(dir.join("tenkai.toml"), body).unwrap();
    }

    async fn publish_unsigned(ctx: &mut crate::client::Ctx, dir: &Path) -> String {
        crate::catalog::publish(
            ctx,
            &dir.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                signature: None,
                trust_roots: None,
                allow_unsigned_development: true,
                provenance: Vec::new(),
                provenance_trust_roots: None,
                change_set_evidence: None,
                artifact_registry: None,
                state_dir: None,
            },
        )
        .await
        .unwrap()
    }

    async fn apply_local(ctx: &mut crate::client::Ctx, product: &str, channel: &str) -> String {
        crate::plan::subscribe(ctx, "local", product, channel)
            .await
            .unwrap();
        crate::plan::set_environment_fact(ctx, "local", "architecture", "arm64")
            .await
            .unwrap();
        crate::plan::set_environment_fact(ctx, "local", "accelerator", "cpu")
            .await
            .unwrap();
        crate::plan::set_environment_fact(ctx, "local", "memory_gib", "16")
            .await
            .unwrap();
        let plan = crate::plan::create(ctx, "local").await.unwrap();
        let plan_id = plan.id.clone();
        crate::apply::execute_with_options(
            ctx,
            &plan_id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "classical onnx lab fixture",
                },
                software_executor: None,
                model_runtime_executor: None,
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        plan_id
    }

    #[tokio::test]
    async fn lab_register_deploy_canary_promote_rollback_and_digest_mismatch() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-onnx-lab-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let manifest_dir = root.join("model");
        let keys_path = root.join("registry.keys.json");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        std::fs::write(
            &keys_path,
            format!(
                r#"{{"keys":[{{"key_id":"{KEY_ID}","public_key":"{}"}}]}}"#,
                public_hex(SEED)
            ),
        )
        .unwrap();
        let _env = crate::host_env::overlay::set([
            (TRUSTED_KEYS_ENV, Some(keys_path.as_os_str())),
            (MONITORING_BASE_ENV, None),
        ]);

        let (digest_v1, weights_v1) = write_fixture(&manifest_dir, b"onnx-lab-v1", 1);
        write_manifest(&manifest_dir, "1.0.0", &digest_v1, &weights_v1, 1);

        let mut ctx = crate::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "onnx lab host")
            .await
            .unwrap();
        publish_unsigned(&mut ctx, &manifest_dir).await;
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut ctx,
            "churn-scorer@1.0.0",
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("onnx-lab");
        crate::catalog::promote(&mut ctx, &actor, "churn-scorer@1.0.0", "canary")
            .await
            .unwrap();
        crate::canary::set_designated(&mut ctx, &actor, "local", true)
            .await
            .unwrap();
        crate::canary::configure(
            &mut ctx,
            &actor,
            "churn-scorer@1.0.0",
            "stable",
            vec!["local".into()],
            false,
        )
        .await
        .unwrap();
        apply_local(&mut ctx, "churn-scorer", "canary").await;
        let promoted = crate::catalog::promote(&mut ctx, &actor, "churn-scorer@1.0.0", "stable")
            .await
            .unwrap();
        assert!(promoted.contains("stable"), "{promoted}");

        let (digest_v2, weights_v2) = write_fixture(&manifest_dir, b"onnx-lab-v2", 2);
        write_manifest(&manifest_dir, "2.0.0", &digest_v2, &weights_v2, 2);
        publish_unsigned(&mut ctx, &manifest_dir).await;
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut ctx,
            "churn-scorer@2.0.0",
        )
        .await
        .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "churn-scorer@2.0.0", "canary")
            .await
            .unwrap();
        apply_local(&mut ctx, "churn-scorer", "canary").await;

        let status = crate::environment::status(&mut ctx, "local").await.unwrap();
        let deployed = status
            .iter()
            .find(|row| row.product == "churn-scorer")
            .and_then(|row| row.deployed.as_deref());
        assert_eq!(deployed, Some("2.0.0"), "{status:?}");

        let rollback_step = crate::plan::rollback_step(&mut ctx, "local", "churn-scorer")
            .await
            .unwrap();
        let rollback = crate::plan::create_from_steps(&mut ctx, "local", vec![rollback_step])
            .await
            .unwrap();
        crate::apply::execute_with_options(
            &mut ctx,
            &rollback.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "classical onnx lab rollback",
                },
                software_executor: None,
                model_runtime_executor: None,
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        let status = crate::environment::status(&mut ctx, "local").await.unwrap();
        let deployed = status
            .iter()
            .find(|row| row.product == "churn-scorer")
            .and_then(|row| row.deployed.as_deref());
        assert_eq!(deployed, Some("1.0.0"), "{status:?}");

        let (mismatch, weights_bad) = write_fixture(&manifest_dir, b"onnx-lab-bad", 3);
        write_manifest(&manifest_dir, "3.0.0", &mismatch, &weights_bad, 3);
        std::fs::write(&weights_bad, b"wrong-bytes").unwrap();
        let err = crate::catalog::publish(
            &mut ctx,
            &manifest_dir.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                signature: None,
                trust_roots: None,
                allow_unsigned_development: true,
                provenance: Vec::new(),
                provenance_trust_roots: None,
                change_set_evidence: None,
                artifact_registry: None,
                state_dir: None,
            },
        )
        .await;
        // Publish hashes the signed descriptor, not the weight bytes. Apply must refuse.
        if err.is_ok() {
            crate::model_release_evidence::record_passing_evaluation_for_release(
                &mut ctx,
                "churn-scorer@3.0.0",
            )
            .await
            .unwrap();
            crate::catalog::promote(&mut ctx, &actor, "churn-scorer@3.0.0", "canary")
                .await
                .unwrap();
            crate::plan::subscribe(&mut ctx, "local", "churn-scorer", "canary")
                .await
                .unwrap();
            let apply_err = crate::plan::create(&mut ctx, "local").await.unwrap();
            let failed = crate::apply::execute_with_options(
                &mut ctx,
                &apply_err.id,
                crate::apply::ExecutionOptions {
                    skip_gates: false,
                    emergency_reason: None,
                    authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                        reason: "classical onnx digest mismatch",
                    },
                    software_executor: None,
                    model_runtime_executor: None,
                    worker_lifecycle: None,
                    artifact_registry: None,
                    delivery_adapter: None,
                    delivery_fence: None,
                },
            )
            .await;
            let mismatch_failed = match &failed {
                Err(_) => true,
                Ok(outcomes) => outcomes.iter().any(|outcome| outcome.status != "succeeded"),
            };
            assert!(
                mismatch_failed,
                "digest mismatch must fail apply: {failed:?}"
            );
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn catalog_promote_requires_named_registry_attestation() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-onnx-promote-attest-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let manifest_dir = root.join("model");
        let keys_path = root.join("registry.keys.json");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        std::fs::write(
            &keys_path,
            format!(
                r#"{{"keys":[{{"key_id":"{KEY_ID}","public_key":"{}"}}]}}"#,
                public_hex(SEED)
            ),
        )
        .unwrap();
        let _env = crate::host_env::overlay::set([
            (TRUSTED_KEYS_ENV, Some(keys_path.as_os_str())),
            (MONITORING_BASE_ENV, None),
        ]);

        let (digest, weights) = write_fixture(&manifest_dir, b"onnx-promote-v1", 1);
        let mut toml = std::fs::read_to_string({
            write_manifest(&manifest_dir, "1.0.0", &digest, &weights, 1);
            manifest_dir.join("tenkai.toml")
        })
        .unwrap();
        toml = toml.replace(
            "registry_attestation = \"promotion-attestation-v1.json\"\n",
            "",
        );
        std::fs::write(manifest_dir.join("tenkai.toml"), toml).unwrap();
        std::fs::remove_file(manifest_dir.join("promotion-attestation-v1.json")).unwrap();

        let mut ctx = crate::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        publish_unsigned(&mut ctx, &manifest_dir).await;
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut ctx,
            "churn-scorer@1.0.0",
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("onnx-attest");
        let missing = crate::catalog::promote(&mut ctx, &actor, "churn-scorer@1.0.0", "canary")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("classical model promotion blocked")
                && missing.contains("registry promotion attestation missing"),
            "{missing}"
        );

        std::fs::write(
            manifest_dir.join("promotion-attestation-v1.json"),
            signed_attestation(&format!("sha256:{}", "00".repeat(32)), 1, "production"),
        )
        .unwrap();
        write_manifest(&manifest_dir, "1.0.1", &digest, &weights, 1);
        publish_unsigned(&mut ctx, &manifest_dir).await;
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut ctx,
            "churn-scorer@1.0.1",
        )
        .await
        .unwrap();
        let mismatch = crate::catalog::promote(&mut ctx, &actor, "churn-scorer@1.0.1", "canary")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            mismatch.contains("mismatch") && mismatch.contains("artifact_digest"),
            "{mismatch}"
        );

        std::fs::write(
            manifest_dir.join("promotion-attestation-v1.json"),
            signed_attestation(&digest, 1, "production"),
        )
        .unwrap();
        write_manifest(&manifest_dir, "1.0.2", &digest, &weights, 1);
        publish_unsigned(&mut ctx, &manifest_dir).await;
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut ctx,
            "churn-scorer@1.0.2",
        )
        .await
        .unwrap();
        let workdir = {
            let release = ctx
                .get(&crate::ontology::release_id("churn-scorer", "1.0.2"))
                .await
                .unwrap()
                .unwrap();
            std::path::PathBuf::from(release.properties.get("workdir").unwrap())
        };
        std::fs::write(
            workdir.join("promotion-attestation-v1.json"),
            signed_attestation(&digest, 9, "production"),
        )
        .unwrap();
        let tampered = crate::catalog::promote(&mut ctx, &actor, "churn-scorer@1.0.2", "canary")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            tampered.contains("mismatch") && tampered.contains("snapshot artifact_digest"),
            "{tampered}"
        );
        std::fs::write(
            workdir.join("promotion-attestation-v1.json"),
            signed_attestation(&digest, 1, "production"),
        )
        .unwrap();
        let promoted = crate::catalog::promote(&mut ctx, &actor, "churn-scorer@1.0.2", "canary")
            .await
            .unwrap();
        assert!(promoted.contains("canary"), "{promoted}");
        let _ = std::fs::remove_dir_all(root);
    }
}
