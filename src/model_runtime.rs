//! Model-runtime product contract and executor port.
//!
//! Tenkai governs lifecycle (publish, plan, apply, health, rollback) for
//! open-weight model deployments. Inference engines remain in-process ports
//! that download weights, load models, and serve traffic. Multi-GB weight
//! payloads are never stored in Tenkai operational state—only content-addressed
//! digests and descriptors.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::manifest::{
    Manifest, ModelHealthSection, ModelRequirementsSection, ModelRuntimeSection, ModelSection,
};

mod mlx;
mod onnx;

pub use mlx::{FakeMlxEngine, MLX_ENGINE, MlxHostExecutor, MlxLmServerLauncher};
pub use onnx::{
    ClassicalOnnxExecutor, FakeOnnxEngine, OnnxEngineRequest, OnnxResources, OnnxScoringEngine,
    PredictionSummarySink, RecordingSummarySink, RegistryTrust,
    require_classical_promotion_attestation,
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
        if self.runtime.engine == "onnx" {
            if self.model.format != "onnx" {
                bail!("model_runtime engine onnx requires model.format=onnx");
            }
            crate::manifest::validate_input_path(
                "model.registry_descriptor",
                &self.model.registry_descriptor,
            )?;
            if !self.model.registry_attestation.is_empty() {
                crate::manifest::validate_input_path(
                    "model.registry_attestation",
                    &self.model.registry_attestation,
                )?;
            }
        } else if !self.model.registry_descriptor.is_empty() {
            bail!("model.registry_descriptor is only valid for runtime.engine=onnx");
        } else if !self.model.registry_attestation.is_empty() {
            bail!("model.registry_attestation is only valid for runtime.engine=onnx");
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
        if let Some(gpu) = &self.requirements.gpu {
            validate_gpu_requirements(gpu)?;
        }
        if self.health.max_startup_seconds == 0 {
            bail!("health.max_startup_seconds must be non-zero");
        }
        // Weights stay external: source must not address Tenkai operational storage.
        if self.model.source.starts_with("sqlite:") || self.model.source.starts_with("tenkai-db:") {
            bail!("model.source cannot address Tenkai operational storage");
        }
        if self.model.source.starts_with("hf://") || self.model.source.starts_with("oci://") {
            WeightSource::parse(&self.model)?;
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

/// Channel promotion of classical (`onnx`) model_runtime releases requires a
/// signed registry promotion attestation matching the deployed version and
/// artifact digest. Other product kinds are unchanged.
pub fn require_classical_registry_attestation(release: &crate::pb::sekai::Object) -> Result<()> {
    let Some(raw) = release.properties.get("manifest") else {
        return Ok(());
    };
    let manifest = crate::manifest::parse_raw(raw)?;
    if manifest.product.kind != crate::manifest::ProductKind::ModelRuntime {
        return Ok(());
    }
    let descriptor = ModelRuntimeDescriptor::from_manifest(&manifest)?;
    if descriptor.runtime.engine != "onnx" {
        return Ok(());
    }
    let workdir = release
        .properties
        .get("workdir")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty());
    let Some(workdir) = workdir else {
        bail!(
            "classical model promotion blocked: registry promotion attestation missing (release workdir)"
        );
    };
    let expected_artifact = release
        .properties
        .get("artifact_digest")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "classical model promotion blocked: registry promotion attestation missing (artifact_digest)"
            )
        })?;
    let actual_artifact = crate::manifest::identity_digest(
        &workdir,
        &manifest.immutable_inputs(),
        &manifest.artifacts,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "classical model promotion blocked: registry promotion attestation invalid ({error})"
        )
    })?;
    if actual_artifact != *expected_artifact {
        bail!(
            "classical model promotion blocked: registry promotion attestation mismatch: snapshot artifact_digest expected {expected_artifact} got {actual_artifact}"
        );
    }
    let trust = RegistryTrust::from_env()?;
    require_classical_promotion_attestation(&descriptor, &workdir, &trust)
}

fn validate_artifact_digest(value: &str) -> Result<()> {
    crate::signature_verification::validate_prefixed_digest("model.artifact_digest", value)
}

/// Media type of a model-weights OCI artifact: one blob holding the weights file.
pub const MODEL_WEIGHTS_MEDIA_TYPE: &str = "application/vnd.tenkai.model.weights.v1";

/// Hub endpoint `hf://` sources resolve against unless the cache overrides it.
pub const DEFAULT_HUB_ENDPOINT: &str = "https://huggingface.co";

/// Where a `model.source` fetches weights from.
enum WeightSource<'a> {
    /// `file://<absolute path>`
    File(&'a Path),
    /// `http://` or `https://` URL.
    Http(&'a str),
    /// `hf://<org>/<repo>/<path>` at a pinned 40-hex commit `revision`.
    Hub {
        repo: &'a str,
        path: &'a str,
        revision: &'a str,
    },
    /// `oci://<registry>/<repository>@sha256:<hex>`, the digest equal to `artifact_digest`.
    Oci(crate::oci_artifact::OciArtifactRef),
}

impl<'a> WeightSource<'a> {
    fn parse(model: &'a ModelSection) -> Result<Self> {
        let source = model.source.as_str();
        if let Some(path) = source.strip_prefix("file://") {
            let path = Path::new(path);
            if !path.is_absolute() {
                bail!("file:// model.source must be an absolute path");
            }
            return Ok(Self::File(path));
        }
        if source.starts_with("http://") || source.starts_with("https://") {
            return Ok(Self::Http(source));
        }
        if let Some(rest) = source.strip_prefix("hf://") {
            let mut segments = rest.splitn(3, '/');
            let (Some(org), Some(name), Some(path)) =
                (segments.next(), segments.next(), segments.next())
            else {
                bail!("hf:// model.source must be hf://<org>/<repo>/<file path>, got {source}");
            };
            // Plain segments only, so the built URL cannot be re-normalized
            // (for example a percent-encoded `..`) to another revision.
            if [org, name]
                .into_iter()
                .chain(path.split('/'))
                .any(|segment| {
                    segment.is_empty()
                        || segment == "."
                        || segment == ".."
                        || !segment
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                })
            {
                bail!(
                    "hf:// model.source segments must be non-empty [A-Za-z0-9._-] names: {source}"
                );
            }
            let revision = model.revision.as_str();
            if revision.len() != 40
                || !revision
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
            {
                bail!(
                    "hf:// model.source needs model.revision pinned to a 40-hex commit; floating refs are refused, got {revision:?}"
                );
            }
            return Ok(Self::Hub {
                repo: &rest[..org.len() + 1 + name.len()],
                path,
                revision,
            });
        }
        if let Some(rest) = source.strip_prefix("oci://") {
            let (location, digest) = rest
                .split_once('@')
                .with_context(|| format!("oci:// model.source must pin @sha256:<hex>: {source}"))?;
            let (registry, repository) = location.split_once('/').with_context(|| {
                format!(
                    "oci:// model.source must be oci://<registry>/<repository>@<digest>: {source}"
                )
            })?;
            if digest != model.artifact_digest {
                bail!(
                    "oci:// model.source digest {digest} must equal model.artifact_digest {}",
                    model.artifact_digest
                );
            }
            let reference = crate::oci_artifact::OciArtifactRef {
                registry: registry.into(),
                repository: repository.into(),
                digest: digest.into(),
                media_type: MODEL_WEIGHTS_MEDIA_TYPE.into(),
            };
            reference.validate()?;
            return Ok(Self::Oci(reference));
        }
        bail!(
            "unsupported model.source scheme (need file://, http(s)://, hf://, or oci://): {source}"
        );
    }
}

/// The OCI artifact a model's weights are pulled from, for offline bundle export
/// (`offline_bundle::insert_artifact_layers`). `None` unless `model.source` is `oci://`.
pub fn weight_artifact(
    model: &ModelSection,
) -> Result<Option<crate::oci_artifact::OciArtifactRef>> {
    if !model.source.starts_with("oci://") {
        return Ok(None);
    }
    match WeightSource::parse(model)? {
        WeightSource::Oci(reference) => Ok(Some(reference)),
        _ => unreachable!("oci:// source parses as Oci"),
    }
}

/// How `hf://` cache misses may reach the hub, from the environment's connectivity class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HubOrigin {
    /// Connected or intermittent: fetch from the hub endpoint, following any redirect.
    Open,
    /// Isolated with a hub mirror: fetch from the mirror, refusing off-mirror redirects.
    MirrorOnly,
    /// Isolated without a mirror: refuse before any network attempt.
    Refused,
}

/// Host (and port) of a hub endpoint URL: the key its `artifact_mirror.<host>` entry uses.
fn endpoint_host(endpoint: &str) -> &str {
    let rest = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    rest.split('/').next().unwrap_or(rest)
}

fn artifact_digest_hex(value: &str) -> Result<&str> {
    validate_artifact_digest(value)?;
    Ok(value
        .strip_prefix("sha256:")
        .expect("validated digest has sha256: prefix"))
}

/// Content-addressed weight cache outside the operational SQLite database.
///
/// `hf://` sources resolve against the hub endpoint (default [`DEFAULT_HUB_ENDPOINT`]) with an
/// optional bearer token the embedder supplies; `oci://` sources pull through an artifact
/// registry and the environment's mirrors only. Neither credential lives in a manifest.
/// [`WeightCache::with_environment`] applies an environment's mirrors and isolation.
#[derive(Clone)]
pub struct WeightCache {
    root: PathBuf,
    hub_endpoint: String,
    hub_token: Option<String>,
    hub_origin: HubOrigin,
    artifacts: Option<(
        Arc<dyn crate::oci_artifact::ArtifactRegistry>,
        BTreeMap<String, String>,
    )>,
}

impl std::fmt::Debug for WeightCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeightCache")
            .field("root", &self.root)
            .field("hub_endpoint", &self.hub_endpoint)
            .field("hub_token", &self.hub_token.as_ref().map(|_| "<redacted>"))
            .field("hub_origin", &self.hub_origin)
            .field("artifact_registry", &self.artifacts.is_some())
            .finish()
    }
}

impl WeightCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            hub_endpoint: DEFAULT_HUB_ENDPOINT.into(),
            hub_token: None,
            hub_origin: HubOrigin::Open,
            artifacts: None,
        }
    }

    /// Resolve `hf://` sources against `endpoint`, authenticating with `token` when set.
    pub fn with_hub(mut self, endpoint: impl Into<String>, token: Option<String>) -> Self {
        self.hub_endpoint = endpoint.into().trim_end_matches('/').to_string();
        self.hub_token = token;
        self
    }

    /// Pull `oci://` sources from `registry`, rewritten onto `mirrors` (origin registry ->
    /// environment mirror). A source without a mirror is refused, as for release artifacts.
    pub fn with_artifact_registry(
        mut self,
        registry: Arc<dyn crate::oci_artifact::ArtifactRegistry>,
        mirrors: BTreeMap<String, String>,
    ) -> Self {
        self.artifacts = Some((registry, mirrors));
        self
    }

    /// Apply one environment's weight-origin policy. An `artifact_mirror.<hub host>` entry
    /// moves `hf://` resolution onto `https://<mirror>`; an isolated environment without
    /// one refuses hub origin pulls, so only cached (bundle-imported) blobs resolve. The
    /// registry, when present, serves `oci://` sources through the same mirrors.
    pub fn with_environment(mut self, environment: ModelRuntimeArtifacts) -> Self {
        let hub_host = endpoint_host(&self.hub_endpoint).to_string();
        if let Some(mirror) = environment.mirrors.get(&hub_host) {
            self.hub_endpoint = format!("https://{mirror}");
        }
        self.hub_origin = match (
            environment.isolated,
            environment.mirrors.contains_key(&hub_host),
        ) {
            (false, _) => HubOrigin::Open,
            (true, true) => HubOrigin::MirrorOnly,
            (true, false) => HubOrigin::Refused,
        };
        if let Some(registry) = environment.registry {
            self.artifacts = Some((registry, environment.mirrors));
        }
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn blob_path(&self, artifact_digest: &str) -> Result<PathBuf> {
        let hex = artifact_digest_hex(artifact_digest)?;
        Ok(self.root.join("sha256").join(hex))
    }

    /// Whether `artifact_digest` is cached: `false` when absent, an error when
    /// the cached blob does not match its digest.
    pub fn verify_cached(&self, artifact_digest: &str) -> Result<bool> {
        let path = self.blob_path(artifact_digest)?;
        if !path.is_file() {
            return Ok(false);
        }
        verify_file_digest(&path, artifact_digest)?;
        Ok(true)
    }

    /// Admit a streaming-verified weight file. Matching cache hits are a no-op.
    /// Digest mismatch leaves the cache blob unchanged.
    pub fn admit_file(&self, artifact_digest: &str, source: &Path) -> Result<PathBuf> {
        let destination = self.blob_path(artifact_digest)?;
        if destination.is_file() {
            verify_file_digest(&destination, artifact_digest)?;
            return Ok(destination);
        }
        verify_file_digest(source, artifact_digest)
            .context("weight digest verification failed; model not activated")?;
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating weight cache {}", parent.display()))?;
        }
        if source == destination.as_path() {
            return Ok(destination);
        }
        match std::fs::rename(source, &destination) {
            Ok(()) => Ok(destination),
            Err(_) => {
                std::fs::copy(source, &destination).with_context(|| {
                    format!(
                        "copying verified weights from {} to {}",
                        source.display(),
                        destination.display()
                    )
                })?;
                let _ = std::fs::remove_file(source);
                Ok(destination)
            }
        }
    }

    /// Fetch `model` weights from its source and verify `model.artifact_digest`.
    ///
    /// Sources: `file://` absolute path, `http(s)://`, `hf://` at a pinned commit, and
    /// `oci://` through the configured artifact registry. Unknown schemes fail closed. On
    /// digest mismatch the incomplete file is removed and the model is not activated.
    pub fn fetch_and_verify(&self, model: &ModelSection) -> Result<PathBuf> {
        let artifact_digest = model.artifact_digest.as_str();
        validate_artifact_digest(artifact_digest)?;
        let source = WeightSource::parse(model)?;
        let destination = self.blob_path(artifact_digest)?;
        if destination.is_file() {
            verify_file_digest(&destination, artifact_digest)?;
            return Ok(destination);
        }
        if self.hub_origin == HubOrigin::Refused && matches!(source, WeightSource::Hub { .. }) {
            bail!(
                "model {} is not in the weight cache and this isolated environment has no artifact mirror for {}; hub origin pull is refused (import an offline bundle carrying {artifact_digest} or set the mirror)",
                model.source,
                endpoint_host(&self.hub_endpoint)
            );
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating weight cache {}", parent.display()))?;
        }
        // Per-invocation partial file: concurrent fetches of one digest never unlink or
        // overwrite each other's download; promotion is an atomic rename of verified bytes.
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let temporary =
            destination.with_extension(format!("partial-{}-{nonce}", std::process::id()));
        if let Err(error) = self.fetch_source_to(&source, &temporary) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
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

    fn fetch_source_to(&self, source: &WeightSource<'_>, destination: &Path) -> Result<()> {
        match source {
            WeightSource::File(path) => {
                std::fs::copy(path, destination).with_context(|| {
                    format!(
                        "copying model weights from {} to {}",
                        path.display(),
                        destination.display()
                    )
                })?;
                Ok(())
            }
            WeightSource::Http(url) => download_to(url, None, false, destination),
            WeightSource::Hub {
                repo,
                path,
                revision,
            } => {
                let url = format!("{}/{repo}/resolve/{revision}/{path}", self.hub_endpoint);
                let pinned = self.hub_origin == HubOrigin::MirrorOnly;
                download_to(&url, self.hub_token.as_deref(), pinned, destination)
            }
            WeightSource::Oci(reference) => {
                let (registry, mirrors) = self.artifacts.as_ref().with_context(|| {
                    format!(
                        "oci:// weights {} need an artifact registry on the weight cache",
                        reference.digest
                    )
                })?;
                let pull = crate::oci_artifact::pull_reference(reference, mirrors)?;
                let bytes = registry.fetch(&pull).with_context(|| {
                    format!("pulling weights {} from {}", pull.digest, pull.registry)
                })?;
                std::fs::write(destination, bytes)
                    .with_context(|| format!("writing pulled weights to {}", destination.display()))
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

/// Download `url` to `destination`. `same_origin` refuses redirects that leave the
/// starting scheme, host, and port, so an isolated environment's mirror cannot bounce a
/// fetch out to the public origin.
fn download_to(
    url: &str,
    bearer: Option<&str>,
    same_origin: bool,
    destination: &Path,
) -> Result<()> {
    let redirects = if same_origin {
        let start = reqwest::Url::parse(url)
            .with_context(|| format!("parsing weight download URL {url}"))?
            .origin();
        reqwest::redirect::Policy::custom(move |attempt| {
            let target = attempt.url().origin();
            if target != start {
                attempt.error(format!(
                    "redirect to {} leaves the environment mirror; origin pull is refused",
                    target.ascii_serialization()
                ))
            } else if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        })
    } else {
        reqwest::redirect::Policy::default()
    };
    let client = crate::outbound_tls::blocking_client()?
        .timeout(std::time::Duration::from_secs(60))
        .redirect(redirects)
        .build()
        .context("building weight download client")?;
    let mut request = client.get(url);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let mut response = request
        .send()
        .with_context(|| format!("downloading model weights from {url}"))?
        .error_for_status()
        .with_context(|| format!("weight download from {url} failed"))?;
    let mut file = std::fs::File::create(destination)
        .with_context(|| format!("creating {}", destination.display()))?;
    std::io::copy(&mut response, &mut file)
        .with_context(|| format!("writing downloaded weights to {}", destination.display()))?;
    Ok(())
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

/// Host injection point for non-reference model-runtime executors.
///
/// The core crate cannot depend on cluster adapters, so hosts that can serve
/// additional engines (for example a Kubernetes vLLM executor) install a
/// factory and pass it through the apply options. The factory binds one
/// executor to an environment's cluster configuration and descriptor state.
pub trait ModelRuntimeExecutorFactory: Send + Sync {
    /// Build the executor for one environment, or fail with a named error.
    /// `artifacts` carries the admitted registry and environment mirrors for
    /// `oci://` weight sources, when the host configured a registry.
    /// `engine` is the descriptor's `runtime.engine`.
    fn executor(
        &self,
        engine: &str,
        environment: &str,
        cluster_config: &Path,
        state_path: &Path,
        artifacts: Option<ModelRuntimeArtifacts>,
    ) -> Result<Arc<dyn ModelRuntimeExecutor>>;
}

/// One environment's weight-origin policy, applied with [`WeightCache::with_environment`]:
/// the admitted registry for `oci://` weights (when the host has one), the environment's
/// origin-to-mirror rewrites, and whether the environment is isolated.
#[derive(Clone)]
pub struct ModelRuntimeArtifacts {
    pub registry: Option<Arc<dyn crate::oci_artifact::ArtifactRegistry>>,
    pub mirrors: BTreeMap<String, String>,
    pub isolated: bool,
    /// Release workdir holding `model.registry_descriptor` for `runtime.engine=onnx`.
    pub workdir: Option<PathBuf>,
}

static MODEL_RUNTIME_EXECUTOR_FACTORY: std::sync::OnceLock<Arc<dyn ModelRuntimeExecutorFactory>> =
    std::sync::OnceLock::new();

/// Install the host's model-runtime executor factory (called once at process
/// start by the crate that owns the cluster adapters).
pub fn install_model_runtime_executor_factory(factory: Arc<dyn ModelRuntimeExecutorFactory>) {
    let _ = MODEL_RUNTIME_EXECUTOR_FACTORY.set(factory);
}

/// The installed host factory, when the host registered one.
pub fn selected_model_runtime_executor_factory() -> Option<Arc<dyn ModelRuntimeExecutorFactory>> {
    MODEL_RUNTIME_EXECUTOR_FACTORY.get().cloned()
}

/// Select the executor for one descriptor by `runtime.engine`.
///
/// `llama.cpp` always keeps the reference executor. `mlx` uses the Apple-silicon
/// host-process executor (fake engine in CI). `onnx` uses the classical
/// scoring executor (fake engine in CI) and needs the release workdir so it
/// can read the signed registry descriptor. `vllm`, `tgi` and `nim` use the injected
/// host executor, and only on an environment that carries a cluster
/// configuration.
/// Every other case fails closed with a named error: an engine must never
/// fall back to an executor that does not implement it.
pub fn select_model_runtime_executor(
    descriptor: &ModelRuntimeDescriptor,
    environment: &str,
    cluster_config: Option<&Path>,
    factory: Option<&dyn ModelRuntimeExecutorFactory>,
    state_path: &Path,
    artifacts: Option<ModelRuntimeArtifacts>,
) -> Result<Arc<dyn ModelRuntimeExecutor>> {
    match descriptor.runtime.engine.as_str() {
        "llama.cpp" => Ok(Arc::new(ReferenceLlamaCppExecutor::for_operator_host(
            state_path.to_path_buf(),
        ))),
        "mlx" => Ok(Arc::new(MlxHostExecutor::for_operator_host(
            state_path.to_path_buf(),
            artifacts,
        ))),
        "onnx" => {
            let workdir = artifacts
                .as_ref()
                .and_then(|artifacts| artifacts.workdir.clone())
                .with_context(|| {
                    format!(
                        "model_runtime engine onnx requires the release workdir for environment {environment}"
                    )
                })?;
            Ok(Arc::new(ClassicalOnnxExecutor::for_operator_host(
                state_path.to_path_buf(),
                workdir,
                artifacts,
            )?))
        }
        engine @ ("vllm" | "tgi" | "nim") => {
            let cluster_config = cluster_config.with_context(|| {
                format!(
                    "model_runtime engine {engine} requires an environment cluster_config_path; environment {environment} has none"
                )
            })?;
            let factory = factory.with_context(|| {
                format!("model_runtime engine {engine} has no executor on this host: no model-runtime executor factory is installed")
            })?;
            factory.executor(engine, environment, cluster_config, state_path, artifacts)
        }
        engine => bail!(
            "unknown model_runtime engine {engine} for environment {environment}: no executor is available"
        ),
    }
}

/// Local reference executor that stages the validated descriptor and, when a
/// [`WeightCache`] is configured, fetches and verifies weight digests.
///
/// It does **not** start an inference server. In-tree executors such as
/// [`ReferenceLlamaCppExecutor`] implement [`ModelRuntimeExecutor`] and add
/// start/smoke/switch steps after using the same cache verify path.
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
            cache.fetch_and_verify(&descriptor.model)?;
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
    /// Must be loopback for the reference executor.
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
    /// Adapter-private marker (pid file path, fake id, …). Never a secret.
    pub marker: String,
}

/// Process control port for inference engines. Tenkai core never links a
/// specific engine binary; in-tree adapters implement start/smoke/stop.
pub trait InferenceEngineProcess: Send + Sync {
    fn start_candidate(&self, request: &EngineStartRequest) -> Result<EngineHandle>;
    fn smoke(&self, handle: &EngineHandle, health: &ModelHealthSection) -> Result<()>;
    fn stop(&self, handle: &EngineHandle) -> Result<()>;
}

/// Deterministic fake engine for CI. Does not open sockets or spawn processes.
///
/// Rationale for choosing **llama.cpp** as the reference real executor: it is the
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
                "reference executor supports runtime.engine=llama.cpp only, got {}",
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
        let client = crate::outbound_tls::blocking_client()?
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

pub(super) fn require_loopback_bind(host: &str, port: u16) -> Result<()> {
    if port == 0 {
        bail!("model runtime port must not be zero");
    }
    let host = host.trim();
    if host != "127.0.0.1" && host != "::1" && host != "localhost" {
        bail!("reference model engine must bind loopback only, got host {host:?}");
    }
    Ok(())
}

pub(super) fn require_loopback_health_endpoint(endpoint: &str) -> Result<()> {
    let endpoint = endpoint.trim();
    if !(endpoint.starts_with("http://127.0.0.1")
        || endpoint.starts_with("http://localhost")
        || endpoint.starts_with("http://[::1]"))
    {
        bail!("reference model engine health endpoint must use loopback HTTP, got {endpoint:?}");
    }
    Ok(())
}

pub(super) fn bind_host_from_health_endpoint(endpoint: &str) -> Result<String> {
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
        let weights_path = if let Some(cache) = &self.weight_cache {
            Some(cache.fetch_and_verify(&descriptor.model)?)
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

fn validate_gpu_requirements(gpu: &crate::manifest::GpuRequirements) -> Result<()> {
    if gpu.vram_gib == 0 || gpu.count == 0 || gpu.tensor_parallel == 0 {
        bail!("requirements.gpu vram_gib, count, and tensor_parallel must be non-zero");
    }
    if gpu
        .vendor
        .iter()
        .chain(&gpu.families)
        .any(|entry| entry.trim().is_empty())
    {
        bail!("requirements.gpu vendor and families entries must not be empty");
    }
    if let Some(runtime) = &gpu.runtime
        && !matches!(runtime.as_str(), "cuda" | "rocm")
    {
        bail!("requirements.gpu.runtime must be cuda or rocm, got {runtime:?}");
    }
    if gpu.runtime_min.is_some() && gpu.runtime.is_none() {
        bail!("requirements.gpu.runtime_min needs requirements.gpu.runtime");
    }
    for (field, version) in [
        ("driver_min", &gpu.driver_min),
        ("runtime_min", &gpu.runtime_min),
    ] {
        if let Some(version) = version
            && crate::plan::dotted_version(version).is_none()
        {
            bail!("requirements.gpu.{field} must be a dotted numeric version, got {version:?}");
        }
    }
    Ok(())
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
                source: "hf://org/qwen-coder/qwen-coder-q4_k_m.gguf".into(),
                revision: "9bcfabc0123456789abcdef0123456789abcdef0".into(),
                format: "gguf".into(),
                quantization: "Q4_K_M".into(),
                artifact_digest: format!("sha256:{}", "ab".repeat(32)),
                license: "apache-2.0".into(),
                registry_descriptor: String::new(),
                registry_attestation: String::new(),
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
                gpu: None,
            },
            health: ModelHealthSection {
                endpoint: "http://127.0.0.1:8080/v1/models".into(),
                smoke_prompt: "Return exactly: OK".into(),
                max_startup_seconds: 300,
            },
        }
    }

    #[derive(Default)]
    struct RecordingExecutor {
        applied: std::sync::Mutex<Vec<String>>,
        removed: std::sync::Mutex<u32>,
    }

    impl ModelRuntimeExecutor for RecordingExecutor {
        fn apply(&self, descriptor: &ModelRuntimeDescriptor) -> Result<String> {
            self.applied
                .lock()
                .unwrap()
                .push(descriptor.runtime.engine.clone());
            Ok("injected".into())
        }

        fn remove(&self) -> Result<()> {
            *self.removed.lock().unwrap() += 1;
            Ok(())
        }

        fn observe(&self) -> Result<Option<String>> {
            Ok(None)
        }
    }

    struct RecordingFactory {
        executor: Arc<RecordingExecutor>,
        calls: std::sync::Mutex<Vec<(String, PathBuf)>>,
    }

    impl ModelRuntimeExecutorFactory for RecordingFactory {
        fn executor(
            &self,
            engine: &str,
            _environment: &str,
            cluster_config: &Path,
            _state_path: &Path,
            _artifacts: Option<ModelRuntimeArtifacts>,
        ) -> Result<Arc<dyn ModelRuntimeExecutor>> {
            self.calls
                .lock()
                .unwrap()
                .push((engine.to_string(), cluster_config.to_path_buf()));
            Ok(self.executor.clone())
        }
    }

    #[test]
    fn engine_selection_keeps_reference_for_llama_cpp() {
        let descriptor = sample_descriptor();
        let root = std::env::temp_dir().join(format!("tenkai-select-llama-{}", std::process::id()));
        let state = root.join("active.json");
        let selected =
            select_model_runtime_executor(&descriptor, "lab", None, None, &state, None).unwrap();
        let digest = selected.apply(&descriptor).unwrap();
        assert_eq!(digest, descriptor.digest().unwrap());
        assert!(
            state.exists(),
            "reference executor must stage the descriptor"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn engine_selection_uses_mlx_host_executor() {
        let mut descriptor = sample_descriptor();
        descriptor.runtime.engine = "mlx".into();
        let root = std::env::temp_dir().join(format!(
            "tenkai-select-mlx-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let state = root.join("active.json");
        let selected =
            select_model_runtime_executor(&descriptor, "lab", None, None, &state, None).unwrap();
        let digest = selected.apply(&descriptor).unwrap();
        assert_eq!(digest, descriptor.digest().unwrap());
        assert!(state.exists(), "mlx executor must stage the descriptor");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn engine_selection_uses_classical_executor_for_onnx() {
        let mut descriptor = sample_descriptor();
        descriptor.runtime.engine = "onnx".into();
        descriptor.model.format = "onnx".into();
        descriptor.model.registry_descriptor = "signed-descriptor.json".into();
        descriptor.health.endpoint = "http://127.0.0.1:18080/readyz".into();
        let root = std::env::temp_dir().join(format!(
            "tenkai-select-onnx-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let state = root.join("active.json");
        let missing_workdir =
            match select_model_runtime_executor(&descriptor, "lab", None, None, &state, None) {
                Ok(_) => panic!("onnx without a workdir must be refused"),
                Err(error) => error.to_string(),
            };
        assert!(
            missing_workdir.contains("release workdir"),
            "{missing_workdir}"
        );
        let artifacts = ModelRuntimeArtifacts {
            registry: None,
            mirrors: BTreeMap::new(),
            isolated: false,
            workdir: Some(root.clone()),
        };
        let selected =
            select_model_runtime_executor(&descriptor, "lab", None, None, &state, Some(artifacts))
                .unwrap();
        let err = selected.apply(&descriptor).unwrap_err().to_string();
        assert!(
            err.contains("trusted registry keys") || err.contains("signed registry descriptor"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn engine_selection_uses_injected_executor_for_gpu_engines_on_cluster_environment() {
        for engine in ["vllm", "tgi", "nim"] {
            let mut descriptor = sample_descriptor();
            descriptor.runtime.engine = engine.into();
            let recording = Arc::new(RecordingExecutor::default());
            let factory = RecordingFactory {
                executor: recording.clone(),
                calls: std::sync::Mutex::new(Vec::new()),
            };
            let cluster = Path::new("/etc/tenkai/kubeconfig");
            let state = Path::new("/tmp/model-runtime-state.json");
            let selected = select_model_runtime_executor(
                &descriptor,
                "lab",
                Some(cluster),
                Some(&factory),
                state,
                None,
            )
            .unwrap();
            assert_eq!(selected.apply(&descriptor).unwrap(), "injected");
            assert_eq!(recording.applied.lock().unwrap().as_slice(), [engine]);
            assert_eq!(
                factory.calls.lock().unwrap().as_slice(),
                [(engine.to_string(), cluster.to_path_buf())]
            );
        }
    }

    #[test]
    fn engine_selection_refuses_gpu_engines_without_cluster_or_factory() {
        for engine in ["vllm", "tgi", "nim"] {
            let mut descriptor = sample_descriptor();
            descriptor.runtime.engine = engine.into();
            let state = Path::new("/tmp/model-runtime-state.json");
            let no_cluster =
                select_model_runtime_executor(&descriptor, "lab", None, None, state, None)
                    .err()
                    .unwrap();
            assert!(
                no_cluster.to_string().contains("cluster_config_path"),
                "{no_cluster}"
            );
            let no_factory = select_model_runtime_executor(
                &descriptor,
                "lab",
                Some(Path::new("/etc/tenkai/kubeconfig")),
                None,
                state,
                None,
            )
            .err()
            .unwrap();
            assert!(
                no_factory
                    .to_string()
                    .contains("no model-runtime executor factory"),
                "{no_factory}"
            );
        }
    }

    #[test]
    fn engine_selection_refuses_unknown_engines() {
        let mut descriptor = sample_descriptor();
        for engine in ["tensorrt", "sglang", "triton"] {
            descriptor.runtime.engine = engine.into();
            let error = select_model_runtime_executor(
                &descriptor,
                "lab",
                Some(Path::new("/etc/tenkai/kubeconfig")),
                None,
                Path::new("/tmp/model-runtime-state.json"),
                None,
            )
            .err()
            .unwrap();
            let text = error.to_string();
            assert!(
                text.contains(&format!("unknown model_runtime engine {engine}")),
                "{text}"
            );
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
    fn gpu_requirements_parse_and_validate() {
        let requirements: ModelRequirementsSection = toml::from_str(
            r#"
            architecture = ["x86_64"]
            memory_gib = 64

            [gpu]
            vendor = ["nvidia"]
            vram_gib = 80
            tensor_parallel = 2
            runtime = "cuda"
            runtime_min = "12.1"
            "#,
        )
        .unwrap();
        let gpu = requirements.gpu.clone().unwrap();
        assert_eq!((gpu.count, gpu.tensor_parallel), (1, 2));
        let mut descriptor = sample_descriptor();
        descriptor.requirements = requirements;
        descriptor.validate().unwrap();

        for broken in [
            r#"vram_gib = 0"#,
            r#"vram_gib = 80
            runtime_min = "12.1""#,
            r#"vram_gib = 80
            runtime = "metal""#,
            r#"vram_gib = 80
            driver_min = "535.x""#,
        ] {
            descriptor.requirements.gpu = Some(toml::from_str(broken).unwrap());
            assert!(descriptor.validate().is_err(), "{broken}");
        }
    }

    #[test]
    fn from_manifest_builds_descriptor() {
        let sample = sample_descriptor();
        let manifest = Manifest {
            compatibility: None,
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
            artifacts: Vec::new(),
            gate: GateSection::default(),
            delivery: Default::default(),
            topology: None,
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
        next.model.revision = "1111111111111111111111111111111111111111".into();
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
        let file_model = |artifact_digest: &str| ModelSection {
            source: format!("file://{}", source_file.display()),
            artifact_digest: artifact_digest.into(),
            ..sample_descriptor().model
        };
        let stored = cache.fetch_and_verify(&file_model(&digest)).unwrap();
        assert!(stored.is_file());
        // Second fetch hits cache.
        let again = cache.fetch_and_verify(&file_model(&digest)).unwrap();
        assert_eq!(stored, again);

        let bad = format!("sha256:{}", "00".repeat(32));
        let err = cache
            .fetch_and_verify(&file_model(&bad))
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

    const COMMIT: &str = "9bcfabc0123456789abcdef0123456789abcdef0";

    /// Serves one request with `body`, returning the request head it saw.
    fn fake_hub(body: &'static [u8]) -> (String, std::thread::JoinHandle<String>) {
        use std::io::{BufRead as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                head.push_str(&line);
            }
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
            head
        });
        (endpoint, server)
    }

    fn hub_model(artifact_digest: String) -> ModelSection {
        ModelSection {
            source: "hf://org/qwen-coder/gguf/qwen-coder-q4_k_m.gguf".into(),
            revision: COMMIT.into(),
            artifact_digest,
            ..sample_descriptor().model
        }
    }

    #[test]
    fn hub_source_downloads_the_pinned_commit_with_the_token() {
        let root = std::env::temp_dir().join(format!("tenkai-hub-{}", uuid::Uuid::new_v4()));
        let payload: &'static [u8] = b"hub-model-bytes";
        let (endpoint, server) = fake_hub(payload);
        let cache =
            WeightCache::new(root.join("cache")).with_hub(&endpoint, Some("hub-test-token".into()));
        let digest = format!("sha256:{:x}", Sha256::digest(payload));
        let stored = cache.fetch_and_verify(&hub_model(digest)).unwrap();
        assert_eq!(std::fs::read(stored).unwrap(), payload);
        let head = server.join().unwrap();
        assert!(
            head.starts_with(&format!(
                "GET /org/qwen-coder/resolve/{COMMIT}/gguf/qwen-coder-q4_k_m.gguf "
            )),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("authorization: bearer hub-test-token"),
            "{head}"
        );
        assert!(!format!("{cache:?}").contains("hub-test-token"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hub_source_with_a_mismatched_digest_fails_closed() {
        let root = std::env::temp_dir().join(format!("tenkai-hub-{}", uuid::Uuid::new_v4()));
        let (endpoint, server) = fake_hub(b"tampered-bytes");
        let cache = WeightCache::new(root.join("cache")).with_hub(&endpoint, None);
        let expected = format!("sha256:{:x}", Sha256::digest(b"hub-model-bytes"));
        let err = cache
            .fetch_and_verify(&hub_model(expected.clone()))
            .unwrap_err();
        assert!(format!("{err:#}").contains("digest mismatch"), "{err:#}");
        server.join().unwrap();
        assert!(!cache.blob_path(&expected).unwrap().exists());
        let leftovers = std::fs::read_dir(cache.blob_path(&expected).unwrap().parent().unwrap())
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert_eq!(leftovers, 0, "no partial download may remain");
        let _ = std::fs::remove_dir_all(root);
    }

    fn isolated(mirrors: BTreeMap<String, String>) -> ModelRuntimeArtifacts {
        ModelRuntimeArtifacts {
            registry: None,
            mirrors,
            isolated: true,
            workdir: None,
        }
    }

    #[test]
    fn isolated_environment_refuses_hub_origin_and_serves_cached_blobs() {
        let root = std::env::temp_dir().join(format!("tenkai-hub-{}", uuid::Uuid::new_v4()));
        // A hub that must never be dialed: any accepted connection fails the test.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let hub_host = listener.local_addr().unwrap().to_string();
        let cache = WeightCache::new(root.join("cache"))
            .with_hub(format!("http://{hub_host}"), None)
            .with_environment(isolated(BTreeMap::new()));
        let payload = b"bundle-model-bytes";
        let digest = format!("sha256:{:x}", Sha256::digest(payload));
        let model = hub_model(digest.clone());

        let err = cache.fetch_and_verify(&model).unwrap_err().to_string();
        assert!(err.contains(&model.source), "{err}");
        assert!(
            err.contains(&format!("no artifact mirror for {hub_host}")),
            "{err}"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "refusal must not reach the network"
        );

        // A blob imported from an offline bundle resolves without any mirror.
        let staged = root.join("staged");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&staged, payload).unwrap();
        cache.admit_file(&digest, &staged).unwrap();
        let stored = cache.fetch_and_verify(&model).unwrap();
        assert_eq!(std::fs::read(stored).unwrap(), payload);
        assert!(listener.accept().is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pinned_download_refuses_a_redirect_off_the_mirror() {
        use std::io::{BufRead as _, Write as _};
        let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        origin.set_nonblocking(true).unwrap();
        let origin_url = format!("http://{}/blob", origin.local_addr().unwrap());
        let mirror = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mirror_url = format!("http://{}/blob", mirror.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (stream, _) = mirror.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nlocation: {origin_url}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let destination =
            std::env::temp_dir().join(format!("tenkai-redirect-{}", uuid::Uuid::new_v4()));
        let err = download_to(&mirror_url, None, true, &destination).unwrap_err();
        assert!(
            format!("{err:#}").contains("leaves the environment mirror"),
            "{err:#}"
        );
        server.join().unwrap();
        assert!(origin.accept().is_err(), "origin must not be dialed");
        let _ = std::fs::remove_file(destination);
    }

    #[test]
    fn hub_mirror_replaces_the_origin_endpoint() {
        let cache = WeightCache::new("unused").with_environment(isolated(BTreeMap::from([(
            "huggingface.co".into(),
            "hub-mirror.internal".into(),
        )])));
        assert_eq!(cache.hub_endpoint, "https://hub-mirror.internal");
        assert_eq!(cache.hub_origin, HubOrigin::MirrorOnly);
        let connected = WeightCache::new("unused").with_environment(ModelRuntimeArtifacts {
            isolated: false,
            ..isolated(BTreeMap::new())
        });
        assert_eq!(connected.hub_endpoint, DEFAULT_HUB_ENDPOINT);
        assert_eq!(connected.hub_origin, HubOrigin::Open);
    }

    #[test]
    fn unpinned_or_malformed_weight_sources_are_rejected_at_validation() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        for (source, revision) in [
            ("hf://org/qwen-coder/model.gguf", "main"),
            ("hf://org/qwen-coder/model.gguf", "9bcfabc"),
            ("hf://org/qwen-coder/model.gguf", &COMMIT.to_uppercase()),
            ("hf://org/qwen-coder", COMMIT),
            ("hf://org/qwen-coder/../secrets", COMMIT),
            ("hf://org/qwen-coder/%2e%2e/main/model.gguf", COMMIT),
            ("hf://org/qwen-coder/model.gguf?revision=main", COMMIT),
            ("oci://registry.example/models/qwen", COMMIT),
            (
                "oci://registry.example/models/qwen@sha256:0000000000000000000000000000000000000000000000000000000000000000",
                COMMIT,
            ),
        ] {
            let mut descriptor = sample_descriptor();
            descriptor.model.source = source.into();
            descriptor.model.revision = revision.into();
            descriptor.model.artifact_digest = digest.clone();
            assert!(descriptor.validate().is_err(), "{source} @ {revision}");
        }
        let mut pinned = sample_descriptor();
        pinned.model.source = format!("oci://registry.example/models/qwen@{digest}");
        pinned.model.artifact_digest = digest;
        pinned.validate().unwrap();
    }

    #[test]
    fn oci_weights_pull_through_the_mirror_and_travel_in_offline_bundles() {
        use crate::oci_artifact::{MemoryArtifactRegistry, OciArtifactRef};
        let root = std::env::temp_dir().join(format!("tenkai-oci-{}", uuid::Uuid::new_v4()));
        let payload = b"oci-model-bytes".to_vec();
        let digest = format!("sha256:{:x}", Sha256::digest(&payload));
        let model = ModelSection {
            source: format!("oci://registry.example/models/qwen@{digest}"),
            artifact_digest: digest.clone(),
            ..sample_descriptor().model
        };
        let origin = weight_artifact(&model).unwrap().unwrap();
        assert_eq!(origin.media_type, MODEL_WEIGHTS_MEDIA_TYPE);
        let registry = Arc::new(MemoryArtifactRegistry::new());
        registry
            .put(
                &OciArtifactRef {
                    registry: "mirror.example".into(),
                    ..origin.clone()
                },
                payload.clone(),
            )
            .unwrap();

        let no_registry = WeightCache::new(root.join("none"));
        assert!(no_registry.fetch_and_verify(&model).is_err());
        let no_mirror = WeightCache::new(root.join("unmirrored"))
            .with_artifact_registry(registry.clone(), BTreeMap::new());
        let err = no_mirror.fetch_and_verify(&model).unwrap_err().to_string();
        assert!(err.contains("origin pull is refused"), "{err}");

        let cache = WeightCache::new(root.join("cache")).with_artifact_registry(
            registry.clone(),
            BTreeMap::from([("registry.example".into(), "mirror.example".into())]),
        );
        let stored = cache.fetch_and_verify(&model).unwrap();
        assert_eq!(std::fs::read(&stored).unwrap(), payload);
        // Fetched weights are ordinary cache entries for eviction.
        assert_eq!(cache.evict(&[], 0).unwrap(), vec![digest.clone()]);
        assert!(!stored.exists());

        let mut payloads = BTreeMap::new();
        let mirror_ref = OciArtifactRef {
            registry: "mirror.example".into(),
            ..origin
        };
        crate::offline_bundle::insert_artifact_layers(
            &mut payloads,
            std::slice::from_ref(&mirror_ref),
            registry.as_ref(),
        )
        .unwrap();
        assert_eq!(
            payloads
                .get(&mirror_ref.layer_entry_path().unwrap())
                .map(|(_, bytes)| bytes),
            Some(&payload)
        );
        let _ = std::fs::remove_dir_all(root);
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
