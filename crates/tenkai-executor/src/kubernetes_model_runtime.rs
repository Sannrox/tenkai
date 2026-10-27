//! GPU `model_runtime` executor on the in-process Kubernetes path: vLLM (#600)
//! and Text Generation Inference (#615) serve through one lifecycle.
//!
//! Each descriptor generation is a candidate Deployment and Service. A candidate
//! becomes active only after it is Available and passes a fixed completion smoke
//! probe; then the stable Service selects it. The previous generation stays
//! deployed so [`KubernetesModelRuntimeExecutor::rollback`] can re-select it.
//!
//! Both engines load a model directory (configuration, tokenizer, weights), so the pinned
//! artifact is a tar of that directory (`model.format = "directory+tar"`). After the
//! cache verifies its digest, the executor unpacks it once under the cache root,
//! which pods mount read-only from the claim that holds it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use tenkai::manifest::ModelHealthSection;
use tenkai::model_runtime::{ModelRuntimeDescriptor, ModelRuntimeExecutor, WeightCache};
use tenkai::software_executor::k8s_label_value;

use crate::in_process_kubernetes::{ClusterApplyApi, FIELD_MANAGER, disagreeing_condition};

/// Where the verified weight cache is mounted in serving pods.
const WEIGHTS_MOUNT: &str = "/weights";
const GENERATION_LABEL: &str = "tenkai.generation";
/// `model.format` of a tar archive holding a complete model directory.
pub const MODEL_DIRECTORY_FORMAT: &str = "directory+tar";
/// Kubernetes object names are at most 63 characters.
const NAME_LIMIT: usize = 63;
const GENERATION_LEN: usize = 12;
const PRODUCT_LABEL: &str = "tenkai.product";

/// The serving engine a [`ServingConfig`] runs, from `runtime.engine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingEngine {
    Vllm,
    /// Text Generation Inference.
    Tgi,
}

impl ServingEngine {
    pub fn parse(engine: &str) -> Result<Self> {
        match engine {
            "vllm" => Ok(Self::Vllm),
            "tgi" => Ok(Self::Tgi),
            other => bail!("model_runtime engine {other} has no Kubernetes serving executor"),
        }
    }

    /// The `runtime.engine` value.
    pub fn name(self) -> &'static str {
        match self {
            Self::Vllm => "vllm",
            Self::Tgi => "tgi",
        }
    }

    /// Prefix of this engine's host configuration variables.
    fn env_prefix(self) -> &'static str {
        match self {
            Self::Vllm => "TENKAI_VLLM",
            Self::Tgi => "TENKAI_TGI",
        }
    }

    /// Container arguments and environment serving `model_path` on `port`.
    fn container(
        self,
        model_path: &Path,
        served_model: &str,
        port: u16,
        tensor_parallel: u32,
        context_length: u32,
    ) -> (Value, Value) {
        match self {
            Self::Vllm => (
                json!([
                    "--model",
                    model_path,
                    "--served-model-name",
                    served_model,
                    "--port",
                    port.to_string(),
                    "--tensor-parallel-size",
                    tensor_parallel.to_string(),
                    "--max-model-len",
                    context_length.to_string(),
                ]),
                json!([]),
            ),
            Self::Tgi => (
                json!([
                    "--model-id",
                    model_path,
                    "--hostname",
                    "0.0.0.0",
                    "--port",
                    port.to_string(),
                    "--num-shard",
                    tensor_parallel.to_string(),
                    "--max-total-tokens",
                    context_length.to_string(),
                    "--max-input-tokens",
                    context_length.saturating_sub(1).max(1).to_string(),
                ]),
                // The model is the mounted directory; nothing is downloaded at start.
                json!([{"name": "HF_HUB_OFFLINE", "value": "1"}]),
            ),
        }
    }
}

/// Environment-scoped serving configuration; nothing here comes from the manifest.
#[derive(Debug, Clone)]
pub struct ServingConfig {
    pub engine: ServingEngine,
    pub cluster_config: PathBuf,
    pub namespace: String,
    /// Serving image, pinned by digest.
    pub image: String,
    /// PersistentVolumeClaim that is the volume holding this executor's `WeightCache`
    /// root: the executor writes and verifies there, pods mount the same volume
    /// read-only at `/weights`. This executor does not copy weights between volumes.
    pub weights_claim: String,
    pub node_selector: BTreeMap<String, String>,
    /// Kubernetes toleration objects, passed through as-is.
    pub tolerations: Vec<Value>,
}

/// Host factory that binds the Kubernetes serving executor to one
/// environment, for `runtime.engine` `vllm` or `tgi`.
///
/// Serving configuration is host configuration, never manifest data. Each
/// engine reads its own variables (`TENKAI_VLLM_*` or `TENKAI_TGI_*`): the
/// digest-pinned serving image (`_IMAGE`), the weights claim
/// (`_WEIGHTS_CLAIM`), and the weight-cache root (`_WEIGHTS_ROOT`) must be
/// set, or executor construction fails closed with a named error. The cache
/// root must be the host mount of the weights claim: the executor writes
/// verified weights there and serving pods mount the same claim read-only;
/// nothing copies between volumes. The environment name is the namespace, as
/// on the in-process software path. `_SMOKE_BASE_URL` overrides the
/// smoke-probe URL template.
pub struct KubernetesModelRuntimeFactory;

impl tenkai::model_runtime::ModelRuntimeExecutorFactory for KubernetesModelRuntimeFactory {
    fn executor(
        &self,
        engine: &str,
        environment: &str,
        cluster_config: &Path,
        state_path: &Path,
        artifacts: Option<tenkai::model_runtime::ModelRuntimeArtifacts>,
    ) -> Result<std::sync::Arc<dyn ModelRuntimeExecutor>> {
        let engine = ServingEngine::parse(engine)?;
        let (name, prefix) = (engine.name(), engine.env_prefix());
        let var = |suffix: &str| {
            std::env::var(format!("{prefix}_{suffix}"))
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        let image = var("IMAGE").with_context(|| {
            format!("model_runtime engine {name} requires {prefix}_IMAGE (digest-pinned serving image) on this host")
        })?;
        if !image.contains("@sha256:") {
            bail!("{prefix}_IMAGE must pin the serving image by digest (@sha256:...)");
        }
        let weights_claim = var("WEIGHTS_CLAIM").with_context(|| {
            format!("model_runtime engine {name} requires {prefix}_WEIGHTS_CLAIM on this host")
        })?;
        let weights_root = var("WEIGHTS_ROOT").map(PathBuf::from).with_context(|| {
            format!("model_runtime engine {name} requires {prefix}_WEIGHTS_ROOT (host mount of the weights claim) on this host")
        })?;
        let probe = HttpSmokeProbe {
            engine,
            base_url: var("SMOKE_BASE_URL")
                .unwrap_or_else(|| "http://{service}.{namespace}.svc:{port}".into()),
            timeout: Duration::from_secs(30),
        };
        Ok(std::sync::Arc::new(KubernetesModelRuntimeExecutor::new(
            crate::in_process_kubernetes::LiveKubeApi,
            probe,
            ServingConfig {
                engine,
                cluster_config: cluster_config.to_path_buf(),
                namespace: environment.to_string(),
                image,
                weights_claim,
                node_selector: BTreeMap::new(),
                tolerations: Vec::new(),
            },
            match artifacts {
                Some(artifacts) => WeightCache::new(weights_root).with_environment(artifacts),
                None => WeightCache::new(weights_root),
            },
            state_path.to_path_buf(),
        )))
    }
}

/// Fixed completion probe against a candidate Service before activation.
pub trait SmokeProbe: Send + Sync {
    /// One attempt, finished within `timeout` (the remaining startup budget).
    fn smoke(
        &self,
        namespace: &str,
        service: &str,
        port: u16,
        served_model: &str,
        health: &ModelHealthSection,
        timeout: Duration,
    ) -> Result<()>;
}

/// Probes `base_url` with `{service}`, `{namespace}`, and `{port}` substituted, for
/// example `http://{service}.{namespace}.svc:{port}` when the executor runs in-cluster.
#[derive(Debug, Clone)]
pub struct HttpSmokeProbe {
    /// Selects the request: OpenAI completions for vLLM, `/generate` for TGI.
    pub engine: ServingEngine,
    pub base_url: String,
    /// Per-attempt cap; each attempt is also bounded by the remaining startup budget.
    pub timeout: Duration,
}

impl SmokeProbe for HttpSmokeProbe {
    fn smoke(
        &self,
        namespace: &str,
        service: &str,
        port: u16,
        served_model: &str,
        health: &ModelHealthSection,
        timeout: Duration,
    ) -> Result<()> {
        if !self.base_url.contains("{service}") || !self.base_url.contains("{port}") {
            bail!("smoke probe base_url must contain {{service}} and {{port}}");
        }
        let base = self
            .base_url
            .replace("{service}", service)
            .replace("{namespace}", namespace)
            .replace("{port}", &port.to_string());
        let prompt = if health.smoke_prompt.trim().is_empty() {
            "Return exactly: OK"
        } else {
            health.smoke_prompt.as_str()
        };
        // Plain completions: base models without a chat template still answer. The
        // predicate is a non-empty completion, which proves the inference path end to
        // end; exact text is not required because base models do not follow
        // instructions. This is stricter than the llama.cpp path's HTTP-success check.
        let (path, body, text_at) = match self.engine {
            ServingEngine::Vllm => (
                "/v1/completions",
                json!({
                    "model": served_model,
                    "prompt": prompt,
                    "max_tokens": 16,
                    "temperature": 0,
                }),
                "/choices/0/text",
            ),
            ServingEngine::Tgi => (
                "/generate",
                json!({
                    "inputs": prompt,
                    "parameters": {"max_new_tokens": 16, "do_sample": false},
                }),
                "/generated_text",
            ),
        };
        let response: Value = tenkai::outbound_tls::blocking_client()?
            .timeout(timeout.min(self.timeout))
            .build()
            .context("building smoke probe client")?
            .post(format!("{}{path}", base.trim_end_matches('/')))
            .json(&body)
            .send()
            .with_context(|| format!("smoke probe to {service}"))?
            .error_for_status()
            .with_context(|| format!("smoke probe to {service} failed"))?
            .json()
            .with_context(|| format!("smoke probe to {service} returned invalid JSON"))?;
        let text = response
            .pointer(text_at)
            .and_then(Value::as_str)
            .unwrap_or_default();
        if text.trim().is_empty() {
            bail!("smoke probe to {service} returned an empty completion");
        }
        Ok(())
    }
}

pub struct KubernetesModelRuntimeExecutor<A, P> {
    api: A,
    probe: P,
    config: ServingConfig,
    weight_cache: WeightCache,
    state_path: PathBuf,
    timeout: Duration,
    poll_interval: Duration,
}

impl<A: ClusterApplyApi, P: SmokeProbe> KubernetesModelRuntimeExecutor<A, P> {
    /// `state_path` records the active descriptor; `<state>.previous` the rollback one.
    pub fn new(
        api: A,
        probe: P,
        config: ServingConfig,
        weight_cache: WeightCache,
        state_path: PathBuf,
    ) -> Self {
        Self {
            api,
            probe,
            config,
            weight_cache,
            state_path,
            timeout: Duration::from_secs(900),
            poll_interval: Duration::from_secs(2),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration, poll_interval: Duration) -> Self {
        self.timeout = timeout;
        self.poll_interval = poll_interval;
        self
    }

    /// Re-select the retained previous generation, which must still be Available.
    pub fn rollback(&self) -> Result<String> {
        let _lock = self.lock()?;
        let previous = self
            .load_in_scope(&self.previous_path())?
            .context("model_runtime rollback has no retained previous generation")?;
        let active = self.load_in_scope(&self.state_path)?;
        self.wait_available(
            &deployment_name(&previous.descriptor.product_name, &previous.generation),
            Instant::now() + self.timeout,
        )
        .context("previous generation is not available; rollback refused")?;
        if let Err(error) = self.select(&previous.descriptor, &previous.generation) {
            // The patch may have landed despite the error; put the outgoing selector back.
            if let Some(active) = &active {
                let _ = self.select(&active.descriptor, &active.generation);
            }
            return Err(error).context("rollback switch failed; outgoing selector restored");
        }
        let recorded = store(&self.state_path, &previous).and_then(|()| match &active {
            Some(active) => store(&self.previous_path(), active),
            None => remove_file(&self.previous_path()),
        });
        if let Err(error) = recorded {
            let _ = store(&self.previous_path(), &previous);
            if let Some(active) = &active {
                let _ = store(&self.state_path, active);
                let _ = self.select(&active.descriptor, &active.generation);
            }
            return Err(error).context("recording the rollback failed; switch undone");
        }
        previous.descriptor.digest()
    }

    /// Generation id over the descriptor and the serving configuration, so a changed
    /// image or placement launches a gated candidate instead of patching live pods.
    pub(crate) fn generation_for(&self, descriptor: &ModelRuntimeDescriptor) -> Result<String> {
        let serving = json!({
            "descriptor": descriptor.digest()?,
            "engine": self.config.engine.name(),
            "namespace": self.config.namespace,
            "image": self.config.image,
            "weights_claim": self.config.weights_claim,
            "node_selector": self.config.node_selector,
            "tolerations": self.config.tolerations,
        });
        let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&serving)?));
        Ok(digest[..GENERATION_LEN].to_string())
    }

    /// Exclusive lock on `<state>.lock` for the whole lifecycle step, so concurrent
    /// applies, rollbacks, and removes on one state path (even from separate executor
    /// instances) never interleave their selector switch and state writes.
    fn lock(&self) -> Result<std::fs::File> {
        let path = self.state_path.with_extension("lock");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.lock()
            .with_context(|| format!("locking {}", path.display()))?;
        Ok(file)
    }

    /// Load a record, refusing one from another cluster or namespace: its objects would
    /// be unreachable from this configuration and left running.
    fn load_in_scope(&self, path: &Path) -> Result<Option<Recorded>> {
        let recorded = load(path)?;
        if let Some(recorded) = &recorded
            && (recorded.cluster_config != self.config.cluster_config
                || recorded.namespace != self.config.namespace)
        {
            bail!(
                "model_runtime state {} belongs to namespace {} on another cluster configuration; remove it there before changing scope",
                path.display(),
                recorded.namespace
            );
        }
        Ok(recorded)
    }

    fn previous_path(&self) -> PathBuf {
        self.state_path.with_extension("json.previous")
    }

    fn cluster(&self) -> &Path {
        &self.config.cluster_config
    }

    fn apply_object(&self, object: &Value) -> Result<()> {
        self.api
            .apply_server_side(
                self.cluster(),
                &self.config.namespace,
                FIELD_MANAGER,
                object,
            )
            .map(|_| ())
    }

    fn remove_generation(&self, product: &str, generation: &str) -> Result<()> {
        let name = deployment_name(product, generation);
        self.api
            .remove(self.cluster(), &self.config.namespace, &name, "Service")?;
        self.api
            .remove(self.cluster(), &self.config.namespace, &name, "Deployment")
    }

    fn wait_available(&self, name: &str, deadline: Instant) -> Result<()> {
        loop {
            let problem = match self.api.observe(
                self.cluster(),
                &self.config.namespace,
                name,
                "Deployment",
            )? {
                Some(observation) => disagreeing_condition(&observation),
                None => Some(format!("Deployment {name} is absent")),
            };
            let Some(problem) = problem else {
                return Ok(());
            };
            if Instant::now() >= deadline {
                bail!("{problem}");
            }
            std::thread::sleep(self.poll_interval);
        }
    }

    /// Retry the smoke probe until the startup deadline: Service endpoints and DNS can
    /// lag a Deployment becoming Available.
    fn smoke_until_deadline(
        &self,
        descriptor: &ModelRuntimeDescriptor,
        service: &str,
        deadline: Instant,
    ) -> Result<()> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!(
                    "{} smoke probe did not pass before the startup deadline",
                    self.config.engine.name()
                );
            }
            let outcome = self.probe.smoke(
                &self.config.namespace,
                service,
                descriptor.runtime.port,
                &descriptor.product_name,
                &descriptor.health,
                remaining,
            );
            if Instant::now() > deadline {
                bail!(
                    "{} smoke probe answered after the startup deadline",
                    self.config.engine.name()
                );
            }
            if outcome.is_ok() {
                return outcome;
            }
            std::thread::sleep(
                self.poll_interval
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    /// Point the stable Service at `generation`.
    fn select(&self, descriptor: &ModelRuntimeDescriptor, generation: &str) -> Result<()> {
        self.apply_object(&service(
            &stable_name(&descriptor.product_name),
            &descriptor.product_name,
            generation,
            descriptor.runtime.port,
        ))
    }

    /// Unpack the verified directory archive once into `<cache>/models/<hex>`.
    fn stage_model_directory(&self, descriptor: &ModelRuntimeDescriptor) -> Result<PathBuf> {
        if descriptor.model.format != MODEL_DIRECTORY_FORMAT {
            bail!(
                "{} model_runtime needs model.format={MODEL_DIRECTORY_FORMAT}, got {}",
                self.config.engine.name(),
                descriptor.model.format
            );
        }
        let archive = self.weight_cache.fetch_and_verify(&descriptor.model)?;
        let hex = descriptor
            .model
            .artifact_digest
            .trim_start_matches("sha256:");
        let target = self.weight_cache.root().join("models").join(hex);
        if target.is_dir() {
            // The engine loads the extracted files, so they must still match the archive.
            if directory_matches_archive(&archive, &target)? {
                return Ok(target);
            }
            std::fs::remove_dir_all(&target).with_context(|| {
                format!("removing drifted model directory {}", target.display())
            })?;
        }
        // Per-invocation staging: concurrent executors sharing the cache never touch
        // each other's partial extraction, and only a complete one is promoted.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let staging = target.with_extension(format!("partial-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&staging)
            .with_context(|| format!("creating {}", staging.display()))?;
        if let Err(error) = unpack_regular_entries(&archive, &staging) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }
        if let Err(error) = std::fs::rename(&staging, &target) {
            let _ = std::fs::remove_dir_all(&staging);
            if !target.is_dir() {
                return Err(error)
                    .with_context(|| format!("promoting model directory {}", target.display()));
            }
        }
        Ok(target)
    }

    fn deployment(&self, descriptor: &ModelRuntimeDescriptor, generation: &str) -> Result<Value> {
        let gpu = descriptor.requirements.gpu.as_ref().with_context(|| {
            format!(
                "{} model_runtime needs [requirements.gpu] to size its GPU request",
                self.config.engine.name()
            )
        })?;
        let model_dir = self.stage_model_directory(descriptor)?;
        let relative = model_dir
            .strip_prefix(self.weight_cache.root())
            .context("staged model directory is outside the weight cache root")?;
        let model_path = Path::new(WEIGHTS_MOUNT).join(relative);
        let resource =
            if gpu.vendor.iter().any(|vendor| vendor == "nvidia") || gpu.vendor.is_empty() {
                "nvidia.com/gpu"
            } else if gpu.vendor.iter().any(|vendor| vendor == "amd") {
                "amd.com/gpu"
            } else {
                bail!(
                    "{} model_runtime supports nvidia or amd GPUs, got {:?}",
                    self.config.engine.name(),
                    gpu.vendor
                );
            };
        let devices = gpu.count.max(gpu.tensor_parallel).to_string();
        let port = descriptor.runtime.port;
        let name = deployment_name(&descriptor.product_name, generation);
        let labels = labels(
            &descriptor.product_name,
            generation,
            &descriptor.product_version,
        );
        let (args, env) = self.config.engine.container(
            &model_path,
            &descriptor.product_name,
            port,
            gpu.tensor_parallel,
            descriptor.runtime.context_length,
        );
        Ok(json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": name, "labels": labels},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {
                    PRODUCT_LABEL: k8s_label_value(&descriptor.product_name),
                    GENERATION_LABEL: generation,
                }},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "nodeSelector": self.config.node_selector,
                        "tolerations": self.config.tolerations,
                        "containers": [{
                            "name": self.config.engine.name(),
                            "image": self.config.image,
                            "args": args,
                            "env": env,
                            "ports": [{"containerPort": port}],
                            "resources": {
                                "requests": {
                                    resource: devices,
                                    "memory": format!("{}Gi", descriptor.requirements.memory_gib),
                                },
                                "limits": {resource: devices},
                            },
                            "readinessProbe": {
                                "httpGet": {"path": "/health", "port": port},
                                "periodSeconds": 10,
                            },
                            "volumeMounts": [
                                {"name": "weights", "mountPath": WEIGHTS_MOUNT, "readOnly": true},
                                // Engine workers and NCCL need more than the default 64 MiB.
                                {"name": "dshm", "mountPath": "/dev/shm"},
                            ],
                        }],
                        "volumes": [
                            {
                                "name": "weights",
                                "persistentVolumeClaim": {
                                    "claimName": self.config.weights_claim,
                                    "readOnly": true,
                                },
                            },
                            {"name": "dshm", "emptyDir": {"medium": "Memory"}},
                        ],
                    },
                },
            },
        }))
    }
}

impl<A: ClusterApplyApi, P: SmokeProbe> ModelRuntimeExecutor
    for KubernetesModelRuntimeExecutor<A, P>
{
    fn apply(&self, descriptor: &ModelRuntimeDescriptor) -> Result<String> {
        descriptor.validate()?;
        if descriptor.runtime.engine != self.config.engine.name() {
            bail!(
                "this executor serves runtime.engine={}, got {}",
                self.config.engine.name(),
                descriptor.runtime.engine
            );
        }
        require_digest_pinned(&self.config.image)?;
        let _lock = self.lock()?;
        let expected = descriptor.digest()?;
        let generation = self.generation_for(descriptor)?;
        let active = self.load_in_scope(&self.state_path)?;
        let stale = self.load_in_scope(&self.previous_path())?;
        let name = deployment_name(&descriptor.product_name, &generation);
        let already_active = active
            .as_ref()
            .is_some_and(|active| active.generation == generation);
        // Staging the weights happens before the startup budget starts.
        let deployment = self.deployment(descriptor, &generation)?;
        let candidate_service = service(
            &name,
            &descriptor.product_name,
            &generation,
            descriptor.runtime.port,
        );
        // One startup budget for readiness and smoke: the descriptor's limit, capped by
        // the executor's.
        let startup = Duration::from_secs(descriptor.health.max_startup_seconds.into());
        let deadline = Instant::now() + startup.min(self.timeout);
        let gate = self
            .apply_object(&deployment)
            .and_then(|()| self.apply_object(&candidate_service))
            .and_then(|()| self.wait_available(&name, deadline))
            .and_then(|()| self.smoke_until_deadline(descriptor, &name, deadline));
        if let Err(error) = gate {
            // Never delete the active generation or the one retained for rollback.
            let retained = stale.as_ref().map(|stale| stale.generation.as_str());
            if !already_active && retained != Some(generation.as_str()) {
                let _ = self.remove_generation(&descriptor.product_name, &generation);
            }
            return Err(error).context(format!(
                "{} generation failed launch, readiness, or smoke; traffic left unchanged",
                self.config.engine.name()
            ));
        }
        if already_active {
            // Reconciled the recorded generation; re-assert its selector.
            self.select(descriptor, &generation)?;
            return Ok(expected);
        }
        let retained_candidate =
            stale.as_ref().map(|stale| stale.generation.as_str()) == Some(generation.as_str());
        if let Err(error) = self.select(descriptor, &generation) {
            // The patch may have landed despite the error: restore the outgoing selector
            // (or drop the new stable Service) before freeing the candidate's GPUs.
            let restored = match &active {
                Some(active) => self.select(&active.descriptor, &active.generation),
                None => self.api.remove(
                    self.cluster(),
                    &self.config.namespace,
                    &stable_name(&descriptor.product_name),
                    "Service",
                ),
            };
            if restored.is_err() {
                return Err(error).context(
                    "switching the stable Service failed and the outgoing selector could not be restored; candidate kept",
                );
            }
            if !retained_candidate {
                let _ = self.remove_generation(&descriptor.product_name, &generation);
            }
            return Err(error).context("switching the stable Service failed; switch undone");
        }
        // Record the switch; if that fails, point traffic back at the outgoing generation.
        let candidate = Recorded {
            generation: generation.clone(),
            descriptor: descriptor.clone(),
            cluster_config: self.config.cluster_config.clone(),
            namespace: self.config.namespace.clone(),
        };
        let recorded = match &active {
            Some(active) => store(&self.previous_path(), active),
            None => remove_file(&self.previous_path()),
        }
        .and_then(|()| store(&self.state_path, &candidate));
        if let Err(error) = recorded {
            // Undo the switch: the recorded pair and the selector stay as they were.
            let _ = match &stale {
                Some(stale) => store(&self.previous_path(), stale),
                None => remove_file(&self.previous_path()),
            };
            match &active {
                Some(active) => {
                    let _ = store(&self.state_path, active);
                    // Free the unrecorded candidate only once traffic is back on the
                    // outgoing generation, and never the retained rollback generation.
                    let restored = self.select(&active.descriptor, &active.generation);
                    if restored.is_ok() && !retained_candidate {
                        let _ = self.remove_generation(&descriptor.product_name, &generation);
                    }
                }
                None => {
                    let _ = remove_file(&self.state_path);
                    let _ = self.api.remove(
                        self.cluster(),
                        &self.config.namespace,
                        &stable_name(&descriptor.product_name),
                        "Service",
                    );
                    let _ = self.remove_generation(&descriptor.product_name, &generation);
                }
            }
            return Err(error).context("recording the activated generation failed; switch undone");
        }
        // Keep the outgoing generation for rollback and drop the one before it. Best
        // effort: a leftover generation is garbage, not a wrong activation.
        if let Some(stale) = stale {
            let outgoing = active.as_ref().map(|active| active.generation.as_str());
            if stale.generation != generation && outgoing != Some(stale.generation.as_str()) {
                let _ = self.remove_generation(&stale.descriptor.product_name, &stale.generation);
            }
        }
        Ok(expected)
    }

    fn remove(&self) -> Result<()> {
        let _lock = self.lock()?;
        for path in [self.state_path.clone(), self.previous_path()] {
            if let Some(recorded) = self.load_in_scope(&path)? {
                let product = &recorded.descriptor.product_name;
                self.remove_generation(product, &recorded.generation)?;
                self.api.remove(
                    self.cluster(),
                    &self.config.namespace,
                    &stable_name(product),
                    "Service",
                )?;
            }
            remove_file(&path)?;
        }
        Ok(())
    }

    fn observe(&self) -> Result<Option<String>> {
        self.load_in_scope(&self.state_path)?
            .map(|recorded| recorded.descriptor.digest())
            .transpose()
    }
}

/// A served generation: its id and the descriptor it serves. The id also covers the
/// serving configuration at launch, so it is recorded rather than recomputed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Recorded {
    generation: String,
    descriptor: ModelRuntimeDescriptor,
    /// Cluster and namespace the generation runs in.
    cluster_config: PathBuf,
    namespace: String,
}

/// Suffix reserved for stable Services. Candidates end in a hex generation id, so the
/// two name sets never overlap whatever the product names are.
const STABLE_SUFFIX: &str = "-svc";

/// The product as a DNS-1123 label of at most `NAME_LIMIT - STABLE_SUFFIX` chars,
/// starting with a letter. When sanitizing or shortening changed the product id, a
/// short digest of the original keeps distinct products apart.
fn base_name(product: &str) -> String {
    let limit = NAME_LIMIT - STABLE_SUFFIX.len();
    let mut name = String::new();
    for c in product.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            name.push(c);
        } else if !name.ends_with('-') {
            name.push('-');
        }
    }
    let mut name = name.trim_matches('-').to_string();
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert_str(0, "m-");
    }
    if name == product && name.len() <= limit {
        return name;
    }
    let digest = format!("{:x}", Sha256::digest(product.as_bytes()));
    let prefix: String = name.chars().take(limit - 7).collect();
    let prefix = prefix.trim_end_matches('-');
    if prefix.is_empty() {
        format!("m-{}", &digest[..6])
    } else {
        format!("{prefix}-{}", &digest[..6])
    }
}

/// Stable Service name for the product.
fn stable_name(product: &str) -> String {
    format!("{}{STABLE_SUFFIX}", base_name(product))
}

/// Candidate Deployment/Service name: shortened base plus the generation id.
fn deployment_name(product: &str, generation: &str) -> String {
    let prefix: String = base_name(product)
        .chars()
        .take(NAME_LIMIT - GENERATION_LEN - 1)
        .collect();
    format!("{}-{generation}", prefix.trim_end_matches('-'))
}

fn labels(product: &str, generation: &str, version: &str) -> Value {
    json!({
        PRODUCT_LABEL: k8s_label_value(product),
        GENERATION_LABEL: generation,
        "tenkai.version": k8s_label_value(version),
    })
}

fn service(name: &str, product: &str, generation: &str, port: u16) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "labels": {PRODUCT_LABEL: k8s_label_value(product)}},
        "spec": {
            "selector": {PRODUCT_LABEL: k8s_label_value(product), GENERATION_LABEL: generation},
            "ports": [{"port": port, "targetPort": port}],
        },
    })
}

/// Unpack only regular files and directories with plain relative paths; links and
/// other entry types are refused so nothing can resolve outside `target`.
fn unpack_regular_entries(archive: &Path, target: &Path) -> Result<()> {
    let file = std::fs::File::open(archive)
        .with_context(|| format!("opening model archive {}", archive.display()))?;
    let mut entries = tar::Archive::new(file);
    for entry in entries.entries().context("reading model archive")? {
        let mut entry = entry.context("reading model archive entry")?;
        let kind = entry.header().entry_type();
        let path = entry
            .path()
            .context("model archive entry path")?
            .into_owned();
        // `./`-prefixed entries from `tar -C dir .` are fine; parent, root, and
        // prefix components are not.
        if !(kind.is_file() || kind.is_dir())
            || path.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            })
        {
            bail!(
                "model archive entry {} is not a plain file or directory",
                path.display()
            );
        }
        if !entry.unpack_in(target).context("unpacking model archive")? {
            bail!(
                "model archive entry {} escapes the model directory",
                path.display()
            );
        }
    }
    Ok(())
}

/// The serving image must be `<name>@sha256:<64 hex>` so its contents cannot change
/// between applies.
fn require_digest_pinned(image: &str) -> Result<()> {
    let pinned = image.split_once("@sha256:").is_some_and(|(name, hex)| {
        !name.is_empty()
            && hex.len() == 64
            && hex
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    });
    if !pinned {
        bail!("serving image must be pinned by sha256 digest, got {image:?}");
    }
    Ok(())
}

/// Whether `dir` holds exactly the archive's regular files with identical contents.
fn directory_matches_archive(archive: &Path, dir: &Path) -> Result<bool> {
    let file = std::fs::File::open(archive)
        .with_context(|| format!("opening model archive {}", archive.display()))?;
    let mut expected = std::collections::BTreeMap::new();
    for entry in tar::Archive::new(file)
        .entries()
        .context("reading model archive")?
    {
        let mut entry = entry.context("reading model archive entry")?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path: PathBuf = entry
            .path()
            .context("model archive entry path")?
            .components()
            .filter(|part| matches!(part, std::path::Component::Normal(_)))
            .collect();
        let mut hasher = Sha256::new();
        std::io::copy(&mut entry, &mut hasher).context("hashing model archive entry")?;
        expected.insert(path, hasher.finalize());
    }
    let mut actual = std::collections::BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in
            std::fs::read_dir(&next).with_context(|| format!("listing {}", next.display()))?
        {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let mut hasher = Sha256::new();
                std::io::copy(&mut std::fs::File::open(entry.path())?, &mut hasher)?;
                let relative = entry
                    .path()
                    .strip_prefix(dir)
                    .context("model directory entry outside the directory")?
                    .to_path_buf();
                actual.insert(relative, hasher.finalize());
            } else {
                return Ok(false);
            }
        }
    }
    Ok(actual == expected)
}

fn load(path: &Path) -> Result<Option<Recorded>> {
    let recorded = tenkai::atomic_state::read_json_optional::<Recorded>(path)?;
    if let Some(recorded) = &recorded {
        recorded.descriptor.validate()?;
    }
    Ok(recorded)
}

fn store(path: &Path, recorded: &Recorded) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let expected = recorded.descriptor.digest()?;
    tenkai::atomic_state::write_json_verified(path, recorded, |observed: &Recorded| {
        if observed.descriptor.digest()? != expected || observed.generation != recorded.generation {
            bail!("model_runtime post-mutation verification failed");
        }
        Ok(())
    })
}

fn remove_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::in_process_kubernetes::{MemoryClusterApi, WorkloadCondition, WorkloadObservation};
    use std::sync::Mutex;
    use tenkai::manifest::{
        GpuRequirements, ModelRequirementsSection, ModelRuntimeSection, ModelSection,
    };
    use tenkai::model_runtime::MODEL_RUNTIME_CONTRACT_VERSION;

    const NS: &str = "gpu-a";

    /// Scripted smoke outcomes; records which services were probed.
    #[derive(Default)]
    struct ScriptedProbe {
        fail: Mutex<bool>,
        probed: Mutex<Vec<String>>,
    }

    impl SmokeProbe for &ScriptedProbe {
        fn smoke(
            &self,
            _namespace: &str,
            service: &str,
            _port: u16,
            _served_model: &str,
            _health: &ModelHealthSection,
            _timeout: Duration,
        ) -> Result<()> {
            self.probed.lock().unwrap().push(service.into());
            if *self.fail.lock().unwrap() {
                bail!("scripted smoke failure");
            }
            Ok(())
        }
    }

    /// Reports every Deployment unavailable while `unready` is set.
    struct Cluster<'a> {
        inner: &'a MemoryClusterApi,
        unready: Mutex<bool>,
    }

    impl ClusterApplyApi for &Cluster<'_> {
        fn apply_server_side(
            &self,
            cluster_config: &Path,
            namespace: &str,
            field_manager: &str,
            object: &Value,
        ) -> Result<WorkloadObservation> {
            self.inner
                .apply_server_side(cluster_config, namespace, field_manager, object)
        }

        fn observe(
            &self,
            cluster_config: &Path,
            namespace: &str,
            name: &str,
            kind: &str,
        ) -> Result<Option<WorkloadObservation>> {
            let observed = self.inner.observe(cluster_config, namespace, name, kind)?;
            Ok(observed.map(|mut observation| {
                if *self.unready.lock().unwrap() {
                    observation.conditions = vec![WorkloadCondition {
                        type_name: "Available".into(),
                        status: "False".into(),
                        reason: "MinimumReplicasUnavailable".into(),
                    }];
                }
                observation
            }))
        }

        fn remove(
            &self,
            cluster_config: &Path,
            namespace: &str,
            name: &str,
            kind: &str,
        ) -> Result<()> {
            self.inner.remove(cluster_config, namespace, name, kind)
        }
    }

    struct Fixture {
        root: PathBuf,
        cache: WeightCache,
        source: PathBuf,
        digest: String,
    }

    /// A tar archive of `entries` as (path, bytes) regular files.
    fn model_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn fixture_with(archive: &[u8]) -> Fixture {
        let root = std::env::temp_dir().join(format!("tenkai-vllm-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("model.tar");
        std::fs::write(&source, archive).unwrap();
        Fixture {
            cache: WeightCache::new(root.join("cache")),
            digest: format!("sha256:{:x}", Sha256::digest(archive)),
            source,
            root,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(&model_archive(&[
            ("config.json", b"{}"),
            ("tokenizer.json", b"{}"),
            ("model.safetensors", b"vllm-weights"),
        ]))
    }

    fn descriptor(fixture: &Fixture, version: &str) -> ModelRuntimeDescriptor {
        ModelRuntimeDescriptor {
            contract_version: MODEL_RUNTIME_CONTRACT_VERSION,
            product_name: "llama-70b".into(),
            product_version: version.into(),
            model: ModelSection {
                source: format!("file://{}", fixture.source.display()),
                revision: "r1".into(),
                format: MODEL_DIRECTORY_FORMAT.into(),
                quantization: "bf16".into(),
                artifact_digest: fixture.digest.clone(),
                license: "llama3".into(),
                registry_descriptor: String::new(),
                registry_attestation: String::new(),
            },
            runtime: ModelRuntimeSection {
                engine: "vllm".into(),
                port: 8000,
                context_length: 8192,
            },
            requirements: ModelRequirementsSection {
                architecture: vec!["x86_64".into()],
                memory_gib: 64,
                accelerator: vec![],
                gpu: Some(GpuRequirements {
                    vendor: vec!["nvidia".into()],
                    families: vec![],
                    vram_gib: 80,
                    count: 1,
                    tensor_parallel: 2,
                    driver_min: None,
                    runtime: None,
                    runtime_min: None,
                }),
            },
            health: ModelHealthSection {
                endpoint: "http://127.0.0.1:8000/v1/models".into(),
                smoke_prompt: "Return exactly: OK".into(),
                max_startup_seconds: 600,
            },
        }
    }

    fn config(fixture: &Fixture) -> ServingConfig {
        ServingConfig {
            engine: ServingEngine::Vllm,
            cluster_config: fixture.root.join("kubeconfig"),
            namespace: NS.into(),
            image: "vllm/vllm-openai@sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            weights_claim: "model-weights".into(),
            node_selector: BTreeMap::from([("gpu.family".into(), "hopper".into())]),
            tolerations: vec![json!({"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoSchedule"})],
        }
    }

    fn executor<'a>(
        fixture: &Fixture,
        cluster: &'a Cluster<'a>,
        probe: &'a ScriptedProbe,
    ) -> KubernetesModelRuntimeExecutor<&'a Cluster<'a>, &'a ScriptedProbe> {
        executor_for(fixture, cluster, probe, ServingEngine::Vllm)
    }

    fn executor_for<'a>(
        fixture: &Fixture,
        cluster: &'a Cluster<'a>,
        probe: &'a ScriptedProbe,
        engine: ServingEngine,
    ) -> KubernetesModelRuntimeExecutor<&'a Cluster<'a>, &'a ScriptedProbe> {
        KubernetesModelRuntimeExecutor::new(
            cluster,
            probe,
            ServingConfig {
                engine,
                ..config(fixture)
            },
            fixture.cache.clone(),
            fixture.root.join("state").join("llama-70b.json"),
        )
        .with_timeout(Duration::from_millis(50), Duration::from_millis(5))
    }

    fn selected_generation(api: &MemoryClusterApi) -> Option<String> {
        api.object(NS, "Service", "llama-70b-svc")?
            .pointer("/spec/selector/tenkai.generation")?
            .as_str()
            .map(str::to_string)
    }

    #[test]
    fn renders_gpu_requests_placement_and_read_only_weights() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor(&fixture, &cluster, &probe);
        let descriptor = descriptor(&fixture, "1.0.0");
        let deployment = executor
            .deployment(&descriptor, &executor.generation_for(&descriptor).unwrap())
            .unwrap();
        let pod = deployment.pointer("/spec/template/spec").unwrap();
        let container = &pod["containers"][0];
        assert_eq!(container["resources"]["limits"]["nvidia.com/gpu"], "2");
        assert_eq!(container["resources"]["requests"]["nvidia.com/gpu"], "2");
        assert_eq!(pod["nodeSelector"]["gpu.family"], "hopper");
        assert_eq!(pod["tolerations"][0]["key"], "nvidia.com/gpu");
        assert_eq!(pod["volumes"][1]["emptyDir"]["medium"], "Memory");
        assert_eq!(container["resources"]["requests"]["memory"], "64Gi");
        assert_eq!(container["volumeMounts"][0]["readOnly"], true);
        assert_eq!(
            pod["volumes"][0]["persistentVolumeClaim"]["claimName"],
            "model-weights"
        );
        assert_eq!(pod["volumes"][0]["persistentVolumeClaim"]["readOnly"], true);
        let args: Vec<&str> = container["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect();
        let hex = fixture.digest.trim_start_matches("sha256:");
        assert!(
            args.contains(&format!("/weights/models/{hex}").as_str()),
            "{args:?}"
        );
        let staged = fixture.cache.root().join("models").join(hex);
        assert_eq!(
            std::fs::read(staged.join("model.safetensors")).unwrap(),
            b"vllm-weights"
        );
        assert!(staged.join("tokenizer.json").is_file());
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--tensor-parallel-size", "2"])
        );
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn activates_only_after_readiness_and_smoke_and_rolls_back() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor(&fixture, &cluster, &probe);
        let v1 = descriptor(&fixture, "1.0.0");
        let v2 = descriptor(&fixture, "1.1.0");
        let (g1, g2) = (
            executor.generation_for(&v1).unwrap(),
            executor.generation_for(&v2).unwrap(),
        );

        executor.apply(&v1).unwrap();
        assert_eq!(selected_generation(&api), Some(g1.clone()));
        executor.apply(&v2).unwrap();
        assert_eq!(selected_generation(&api), Some(g2.clone()));
        assert_eq!(executor.observe().unwrap(), Some(v2.digest().unwrap()));
        assert_eq!(probe.probed.lock().unwrap().len(), 2);

        // Failed smoke: candidate removed, v2 stays active.
        let v3 = descriptor(&fixture, "1.2.0");
        let g3 = executor.generation_for(&v3).unwrap();
        *probe.fail.lock().unwrap() = true;
        assert!(executor.apply(&v3).is_err());
        assert!(
            api.object(NS, "Deployment", &format!("llama-70b-{g3}"))
                .is_none()
        );
        assert_eq!(selected_generation(&api), Some(g2.clone()));

        // Failed readiness: same outcome, no smoke attempt.
        *probe.fail.lock().unwrap() = false;
        *cluster.unready.lock().unwrap() = true;
        let probes_before = probe.probed.lock().unwrap().len();
        assert!(executor.apply(&v3).is_err());
        assert_eq!(probe.probed.lock().unwrap().len(), probes_before);
        assert!(
            api.object(NS, "Deployment", &format!("llama-70b-{g3}"))
                .is_none()
        );
        assert_eq!(executor.observe().unwrap(), Some(v2.digest().unwrap()));

        // Rollback re-selects the retained previous generation.
        *cluster.unready.lock().unwrap() = false;
        assert_eq!(executor.rollback().unwrap(), v1.digest().unwrap());
        assert_eq!(selected_generation(&api), Some(g1));
        assert_eq!(executor.observe().unwrap(), Some(v1.digest().unwrap()));
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    /// TGI runs the same gated lifecycle with its own server arguments: the
    /// mounted model directory, offline hub, and shards for tensor parallelism.
    #[test]
    fn tgi_serves_the_mounted_directory_offline_and_rolls_back() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor_for(&fixture, &cluster, &probe, ServingEngine::Tgi);
        let tgi = |version| {
            let mut descriptor = descriptor(&fixture, version);
            descriptor.runtime.engine = "tgi".into();
            descriptor
        };
        let (v1, v2, v3) = (tgi("1.0.0"), tgi("1.1.0"), tgi("1.2.0"));
        let (g1, g2, g3) = (
            executor.generation_for(&v1).unwrap(),
            executor.generation_for(&v2).unwrap(),
            executor.generation_for(&v3).unwrap(),
        );

        let container =
            executor.deployment(&v1, &g1).unwrap()["spec"]["template"]["spec"]["containers"][0]
                .clone();
        assert_eq!(container["name"], "tgi");
        let args: Vec<&str> = container["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect();
        let hex = fixture.digest.trim_start_matches("sha256:");
        let model = format!("/weights/models/{hex}");
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--model-id", model.as_str()]),
            "{args:?}"
        );
        assert!(
            args.windows(2).any(|pair| pair == ["--num-shard", "2"]),
            "{args:?}"
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--max-total-tokens", "8192"]),
            "{args:?}"
        );
        assert_eq!(
            container["env"][0],
            json!({"name": "HF_HUB_OFFLINE", "value": "1"})
        );
        assert_eq!(container["resources"]["limits"]["nvidia.com/gpu"], "2");

        executor.apply(&v1).unwrap();
        executor.apply(&v2).unwrap();
        assert_eq!(selected_generation(&api), Some(g2.clone()));
        *probe.fail.lock().unwrap() = true;
        assert!(executor.apply(&v3).is_err());
        assert!(
            api.object(NS, "Deployment", &format!("llama-70b-{g3}"))
                .is_none()
        );
        assert_eq!(selected_generation(&api), Some(g2));
        assert_eq!(executor.rollback().unwrap(), v1.digest().unwrap());
        assert_eq!(selected_generation(&api), Some(g1));

        // A vLLM descriptor is not this executor's to serve.
        assert!(executor.apply(&descriptor(&fixture, "2.0.0")).is_err());
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn activation_retains_only_the_outgoing_generation() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor(&fixture, &cluster, &probe);
        let versions = ["1.0.0", "1.1.0", "1.2.0"].map(|version| descriptor(&fixture, version));
        for descriptor in &versions {
            executor.apply(descriptor).unwrap();
        }
        let deployed = |descriptor: &ModelRuntimeDescriptor| {
            let name = format!("llama-70b-{}", executor.generation_for(descriptor).unwrap());
            api.object(NS, "Deployment", &name).is_some()
        };
        assert!(!deployed(&versions[0]));
        assert!(deployed(&versions[1]));
        assert!(deployed(&versions[2]));

        executor.remove().unwrap();
        assert!(versions.iter().all(|descriptor| !deployed(descriptor)));
        assert!(api.object(NS, "Service", "llama-70b-svc").is_none());
        assert_eq!(executor.observe().unwrap(), None);
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn refuses_other_engines_and_variants_without_gpu_requirements() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor(&fixture, &cluster, &probe);
        let mut llama = descriptor(&fixture, "1.0.0");
        llama.runtime.engine = "llama.cpp".into();
        assert!(executor.apply(&llama).is_err());
        let mut no_gpu = descriptor(&fixture, "1.0.0");
        no_gpu.requirements.gpu = None;
        assert!(executor.apply(&no_gpu).is_err());
        assert_eq!(executor.observe().unwrap(), None);
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    /// A one-entry archive whose stored name is `name`, bypassing the builder's checks.
    fn raw_archive_named(name: &[u8]) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name);
        header.set_size(2);
        header.set_mode(0o644);
        header.set_cksum();
        let mut raw = header.as_bytes().to_vec();
        raw.extend_from_slice(b"{}");
        raw.resize(raw.len().div_ceil(512) * 512 + 1024, 0);
        raw
    }

    #[test]
    fn archives_with_links_or_escaping_paths_are_refused() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_link(&mut header, "tokenizer.json", "/etc/passwd")
            .unwrap();
        let with_link = builder.into_inner().unwrap();
        for archive in [with_link, raw_archive_named(b"../escaped.json")] {
            let fixture = fixture_with(&archive);
            let api = MemoryClusterApi::new();
            let cluster = Cluster {
                inner: &api,
                unready: Mutex::new(false),
            };
            let probe = ScriptedProbe::default();
            let executor = executor(&fixture, &cluster, &probe);
            assert!(executor.apply(&descriptor(&fixture, "1.0.0")).is_err());
            let hex = fixture.digest.trim_start_matches("sha256:").to_string();
            assert!(!fixture.cache.root().join("models").join(&hex).exists());
            assert!(
                !fixture
                    .cache
                    .root()
                    .join("models")
                    .join("escaped.json")
                    .exists()
            );
            let _ = std::fs::remove_dir_all(fixture.root);
        }
    }

    #[test]
    fn object_names_are_dns_labels_and_keep_products_apart() {
        for product in ["My_Model", "my.model+v2", "llama-70b", "---", "123-model"] {
            for name in [
                stable_name(product),
                deployment_name(product, "0123456789ab"),
            ] {
                assert!(name.len() <= NAME_LIMIT, "{name}");
                assert!(
                    name.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                        && name.starts_with(|c: char| c.is_ascii_lowercase())
                        && !name.ends_with('-'),
                    "{product} -> {name}"
                );
            }
        }
        assert_eq!(stable_name("llama-70b"), "llama-70b-svc");
        // A product named like another product's candidate cannot take its Service.
        let candidate = deployment_name("foo", "0123456789ab");
        assert_ne!(stable_name(&candidate), candidate);
        assert_ne!(stable_name("My_Model"), stable_name("my-model"));
        let (long_a, long_b) = (
            format!("{}a", "x".repeat(63)),
            format!("{}b", "x".repeat(63)),
        );
        assert_ne!(stable_name(&long_a), stable_name(&long_b));
    }

    #[test]
    fn long_product_names_keep_candidates_apart_from_the_stable_service() {
        let product = "a".repeat(63);
        let name = deployment_name(&product, "0123456789ab");
        assert!(name.len() <= NAME_LIMIT, "{name}");
        assert!(name.ends_with("-0123456789ab"));
        assert_ne!(name, stable_name(&product));
    }

    #[test]
    fn reapplying_the_active_descriptor_restores_its_selector() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor(&fixture, &cluster, &probe);
        let v1 = descriptor(&fixture, "1.0.0");
        let v2 = descriptor(&fixture, "1.1.0");
        executor.apply(&v1).unwrap();
        executor.apply(&v2).unwrap();
        api.apply_server_side(
            Path::new("kubeconfig"),
            NS,
            FIELD_MANAGER,
            &service(
                "llama-70b-svc",
                "llama-70b",
                &executor.generation_for(&v1).unwrap(),
                8000,
            ),
        )
        .unwrap();
        executor.apply(&v2).unwrap();
        assert_eq!(
            selected_generation(&api),
            Some(executor.generation_for(&v2).unwrap())
        );
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn failed_reapply_keeps_the_retained_generation_and_reconcile_recreates_the_active_one() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor(&fixture, &cluster, &probe);
        let v1 = descriptor(&fixture, "1.0.0");
        let v2 = descriptor(&fixture, "1.1.0");
        executor.apply(&v1).unwrap();
        executor.apply(&v2).unwrap();
        let v1_name = format!("llama-70b-{}", executor.generation_for(&v1).unwrap());
        let v2_name = format!("llama-70b-{}", executor.generation_for(&v2).unwrap());

        *probe.fail.lock().unwrap() = true;
        assert!(executor.apply(&v1).is_err());
        assert!(api.object(NS, "Deployment", &v1_name).is_some());
        *probe.fail.lock().unwrap() = false;

        api.remove(Path::new("kubeconfig"), NS, &v2_name, "Deployment")
            .unwrap();
        executor.apply(&v2).unwrap();
        assert!(api.object(NS, "Deployment", &v2_name).is_some());
        assert_eq!(executor.rollback().unwrap(), v1.digest().unwrap());
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn current_directory_entries_from_ordinary_tarballs_are_accepted() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        dir.set_cksum();
        builder
            .append_data(&mut dir, "./", std::io::empty())
            .unwrap();
        for (path, bytes) in [("./config.json", &b"{}"[..]), ("./model.safetensors", b"w")] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, bytes).unwrap();
        }
        let fixture = fixture_with(&builder.into_inner().unwrap());
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor(&fixture, &cluster, &probe);
        executor.apply(&descriptor(&fixture, "1.0.0")).unwrap();
        let hex = fixture.digest.trim_start_matches("sha256:").to_string();
        assert!(
            fixture
                .cache
                .root()
                .join("models")
                .join(hex)
                .join("config.json")
                .is_file()
        );
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn serving_config_change_launches_a_gated_generation_instead_of_patching() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let v1 = descriptor(&fixture, "1.0.0");
        let before = executor(&fixture, &cluster, &probe);
        before.apply(&v1).unwrap();
        let old_generation = before.generation_for(&v1).unwrap();

        let mut changed = config(&fixture);
        changed.image = "vllm/vllm-openai@sha256:1111111111111111111111111111111111111111111111111111111111111111".into();
        let after = KubernetesModelRuntimeExecutor::new(
            &cluster,
            &probe,
            changed,
            fixture.cache.clone(),
            fixture.root.join("state").join("llama-70b.json"),
        )
        .with_timeout(Duration::from_millis(50), Duration::from_millis(5));
        let new_generation = after.generation_for(&v1).unwrap();
        assert_ne!(old_generation, new_generation);

        // A failing gate leaves the old generation serving, untouched.
        *probe.fail.lock().unwrap() = true;
        assert!(after.apply(&v1).is_err());
        assert_eq!(selected_generation(&api), Some(old_generation.clone()));
        let old_name = format!("llama-70b-{old_generation}");
        let old_image = api.object(NS, "Deployment", &old_name).unwrap()
            ["spec"]["template"]["spec"]["containers"][0]["image"]
            .clone();
        assert!(old_image.as_str().unwrap().ends_with("0000"));

        *probe.fail.lock().unwrap() = false;
        after.apply(&v1).unwrap();
        assert_eq!(selected_generation(&api), Some(new_generation));
        assert_eq!(after.rollback().unwrap(), v1.digest().unwrap());
        assert_eq!(selected_generation(&api), Some(old_generation));
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn concurrent_applies_leave_selector_and_record_in_agreement() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor(&fixture, &cluster, &probe);
        let versions: Vec<_> = (0..4)
            .map(|minor| descriptor(&fixture, &format!("1.{minor}.0")))
            .collect();
        std::thread::scope(|scope| {
            for descriptor in &versions {
                let executor = &executor;
                scope.spawn(move || executor.apply(descriptor).unwrap());
            }
        });
        let active = load(&executor.state_path).unwrap().unwrap();
        assert_eq!(selected_generation(&api), Some(active.generation));
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn changing_namespace_against_existing_state_is_refused() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let v1 = descriptor(&fixture, "1.0.0");
        executor(&fixture, &cluster, &probe).apply(&v1).unwrap();
        let mut moved = config(&fixture);
        moved.namespace = "gpu-b".into();
        let elsewhere = KubernetesModelRuntimeExecutor::new(
            &cluster,
            &probe,
            moved,
            fixture.cache.clone(),
            fixture.root.join("state").join("llama-70b.json"),
        );
        assert!(elsewhere.apply(&v1).is_err());
        assert!(elsewhere.remove().is_err());
        assert!(api.object(NS, "Service", "llama-70b-svc").is_some());
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn drifted_model_directories_are_rebuilt_from_the_archive() {
        let fixture = fixture();
        let api = MemoryClusterApi::new();
        let cluster = Cluster {
            inner: &api,
            unready: Mutex::new(false),
        };
        let probe = ScriptedProbe::default();
        let executor = executor(&fixture, &cluster, &probe);
        let v1 = descriptor(&fixture, "1.0.0");
        executor.apply(&v1).unwrap();
        let hex = fixture.digest.trim_start_matches("sha256:").to_string();
        let staged = fixture.cache.root().join("models").join(&hex);
        std::fs::write(staged.join("model.safetensors"), b"tampered").unwrap();
        std::fs::write(staged.join("extra.json"), b"{}").unwrap();
        executor.apply(&descriptor(&fixture, "1.1.0")).unwrap();
        assert_eq!(
            std::fs::read(staged.join("model.safetensors")).unwrap(),
            b"vllm-weights"
        );
        assert!(!staged.join("extra.json").exists());
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[test]
    fn serving_images_must_be_digest_pinned() {
        for image in [
            "vllm/vllm-openai:latest",
            "vllm/vllm-openai",
            "@sha256:00",
            "x@sha256:ABC",
        ] {
            assert!(require_digest_pinned(image).is_err(), "{image}");
        }
        require_digest_pinned(&config(&fixture()).image).unwrap();
    }
}
