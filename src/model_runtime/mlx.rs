//! Host-process `model_runtime` executor for Apple silicon / edge hosts.
//!
//! `runtime.engine = "mlx"` follows the llama.cpp lifecycle: [`WeightCache`]
//! verifies weights, a candidate binds loopback, health plus a completion smoke
//! must pass, then the candidate activates and the previous generation is
//! retained. Default CI uses [`FakeMlxEngine`]; a real `mlx_lm.server` (or
//! equivalent) is selected only when `TENKAI_MLX_SERVER` or
//! `TENKAI_USE_REAL_MLX` is set. The core crate never links MLX.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};

use super::{
    EngineHandle, EngineStartRequest, InferenceEngineProcess, ModelRuntimeDescriptor,
    ModelRuntimeExecutor, WeightCache, bind_host_from_health_endpoint, require_loopback_bind,
    require_loopback_health_endpoint,
};
use crate::manifest::ModelHealthSection;

/// Manifest `runtime.engine` id for this plugin.
pub const MLX_ENGINE: &str = "mlx";

const DEFAULT_SMOKE_PROMPT: &str = "Return exactly: OK";
const SERVER_ENV: &str = "TENKAI_MLX_SERVER";
const USE_REAL_ENV: &str = "TENKAI_USE_REAL_MLX";
const DEFAULT_BINARY: &str = "mlx_lm.server";

/// Deterministic fake MLX process for CI. No sockets, no Apple GPU, no binary.
#[derive(Debug, Default)]
pub struct FakeMlxEngine {
    pub fail_smoke: bool,
    pub fail_start: bool,
    pub last_start: Mutex<Option<EngineStartRequest>>,
}

impl InferenceEngineProcess for FakeMlxEngine {
    fn start_candidate(&self, request: &EngineStartRequest) -> Result<EngineHandle> {
        require_loopback_bind(&request.bind_host, request.port)?;
        if request.engine != MLX_ENGINE {
            bail!(
                "mlx executor supports runtime.engine={MLX_ENGINE} only, got {}",
                request.engine
            );
        }
        if self.fail_start {
            bail!(
                "fake mlx engine refused to start candidate generation {}",
                request.generation_id
            );
        }
        *self.last_start.lock().expect("fake mlx start lock") = Some(request.clone());
        Ok(EngineHandle {
            generation_id: request.generation_id.clone(),
            port: request.port,
            bind_host: request.bind_host.clone(),
            marker: format!("fake-mlx:{}", request.generation_id),
        })
    }

    fn smoke(&self, handle: &EngineHandle, health: &ModelHealthSection) -> Result<()> {
        require_loopback_health_endpoint(&health.endpoint)?;
        if self.fail_smoke {
            bail!(
                "fake mlx engine smoke failed for generation {} at {}",
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

/// Optional real `mlx_lm.server` launcher (external binary, not a crate dep).
///
/// Spawns `TENKAI_MLX_SERVER` (default `mlx_lm.server`) bound to loopback with
/// argv only. Community software-only deploys do not require this binary; use
/// [`FakeMlxEngine`] in tests and default apply wiring when unset.
///
/// The launcher keeps each candidate's `Child` (#1292): a smoke passes only
/// while the candidate it started is alive, and stopping it signals that
/// child. A handle recorded by an earlier process carries the server's start
/// time, and stop signals its PID only while that PID still has that start
/// time.
#[derive(Debug, Clone)]
pub struct MlxLmServerLauncher {
    binary: PathBuf,
    children: Arc<Mutex<HashMap<String, std::process::Child>>>,
}

impl MlxLmServerLauncher {
    pub fn new(binary: PathBuf) -> Self {
        Self {
            binary,
            children: Arc::default(),
        }
    }

    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Whether the candidate for `generation` that this launcher started is
    /// still running; `None` when this launcher did not start it.
    fn child_running(&self, generation: &str) -> Result<Option<bool>> {
        let mut children = self.children.lock().expect("mlx children lock");
        match children.get_mut(generation) {
            Some(child) => Ok(Some(child.try_wait()?.is_none())),
            None => Ok(None),
        }
    }

    fn require_candidate_running(&self, handle: &EngineHandle) -> Result<()> {
        match self.child_running(&handle.generation_id)? {
            Some(true) => Ok(()),
            Some(false) => bail!(
                "mlx candidate for generation {} exited; nothing it started is serving port {}",
                handle.generation_id,
                handle.port
            ),
            None => {
                let (pid, started) = recorded_process(&handle.marker)?;
                if process_start_time(pid)?.as_deref() != Some(started) {
                    bail!(
                        "mlx server for generation {} (pid {pid}) is no longer running",
                        handle.generation_id
                    );
                }
                Ok(())
            }
        }
    }
}

impl Default for MlxLmServerLauncher {
    fn default() -> Self {
        let binary = std::env::var_os(SERVER_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BINARY));
        Self::new(binary)
    }
}

/// `pid:<pid>@<start time>` from a handle this launcher recorded. A bare
/// `pid:<pid>` (recorded before #1292) has no identity to check.
fn recorded_process(marker: &str) -> Result<(u32, &str)> {
    let recorded = marker
        .strip_prefix("pid:")
        .with_context(|| format!("mlx handle marker {marker:?} names no process"))?;
    let (pid, started) = recorded.split_once('@').with_context(|| {
        format!(
            "mlx handle for pid {recorded} records no start time, so its identity cannot be checked; stop that server by hand"
        )
    })?;
    let pid = pid
        .parse::<u32>()
        .with_context(|| format!("mlx handle marker {marker:?} has an invalid pid"))?;
    if pid == 0 || started.is_empty() {
        bail!("mlx handle marker {marker:?} is incomplete");
    }
    Ok((pid, started))
}

/// The start time `ps` reports for `pid`, or `None` when no such process
/// runs. Together with the PID it identifies one process: a reused PID has a
/// later start time.
fn process_start_time(pid: u32) -> Result<Option<String>> {
    // Fixed zone and locale: another Tenkai process must read the same text.
    let output = std::process::Command::new("ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .env("TZ", "UTC")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .context("reading the process start time with ps")?;
    let started = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok((output.status.success() && !started.is_empty()).then_some(started))
}

fn send_term(pid: u32) -> Result<()> {
    let status = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .context("signalling the mlx server")?;
    if !status.success() {
        bail!("kill -TERM {pid} failed");
    }
    Ok(())
}

impl InferenceEngineProcess for MlxLmServerLauncher {
    fn start_candidate(&self, request: &EngineStartRequest) -> Result<EngineHandle> {
        require_loopback_bind(&request.bind_host, request.port)?;
        if request.engine != MLX_ENGINE {
            bail!(
                "mlx launcher only supports runtime.engine={MLX_ENGINE}, got {}",
                request.engine
            );
        }
        let weights = request
            .weights_path
            .as_ref()
            .context("mlx launcher requires verified weights path")?;
        // A listener already on the port would answer the smoke in the
        // candidate's place, so the port must be free before the spawn.
        std::net::TcpListener::bind((request.bind_host.as_str(), request.port)).with_context(
            || {
                format!(
                    "mlx candidate port {}:{} is in use; a same-port handoff is not supported",
                    request.bind_host, request.port
                )
            },
        )?;
        // `--model` is the verified WeightCache blob, same as llama.cpp. This
        // plugin does not unpack a model directory; directory+tar is the vLLM path.
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
        let mut child = command.spawn().with_context(|| {
            format!(
                "starting mlx candidate via {} (set {SERVER_ENV} or use FakeMlxEngine)",
                self.binary.display()
            )
        })?;
        let pid = child.id();
        let started = match process_start_time(pid) {
            Ok(Some(started)) => started,
            outcome => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(outcome.err().unwrap_or_else(|| {
                    anyhow::anyhow!("mlx candidate pid {pid} exited before it was recorded")
                }));
            }
        };
        if let Some(mut replaced) = self
            .children
            .lock()
            .expect("mlx children lock")
            .insert(request.generation_id.clone(), child)
        {
            let _ = replaced.kill();
            let _ = replaced.wait();
        }
        Ok(EngineHandle {
            generation_id: request.generation_id.clone(),
            port: request.port,
            bind_host: request.bind_host.clone(),
            marker: format!("pid:{pid}@{started}"),
        })
    }

    fn smoke(&self, handle: &EngineHandle, health: &ModelHealthSection) -> Result<()> {
        let origin = loopback_http_origin(&health.endpoint)?;
        let prompt = if health.smoke_prompt.trim().is_empty() {
            DEFAULT_SMOKE_PROMPT
        } else {
            health.smoke_prompt.as_str()
        };
        let models_url = format!("{origin}/v1/models");
        let client = crate::outbound_tls::blocking_client()?
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(u64::from(
                health.max_startup_seconds.clamp(1, 60),
            )))
            .build()
            .context("building mlx health client")?;
        // Candidate binds the descriptor port, same as llama.cpp. Distinct
        // generations use distinct ports; a same-port handoff is not this plugin.
        let deadline =
            Instant::now() + Duration::from_secs(health.max_startup_seconds.max(1) as u64);
        let mut last_error = String::from("health probe did not run");
        while Instant::now() < deadline {
            // Only the process this launcher started may answer the smoke.
            self.require_candidate_running(handle)?;
            match client.get(&models_url).send() {
                Ok(response) if response.status().is_success() => {
                    completion_smoke(&client, &origin, prompt, handle)?;
                    return self.require_candidate_running(handle);
                }
                Ok(response) => {
                    last_error = format!(
                        "health endpoint {models_url} returned {}",
                        response.status()
                    );
                }
                Err(error) => last_error = error.to_string(),
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "mlx smoke failed for generation {} at {models_url}: {last_error}",
            handle.generation_id
        )
    }

    /// Signals the child this launcher started, or a recorded PID only while
    /// it still has the recorded start time. Never signals an unverified PID.
    fn stop(&self, handle: &EngineHandle) -> Result<()> {
        let child = self
            .children
            .lock()
            .expect("mlx children lock")
            .remove(&handle.generation_id);
        if let Some(mut child) = child {
            // Unreaped, so the PID cannot have been reused.
            if child.try_wait()?.is_none() {
                send_term(child.id())?;
                let deadline = Instant::now() + Duration::from_secs(10);
                while child.try_wait()?.is_none() {
                    if Instant::now() >= deadline {
                        child.kill()?;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                child.wait()?;
            }
            return Ok(());
        }
        let (pid, started) = recorded_process(&handle.marker)?;
        match process_start_time(pid)? {
            None => Ok(()),
            Some(current) if current == started => send_term(pid),
            Some(_) => bail!(
                "pid {pid} is not the mlx server recorded for generation {}; not signalled",
                handle.generation_id
            ),
        }
    }
}

fn operator_weight_cache(
    state_path: &Path,
    artifacts: Option<super::ModelRuntimeArtifacts>,
) -> WeightCache {
    let cache_root = crate::host_env::var_os("TENKAI_WEIGHT_CACHE")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| state_path.with_extension("weights"));
    match artifacts {
        Some(artifacts) => WeightCache::new(cache_root).with_environment(artifacts),
        None => WeightCache::new(cache_root),
    }
}

fn loopback_http_origin(endpoint: &str) -> Result<String> {
    require_loopback_health_endpoint(endpoint)?;
    let parsed = reqwest::Url::parse(endpoint).context("mlx health endpoint is not a URL")?;
    if parsed.scheme() != "http" {
        bail!(
            "mlx health origin must use loopback HTTP, got {}",
            parsed.scheme()
        );
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("mlx health endpoint must not include userinfo");
    }
    let host = parsed.host_str().unwrap_or_default();
    let (host, ipv6) = match host {
        "127.0.0.1" | "localhost" => (host, false),
        "::1" | "[::1]" => ("::1", true),
        _ => bail!("mlx health origin must be loopback, got host {host:?}"),
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    if ipv6 {
        Ok(format!("http://[{host}]:{port}"))
    } else {
        Ok(format!("http://{host}:{port}"))
    }
}

fn served_model_id(client: &reqwest::blocking::Client, origin: &str) -> Result<String> {
    let url = format!("{}/v1/models", origin.trim_end_matches('/'));
    let response: Value = client
        .get(&url)
        .send()
        .with_context(|| format!("mlx served-model lookup at {url}"))?
        .error_for_status()
        .with_context(|| format!("mlx served-model lookup at {url} failed"))?
        .json()
        .with_context(|| format!("mlx served-model lookup at {url} returned invalid JSON"))?;
    let id = response
        .pointer("/data/0/id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .with_context(|| format!("mlx served-model lookup at {url} returned no model id"))?;
    Ok(id.to_string())
}

fn completion_smoke(
    client: &reqwest::blocking::Client,
    origin: &str,
    prompt: &str,
    handle: &EngineHandle,
) -> Result<()> {
    let model = served_model_id(client, origin)?;
    let url = format!("{}/v1/completions", origin.trim_end_matches('/'));
    let response: Value = client
        .post(&url)
        .json(&json!({
            "model": model,
            "prompt": prompt,
            "max_tokens": 16,
            "temperature": 0,
        }))
        .send()
        .with_context(|| format!("mlx completion smoke to {url}"))?
        .error_for_status()
        .with_context(|| format!("mlx completion smoke to {url} failed"))?
        .json()
        .with_context(|| format!("mlx completion smoke to {url} returned invalid JSON"))?;
    let text = response
        .pointer("/choices/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if text.trim().is_empty() {
        bail!(
            "mlx completion smoke for generation {} returned an empty completion",
            handle.generation_id
        );
    }
    Ok(())
}

/// MLX host-process executor: verify weights → start candidate → health and
/// completion smoke → activate, retaining the previous generation for Tenkai
/// rollback.
pub struct MlxHostExecutor {
    state_path: PathBuf,
    weight_cache: Option<WeightCache>,
    engine: Arc<dyn InferenceEngineProcess>,
}

impl MlxHostExecutor {
    pub fn new(state_path: PathBuf, engine: Arc<dyn InferenceEngineProcess>) -> Self {
        Self {
            state_path,
            weight_cache: None,
            engine,
        }
    }

    /// Community/CI default: fake process, full lifecycle contract.
    pub fn with_fake(state_path: PathBuf) -> Self {
        Self::new(state_path, Arc::new(FakeMlxEngine::default()))
    }

    /// Operator host selection: real `mlx_lm.server` when `TENKAI_MLX_SERVER` is
    /// set (path to binary) or `TENKAI_USE_REAL_MLX=1`; otherwise the fake engine.
    ///
    /// The real launcher loads `--model <verified WeightCache path>`, so this
    /// path always attaches a cache (`TENKAI_WEIGHT_CACHE`, else a sidecar of
    /// the state file) and applies environment weight-origin policy when
    /// `artifacts` is present. Fake CI stays cache-free so default apply needs
    /// no weights. The core crate never links MLX.
    pub fn for_operator_host(
        state_path: PathBuf,
        artifacts: Option<super::ModelRuntimeArtifacts>,
    ) -> Self {
        let use_real = std::env::var_os(SERVER_ENV).is_some()
            || std::env::var(USE_REAL_ENV)
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        if use_real {
            Self::new(state_path.clone(), Arc::new(MlxLmServerLauncher::default()))
                .with_weight_cache(operator_weight_cache(&state_path, artifacts))
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

    /// Records the candidate as active. Each file is replaced atomically; a
    /// failure part way restores the previous descriptor and handle so state
    /// never names a generation whose handle is missing.
    fn activate(
        &self,
        descriptor: &ModelRuntimeDescriptor,
        candidate: &EngineHandle,
        previous_active: Option<&ModelRuntimeDescriptor>,
        previous_handle: Option<&EngineHandle>,
    ) -> Result<()> {
        if let Some(prev) = previous_active {
            self.write_descriptor(&self.previous_path(), prev)?;
        }
        let written = self
            .write_descriptor(&self.state_path, descriptor)
            .and_then(|()| self.write_handle(candidate));
        if written.is_err() {
            match previous_active {
                Some(prev) => {
                    let _ = self.write_descriptor(&self.state_path, prev);
                }
                None => {
                    let _ = crate::atomic_state::remove_if_exists(&self.state_path);
                }
            }
            match previous_handle {
                Some(prev) => {
                    let _ = self.write_handle(prev);
                }
                None => {
                    let _ = crate::atomic_state::remove_if_exists(&self.active_handle_path());
                }
            }
        }
        written
    }

    fn write_handle(&self, handle: &EngineHandle) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(handle)?;
        crate::atomic_state::write_bytes_verified(&self.active_handle_path(), &bytes, |read| {
            if serde_json::from_slice::<EngineHandle>(read)? != *handle {
                bail!("model_runtime engine handle verification failed");
            }
            Ok(())
        })
    }

    fn require_mlx_placement(descriptor: &ModelRuntimeDescriptor) -> Result<()> {
        if descriptor.runtime.engine != MLX_ENGINE {
            bail!(
                "MlxHostExecutor requires runtime.engine={MLX_ENGINE}, got {}",
                descriptor.runtime.engine
            );
        }
        if !descriptor
            .requirements
            .accelerator
            .iter()
            .any(|entry| entry == "apple-metal")
        {
            bail!(
                "model_runtime engine mlx requires requirements.accelerator to include apple-metal"
            );
        }
        if let Some(gpu) = &descriptor.requirements.gpu {
            let runtime = gpu.runtime.as_deref().unwrap_or("unset");
            bail!(
                "model_runtime engine mlx uses accelerator=[\"apple-metal\"] and must not declare requirements.gpu (cuda/rocm GPU facts), got runtime={runtime}"
            );
        }
        Ok(())
    }
}

impl ModelRuntimeExecutor for MlxHostExecutor {
    fn apply(&self, descriptor: &ModelRuntimeDescriptor) -> Result<String> {
        descriptor.validate()?;
        Self::require_mlx_placement(descriptor)?;
        // Verified blob path, same contract as llama.cpp: mlx_lm.server --model
        // loads that file (gguf/safetensors). Directory-tree serving is vLLM.
        let weights_path = if let Some(cache) = &self.weight_cache {
            Some(cache.fetch_and_verify(&descriptor.model)?)
        } else {
            None
        };

        let previous_active = Self::load_descriptor(&self.state_path)?;
        let previous_handle = Self::load_handle(&self.active_handle_path())?;
        let expected = descriptor.digest()?;
        let bind_host = bind_host_from_health_endpoint(&descriptor.health.endpoint)?;
        if let Some(active) = &previous_handle {
            // Re-applying the serving generation changes nothing.
            if active.generation_id == expected
                && self.observe()?.as_deref() == Some(expected.as_str())
                && self.engine.smoke(active, &descriptor.health).is_ok()
            {
                return Ok(expected);
            }
            // The candidate cannot bind while the active server holds the
            // port, and a smoke there would reach the active server (#1292).
            if active.generation_id != expected
                && active.port == descriptor.runtime.port
                && active.bind_host == bind_host
            {
                bail!(
                    "model_runtime candidate uses port {} of the active generation; a same-port handoff is not supported, so give the new release another port (active generation retained)",
                    active.port
                );
            }
        }
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

        let candidate = match self.engine.start_candidate(&start) {
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

        if let Err(error) = self.activate(
            descriptor,
            &candidate,
            previous_active.as_ref(),
            previous_handle.as_ref(),
        ) {
            let _ = self.engine.stop(&candidate);
            return Err(error).context(
                "model_runtime activation failed; candidate stopped and previous generation retained",
            );
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
    use crate::manifest::{
        GpuRequirements, ModelHealthSection, ModelRequirementsSection, ModelRuntimeSection,
        ModelSection,
    };
    use crate::model_runtime::MODEL_RUNTIME_CONTRACT_VERSION;
    use sha2::{Digest as _, Sha256};
    use std::sync::Arc;

    fn unique_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tenkai-mlx-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    fn mlx_descriptor() -> ModelRuntimeDescriptor {
        ModelRuntimeDescriptor {
            contract_version: MODEL_RUNTIME_CONTRACT_VERSION,
            product_name: "qwen-coder".into(),
            product_version: "3.2.1".into(),
            model: ModelSection {
                source: "hf://org/qwen-coder/qwen-coder-q4.safetensors".into(),
                revision: "9bcfabc0123456789abcdef0123456789abcdef0".into(),
                format: "safetensors".into(),
                quantization: "Q4".into(),
                artifact_digest: format!("sha256:{}", "ab".repeat(32)),
                license: "apache-2.0".into(),
                registry_descriptor: String::new(),
                registry_attestation: String::new(),
            },
            runtime: ModelRuntimeSection {
                engine: MLX_ENGINE.into(),
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

    /// A later release on its own port, as a handoff requires.
    fn other_port(mut descriptor: ModelRuntimeDescriptor) -> ModelRuntimeDescriptor {
        descriptor.product_version = "9.9.9".into();
        descriptor.runtime.port = 8090;
        descriptor.health.endpoint = "http://127.0.0.1:8090/v1/models".into();
        descriptor
    }

    #[test]
    fn apply_activates_after_smoke_and_retains_previous() {
        let root = unique_root("activate");
        let state = root.join("active.json");
        let executor = MlxHostExecutor::with_fake(state.clone());
        let mut first = mlx_descriptor();
        first.product_version = "1.0.0".into();
        let first_digest = executor.apply(&first).unwrap();
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(first_digest.as_str())
        );

        let mut second = mlx_descriptor();
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
    fn failed_candidate_smoke_leaves_previous_generation() {
        let root = unique_root("smoke-fail");
        let state = root.join("active.json");
        let ok = MlxHostExecutor::with_fake(state.clone());
        let good = mlx_descriptor();
        let active = ok.apply(&good).unwrap();

        let failing = MlxHostExecutor::new(
            state,
            Arc::new(FakeMlxEngine {
                fail_smoke: true,
                fail_start: false,
                last_start: Mutex::new(None),
            }),
        );
        let bad = other_port(mlx_descriptor());
        let err = failing.apply(&bad).unwrap_err().to_string();
        assert!(err.contains("smoke failed"), "{err}");
        assert_eq!(ok.observe().unwrap().as_deref(), Some(active.as_str()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_candidate_start_leaves_previous_generation() {
        let root = unique_root("start-fail");
        let state = root.join("active.json");
        let ok = MlxHostExecutor::with_fake(state.clone());
        let good = mlx_descriptor();
        let active = ok.apply(&good).unwrap();

        let failing = MlxHostExecutor::new(
            state,
            Arc::new(FakeMlxEngine {
                fail_smoke: false,
                fail_start: true,
                last_start: Mutex::new(None),
            }),
        );
        let bad = other_port(mlx_descriptor());
        let err = failing.apply(&bad).unwrap_err().to_string();
        assert!(err.contains("start failed"), "{err}");
        assert_eq!(ok.observe().unwrap().as_deref(), Some(active.as_str()));
        std::fs::remove_dir_all(root).unwrap();
    }

    /// #1292: a candidate on the active port is refused before it starts,
    /// and the active generation keeps serving.
    #[test]
    fn same_port_handoff_is_refused_and_active_retained() {
        let root = unique_root("same-port");
        let fake = Arc::new(FakeMlxEngine::default());
        let executor = MlxHostExecutor::new(root.join("active.json"), fake.clone());
        let active = executor.apply(&mlx_descriptor()).unwrap();
        fake.last_start.lock().unwrap().take();

        assert_eq!(executor.apply(&mlx_descriptor()).unwrap(), active);
        assert!(
            fake.last_start.lock().unwrap().is_none(),
            "re-applying the active generation starts nothing"
        );

        let mut next = mlx_descriptor();
        next.product_version = "3.2.2".into();
        let err = format!("{:#}", executor.apply(&next).unwrap_err());
        assert!(err.contains("same-port handoff"), "{err}");
        assert!(fake.last_start.lock().unwrap().is_none());
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(active.as_str())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn start_request(port: u16) -> EngineStartRequest {
        EngineStartRequest {
            product_name: "qwen-coder".into(),
            product_version: "1.0.0".into(),
            weights_path: Some(PathBuf::from("weights.bin")),
            port,
            bind_host: "127.0.0.1".into(),
            engine: MLX_ENGINE.into(),
            health_endpoint: format!("http://127.0.0.1:{port}/v1/models"),
            generation_id: format!("gen-{}", uuid::Uuid::new_v4()),
        }
    }

    #[test]
    fn launcher_refuses_an_occupied_port_before_spawning() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let launcher = MlxLmServerLauncher::new(PathBuf::from("/nonexistent/mlx-server"));
        let err = format!(
            "{:#}",
            launcher.start_candidate(&start_request(port)).unwrap_err()
        );
        assert!(err.contains("is in use"), "{err}");
    }

    /// A candidate that exits (for example on a failed bind) never passes
    /// the smoke, so apply cannot record it as serving.
    #[test]
    fn launcher_smoke_fails_when_its_candidate_exited() {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let launcher = MlxLmServerLauncher::new(PathBuf::from("false"));
        let request = start_request(port);
        let handle = launcher.start_candidate(&request).unwrap();
        let err = launcher
            .smoke(
                &handle,
                &ModelHealthSection {
                    endpoint: request.health_endpoint.clone(),
                    smoke_prompt: String::new(),
                    max_startup_seconds: 30,
                },
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("exited"), "{err}");
        launcher.stop(&handle).unwrap();
    }

    /// A recorded PID is signalled only while it still has the recorded
    /// start time; a reused or legacy PID-only handle is never signalled.
    #[test]
    fn stop_signals_a_recorded_pid_only_when_its_start_time_matches() {
        let mut process = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = process.id();
        let launcher = MlxLmServerLauncher::new(PathBuf::from("unused"));
        let handle = |marker: String| EngineHandle {
            generation_id: "recorded".into(),
            port: 8080,
            bind_host: "127.0.0.1".into(),
            marker,
        };
        for (marker, refusal) in [
            (
                format!("pid:{pid}@Thu Jan  1 00:00:00 1970"),
                "not signalled",
            ),
            (format!("pid:{pid}"), "no start time"),
        ] {
            let err = format!("{:#}", launcher.stop(&handle(marker)).unwrap_err());
            assert!(err.contains(refusal), "{err}");
            assert!(process.try_wait().unwrap().is_none(), "{refusal}");
        }
        let started = process_start_time(pid).unwrap().unwrap();
        launcher
            .stop(&handle(format!("pid:{pid}@{started}")))
            .unwrap();
        assert!(
            process.wait().unwrap().code().is_none(),
            "terminated by signal"
        );
    }

    #[test]
    fn apply_verifies_weights_then_starts_with_cached_path() {
        let root = unique_root("weights");
        std::fs::create_dir_all(&root).unwrap();
        let payload = b"mlx-fixture-weights";
        let weights = root.join("weights.bin");
        std::fs::write(&weights, payload).unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(payload));
        let fake = Arc::new(FakeMlxEngine::default());
        let executor = MlxHostExecutor::new(root.join("active.json"), fake.clone())
            .with_weight_cache(WeightCache::new(root.join("cache")));
        let mut descriptor = mlx_descriptor();
        descriptor.model.source = format!("file://{}", weights.display());
        descriptor.model.artifact_digest = digest;
        executor.apply(&descriptor).unwrap();
        let started = fake
            .last_start
            .lock()
            .expect("fake mlx start lock")
            .clone()
            .expect("start recorded");
        let path = started.weights_path.expect("verified weights path");
        assert_eq!(std::fs::read(path).unwrap(), payload);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_cuda_rocm_gpu_runtime_facts() {
        let root = unique_root("gpu");
        let executor = MlxHostExecutor::with_fake(root.join("active.json"));
        let mut descriptor = mlx_descriptor();
        descriptor.requirements.gpu = Some(GpuRequirements {
            vendor: vec!["nvidia".into()],
            families: vec![],
            vram_gib: 24,
            count: 1,
            tensor_parallel: 1,
            driver_min: None,
            runtime: Some("cuda".into()),
            runtime_min: None,
        });
        let err = executor.apply(&descriptor).unwrap_err().to_string();
        assert!(err.contains("apple-metal"), "{err}");
        assert!(err.contains("requirements.gpu"), "{err}");
        assert!(err.contains("cuda"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn operator_cache_applies_isolated_weight_origin_policy() {
        let root = unique_root("isolated");
        let artifacts = crate::model_runtime::ModelRuntimeArtifacts {
            registry: None,
            mirrors: Default::default(),
            isolated: true,
            workdir: None,
        };
        let cache = operator_weight_cache(&root.join("active.json"), Some(artifacts));
        let err = cache
            .fetch_and_verify(&mlx_descriptor().model)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no artifact mirror"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn real_launcher_requires_verified_weights_path() {
        let launcher = MlxLmServerLauncher::new(PathBuf::from(DEFAULT_BINARY));
        let err = launcher
            .start_candidate(&EngineStartRequest {
                product_name: "qwen-coder".into(),
                product_version: "1.0.0".into(),
                weights_path: None,
                port: 8080,
                bind_host: "127.0.0.1".into(),
                engine: MLX_ENGINE.into(),
                health_endpoint: "http://127.0.0.1:8080/v1/models".into(),
                generation_id: "gen".into(),
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("verified weights path"), "{err}");
    }

    #[test]
    fn loopback_origin_rejects_userinfo_and_prefix_lookalikes() {
        for endpoint in [
            "http://127.0.0.1@example.com:8080/v1/models",
            "http://127.0.0.1.attacker.example/v1/models",
            "http://127.0.0.1.example.com:8080/v1/models",
        ] {
            let err = loopback_http_origin(endpoint).unwrap_err().to_string();
            assert!(
                err.contains("loopback") || err.contains("userinfo"),
                "{endpoint}: {err}"
            );
        }
        assert_eq!(
            loopback_http_origin("http://127.0.0.1:8080/v1/models").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            loopback_http_origin("http://[::1]:8080/v1/models").unwrap(),
            "http://[::1]:8080"
        );
    }

    #[test]
    fn refuses_non_loopback_health() {
        let root = unique_root("bind");
        let executor = MlxHostExecutor::with_fake(root.join("active.json"));
        let mut descriptor = mlx_descriptor();
        descriptor.health.endpoint = "http://0.0.0.0:8080/v1/models".into();
        assert!(executor.apply(&descriptor).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn for_operator_host_uses_fake_when_real_mlx_env_unset() {
        if std::env::var_os(SERVER_ENV).is_some() || std::env::var_os(USE_REAL_ENV).is_some() {
            return;
        }
        let root = unique_root("host");
        let executor = MlxHostExecutor::for_operator_host(root.join("active.json"), None);
        assert!(executor.apply(&mlx_descriptor()).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Optional real-binary check. Not run in default CI; needs no Apple GPU
    /// unless the operator actually points `{SERVER_ENV}` at a live server.
    ///
    /// ```text
    /// TENKAI_MLX_SERVER=/path/to/mlx_lm.server \
    ///   cargo test --locked mlx_operator_golden_path -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires real mlx_lm.server; set TENKAI_MLX_SERVER and run with --ignored"]
    fn mlx_operator_golden_path() {
        let binary =
            std::env::var(SERVER_ENV).expect("TENKAI_MLX_SERVER must be set for this ignored test");
        let path = PathBuf::from(&binary);
        assert!(
            path.is_file() || path.components().count() == 1,
            "TENKAI_MLX_SERVER must name an existing file or a PATH command: {binary}"
        );
        let root = unique_root("gold");
        let weights = root.join("weights.bin");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&weights, b"fixture-weights").unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(b"fixture-weights"));
        let mut descriptor = mlx_descriptor();
        descriptor.model.source = format!("file://{}", weights.display());
        descriptor.model.artifact_digest = digest;
        descriptor.health.endpoint = "http://127.0.0.1:18081/v1/models".into();
        descriptor.runtime.port = 18081;
        let executor = MlxHostExecutor::new(
            root.join("active.json"),
            Arc::new(MlxLmServerLauncher::new(path)),
        )
        .with_weight_cache(WeightCache::new(root.join("cache")));
        let result = executor.apply(&descriptor);
        let _ = executor.remove();
        let _ = std::fs::remove_dir_all(root);
        match result {
            Ok(_) => {}
            Err(error) => {
                let msg = error.to_string();
                assert!(
                    msg.contains("mlx")
                        || msg.contains("smoke")
                        || msg.contains("starting")
                        || msg.contains("health")
                        || msg.contains("completion"),
                    "unexpected error: {msg}"
                );
            }
        }
    }
}
