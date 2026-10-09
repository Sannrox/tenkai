//! Docker host executor for multi-container `product.kind = software` releases.
//!
//! Selected with `TENKAI_SOFTWARE_EXECUTOR=docker`. Topology lives at
//! `{workdir}/docker/host.json`. Images must be digest-pinned. Secret values
//! stay in operator-managed env files; Tenkai stores only the directory path.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use super::{
    SoftwareApplyRequest, SoftwareDeployPhase, SoftwareExecutor, SoftwareObserveStatus,
    diagnostics, validate_request,
};

/// Directory under the release workdir that holds the Docker host topology.
pub const DOCKER_TOPOLOGY_DIR: &str = "docker";
/// Topology filename inside [`DOCKER_TOPOLOGY_DIR`].
pub const DOCKER_TOPOLOGY_FILE: &str = "host.json";
/// Environment property that stores the secret-file directory path.
pub const DOCKER_SECRET_DIR_PROPERTY: &str = "docker_secret_dir";

const IMAGE_DIGEST_PREFIX: &str = "sha256:";
const IMAGE_DIGEST_HEX_LEN: usize = 64;

/// Environment-scoped directory of secret env files. Credential bytes are refused.
pub fn validate_secret_dir_path(path: &Path) -> Result<()> {
    let raw = path.to_string_lossy();
    if raw.is_empty() || raw.contains('\0') || raw.contains('\n') {
        bail!("docker_secret_dir must be a single filesystem path");
    }
    let lower = raw.to_ascii_lowercase();
    for needle in ["-----begin ", "bearer ", "token=", "password=", "secret="] {
        if lower.contains(needle) {
            bail!("docker_secret_dir must be a directory path, not credential material");
        }
    }
    Ok(())
}

/// Read and admit `docker_secret_dir` from Environment properties.
pub fn secret_dir_from_properties(properties: &HashMap<String, String>) -> Result<Option<PathBuf>> {
    match properties.get(DOCKER_SECRET_DIR_PROPERTY) {
        None => Ok(None),
        Some(value) => {
            let path = PathBuf::from(value);
            validate_secret_dir_path(&path)?;
            Ok(Some(path))
        }
    }
}

/// Digest-pinned Docker host topology declared by a software release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerHostTopology {
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    pub containers: Vec<DockerHostContainer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerHostContainer {
    pub name: String,
    pub image: String,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<DockerVolumeMount>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<DockerHealthCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerVolumeMount {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerHealthCheck {
    pub cmd: String,
}

/// Docker CLI adapter (`docker network/volume/run/inspect/rm/restart`).
///
/// Binary from `TENKAI_DOCKER_BIN` or `docker` on PATH. Default CI uses a fake
/// CLI; live Docker remains an ignored operator smoke.
#[derive(Debug, Clone)]
pub struct DockerHostExecutor {
    pub docker_binary: PathBuf,
    health_attempts: u32,
    health_delay: Duration,
    extra_env: BTreeMap<String, String>,
}

impl Default for DockerHostExecutor {
    fn default() -> Self {
        let docker_binary = std::env::var_os("TENKAI_DOCKER_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("docker"));
        Self {
            docker_binary,
            health_attempts: 30,
            health_delay: Duration::from_secs(1),
            extra_env: BTreeMap::new(),
        }
    }
}

impl DockerHostExecutor {
    /// Test adapter with a fake CLI and immediate health inspect.
    pub fn for_binary(docker_binary: PathBuf) -> Self {
        Self {
            docker_binary,
            health_attempts: 3,
            health_delay: Duration::from_millis(0),
            extra_env: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    fn with_fake_env(mut self, state: &Path, forbid: &str, unhealthy: &[&str]) -> Self {
        self.extra_env.insert(
            "TENKAI_DOCKER_FAKE_STATE".into(),
            state.to_string_lossy().into_owned(),
        );
        self.extra_env
            .insert("TENKAI_DOCKER_FAKE_FORBID".into(), forbid.into());
        self.extra_env
            .insert("TENKAI_DOCKER_FAKE_UNHEALTHY".into(), unhealthy.join(","));
        self
    }

    fn docker_command(&self) -> Command {
        let mut command = Command::new(&self.docker_binary);
        for (key, value) in &self.extra_env {
            command.env(key, value);
        }
        command
    }

    fn topology(&self, request: &SoftwareApplyRequest) -> Result<DockerHostTopology> {
        load_topology(&request.workdir)
    }
}

impl SoftwareExecutor for DockerHostExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let topology = self.topology(request)?;
        validate_topology(&topology, request.secret_dir_path.as_deref())?;
        ensure_networks(self, request, &topology)?;
        ensure_volumes(self, request, &topology)?;
        let ordered = order_containers(&topology)?;
        let desired: BTreeSet<String> = ordered
            .iter()
            .map(|container| container_runtime_name(request, &container.name))
            .collect();
        for container in &ordered {
            replace_container(self, request, &topology, container)?;
            wait_healthy(self, request, container)?;
        }
        remove_unowned_containers(self, request, &desired)?;
        Ok(())
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let topology = self.topology(request)?;
        validate_topology(&topology, request.secret_dir_path.as_deref())?;
        for container in order_containers(&topology)?.iter().rev() {
            let name = container_runtime_name(request, &container.name);
            docker_ok(
                self,
                request,
                SoftwareDeployPhase::Remove,
                "rm",
                &["rm", "-f", &name],
            )?;
        }
        for network in &topology.networks {
            let name = network_runtime_name(request, network);
            let _ = docker_ok(
                self,
                request,
                SoftwareDeployPhase::Remove,
                "network rm",
                &["network", "rm", &name],
            );
        }
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let topology = self.topology(request)?;
        validate_topology(&topology, request.secret_dir_path.as_deref())?;
        let mut present = 0;
        for container in &topology.containers {
            let name = container_runtime_name(request, &container.name);
            match inspect_container(self, &name) {
                Ok(None) => return Ok(SoftwareObserveStatus::Absent),
                Ok(Some(inspected)) => {
                    if container_mismatch(request, container, &inspected) {
                        return Ok(SoftwareObserveStatus::Mismatched);
                    }
                    present += 1;
                }
                Err(_) => return Ok(SoftwareObserveStatus::Unknown),
            }
        }
        if present == 0 {
            Ok(SoftwareObserveStatus::Unknown)
        } else {
            Ok(SoftwareObserveStatus::Present)
        }
    }

    fn restart(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let topology = self.topology(request)?;
        validate_topology(&topology, request.secret_dir_path.as_deref())?;
        for container in order_containers(&topology)? {
            let name = container_runtime_name(request, &container.name);
            if inspect_container(self, &name)?.is_none() {
                replace_container(self, request, &topology, container)?;
            } else {
                docker_ok(
                    self,
                    request,
                    SoftwareDeployPhase::Restart,
                    "restart",
                    &["restart", &name],
                )?;
            }
            wait_healthy(self, request, container)?;
        }
        Ok(())
    }
}

/// Load `{workdir}/docker/host.json`.
pub fn load_topology(workdir: &Path) -> Result<DockerHostTopology> {
    let path = docker_topology_path(workdir)?;
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading docker topology {}", path.display()))?;
    let topology: DockerHostTopology = serde_json::from_str(&raw)
        .with_context(|| format!("parsing docker topology {}", path.display()))?;
    Ok(topology)
}

fn docker_topology_path(workdir: &Path) -> Result<PathBuf> {
    let dir = workdir.join(DOCKER_TOPOLOGY_DIR);
    if !dir.is_dir() {
        bail!(
            "docker host workdir must contain a {DOCKER_TOPOLOGY_DIR}/ directory at {}",
            dir.display()
        );
    }
    let workdir_canon = workdir
        .canonicalize()
        .with_context(|| format!("canonicalizing workdir {}", workdir.display()))?;
    let dir_canon = dir
        .canonicalize()
        .with_context(|| format!("canonicalizing docker topology dir {}", dir.display()))?;
    if !dir_canon.starts_with(&workdir_canon) {
        bail!("docker topology directory escapes workdir");
    }
    let path = dir.join(DOCKER_TOPOLOGY_FILE);
    if !path.is_file() {
        bail!("docker host topology {} is missing", path.display());
    }
    Ok(path)
}

/// Validate digest pins, names, mounts, dependency order, and env-file names.
pub fn validate_topology(topology: &DockerHostTopology, secret_dir: Option<&Path>) -> Result<()> {
    if topology.containers.is_empty() {
        bail!("docker host topology must declare at least one container");
    }
    let networks: BTreeSet<&str> = topology.networks.iter().map(String::as_str).collect();
    let volumes: BTreeSet<&str> = topology.volumes.iter().map(String::as_str).collect();
    if networks.len() != topology.networks.len() {
        bail!("docker host topology networks must be unique");
    }
    if volumes.len() != topology.volumes.len() {
        bail!("docker host topology volumes must be unique");
    }
    for name in networks.iter().chain(volumes.iter()) {
        validate_resource_name("resource", name)?;
    }
    let mut seen = BTreeSet::new();
    for container in &topology.containers {
        validate_resource_name("container", &container.name)?;
        if !seen.insert(container.name.as_str()) {
            bail!(
                "docker host topology container {} is duplicated",
                container.name
            );
        }
        validate_image_digest(&container.image)?;
        for network in &container.networks {
            if !networks.contains(network.as_str()) {
                bail!(
                    "container {} references undeclared network {network}",
                    container.name
                );
            }
        }
        for mount in &container.volumes {
            if !volumes.contains(mount.name.as_str()) {
                bail!(
                    "container {} references undeclared volume {}",
                    container.name,
                    mount.name
                );
            }
            validate_mount_target_path(&container.name, &mount.name, &mount.path)?;
        }
        if let Some(env_file) = &container.env_file {
            validate_env_file_name(env_file)?;
            let Some(secret_dir) = secret_dir else {
                bail!(
                    "container {} declares env_file {env_file} but docker_secret_dir is unset",
                    container.name
                );
            };
            resolve_env_file(secret_dir, env_file)?;
        }
        if let Some(health) = &container.health {
            if health.cmd.trim().is_empty() {
                bail!("container {} health.cmd must not be empty", container.name);
            }
            let lower = health.cmd.to_ascii_lowercase();
            for needle in ["bearer ", "token=", "password=", "secret="] {
                if lower.contains(needle) {
                    bail!(
                        "container {} health.cmd must not carry credential material",
                        container.name
                    );
                }
            }
        }
    }
    order_containers(topology)?;
    Ok(())
}

/// Volume `--mount` target. Comma, `=`, quotes, and whitespace would inject
/// extra Docker mount fields (bind-mount override). `..` leaves the container.
fn validate_mount_target_path(container: &str, volume: &str, path: &str) -> Result<()> {
    let allowed = path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'));
    if !path.starts_with('/')
        || path.len() < 2
        || path.contains('\0')
        || path.contains("..")
        || !allowed
    {
        bail!(
            "container {container} volume {volume} path must be an absolute in-container unix path without mount-option characters"
        );
    }
    Ok(())
}

fn validate_resource_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 63
        || !name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("{kind} name {name:?} must match [a-z][a-z0-9-]{{0,62}}");
    }
    Ok(())
}

fn validate_image_digest(image: &str) -> Result<()> {
    let Some(hex) = image.strip_prefix(IMAGE_DIGEST_PREFIX) else {
        bail!("docker image {image} must be digest-pinned as sha256:<64 hex>");
    };
    if hex.len() != IMAGE_DIGEST_HEX_LEN || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("docker image {image} must be digest-pinned as sha256:<64 hex>");
    }
    Ok(())
}

fn validate_env_file_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.contains("..")
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        bail!("env_file {name:?} must be a basename, not a path");
    }
    Ok(())
}

fn resolve_env_file(secret_dir: &Path, name: &str) -> Result<PathBuf> {
    validate_secret_dir_path(secret_dir)?;
    let joined = secret_dir.join(name);
    let dir_canon = secret_dir.canonicalize().with_context(|| {
        format!(
            "docker_secret_dir {} is not a readable directory",
            secret_dir.display()
        )
    })?;
    if !dir_canon.is_dir() {
        bail!(
            "docker_secret_dir {} is not a directory",
            dir_canon.display()
        );
    }
    let file_canon = joined
        .canonicalize()
        .with_context(|| format!("env_file {} is not a readable file", joined.display()))?;
    if !file_canon.is_file() {
        bail!("env_file {} is not a file", file_canon.display());
    }
    if !file_canon.starts_with(&dir_canon) {
        bail!(
            "env_file {} escapes docker_secret_dir",
            file_canon.display()
        );
    }
    Ok(file_canon)
}

fn order_containers(topology: &DockerHostTopology) -> Result<Vec<&DockerHostContainer>> {
    let index: BTreeMap<&str, &DockerHostContainer> = topology
        .containers
        .iter()
        .map(|container| (container.name.as_str(), container))
        .collect();
    let mut remaining: BTreeSet<&str> = index.keys().copied().collect();
    let mut ordered = Vec::new();
    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .copied()
            .filter(|name| {
                index[name]
                    .depends_on
                    .iter()
                    .all(|dep| !remaining.contains(dep.as_str()))
            })
            .collect::<Vec<_>>();
        if ready.is_empty() {
            bail!("docker host topology depends_on has a cycle");
        }
        for name in ready {
            remaining.remove(name);
            let container = index[name];
            for dep in &container.depends_on {
                if !index.contains_key(dep.as_str()) {
                    bail!(
                        "container {} depends_on undeclared container {dep}",
                        container.name
                    );
                }
            }
            ordered.push(container);
        }
    }
    Ok(ordered)
}

fn container_runtime_name(request: &SoftwareApplyRequest, name: &str) -> String {
    format!("{}-{}-ctr-{name}", request.environment, request.product)
}

fn network_runtime_name(request: &SoftwareApplyRequest, name: &str) -> String {
    format!("{}-{}-net-{name}", request.environment, request.product)
}

fn volume_runtime_name(request: &SoftwareApplyRequest, name: &str) -> String {
    format!("{}-{}-vol-{name}", request.environment, request.product)
}

fn ownership_labels(request: &SoftwareApplyRequest, container: &str) -> Vec<String> {
    vec![
        format!("tenkai.product={}", request.product),
        format!("tenkai.version={}", request.version),
        format!("tenkai.release-id={}", request.release_id),
        format!("tenkai.config-digest={}", request.config_digest),
        format!("tenkai.environment={}", request.environment),
        format!("tenkai.container={container}"),
    ]
}

fn ensure_networks(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    topology: &DockerHostTopology,
) -> Result<()> {
    for network in &topology.networks {
        let name = network_runtime_name(request, network);
        let mut args = vec!["network".to_string(), "create".into()];
        for label in ownership_labels(request, network) {
            args.push("--label".into());
            args.push(label);
        }
        args.push(name);
        docker_create_idempotent(executor, request, "network create", &args)?;
    }
    Ok(())
}

fn ensure_volumes(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    topology: &DockerHostTopology,
) -> Result<()> {
    for volume in &topology.volumes {
        let name = volume_runtime_name(request, volume);
        let mut args = vec!["volume".to_string(), "create".into()];
        for label in ownership_labels(request, volume) {
            args.push("--label".into());
            args.push(label);
        }
        args.push(name);
        docker_create_idempotent(executor, request, "volume create", &args)?;
    }
    Ok(())
}

fn replace_container(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    topology: &DockerHostTopology,
    container: &DockerHostContainer,
) -> Result<()> {
    let name = container_runtime_name(request, &container.name);
    docker_ok(
        executor,
        request,
        SoftwareDeployPhase::Apply,
        "rm",
        &["rm", "-f", &name],
    )?;
    let mut args = vec![
        "run".to_string(),
        "-d".into(),
        "--name".into(),
        name.clone(),
    ];
    for label in ownership_labels(request, &container.name) {
        args.push("--label".into());
        args.push(label);
    }
    for (key, value) in &request.overlays {
        args.push("--label".into());
        args.push(format!("tenkai.config.{key}={value}"));
    }
    match container.networks.as_slice() {
        [] => {}
        [first, rest @ ..] => {
            args.push("--network".into());
            args.push(network_runtime_name(request, first));
            let _ = rest;
        }
    }
    for mount in &container.volumes {
        args.push("--mount".into());
        args.push(format!(
            "type=volume,source={},target={}",
            volume_runtime_name(request, &mount.name),
            mount.path
        ));
    }
    if let Some(env_file) = &container.env_file {
        let secret_dir = request.secret_dir_path.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "container {} declares env_file {env_file} but docker_secret_dir is unset",
                container.name
            )
        })?;
        let path = resolve_env_file(secret_dir, env_file)?;
        args.push("--env-file".into());
        args.push(path.to_string_lossy().into_owned());
    }
    if let Some(health) = &container.health {
        args.push("--health-cmd".into());
        args.push(health.cmd.clone());
        args.push("--health-interval".into());
        args.push("1s".into());
        args.push("--health-retries".into());
        args.push("3".into());
        args.push("--health-timeout".into());
        args.push("1s".into());
    }
    args.push(container.image.clone());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    docker_ok(
        executor,
        request,
        SoftwareDeployPhase::Apply,
        "run",
        &arg_refs,
    )?;
    if let Some((_, rest)) = container.networks.split_first() {
        for network in rest {
            let network_name = network_runtime_name(request, network);
            docker_ok(
                executor,
                request,
                SoftwareDeployPhase::Apply,
                "network connect",
                &["network", "connect", &network_name, &name],
            )?;
        }
    }
    let _ = topology;
    Ok(())
}

fn wait_healthy(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    container: &DockerHostContainer,
) -> Result<()> {
    let name = container_runtime_name(request, &container.name);
    for attempt in 0..executor.health_attempts {
        let inspected = inspect_container(executor, &name)?.ok_or_else(|| {
            anyhow::anyhow!("docker container {name} disappeared during health wait")
        })?;
        match inspected.health.as_str() {
            "healthy" | "" if inspected.running => return Ok(()),
            "starting" if attempt + 1 < executor.health_attempts => {
                if !executor.health_delay.is_zero() {
                    std::thread::sleep(executor.health_delay);
                }
                continue;
            }
            status => {
                bail!(
                    "{}",
                    diagnostics::format_software_phase_error(
                        SoftwareDeployPhase::Health,
                        &request.product,
                        &request.version,
                        &request.environment,
                        &format!("container {} health is {status}", container.name),
                    )
                );
            }
        }
    }
    bail!(
        "{}",
        diagnostics::format_software_phase_error(
            SoftwareDeployPhase::Health,
            &request.product,
            &request.version,
            &request.environment,
            &format!("container {} health wait exhausted", container.name),
        )
    )
}

#[derive(Debug, Clone)]
struct InspectedContainer {
    image: String,
    labels: BTreeMap<String, String>,
    running: bool,
    health: String,
}

fn inspect_container(
    executor: &DockerHostExecutor,
    name: &str,
) -> Result<Option<InspectedContainer>> {
    let output = executor
        .docker_command()
        .args(["inspect", name])
        .output()
        .with_context(|| {
            format!(
                "starting docker inspect via {}",
                executor.docker_binary.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("no such object") || stderr.contains("no such container") {
            return Ok(None);
        }
        bail!(
            "docker inspect {name} failed: {}",
            diagnostics::sanitize_diagnostic_text(&String::from_utf8_lossy(&output.stderr))
        );
    }
    parse_inspect_json(&String::from_utf8_lossy(&output.stdout))
}

fn parse_inspect_json(raw: &str) -> Result<Option<InspectedContainer>> {
    let value: serde_json::Value = serde_json::from_str(raw).context("parsing docker inspect")?;
    let Some(entry) = value.as_array().and_then(|items| items.first()) else {
        return Ok(None);
    };
    let image = entry
        .pointer("/Config/Image")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let mut labels = BTreeMap::new();
    if let Some(map) = entry
        .pointer("/Config/Labels")
        .and_then(|value| value.as_object())
    {
        for (key, value) in map {
            if let Some(text) = value.as_str() {
                labels.insert(key.clone(), text.to_string());
            }
        }
    }
    let running = entry
        .pointer("/State/Running")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let health = entry
        .pointer("/State/Health/Status")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    Ok(Some(InspectedContainer {
        image,
        labels,
        running,
        health,
    }))
}

fn container_mismatch(
    request: &SoftwareApplyRequest,
    container: &DockerHostContainer,
    inspected: &InspectedContainer,
) -> bool {
    inspected.image != container.image
        || inspected.labels.get("tenkai.version").map(String::as_str)
            != Some(request.version.as_str())
        || inspected
            .labels
            .get("tenkai.release-id")
            .map(String::as_str)
            != Some(request.release_id.as_str())
        || inspected
            .labels
            .get("tenkai.config-digest")
            .map(String::as_str)
            .unwrap_or("")
            != request.config_digest
}

fn remove_unowned_containers(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    desired: &BTreeSet<String>,
) -> Result<()> {
    let filter = format!("label=tenkai.product={}", request.product);
    let env_filter = format!("label=tenkai.environment={}", request.environment);
    let output = docker_output(
        executor,
        &["ps", "-aq", "--filter", &filter, "--filter", &env_filter],
    )?;
    if !output.status.success() {
        return Ok(());
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let name = line.trim();
        if name.is_empty() || desired.contains(name) {
            continue;
        }
        docker_ok(
            executor,
            request,
            SoftwareDeployPhase::Apply,
            "rm extra",
            &["rm", "-f", name],
        )?;
    }
    Ok(())
}

fn docker_create_idempotent(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    hint: &str,
    args: &[String],
) -> Result<()> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = docker_output(executor, &refs)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if stderr.contains("already exists") {
        return Ok(());
    }
    let detail = diagnostics::sanitize_diagnostic_text(stderr.trim());
    bail!(
        "software deploy phase={} product={} environment/namespace={}: docker {hint} failed: {detail}",
        SoftwareDeployPhase::Apply.as_str(),
        request.product,
        request.environment
    )
}

fn docker_ok(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    phase: SoftwareDeployPhase,
    hint: &str,
    args: &[&str],
) -> Result<()> {
    let mut command = executor.docker_command();
    command.args(args);
    diagnostics::run_captured_command(
        &mut command,
        phase,
        hint,
        &request.product,
        &request.environment,
        "docker",
        "set TENKAI_DOCKER_BIN or install docker",
    )
}

fn docker_output(executor: &DockerHostExecutor, args: &[&str]) -> Result<Output> {
    executor
        .docker_command()
        .args(args)
        .output()
        .with_context(|| {
            format!(
                "starting docker via {} (set TENKAI_DOCKER_BIN or install docker)",
                executor.docker_binary.display()
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_context::test_management_context;
    use crate::catalog::{PublishOptions, publish};
    use crate::client::Ctx;
    use crate::plan;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Arc;

    const DIGEST_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const SECRET: &str = "super-secret-token-value";

    fn fake_docker(root: &Path) -> (PathBuf, PathBuf) {
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/docker/fake-docker.py");
        let script = root.join("fake-docker");
        std::fs::copy(&fixture, &script).unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        let state = root.join("fake-state.json");
        (script, state)
    }

    fn sample_topology() -> DockerHostTopology {
        DockerHostTopology {
            networks: vec!["appnet".into()],
            volumes: vec!["appdata".into()],
            containers: vec![
                DockerHostContainer {
                    name: "db".into(),
                    image: DIGEST_A.into(),
                    networks: vec!["appnet".into()],
                    volumes: vec![DockerVolumeMount {
                        name: "appdata".into(),
                        path: "/var/lib/data".into(),
                    }],
                    depends_on: Vec::new(),
                    env_file: None,
                    health: Some(DockerHealthCheck { cmd: "true".into() }),
                },
                DockerHostContainer {
                    name: "api".into(),
                    image: DIGEST_B.into(),
                    networks: vec!["appnet".into()],
                    volumes: Vec::new(),
                    depends_on: vec!["db".into()],
                    env_file: Some("api.env".into()),
                    health: Some(DockerHealthCheck { cmd: "true".into() }),
                },
            ],
        }
    }

    fn write_release(root: &Path, version: &str, api_image: &str) {
        let dir = root.join(version);
        std::fs::create_dir_all(dir.join("docker")).unwrap();
        let mut topology = sample_topology();
        topology.containers[1].image = api_image.into();
        std::fs::write(
            dir.join("docker/host.json"),
            serde_json::to_string_pretty(&topology).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"[product]
name = "edge-app"
version = "{version}"
kind = "software"

[deploy]
workdir = "."
install = "echo 'set TENKAI_SOFTWARE_EXECUTOR=docker' >&2; exit 1"
uninstall = "true"
inputs = ["docker"]
"#
            ),
        )
        .unwrap();
    }

    fn request_for(root: &Path, secret_dir: &Path, version: &str) -> SoftwareApplyRequest {
        let mut request = super::super::request_from_parts(
            "edge-app",
            version,
            "local",
            root.join(version),
            format!("tenkai:release:edge-app@{version}"),
        );
        request.secret_dir_path = Some(secret_dir.to_path_buf());
        request
    }

    fn executor_for(script: &Path, state: &Path, unhealthy: &[&str]) -> DockerHostExecutor {
        DockerHostExecutor::for_binary(script.to_path_buf()).with_fake_env(state, SECRET, unhealthy)
    }

    #[test]
    fn topology_requires_digest_pins_and_basename_env_files() {
        let mut topology = sample_topology();
        topology.containers[1].env_file = None;
        topology.containers[1].image = "nginx:latest".into();
        let err = validate_topology(&topology, None).unwrap_err().to_string();
        assert!(err.contains("digest-pinned"), "{err}");
        topology = sample_topology();
        topology.containers[1].env_file = Some("../etc/passwd".into());
        let err = validate_topology(&topology, None).unwrap_err().to_string();
        assert!(err.contains("basename"), "{err}");
    }

    #[test]
    fn topology_rejects_mount_option_injection_in_volume_path() {
        let mut topology = sample_topology();
        topology.containers[1].env_file = None;
        topology.containers[0].volumes[0].path = "/host,type=bind,source=/".into();
        let err = validate_topology(&topology, None).unwrap_err().to_string();
        assert!(err.contains("mount-option"), "{err}");
        topology.containers[0].volumes[0].path = "/var/lib/data=evil".into();
        let err = validate_topology(&topology, None).unwrap_err().to_string();
        assert!(err.contains("mount-option"), "{err}");
        topology.containers[0].volumes[0].path = "/var/lib/data".into();
        validate_topology(&topology, None).unwrap();
    }

    #[test]
    fn topology_rejects_depends_on_cycles() {
        let mut topology = sample_topology();
        topology.containers[0].depends_on = vec!["api".into()];
        topology.containers[1].env_file = None;
        let err = validate_topology(&topology, None).unwrap_err().to_string();
        assert!(err.contains("cycle"), "{err}");
    }

    #[test]
    fn secret_dir_path_cannot_carry_credential_bytes() {
        let err = validate_secret_dir_path(Path::new("password=s3cret"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("directory path"), "{err}");
    }

    #[test]
    fn apply_observe_restart_and_remove_two_container_fixture() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-docker-exec-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let secret_dir = root.join("secrets");
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("api.env"), format!("TOKEN={SECRET}\n")).unwrap();
        write_release(&root, "1.0.0", DIGEST_B);
        let (script, state) = fake_docker(&root);
        let executor = executor_for(&script, &state, &[]);
        let request = request_for(&root, &secret_dir, "1.0.0");
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Absent
        );
        executor.apply(&request).unwrap();
        let fake_state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        let db = fake_state["containers"]["local-edge-app-ctr-db"]
            .as_object()
            .expect("db container");
        let mounts = db["mounts"].as_array().expect("parsed mounts");
        assert_eq!(mounts.len(), 1, "{mounts:?}");
        assert_eq!(mounts[0]["type"], "volume");
        assert_eq!(mounts[0]["target"], "/var/lib/data");
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        executor.restart(&request).unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        let argv = std::fs::read_to_string(root.join("argv.log")).unwrap();
        assert!(argv.contains("--env-file"), "{argv}");
        assert!(argv.contains("api.env"), "{argv}");
        assert!(!argv.contains(SECRET), "{argv}");
        let serialized = serde_json::to_string(&request).unwrap();
        assert!(!serialized.contains(SECRET), "{serialized}");
        executor.remove(&request).unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Absent
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failing_container_health_is_a_typed_health_error() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-docker-unhealthy-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let secret_dir = root.join("secrets");
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("api.env"), format!("TOKEN={SECRET}\n")).unwrap();
        write_release(&root, "2.0.0", DIGEST_C);
        let (script, state) = fake_docker(&root);
        let executor = executor_for(&script, &state, &[DIGEST_C]);
        let request = request_for(&root, &secret_dir, "2.0.0");
        let err = executor.apply(&request).unwrap_err().to_string();
        assert!(err.contains("phase=health"), "{err}");
        assert!(!err.contains(SECRET), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn fixture_apply_observe_restart_and_failing_upgrade_rollback() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-docker-drill-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let secret_dir = root.join("secrets");
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("api.env"), format!("TOKEN={SECRET}\n")).unwrap();
        write_release(&root, "1.0.0", DIGEST_B);
        write_release(&root, "2.0.0", DIGEST_C);
        let (script, state) = fake_docker(&root);
        let executor = Arc::new(executor_for(&script, &state, &[DIGEST_C]));
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        publish(&mut ctx, &root.join("1.0.0").join("tenkai.toml"), &options)
            .await
            .unwrap();
        publish(&mut ctx, &root.join("2.0.0").join("tenkai.toml"), &options)
            .await
            .unwrap();
        let actor = test_management_context("docker-drill");
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "local", "fixture").await.unwrap();
        crate::environment::set_docker_secret_dir(&mut ctx, "local", &secret_dir)
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "local", "edge-app", "stable")
            .await
            .unwrap();

        let first = plan::create(&mut ctx, "local").await.unwrap();
        let installed = crate::apply::execute_with_options(
            &mut ctx,
            &first.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "docker host executor drill",
                },
                software_executor: Some(executor.clone()),
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        assert!(
            installed
                .iter()
                .all(|outcome| outcome.status == "succeeded"),
            "{installed:?}"
        );

        let observe = request_for(&root, &secret_dir, "1.0.0");
        assert_eq!(
            executor.observe(&observe).unwrap(),
            SoftwareObserveStatus::Present
        );
        executor.restart(&observe).unwrap();

        crate::catalog::promote(&mut ctx, &actor, "edge-app@2.0.0", "stable")
            .await
            .unwrap();
        let upgrade = plan::create(&mut ctx, "local").await.unwrap();
        let rolled = crate::apply::execute_with_options(
            &mut ctx,
            &upgrade.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "docker host executor drill",
                },
                software_executor: Some(executor.clone()),
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        assert!(
            rolled.iter().any(|outcome| outcome.status == "rolled_back"),
            "{rolled:?}"
        );
        assert_eq!(
            executor.observe(&observe).unwrap(),
            SoftwareObserveStatus::Present
        );

        let sqlite = std::fs::read(root.join("tenkai.db")).unwrap();
        let sqlite_text = String::from_utf8_lossy(&sqlite);
        assert!(!sqlite_text.contains(SECRET), "secret leaked into sqlite");
        let argv = std::fs::read_to_string(root.join("argv.log")).unwrap();
        assert!(argv.contains("--env-file"), "{argv}");
        assert!(!argv.contains(SECRET), "{argv}");
        for outcome in installed.iter().chain(rolled.iter()) {
            assert!(!outcome.detail.contains(SECRET), "{outcome:?}");
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
