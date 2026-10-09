//! Docker host executor for multi-container `product.kind = software` releases.
//!
//! Selected with `TENKAI_SOFTWARE_EXECUTOR=docker`. Topology lives at
//! `{workdir}/docker/host.json`. Images must be digest-pinned. Secret values
//! stay in operator-managed env files; Tenkai stores only the directory path.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

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
    pub depends_on: Vec<DockerDependency>,
    #[serde(default)]
    pub mode: DockerContainerMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<DockerHealthCheck>,
    /// Host port publications; loopback unless `host_ip` says otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<DockerPortPublication>,
    /// Replaces the image entrypoint. The first element is the executable;
    /// the rest are passed ahead of `command`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// Replaces the image command. Absent keeps the image default unless
    /// `entrypoint` is set, which clears it as `docker run --entrypoint` does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Stable DNS aliases per declared network, independent of runtime names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aliases: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<DockerConfigFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerConfigFile {
    pub source: String,
    pub destination: String,
    #[serde(default)]
    pub read_only: bool,
}

/// Legacy names keep their existing readiness ordering; conditional dependencies
/// express the process state a dependent must observe before it can start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum DockerDependency {
    Legacy(String),
    Conditional {
        container: String,
        condition: DockerDependencyCondition,
    },
}

impl DockerDependency {
    fn name(&self) -> &str {
        match self {
            Self::Legacy(name)
            | Self::Conditional {
                container: name, ..
            } => name,
        }
    }
    fn condition(&self) -> Option<DockerDependencyCondition> {
        match self {
            Self::Legacy(_) => None,
            Self::Conditional { condition, .. } => Some(*condition),
        }
    }
}

impl From<&str> for DockerDependency {
    fn from(name: &str) -> Self {
        Self::Legacy(name.into())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerContainerMode {
    #[default]
    Service,
    OneShot {
        timeout_secs: u64,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerDependencyCondition {
    #[default]
    Started,
    Healthy,
    CompletedSuccessfully,
}

/// One `docker run --publish`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerPortPublication {
    #[serde(default = "loopback")]
    pub host_ip: IpAddr,
    pub host_port: u16,
    pub container_port: u16,
    #[serde(default)]
    pub protocol: DockerPortProtocol,
}

fn loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DockerPortProtocol {
    #[default]
    Tcp,
    Udp,
}

impl DockerPortPublication {
    /// `--publish` value; IPv6 host addresses are bracketed.
    fn publish_arg(&self) -> String {
        let host = match self.host_ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        let protocol = match self.protocol {
            DockerPortProtocol::Tcp => "tcp",
            DockerPortProtocol::Udp => "udp",
        };
        format!(
            "{host}:{}:{}/{protocol}",
            self.host_port, self.container_port
        )
    }
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
        for container in &topology.containers {
            container_spec_digest(request, container)?;
        }
        ensure_networks(self, request, &topology)?;
        ensure_volumes(self, request, &topology)?;
        pull_missing_images(self, request, &topology)?;
        let ordered = order_containers(&topology)?;
        let desired: BTreeSet<String> = ordered
            .iter()
            .map(|container| managed_container_name(request, container))
            .collect::<Result<_>>()?;
        let mut journal = Vec::new();
        for container in &ordered {
            let replaced = check_dependencies(self, request, &topology, container)
                .and_then(|()| replace_container(self, request, &topology, container, &mut journal))
                .and_then(|()| wait_container(self, request, container));
            if let Err(error) = replaced {
                // Return the product to the containers it ran before this apply.
                return Err(match roll_back(self, request, &journal) {
                    Ok(()) => anyhow::anyhow!("{error:#}; restored the previous containers"),
                    Err(restore) => anyhow::anyhow!(
                        "{error:#}; restoring the previous containers also failed: {restore:#}"
                    ),
                });
            }
        }
        // Deletes the previous containers too. If this fails the caller still
        // re-applies the previous release, which replaces whatever runs here.
        remove_unowned_containers(self, request, &desired, true)?;
        Ok(())
    }

    /// `apply` restores the previous containers itself when it fails, so the
    /// caller only finishes a restore that `apply` could not complete: remove
    /// containers that have a kept previous one or still carry the failed
    /// release's label (a failed apply always targets a new release), then
    /// bring the kept ones back in dependency order.
    fn cleanup_failed_apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let topology = self.topology(request)?;
        let ordered = order_containers(&topology)?;
        let mut kept = Vec::new();
        for container in ordered.iter().rev() {
            let name = managed_container_name(request, container)?;
            let previous = previous_runtime_name(request, &container.name);
            if inspect_container(self, &previous)?.is_some() {
                remove_if_present(self, request, &name)?;
                kept.push((name, previous));
            } else if inspect_container(self, &name)?.is_some_and(|inspected| {
                inspected.labels.get("tenkai.release-id") == Some(&request.release_id)
                    && !successful_job(&inspected)
            }) {
                remove_if_present(self, request, &name)?;
            }
        }
        for (name, previous) in kept.iter().rev() {
            reinstate(self, request, name, previous)?;
        }
        // Drops networks only the failed release created; Docker keeps any
        // network a restored container still uses.
        remove_networks(self, request, &topology);
        Ok(())
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let topology = self.topology(request)?;
        validate_topology(&topology, request.secret_dir_path.as_deref())?;
        for container in order_containers(&topology)?.iter().rev() {
            let name = managed_container_name(request, container)?;
            remove_if_present(self, request, &name)?;
            remove_if_present(
                self,
                request,
                &previous_runtime_name(request, &container.name),
            )?;
        }
        remove_unowned_containers(self, request, &BTreeSet::new(), false)?;
        remove_networks(self, request, &topology);
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let topology = self.topology(request)?;
        validate_topology(&topology, request.secret_dir_path.as_deref())?;
        let mut present = 0;
        for container in &topology.containers {
            let name = managed_container_name(request, container)?;
            let Ok(spec_digest) = container_spec_digest(request, container) else {
                return Ok(SoftwareObserveStatus::Unknown);
            };
            match inspect_container(self, &name) {
                Ok(None) => return Ok(SoftwareObserveStatus::Absent),
                Ok(Some(inspected)) => {
                    if container_mismatch(request, container, &spec_digest, &inspected)
                        || matches!(container.mode, DockerContainerMode::OneShot { .. })
                            && !successful_job(&inspected)
                    {
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
        for container in &topology.containers {
            container_spec_digest(request, container)?;
        }
        let mut journal = Vec::new();
        for container in order_containers(&topology)? {
            let restarted = check_dependencies(self, request, &topology, container)
                .and_then(|()| restart_container(self, request, &topology, container, &mut journal))
                .and_then(|()| wait_container(self, request, container));
            if let Err(error) = restarted {
                return Err(match roll_back(self, request, &journal) {
                    Ok(()) => anyhow::anyhow!("{error:#}; restored the previous containers"),
                    Err(restore) => anyhow::anyhow!(
                        "{error:#}; restoring the previous containers also failed: {restore:#}"
                    ),
                });
            }
        }
        for change in &journal {
            if let Change::Replaced { previous, .. } = change {
                remove_if_present(self, request, previous)?;
            }
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
    let mut published = BTreeSet::new();
    let mut aliased = BTreeSet::new();
    for container in &topology.containers {
        validate_resource_name("container", &container.name)?;
        if !seen.insert(container.name.as_str()) {
            bail!(
                "docker host topology container {} is duplicated",
                container.name
            );
        }
        validate_image_reference(&container.image)?;
        if let DockerContainerMode::OneShot { timeout_secs } = container.mode {
            if !(1..=86_400).contains(&timeout_secs) {
                bail!(
                    "container {} one-shot timeout must be 1..86400 seconds",
                    container.name
                );
            }
            if container.health.is_some() {
                bail!(
                    "container {} one-shot completion cannot use a health check",
                    container.name
                );
            }
        }
        for port in &container.ports {
            if port.host_port == 0 || port.container_port == 0 {
                bail!(
                    "container {} ports must be between 1 and 65535",
                    container.name
                );
            }
            if !published.insert((port.host_ip, port.host_port, port.protocol)) {
                bail!(
                    "container {} publishes {} more than once in the topology",
                    container.name,
                    port.publish_arg()
                );
            }
        }
        if let Some(entrypoint) = &container.entrypoint {
            match entrypoint.first() {
                Some(executable) if !executable.is_empty() && !executable.starts_with('-') => {}
                _ => bail!(
                    "container {} entrypoint must start with an executable",
                    container.name
                ),
            }
        }
        for argument in container
            .entrypoint
            .iter()
            .chain(container.command.iter())
            .flatten()
        {
            validate_argument(&container.name, argument)?;
        }
        for (network, aliases) in &container.aliases {
            if !container.networks.contains(network) {
                bail!(
                    "container {} declares aliases on network {network} it does not join",
                    container.name
                );
            }
            for alias in aliases {
                validate_resource_name("network alias", alias)?;
                if !aliased.insert((network.as_str(), alias.as_str())) {
                    bail!("network {network} alias {alias} is declared more than once");
                }
            }
        }
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
        if container.files.len() > 64 {
            bail!("container {} exceeds 64 config files", container.name);
        }
        let mut destinations = BTreeSet::new();
        for file in &container.files {
            let source = Path::new(&file.source);
            if file.source.is_empty()
                || !source
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
            {
                bail!(
                    "container {} config source must be a relative release path without traversal",
                    container.name
                );
            }
            validate_mount_target_path(&container.name, "config file", &file.destination)?;
            let destination = Path::new(&file.destination);
            if destination.file_name().is_none()
                || destination.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
                || !destinations.insert(&file.destination)
                || container
                    .volumes
                    .iter()
                    .any(|mount| destination.starts_with(&mount.path))
                || container.files.iter().any(|other| {
                    other.destination != file.destination
                        && destination.starts_with(&other.destination)
                })
            {
                bail!(
                    "container {} has a colliding or invalid config destination",
                    container.name
                );
            }
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
            if carries_credential(&health.cmd) {
                bail!(
                    "container {} health.cmd must not carry credential material",
                    container.name
                );
            }
        }
    }
    for container in &topology.containers {
        let mut dependencies = BTreeSet::new();
        for dependency in &container.depends_on {
            let name = dependency.name();
            if !dependencies.insert(name) {
                bail!("container {} repeats dependency {name}", container.name);
            }
            let target = topology
                .containers
                .iter()
                .find(|target| target.name == name)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "container {} depends on undeclared container {name}",
                        container.name
                    )
                })?;
            let condition = dependency
                .condition()
                .unwrap_or(DockerDependencyCondition::Started);
            match condition {
                DockerDependencyCondition::Started | DockerDependencyCondition::Healthy
                    if !matches!(target.mode, DockerContainerMode::Service) =>
                {
                    bail!("dependency {name} is a one-shot job; require completed_successfully")
                }
                DockerDependencyCondition::Healthy if target.health.is_none() => {
                    bail!("dependency {name} has no health check")
                }
                DockerDependencyCondition::CompletedSuccessfully
                    if matches!(target.mode, DockerContainerMode::Service) =>
                {
                    bail!("dependency {name} is a service; completion requires a one-shot job")
                }
                _ => {}
            }
        }
    }
    order_containers(topology)?;
    Ok(())
}

fn carries_credential(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["bearer ", "token=", "password=", "secret="]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Entrypoint and command arguments reach the container, not the Docker CLI,
/// but they are stored in the release and shown by `docker inspect`.
fn validate_argument(container: &str, argument: &str) -> Result<()> {
    if argument.contains('\0') {
        bail!("container {container} arguments must not contain NUL");
    }
    if carries_credential(argument) {
        bail!("container {container} arguments must not carry credential material; use env_file");
    }
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

/// Admit `sha256:<64 hex>` (a local image ID, never pulled) or
/// `<repository>@sha256:<64 hex>` (a registry manifest digest, pulled when
/// missing). Tags are refused, alone or next to a digest.
fn validate_image_reference(image: &str) -> Result<()> {
    let refused = || {
        anyhow::anyhow!(
            "docker image {image} must be digest-pinned as sha256:<64 hex> or <repository>@sha256:<64 hex>, without a tag"
        )
    };
    let (repository, digest) = match image.split_once('@') {
        Some((repository, digest)) => (Some(repository), digest),
        None => (None, image),
    };
    let hex = digest
        .strip_prefix(IMAGE_DIGEST_PREFIX)
        .ok_or_else(refused)?;
    if hex.len() != IMAGE_DIGEST_HEX_LEN
        || !hex
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
    {
        return Err(refused());
    }
    if let Some(repository) = repository
        && !valid_repository(repository)
    {
        return Err(refused());
    }
    Ok(())
}

/// Docker reference grammar without a tag: an optional `host[:port]/` prefix
/// and lowercase path components separated by `.`, `_`, `__`, or `-`.
fn valid_repository(repository: &str) -> bool {
    let mut components: Vec<&str> = repository.split('/').collect();
    if components.len() > 1
        && let Some(host) = components.first().copied()
        && (host.contains('.') || host.contains(':') || host == "localhost")
    {
        let (name, port) = match host.split_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        };
        let host_ok = !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
        let port_ok = port.is_none_or(|port| {
            !port.is_empty() && port.len() <= 5 && port.chars().all(|c| c.is_ascii_digit())
        });
        if !host_ok || !port_ok {
            return false;
        }
        components.remove(0);
    }
    !components.is_empty() && components.into_iter().all(valid_path_component)
}

/// `[a-z0-9]+` runs joined by `.`, `_`, `__`, or one or more `-`.
fn valid_path_component(component: &str) -> bool {
    let mut separator = String::new();
    let mut started = false;
    for c in component.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            let joined = separator.is_empty()
                || matches!(separator.as_str(), "." | "_" | "__")
                || separator.chars().all(|c| c == '-');
            if !joined {
                return false;
            }
            separator.clear();
            started = true;
        } else if started && matches!(c, '.' | '_' | '-') {
            separator.push(c);
        } else {
            return false;
        }
    }
    started && separator.is_empty()
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
                    .all(|dep| !remaining.contains(dep.name()))
            })
            .collect::<Vec<_>>();
        if ready.is_empty() {
            bail!("docker host topology depends_on has a cycle");
        }
        for name in ready {
            remaining.remove(name);
            let container = index[name];
            for dep in &container.depends_on {
                if !index.contains_key(dep.name()) {
                    bail!(
                        "container {} depends_on undeclared container {}",
                        container.name,
                        dep.name()
                    );
                }
            }
            ordered.push(container);
        }
    }
    Ok(ordered)
}

fn container_runtime_name(request: &SoftwareApplyRequest, name: &str) -> String {
    format!("{}-ctr-{name}", scope_prefix(request))
}

/// A completion receipt belongs to one release and effective configuration.
fn managed_container_name(
    request: &SoftwareApplyRequest,
    container: &DockerHostContainer,
) -> Result<String> {
    if matches!(container.mode, DockerContainerMode::Service) {
        return Ok(container_runtime_name(request, &container.name));
    }
    let mut hash = Sha256::new();
    hash.update(request.release_id.as_bytes());
    hash.update([0]);
    hash.update(request.config_digest.as_bytes());
    hash.update([0]);
    hash.update(container_spec_digest(request, container)?.as_bytes());
    let generation = format!("{:x}", hash.finalize());
    Ok(format!(
        "{}-job-{}-{}",
        scope_prefix(request),
        container.name,
        &generation[..16]
    ))
}

fn successful_job(inspected: &InspectedContainer) -> bool {
    inspected
        .labels
        .get("tenkai.job")
        .is_some_and(|value| value == "true")
        && inspected.status == "exited"
        && inspected.exit_code == Some(0)
}

fn network_runtime_name(request: &SoftwareApplyRequest, name: &str) -> String {
    format!("{}-net-{name}", scope_prefix(request))
}

fn volume_runtime_name(request: &SoftwareApplyRequest, name: &str) -> String {
    format!("{}-vol-{name}", scope_prefix(request))
}

/// Content-addressed prefix so hyphenated environment or product values cannot collide.
fn scope_prefix(request: &SoftwareApplyRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.environment.as_bytes());
    hasher.update([0]);
    hasher.update(request.product.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    format!("t{}", &hex[..12])
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

fn pull_missing_images(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    topology: &DockerHostTopology,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for container in &topology.containers {
        if !seen.insert(container.image.as_str()) {
            continue;
        }
        if image_present(executor, &container.image)? {
            continue;
        }
        if !container.image.contains('@') {
            bail!(
                "software deploy phase={} product={} environment/namespace={}: local image ID {} is not present on the host; pin a <repository>@sha256 reference to pull it",
                SoftwareDeployPhase::Apply.as_str(),
                request.product,
                request.environment,
                container.image
            );
        }
        docker_ok(
            executor,
            request,
            SoftwareDeployPhase::Apply,
            "pull",
            &["pull", &container.image],
        )?;
    }
    Ok(())
}

fn image_present(executor: &DockerHostExecutor, image: &str) -> Result<bool> {
    let output = docker_output(executor, &["image", "inspect", image])?;
    Ok(output.status.success())
}

/// One container an `apply` created or replaced, in order, so a failed apply
/// can return to the containers that ran before it.
enum Change {
    /// Created by this attempt, or an interrupted job adopted for bounded cleanup.
    Created(String),
    /// The previous container was stopped and renamed to `previous`.
    Replaced { name: String, previous: String },
}

/// Name a replaced container keeps until the new one is healthy. Its `-prev-`
/// namespace cannot collide with a declared container's `-ctr-` name.
fn previous_runtime_name(request: &SoftwareApplyRequest, name: &str) -> String {
    format!("{}-prev-{name}", scope_prefix(request))
}

/// Bounce one container. `docker restart` keeps the environment a container
/// was created with, so a missing container or one whose spec changed (for
/// example a rotated `env_file`) is recreated instead.
fn restart_container(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    topology: &DockerHostTopology,
    container: &DockerHostContainer,
    journal: &mut Vec<Change>,
) -> Result<()> {
    if matches!(container.mode, DockerContainerMode::OneShot { .. }) {
        return replace_container(executor, request, topology, container, journal);
    }
    let name = managed_container_name(request, container)?;
    refuse_foreign_container(executor, request, &name)?;
    let spec_digest = container_spec_digest(request, container)?;
    match inspect_container(executor, &name)? {
        Some(inspected) if !container_mismatch(request, container, &spec_digest, &inspected) => {
            docker_ok(
                executor,
                request,
                SoftwareDeployPhase::Restart,
                "restart",
                &["restart", &name],
            )
        }
        _ => replace_container(executor, request, topology, container, journal),
    }
}

/// Resolve a container's declared `env_file` inside the environment's secret
/// directory.
fn env_file_path(
    request: &SoftwareApplyRequest,
    container: &DockerHostContainer,
) -> Result<Option<PathBuf>> {
    let Some(env_file) = &container.env_file else {
        return Ok(None);
    };
    let secret_dir = request.secret_dir_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "container {} declares env_file {env_file} but docker_secret_dir is unset",
            container.name
        )
    })?;
    resolve_env_file(secret_dir, env_file).map(Some)
}

/// Digest of what `docker run` bakes into a container but release and config
/// labels cannot see: the resolved `env_file` path and its contents. The bytes
/// are hashed in memory; only the digest becomes the `tenkai.spec-digest`
/// label, and `docker inspect` already exposes the values themselves.
fn container_spec_digest(
    request: &SoftwareApplyRequest,
    container: &DockerHostContainer,
) -> Result<String> {
    let files = container
        .files
        .iter()
        .map(|file| config_file_bytes(request, file))
        .collect::<Result<Vec<_>>>()?;
    spec_digest_with_files(request, container, &files)
}

fn spec_digest_with_files(
    request: &SoftwareApplyRequest,
    container: &DockerHostContainer,
    files: &[Vec<u8>],
) -> Result<String> {
    let mut hasher = Sha256::new();
    if let Some(path) = env_file_path(request, container)? {
        let contents =
            std::fs::read(&path).with_context(|| format!("reading env_file {}", path.display()))?;
        hasher.update(path.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(contents);
    }
    for (file, contents) in container.files.iter().zip(files) {
        hasher.update(serde_json::to_vec(file)?);
        hasher.update([0]);
        hasher.update(Sha256::digest(contents));
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn config_file_bytes(request: &SoftwareApplyRequest, file: &DockerConfigFile) -> Result<Vec<u8>> {
    let file = open_config_source(&request.workdir, &file.source)?;
    use std::io::Read as _;
    let mut contents = Vec::new();
    const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        bail!("config file exceeds 16 MiB limit");
    }
    Ok(contents)
}

/// Anchor each source component to an open directory, so renaming a source
/// or replacing a parent with a symlink cannot redirect reads outside the root.
#[cfg(unix)]
fn open_config_source(root: &Path, source: &str) -> Result<std::fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let mut components = Path::new(source).components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(component) = component else {
            bail!("config source must be a relative path without traversal");
        };
        let name = std::ffi::CString::new(component.as_encoded_bytes())?;
        let last = components.peek().is_none();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        // SAFETY: directory owns a live descriptor and name is NUL-terminated.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new descriptor, transferred to File once.
        let opened = unsafe { std::fs::File::from_raw_fd(fd) };
        if last {
            if !opened.metadata()?.is_file() {
                bail!("config source must be a regular file");
            }
            return Ok(opened);
        }
        directory = opened;
    }
    bail!("config source must not be empty")
}

#[cfg(not(unix))]
fn open_config_source(_root: &Path, _source: &str) -> Result<std::fs::File> {
    bail!("Docker release configuration files require descriptor-relative Unix file access")
}

/// Stream a root-owned regular file into a stopped container. Only archive
/// metadata and file bytes cross the Docker client boundary; receipts omit both.
fn populate_config_files(
    executor: &DockerHostExecutor,
    container: &DockerHostContainer,
    name: &str,
    files: &[Vec<u8>],
) -> Result<()> {
    use std::io::Write as _;
    use std::process::Stdio;
    for (file, contents) in container.files.iter().zip(files) {
        let destination = Path::new(&file.destination);
        let filename = destination
            .file_name()
            .context("config destination has no filename")?;
        let parent = destination
            .parent()
            .context("config destination has no parent")?;
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(if file.read_only { 0o444 } else { 0o644 });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append_data(&mut header, Path::new(filename), contents.as_slice())?;
        let bytes = archive.into_inner()?;
        let target = format!("{name}:{}", parent.display());
        let mut child = executor
            .docker_command()
            .args(["cp", "-", &target])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("starting Docker config copy")?;
        let write = child
            .stdin
            .take()
            .context("Docker config copy has no input")?
            .write_all(&bytes);
        let status = child.wait()?;
        write.context("streaming Docker config file")?;
        if !status.success() {
            bail!(
                "Docker config copy failed for container {} destination {}",
                container.name,
                file.destination
            );
        }
    }
    Ok(())
}

/// Create the container for `container` unless a matching, running, not
/// unhealthy one already exists. A container being replaced is stopped and
/// kept under [`previous_runtime_name`]; every change is pushed onto `journal` before
/// the new container starts.
fn replace_container(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    topology: &DockerHostTopology,
    container: &DockerHostContainer,
    journal: &mut Vec<Change>,
) -> Result<()> {
    let name = managed_container_name(request, container)?;
    refuse_foreign_container(executor, request, &name)?;
    let files = container
        .files
        .iter()
        .map(|file| config_file_bytes(request, file))
        .collect::<Result<Vec<_>>>()?;
    let spec_digest = spec_digest_with_files(request, container, &files)?;
    match inspect_container(executor, &name)? {
        Some(inspected)
            if !container_mismatch(request, container, &spec_digest, &inspected)
                && ((matches!(container.mode, DockerContainerMode::Service)
                    && inspected.running
                    && inspected.health != "unhealthy")
                    || (matches!(container.mode, DockerContainerMode::OneShot { .. })
                        && inspected.status == "exited"
                        && inspected.exit_code == Some(0))) =>
        {
            return Ok(());
        }
        Some(inspected)
            if matches!(container.mode, DockerContainerMode::OneShot { .. })
                && inspected.running
                && !container_mismatch(request, container, &spec_digest, &inspected) =>
        {
            // Adopt work left by an interrupted attempt so timeout and recovery
            // own its cleanup; successful completion remains reusable evidence.
            journal.push(Change::Created(name));
            return Ok(());
        }
        Some(inspected) => {
            let previous = previous_runtime_name(request, &container.name);
            // A leftover from an interrupted apply; the live container wins.
            remove_if_present(executor, request, &previous)?;
            // Rename before stopping: a failed rename leaves the old container
            // running, and once journaled a failed stop is still restorable.
            docker_ok(
                executor,
                request,
                SoftwareDeployPhase::Apply,
                "rename",
                &["rename", &name, &previous],
            )?;
            journal.push(Change::Replaced {
                name: name.clone(),
                previous: previous.clone(),
            });
            if inspected.running {
                docker_ok(
                    executor,
                    request,
                    SoftwareDeployPhase::Apply,
                    "stop",
                    &["stop", &previous],
                )?;
            }
        }
        None => journal.push(Change::Created(name.clone())),
    }
    let mut args = if container.files.is_empty() {
        vec!["run".to_string(), "-d".into()]
    } else {
        vec!["create".to_string()]
    };
    args.extend(["--name".into(), name.clone()]);
    for label in ownership_labels(request, &container.name) {
        args.push("--label".into());
        args.push(label);
    }
    args.push("--label".into());
    args.push(format!("tenkai.spec-digest={spec_digest}"));
    if matches!(container.mode, DockerContainerMode::OneShot { .. }) {
        args.push("--label".into());
        args.push("tenkai.job=true".into());
        args.push("--label".into());
        args.push(format!("tenkai.job-started-at-ms={}", crate::now_millis()));
    }
    for (key, value) in &request.overlays {
        args.push("--label".into());
        args.push(format!("tenkai.config.{key}={value}"));
    }
    // `--network-alias` applies only to the `--network` joined at run time;
    // later networks take their aliases on `network connect`.
    if let Some(first) = container.networks.first() {
        args.push("--network".into());
        args.push(network_runtime_name(request, first));
        for alias in container.aliases.get(first).into_iter().flatten() {
            args.push("--network-alias".into());
            args.push(alias.clone());
        }
    }
    for port in &container.ports {
        args.push("--publish".into());
        args.push(port.publish_arg());
    }
    for mount in &container.volumes {
        args.push("--mount".into());
        args.push(format!(
            "type=volume,source={},target={}",
            volume_runtime_name(request, &mount.name),
            mount.path
        ));
    }
    if let Some(path) = env_file_path(request, container)? {
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
    // Docker takes one entrypoint executable; its remaining elements lead the
    // container arguments, which is the same process argv.
    let (entrypoint, entrypoint_args) = match container.entrypoint.as_deref() {
        Some([executable, rest @ ..]) => (Some(executable), rest),
        _ => (None, &[][..]),
    };
    if let Some(executable) = entrypoint {
        args.push("--entrypoint".into());
        args.push(executable.clone());
    }
    args.push(container.image.clone());
    args.extend(entrypoint_args.iter().cloned());
    args.extend(container.command.iter().flatten().cloned());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    if !container.files.is_empty() {
        docker_ok(
            executor,
            request,
            SoftwareDeployPhase::Apply,
            "create",
            &arg_refs,
        )?;
        populate_config_files(executor, container, &name, &files)?;
        if container_spec_digest(request, container)? != spec_digest {
            bail!("release configuration changed during container creation");
        }
        let start = ["start", name.as_str()];
        if let DockerContainerMode::OneShot { timeout_secs } = container.mode {
            run_one_shot(executor, request, &start, timeout_secs)?;
        } else {
            docker_ok(
                executor,
                request,
                SoftwareDeployPhase::Apply,
                "start",
                &start,
            )?;
        }
    } else if let DockerContainerMode::OneShot { timeout_secs } = container.mode {
        run_one_shot(executor, request, &arg_refs, timeout_secs)?;
    } else {
        docker_ok(
            executor,
            request,
            SoftwareDeployPhase::Apply,
            "run",
            &arg_refs,
        )?;
    }
    if let Some((_, rest)) = container.networks.split_first() {
        for network in rest {
            let mut connect = vec!["network".to_string(), "connect".into()];
            for alias in container.aliases.get(network).into_iter().flatten() {
                connect.push("--alias".into());
                connect.push(alias.clone());
            }
            connect.push(network_runtime_name(request, network));
            connect.push(name.clone());
            let connect: Vec<&str> = connect.iter().map(String::as_str).collect();
            docker_ok(
                executor,
                request,
                SoftwareDeployPhase::Apply,
                "network connect",
                &connect,
            )?;
        }
    }
    let _ = topology;
    Ok(())
}

/// Undo `journal`: remove what the apply started in reverse dependency order,
/// then bring back each replaced container in dependency order.
fn roll_back(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    journal: &[Change],
) -> Result<()> {
    for change in journal.iter().rev() {
        let (Change::Created(name) | Change::Replaced { name, .. }) = change;
        if matches!(change, Change::Created(_))
            && inspect_container(executor, name)?
                .as_ref()
                .is_some_and(successful_job)
        {
            continue;
        }
        remove_if_present(executor, request, name)?;
    }
    for change in journal {
        if let Change::Replaced { name, previous } = change {
            reinstate(executor, request, name, previous)?;
        }
    }
    Ok(())
}

/// Rename the stopped `previous` container back to `name` and start it.
fn reinstate(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    name: &str,
    previous: &str,
) -> Result<()> {
    refuse_foreign_container(executor, request, previous)?;
    docker_ok(
        executor,
        request,
        SoftwareDeployPhase::Restore,
        "rename",
        &["rename", previous, name],
    )?;
    if inspect_container(executor, name)?
        .as_ref()
        .is_some_and(|inspected| {
            inspected
                .labels
                .get("tenkai.job")
                .is_some_and(|value| value == "true")
        })
    {
        return Ok(());
    }
    docker_ok(
        executor,
        request,
        SoftwareDeployPhase::Restore,
        "start",
        &["start", name],
    )
}

/// Best effort: Docker refuses to remove a network a container still uses.
fn remove_networks(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    topology: &DockerHostTopology,
) {
    for network in &topology.networks {
        let name = network_runtime_name(request, network);
        let _ = docker_ok(
            executor,
            request,
            SoftwareDeployPhase::Remove,
            "network rm",
            &["network", "rm", &name],
        );
    }
}

/// `docker rm -f` a container of this product and environment, if it exists;
/// a container owned by anyone else is refused.
fn remove_if_present(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    name: &str,
) -> Result<()> {
    let Some(inspected) = inspect_container(executor, name)? else {
        return Ok(());
    };
    if !labels_owned_by(request, &inspected.labels) {
        return Err(foreign_owner_error(request, name, &inspected.labels));
    }
    docker_ok(
        executor,
        request,
        SoftwareDeployPhase::Remove,
        "rm",
        &["rm", "-f", name],
    )
}

fn check_dependencies(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    topology: &DockerHostTopology,
    container: &DockerHostContainer,
) -> Result<()> {
    for dependency in &container.depends_on {
        let Some(condition) = dependency.condition() else {
            continue;
        };
        let dependency = dependency.name();
        let target = topology
            .containers
            .iter()
            .find(|target| target.name == dependency)
            .ok_or_else(|| anyhow::anyhow!("dependency {dependency} is not declared"))?;
        let name = managed_container_name(request, target)?;
        let observed = inspect_container(executor, &name)?
            .ok_or_else(|| anyhow::anyhow!("dependency {dependency} is absent"))?;
        let satisfied = match condition {
            DockerDependencyCondition::Started => observed.running,
            DockerDependencyCondition::Healthy => observed.running && observed.health == "healthy",
            DockerDependencyCondition::CompletedSuccessfully => {
                observed.status == "exited" && observed.exit_code == Some(0)
            }
        };
        if !satisfied {
            bail!(
                "dependency {dependency} for {} does not satisfy {condition:?}",
                container.name
            );
        }
    }
    Ok(())
}

/// Bound job startup without exporting its potentially secret-bearing logs.
fn run_one_shot(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    args: &[&str],
    timeout_secs: u64,
) -> Result<()> {
    use std::process::Stdio;
    let mut child = executor
        .docker_command()
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("starting one-shot docker job")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            bail!(
                "one-shot job for {} exited unsuccessfully (code {:?})",
                request.product,
                status.code()
            );
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "one-shot job for {} exceeded timeout of {timeout_secs} seconds",
                request.product
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_container(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    container: &DockerHostContainer,
) -> Result<()> {
    let name = managed_container_name(request, container)?;
    if let DockerContainerMode::OneShot { timeout_secs } = container.mode {
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            let observed = inspect_container(executor, &name)?
                .ok_or_else(|| anyhow::anyhow!("one-shot job {} disappeared", container.name))?;
            if observed.status == "exited" {
                if observed.exit_code == Some(0) {
                    return Ok(());
                }
                bail!(
                    "one-shot job {} exited unsuccessfully (code {:?})",
                    container.name,
                    observed.exit_code
                );
            }
            if std::time::Instant::now() >= deadline {
                remove_if_present(executor, request, &name)?;
                bail!(
                    "one-shot job {} exceeded timeout of {timeout_secs} seconds",
                    container.name
                );
            }
            if !observed.running {
                bail!(
                    "one-shot job {} has no running or completed process",
                    container.name
                );
            }
            std::thread::sleep(
                executor
                    .health_delay
                    .max(Duration::from_millis(10))
                    .min(deadline.saturating_duration_since(std::time::Instant::now())),
            );
        }
    }
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
    status: String,
    exit_code: Option<i64>,
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
        if stderr.contains("no such object")
            || stderr.contains("no such container")
            || stderr.contains("no such network")
            || stderr.contains("no such volume")
        {
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
    for pointer in ["/Labels", "/Config/Labels"] {
        if let Some(map) = entry.pointer(pointer).and_then(|value| value.as_object()) {
            for (key, value) in map {
                if let Some(text) = value.as_str() {
                    labels.insert(key.clone(), text.to_string());
                }
            }
        }
    }
    let running = entry
        .pointer("/State/Running")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let status = entry
        .pointer("/State/Status")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let exit_code = entry
        .pointer("/State/ExitCode")
        .and_then(|value| value.as_i64());
    let health = entry
        .pointer("/State/Health/Status")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    Ok(Some(InspectedContainer {
        image,
        labels,
        running,
        status,
        exit_code,
        health,
    }))
}

fn container_mismatch(
    request: &SoftwareApplyRequest,
    container: &DockerHostContainer,
    spec_digest: &str,
    inspected: &InspectedContainer,
) -> bool {
    inspected.image != container.image
        || inspected
            .labels
            .get("tenkai.spec-digest")
            .map(String::as_str)
            != Some(spec_digest)
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
    retain_completed_jobs: bool,
) -> Result<()> {
    let filter = format!("label=tenkai.product={}", request.product);
    let env_filter = format!("label=tenkai.environment={}", request.environment);
    let output = docker_output(
        executor,
        &[
            "ps",
            "-a",
            "--format",
            "{{.Names}}",
            "--filter",
            &filter,
            "--filter",
            &env_filter,
        ],
    )?;
    if !output.status.success() {
        return Ok(());
    }
    let mut observed = Vec::new();
    let mut active_jobs = BTreeSet::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        let inspected = inspect_container(executor, name)?;
        if retain_completed_jobs
            && desired.contains(name)
            && let Some(job) = inspected.as_ref().filter(|job| successful_job(job))
            && let Some(component) = job.labels.get("tenkai.container")
        {
            active_jobs.insert(component.clone());
        }
        observed.push((name.to_string(), inspected));
    }
    // Keep the active generation and one recent predecessor per declared job.
    let mut previous = BTreeMap::<String, (i64, String)>::new();
    if retain_completed_jobs {
        for (name, inspected) in &observed {
            if desired.contains(name) {
                continue;
            }
            let Some(job) = inspected.as_ref().filter(|job| successful_job(job)) else {
                continue;
            };
            let Some(component) = job
                .labels
                .get("tenkai.container")
                .filter(|component| active_jobs.contains(*component))
            else {
                continue;
            };
            let started_at = job
                .labels
                .get("tenkai.job-started-at-ms")
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0);
            let candidate = (started_at, name.clone());
            if previous
                .get(component)
                .is_none_or(|prior| &candidate > prior)
            {
                previous.insert(component.clone(), candidate);
            }
        }
    }
    let retained: BTreeSet<_> = previous.into_values().map(|(_, name)| name).collect();
    for (name, _) in observed {
        if desired.contains(&name) || retained.contains(&name) {
            continue;
        }
        docker_ok(
            executor,
            request,
            SoftwareDeployPhase::Apply,
            "rm extra",
            &["rm", "-f", &name],
        )?;
    }
    Ok(())
}

fn labels_owned_by(request: &SoftwareApplyRequest, labels: &BTreeMap<String, String>) -> bool {
    labels.get("tenkai.product").map(String::as_str) == Some(request.product.as_str())
        && labels.get("tenkai.environment").map(String::as_str)
            == Some(request.environment.as_str())
}

fn foreign_owner_error(
    request: &SoftwareApplyRequest,
    name: &str,
    labels: &BTreeMap<String, String>,
) -> anyhow::Error {
    anyhow::anyhow!(
        "software deploy phase={} product={} environment/namespace={}: docker name {name} is owned by product={} environment={}",
        SoftwareDeployPhase::Apply.as_str(),
        request.product,
        request.environment,
        labels
            .get("tenkai.product")
            .map(String::as_str)
            .unwrap_or("unknown"),
        labels
            .get("tenkai.environment")
            .map(String::as_str)
            .unwrap_or("unknown"),
    )
}

fn refuse_foreign_container(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    name: &str,
) -> Result<()> {
    let Some(inspected) = inspect_container(executor, name)? else {
        return Ok(());
    };
    if labels_owned_by(request, &inspected.labels) {
        return Ok(());
    }
    Err(foreign_owner_error(request, name, &inspected.labels))
}

fn require_existing_owned(
    executor: &DockerHostExecutor,
    request: &SoftwareApplyRequest,
    name: &str,
) -> Result<()> {
    let Some(inspected) = inspect_container(executor, name)? else {
        bail!(
            "software deploy phase={} product={} environment/namespace={}: docker name {name} already exists but inspect found nothing",
            SoftwareDeployPhase::Apply.as_str(),
            request.product,
            request.environment
        );
    };
    if labels_owned_by(request, &inspected.labels) {
        return Ok(());
    }
    Err(foreign_owner_error(request, name, &inspected.labels))
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
        let name = args.last().map(String::as_str).unwrap_or("");
        return require_existing_owned(executor, request, name);
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

    const DIGEST_A: &str = "registry.example:5000/edge/db@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "registry.example:5000/edge/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str = "registry.example:5000/edge/api@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
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
            networks: vec!["appnet".into(), "backnet".into()],
            volumes: vec!["appdata".into()],
            containers: vec![
                DockerHostContainer {
                    name: "db".into(),
                    image: DIGEST_A.into(),
                    networks: vec!["appnet".into(), "backnet".into()],
                    volumes: vec![DockerVolumeMount {
                        name: "appdata".into(),
                        path: "/var/lib/data".into(),
                    }],
                    depends_on: Vec::new(),
                    mode: DockerContainerMode::Service,
                    env_file: None,
                    health: Some(DockerHealthCheck { cmd: "true".into() }),
                    ports: Vec::new(),
                    entrypoint: Some(vec!["docker-entrypoint.sh".into(), "--verbose".into()]),
                    command: Some(vec!["postgres".into(), "-c".into(), "fsync=on".into()]),
                    aliases: BTreeMap::from([
                        ("appnet".into(), vec!["database".into()]),
                        ("backnet".into(), vec!["db-backend".into()]),
                    ]),
                    files: Vec::new(),
                },
                DockerHostContainer {
                    name: "api".into(),
                    image: DIGEST_B.into(),
                    networks: vec!["appnet".into()],
                    volumes: Vec::new(),
                    depends_on: vec!["db".into()],
                    mode: DockerContainerMode::Service,
                    env_file: Some("api.env".into()),
                    health: Some(DockerHealthCheck { cmd: "true".into() }),
                    ports: vec![DockerPortPublication {
                        host_ip: loopback(),
                        host_port: 8080,
                        container_port: 80,
                        protocol: DockerPortProtocol::Tcp,
                    }],
                    entrypoint: None,
                    command: None,
                    aliases: BTreeMap::new(),
                    files: Vec::new(),
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
    fn config_files_are_installed_before_start_and_follow_release_replacement() {
        let root = std::env::temp_dir().join(format!("tenkai-config-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let (script, state) = fake_docker(&root);
        let executor = executor_for(&script, &state, &[]);
        for (version, contents) in [
            ("1.0.0", "first configuration"),
            ("2.0.0", "second configuration"),
        ] {
            write_release(&root, version, DIGEST_B);
            let mut topology = sample_topology();
            topology.containers[1].env_file = None;
            topology.containers[1].files = vec![DockerConfigFile {
                source: "docker/app.json".into(),
                destination: "/etc/app.json".into(),
                read_only: true,
            }];
            std::fs::write(root.join(version).join("docker/app.json"), contents).unwrap();
            std::fs::write(
                root.join(version).join("docker/host.json"),
                serde_json::to_vec(&topology).unwrap(),
            )
            .unwrap();
        }
        let first = request_for(&root, &root, "1.0.0");
        let second = request_for(&root, &root, "2.0.0");
        for (request, expected) in [
            (&first, "first configuration"),
            (&second, "second configuration"),
            (&first, "first configuration"),
        ] {
            executor.apply(request).unwrap();
            executor.restart(request).unwrap();
            assert_eq!(
                executor.observe(request).unwrap(),
                SoftwareObserveStatus::Present
            );
            let data: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
            let topology = load_topology(&request.workdir).unwrap();
            let name = managed_container_name(request, &topology.containers[1]).unwrap();
            let file = &data["containers"][&name]["files_at_start"]["/etc/app.json"];
            assert_eq!(file["contents"], expected);
            assert_eq!(file["mode"], 0o444);
            assert_eq!(file["uid"], 0);
            assert_eq!(file["gid"], 0);
        }
        std::fs::write(first.workdir.join("docker/app.json"), "changed source").unwrap();
        assert_eq!(
            executor.observe(&first).unwrap(),
            SoftwareObserveStatus::Mismatched
        );
        executor.apply(&first).unwrap();
        assert_eq!(
            executor.observe(&first).unwrap(),
            SoftwareObserveStatus::Present
        );
        let log = std::fs::read_to_string(root.join("argv.log")).unwrap();
        assert!(!log.contains("first configuration"));
        assert!(!log.contains("second configuration"));
        assert!(log.contains("\"cp\", \"-\""));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn config_admission_rejects_path_escapes_and_collisions_before_docker_mutation() {
        let root =
            std::env::temp_dir().join(format!("tenkai-config-admit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let (script, state) = fake_docker(&root);
        let executor = executor_for(&script, &state, &[]);
        write_release(&root, "1.0.0", DIGEST_B);
        let request = request_for(&root, &root, "1.0.0");
        std::fs::write(root.join("outside.json"), "outside").unwrap();
        std::os::unix::fs::symlink(
            root.join("outside.json"),
            request.workdir.join("docker/escape.json"),
        )
        .unwrap();
        for (source, destination) in [
            ("../outside.json", "/etc/app.json"),
            ("docker/escape.json", "/etc/app.json"),
            ("docker/missing.json", "/etc/app.json"),
            ("docker/host.json", "/etc/../app.json"),
            ("docker/host.json", "/var/lib/data/app.json"),
        ] {
            let mut topology = sample_topology();
            topology.containers[1].env_file = None;
            topology.containers[0].files = vec![DockerConfigFile {
                source: source.into(),
                destination: destination.into(),
                read_only: true,
            }];
            std::fs::write(
                request.workdir.join("docker/host.json"),
                serde_json::to_vec(&topology).unwrap(),
            )
            .unwrap();
            assert!(
                executor.apply(&request).is_err(),
                "{source} -> {destination}"
            );
            assert!(!state.exists());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    fn write_job_release(root: &Path, version: &str) -> DockerHostTopology {
        write_release(root, version, DIGEST_B);
        let mut topology = sample_topology();
        let mut service = topology.containers[1].clone();
        service.name = "worker".into();
        service.env_file = None;
        service.depends_on = vec![DockerDependency::Conditional {
            container: "init".into(),
            condition: DockerDependencyCondition::CompletedSuccessfully,
        }];
        topology.containers[1].name = "init".into();
        topology.containers[1].env_file = None;
        topology.containers[1].health = None;
        topology.containers[1].ports.clear();
        topology.containers[1].mode = DockerContainerMode::OneShot { timeout_secs: 1 };
        topology.containers[1].depends_on = vec![DockerDependency::Conditional {
            container: "db".into(),
            condition: DockerDependencyCondition::Healthy,
        }];
        topology.containers.push(service);
        std::fs::write(
            root.join(version).join("docker/host.json"),
            serde_json::to_vec_pretty(&topology).unwrap(),
        )
        .unwrap();
        topology
    }

    #[test]
    fn completion_gated_jobs_retain_evidence_across_apply_restart_and_rollback_activation() {
        let root = std::env::temp_dir().join(format!("tenkai-job-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let topology = write_job_release(&root, "1.0.0");
        write_job_release(&root, "1.1.0");
        let (script, state) = fake_docker(&root);
        let executor = executor_for(&script, &state, &[]);
        let first = request_for(&root, &root, "1.0.0");
        executor.apply(&first).unwrap();
        assert_eq!(
            executor.observe(&first).unwrap(),
            SoftwareObserveStatus::Present
        );
        let log_path = root.join("argv.log");
        let first_log = std::fs::read_to_string(&log_path).unwrap();
        let calls: Vec<Vec<String>> = first_log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let launched: Vec<_> = calls
            .iter()
            .filter(|args| args[0] == "run")
            .map(|args| args[args.iter().position(|arg| arg == "--name").unwrap() + 1].clone())
            .collect();
        assert_eq!(
            launched,
            topology
                .containers
                .iter()
                .map(|container| managed_container_name(&first, container).unwrap())
                .collect::<Vec<_>>()
        );
        executor.apply(&first).unwrap();
        executor.restart(&first).unwrap();
        let repeated = std::fs::read_to_string(&log_path).unwrap();
        assert!(!repeated[first_log.len()..].lines().any(|line| {
            let args: Vec<String> = serde_json::from_str(line).unwrap();
            args[0] == "run"
        }));
        let second = request_for(&root, &root, "1.1.0");
        let mut next_topology = write_job_release(&root, "1.1.0");
        next_topology.containers[2].image = DIGEST_C.into();
        std::fs::write(
            root.join("1.1.0/docker/host.json"),
            serde_json::to_vec_pretty(&next_topology).unwrap(),
        )
        .unwrap();
        let failed = executor_for(&script, &state, &[DIGEST_C]);
        assert!(
            failed
                .apply(&second)
                .unwrap_err()
                .to_string()
                .contains("restored the previous containers")
        );
        failed.cleanup_failed_apply(&second).unwrap();
        executor.apply(&first).unwrap();
        let before_retry = std::fs::read_to_string(&log_path).unwrap();
        executor.apply(&second).unwrap();
        let after_retry = std::fs::read_to_string(&log_path).unwrap();
        let completed_job = managed_container_name(&second, &next_topology.containers[1]).unwrap();
        assert!(!after_retry[before_retry.len()..].lines().any(|line| {
            let args: Vec<String> = serde_json::from_str(line).unwrap();
            args[0] == "run" && args.contains(&completed_job)
        }));
        let upgraded = std::fs::read_to_string(&log_path).unwrap();
        executor.apply(&first).unwrap();
        let rolled_back = std::fs::read_to_string(&log_path).unwrap();
        let old_job = managed_container_name(&first, &topology.containers[1]).unwrap();
        assert!(!rolled_back[upgraded.len()..].lines().any(|line| {
            let args: Vec<String> = serde_json::from_str(line).unwrap();
            args[0] == "run" && args.contains(&old_job)
        }));
        executor.remove(&first).unwrap();
        let final_state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        assert!(final_state["containers"].as_object().unwrap().is_empty());
        assert_eq!(final_state["volumes"].as_object().unwrap().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn job_nonzero_exit_and_timeout_block_dependents_and_allow_explicit_retry() {
        for timeout in [false, true] {
            let root =
                std::env::temp_dir().join(format!("tenkai-job-refusal-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&root).unwrap();
            let topology = write_job_release(&root, "1.0.0");
            let (script, state) = fake_docker(&root);
            let mut executor =
                executor_for(&script, &state, if timeout { &[] } else { &[DIGEST_B] });
            if timeout {
                executor
                    .extra_env
                    .insert("TENKAI_DOCKER_FAKE_JOB_RUNNING".into(), "1".into());
            }
            let request = request_for(&root, &root, "1.0.0");
            let error = executor.apply(&request).unwrap_err().to_string();
            assert!(
                error.contains(if timeout {
                    "exceeded timeout"
                } else {
                    "exited unsuccessfully"
                }),
                "{error}"
            );
            assert!(!error.contains(SECRET));
            let refused_state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
            assert!(refused_state["containers"].as_object().unwrap().is_empty());
            let log = std::fs::read_to_string(root.join("argv.log")).unwrap();
            let worker = managed_container_name(&request, &topology.containers[2]).unwrap();
            assert!(!log.lines().any(|line| {
                let args: Vec<String> = serde_json::from_str(line).unwrap();
                args[0] == "run" && args.contains(&worker)
            }));
            let retried = executor_for(&script, &state, &[]);
            retried.apply(&request).unwrap();
            assert_eq!(
                retried.observe(&request).unwrap(),
                SoftwareObserveStatus::Present
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn interrupted_running_job_is_removed_when_its_adopted_attempt_times_out() {
        let root =
            std::env::temp_dir().join(format!("tenkai-interrupted-job-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let topology = write_job_release(&root, "1.0.0");
        let (script, state_path) = fake_docker(&root);
        let executor = executor_for(&script, &state_path, &[]);
        let request = request_for(&root, &root, "1.0.0");
        executor.apply(&request).unwrap();
        let job = managed_container_name(&request, &topology.containers[1]).unwrap();
        let worker = managed_container_name(&request, &topology.containers[2]).unwrap();
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        state["containers"].as_object_mut().unwrap().remove(&worker);
        state["containers"][&job]["running"] = true.into();
        state["containers"][&job]["status"] = "running".into();
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let error = executor.apply(&request).unwrap_err().to_string();
        assert!(error.contains("exceeded timeout"), "{error}");
        let stopped: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert!(stopped["containers"].get(&job).is_none());
        assert!(stopped["containers"].get(&worker).is_none());
        executor.apply(&request).unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn topology_rejects_unbounded_jobs_and_incompatible_dependency_conditions() {
        let mut topology = sample_topology();
        topology.containers[1].env_file = None;
        topology.containers[1].health = None;
        topology.containers[1].mode = DockerContainerMode::OneShot { timeout_secs: 0 };
        assert!(
            validate_topology(&topology, None)
                .unwrap_err()
                .to_string()
                .contains("timeout")
        );
        topology.containers[1].mode = DockerContainerMode::OneShot { timeout_secs: 1 };
        topology.containers[1].health = Some(DockerHealthCheck { cmd: "true".into() });
        assert!(
            validate_topology(&topology, None)
                .unwrap_err()
                .to_string()
                .contains("health check")
        );
        topology.containers[1].health = None;
        topology.containers[1].depends_on = vec![DockerDependency::Conditional {
            container: "db".into(),
            condition: DockerDependencyCondition::CompletedSuccessfully,
        }];
        assert!(
            validate_topology(&topology, None)
                .unwrap_err()
                .to_string()
                .contains("requires a one-shot job")
        );
        topology.containers[1].depends_on.clear();
        topology.containers[0].depends_on = vec!["api".into()];
        assert!(
            validate_topology(&topology, None)
                .unwrap_err()
                .to_string()
                .contains("require completed_successfully")
        );
        topology.containers[0].depends_on = vec![DockerDependency::Conditional {
            container: "api".into(),
            condition: DockerDependencyCondition::CompletedSuccessfully,
        }];
        validate_topology(&topology, None).unwrap();
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
    fn image_references_must_carry_a_digest_and_no_tag() {
        let hex = "a".repeat(64);
        for admitted in [
            format!("sha256:{hex}"),
            format!("nginx@sha256:{hex}"),
            format!("docker.io/library/nginx@sha256:{hex}"),
            format!("localhost:5000/team/app__v2@sha256:{hex}"),
            format!("ghcr.io/org/app-name.web@sha256:{hex}"),
        ] {
            validate_image_reference(&admitted)
                .unwrap_or_else(|error| panic!("{admitted}: {error}"));
        }
        for refused in [
            "nginx".to_string(),
            "nginx:1.27".to_string(),
            format!("nginx:1.27@sha256:{hex}"),
            format!("Nginx@sha256:{hex}"),
            format!("@sha256:{hex}"),
            format!("nginx@sha256:{}", "A".repeat(64)),
            format!("nginx@sha512:{hex}"),
            format!("team//app@sha256:{hex}"),
            format!("app-@sha256:{hex}"),
            format!("app._x@sha256:{hex}"),
            format!("--privileged@sha256:{hex}"),
        ] {
            assert!(validate_image_reference(&refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn topology_rejects_invalid_publications_aliases_and_entrypoints() {
        let invalid = |edit: &dyn Fn(&mut DockerHostTopology)| {
            let mut topology = sample_topology();
            topology.containers[1].env_file = None;
            edit(&mut topology);
            validate_topology(&topology, None).unwrap_err().to_string()
        };
        assert!(
            invalid(&|t| t.containers[1].ports[0].host_port = 0).contains("between 1 and 65535")
        );
        assert!(
            invalid(&|t| t.containers[0].ports = t.containers[1].ports.clone())
                .contains("more than once")
        );
        assert!(
            invalid(&|t| {
                t.containers[1]
                    .aliases
                    .insert("othernet".into(), vec!["web".into()]);
            })
            .contains("does not join")
        );
        assert!(
            invalid(&|t| {
                t.containers[1]
                    .aliases
                    .insert("appnet".into(), vec!["database".into()]);
            })
            .contains("more than once")
        );
        assert!(
            invalid(&|t| {
                t.containers[1]
                    .aliases
                    .insert("appnet".into(), vec!["Bad_Alias".into()]);
            })
            .contains("network alias")
        );
        assert!(
            invalid(&|t| t.containers[1].entrypoint = Some(vec!["--privileged".into()]))
                .contains("executable")
        );
        assert!(
            invalid(&|t| t.containers[1].command = Some(vec!["PASSWORD=hunter2".into()]))
                .contains("credential")
        );

        let unknown = r#"{"containers":[{"name":"web","image":"nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","privileged":true}]}"#;
        assert!(serde_json::from_str::<DockerHostTopology>(unknown).is_err());
        let port = r#"{"host_port":8080,"container_port":80,"protocol":"sctp"}"#;
        assert!(serde_json::from_str::<DockerPortPublication>(port).is_err());
        let port = r#"{"host_ip":"::1","host_port":8080,"container_port":80}"#;
        let port: DockerPortPublication = serde_json::from_str(port).unwrap();
        assert_eq!(port.publish_arg(), "[::1]:8080:80/tcp");
        let port = r#"{"host_port":8080,"container_port":80}"#;
        let port: DockerPortPublication = serde_json::from_str(port).unwrap();
        assert_eq!(port.publish_arg(), "127.0.0.1:8080:80/tcp");
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
        let argv_after_first = std::fs::read_to_string(root.join("argv.log")).unwrap();
        assert!(
            argv_after_first.contains("\"pull\""),
            "first apply should pull images: {argv_after_first}"
        );
        let pull_at = argv_after_first.find("\"pull\"").unwrap();
        let run_at = argv_after_first.find("\"run\"").expect("first apply run");
        assert!(
            pull_at < run_at,
            "pull must happen before run: {argv_after_first}"
        );
        let fake_state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        let db_name = container_runtime_name(&request, "db");
        let api_name = container_runtime_name(&request, "api");
        let db = fake_state["containers"][&db_name]
            .as_object()
            .expect("db container");
        let net = network_runtime_name(&request, "appnet");
        assert_eq!(
            db["entrypoint"],
            serde_json::json!(["docker-entrypoint.sh"])
        );
        assert_eq!(
            db["command"],
            serde_json::json!(["--verbose", "postgres", "-c", "fsync=on"])
        );
        assert_eq!(db["networks"][&net], serde_json::json!(["database"]));
        let backnet = network_runtime_name(&request, "backnet");
        assert_eq!(db["networks"][&backnet], serde_json::json!(["db-backend"]));
        let api = &fake_state["containers"][&api_name];
        assert_eq!(api["ports"], serde_json::json!(["127.0.0.1:8080:80/tcp"]));
        assert_eq!(api["command"], serde_json::json!([]));
        let mounts = db["mounts"].as_array().expect("parsed mounts");
        assert_eq!(mounts.len(), 1, "{mounts:?}");
        assert_eq!(mounts[0]["type"], "volume");
        assert_eq!(mounts[0]["target"], "/var/lib/data");
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        executor.apply(&request).unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        let argv_after_second = std::fs::read_to_string(root.join("argv.log")).unwrap();
        let second_argv = &argv_after_second[argv_after_first.len()..];
        assert!(
            !second_argv.contains("\"run\""),
            "unchanged containers must not be replaced: {second_argv}"
        );
        let fake_state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert!(
            fake_state["containers"]
                .as_object()
                .unwrap()
                .contains_key(&db_name),
            "{fake_state}"
        );
        assert!(
            fake_state["containers"]
                .as_object()
                .unwrap()
                .contains_key(&api_name),
            "{fake_state}"
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
    fn hyphenated_environment_and_product_pairs_do_not_share_runtime_names() {
        let left = super::super::request_from_parts(
            "edge-app",
            "1.0.0",
            "prod",
            ".",
            "tenkai:release:edge-app@1.0.0",
        );
        let right = super::super::request_from_parts(
            "app",
            "1.0.0",
            "prod-edge",
            ".",
            "tenkai:release:app@1.0.0",
        );
        assert_ne!(
            container_runtime_name(&left, "db"),
            container_runtime_name(&right, "db")
        );
        assert_ne!(
            volume_runtime_name(&left, "data"),
            volume_runtime_name(&right, "data")
        );
        assert_ne!(
            network_runtime_name(&left, "net"),
            network_runtime_name(&right, "net")
        );
        assert_ne!(container_runtime_name(&left, "db"), "prod-edge-app-ctr-db");
    }

    #[test]
    fn colliding_hyphen_pairs_keep_both_releases() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-docker-collide-{}-{}",
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
        let mut left = request_for(&root, &secret_dir, "1.0.0");
        left.environment = "prod".into();
        left.product = "edge-app".into();
        let mut right = request_for(&root, &secret_dir, "1.0.0");
        right.environment = "prod-edge".into();
        right.product = "app".into();
        right.release_id = "tenkai:release:app@1.0.0".into();
        executor.apply(&left).unwrap();
        executor.apply(&right).unwrap();
        let fake_state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        let containers = fake_state["containers"].as_object().unwrap();
        let left_db = container_runtime_name(&left, "db");
        let right_db = container_runtime_name(&right, "db");
        assert_ne!(left_db, right_db);
        assert!(containers.contains_key(&left_db), "{fake_state}");
        assert!(containers.contains_key(&right_db), "{fake_state}");
        assert_eq!(
            executor.observe(&left).unwrap(),
            SoftwareObserveStatus::Present
        );
        assert_eq!(
            executor.observe(&right).unwrap(),
            SoftwareObserveStatus::Present
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn apply_refuses_to_remove_a_container_owned_by_another_release() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-docker-foreign-{}-{}",
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
        let name = container_runtime_name(&request, "db");
        let seeded = serde_json::json!({
            "containers": {
                name.clone(): {
                    "id": "aaaaaaaaaaaa",
                    "image": DIGEST_A,
                    "labels": {
                        "tenkai.product": "other",
                        "tenkai.environment": "lab",
                        "tenkai.container": "db"
                    },
                    "running": true,
                    "health": "healthy",
                    "mounts": []
                }
            },
            "networks": {},
            "volumes": {}
        });
        std::fs::write(&state, seeded.to_string()).unwrap();
        let err = executor.apply(&request).unwrap_err().to_string();
        assert!(err.contains("owned by"), "{err}");
        assert!(err.contains("other"), "{err}");
        let fake_state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert!(
            fake_state["containers"]
                .as_object()
                .unwrap()
                .contains_key(&name),
            "{fake_state}"
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
        // A failed first install keeps no container and drops its network.
        executor.cleanup_failed_apply(&request).unwrap();
        assert!(fake_containers(&state).is_empty());
        let argv = std::fs::read_to_string(root.join("argv.log")).unwrap();
        assert!(argv.contains(r#"["network", "rm""#), "{argv}");
        // Cleanup also removes containers an interrupted rollback left behind.
        executor_for(&script, &state, &[]).apply(&request).unwrap();
        executor.cleanup_failed_apply(&request).unwrap();
        assert!(fake_containers(&state).is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    fn fake_containers(state: &Path) -> serde_json::Map<String, serde_json::Value> {
        let state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(state).unwrap()).unwrap();
        state["containers"].as_object().unwrap().clone()
    }

    #[test]
    fn failed_upgrade_restores_the_previous_containers() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-docker-restore-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let secret_dir = root.join("secrets");
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("api.env"), "TOKEN=x\n").unwrap();
        write_release(&root, "1.0.0", DIGEST_B);
        write_release(&root, "2.0.0", DIGEST_C);
        let (script, state) = fake_docker(&root);
        let executor = executor_for(&script, &state, &[DIGEST_C]);
        let v1 = request_for(&root, &secret_dir, "1.0.0");
        let v2 = request_for(&root, &secret_dir, "2.0.0");
        executor.apply(&v1).unwrap();

        // db comes up healthy under 2.0.0, api never does.
        let error = executor.apply(&v2).unwrap_err().to_string();
        assert!(error.contains("phase=health"), "{error}");
        assert!(
            error.contains("restored the previous containers"),
            "{error}"
        );
        let containers = fake_containers(&state);
        assert_eq!(containers.len(), 2, "{containers:?}");
        for container in containers.values() {
            assert_eq!(container["labels"]["tenkai.version"], "1.0.0");
            assert_eq!(container["running"], true);
        }
        assert_eq!(
            executor.observe(&v1).unwrap(),
            SoftwareObserveStatus::Present
        );

        // Cleanup leaves the restored release alone, and re-applying it
        // recreates nothing.
        executor.cleanup_failed_apply(&v2).unwrap();
        let before = std::fs::read_to_string(root.join("argv.log")).unwrap();
        executor.apply(&v1).unwrap();
        let after = std::fs::read_to_string(root.join("argv.log")).unwrap();
        assert!(!after[before.len()..].contains("\"run\""), "{after}");
        assert_eq!(fake_containers(&state).len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rotated_env_file_recreates_its_container_on_reapply_and_restart() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-docker-rotate-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let secret_dir = root.join("secrets");
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("api.env"), "TOKEN=old\n").unwrap();
        write_release(&root, "1.0.0", DIGEST_B);
        let (script, state) = fake_docker(&root);
        let executor = executor_for(&script, &state, &[]);
        let request = request_for(&root, &secret_dir, "1.0.0");
        executor.apply(&request).unwrap();
        let api = container_runtime_name(&request, "api");
        let runs_since = |before: &str| {
            let argv = std::fs::read_to_string(root.join("argv.log")).unwrap();
            argv[before.len()..]
                .lines()
                .filter(|line| line.starts_with(r#"["run""#))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };

        std::fs::write(secret_dir.join("api.env"), "TOKEN=new\n").unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Mismatched
        );
        let before = std::fs::read_to_string(root.join("argv.log")).unwrap();
        executor.apply(&request).unwrap();
        let runs = runs_since(&before);
        assert_eq!(runs.len(), 1, "only api is recreated: {runs:?}");
        assert!(runs[0].contains(&api), "{runs:?}");
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );

        // `docker restart` would keep the old values, so restart recreates.
        std::fs::write(secret_dir.join("api.env"), "TOKEN=newer\n").unwrap();
        let before = std::fs::read_to_string(root.join("argv.log")).unwrap();
        executor.restart(&request).unwrap();
        let runs = runs_since(&before);
        assert_eq!(runs.len(), 1, "{runs:?}");
        assert!(runs[0].contains(&api), "{runs:?}");
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        assert!(!fake_containers(&state).contains_key(&previous_runtime_name(&request, "api")));
        let argv = std::fs::read_to_string(root.join("argv.log")).unwrap();
        assert!(!argv.contains("TOKEN="), "{argv}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reapply_replaces_a_matching_but_unhealthy_container() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-docker-unhealthy-skip-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let secret_dir = root.join("secrets");
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("api.env"), "TOKEN=x\n").unwrap();
        write_release(&root, "1.0.0", DIGEST_B);
        let (script, state) = fake_docker(&root);
        let executor = executor_for(&script, &state, &[]);
        let request = request_for(&root, &secret_dir, "1.0.0");
        executor.apply(&request).unwrap();
        let db = container_runtime_name(&request, "db");
        let mut fake: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        fake["containers"][&db]["health"] = "unhealthy".into();
        std::fs::write(&state, fake.to_string()).unwrap();

        executor.apply(&request).unwrap();
        assert_eq!(fake_containers(&state)[&db]["health"], "healthy");
        assert!(!fake_containers(&state).contains_key(&previous_runtime_name(&request, "db")));
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

    /// Clean-engine drill: two registry digest pins, a loopback web endpoint,
    /// alias-based service discovery, and a declared command.
    #[test]
    #[ignore = "requires a Docker engine with registry access; run with --ignored"]
    fn live_engine_registry_pins_ports_aliases_and_command() {
        const WEB: &str =
            "nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10";
        const CLIENT: &str =
            "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";
        let root = std::env::temp_dir().join(format!(
            "tenkai-docker-live-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(root.join("1.0.0/docker")).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let topology = serde_json::json!({
            "networks": ["appnet"],
            "containers": [
                {
                    "name": "web",
                    "image": WEB,
                    "networks": ["appnet"],
                    "aliases": {"appnet": ["web"]},
                    "ports": [{"host_port": port, "container_port": 80}]
                },
                {
                    "name": "client",
                    "image": CLIENT,
                    "networks": ["appnet"],
                    "depends_on": ["web"],
                    "entrypoint": ["sh", "-c"],
                    "command": ["while true; do wget -q -O /tmp/index http://web/ && touch /tmp/ok; sleep 1; done"],
                    "health": {"cmd": "test -f /tmp/ok"}
                }
            ]
        });
        std::fs::write(
            root.join("1.0.0/docker/host.json"),
            serde_json::to_string_pretty(&topology).unwrap(),
        )
        .unwrap();
        let request = request_for(&root, &root, "1.0.0");
        let executor = DockerHostExecutor::default();
        let result = executor.apply(&request).and_then(|()| {
            assert_eq!(executor.observe(&request)?, SoftwareObserveStatus::Present);
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))?;
            std::io::Write::write_all(&mut stream, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
            let mut response = String::new();
            std::io::Read::read_to_string(&mut stream, &mut response)?;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            executor.restart(&request)
        });
        executor.remove(&request).unwrap();
        let _ = std::fs::remove_dir_all(root);
        result.unwrap();
    }
}
