//! Software product apply ports (Kubernetes via Helm or native manifests,
//! Docker host topology via the Docker CLI).
//!
//! **Helm (#95):** chart-oriented `helm upgrade --install` when
//! `TENKAI_SOFTWARE_EXECUTOR=helm`.
//!
//! **Native Kubernetes (#105):** plain multi-doc YAML under `manifests/` via
//! `kubectl` argv (not Helm).
//!
//! **In-process Kubernetes (#376):** server-side apply with field manager
//! `tenkai`, bounded rollout wait, and health from workload conditions.
//! Selected with `TENKAI_SOFTWARE_EXECUTOR=kubernetes-inprocess`.
//!
//! **Docker host (#528):** digest-pinned containers, networks, and volumes from
//! `{workdir}/docker/host.json` via `TENKAI_SOFTWARE_EXECUTOR=docker`.
//!
//! Hosts call `tenkai_executor::install()` then [`SoftwareExecutors::try_from_process`].
//! Each release runs with the executor it declares in `[deploy] executor`, or
//! with the process default when it declares none (ADR 0041). Community
//! defaults keep the shell `deploy.install` path when `TENKAI_SOFTWARE_EXECUTOR`
//! is unset. An unknown or uninstalled value is refused; it never becomes
//! shell. Credential-free diagnostics live in the diagnostics module.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

mod cluster_config;
mod diagnostics;
mod docker_secret;

pub use cluster_config::{
    CLUSTER_CONFIG_PATH_PROPERTY, cluster_config_path_from_properties, validate_cluster_config_path,
};
pub use diagnostics::{
    SoftwareDeployPhase, format_software_phase_error, rollback_channel_note, run_captured_command,
    sanitize_diagnostic_text,
};
pub use docker_secret::{
    DOCKER_SECRET_DIR_PROPERTY, secret_dir_from_properties, validate_secret_dir_path,
};

/// Wall time of one software apply, split into the phases the rollout-time
/// harness reports (plan, pull, apply, health wait, record).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPhaseTimes {
    pub plan_ms: u64,
    pub pull_ms: u64,
    pub apply_ms: u64,
    pub health_ms: u64,
    pub record_ms: u64,
}

impl RolloutPhaseTimes {
    /// Sum of the five phases. Saturating so a clock jump cannot wrap the report.
    pub fn wall_ms(&self) -> u64 {
        self.plan_ms
            .saturating_add(self.pull_ms)
            .saturating_add(self.apply_ms)
            .saturating_add(self.health_ms)
            .saturating_add(self.record_ms)
    }
}

static HELM_EXECUTOR: OnceLock<fn() -> Box<dyn SoftwareExecutor>> = OnceLock::new();
static KUBERNETES_EXECUTOR: OnceLock<fn() -> Box<dyn SoftwareExecutor>> = OnceLock::new();
static DOCKER_EXECUTOR: OnceLock<fn() -> Box<dyn SoftwareExecutor>> = OnceLock::new();
static IN_PROCESS_EXECUTOR: OnceLock<fn() -> Box<dyn SoftwareExecutor>> = OnceLock::new();

/// Install the Helm CLI adapter from `tenkai-executor`.
pub fn install_helm_software_executor(factory: fn() -> Box<dyn SoftwareExecutor>) {
    let _ = HELM_EXECUTOR.set(factory);
}

/// Install the kubectl CLI adapter from `tenkai-executor`.
pub fn install_kubernetes_software_executor(factory: fn() -> Box<dyn SoftwareExecutor>) {
    let _ = KUBERNETES_EXECUTOR.set(factory);
}

/// Install the Docker CLI adapter from `tenkai-executor`.
pub fn install_docker_software_executor(factory: fn() -> Box<dyn SoftwareExecutor>) {
    let _ = DOCKER_EXECUTOR.set(factory);
}

/// Install the in-process Kubernetes adapter from `tenkai-executor`.
pub fn install_in_process_software_executor(factory: fn() -> Box<dyn SoftwareExecutor>) {
    let _ = IN_PROCESS_EXECUTOR.set(factory);
}

/// Request to apply or remove a software product generation on one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareApplyRequest {
    pub product: String,
    /// Instance this request applies to. Empty means the product name
    /// (ADR 0044 §1), omitted from JSON so default-instance payloads stay
    /// unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub instance: String,
    pub version: String,
    pub environment: String,
    pub workdir: PathBuf,
    /// Release id for audit (never a secret).
    pub release_id: String,
    /// Non-secret environment overlays. Helm passes them as `--set tenkai.config.*`;
    /// native and in-process Kubernetes stamp `tenkai.config-digest` only.
    #[serde(default)]
    pub overlays: BTreeMap<String, String>,
    /// Digest of `overlays`. Empty when no overlays are set.
    #[serde(default)]
    pub config_digest: String,
    /// Environment-mirror refs admitted for this apply. Origin pull is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_pulls: Vec<crate::oci_artifact::OciArtifactRef>,
    /// Environment-scoped kubeconfig file path. Never a secret blob or argv flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_config_path: Option<PathBuf>,
    /// Environment-scoped directory of Docker env files. Never secret bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_dir_path: Option<PathBuf>,
    /// Identity of this apply attempt: the environment lease generation for a
    /// leased apply, else a fresh random value. The Docker executor stamps it
    /// on every container the attempt creates, and failed-apply cleanup
    /// removes only containers carrying it, so containers an earlier release
    /// created are left alone (#669). Empty means unknown: cleanup removes
    /// nothing by release label alone.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub apply_attempt: String,
    /// Canonical JSON dependency document (ADR 0043 §6). Empty when the
    /// release declares no requirements. Old executors ignore an unknown
    /// field; new ones treat empty as no document.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dependency_document: String,
    /// Sealed values the environment runtime opened for this apply (ADR
    /// 0045 §4). Never serialized: they reach no server, operator program,
    /// or log. Only the Helm executor writes them.
    #[serde(skip)]
    pub opened_secrets: Vec<OpenedSecret>,
}

/// One sealed value opened in memory, for the slot a plan step names. Its
/// `Debug` names the slot, never the value.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedSecret {
    pub secret: String,
    pub key: String,
    /// The sealed digest the plan step names.
    pub digest: String,
    pub value: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for OpenedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenedSecret")
            .field("secret", &self.secret)
            .field("key", &self.key)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// Literal substituted in native/in-process Kubernetes YAML at apply, and
/// nowhere else (ADR 0044 §2). Helm charts get `--set tenkai.instance` instead.
pub const INSTANCE_PLACEHOLDER: &str = "${TENKAI_INSTANCE}";

impl SoftwareApplyRequest {
    /// Instance this request applies to. Empty `instance` means the product.
    pub fn instance_name(&self) -> &str {
        if self.instance.is_empty() {
            &self.product
        } else {
            &self.instance
        }
    }
}

/// Replace [`INSTANCE_PLACEHOLDER`] with `instance`. Other bytes are unchanged.
pub fn substitute_instance_placeholder(text: &str, instance: &str) -> String {
    text.replace(INSTANCE_PLACEHOLDER, instance)
}

/// Kubernetes label selector that isolates one instance of a product.
pub fn instance_selector(request: &SoftwareApplyRequest) -> String {
    format!(
        "tenkai.product={},tenkai.instance={}",
        k8s_label_value(&request.product),
        k8s_label_value(request.instance_name()),
    )
}

/// Temporary copy of `{workdir}/manifests` with [`INSTANCE_PLACEHOLDER`] replaced.
pub struct MaterializedManifests {
    pub dir: PathBuf,
}

impl Drop for MaterializedManifests {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Copy native manifests and substitute the instance placeholder. The signed
/// workdir is not rewritten.
pub fn materialize_kubernetes_manifests(
    request: &SoftwareApplyRequest,
) -> Result<MaterializedManifests> {
    let src = kubernetes_manifests_dir(&request.workdir)?;
    let dest = std::env::temp_dir().join(format!(
        "tenkai-k8s-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let files = list_manifest_files(&src)?;
    if files.is_empty() {
        bail!(
            "native kubernetes apply requires at least one .yaml/.yml under {}",
            src.display()
        );
    }
    for path in &files {
        let rel = path.strip_prefix(&src).with_context(|| {
            format!("manifest {} is not under {}", path.display(), src.display())
        })?;
        let out = dest.join(rel);
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading manifest {}", path.display()))?;
        let rendered = substitute_instance_placeholder(&raw, request.instance_name());
        std::fs::write(&out, rendered).with_context(|| format!("writing {}", out.display()))?;
    }
    Ok(MaterializedManifests { dir: dest })
}

/// An executor cannot reach its target, found before anything was applied:
/// for example an in-cluster release whose cluster config file does not exist
/// until a host release creates the cluster, or is not configured at all. The
/// step fails with nothing to clean up, the deployment stays as it was, and
/// reconcile retries with its backoff (ADR 0041 section 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetUnavailable(pub String);

impl std::fmt::Display for TargetUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TargetUnavailable {}

/// Pluggable software apply path. Tenkai never hard-depends on a cluster.
pub trait SoftwareExecutor: Send + Sync {
    /// Checks, before anything changes, that the target this adapter writes
    /// to exists. Apply and restart call it first; a refusal means nothing
    /// was applied. Default: nothing to check.
    fn require_target(&self, request: &SoftwareApplyRequest) -> Result<(), TargetUnavailable> {
        let _ = request;
        Ok(())
    }
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()>;
    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()>;
    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus>;
    /// Clean up after `apply` failed. Default removes the release; an adapter
    /// whose failed `apply` already restored the previous runtime overrides it.
    fn cleanup_failed_apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        self.remove(request)
    }
    /// Same-version bounce. Default re-applies the current pin.
    fn restart(&self, request: &SoftwareApplyRequest) -> Result<()> {
        self.apply(request)
    }
    /// `apply` under an apply lease. Apply sets `stop` when it loses the
    /// lease; an adapter that waits on its target returns an error soon after,
    /// so its wait never outlives the lease. Default ignores `stop`.
    fn apply_until_stopped(&self, request: &SoftwareApplyRequest, stop: &AtomicBool) -> Result<()> {
        let _ = stop;
        self.apply(request)
    }
    /// `restart` under an apply lease, stopping like [`Self::apply_until_stopped`].
    fn restart_until_stopped(
        &self,
        request: &SoftwareApplyRequest,
        stop: &AtomicBool,
    ) -> Result<()> {
        let _ = stop;
        self.restart(request)
    }
    /// Whether this adapter deploys from admitted environment-mirror refs.
    fn consumes_admitted_artifact_pulls(&self) -> bool {
        false
    }
    /// Snapshot of running units after a successful apply. Default is none.
    fn observed_runtime(
        &self,
        request: &SoftwareApplyRequest,
    ) -> Result<Option<crate::observed_runtime::ObservedRuntimeComponent>> {
        let _ = request;
        Ok(None)
    }
    /// Bounded, allowlisted live workload facts for a support bundle (#1017).
    /// Default is none: this adapter does not talk to a cluster.
    fn support_workloads(
        &self,
        environment: &str,
        cluster_config: &Path,
    ) -> Result<Vec<crate::support_bundle::SupportWorkload>> {
        let _ = (environment, cluster_config);
        Ok(Vec::new())
    }
    /// Compare the applied spec with the live target without acting (#1028).
    /// Default is `unknown`: this adapter does not compute fingerprints.
    fn observe_spec_drift(
        &self,
        request: &SoftwareApplyRequest,
    ) -> Result<crate::spec_drift::SpecDriftView> {
        let _ = request;
        Ok(crate::spec_drift::SpecDriftView::unknown())
    }
    /// Apply one generation and return wall time per phase. Default times `apply`.
    fn apply_with_phases(&self, request: &SoftwareApplyRequest) -> Result<RolloutPhaseTimes> {
        let started = Instant::now();
        self.apply(request)?;
        Ok(RolloutPhaseTimes {
            apply_ms: started.elapsed().as_millis() as u64,
            ..RolloutPhaseTimes::default()
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareObserveStatus {
    Absent,
    Present,
    Unknown,
    /// Live Tenkai version or release identity does not match the requested pin.
    Mismatched,
}

/// Deterministic fake for CI (no cluster, no helm binary).
#[derive(Debug, Default)]
pub struct FakeSoftwareExecutor {
    applied: Mutex<Vec<String>>,
    documents: Mutex<Vec<String>>,
    fail_apply: bool,
    apply_delay: std::time::Duration,
}

impl FakeSoftwareExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_fail_apply(mut self, fail: bool) -> Self {
        self.fail_apply = fail;
        self
    }

    pub fn with_apply_delay(mut self, delay: std::time::Duration) -> Self {
        self.apply_delay = delay;
        self
    }

    pub fn applied_keys(&self) -> Vec<String> {
        self.applied.lock().expect("fake software mutex").clone()
    }

    /// Canonical dependency documents delivered with each apply, empty when none.
    pub fn applied_documents(&self) -> Vec<String> {
        self.documents.lock().expect("fake software mutex").clone()
    }
}

impl SoftwareExecutor for FakeSoftwareExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        if !self.apply_delay.is_zero() {
            std::thread::sleep(self.apply_delay);
        }
        if self.fail_apply {
            bail!(
                "fake software executor refused apply for {}@{} in {}",
                request.product,
                request.version,
                request.environment
            );
        }
        let key = request_key(request);
        self.applied.lock().expect("fake software mutex").push(key);
        self.documents
            .lock()
            .expect("fake software mutex")
            .push(request.dependency_document.clone());
        Ok(())
    }

    fn consumes_admitted_artifact_pulls(&self) -> bool {
        true
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let key = request_key(request);
        let mut guard = self.applied.lock().expect("fake software mutex");
        guard.retain(|entry| entry != &key);
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let key = request_key(request);
        let guard = self.applied.lock().expect("fake software mutex");
        if guard.iter().any(|entry| entry == &key) {
            Ok(SoftwareObserveStatus::Present)
        } else {
            Ok(SoftwareObserveStatus::Absent)
        }
    }
}

/// Directory under the release workdir that holds native Kubernetes manifests.
pub const KUBERNETES_MANIFESTS_DIR: &str = "manifests";

pub fn kubernetes_manifests_dir(workdir: &Path) -> Result<PathBuf> {
    let dir = workdir.join(KUBERNETES_MANIFESTS_DIR);
    if !dir.is_dir() {
        bail!(
            "native kubernetes workdir must contain a {KUBERNETES_MANIFESTS_DIR}/ directory at {}",
            dir.display()
        );
    }
    // Refuse path escape: manifests dir must stay under workdir.
    let workdir_canon = workdir
        .canonicalize()
        .with_context(|| format!("canonicalizing workdir {}", workdir.display()))?;
    let dir_canon = dir
        .canonicalize()
        .with_context(|| format!("canonicalizing manifests {}", dir.display()))?;
    if !dir_canon.starts_with(&workdir_canon) {
        bail!("manifests directory escapes workdir");
    }
    Ok(dir)
}

/// Sorted list of manifest files for deterministic apply order.
pub fn list_manifest_files(manifests_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_manifest_files(manifests_dir, manifests_dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_manifest_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("listing kubernetes manifests {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat {}", path.display()))?;
        if file_type.is_dir() {
            collect_manifest_files(root, &path, out)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            // Ensure file remains under root.
            let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            let path_canon = path.canonicalize().unwrap_or_else(|_| path.clone());
            if !path_canon.starts_with(&root_canon) {
                bail!(
                    "manifest path escapes manifests directory: {}",
                    path.display()
                );
            }
            out.push(path);
        }
    }
    Ok(())
}

/// Kubernetes label values: alphanumeric, '-', '_', '.'; other chars → '-'.
pub fn k8s_label_value(raw: &str) -> String {
    let mapped: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Label values are at most 63 chars and must start and end alphanumeric.
    let truncated: String = mapped
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .chars()
        .take(63)
        .collect();
    let trimmed = truncated.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() {
        "unknown".into()
    } else {
        trimmed.into()
    }
}

/// A software executor named by `[deploy] executor` in a release manifest or by
/// the process default `TENKAI_SOFTWARE_EXECUTOR` (ADR 0041). Both read the
/// same name set through [`SoftwareExecutorKind::from_name`]; the test-only
/// `fake` selector is the one process name a manifest cannot declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SoftwareExecutorKind {
    /// `deploy.install` behind `tenkai-executor-guard`, as the server's user.
    Shell,
    /// `deploy.install` run by the root-side host applier.
    Host,
    Helm,
    /// Native manifests through `kubectl`; also named `k8s` and `native`.
    Kubernetes,
    KubernetesInProcess,
    Docker,
}

const SOFTWARE_EXECUTOR_NAME_HINT: &str =
    "shell, host, helm, kubernetes (k8s, native), kubernetes-inprocess, docker";

impl SoftwareExecutorKind {
    pub const ALL: [Self; 6] = [
        Self::Shell,
        Self::Host,
        Self::Helm,
        Self::Kubernetes,
        Self::KubernetesInProcess,
        Self::Docker,
    ];

    /// Canonical name; aliases normalize to it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Host => "host",
            Self::Helm => "helm",
            Self::Kubernetes => "kubernetes",
            Self::KubernetesInProcess => "kubernetes-inprocess",
            Self::Docker => "docker",
        }
    }

    /// Parse a canonical name or alias, ASCII case-insensitively, as
    /// `TENKAI_SOFTWARE_EXECUTOR` always has.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| name.eq_ignore_ascii_case(kind.as_str()))
            .or_else(|| {
                (name.eq_ignore_ascii_case("k8s") || name.eq_ignore_ascii_case("native"))
                    .then_some(Self::Kubernetes)
            })
    }
}

impl std::fmt::Display for SoftwareExecutorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SoftwareExecutorKind {
    type Err = anyhow::Error;

    fn from_str(name: &str) -> Result<Self> {
        Self::from_name(name).with_context(|| {
            format!(
                "unknown software executor {name:?}; expected one of {SOFTWARE_EXECUTOR_NAME_HINT}"
            )
        })
    }
}

impl Serialize for SoftwareExecutorKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SoftwareExecutorKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

/// The installed adapter for `kind`. `None` for `shell` (the caller keeps the
/// `deploy.install` path), for `host` (see [`SoftwareExecutors::host`]), and
/// for an adapter the host binary did not install.
pub fn software_executor_for(kind: SoftwareExecutorKind) -> Option<Box<dyn SoftwareExecutor>> {
    let factory = match kind {
        SoftwareExecutorKind::Shell | SoftwareExecutorKind::Host => return None,
        SoftwareExecutorKind::Helm => HELM_EXECUTOR.get(),
        SoftwareExecutorKind::Kubernetes => KUBERNETES_EXECUTOR.get(),
        SoftwareExecutorKind::KubernetesInProcess => IN_PROCESS_EXECUTOR.get(),
        SoftwareExecutorKind::Docker => DOCKER_EXECUTOR.get(),
    };
    factory.map(|factory| factory())
}

/// The software executors one process runs releases with (ADR 0041).
///
/// A release that declares `[deploy] executor` runs with that executor or
/// fails closed naming it; it never falls back. A release that declares
/// nothing runs with the process default (`TENKAI_SOFTWARE_EXECUTOR`) exactly
/// as before. Resolution reads only signed release content and this process's
/// configuration, so two server versions agree on undeclared releases.
#[derive(Clone)]
pub struct SoftwareExecutors {
    /// Kind the process default runs as. `None` is an unnamed test default
    /// (`fake`), which no declared kind ever equals.
    default_kind: Option<SoftwareExecutorKind>,
    /// Process default adapter. `None` is the shell `deploy.install` path.
    default: Option<Arc<dyn SoftwareExecutor>>,
    /// Adapters for declared kinds. `shell` and `host` never have one.
    declared: Vec<(SoftwareExecutorKind, Arc<dyn SoftwareExecutor>)>,
    /// Runs `host` releases through the root-side applier, as host plan
    /// steps only; otherwise why it is unavailable.
    host: std::result::Result<Arc<crate::host_executor::HostExecutor>, String>,
    /// Set when `TENKAI_SOFTWARE_EXECUTOR` is unknown or its adapter is
    /// missing. [`Self::resolve`] for an undeclared release fails closed
    /// with this text instead of using the shell path.
    process_default_error: Option<String>,
}

/// Why a process without `TENKAI_HOST_SPOOL_DIR` has no host executor.
fn host_not_configured() -> String {
    format!(
        "set {} to the applier's spool directory",
        crate::host_executor::SPOOL_DIR_ENV
    )
}

/// Shell default and no declared adapters.
impl Default for SoftwareExecutors {
    fn default() -> Self {
        Self {
            default_kind: Some(SoftwareExecutorKind::Shell),
            default: None,
            declared: Vec::new(),
            host: Err(host_not_configured()),
            process_default_error: None,
        }
    }
}

impl SoftwareExecutors {
    /// This process's executors: the `TENKAI_SOFTWARE_EXECUTOR` default,
    /// every adapter the host installed (`tenkai_executor::install()`), and
    /// the host executor `TENKAI_HOST_SPOOL_DIR` configures. A host executor
    /// whose configuration does not parse or that is not ready
    /// ([`crate::host_executor::HostExecutor::check_ready`]) is unavailable,
    /// so host steps fail closed naming why, as `/readyz` omits it.
    ///
    /// An unknown name, or a known name whose adapter is not installed, is
    /// stored as [`Self::process_default_error`]: undeclared releases fail
    /// closed and never fall back to shell. Hosts that must refuse at start
    /// call [`Self::try_from_process`].
    pub fn from_process() -> Self {
        match Self::try_from_process() {
            Ok(this) => this,
            Err(error) => Self {
                default_kind: None,
                default: None,
                process_default_error: Some(format!("{error:#}")),
                ..Self::installed_adapters()
            },
        }
    }

    /// Like [`Self::from_process`], but an unknown or uninstalled
    /// `TENKAI_SOFTWARE_EXECUTOR` is an error. Shell remains the default only
    /// when the variable is unset, or set to `shell`.
    pub fn try_from_process() -> Result<Self> {
        let value = match std::env::var("TENKAI_SOFTWARE_EXECUTOR") {
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => return Err(error.into()),
            Ok(value) => Some(value),
        };
        let (default_kind, default) = process_default_from_value(value.as_deref())?;
        Ok(Self {
            default_kind,
            default,
            process_default_error: None,
            ..Self::installed_adapters()
        })
    }

    fn installed_adapters() -> Self {
        let declared = SoftwareExecutorKind::ALL
            .into_iter()
            .filter_map(|kind| Some((kind, Arc::from(software_executor_for(kind)?))))
            .collect();
        Self {
            default_kind: Some(SoftwareExecutorKind::Shell),
            default: None,
            declared,
            host: match crate::host_executor::HostExecutor::from_env() {
                Ok(Some(host)) => host
                    .check_ready()
                    .map(|()| Arc::new(host))
                    .map_err(|error| format!("{error:#}")),
                Ok(None) => Err(host_not_configured()),
                Err(error) => Err(format!("{error:#}")),
            },
            process_default_error: None,
        }
    }

    /// `/readyz` token for the process default, for example
    /// `software_executor:shell`. `fake` when the default is the unnamed test
    /// adapter. Absent when the configured default was refused.
    pub fn readiness_token(&self) -> Option<String> {
        if self.process_default_error.is_some() {
            return None;
        }
        Some(format!(
            "software_executor:{}",
            self.default_kind
                .map_or("fake", SoftwareExecutorKind::as_str)
        ))
    }

    /// An unnamed default adapter (a test fake) and no declared adapters.
    pub fn with_default(default: Arc<dyn SoftwareExecutor>) -> Self {
        Self {
            default_kind: None,
            default: Some(default),
            declared: Vec::new(),
            host: Err(host_not_configured()),
            process_default_error: None,
        }
    }

    /// Run releases that declare `kind` with `adapter`, replacing any earlier
    /// one. Ignored for `shell`, which always keeps the `deploy.install` path,
    /// and for `host`, which runs only through [`Self::with_host`].
    pub fn with_adapter(
        mut self,
        kind: SoftwareExecutorKind,
        adapter: Arc<dyn SoftwareExecutor>,
    ) -> Self {
        self.declared.retain(|(existing, _)| *existing != kind);
        if !matches!(
            kind,
            SoftwareExecutorKind::Shell | SoftwareExecutorKind::Host
        ) {
            self.declared.push((kind, adapter));
        }
        self
    }

    /// Run `host` releases with `host`, replacing any earlier one.
    pub fn with_host(mut self, host: Arc<crate::host_executor::HostExecutor>) -> Self {
        self.host = Ok(host);
        self
    }

    /// The host executor, or an error naming what is missing.
    pub fn host(&self) -> Result<&Arc<crate::host_executor::HostExecutor>> {
        self.host.as_ref().map_err(|reason| {
            anyhow::anyhow!(
                "release declares deploy.executor = \"host\", and the host executor is not available in this process: {reason}"
            )
        })
    }

    /// Fail closed unless a release that declares `declared` can run here.
    pub fn require_available(&self, declared: Option<SoftwareExecutorKind>) -> Result<()> {
        if declared == Some(SoftwareExecutorKind::Host) {
            return self.host().map(|_| ());
        }
        self.resolve(declared).map(|_| ())
    }

    /// The kind a release with `declared` runs as here. Compare these, never
    /// the written text: `k8s` and `kubernetes` are the same executor.
    pub fn effective_kind(
        &self,
        declared: Option<SoftwareExecutorKind>,
    ) -> Option<SoftwareExecutorKind> {
        declared.or(self.default_kind)
    }

    /// The adapter for a release with `declared`; `None` is the shell
    /// `deploy.install` path. A declared executor this process lacks is an
    /// error naming it. `host` releases have no adapter: they run only as
    /// host plan steps, so asking for one is an error.
    pub fn resolve(
        &self,
        declared: Option<SoftwareExecutorKind>,
    ) -> Result<Option<Arc<dyn SoftwareExecutor>>> {
        let Some(kind) = declared else {
            if let Some(error) = &self.process_default_error {
                bail!("{error}");
            }
            return Ok(self.default.clone());
        };
        if kind == SoftwareExecutorKind::Shell {
            return Ok(None);
        }
        if kind == SoftwareExecutorKind::Host {
            self.host()?;
            bail!("host releases run only as host plan steps through the root-side applier");
        }
        if let Some((_, adapter)) = self.declared.iter().find(|(existing, _)| *existing == kind) {
            return Ok(Some(adapter.clone()));
        }
        bail!(
            "release declares deploy.executor = \"{kind}\", and that executor is not installed in this process"
        )
    }

    /// Refuse to move `product` from its installed release's executor to
    /// another. Moving executors is a remove followed by an install.
    pub fn require_same_executor(
        &self,
        product: &str,
        installed: Option<SoftwareExecutorKind>,
        target: Option<SoftwareExecutorKind>,
    ) -> Result<()> {
        let (installed, target) = (self.effective_kind(installed), self.effective_kind(target));
        if installed != target {
            let name = |kind: Option<SoftwareExecutorKind>| {
                kind.map_or("fake", SoftwareExecutorKind::as_str)
            };
            bail!(
                "{product} is installed with the {} executor and the target release resolves to {}; a product keeps one executor, so remove it and install it again to change executor",
                name(installed),
                name(target)
            );
        }
        Ok(())
    }
}

impl std::fmt::Debug for SoftwareExecutors {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoftwareExecutors")
            .field("default_kind", &self.default_kind)
            .field("default", &self.default.is_some())
            .field(
                "declared",
                &self
                    .declared
                    .iter()
                    .map(|(kind, _)| *kind)
                    .collect::<Vec<_>>(),
            )
            .field("host", &self.host.as_ref().ok())
            .field("process_default_error", &self.process_default_error)
            .finish()
    }
}

/// Select a software executor from host runtime configuration.
///
/// Reads `TENKAI_SOFTWARE_EXECUTOR` (a [`SoftwareExecutorKind`] name, or `fake`).
/// `None` means the caller should keep the shell `deploy.install` path. An
/// unknown name or a missing adapter is also `None`; hosts that must refuse
/// those values call [`SoftwareExecutors::try_from_process`].
pub fn selected_software_executor() -> Option<Box<dyn SoftwareExecutor>> {
    let value = std::env::var("TENKAI_SOFTWARE_EXECUTOR").ok()?;
    if value.eq_ignore_ascii_case("fake") {
        return Some(Box::new(FakeSoftwareExecutor::new()));
    }
    software_executor_for(SoftwareExecutorKind::from_name(&value)?)
}

/// Process default kind and adapter. `None` kind is the unnamed `fake`
/// adapter; `None` adapter is the shell path.
type ProcessDefault = (
    Option<SoftwareExecutorKind>,
    Option<Arc<dyn SoftwareExecutor>>,
);

/// Process default for `TENKAI_SOFTWARE_EXECUTOR`. `None` is unset: the shell
/// path. `shell` is the same path. `fake` is the unnamed test adapter. Any
/// other unknown name, `host`, or a known adapter this process did not
/// install is an error; it never becomes shell.
fn process_default_from_value(value: Option<&str>) -> Result<ProcessDefault> {
    let Some(value) = value else {
        return Ok((Some(SoftwareExecutorKind::Shell), None));
    };
    if value.eq_ignore_ascii_case("fake") {
        return Ok((None, Some(Arc::new(FakeSoftwareExecutor::new()))));
    }
    let kind = SoftwareExecutorKind::from_name(value).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown software executor {value:?}; expected one of {SOFTWARE_EXECUTOR_NAME_HINT}"
        )
    })?;
    if kind == SoftwareExecutorKind::Shell {
        return Ok((Some(kind), None));
    }
    if kind == SoftwareExecutorKind::Host {
        bail!(
            "TENKAI_SOFTWARE_EXECUTOR is set to \"host\", and that executor is not a process default"
        );
    }
    match software_executor_for(kind) {
        Some(adapter) => Ok((Some(kind), Some(Arc::from(adapter)))),
        None => bail!(
            "TENKAI_SOFTWARE_EXECUTOR is set to \"{kind}\", and that executor is not installed in this process"
        ),
    }
}

fn request_key(request: &SoftwareApplyRequest) -> String {
    let mut key = if request.config_digest.is_empty() {
        format!(
            "{}|{}|{}|{}",
            request.environment,
            request.product,
            request.instance_name(),
            request.version
        )
    } else {
        format!(
            "{}|{}|{}|{}|{}",
            request.environment,
            request.product,
            request.instance_name(),
            request.version,
            request.config_digest
        )
    };
    if !request.dependency_document.is_empty() {
        key.push('|');
        key.push_str(&crate::dependency_document::digest_json(
            &request.dependency_document,
        ));
    }
    key
}

pub fn validate_request(request: &SoftwareApplyRequest) -> Result<()> {
    for (label, value) in [
        ("product", request.product.as_str()),
        ("version", request.version.as_str()),
        ("environment", request.environment.as_str()),
    ] {
        if value.trim().is_empty() {
            bail!("software apply {label} must not be empty");
        }
        if value.contains('/') || value.contains('\\') || value.contains('\0') {
            bail!("software apply {label} must not contain path separators or NULs");
        }
    }
    // Empty instance means the product, already checked above.
    if !request.instance.is_empty()
        && (request.instance.contains('/')
            || request.instance.contains('\\')
            || request.instance.contains('\0'))
    {
        bail!("software apply instance must not contain path separators or NULs");
    }
    Ok(())
}

/// Build a request from release content fields (library helper).
pub fn request_from_parts(
    product: impl Into<String>,
    version: impl Into<String>,
    environment: impl Into<String>,
    workdir: impl AsRef<Path>,
    release_id: impl Into<String>,
) -> SoftwareApplyRequest {
    SoftwareApplyRequest {
        product: product.into(),
        instance: String::new(),
        version: version.into(),
        environment: environment.into(),
        workdir: workdir.as_ref().to_path_buf(),
        release_id: release_id.into(),
        overlays: BTreeMap::new(),
        config_digest: String::new(),
        artifact_pulls: Vec::new(),
        cluster_config_path: None,
        secret_dir_path: None,
        apply_attempt: uuid::Uuid::new_v4().simple().to_string(),
        dependency_document: String::new(),
        opened_secrets: Vec::new(),
    }
}

/// Attach non-secret overlays to a software apply request.
pub fn with_overlays(
    mut request: SoftwareApplyRequest,
    overlays: BTreeMap<String, String>,
) -> SoftwareApplyRequest {
    request.config_digest = crate::environment::overlay_digest(&overlays);
    request.overlays = overlays;
    request
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(root: &Path) -> SoftwareApplyRequest {
        std::fs::create_dir_all(root).unwrap();
        SoftwareApplyRequest {
            product: "api".into(),
            instance: String::new(),
            version: "1.0.0".into(),
            environment: "prod".into(),
            workdir: root.to_path_buf(),
            release_id: "tenkai:release:api@1.0.0".into(),
            overlays: BTreeMap::new(),
            config_digest: String::new(),
            artifact_pulls: Vec::new(),
            cluster_config_path: None,
            secret_dir_path: None,
            apply_attempt: String::new(),
            dependency_document: String::new(),
            opened_secrets: Vec::new(),
        }
    }

    #[test]
    fn fake_apply_remove_and_observe() {
        let root = std::env::temp_dir().join(format!("tenkai-soft-{}", uuid::Uuid::new_v4()));
        let request = sample_request(&root);
        let executor = FakeSoftwareExecutor::new();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Absent
        );
        executor.apply(&request).unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        executor.remove(&request).unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Absent
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fake_fail_apply_is_actionable() {
        let root = std::env::temp_dir().join(format!("tenkai-soft-fail-{}", uuid::Uuid::new_v4()));
        let request = sample_request(&root);
        let executor = FakeSoftwareExecutor::new().with_fail_apply(true);
        let err = executor.apply(&request).unwrap_err().to_string();
        assert!(err.contains("refused apply"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_path_injection_in_product() {
        let root = std::env::temp_dir().join(format!("tenkai-soft-bad-{}", uuid::Uuid::new_v4()));
        let mut request = sample_request(&root);
        request.product = "../evil".into();
        assert!(FakeSoftwareExecutor::new().apply(&request).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn executor_names_round_trip_and_reject_fake() {
        for kind in SoftwareExecutorKind::ALL {
            assert_eq!(SoftwareExecutorKind::from_name(kind.as_str()), Some(kind));
            assert_eq!(
                SoftwareExecutorKind::from_name(&kind.as_str().to_ascii_uppercase()),
                Some(kind)
            );
        }
        assert_eq!(
            SoftwareExecutorKind::from_name("K8s"),
            Some(SoftwareExecutorKind::Kubernetes)
        );
        let err = "fake".parse::<SoftwareExecutorKind>().unwrap_err();
        assert!(err.to_string().contains("\"fake\""), "{err}");
    }

    #[test]
    fn a_declared_executor_resolves_to_its_adapter_or_fails_closed() {
        let default: Arc<dyn SoftwareExecutor> = Arc::new(FakeSoftwareExecutor::new());
        let helm: Arc<dyn SoftwareExecutor> = Arc::new(FakeSoftwareExecutor::new());
        let executors = SoftwareExecutors::with_default(default.clone());
        let resolved = executors.resolve(None).unwrap().unwrap();
        assert!(Arc::ptr_eq(&resolved, &default));
        // A declared shell never runs on a non-shell default.
        assert!(
            executors
                .resolve(Some(SoftwareExecutorKind::Shell))
                .unwrap()
                .is_none()
        );
        let err = match executors.resolve(Some(SoftwareExecutorKind::Helm)) {
            Ok(_) => panic!("an uninstalled helm fell back"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("\"helm\""), "{err}");
        let executors = executors.with_adapter(SoftwareExecutorKind::Helm, helm.clone());
        let resolved = executors
            .resolve(Some(SoftwareExecutorKind::Helm))
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(&resolved, &helm));
    }

    #[test]
    fn same_executor_compares_resolved_kinds() {
        use SoftwareExecutorKind::{KubernetesInProcess, Shell};
        let shell_default = SoftwareExecutors::default();
        // Undeclared runs on the shell default, so declaring shell is no change.
        shell_default
            .require_same_executor("api", None, Some(Shell))
            .unwrap();
        let err = shell_default
            .require_same_executor("api", None, Some(KubernetesInProcess))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("api is installed with the shell executor")
                && err.contains("resolves to kubernetes-inprocess"),
            "{err}"
        );
        let fake_default = SoftwareExecutors::with_default(Arc::new(FakeSoftwareExecutor::new()));
        fake_default
            .require_same_executor("api", None, None)
            .unwrap();
        assert!(
            fake_default
                .require_same_executor("api", None, Some(Shell))
                .is_err()
        );
    }

    #[test]
    fn selected_executor_defaults_to_none() {
        // When operator env is unset, shell path remains default.
        if std::env::var_os("TENKAI_SOFTWARE_EXECUTOR").is_none() {
            assert!(selected_software_executor().is_none());
        }
    }

    #[test]
    fn process_default_is_shell_only_when_unset_or_named_shell() {
        let (kind, adapter) = process_default_from_value(None).unwrap();
        assert_eq!(kind, Some(SoftwareExecutorKind::Shell));
        assert!(adapter.is_none());
        let (kind, adapter) = process_default_from_value(Some("shell")).unwrap();
        assert_eq!(kind, Some(SoftwareExecutorKind::Shell));
        assert!(adapter.is_none());
        let (kind, adapter) = process_default_from_value(Some("SHELL")).unwrap();
        assert_eq!(kind, Some(SoftwareExecutorKind::Shell));
        assert!(adapter.is_none());
        let (kind, adapter) = process_default_from_value(Some("fake")).unwrap();
        assert_eq!(kind, None);
        assert!(adapter.is_some());
    }

    #[test]
    fn process_default_refuses_unknown_uninstalled_and_host() {
        let err = match process_default_from_value(Some("kuberntes-inprocess")) {
            Ok(_) => panic!("a typo became a process default"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("unknown software executor \"kuberntes-inprocess\"")
                && err.contains("kubernetes-inprocess"),
            "{err}"
        );
        let err = match process_default_from_value(Some("kubernetes-inprocess")) {
            Ok(_) => panic!("uninstalled kubernetes-inprocess became a process default"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("TENKAI_SOFTWARE_EXECUTOR is set to \"kubernetes-inprocess\"")
                && err.contains("not installed in this process"),
            "{err}"
        );
        let err = match process_default_from_value(Some("helm")) {
            Ok(_) => panic!("uninstalled helm became a process default"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("TENKAI_SOFTWARE_EXECUTOR is set to \"helm\"")
                && err.contains("not installed in this process"),
            "{err}"
        );
        let err = match process_default_from_value(Some("host")) {
            Ok(_) => panic!("host became a process default"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("TENKAI_SOFTWARE_EXECUTOR is set to \"host\"")
                && err.contains("not a process default"),
            "{err}"
        );
    }

    #[test]
    fn undeclared_resolve_fails_closed_when_the_process_default_was_refused() {
        let executors = SoftwareExecutors {
            process_default_error: Some(
                "TENKAI_SOFTWARE_EXECUTOR is set to \"helm\", and that executor is not installed in this process"
                    .into(),
            ),
            ..SoftwareExecutors::default()
        };
        let err = match executors.resolve(None) {
            Ok(_) => panic!("an invalid process default fell back to shell"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("\"helm\"") && err.contains("not installed in this process"),
            "{err}"
        );
        assert!(
            executors
                .resolve(Some(SoftwareExecutorKind::Shell))
                .unwrap()
                .is_none()
        );
        assert_eq!(executors.readiness_token(), None);
        assert_eq!(
            SoftwareExecutors::default().readiness_token().as_deref(),
            Some("software_executor:shell")
        );
    }

    #[test]
    fn lists_manifests_sorted_and_rejects_missing_dir() {
        let root = std::env::temp_dir().join(format!("tenkai-mf-{}", uuid::Uuid::new_v4()));
        let manifests = root.join(KUBERNETES_MANIFESTS_DIR);
        std::fs::create_dir_all(manifests.join("nested")).unwrap();
        std::fs::write(manifests.join("b-deploy.yaml"), "apiVersion: v1\n").unwrap();
        std::fs::write(manifests.join("a-ns.yaml"), "apiVersion: v1\n").unwrap();
        std::fs::write(manifests.join("nested").join("c.yaml"), "apiVersion: v1\n").unwrap();
        std::fs::write(manifests.join("readme.txt"), "skip").unwrap();
        let files = list_manifest_files(&manifests).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a-ns.yaml", "b-deploy.yaml", "c.yaml"]);
        assert!(kubernetes_manifests_dir(&root.join("nope")).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn instance_placeholder_and_default_name() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-instance-req-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut request = sample_request(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(request.instance_name(), "api");
        request.instance = "db-a".into();
        assert_eq!(request.instance_name(), "db-a");
        assert_eq!(
            substitute_instance_placeholder("name: ${TENKAI_INSTANCE}\nkeep: ${OTHER}", "db-a"),
            "name: db-a\nkeep: ${OTHER}"
        );
        let selector = instance_selector(&request);
        assert!(selector.contains("tenkai.instance=db-a"), "{selector}");
        assert!(selector.contains("tenkai.product=api"), "{selector}");
        request.instance = "db/a".into();
        let err = validate_request(&request).unwrap_err().to_string();
        assert!(err.contains("instance"), "{err}");
    }

    #[test]
    fn k8s_label_value_sanitizes_release_ids() {
        assert_eq!(
            k8s_label_value("tenkai:release:api@1.0.0"),
            "tenkai-release-api-1.0.0"
        );
        assert_eq!(k8s_label_value("---"), "unknown");
    }

    #[test]
    fn phase_error_names_health_and_product_without_secrets() {
        let err = format_software_phase_error(
            SoftwareDeployPhase::Health,
            "hello-minikube",
            "0.2.0",
            "local",
            "error: rollout timed out; Bearer super-secret-token-value",
        );
        assert!(err.contains("phase=health"), "{err}");
        assert!(err.contains("hello-minikube@0.2.0"), "{err}");
        assert!(err.contains("environment/namespace=local"), "{err}");
        assert!(!err.contains("super-secret-token-value"), "{err}");
        assert!(err.contains("[redacted]"), "{err}");
        let long = format_software_phase_error(
            SoftwareDeployPhase::Apply,
            "api",
            "1.0.0",
            "stage",
            "token=abcdefghijklmnopqrstuvwxyz0123456789extra",
        );
        assert!(!long.contains("abcdefghij"), "{long}");
        assert!(long.contains("[redacted]"), "{long}");
        let json_secret = sanitize_diagnostic_text(
            r#"Error from server: {"kind": "Secret", "data": {"api-key": "supersecret"}}"#,
        );
        assert!(
            json_secret.contains("omitted") || json_secret.contains("secret"),
            "{json_secret}"
        );
        assert!(!json_secret.contains("supersecret"), "{json_secret}");
        let auth = sanitize_diagnostic_text("Authorization: Bearer super-secret-token\nnext");
        assert!(!auth.contains("super-secret-token"), "{auth}");
        assert!(auth.contains("[redacted]"), "{auth}");
        // JSON, query-string, env-style, and camelCase credential carriers (#150 / autoreview).
        for sample in [
            r#"error: {"token":"json-secret-value"}"#,
            r#"error: {"token": "json-secret-value"}"#,
            "client_secret=query-secret-value",
            "access_token=query-secret-value",
            "api_key=query-secret-value",
            "api-key: query-secret-value",
            r#"{"access_token":"json-secret-value","ok":true}"#,
            "AWS_SECRET_ACCESS_KEY=query-secret-value",
            "clientSecret=query-secret-value",
            "private-key-data=query-secret-value",
            "credentials=query-secret-value",
            r#"{"clientSecret":"json-secret-value"}"#,
        ] {
            let cleaned = sanitize_diagnostic_text(sample);
            assert!(
                !cleaned.contains("json-secret-value") && !cleaned.contains("query-secret-value"),
                "leaked secret in {sample:?} -> {cleaned}"
            );
            assert!(cleaned.contains("[redacted]"), "{sample:?} -> {cleaned}");
        }
        // Non-credential assignment must survive (operator-useful kubectl text).
        let safe = sanitize_diagnostic_text(
            "error: deployment.apps \"hello\" not found in namespace=local",
        );
        assert!(safe.contains("not found"), "{safe}");
        assert!(
            safe.contains("namespace=local") || safe.contains("namespace"),
            "{safe}"
        );
        // Escaped quotes inside a credential value must not leak the tail.
        let escaped = sanitize_diagnostic_text(r#"{"token":"prefix\"remaining-secret"}"#);
        assert!(!escaped.contains("remaining-secret"), "{escaped}");
        assert!(escaped.contains("[redacted]"), "{escaped}");
    }

    #[test]
    fn rollback_note_mentions_channel_unchanged() {
        let note = rollback_channel_note("api", "1.0.0");
        assert!(note.contains("restored api to 1.0.0"), "{note}");
        assert!(note.contains("channel head is unchanged"), "{note}");
    }

    #[test]
    fn k8s_label_values_start_and_end_alphanumeric() {
        assert_eq!(super::k8s_label_value("model_"), "model");
        assert_eq!(super::k8s_label_value("1.0."), "1.0");
        assert_eq!(super::k8s_label_value("_.-"), "unknown");
        let long = format!("{}_tail", "a".repeat(62));
        let value = super::k8s_label_value(&long);
        assert!(value.len() <= 63 && value.ends_with('a'), "{value}");
    }
}
