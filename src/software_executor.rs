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
//! Hosts call `tenkai_executor::install()` then [`selected_software_executor`].
//! Community defaults keep the shell `deploy.install` path when no executor is
//! supplied. Credential-free diagnostics live in the diagnostics module.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
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
}

/// Pluggable software apply path. Tenkai never hard-depends on a cluster.
pub trait SoftwareExecutor: Send + Sync {
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

/// Select a software executor from host runtime configuration.
///
/// Reads `TENKAI_SOFTWARE_EXECUTOR` (helm / kubernetes / kubernetes-inprocess / docker / fake). `None` means
/// the caller should keep the shell `deploy.install` path. Apply does not
/// consult this itself; hosts pass the result through `ExecutionOptions`.
pub fn selected_software_executor() -> Option<Box<dyn SoftwareExecutor>> {
    match std::env::var("TENKAI_SOFTWARE_EXECUTOR") {
        Ok(value) if value.eq_ignore_ascii_case("helm") => {
            HELM_EXECUTOR.get().map(|factory| factory())
        }
        Ok(value) if value.eq_ignore_ascii_case("docker") => {
            DOCKER_EXECUTOR.get().map(|factory| factory())
        }
        Ok(value)
            if value.eq_ignore_ascii_case("kubernetes")
                || value.eq_ignore_ascii_case("k8s")
                || value.eq_ignore_ascii_case("native") =>
        {
            KUBERNETES_EXECUTOR.get().map(|factory| factory())
        }
        Ok(value) if value.eq_ignore_ascii_case("fake") => {
            Some(Box::new(FakeSoftwareExecutor::new()))
        }
        Ok(value) if value.eq_ignore_ascii_case("kubernetes-inprocess") => {
            IN_PROCESS_EXECUTOR.get().map(|factory| factory())
        }
        _ => None,
    }
}

fn request_key(request: &SoftwareApplyRequest) -> String {
    if request.config_digest.is_empty() {
        format!(
            "{}|{}|{}",
            request.environment, request.product, request.version
        )
    } else {
        format!(
            "{}|{}|{}|{}",
            request.environment, request.product, request.version, request.config_digest
        )
    }
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
    fn selected_executor_defaults_to_none() {
        // When operator env is unset, shell path remains default.
        if std::env::var_os("TENKAI_SOFTWARE_EXECUTOR").is_none() {
            assert!(selected_software_executor().is_none());
        }
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
