//! Software product apply ports (Kubernetes via Helm or native manifests).
//!
//! **Helm (#95):** chart-oriented `helm upgrade --install` when
//! `TENKAI_SOFTWARE_EXECUTOR=helm`.
//!
//! **Native Kubernetes (#105):** plain multi-doc YAML under `manifests/` via
//! `kubectl` argv (not Helm). Chosen over an in-process kube client for this
//! issue to keep zero new crate dependencies and match the external-binary
//! pattern used for Helm; an in-process client remains a valid follow-on.
//!
//! Community defaults keep the existing shell `deploy.install` path when no
//! software executor env is set.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

/// Request to apply or remove a software product generation on one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareApplyRequest {
    pub product: String,
    pub version: String,
    pub environment: String,
    pub workdir: PathBuf,
    /// Optional release digest for audit (never a secret).
    pub release_id: String,
}

/// Pluggable software apply path. Tenkai never hard-depends on a cluster.
pub trait SoftwareExecutor: Send + Sync {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()>;
    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()>;
    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareObserveStatus {
    Absent,
    Present,
    Unknown,
}

/// Deterministic fake for CI (no cluster, no helm binary).
#[derive(Debug, Default)]
pub struct FakeSoftwareExecutor {
    applied: Mutex<Vec<String>>,
    fail_apply: bool,
}

impl FakeSoftwareExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_fail_apply(mut self, fail: bool) -> Self {
        self.fail_apply = fail;
        self
    }

    pub fn applied_keys(&self) -> Vec<String> {
        self.applied.lock().expect("fake software mutex").clone()
    }
}

impl SoftwareExecutor for FakeSoftwareExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
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

/// Helm reference launcher (`helm upgrade --install` / `helm uninstall`).
///
/// Binary from `TENKAI_HELM_BIN` or `helm` on PATH. Namespace = environment
/// name (validated identifier). Chart path = product workdir.
#[derive(Debug, Clone)]
pub struct HelmSoftwareExecutor {
    pub helm_binary: PathBuf,
}

impl Default for HelmSoftwareExecutor {
    fn default() -> Self {
        let helm_binary = std::env::var_os("TENKAI_HELM_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("helm"));
        Self { helm_binary }
    }
}

impl SoftwareExecutor for HelmSoftwareExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        if !request.workdir.is_dir() {
            bail!(
                "helm chart workdir does not exist: {}",
                request.workdir.display()
            );
        }
        let status = Command::new(&self.helm_binary)
            .arg("upgrade")
            .arg("--install")
            .arg(&request.product)
            .arg(&request.workdir)
            .arg("--namespace")
            .arg(&request.environment)
            .arg("--create-namespace")
            .arg("--wait")
            .arg("--timeout")
            .arg("5m")
            .arg("--set")
            .arg(format!("tenkai.version={}", request.version))
            .arg("--set")
            .arg(format!("tenkai.releaseId={}", request.release_id))
            .status()
            .with_context(|| {
                format!(
                    "starting helm via {} (set TENKAI_HELM_BIN or install helm)",
                    self.helm_binary.display()
                )
            })?;
        if !status.success() {
            bail!(
                "helm upgrade --install failed for {} in namespace {} (status {status})",
                request.product,
                request.environment
            );
        }
        Ok(())
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let status = Command::new(&self.helm_binary)
            .arg("uninstall")
            .arg(&request.product)
            .arg("--namespace")
            .arg(&request.environment)
            .arg("--wait")
            .status()
            .with_context(|| {
                format!("starting helm uninstall via {}", self.helm_binary.display())
            })?;
        if !status.success() {
            // Not found may still be non-zero depending on helm version; surface error.
            bail!(
                "helm uninstall failed for {} in namespace {} (status {status})",
                request.product,
                request.environment
            );
        }
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let output = Command::new(&self.helm_binary)
            .arg("status")
            .arg(&request.product)
            .arg("--namespace")
            .arg(&request.environment)
            .output()
            .with_context(|| format!("starting helm status via {}", self.helm_binary.display()))?;
        if output.status.success() {
            Ok(SoftwareObserveStatus::Present)
        } else {
            Ok(SoftwareObserveStatus::Absent)
        }
    }
}

/// Directory under the release workdir that holds native Kubernetes manifests.
pub const KUBERNETES_MANIFESTS_DIR: &str = "manifests";

/// Native Kubernetes apply via `kubectl` (plain manifests, not Helm charts).
///
/// Binary from `TENKAI_KUBECTL_BIN` or `kubectl` on PATH. Namespace = environment
/// name. Manifests live in `{workdir}/manifests/**/*.{yaml,yml}` (sorted).
#[derive(Debug, Clone)]
pub struct KubernetesSoftwareExecutor {
    pub kubectl_binary: PathBuf,
}

impl Default for KubernetesSoftwareExecutor {
    fn default() -> Self {
        let kubectl_binary = std::env::var_os("TENKAI_KUBECTL_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("kubectl"));
        Self { kubectl_binary }
    }
}

impl SoftwareExecutor for KubernetesSoftwareExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        if files.is_empty() {
            bail!(
                "native kubernetes apply requires at least one .yaml/.yml under {}",
                manifests.display()
            );
        }
        ensure_namespace(self, &request.environment)?;
        for path in &files {
            let status = Command::new(&self.kubectl_binary)
                .arg("apply")
                .arg("-f")
                .arg(path)
                .arg("--namespace")
                .arg(&request.environment)
                .status()
                .with_context(|| {
                    format!(
                        "starting kubectl apply via {} (set TENKAI_KUBECTL_BIN or install kubectl)",
                        self.kubectl_binary.display()
                    )
                })?;
            if !status.success() {
                bail!(
                    "kubectl apply failed for {} in namespace {} (file {}, status {status})",
                    request.product,
                    request.environment,
                    path.display()
                );
            }
        }
        // Ownership labels for Tenkai correlation (values sanitized for k8s).
        let label_args = ownership_label_args(request);
        let status = Command::new(&self.kubectl_binary)
            .arg("label")
            .arg("--overwrite")
            .arg("-f")
            .arg(&manifests)
            .arg("--recursive")
            .arg("--namespace")
            .arg(&request.environment)
            .args(&label_args)
            .status()
            .with_context(|| {
                format!(
                    "starting kubectl label via {}",
                    self.kubectl_binary.display()
                )
            })?;
        if !status.success() {
            bail!(
                "kubectl label failed for {} in namespace {} after apply (status {status})",
                request.product,
                request.environment
            );
        }
        Ok(())
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        if files.is_empty() {
            bail!(
                "native kubernetes remove requires manifests under {}",
                manifests.display()
            );
        }
        // Delete in reverse order for safer teardown of dependent resources.
        for path in files.iter().rev() {
            let status = Command::new(&self.kubectl_binary)
                .arg("delete")
                .arg("-f")
                .arg(path)
                .arg("--namespace")
                .arg(&request.environment)
                .arg("--ignore-not-found=true")
                .arg("--wait=true")
                .status()
                .with_context(|| {
                    format!(
                        "starting kubectl delete via {}",
                        self.kubectl_binary.display()
                    )
                })?;
            if !status.success() {
                bail!(
                    "kubectl delete failed for {} in namespace {} (file {}, status {status})",
                    request.product,
                    request.environment,
                    path.display()
                );
            }
        }
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        if files.is_empty() {
            return Ok(SoftwareObserveStatus::Unknown);
        }
        // Present only if every manifest file still resolves in the namespace.
        for path in &files {
            let output = Command::new(&self.kubectl_binary)
                .arg("get")
                .arg("-f")
                .arg(path)
                .arg("--namespace")
                .arg(&request.environment)
                .output()
                .with_context(|| {
                    format!("starting kubectl get via {}", self.kubectl_binary.display())
                })?;
            if !output.status.success() {
                return Ok(SoftwareObserveStatus::Absent);
            }
        }
        Ok(SoftwareObserveStatus::Present)
    }
}

fn kubernetes_manifests_dir(workdir: &Path) -> Result<PathBuf> {
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

fn ensure_namespace(executor: &KubernetesSoftwareExecutor, namespace: &str) -> Result<()> {
    let get = Command::new(&executor.kubectl_binary)
        .arg("get")
        .arg("namespace")
        .arg(namespace)
        .status()
        .with_context(|| {
            format!(
                "checking namespace via {}",
                executor.kubectl_binary.display()
            )
        })?;
    if get.success() {
        return Ok(());
    }
    let create = Command::new(&executor.kubectl_binary)
        .arg("create")
        .arg("namespace")
        .arg(namespace)
        .status()
        .with_context(|| {
            format!(
                "creating namespace via {}",
                executor.kubectl_binary.display()
            )
        })?;
    if !create.success() {
        bail!(
            "kubectl create namespace {namespace} failed (status {create}); create it or fix kubeconfig"
        );
    }
    Ok(())
}

fn ownership_label_args(request: &SoftwareApplyRequest) -> Vec<String> {
    vec![
        format!("tenkai.product={}", k8s_label_value(&request.product)),
        format!("tenkai.version={}", k8s_label_value(&request.version)),
        format!("tenkai.release-id={}", k8s_label_value(&request.release_id)),
    ]
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
    let trimmed = mapped.trim_matches('-');
    if trimmed.is_empty() {
        "unknown".into()
    } else {
        // Label values max 63 chars.
        trimmed.chars().take(63).collect()
    }
}

/// Select software executor from `TENKAI_SOFTWARE_EXECUTOR`, else None
/// (caller keeps shell install).
pub fn selected_software_executor() -> Option<Box<dyn SoftwareExecutor>> {
    match std::env::var("TENKAI_SOFTWARE_EXECUTOR") {
        Ok(value) if value.eq_ignore_ascii_case("helm") => {
            Some(Box::new(HelmSoftwareExecutor::default()))
        }
        Ok(value)
            if value.eq_ignore_ascii_case("kubernetes")
                || value.eq_ignore_ascii_case("k8s")
                || value.eq_ignore_ascii_case("native") =>
        {
            Some(Box::new(KubernetesSoftwareExecutor::default()))
        }
        Ok(value) if value.eq_ignore_ascii_case("fake") => {
            Some(Box::new(FakeSoftwareExecutor::new()))
        }
        _ => None,
    }
}

fn request_key(request: &SoftwareApplyRequest) -> String {
    format!(
        "{}|{}|{}",
        request.environment, request.product, request.version
    )
}

fn validate_request(request: &SoftwareApplyRequest) -> Result<()> {
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
    }
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
    fn kubernetes_apply_requires_manifests_directory() {
        let root = std::env::temp_dir().join(format!("tenkai-k8s-empty-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let request = sample_request(&root);
        let executor = KubernetesSoftwareExecutor {
            kubectl_binary: PathBuf::from("kubectl-not-used-before-manifest-check"),
        };
        let err = executor.apply(&request).unwrap_err().to_string();
        assert!(err.contains("manifests"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Optional live-cluster path. Not run in default CI.
    #[test]
    #[ignore = "requires kubectl + cluster; set TENKAI_KUBECTL_BIN and run with --ignored"]
    fn kubernetes_operator_kind_path_smoke() {
        let binary = std::env::var("TENKAI_KUBECTL_BIN").unwrap_or_else(|_| "kubectl".into());
        let root = std::env::temp_dir().join(format!("tenkai-k8s-live-{}", uuid::Uuid::new_v4()));
        let manifests = root.join(KUBERNETES_MANIFESTS_DIR);
        std::fs::create_dir_all(&manifests).unwrap();
        // Minimal ConfigMap — safe for a disposable namespace.
        std::fs::write(
            manifests.join("configmap.yaml"),
            r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: tenkai-smoke
data:
  ok: "1"
"#,
        )
        .unwrap();
        let request = SoftwareApplyRequest {
            product: "smoke".into(),
            version: "0.0.1".into(),
            environment: format!("tenkai-smoke-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            workdir: root.clone(),
            release_id: "tenkai:release:smoke@0.0.1".into(),
        };
        let executor = KubernetesSoftwareExecutor {
            kubectl_binary: PathBuf::from(binary),
        };
        executor.apply(&request).expect("apply");
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        executor.remove(&request).expect("remove");
        let _ = std::fs::remove_dir_all(root);
    }
}
