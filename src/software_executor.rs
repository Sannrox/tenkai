//! Software product apply ports (Kubernetes via Helm reference).
//!
//! **Strategy for #95:** Helm is the first reference path because:
//! - chart packaging is the common unit for cluster software;
//! - `helm upgrade --install` is argv-only (no shell);
//! - it does not require Argo CD for Tenkai to own plan/rollback;
//! - Argo remains a valid future backend without replacing this port.
//!
//! Native client and Argo-as-backend are non-goals of this reference. Community
//! defaults keep the existing shell `deploy.install` path when Helm is unset.

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

/// Select software executor: helm when `TENKAI_SOFTWARE_EXECUTOR=helm`, else None
/// (caller keeps shell install).
pub fn selected_software_executor() -> Option<Box<dyn SoftwareExecutor>> {
    match std::env::var("TENKAI_SOFTWARE_EXECUTOR") {
        Ok(value) if value.eq_ignore_ascii_case("helm") => {
            Some(Box::new(HelmSoftwareExecutor::default()))
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
}
