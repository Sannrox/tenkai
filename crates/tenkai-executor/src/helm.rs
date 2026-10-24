//! Helm CLI software-executor adapter (`helm upgrade --install` / `helm uninstall`).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use tenkai::now_millis;
use tenkai::software_executor::{
    SoftwareApplyRequest, SoftwareDeployPhase, SoftwareExecutor, SoftwareObserveStatus,
    run_captured_command, validate_request,
};

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

impl HelmSoftwareExecutor {
    fn helm_upgrade(
        &self,
        request: &SoftwareApplyRequest,
        phase: SoftwareDeployPhase,
        label: &str,
        extra_sets: &[String],
    ) -> Result<()> {
        validate_request(request)?;
        if !request.workdir.is_dir() {
            bail!(
                "helm chart workdir does not exist: {}",
                request.workdir.display()
            );
        }
        let mut command = Command::new(&self.helm_binary);
        command
            .arg("upgrade")
            .arg("--install")
            .arg(&request.product)
            .arg(&request.workdir)
            .arg("--namespace")
            .arg(&request.environment)
            .arg("--create-namespace")
            .arg("--wait")
            .arg("--timeout")
            .arg("5m");
        apply_helm_set_flags(&mut command, request);
        for set in extra_sets {
            command.arg("--set").arg(set);
        }
        run_captured_command(
            &mut command,
            phase,
            label,
            &request.product,
            &request.environment,
            "helm",
            "set TENKAI_HELM_BIN or install helm",
        )
    }
}

impl SoftwareExecutor for HelmSoftwareExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        self.helm_upgrade(
            request,
            SoftwareDeployPhase::Apply,
            "upgrade --install",
            &[],
        )
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let mut command = Command::new(&self.helm_binary);
        command
            .arg("uninstall")
            .arg(&request.product)
            .arg("--namespace")
            .arg(&request.environment)
            .arg("--wait");
        run_captured_command(
            &mut command,
            SoftwareDeployPhase::Remove,
            "uninstall",
            &request.product,
            &request.environment,
            "helm",
            "set TENKAI_HELM_BIN or install helm",
        )
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
        if !output.status.success() {
            return Ok(SoftwareObserveStatus::Absent);
        }
        let values = Command::new(&self.helm_binary)
            .arg("get")
            .arg("values")
            .arg(&request.product)
            .arg("--namespace")
            .arg(&request.environment)
            .arg("--all")
            .arg("-o")
            .arg("json")
            .output();
        let Ok(values) = values else {
            return Ok(SoftwareObserveStatus::Mismatched);
        };
        if !values.status.success() {
            return Ok(SoftwareObserveStatus::Mismatched);
        }
        if helm_values_mismatch(&String::from_utf8_lossy(&values.stdout), request) {
            Ok(SoftwareObserveStatus::Mismatched)
        } else {
            Ok(SoftwareObserveStatus::Present)
        }
    }

    fn restart(&self, request: &SoftwareApplyRequest) -> Result<()> {
        let nonce = now_millis();
        self.helm_upgrade(
            request,
            SoftwareDeployPhase::Restart,
            "upgrade --install --restart",
            &[format!("tenkai.restartNonce={nonce}")],
        )
    }
}

fn apply_helm_set_flags(command: &mut Command, request: &SoftwareApplyRequest) {
    command
        .arg("--set")
        .arg(format!("tenkai.version={}", request.version))
        .arg("--set")
        .arg(format!("tenkai.releaseId={}", request.release_id));
    command
        .arg("--set")
        .arg(format!("tenkai.configDigest={}", request.config_digest));
    for (key, value) in &request.overlays {
        command
            .arg("--set")
            .arg(format!("tenkai.config.{key}={value}"));
    }
}

fn helm_values_mismatch(values_json: &str, request: &SoftwareApplyRequest) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(values_json) else {
        return true;
    };
    let tenkai = value.get("tenkai");
    let version = tenkai
        .and_then(|node| node.get("version"))
        .and_then(|v| v.as_str());
    if version != Some(request.version.as_str()) {
        return true;
    }
    let release_id = tenkai
        .and_then(|node| node.get("releaseId"))
        .and_then(|v| v.as_str());
    if release_id != Some(request.release_id.as_str()) {
        return true;
    }
    let digest = tenkai
        .and_then(|node| node.get("configDigest"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if digest != request.config_digest {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;
    use tenkai::software_executor::{SoftwareApplyRequest, request_from_parts};

    fn sample_request(root: &Path) -> SoftwareApplyRequest {
        std::fs::create_dir_all(root).unwrap();
        let mut request =
            request_from_parts("api", "1.0.0", "prod", root, "tenkai:release:api@1.0.0");
        request.overlays = BTreeMap::new();
        request
    }

    #[test]
    fn helm_apply_captures_and_sanitizes_stderr() {
        let root = std::env::temp_dir().join(format!("tenkai-helm-diag-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let script = root.join("fake-helm");
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'helm failed; Authorization: Bearer super-secret-token' >&2\nexit 1\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(&script).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&script, permissions).unwrap();
        }
        let request = sample_request(&root);
        let executor = HelmSoftwareExecutor {
            helm_binary: script,
        };
        let err = executor.apply(&request).unwrap_err().to_string();
        assert!(err.contains("phase=apply"), "{err}");
        assert!(err.contains("helm"), "{err}");
        assert!(!err.contains("super-secret-token"), "{err}");
        assert!(err.contains("[redacted]"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn helm_values_detect_version_and_digest_mismatch() {
        let root = std::env::temp_dir().join(format!("tenkai-helm-obs-{}", uuid::Uuid::new_v4()));
        let mut request = sample_request(&root);
        request.config_digest = "abc".into();
        assert!(!helm_values_mismatch(
            r#"{"tenkai":{"version":"1.0.0","releaseId":"tenkai:release:api@1.0.0","configDigest":"abc"}}"#,
            &request
        ));
        assert!(helm_values_mismatch(
            r#"{"tenkai":{"version":"9.9.9","releaseId":"tenkai:release:api@1.0.0"}}"#,
            &request
        ));
        assert!(helm_values_mismatch(
            r#"{"tenkai":{"version":"1.0.0","releaseId":"tenkai:release:api@1.0.0","configDigest":"other"}}"#,
            &request
        ));
        assert!(helm_values_mismatch(r#"{"tenkai":{}}"#, &request));
        assert!(helm_values_mismatch("not-json", &request));
        let mut empty_digest = request.clone();
        empty_digest.config_digest.clear();
        assert!(helm_values_mismatch(
            r#"{"tenkai":{"version":"1.0.0","releaseId":"tenkai:release:api@1.0.0","configDigest":"stale"}}"#,
            &empty_digest
        ));
        let _ = std::fs::remove_dir_all(&root);
    }
}
