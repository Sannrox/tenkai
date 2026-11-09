//! Helm CLI software-executor adapter (`helm upgrade --install` / `helm uninstall`).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use tenkai::now_millis;

use crate::helm_secrets::{self, LiveSecrets};
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
    /// A `helm` command for `request`, pointed at its cluster configuration
    /// when the request names one. Every call uses this, so a request never
    /// reaches a different cluster than its other calls.
    fn helm(&self, request: &SoftwareApplyRequest) -> Command {
        let mut command = Command::new(&self.helm_binary);
        if let Some(path) = &request.cluster_config_path {
            command.arg("--kubeconfig").arg(path);
        }
        command
    }

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
        // Sealed values land first, so the release can read them as it starts.
        let secrets = match &request.opened_secrets[..] {
            [] => None,
            _ => {
                let cluster_config = request
                    .cluster_config_path
                    .as_deref()
                    .context("writing sealed secrets needs a cluster configuration")?;
                let api = LiveSecrets::connect(cluster_config, &request.environment)?;
                let sets = helm_secrets::write(&api, request)?;
                Some((api, sets))
            }
        };
        let mut command = self.helm(request);
        command
            .arg("upgrade")
            .arg("--install")
            .arg(request.instance_name())
            .arg(&request.workdir)
            .arg("--namespace")
            .arg(&request.environment)
            .arg("--create-namespace")
            .arg("--wait")
            .arg("--timeout")
            .arg("5m");
        apply_helm_set_flags(&mut command, request);
        let _dependency_file = helm_dependency_file(request, &mut command)?;
        let secret_sets = secrets.iter().flat_map(|(_, sets)| sets);
        for set in extra_sets.iter().chain(secret_sets) {
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
        )?;
        // Older Secrets are an optional cleanup: the apply stands, and the
        // next one retries.
        if let Some((api, _)) = &secrets
            && let Err(error) = helm_secrets::prune(api, request)
        {
            eprintln!(
                "{}: leaving older sealed Secrets in place: {error:#}",
                request.instance_name()
            );
        }
        Ok(())
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
        let mut command = self.helm(request);
        command
            .arg("uninstall")
            .arg(request.instance_name())
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
        )?;
        // Helm does not own the sealed Secrets. When a runtime, their only
        // writer, removes a release (failed-apply cleanup, a rollback's
        // outgoing release), every Tenkai-owned Secret of the instance goes
        // with it, found by its labels without the opened values. Removals
        // anywhere else never touch the cluster's Secrets API.
        if request.remove_owned_secrets
            && let Some(cluster_config) = &request.cluster_config_path
        {
            let api = LiveSecrets::connect_existing(cluster_config)?;
            helm_secrets::remove_all(&api, request)?;
        }
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let output = self
            .helm(request)
            .arg("status")
            .arg(request.instance_name())
            .arg("--namespace")
            .arg(&request.environment)
            .output()
            .with_context(|| format!("starting helm status via {}", self.helm_binary.display()))?;
        if !output.status.success() {
            return Ok(SoftwareObserveStatus::Absent);
        }
        let values = self
            .helm(request)
            .arg("get")
            .arg("values")
            .arg(request.instance_name())
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
        .arg(format!("tenkai.releaseId={}", request.release_id))
        .arg("--set")
        .arg(format!("tenkai.instance={}", request.instance_name()));
    command
        .arg("--set")
        .arg(format!("tenkai.configDigest={}", request.config_digest));
    for (key, value) in &request.overlays {
        command
            .arg("--set")
            .arg(format!("tenkai.config.{key}={value}"));
    }
}

struct TempDoc(PathBuf);

impl Drop for TempDoc {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn helm_dependency_file(
    request: &SoftwareApplyRequest,
    command: &mut Command,
) -> Result<Option<TempDoc>> {
    if request.dependency_document.is_empty() {
        return Ok(None);
    }
    let path = std::env::temp_dir().join(format!(
        "tenkai-dependencies-{}-{}.json",
        std::process::id(),
        uuid_like()
    ));
    std::fs::write(&path, request.dependency_document.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    command.arg("--set-file").arg(format!(
        "{}={}",
        tenkai::dependency_document::HELM_VALUES_KEY,
        path.display()
    ));
    Ok(Some(TempDoc(path)))
}

fn uuid_like() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
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
    fn every_helm_call_targets_the_requested_cluster_config() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::env::temp_dir().join(format!("tenkai-helm-kube-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let log = root.join("argv");
        let script = root.join("fake-helm");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut request = sample_request(&root.join("chart"));
        request.cluster_config_path = Some(root.join("cluster.yaml"));
        let executor = HelmSoftwareExecutor {
            helm_binary: script,
        };
        executor.apply(&request).unwrap();
        executor.remove(&request).unwrap();
        let _ = executor.observe(&request).unwrap();
        let calls = std::fs::read_to_string(&log).unwrap();
        let expected = format!("--kubeconfig {}", root.join("cluster.yaml").display());
        assert_eq!(calls.lines().count(), 4, "{calls}");
        assert!(
            calls.lines().all(|call| call.starts_with(&expected)),
            "{calls}"
        );
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
