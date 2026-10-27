//! Native Kubernetes apply via `kubectl` (plain manifests, not Helm charts).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context as _, Result, bail};

use tenkai::software_executor::{
    SoftwareApplyRequest, SoftwareDeployPhase, SoftwareExecutor, SoftwareObserveStatus,
    k8s_label_value, kubernetes_manifests_dir, list_manifest_files, run_captured_command,
    validate_request,
};

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
            let path_s = path.to_string_lossy();
            run_kubectl(
                &self.kubectl_binary,
                &[
                    "apply",
                    "-f",
                    path_s.as_ref(),
                    "--namespace",
                    &request.environment,
                ],
                SoftwareDeployPhase::Apply,
                &format!("apply -f {}", path.display()),
                &request.product,
                &request.environment,
            )?;
        }
        // Ownership labels for Tenkai correlation (values sanitized for k8s).
        let label_args = ownership_label_args(request);
        let manifests_s = manifests.to_string_lossy();
        let mut args: Vec<&str> = vec![
            "label",
            "--overwrite",
            "-f",
            manifests_s.as_ref(),
            "--recursive",
            "--namespace",
            &request.environment,
        ];
        let owned: Vec<String> = label_args;
        for label in &owned {
            args.push(label.as_str());
        }
        run_kubectl(
            &self.kubectl_binary,
            &args,
            SoftwareDeployPhase::Apply,
            "label --overwrite",
            &request.product,
            &request.environment,
        )?;
        annotate_config_digest(self, request, SoftwareDeployPhase::Apply)?;
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
            let path_s = path.to_string_lossy();
            run_kubectl(
                &self.kubectl_binary,
                &[
                    "delete",
                    "-f",
                    path_s.as_ref(),
                    "--namespace",
                    &request.environment,
                    "--ignore-not-found=true",
                    "--wait=true",
                ],
                SoftwareDeployPhase::Remove,
                &format!("delete -f {}", path.display()),
                &request.product,
                &request.environment,
            )?;
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
        if kubernetes_labels_mismatch(self, request) {
            Ok(SoftwareObserveStatus::Mismatched)
        } else {
            Ok(SoftwareObserveStatus::Present)
        }
    }

    fn restart(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        // Re-apply first so Absent live targets are reinstalled, not bounce-only.
        self.apply(request)?;
        let selector = format!("tenkai.product={}", k8s_label_value(&request.product));
        if !kubernetes_labeled_workloads_exist(self, request, &selector)? {
            bail!(
                "no Deployment or StatefulSet labeled tenkai.product={} in namespace {}",
                request.product,
                request.environment
            );
        }
        let mut restarted = false;
        for kind in ["deployment", "statefulset"] {
            let output = Command::new(&self.kubectl_binary)
                .arg("rollout")
                .arg("restart")
                .arg(kind)
                .arg("--namespace")
                .arg(&request.environment)
                .arg("-l")
                .arg(&selector)
                .output()
                .with_context(|| {
                    format!(
                        "starting kubectl rollout restart via {}",
                        self.kubectl_binary.display()
                    )
                })?;
            if output.status.success()
                && !kubectl_reports_no_resources(&output)
                && kubernetes_labeled_workloads_exist(self, request, &selector)?
            {
                restarted = true;
            }
        }
        if !restarted {
            bail!(
                "no Deployment or StatefulSet labeled tenkai.product={} in namespace {}",
                request.product,
                request.environment
            );
        }
        Ok(())
    }
}

fn ensure_namespace(executor: &KubernetesSoftwareExecutor, namespace: &str) -> Result<()> {
    use std::process::Stdio;
    let get = Command::new(&executor.kubectl_binary)
        .arg("get")
        .arg("namespace")
        .arg(namespace)
        // Missing namespaces are expected on first apply; do not spam NotFound.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
    run_kubectl(
        &executor.kubectl_binary,
        &["create", "namespace", namespace],
        SoftwareDeployPhase::Apply,
        "create namespace",
        "namespace",
        namespace,
    )
}

fn ownership_label_args(request: &SoftwareApplyRequest) -> Vec<String> {
    vec![
        format!("tenkai.product={}", k8s_label_value(&request.product)),
        format!("tenkai.version={}", k8s_label_value(&request.version)),
        format!("tenkai.release-id={}", k8s_label_value(&request.release_id)),
    ]
}

fn run_kubectl(
    binary: &Path,
    args: &[&str],
    phase: SoftwareDeployPhase,
    phase_hint: &str,
    product: &str,
    environment: &str,
) -> Result<()> {
    let mut command = Command::new(binary);
    command.args(args);
    run_captured_command(
        &mut command,
        phase,
        phase_hint,
        product,
        environment,
        "kubectl",
        "set TENKAI_KUBECTL_BIN or install kubectl",
    )
}

fn kubernetes_labels_mismatch(
    executor: &KubernetesSoftwareExecutor,
    request: &SoftwareApplyRequest,
) -> bool {
    let selector = format!("tenkai.product={}", k8s_label_value(&request.product));
    let output = Command::new(&executor.kubectl_binary)
        .arg("get")
        .arg("deploy,statefulset")
        .arg("--namespace")
        .arg(&request.environment)
        .arg("-l")
        .arg(&selector)
        .arg("-o")
        .arg("json")
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    kubernetes_items_mismatch(&String::from_utf8_lossy(&output.stdout), request)
}

fn kubectl_reports_no_resources(output: &Output) -> bool {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    combined.contains("no resources found")
}

fn kubernetes_labeled_workloads_exist(
    executor: &KubernetesSoftwareExecutor,
    request: &SoftwareApplyRequest,
    selector: &str,
) -> Result<bool> {
    let output = Command::new(&executor.kubectl_binary)
        .arg("get")
        .arg("deploy,sts")
        .arg("--namespace")
        .arg(&request.environment)
        .arg("-l")
        .arg(selector)
        .arg("-o")
        .arg("name")
        .output()
        .with_context(|| {
            format!(
                "starting kubectl get via {}",
                executor.kubectl_binary.display()
            )
        })?;
    if !output.status.success() || kubectl_reports_no_resources(&output) {
        return Ok(false);
    }
    Ok(output
        .stdout
        .split(|b| *b == b'\n')
        .any(|line| !line.iter().all(|b| b.is_ascii_whitespace())))
}

fn kubernetes_items_mismatch(items_json: &str, request: &SoftwareApplyRequest) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(items_json) else {
        return false;
    };
    let Some(items) = value.get("items").and_then(|items| items.as_array()) else {
        return false;
    };
    let expected_version = k8s_label_value(&request.version);
    items.iter().any(|item| {
        let version_mismatch = item
            .get("metadata")
            .and_then(|metadata| metadata.get("labels"))
            .and_then(|labels| labels.get("tenkai.version"))
            .and_then(|version| version.as_str())
            .is_some_and(|version| version != expected_version);
        let live_digest = item
            .get("metadata")
            .and_then(|metadata| metadata.get("annotations"))
            .and_then(|annotations| annotations.get("tenkai.config-digest"))
            .and_then(|digest| digest.as_str())
            .unwrap_or("");
        let digest_mismatch = live_digest != request.config_digest;
        version_mismatch || digest_mismatch
    })
}

fn annotate_config_digest(
    executor: &KubernetesSoftwareExecutor,
    request: &SoftwareApplyRequest,
    phase: SoftwareDeployPhase,
) -> Result<()> {
    let selector = format!("tenkai.product={}", k8s_label_value(&request.product));
    let annotation = if request.config_digest.is_empty() {
        "tenkai.config-digest-".to_string()
    } else {
        format!("tenkai.config-digest={}", request.config_digest)
    };
    run_kubectl(
        &executor.kubectl_binary,
        &[
            "annotate",
            "--overwrite",
            "deploy,statefulset",
            "-l",
            &selector,
            "--namespace",
            &request.environment,
            &annotation,
        ],
        phase,
        "annotate tenkai.config-digest",
        &request.product,
        &request.environment,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tenkai::software_executor::{
        KUBERNETES_MANIFESTS_DIR, SoftwareApplyRequest, request_from_parts,
    };

    fn sample_request(root: &Path) -> SoftwareApplyRequest {
        std::fs::create_dir_all(root).unwrap();
        request_from_parts("api", "1.0.0", "prod", root, "tenkai:release:api@1.0.0")
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

    #[test]
    fn kubernetes_items_detect_version_label_mismatch() {
        let root = std::env::temp_dir().join(format!("tenkai-k8s-obs-{}", uuid::Uuid::new_v4()));
        let request = sample_request(&root);
        assert!(!kubernetes_items_mismatch(
            r#"{"items":[{"metadata":{"labels":{"tenkai.version":"1.0.0"}}}]}"#,
            &request
        ));
        assert!(kubernetes_items_mismatch(
            r#"{"items":[{"metadata":{"labels":{"tenkai.version":"1.0.0"},"annotations":{"tenkai.config-digest":"stale"}}}]}"#,
            &request
        ));
        assert!(kubernetes_items_mismatch(
            r#"{"items":[{"metadata":{"labels":{"tenkai.version":"0.9.0"}}}]}"#,
            &request
        ));
        let mut with_digest = request.clone();
        with_digest.config_digest = "abc".into();
        assert!(kubernetes_items_mismatch(
            r#"{"items":[{"metadata":{"labels":{"tenkai.version":"1.0.0"}}}]}"#,
            &with_digest
        ));
        assert!(!kubernetes_items_mismatch(
            r#"{"items":[{"metadata":{"labels":{"tenkai.version":"1.0.0"},"annotations":{"tenkai.config-digest":"abc"}}}]}"#,
            &with_digest
        ));
        let _ = std::fs::remove_dir_all(&root);
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
            overlays: Default::default(),
            config_digest: String::new(),
            artifact_pulls: Vec::new(),
            cluster_config_path: None,
            secret_dir_path: None,
            apply_attempt: String::new(),
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
