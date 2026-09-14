//! Live kind-cluster evidence for in-process server-side apply (#376).
//!
//! Ignored by default so `make test` stays cluster-free. CI copies the kind
//! kubeconfig to an environment-scoped file and sets `TENKAI_CLUSTER_CONFIG`.
//! The executor never reads `KUBECONFIG`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tenkai::software_executor::in_process_kubernetes::{
    FIELD_MANAGER, InProcessKubernetesExecutor, LiveKubeApi,
};
use tenkai::software_executor::{SoftwareApplyRequest, SoftwareExecutor, SoftwareObserveStatus};

fn cluster_config() -> PathBuf {
    let raw = std::env::var("TENKAI_CLUSTER_CONFIG")
        .expect("TENKAI_CLUSTER_CONFIG must be an environment-scoped kubeconfig file");
    let path = PathBuf::from(raw);
    assert!(
        path.is_file(),
        "TENKAI_CLUSTER_CONFIG {} is not a file",
        path.display()
    );
    path
}

fn write_workdir(root: &Path, name: &str, image: &str, replicas: u32) {
    let manifests = root.join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();
    std::fs::write(
        manifests.join("deploy.yaml"),
        format!(
            r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
        - name: pause
          image: {image}
          imagePullPolicy: IfNotPresent
"#
        ),
    )
    .unwrap();
}

fn request(root: &Path, kubeconfig: &Path, env: &str, version: &str) -> SoftwareApplyRequest {
    SoftwareApplyRequest {
        product: "edge-app".into(),
        version: version.into(),
        environment: env.into(),
        workdir: root.to_path_buf(),
        release_id: format!("tenkai:release:edge-app@{version}"),
        overlays: Default::default(),
        config_digest: String::new(),
        artifact_pulls: Vec::new(),
        cluster_config_path: Some(kubeconfig.to_path_buf()),
    }
}

fn kubectl(kubeconfig: &Path, args: &[&str]) -> std::process::Output {
    Command::new("kubectl")
        .arg("--kubeconfig")
        .arg(kubeconfig)
        .args(args)
        .output()
        .expect("start kubectl")
}

fn unique_env(suffix: &str) -> String {
    format!(
        "tk376{suffix}{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )
}

#[test]
#[ignore = "requires a kind cluster and TENKAI_CLUSTER_CONFIG"]
fn apply_a_to_b_to_rollback_observes_rollout_conditions() {
    let kubeconfig = cluster_config();
    let env = unique_env("ab");
    let root_a = std::env::temp_dir().join(format!("{env}-a"));
    let root_b = std::env::temp_dir().join(format!("{env}-b"));
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);
    write_workdir(&root_a, "edge", "registry.k8s.io/pause:3.10", 1);
    write_workdir(&root_b, "edge", "registry.k8s.io/pause:3.10", 2);
    let executor =
        InProcessKubernetesExecutor::new(LiveKubeApi).with_timeout(Duration::from_secs(90));
    executor
        .apply(&request(&root_a, &kubeconfig, &env, "1.0.0"))
        .expect("apply A");
    assert_eq!(
        executor
            .observe(&request(&root_a, &kubeconfig, &env, "1.0.0"))
            .unwrap(),
        SoftwareObserveStatus::Present
    );
    executor
        .apply(&request(&root_b, &kubeconfig, &env, "2.0.0"))
        .expect("apply B");
    executor
        .apply(&request(&root_a, &kubeconfig, &env, "1.0.0"))
        .expect("rollback to A");
    assert_eq!(
        executor
            .observe(&request(&root_a, &kubeconfig, &env, "1.0.0"))
            .unwrap(),
        SoftwareObserveStatus::Present
    );
    let _ = kubectl(&kubeconfig, &["delete", "namespace", &env, "--wait=false"]);
    let _ = std::fs::remove_dir_all(root_a);
    let _ = std::fs::remove_dir_all(root_b);
}

#[test]
#[ignore = "requires a kind cluster and TENKAI_CLUSTER_CONFIG"]
fn failing_rollout_names_workload_condition() {
    let kubeconfig = cluster_config();
    let env = unique_env("fail");
    let root = std::env::temp_dir().join(format!("{env}-fail"));
    let _ = std::fs::remove_dir_all(&root);
    write_workdir(&root, "edge", "tenkai.invalid/missing:fail", 1);
    let executor =
        InProcessKubernetesExecutor::new(LiveKubeApi).with_timeout(Duration::from_secs(25));
    let err = executor
        .apply(&request(&root, &kubeconfig, &env, "1.0.0"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Available=") || err.contains("Progressing=False"),
        "{err}"
    );
    let _ = kubectl(&kubeconfig, &["delete", "namespace", &env, "--wait=false"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires a kind cluster and TENKAI_CLUSTER_CONFIG"]
fn foreign_field_manager_conflicts_without_force() {
    let kubeconfig = cluster_config();
    let env = unique_env("fm");
    let root = std::env::temp_dir().join(format!("{env}-fm"));
    let _ = std::fs::remove_dir_all(&root);
    write_workdir(&root, "edge", "registry.k8s.io/pause:3.10", 1);
    let created = kubectl(&kubeconfig, &["create", "namespace", &env]);
    assert!(created.status.success(), "{created:?}");
    let applied = kubectl(
        &kubeconfig,
        &[
            "apply",
            "--server-side",
            "--field-manager=helm",
            "--namespace",
            &env,
            "-f",
            root.join("manifests/deploy.yaml").to_str().unwrap(),
        ],
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let executor =
        InProcessKubernetesExecutor::new(LiveKubeApi).with_timeout(Duration::from_secs(20));
    let err = executor
        .apply(&request(&root, &kubeconfig, &env, "1.0.0"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("server-side apply conflict"), "{err}");
    assert!(err.contains("helm") || err.contains("conflict"), "{err}");
    assert!(!err.to_ascii_lowercase().contains("force=true"), "{err}");
    let _ = FIELD_MANAGER;
    let _ = kubectl(&kubeconfig, &["delete", "namespace", &env, "--wait=false"]);
    let _ = std::fs::remove_dir_all(root);
}
