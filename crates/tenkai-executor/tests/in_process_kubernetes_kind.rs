//! Live kind-cluster evidence for in-process server-side apply (#376).
//!
//! Ignored by default so `make test` stays cluster-free. CI copies the kind
//! kubeconfig to an environment-scoped file and sets `TENKAI_CLUSTER_CONFIG`.
//! The executor never reads `KUBECONFIG`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tenkai::software_executor::{SoftwareApplyRequest, SoftwareExecutor, SoftwareObserveStatus};
use tenkai_executor::{FIELD_MANAGER, InProcessKubernetesExecutor, LiveKubeApi};

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
        secret_dir_path: None,
        apply_attempt: String::new(),
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

/// Busybox from the Kubernetes test image registry, for containers that
/// need a shell.
const BUSYBOX: &str = "registry.k8s.io/e2e-test-images/busybox:1.36.1-1";

/// One Deployment whose container runs `script` under `sh -c`, with an
/// optional readiness file probe.
fn write_script_workdir(root: &Path, name: &str, script: &str, readiness: bool) {
    let manifests = root.join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();
    let probe = if readiness {
        "          readinessProbe:\n            exec:\n              command: [\"cat\", \"/tmp/ready\"]\n            periodSeconds: 2\n"
    } else {
        ""
    };
    std::fs::write(
        manifests.join("deploy.yaml"),
        format!(
            r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      terminationGracePeriodSeconds: 1
      containers:
        - name: app
          image: {BUSYBOX}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", {script:?}]
{probe}"#
        ),
    )
    .unwrap();
}

/// Apply that must fail before `timeout`; returns the error text.
fn apply_fails_before_timeout(root: &Path, env: &str, timeout: Duration) -> String {
    let kubeconfig = cluster_config();
    let executor = InProcessKubernetesExecutor::new(LiveKubeApi).with_timeout(timeout);
    let started = std::time::Instant::now();
    let err = executor
        .apply(&request(root, &kubeconfig, env, "1.0.0"))
        .unwrap_err();
    let err = format!("{err:#}");
    eprintln!("{err}");
    assert!(
        started.elapsed() < timeout,
        "a terminal stall must fail before the {timeout:?} timeout: {err}"
    );
    assert!(err.contains("cannot become Available"), "{err}");
    let _ = kubectl(&kubeconfig, &["delete", "namespace", env, "--wait=false"]);
    let _ = std::fs::remove_dir_all(root);
    err
}

#[test]
#[ignore = "requires a kind cluster and TENKAI_CLUSTER_CONFIG"]
fn failing_rollout_names_the_image_pull_failure() {
    let env = unique_env("fail");
    let root = std::env::temp_dir().join(format!("{env}-fail"));
    let _ = std::fs::remove_dir_all(&root);
    write_workdir(&root, "edge", "tenkai.invalid/missing:fail", 1);
    let err = apply_fails_before_timeout(&root, &env, Duration::from_secs(180));
    assert!(
        err.contains("ImagePullBackOff") || err.contains("ErrImagePull"),
        "{err}"
    );
    assert!(err.contains("Available="), "{err}");
}

#[test]
#[ignore = "requires a kind cluster and TENKAI_CLUSTER_CONFIG"]
fn a_crash_loop_fails_the_step_naming_the_exit_code() {
    let env = unique_env("crash");
    let root = std::env::temp_dir().join(format!("{env}-crash"));
    let _ = std::fs::remove_dir_all(&root);
    write_script_workdir(
        &root,
        "edge",
        "echo upstream not found > /dev/termination-log; exit 3",
        // The readiness probe never passes, so a container that exits right
        // after starting never counts as available between restarts.
        true,
    );
    let err = apply_fails_before_timeout(&root, &env, Duration::from_secs(240));
    assert!(err.contains("CrashLoopBackOff after"), "{err}");
    assert!(
        err.contains("last exit code 3 (Error): upstream not found"),
        "{err}"
    );
}

#[test]
#[ignore = "requires a kind cluster and TENKAI_CLUSTER_CONFIG"]
fn an_admission_refusal_fails_the_step_naming_the_policy() {
    let kubeconfig = cluster_config();
    let env = unique_env("psa");
    let root = std::env::temp_dir().join(format!("{env}-psa"));
    let _ = std::fs::remove_dir_all(&root);
    write_workdir(&root, "edge", "registry.k8s.io/pause:3.10", 1);
    let created = kubectl(&kubeconfig, &["create", "namespace", &env]);
    assert!(created.status.success(), "{created:?}");
    let labeled = kubectl(
        &kubeconfig,
        &[
            "label",
            "namespace",
            &env,
            "pod-security.kubernetes.io/enforce=restricted",
        ],
    );
    assert!(labeled.status.success(), "{labeled:?}");
    let started = std::time::Instant::now();
    let err = apply_fails_before_timeout(&root, &env, Duration::from_secs(120));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "an admission refusal must fail within seconds, took {:?}",
        started.elapsed()
    );
    assert!(err.contains("ReplicaFailure=True FailedCreate"), "{err}");
    assert!(err.contains("violates PodSecurity"), "{err}");
}

#[test]
#[ignore = "requires a kind cluster and TENKAI_CLUSTER_CONFIG"]
fn a_slow_healthy_rollout_still_succeeds() {
    let kubeconfig = cluster_config();
    let env = unique_env("slow");
    let root = std::env::temp_dir().join(format!("{env}-slow"));
    let _ = std::fs::remove_dir_all(&root);
    write_script_workdir(
        &root,
        "edge",
        "sleep 20; touch /tmp/ready; exec sleep 3600",
        true,
    );
    let executor =
        InProcessKubernetesExecutor::new(LiveKubeApi).with_timeout(Duration::from_secs(180));
    let started = std::time::Instant::now();
    executor
        .apply(&request(&root, &kubeconfig, &env, "1.0.0"))
        .expect("a slow but healthy rollout completes");
    assert!(
        started.elapsed() >= Duration::from_secs(20),
        "the wait must cover the slow readiness, took {:?}",
        started.elapsed()
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
    write_workdir(&root, "edge", "registry.k8s.io/pause:3.10", 2);
    let created = kubectl(&kubeconfig, &["create", "namespace", &env]);
    assert!(created.status.success(), "{created:?}");
    let helm = std::env::temp_dir().join(format!("{env}-helm.yaml"));
    std::fs::write(
        &helm,
        r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: edge
spec:
  replicas: 1
  selector:
    matchLabels:
      app: edge
  template:
    metadata:
      labels:
        app: edge
    spec:
      containers:
        - name: pause
          image: registry.k8s.io/pause:3.10
          imagePullPolicy: IfNotPresent
"#,
    )
    .unwrap();
    let applied = kubectl(
        &kubeconfig,
        &[
            "apply",
            "--server-side",
            "--field-manager=helm",
            "--namespace",
            &env,
            "-f",
            helm.to_str().unwrap(),
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
