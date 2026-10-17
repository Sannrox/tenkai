//! Live kind evidence for the rollout-time harness (#596).
//!
//! Ignored by default. The scheduled CI job creates a kind cluster, sets
//! `TENKAI_CLUSTER_CONFIG`, and fails on a >20% regression versus the stored
//! runner baseline.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use tenkai::rollout_time::{self, Gate, RolloutReport};
use tenkai::software_executor::{SoftwareApplyRequest, SoftwareExecutor, request_from_parts};
use tenkai_executor::InProcessKubernetesExecutor;
use tenkai_executor::LiveKubeApi;

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

fn unique_env(suffix: &str) -> String {
    format!(
        "rt{suffix}{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )
}

fn write_workdir(root: &Path, services: u32, upgrade_first: bool) {
    let manifests = root.join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();
    for index in 1..=services {
        let name = format!("svc{index:02}");
        let image = if upgrade_first && index == 1 {
            "registry.k8s.io/pause:3.9"
        } else {
            "registry.k8s.io/pause:3.10"
        };
        std::fs::write(
            manifests.join(format!("{name}.yaml")),
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
      containers:
        - name: pause
          image: {image}
          imagePullPolicy: IfNotPresent
"#
            ),
        )
        .unwrap();
    }
}

/// `kubectl rollout status` waits for observedGeneration and updated replicas.
/// Apply itself stays on the #376 Available=True contract.
fn wait_for_rollout(kubeconfig: &Path, env: &str, services: u32) -> Result<()> {
    for index in 1..=services {
        let name = format!("svc{index:02}");
        let output = Command::new("kubectl")
            .env("KUBECONFIG", kubeconfig)
            .args([
                "--namespace",
                env,
                "rollout",
                "status",
                &format!("deployment/{name}"),
                "--timeout=180s",
            ])
            .output()?;
        if !output.status.success() {
            bail!(
                "kubectl rollout status {name} in {env} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    Ok(())
}

fn request(root: &Path, kubeconfig: &Path, env: &str, version: &str) -> SoftwareApplyRequest {
    let mut request = request_from_parts(
        "rollout",
        version,
        env,
        root,
        format!("tenkai:release:rollout@{version}"),
    );
    request.cluster_config_path = Some(kubeconfig.to_path_buf());
    request
}

#[test]
#[ignore = "requires a kind cluster and TENKAI_CLUSTER_CONFIG"]
fn kubernetes_inprocess_against_runner_baseline() {
    let kubeconfig = cluster_config();
    let executor =
        InProcessKubernetesExecutor::new(LiveKubeApi).with_timeout(Duration::from_secs(180));
    let mut samples = Vec::new();
    for services in [1_u32, 5, 20] {
        let env = unique_env(&format!("{services}"));
        let root_a = std::env::temp_dir().join(format!("{env}-a"));
        let root_b = std::env::temp_dir().join(format!("{env}-b"));
        let _ = std::fs::remove_dir_all(&root_a);
        let _ = std::fs::remove_dir_all(&root_b);
        write_workdir(&root_a, services, false);
        write_workdir(&root_b, services, true);
        let v1 = request(&root_a, &kubeconfig, &env, "1.0.0");
        let v2 = request(&root_b, &kubeconfig, &env, "2.0.0");
        let apply = |request: &SoftwareApplyRequest| {
            let mut times = executor.apply_with_phases(request)?;
            let extra = Instant::now();
            wait_for_rollout(&kubeconfig, &request.environment, services)?;
            times.health_ms = times
                .health_ms
                .saturating_add(extra.elapsed().as_millis() as u64);
            Ok(times)
        };
        let observe = |request: &SoftwareApplyRequest| executor.observe(request).map(|_| ());
        samples.push(
            rollout_time::time_kubernetes(
                apply,
                observe,
                "kubernetes-inprocess",
                "fresh_install",
                services,
                &v1,
            )
            .unwrap(),
        );
        samples.push(
            rollout_time::time_kubernetes(
                apply,
                observe,
                "kubernetes-inprocess",
                "noop_reapply",
                services,
                &v1,
            )
            .unwrap(),
        );
        samples.push(
            rollout_time::time_kubernetes(
                apply,
                observe,
                "kubernetes-inprocess",
                "one_service_upgrade",
                services,
                &v2,
            )
            .unwrap(),
        );
        samples.push(
            rollout_time::time_kubernetes(
                apply,
                observe,
                "kubernetes-inprocess",
                "rollback",
                services,
                &v1,
            )
            .unwrap(),
        );
        let _ = executor.remove(&v1);
        let _ = std::fs::remove_dir_all(&root_a);
        let _ = std::fs::remove_dir_all(&root_b);
    }
    let baseline = rollout_time::load_baseline(&rollout_time::baseline_path()).unwrap();
    let report = RolloutReport {
        samples,
        reconcile: Vec::new(),
    };
    println!("{}", rollout_time::format_report(&report));
    rollout_time::evaluate(&report, &baseline, Gate::from_env()).unwrap();
}
