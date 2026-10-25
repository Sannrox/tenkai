//! Opt-in GPU evidence for the vLLM Kubernetes executor (#602).
//!
//! Ignored by default so `cargo test` needs no GPU. Enable with
//! `TENKAI_VLLM_LIVE_TEST=1` plus a cluster kubeconfig, digest-pinned serving
//! image, a namespace that already contains the weights claim, the host mount
//! of that claim, and a small `directory+tar` model archive.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use tenkai::manifest::{
    GpuRequirements, ModelHealthSection, ModelRequirementsSection, ModelRuntimeSection,
    ModelSection,
};
use tenkai::model_runtime::{
    MODEL_RUNTIME_CONTRACT_VERSION, ModelRuntimeDescriptor, ModelRuntimeExecutor, WeightCache,
};
use tenkai_executor::{
    HttpSmokeProbe, LiveKubeApi, SmokeProbe, VllmConfig, VllmModelRuntimeExecutor,
};

fn required_env(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("{name} must be set for TENKAI_VLLM_LIVE_TEST"))
}

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(required_env(name));
    assert!(path.exists(), "{name} {} does not exist", path.display());
    path
}

fn unique_product() -> String {
    format!("tiny{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

fn stable_service(product: &str) -> String {
    format!("{product}-svc")
}

fn selected_generation(kubeconfig: &Path, namespace: &str, product: &str) -> String {
    let kubectl = std::env::var_os("TENKAI_KUBECTL_BIN").unwrap_or_else(|| "kubectl".into());
    let output = Command::new(kubectl)
        .arg("--kubeconfig")
        .arg(kubeconfig)
        .args([
            "-n",
            namespace,
            "get",
            "svc",
            &stable_service(product),
            "-o",
            "json",
        ])
        .output()
        .expect("start kubectl");
    assert!(
        output.status.success(),
        "kubectl get Service {}: {}",
        stable_service(product),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("Service JSON");
    value
        .pointer("/spec/selector/tenkai.generation")
        .and_then(serde_json::Value::as_str)
        .filter(|generation| !generation.is_empty())
        .unwrap_or_else(|| panic!("stable Service is missing tenkai.generation: {value}"))
        .to_string()
}

fn smoke_stable(
    probe: &HttpSmokeProbe,
    namespace: &str,
    product: &str,
    health: &ModelHealthSection,
) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let poll = Duration::from_secs(2);
    let service = stable_service(product);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("inference through {service} did not pass before the routing deadline");
        }
        let outcome = probe.smoke(namespace, &service, 8000, product, health, remaining);
        if Instant::now() > deadline {
            panic!("inference through {service} answered after the routing deadline");
        }
        if outcome.is_ok() {
            return;
        }
        std::thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn descriptor(
    product: &str,
    source: &Path,
    digest: &str,
    version: &str,
    startup: u32,
) -> ModelRuntimeDescriptor {
    ModelRuntimeDescriptor {
        contract_version: MODEL_RUNTIME_CONTRACT_VERSION,
        product_name: product.into(),
        product_version: version.into(),
        model: ModelSection {
            source: format!("file://{}", source.display()),
            revision: "r1".into(),
            format: "directory+tar".into(),
            quantization: "bf16".into(),
            artifact_digest: digest.into(),
            license: "apache-2.0".into(),
            registry_descriptor: String::new(),
        },
        runtime: ModelRuntimeSection {
            engine: "vllm".into(),
            port: 8000,
            context_length: 2048,
        },
        requirements: ModelRequirementsSection {
            architecture: vec!["x86_64".into()],
            memory_gib: 16,
            accelerator: vec!["nvidia".into()],
            gpu: Some(GpuRequirements {
                vendor: vec!["nvidia".into()],
                families: vec![],
                vram_gib: 8,
                count: 1,
                tensor_parallel: 1,
                driver_min: None,
                runtime: None,
                runtime_min: None,
            }),
        },
        health: ModelHealthSection {
            endpoint: "http://127.0.0.1:8000/v1/models".into(),
            smoke_prompt: "Return exactly: OK".into(),
            max_startup_seconds: startup,
        },
    }
}

fn parse_json_map(name: &str) -> std::collections::BTreeMap<String, String> {
    match std::env::var(name) {
        Ok(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw).unwrap_or_else(|error| {
            panic!("{name} must be a JSON object of string labels: {error}")
        }),
        _ => std::collections::BTreeMap::new(),
    }
}

fn parse_json_array(name: &str) -> Vec<serde_json::Value> {
    match std::env::var(name) {
        Ok(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw).unwrap_or_else(|error| {
            panic!("{name} must be a JSON array of toleration objects: {error}")
        }),
        _ => Vec::new(),
    }
}

#[test]
#[ignore = "requires TENKAI_VLLM_LIVE_TEST plus a GPU cluster kubeconfig and image"]
fn vllm_live_gpu_apply_forward_smoke_fail_rollback() {
    assert_eq!(
        std::env::var("TENKAI_VLLM_LIVE_TEST").ok().as_deref(),
        Some("1"),
        "set TENKAI_VLLM_LIVE_TEST=1 to run this ignored GPU test"
    );
    let kubeconfig = required_path("TENKAI_CLUSTER_CONFIG");
    assert!(
        kubeconfig.is_file(),
        "TENKAI_CLUSTER_CONFIG {} is not a file",
        kubeconfig.display()
    );
    let image = required_env("TENKAI_VLLM_IMAGE");
    assert!(
        image.contains("@sha256:"),
        "TENKAI_VLLM_IMAGE must pin the serving image by digest"
    );
    let namespace = required_env("TENKAI_VLLM_NAMESPACE");
    let weights_claim = required_env("TENKAI_VLLM_WEIGHTS_CLAIM");
    let weights_root = required_path("TENKAI_VLLM_WEIGHTS_ROOT");
    let model_tar = required_path("TENKAI_VLLM_MODEL_TAR");
    let archive = std::fs::read(&model_tar).expect("read TENKAI_VLLM_MODEL_TAR");
    let digest = format!("sha256:{:x}", Sha256::digest(&archive));
    let product = unique_product();
    let work = std::env::temp_dir().join(format!("tenkai-{product}"));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let source = work.join("model.tar");
    std::fs::write(&source, &archive).unwrap();
    let probe = HttpSmokeProbe {
        base_url: std::env::var("TENKAI_VLLM_SMOKE_BASE_URL")
            .unwrap_or_else(|_| "http://{service}.{namespace}.svc:{port}".into()),
        timeout: Duration::from_secs(30),
    };
    let executor = VllmModelRuntimeExecutor::new(
        LiveKubeApi,
        probe.clone(),
        VllmConfig {
            cluster_config: kubeconfig.clone(),
            namespace: namespace.clone(),
            image,
            weights_claim,
            node_selector: parse_json_map("TENKAI_VLLM_NODE_SELECTOR"),
            tolerations: parse_json_array("TENKAI_VLLM_TOLERATIONS"),
        },
        WeightCache::new(weights_root),
        work.join(format!("{product}.json")),
    );
    let _cleanup = LiveCleanup {
        executor: &executor,
        work: work.clone(),
    };
    let v1 = descriptor(&product, &source, &digest, "0.1.0", 600);
    let v2 = descriptor(&product, &source, &digest, "0.2.0", 600);
    let v3 = descriptor(&product, &source, &digest, "0.3.0", 1);
    let digest1 = executor.apply(&v1).expect("apply first generation");
    let generation1 = selected_generation(&kubeconfig, &namespace, &product);
    smoke_stable(&probe, &namespace, &product, &v1.health);
    assert_eq!(
        executor.observe().unwrap().as_deref(),
        Some(digest1.as_str())
    );
    let digest2 = executor.apply(&v2).expect("roll forward");
    let generation2 = selected_generation(&kubeconfig, &namespace, &product);
    assert_ne!(
        generation2, generation1,
        "roll-forward must switch the stable Service selector"
    );
    smoke_stable(&probe, &namespace, &product, &v2.health);
    assert_eq!(
        executor.observe().unwrap().as_deref(),
        Some(digest2.as_str())
    );
    assert!(
        executor.apply(&v3).is_err(),
        "forced short startup must fail smoke/readiness and leave traffic unchanged"
    );
    assert_eq!(
        selected_generation(&kubeconfig, &namespace, &product),
        generation2,
        "failed apply must leave the stable Service on the last good generation"
    );
    smoke_stable(&probe, &namespace, &product, &v2.health);
    assert_eq!(
        executor.observe().unwrap().as_deref(),
        Some(digest2.as_str())
    );
    let rolled = executor.rollback().expect("rollback to retained previous");
    assert_eq!(rolled, digest1);
    assert_eq!(
        selected_generation(&kubeconfig, &namespace, &product),
        generation1,
        "rollback must re-select the retained previous generation"
    );
    smoke_stable(&probe, &namespace, &product, &v1.health);
    assert_eq!(
        executor.observe().unwrap().as_deref(),
        Some(digest1.as_str())
    );
}

struct LiveCleanup<'a> {
    executor: &'a VllmModelRuntimeExecutor<LiveKubeApi, HttpSmokeProbe>,
    work: PathBuf,
}

impl Drop for LiveCleanup<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.executor.remove() {
            eprintln!(
                "vllm live test: cluster cleanup failed; leaving {} so remove can be retried: {error:#}",
                self.work.display()
            );
            return;
        }
        let _ = std::fs::remove_dir_all(&self.work);
    }
}
