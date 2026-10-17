//! Rollout-time harness: Docker and in-process Kubernetes apply phases plus
//! planner/reconcile ticks, compared to one stored baseline.
//!
//! Default `cargo test` drives the fake Docker CLI and an in-memory store so
//! the harness stays deterministic. Published apply budgets (no-op re-apply of
//! 20 services ≤ 2 s; one-service upgrade ≤ pull + health + 5 s) and the 1 s
//! reconcile tick at 1_000 environments are enforced by the scheduled job
//! (`TENKAI_ROLLOUT_GATE=regression`) together with a >20% check versus
//! `perf/rollout-baseline.json`. Absolute wall-clock budgets are not applied
//! during a parallel `cargo test` process.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::plan;
use crate::reconciler::{self, EnvironmentStatus, Reconciler, TickReport};
use crate::software_executor::{
    DockerHostExecutor, RolloutPhaseTimes, SoftwareApplyRequest, SoftwareExecutor,
    request_from_parts,
};

/// Checked-in runner baseline relative to the tenkai crate root.
pub const BASELINE_FILE: &str = "perf/rollout-baseline.json";
/// No-op re-apply of 20 services must finish within this wall time.
pub const BUDGET_NOOP_REAPPLY_20_MS: u64 = 2_000;
/// One-service upgrade wall minus image pull minus health wait.
pub const BUDGET_UPGRADE_OVERHEAD_MS: u64 = 5_000;
/// One reconcile tick of 1_000 registered environments.
pub const BUDGET_RECONCILE_1000_MS: u64 = 1_000;
/// Scheduled job fails when a live sample exceeds this ratio of the baseline.
pub const REGRESSION_RATIO: f64 = 1.20;

const SERVICE_COUNTS: [u32; 3] = [1, 5, 20];
const RECONCILE_COUNTS: [u32; 2] = [100, 1_000];

/// Which comparison the harness applies to a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Published absolute budgets only (default `cargo test`).
    Absolute,
    /// Absolute budgets plus >20% versus the stored runner baseline.
    Regression,
}

impl Gate {
    /// `TENKAI_ROLLOUT_GATE=regression` selects the scheduled-job gate.
    pub fn from_env() -> Self {
        match std::env::var("TENKAI_ROLLOUT_GATE") {
            Ok(value) if value.eq_ignore_ascii_case("regression") => Self::Regression,
            _ => Self::Absolute,
        }
    }
}

/// One apply scenario (fresh install, no-op re-apply, upgrade, or rollback).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioSample {
    pub scenario: String,
    pub services: u32,
    pub executor: String,
    pub phases: RolloutPhaseTimes,
}

/// Planner compute plus one reconcile tick at a fleet size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileSample {
    pub environments: u32,
    pub plan_ms: u64,
    pub tick_ms: u64,
}

/// Full harness report written to stdout by the scheduled job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutReport {
    pub samples: Vec<ScenarioSample>,
    pub reconcile: Vec<ReconcileSample>,
}

/// Stored runner baseline. Missing live keys skip the 20% comparison.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolloutBaseline {
    pub regression_ratio: f64,
    pub budgets: BaselineBudgets,
    #[serde(default)]
    pub docker: BTreeMap<String, BTreeMap<String, BTreeMap<String, RolloutPhaseTimes>>>,
    #[serde(default)]
    pub kubernetes_inprocess: BTreeMap<String, BTreeMap<String, RolloutPhaseTimes>>,
    #[serde(default)]
    pub planner: BTreeMap<String, u64>,
    #[serde(default)]
    pub reconcile: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineBudgets {
    pub noop_reapply_20_ms: u64,
    pub upgrade_overhead_ms: u64,
    pub reconcile_1000_ms: u64,
}

/// Path of the checked-in baseline next to this crate's `Cargo.toml`.
pub fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BASELINE_FILE)
}

/// Load `perf/rollout-baseline.json`.
pub fn load_baseline(path: &Path) -> Result<RolloutBaseline> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading rollout baseline {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parsing rollout baseline {}", path.display()))
}

/// Compare a report to published budgets and, when `gate` is [`Gate::Regression`],
/// to the stored runner baseline.
pub fn evaluate(report: &RolloutReport, baseline: &RolloutBaseline, gate: Gate) -> Result<()> {
    let mut failures = Vec::new();
    for sample in &report.samples {
        if sample.executor == "docker-live"
            && sample.services == 20
            && sample.scenario == "noop_reapply"
            && sample.phases.wall_ms() > baseline.budgets.noop_reapply_20_ms
        {
            failures.push(format!(
                "no-op re-apply of 20 services took {} ms (budget {} ms)",
                sample.phases.wall_ms(),
                baseline.budgets.noop_reapply_20_ms
            ));
        }
        if sample.executor == "docker-live"
            && sample.services == 20
            && sample.scenario == "one_service_upgrade"
        {
            let overhead = sample
                .phases
                .wall_ms()
                .saturating_sub(sample.phases.pull_ms)
                .saturating_sub(sample.phases.health_ms);
            if overhead > baseline.budgets.upgrade_overhead_ms {
                failures.push(format!(
                    "one-service upgrade overhead {} ms (budget {} ms)",
                    overhead, baseline.budgets.upgrade_overhead_ms
                ));
            }
        }
    }
    if gate == Gate::Regression {
        let ratio = if baseline.regression_ratio > 0.0 {
            baseline.regression_ratio
        } else {
            REGRESSION_RATIO
        };
        for sample in &report.samples {
            if let Some(stored) = baseline_phases(baseline, sample) {
                let limit = ((stored.wall_ms() as f64) * ratio).ceil() as u64;
                if sample.phases.wall_ms() > limit {
                    failures.push(format!(
                        "{} {} services {} took {} ms (>20% over baseline {} ms)",
                        sample.executor,
                        sample.services,
                        sample.scenario,
                        sample.phases.wall_ms(),
                        stored.wall_ms()
                    ));
                }
            }
        }
        for sample in &report.reconcile {
            if sample.environments == 1_000 && sample.tick_ms > baseline.budgets.reconcile_1000_ms {
                failures.push(format!(
                    "reconcile tick at 1000 environments took {} ms (budget {} ms)",
                    sample.tick_ms, baseline.budgets.reconcile_1000_ms
                ));
            }
            let key = sample.environments.to_string();
            if let Some(stored) = baseline.reconcile.get(&key) {
                let limit = ((*stored as f64) * ratio).ceil() as u64;
                if sample.tick_ms > limit {
                    failures.push(format!(
                        "reconcile {} took {} ms (>20% over baseline {stored} ms)",
                        sample.environments, sample.tick_ms
                    ));
                }
            }
            if let Some(stored) = baseline.planner.get(&key) {
                let limit = ((*stored as f64) * ratio).ceil() as u64;
                if sample.plan_ms > limit {
                    failures.push(format!(
                        "planner {} took {} ms (>20% over baseline {stored} ms)",
                        sample.environments, sample.plan_ms
                    ));
                }
            }
        }
    }
    if !failures.is_empty() {
        bail!("rollout-time gate failed: {}", failures.join("; "));
    }
    Ok(())
}

fn baseline_phases<'a>(
    baseline: &'a RolloutBaseline,
    sample: &ScenarioSample,
) -> Option<&'a RolloutPhaseTimes> {
    let services = sample.services.to_string();
    match sample.executor.as_str() {
        "docker-fake" | "docker-live" => {
            let mode = sample.executor.strip_prefix("docker-").unwrap_or("fake");
            baseline
                .docker
                .get(mode)
                .and_then(|by_count| by_count.get(&services))
                .and_then(|by_scenario| by_scenario.get(&sample.scenario))
        }
        "kubernetes-inprocess" => baseline
            .kubernetes_inprocess
            .get(&services)
            .and_then(|by_scenario| by_scenario.get(&sample.scenario)),
        _ => None,
    }
}

/// Human-readable report for CI logs.
pub fn format_report(report: &RolloutReport) -> String {
    let mut lines = Vec::new();
    for sample in &report.samples {
        lines.push(format!(
            "{} {} services {}: plan={}ms pull={}ms apply={}ms health={}ms record={}ms wall={}ms",
            sample.executor,
            sample.services,
            sample.scenario,
            sample.phases.plan_ms,
            sample.phases.pull_ms,
            sample.phases.apply_ms,
            sample.phases.health_ms,
            sample.phases.record_ms,
            sample.phases.wall_ms()
        ));
    }
    for sample in &report.reconcile {
        lines.push(format!(
            "reconcile {} environments: plan={}ms tick={}ms",
            sample.environments, sample.plan_ms, sample.tick_ms
        ));
    }
    lines.join("\n")
}

/// Time Docker apply phases for 1/5/20 services across the four scenarios.
pub fn measure_docker(
    executor: &DockerHostExecutor,
    executor_label: &str,
    image_a: &str,
    image_b: &str,
    root: &Path,
) -> Result<Vec<ScenarioSample>> {
    let mut samples = Vec::new();
    for services in SERVICE_COUNTS {
        samples.extend(measure_docker_count(
            executor,
            executor_label,
            services,
            image_a,
            image_b,
            root,
        )?);
    }
    Ok(samples)
}

fn measure_docker_count(
    executor: &DockerHostExecutor,
    executor_label: &str,
    services: u32,
    image_a: &str,
    image_b: &str,
    root: &Path,
) -> Result<Vec<ScenarioSample>> {
    let work_v1 = root.join(format!("d{services}-v1"));
    let work_v2 = root.join(format!("d{services}-v2"));
    write_docker_release(&work_v1, services, false, image_a, image_b)?;
    write_docker_release(&work_v2, services, true, image_a, image_b)?;
    let env = format!("r{}t{}s{services}", std::process::id(), crate::now_millis());
    // Distinct versions: container_mismatch also keys on tenkai.version and
    // tenkai.release-id, so a real one-image release still recreates every
    // container. The 5 s upgrade budget must include that work.
    let v1 = docker_request(&work_v1, &env, "1.0.0");
    let v2 = docker_request(&work_v2, &env, "2.0.0");
    let samples = vec![
        time_docker(executor, executor_label, "fresh_install", services, &v1)?,
        time_docker(executor, executor_label, "noop_reapply", services, &v1)?,
        time_docker(
            executor,
            executor_label,
            "one_service_upgrade",
            services,
            &v2,
        )?,
        time_docker(executor, executor_label, "rollback", services, &v1)?,
    ];
    let _ = executor.remove(&v1);
    Ok(samples)
}

fn time_docker(
    executor: &DockerHostExecutor,
    executor_label: &str,
    scenario: &str,
    services: u32,
    request: &SoftwareApplyRequest,
) -> Result<ScenarioSample> {
    let mut phases = executor.apply_with_phases(request)?;
    let recorded = Instant::now();
    executor.observe(request)?;
    phases.record_ms = recorded.elapsed().as_millis() as u64;
    Ok(ScenarioSample {
        scenario: scenario.into(),
        services,
        executor: executor_label.into(),
        phases,
    })
}

fn docker_request(workdir: &Path, env: &str, version: &str) -> SoftwareApplyRequest {
    request_from_parts(
        "rollout",
        version,
        env,
        workdir,
        format!("tenkai:release:rollout@{version}"),
    )
}

fn write_docker_release(
    workdir: &Path,
    services: u32,
    upgrade_first: bool,
    image_a: &str,
    image_b: &str,
) -> Result<()> {
    let docker_dir = workdir.join("docker");
    fs::create_dir_all(&docker_dir)
        .with_context(|| format!("creating {}", docker_dir.display()))?;
    let mut containers = Vec::new();
    for index in 1..=services {
        let image = if upgrade_first && index == 1 {
            image_b
        } else {
            image_a
        };
        containers.push(serde_json::json!({
            "name": format!("svc{index:02}"),
            "image": image,
            "networks": ["appnet"]
        }));
    }
    let topology = serde_json::json!({
        "networks": ["appnet"],
        "volumes": [],
        "containers": containers
    });
    fs::write(
        docker_dir.join("host.json"),
        serde_json::to_vec_pretty(&topology)?,
    )?;
    Ok(())
}

/// Install the fake Docker CLI into `root` and return `(script, state)`.
pub fn install_fake_docker(root: &Path) -> Result<(PathBuf, PathBuf)> {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/docker/fake-docker.py");
    let script = root.join("fake-docker");
    fs::copy(&fixture, &script)
        .with_context(|| format!("copying fake docker from {}", fixture.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }
    Ok((script, root.join("fake-state.json")))
}

/// Fake-CLI executor with isolated state.
pub fn fake_docker_executor(script: &Path, state: &Path) -> DockerHostExecutor {
    DockerHostExecutor::for_binary(script.to_path_buf()).with_env(
        "TENKAI_DOCKER_FAKE_STATE",
        state.to_string_lossy().into_owned(),
    )
}

/// Digest-pinned pause image for live Docker, pulling the tag if needed.
pub fn live_pause_image(tag: &str) -> Result<String> {
    let named = format!("registry.k8s.io/pause:{tag}");
    match inspect_repo_digest(&named) {
        Ok(digest) => Ok(digest),
        Err(_) => {
            let status = Command::new("docker")
                .args(["pull", &named])
                .status()
                .context("starting docker pull")?;
            if !status.success() {
                bail!("docker pull {named} failed");
            }
            inspect_repo_digest(&named)
        }
    }
}

fn inspect_repo_digest(image: &str) -> Result<String> {
    let output = Command::new("docker")
        .args([
            "image",
            "inspect",
            "--format",
            "{{index .RepoDigests 0}}",
            image,
        ])
        .output()
        .context("starting docker image inspect")?;
    if !output.status.success() {
        bail!(
            "docker image inspect {image} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let digest = String::from_utf8(output.stdout)?.trim().to_string();
    if digest.is_empty() || !digest.contains("@sha256:") {
        bail!("docker image {image} has no repo digest");
    }
    Ok(digest)
}

/// Whether a local Docker daemon answers `docker info`.
pub fn docker_daemon_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Planner compute plus one `run_once` tick at 100 and 1000 environments.
pub async fn measure_reconcile(root: &Path) -> Result<Vec<ReconcileSample>> {
    let mut samples = Vec::new();
    for count in RECONCILE_COUNTS {
        samples.push(measure_reconcile_count(root, count).await?);
    }
    Ok(samples)
}

async fn measure_reconcile_count(root: &Path, count: u32) -> Result<ReconcileSample> {
    let database = root.join(format!("reconcile-{count}.db"));
    let _ = fs::remove_file(&database);
    let mut ctx = Ctx::embedded(&database)?;
    crate::ontology::register(&mut ctx).await?;
    for index in 0..count {
        plan::env_add(&mut ctx, &format!("e{index:04}"), "rollout").await?;
    }
    let planned = Instant::now();
    for index in 0..count {
        plan::compute(&mut ctx, &format!("e{index:04}")).await?;
    }
    let plan_ms = planned.elapsed().as_millis() as u64;
    let reconciler = Reconciler::new(
        ctx,
        reconciler::Config {
            initial_backoff: std::time::Duration::from_millis(100),
            max_backoff: std::time::Duration::from_millis(250),
            max_concurrency: 8,
            skip_gates: false,
            unapproved_development_reason: Some("rollout-time".into()),
            ..reconciler::Config::default()
        },
    )?;
    let warmup = reconciler.run_once().await?;
    require_current_tick(&warmup, count, "reconcile warmup")?;
    let ticked = Instant::now();
    let report = reconciler.run_once().await?;
    let tick_ms = ticked.elapsed().as_millis() as u64;
    require_current_tick(&report, count, "reconcile tick")?;
    Ok(ReconcileSample {
        environments: count,
        plan_ms,
        tick_ms,
    })
}

fn require_current_tick(report: &TickReport, count: u32, label: &str) -> Result<()> {
    if report.environments.len() != count as usize {
        bail!(
            "{label} at {count} environments reported {}",
            report.environments.len()
        );
    }
    let not_current: Vec<String> = report
        .environments
        .iter()
        .filter(|result| result.status != EnvironmentStatus::Current)
        .map(|result| format!("{}={:?}", result.environment, result.status))
        .collect();
    if !not_current.is_empty() {
        bail!(
            "{label} at {count} environments was not Current: {}",
            not_current.join("; ")
        );
    }
    Ok(())
}

/// Time in-process Kubernetes apply phases. Callers supply the executor and workdirs.
pub fn time_kubernetes(
    apply: impl Fn(&SoftwareApplyRequest) -> Result<RolloutPhaseTimes>,
    observe: impl Fn(&SoftwareApplyRequest) -> Result<()>,
    executor_label: &str,
    scenario: &str,
    services: u32,
    request: &SoftwareApplyRequest,
) -> Result<ScenarioSample> {
    let mut phases = apply(request)?;
    let recorded = Instant::now();
    observe(request)?;
    phases.record_ms = recorded.elapsed().as_millis() as u64;
    Ok(ScenarioSample {
        scenario: scenario.into(),
        services,
        executor: executor_label.into(),
        phases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budgets() -> BaselineBudgets {
        BaselineBudgets {
            noop_reapply_20_ms: BUDGET_NOOP_REAPPLY_20_MS,
            upgrade_overhead_ms: BUDGET_UPGRADE_OVERHEAD_MS,
            reconcile_1000_ms: BUDGET_RECONCILE_1000_MS,
        }
    }

    const FAKE_IMAGE_A: &str = "registry.example/rollout/svc@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FAKE_IMAGE_B: &str = "registry.example/rollout/svc@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sample(scenario: &str, services: u32, executor: &str, wall_split: u64) -> ScenarioSample {
        ScenarioSample {
            scenario: scenario.into(),
            services,
            executor: executor.into(),
            phases: RolloutPhaseTimes {
                plan_ms: wall_split,
                pull_ms: wall_split,
                apply_ms: wall_split,
                health_ms: wall_split,
                record_ms: wall_split,
            },
        }
    }

    #[test]
    fn compare_fails_when_noop_exceeds_two_seconds() {
        let baseline = RolloutBaseline {
            regression_ratio: REGRESSION_RATIO,
            budgets: budgets(),
            docker: BTreeMap::new(),
            kubernetes_inprocess: BTreeMap::new(),
            planner: BTreeMap::new(),
            reconcile: BTreeMap::new(),
        };
        let mut over = sample("noop_reapply", 20, "docker-live", 500);
        over.phases.apply_ms = 3_000;
        let err = evaluate(
            &RolloutReport {
                samples: vec![over],
                reconcile: Vec::new(),
            },
            &baseline,
            Gate::Absolute,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no-op re-apply"), "{err}");
    }

    #[test]
    fn compare_fails_when_upgrade_overhead_exceeds_five_seconds() {
        let baseline = RolloutBaseline {
            regression_ratio: REGRESSION_RATIO,
            budgets: budgets(),
            docker: BTreeMap::new(),
            kubernetes_inprocess: BTreeMap::new(),
            planner: BTreeMap::new(),
            reconcile: BTreeMap::new(),
        };
        let over = ScenarioSample {
            scenario: "one_service_upgrade".into(),
            services: 20,
            executor: "docker-live".into(),
            phases: RolloutPhaseTimes {
                plan_ms: 1_000,
                pull_ms: 10,
                apply_ms: 5_000,
                health_ms: 10,
                record_ms: 1_000,
            },
        };
        let err = evaluate(
            &RolloutReport {
                samples: vec![over],
                reconcile: Vec::new(),
            },
            &baseline,
            Gate::Absolute,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("upgrade overhead"), "{err}");
    }

    #[test]
    fn compare_fails_on_twenty_percent_regression() {
        let mut docker = BTreeMap::new();
        let mut fake = BTreeMap::new();
        let mut by_count = BTreeMap::new();
        by_count.insert(
            "fresh_install".into(),
            RolloutPhaseTimes {
                plan_ms: 10,
                pull_ms: 10,
                apply_ms: 10,
                health_ms: 10,
                record_ms: 10,
            },
        );
        fake.insert("20".into(), by_count);
        docker.insert("live".into(), fake);
        let baseline = RolloutBaseline {
            regression_ratio: REGRESSION_RATIO,
            budgets: budgets(),
            docker,
            kubernetes_inprocess: BTreeMap::new(),
            planner: BTreeMap::new(),
            reconcile: BTreeMap::new(),
        };
        let over = sample("fresh_install", 20, "docker-live", 20);
        let err = evaluate(
            &RolloutReport {
                samples: vec![over],
                reconcile: Vec::new(),
            },
            &baseline,
            Gate::Regression,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(">20%"), "{err}");
        evaluate(
            &RolloutReport {
                samples: vec![sample("fresh_install", 20, "docker-live", 10)],
                reconcile: Vec::new(),
            },
            &baseline,
            Gate::Regression,
        )
        .unwrap();
    }

    #[test]
    fn one_service_upgrade_recreates_on_new_release_identity() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-rollout-one-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        fs::create_dir_all(&root).unwrap();
        let (script, state) = install_fake_docker(&root).unwrap();
        let executor = fake_docker_executor(&script, &state);
        let samples = measure_docker_count(
            &executor,
            "docker-fake",
            5,
            FAKE_IMAGE_A,
            FAKE_IMAGE_B,
            &root,
        )
        .unwrap();
        let log = fs::read_to_string(root.join("argv.log")).unwrap();
        let runs: Vec<&str> = log
            .lines()
            .filter(|line| line.starts_with(r#"["run""#))
            .collect();
        assert_eq!(
            runs.len(),
            15,
            "fresh 5 + upgrade 5 + rollback 5, got {}: {runs:?}",
            runs.len()
        );
        assert!(
            samples
                .iter()
                .any(|sample| sample.scenario == "one_service_upgrade"),
            "{samples:?}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn docker_fake_runs_all_scenarios() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-rollout-docker-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        fs::create_dir_all(&root).unwrap();
        let (script, state) = install_fake_docker(&root).unwrap();
        let executor = fake_docker_executor(&script, &state);
        let samples =
            measure_docker(&executor, "docker-fake", FAKE_IMAGE_A, FAKE_IMAGE_B, &root).unwrap();
        assert_eq!(samples.len(), SERVICE_COUNTS.len() * 4);
        let baseline = load_baseline(&baseline_path()).unwrap();
        let report = RolloutReport {
            samples,
            reconcile: Vec::new(),
        };
        println!("{}", format_report(&report));
        evaluate(&report, &baseline, Gate::Absolute).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reconcile_measurement_rejects_deferred_environments() {
        let report = TickReport {
            environments: vec![reconciler::EnvironmentResult {
                environment: "e0000".into(),
                status: EnvironmentStatus::Deferred { retry_at: 1 },
            }],
        };
        let err = require_current_tick(&report, 1, "reconcile warmup")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Deferred"), "{err}");
    }

    #[tokio::test]
    async fn reconcile_tick_meets_published_budget() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-rollout-reconcile-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        fs::create_dir_all(&root).unwrap();
        let reconcile = measure_reconcile(&root).await.unwrap();
        assert_eq!(reconcile.len(), RECONCILE_COUNTS.len());
        let baseline = load_baseline(&baseline_path()).unwrap();
        let report = RolloutReport {
            samples: Vec::new(),
            reconcile,
        };
        println!("{}", format_report(&report));
        assert!(
            report
                .reconcile
                .iter()
                .any(|sample| sample.environments == 1_000 && sample.tick_ms > 0),
            "{}",
            format_report(&report)
        );
        evaluate(&report, &baseline, Gate::from_env()).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn compare_fails_when_reconcile_tick_exceeds_one_second() {
        let baseline = RolloutBaseline {
            regression_ratio: REGRESSION_RATIO,
            budgets: budgets(),
            docker: BTreeMap::new(),
            kubernetes_inprocess: BTreeMap::new(),
            planner: BTreeMap::new(),
            reconcile: BTreeMap::new(),
        };
        let err = evaluate(
            &RolloutReport {
                samples: Vec::new(),
                reconcile: vec![ReconcileSample {
                    environments: 1_000,
                    plan_ms: 10,
                    tick_ms: 1_001,
                }],
            },
            &baseline,
            Gate::Regression,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("reconcile tick at 1000"), "{err}");
        evaluate(
            &RolloutReport {
                samples: Vec::new(),
                reconcile: vec![ReconcileSample {
                    environments: 1_000,
                    plan_ms: 10,
                    tick_ms: 1_001,
                }],
            },
            &baseline,
            Gate::Absolute,
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires a Docker daemon"]
    fn docker_live_against_runner_baseline() {
        assert!(
            docker_daemon_available(),
            "docker info must succeed for the live rollout-time job"
        );
        let root = std::env::temp_dir().join(format!(
            "tenkai-rollout-live-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        fs::create_dir_all(&root).unwrap();
        let image_a = live_pause_image("3.9").unwrap();
        let image_b = live_pause_image("3.10").unwrap();
        let executor = DockerHostExecutor::for_binary(PathBuf::from("docker"));
        let samples = measure_docker(&executor, "docker-live", &image_a, &image_b, &root).unwrap();
        let baseline = load_baseline(&baseline_path()).unwrap();
        let report = RolloutReport {
            samples,
            reconcile: Vec::new(),
        };
        println!("{}", format_report(&report));
        evaluate(&report, &baseline, Gate::from_env()).unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
