//! Named-profile budget harness for the synthetic environment workload (#300).
//!
//! Measurement never skips signing, approval, or gates. A budget miss fails
//! closed and does not widen support claims. A profile names the store the
//! fleet runs on; the host passes a [`StoreProbe`] for that store, so the
//! embedded SQLite file and the Postgres hub (#1084) share one harness.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::fleet_workload::{self, WorkloadPlan, WorkloadSpec};
use crate::reconciler::{self, Reconciler};

pub const SAMPLE_COUNT: usize = 2;
pub const COMMAND: &str = "tenkaictl fleet measure";

/// A named measurement profile: the store under test and its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Embedded SQLite file, as `tenkaictl fleet measure` runs it.
    CiEmbeddedSqlite,
    /// One tenant schema on the Postgres hub store, on the CI Postgres 17
    /// service. Measurement evidence, not a support or HA claim.
    CiHubPostgres,
}

impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Self::CiEmbeddedSqlite => "ci-embedded-sqlite",
            Self::CiHubPostgres => "ci-hub-postgres",
        }
    }

    /// The hub copies the SQLite budget until measured hub numbers replace
    /// it (#1084 decision).
    pub fn budget(self) -> ResourceBudget {
        match self {
            Self::CiEmbeddedSqlite | Self::CiHubPostgres => ResourceBudget {
                wall_ms: 180_000,
                cpu_ms: 180_000,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                storage_bytes: 512 * 1024 * 1024,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub wall_ms: u64,
    pub cpu_ms: u64,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
}

impl ResourceBudget {
    pub fn validate(&self) -> Result<()> {
        if self.wall_ms == 0
            || self.cpu_ms == 0
            || self.memory_bytes == 0
            || self.storage_bytes == 0
        {
            bail!("resource budgets must be greater than zero");
        }
        Ok(())
    }
}

/// Reads the store a profile measures. Called between ticks, never during one.
pub trait StoreProbe {
    /// Bytes the fleet occupies in the store.
    fn storage_bytes(&self) -> Result<u64>;

    /// Cumulative database-server counters; `None` for a store without a
    /// server, such as an embedded file.
    fn database_load(&self) -> Result<Option<DatabaseLoad>> {
        Ok(None)
    }
}

/// The embedded profile's store: one SQLite file.
pub struct SqliteFile<'a>(pub &'a Path);

impl StoreProbe for SqliteFile<'_> {
    fn storage_bytes(&self) -> Result<u64> {
        Ok(std::fs::metadata(self.0)?.len())
    }
}

/// Database-server work, as counters or as the difference of two readings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseLoad {
    pub transactions: u64,
    pub rows_read: u64,
    pub rows_written: u64,
    pub blocks_read: u64,
    pub blocks_hit: u64,
}

impl DatabaseLoad {
    fn since(self, before: Self) -> Self {
        Self {
            transactions: self.transactions.saturating_sub(before.transactions),
            rows_read: self.rows_read.saturating_sub(before.rows_read),
            rows_written: self.rows_written.saturating_sub(before.rows_written),
            blocks_read: self.blocks_read.saturating_sub(before.blocks_read),
            blocks_hit: self.blocks_hit.saturating_sub(before.blocks_hit),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSample {
    pub wall_ms: u64,
    pub cpu_ms: u64,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    pub environments: usize,
    pub tick_failures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetReport {
    pub profile: String,
    pub command: String,
    pub seed_digest: String,
    pub skip_gates: bool,
    pub samples: Vec<BudgetSample>,
    pub wall_ms_variance: u64,
    pub passed: bool,
    pub limiting_resource: Option<String>,
    /// Server work across all samples; absent for an embedded store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_load: Option<DatabaseLoad>,
}

pub fn format_report(report: &BudgetReport) -> String {
    let mut lines = vec![format!(
        "fleet budget profile={} seed_digest={} samples={} passed={} skip_gates={}",
        report.profile,
        report.seed_digest,
        report.samples.len(),
        report.passed,
        report.skip_gates
    )];
    for (index, sample) in report.samples.iter().enumerate() {
        lines.push(format!(
            "  sample{} wall_ms={} cpu_ms={} memory_bytes={} storage_bytes={} environments={} tick_failures={}",
            index + 1,
            sample.wall_ms,
            sample.cpu_ms,
            sample.memory_bytes,
            sample.storage_bytes,
            sample.environments,
            sample.tick_failures
        ));
    }
    lines.push(format!(
        "  wall_ms_variance={} limiting={}",
        report.wall_ms_variance,
        report.limiting_resource.as_deref().unwrap_or("none")
    ));
    if let Some(load) = report.database_load {
        lines.push(format!(
            "  database_load transactions={} rows_read={} rows_written={} blocks_read={} blocks_hit={}",
            load.transactions, load.rows_read, load.rows_written, load.blocks_read, load.blocks_hit
        ));
    }
    lines.join("\n")
}

/// Materialize `spec` and time [`SAMPLE_COUNT`] reconcile ticks against the
/// profile budget, with gates enabled. A budget miss is an error.
pub async fn measure(
    ctx: &mut Ctx,
    spec: &WorkloadSpec,
    profile: Profile,
    store: &impl StoreProbe,
) -> Result<(WorkloadPlan, BudgetReport)> {
    let budget = profile.budget();
    budget.validate()?;
    let plan = fleet_workload::materialize(ctx, spec).await?;
    let reconciler = Reconciler::new(
        ctx.clone(),
        reconciler::Config {
            skip_gates: false,
            unapproved_development_reason: None,
            max_concurrency: 8,
            ..reconciler::Config::default()
        },
    )?;
    let load_before = store.database_load()?;
    let mut samples = Vec::new();
    for _ in 0..SAMPLE_COUNT {
        samples.push(sample_tick(&reconciler, store).await?);
    }
    let database_load = match (load_before, store.database_load()?) {
        (Some(before), Some(after)) => Some(after.since(before)),
        _ => None,
    };
    let wall_ms_variance = samples
        .iter()
        .map(|sample| sample.wall_ms)
        .max()
        .unwrap_or(0)
        .saturating_sub(
            samples
                .iter()
                .map(|sample| sample.wall_ms)
                .min()
                .unwrap_or(0),
        );
    let limiting = limiting_resource(&samples, &budget).map(String::from);
    let report = BudgetReport {
        profile: profile.name().into(),
        command: COMMAND.into(),
        seed_digest: plan.seed_digest.clone(),
        skip_gates: false,
        samples,
        wall_ms_variance,
        passed: limiting.is_none(),
        limiting_resource: limiting.clone(),
        database_load,
    };
    if !report.passed {
        bail!(
            "budget breach on profile {}: limiting {}",
            profile.name(),
            limiting.unwrap_or_else(|| "unknown".into())
        );
    }
    Ok((plan, report))
}

/// Register the ontology, publish `spec`'s behind and current versions
/// signed, and promote current onto the channel: what `measure` needs
/// before it can materialize. Signing material is written under `root`.
#[cfg(any(test, feature = "test-support"))]
pub async fn seed_signed_channel(ctx: &mut Ctx, root: &Path, spec: &WorkloadSpec) -> Result<()> {
    use crate::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
    };
    crate::ontology::register(ctx).await?;
    for version in [&spec.behind_version, &spec.current_version] {
        crate::dev_sign::publish_signed_product(ctx, root, version, &spec.product).await?;
    }
    let actor = AuthenticatedRequestContextBuilder::new(
        "fleet-budget-seed",
        PrincipalIdentity {
            id: "management".into(),
            kind: PrincipalKind::Management,
        },
        "fleet-budget",
    )
    .build()?;
    crate::catalog::promote(
        ctx,
        &actor,
        &format!("{}@{}", spec.product, spec.current_version),
        &spec.channel,
    )
    .await?;
    Ok(())
}

/// The resource a sample exceeds, from the last sample that exceeds any;
/// `None` when every sample fits the budget.
fn limiting_resource(samples: &[BudgetSample], budget: &ResourceBudget) -> Option<&'static str> {
    samples.iter().rev().find_map(|sample| {
        if sample.wall_ms > budget.wall_ms {
            Some("wall")
        } else if sample.cpu_ms > budget.cpu_ms {
            Some("cpu")
        } else if sample.memory_bytes > budget.memory_bytes {
            Some("memory")
        } else if sample.storage_bytes > budget.storage_bytes {
            Some("storage")
        } else {
            None
        }
    })
}

/// Committed per-tick wall-time baseline for a profile, keyed by fleet size
/// (`perf/hub-fleet-baseline.json`), measured on the CI runner class. The
/// scheduled job (`TENKAI_ROLLOUT_GATE=regression`) fails when a tick is more
/// than `regression_ratio` over its stored time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetBaseline {
    pub profile: String,
    pub regression_ratio: f64,
    pub tick_ms: BTreeMap<String, u64>,
}

pub fn load_baseline(path: &Path) -> Result<FleetBaseline> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading fleet baseline {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing fleet baseline {}", path.display()))
}

/// Compare every sample tick to the stored baseline for its fleet size. A
/// size with no stored time, or a baseline for another profile, fails closed.
pub fn check_baseline(report: &BudgetReport, baseline: &FleetBaseline) -> Result<()> {
    if baseline.profile != report.profile {
        bail!(
            "fleet baseline is for profile {}, report is {}",
            baseline.profile,
            report.profile
        );
    }
    if baseline.regression_ratio < 1.0 {
        bail!("fleet baseline regression_ratio must be at least 1.0");
    }
    let mut failures = Vec::new();
    for sample in &report.samples {
        let size = sample.environments.to_string();
        let Some(stored) = baseline.tick_ms.get(&size) else {
            bail!("fleet baseline has no tick time for {size} environments");
        };
        let limit = ((*stored as f64) * baseline.regression_ratio).ceil() as u64;
        if sample.wall_ms > limit {
            failures.push(format!(
                "tick at {size} environments took {} ms (limit {limit} ms from baseline {stored} ms)",
                sample.wall_ms
            ));
        }
    }
    if !failures.is_empty() {
        bail!(
            "fleet regression on profile {}: {}",
            report.profile,
            failures.join("; ")
        );
    }
    Ok(())
}

/// One tick's resources. CPU and peak memory are this process's, so the
/// sample means the tick's own cost only when nothing else runs in the
/// process, as in `tenkaictl fleet measure` (#1235).
async fn sample_tick(reconciler: &Reconciler, store: &impl StoreProbe) -> Result<BudgetSample> {
    let before = resource_usage()?;
    let started = Instant::now();
    let tick = reconciler.run_once().await?;
    let wall_ms = started.elapsed().as_millis() as u64;
    let after = resource_usage()?;
    let storage_bytes = store.storage_bytes()?;
    Ok(BudgetSample {
        wall_ms,
        cpu_ms: after.0.saturating_sub(before.0),
        memory_bytes: after.1,
        storage_bytes,
        environments: tick.environments.len(),
        tick_failures: tick.failures(),
    })
}

fn resource_usage() -> Result<(u64, u64)> {
    // SAFETY: `usage` is a zeroed `rusage` written only by getrusage.
    unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            bail!("failed to read process resource usage");
        }
        let cpu_ms = timeval_ms(&usage.ru_utime).saturating_add(timeval_ms(&usage.ru_stime));
        // Apple systems report `ru_maxrss` in bytes; other Unix systems in
        // kilobytes.
        let memory_bytes = if cfg!(target_vendor = "apple") {
            usage.ru_maxrss as u64
        } else {
            (usage.ru_maxrss as u64).saturating_mul(1024)
        };
        Ok((cpu_ms, memory_bytes))
    }
}

fn timeval_ms(time: &libc::timeval) -> u64 {
    (time.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((time.tv_usec as u64) / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_workload::WORKLOAD_SIZE;

    fn spec() -> WorkloadSpec {
        WorkloadSpec {
            seed: "budget-seed".into(),
            product: "scale-app".into(),
            channel: "stable".into(),
            current_version: "1.1.0".into(),
            behind_version: "1.0.0".into(),
            environments: WORKLOAD_SIZE,
        }
    }

    #[test]
    fn zero_budget_fails_closed() {
        let err = ResourceBudget {
            wall_ms: 0,
            cpu_ms: 1,
            memory_bytes: 1,
            storage_bytes: 1,
        }
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("greater than zero"), "{err}");
    }

    #[test]
    fn a_sample_over_budget_names_the_limiting_resource() {
        let budget = Profile::CiEmbeddedSqlite.budget();
        let within = BudgetSample {
            wall_ms: 1,
            cpu_ms: 1,
            memory_bytes: 1,
            storage_bytes: 1,
            environments: 1,
            tick_failures: 0,
        };
        assert_eq!(
            limiting_resource(std::slice::from_ref(&within), &budget),
            None
        );
        let over_cpu = BudgetSample {
            cpu_ms: budget.cpu_ms + 1,
            ..within.clone()
        };
        assert_eq!(
            limiting_resource(&[within.clone(), over_cpu], &budget),
            Some("cpu")
        );
        let over_memory = BudgetSample {
            memory_bytes: budget.memory_bytes + 1,
            ..within
        };
        assert_eq!(limiting_resource(&[over_memory], &budget), Some("memory"));
    }

    #[test]
    fn baseline_gate_fails_closed_on_regression_unknown_size_or_profile() {
        let sample = BudgetSample {
            wall_ms: 130,
            cpu_ms: 1,
            memory_bytes: 1,
            storage_bytes: 1,
            environments: 100,
            tick_failures: 0,
        };
        let report = BudgetReport {
            profile: Profile::CiHubPostgres.name().into(),
            command: COMMAND.into(),
            seed_digest: "sha256:seed".into(),
            skip_gates: false,
            samples: vec![sample.clone()],
            wall_ms_variance: 0,
            passed: true,
            limiting_resource: None,
            database_load: None,
        };
        let baseline = FleetBaseline {
            profile: Profile::CiHubPostgres.name().into(),
            regression_ratio: 1.2,
            tick_ms: BTreeMap::from([("100".to_string(), 100)]),
        };
        let err = check_baseline(&report, &baseline).unwrap_err().to_string();
        assert!(err.contains("130 ms (limit 120 ms"), "{err}");

        let within = BudgetReport {
            samples: vec![BudgetSample {
                wall_ms: 120,
                ..sample.clone()
            }],
            ..report.clone()
        };
        check_baseline(&within, &baseline).unwrap();

        let unknown_size = BudgetReport {
            samples: vec![BudgetSample {
                environments: 5,
                ..sample
            }],
            ..report.clone()
        };
        let err = check_baseline(&unknown_size, &baseline)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no tick time for 5"), "{err}");

        let other_profile = BudgetReport {
            profile: Profile::CiEmbeddedSqlite.name().into(),
            ..within
        };
        let err = check_baseline(&other_profile, &baseline)
            .unwrap_err()
            .to_string();
        assert!(err.contains("is for profile ci-hub-postgres"), "{err}");
    }

    #[test]
    fn committed_hub_baseline_parses_for_its_profile() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("perf/hub-fleet-baseline.json");
        let baseline = load_baseline(&path).unwrap();
        assert_eq!(baseline.profile, Profile::CiHubPostgres.name());
        assert!(baseline.regression_ratio >= 1.0);
    }

    const MEASURE_ALONE: &str = "fleet_budget::tests::budget_measurement_in_its_own_process";

    /// CPU and peak memory are read for the whole process, so the measurement
    /// runs alone in a child process of this test binary. Tests running
    /// beside this one cannot push it over the budget (#1235).
    #[test]
    fn two_ticks_stay_under_budget_without_skipping_gates() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", MEASURE_ALONE, "--ignored", "--nocapture"])
            .args(["--test-threads", "1"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        // A filter that matched nothing also exits successfully.
        assert!(stdout.contains("1 passed"), "{stdout}\n{stderr}");
    }

    #[tokio::test]
    #[ignore = "run alone by two_ticks_stay_under_budget_without_skipping_gates"]
    async fn budget_measurement_in_its_own_process() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-budget-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        seed_signed_channel(&mut ctx, &root, &spec()).await.unwrap();
        let (plan, report) = measure(
            &mut ctx,
            &spec(),
            Profile::CiEmbeddedSqlite,
            &SqliteFile(&database),
        )
        .await
        .unwrap();
        assert_eq!(plan.members.len(), WORKLOAD_SIZE as usize);
        assert_eq!(report.samples.len(), SAMPLE_COUNT);
        assert!(!report.skip_gates);
        assert_eq!(report.profile, Profile::CiEmbeddedSqlite.name());
        assert_eq!(report.database_load, None);
        assert!(report.passed);
        assert!(
            report
                .samples
                .iter()
                .all(|sample| sample.environments == WORKLOAD_SIZE as usize)
        );
        let text = format_report(&report);
        assert!(text.contains("passed=true"), "{text}");
        assert!(text.contains("skip_gates=false"), "{text}");
        let _ = std::fs::remove_dir_all(root);
    }
}
