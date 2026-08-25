//! Named-profile budget harness for the thousand-environment workload (#300).
//!
//! Measurement never skips signing, approval, or gates. A budget miss fails
//! closed and does not widen support claims.

use std::path::Path;
use std::time::Instant;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::fleet_workload::{self, WorkloadPlan, WorkloadSpec};
use crate::reconciler::{self, Reconciler};

pub const PROFILE: &str = "ci-embedded-sqlite";
pub const SAMPLE_COUNT: usize = 2;
pub const COMMAND: &str = "tenkaictl fleet measure";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub wall_ms: u64,
    pub cpu_ms: u64,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
}

impl ResourceBudget {
    pub fn ci_embedded_sqlite() -> Self {
        Self {
            wall_ms: 180_000,
            cpu_ms: 180_000,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            storage_bytes: 512 * 1024 * 1024,
        }
    }

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
    lines.join("\n")
}

pub async fn measure(
    ctx: &mut Ctx,
    spec: &WorkloadSpec,
    database: &Path,
    budget: &ResourceBudget,
) -> Result<(WorkloadPlan, BudgetReport)> {
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
    let mut samples = Vec::new();
    for _ in 0..SAMPLE_COUNT {
        samples.push(sample_tick(&reconciler, database).await?);
    }
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
    let mut limiting = None;
    for sample in &samples {
        if sample.wall_ms > budget.wall_ms {
            limiting = Some("wall".into());
        } else if sample.cpu_ms > budget.cpu_ms {
            limiting = Some("cpu".into());
        } else if sample.memory_bytes > budget.memory_bytes {
            limiting = Some("memory".into());
        } else if sample.storage_bytes > budget.storage_bytes {
            limiting = Some("storage".into());
        }
    }
    let report = BudgetReport {
        profile: PROFILE.into(),
        command: COMMAND.into(),
        seed_digest: plan.seed_digest.clone(),
        skip_gates: false,
        samples,
        wall_ms_variance,
        passed: limiting.is_none(),
        limiting_resource: limiting.clone(),
    };
    if !report.passed {
        bail!(
            "budget breach on profile {PROFILE}: limiting {}",
            limiting.unwrap_or_else(|| "unknown".into())
        );
    }
    Ok((plan, report))
}

async fn sample_tick(reconciler: &Reconciler, database: &Path) -> Result<BudgetSample> {
    let before = resource_usage()?;
    let started = Instant::now();
    let tick = reconciler.run_once().await?;
    let wall_ms = started.elapsed().as_millis() as u64;
    let after = resource_usage()?;
    let storage_bytes = std::fs::metadata(database)?.len();
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
        let memory_bytes = if cfg!(target_os = "linux") {
            (usage.ru_maxrss as u64).saturating_mul(1024)
        } else {
            usage.ru_maxrss as u64
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
    use crate::catalog::PublishOptions;
    use crate::client::Ctx;
    use crate::fleet_workload::WORKLOAD_SIZE;

    fn spec() -> WorkloadSpec {
        WorkloadSpec {
            seed: "budget-seed".into(),
            product: "scale-app".into(),
            channel: "stable".into(),
            current_version: "1.1.0".into(),
            behind_version: "1.0.0".into(),
        }
    }

    async fn publish_signed(ctx: &mut Ctx, root: &std::path::Path, version: &str) {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "scale-app"
version = "{version}"

[deploy]
install = "true"
"#
            ),
        )
        .unwrap();
        let keys = root.join("keys");
        let signature = dir.join("release.sig.json");
        let trust = dir.join("release-trust.toml");
        crate::dev_sign::sign_release(&keys, &dir.join("tenkai.toml"), &signature, &trust).unwrap();
        crate::catalog::publish(
            ctx,
            &dir.join("tenkai.toml"),
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                allow_unsigned_development: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
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

    #[tokio::test]
    async fn two_ticks_stay_under_budget_without_skipping_gates() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-budget-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        publish_signed(&mut ctx, &root, "1.0.0").await;
        publish_signed(&mut ctx, &root, "1.1.0").await;
        let actor = crate::auth_context::test_management_context("budget");
        crate::catalog::promote(&mut ctx, &actor, "scale-app@1.1.0", "stable")
            .await
            .unwrap();
        let budget = ResourceBudget::ci_embedded_sqlite();
        let (plan, report) = measure(&mut ctx, &spec(), &database, &budget)
            .await
            .unwrap();
        assert_eq!(plan.members.len(), WORKLOAD_SIZE as usize);
        assert_eq!(report.samples.len(), SAMPLE_COUNT);
        assert!(!report.skip_gates);
        assert_eq!(report.profile, PROFILE);
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
