//! Fairness and failure isolation for the thousand-environment workload (#301).
//!
//! Failing synthetic environments must not starve the rest of the fleet or
//! manufacture success. Recovery uses Tenkai-owned backup only.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::environment;
use crate::fleet_workload::{self, WorkloadPlan, WorkloadPosture, WorkloadSpec};
use crate::reconciler::{EnvironmentStatus, Reconciler, TickReport};

const PROPERTY_POSTURE: &str = "synthetic_workload.posture";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessReport {
    pub seed_digest: String,
    pub first_failures: usize,
    pub second_failures: usize,
    pub failing_applied: usize,
    pub healthy_results: usize,
    pub backup_environments: usize,
}

pub fn format_report(report: &FairnessReport) -> String {
    format!(
        "fleet fairness seed_digest={} first_failures={} second_failures={} failing_applied={} healthy_results={} backup_environments={}",
        report.seed_digest,
        report.first_failures,
        report.second_failures,
        report.failing_applied,
        report.healthy_results,
        report.backup_environments
    )
}

pub async fn observe(
    ctx: &mut Ctx,
    spec: &WorkloadSpec,
    backup: &Path,
) -> Result<(WorkloadPlan, FairnessReport)> {
    let plan = fleet_workload::materialize(ctx, spec).await?;
    let reconciler = Reconciler::new(
        ctx.clone(),
        crate::reconciler::Config {
            skip_gates: false,
            unapproved_development_reason: None,
            ..crate::reconciler::Config::default()
        },
    )?;
    let first = reconciler.run_once().await?;
    let second = reconciler.run_once().await?;
    let postures = stored_postures(ctx).await?;
    let failing_applied =
        count_failing_applied(&first, &postures) + count_failing_applied(&second, &postures);
    if failing_applied > 0 {
        bail!("failing environments manufactured success ({failing_applied} applied)");
    }
    let healthy_results = count_healthy_results(&first, &postures);
    if healthy_results == 0 {
        bail!("failing environments starved healthy work");
    }
    ctx.backup_embedded(backup)?;
    let mut restored = Ctx::embedded(backup)?;
    crate::ontology::register(&mut restored).await?;
    let backup_environments =
        fleet_workload::stored_posture_counts(&mut restored, &plan.seed_digest)
            .await?
            .values()
            .copied()
            .sum::<u32>() as usize;
    if backup_environments != plan.members.len() {
        bail!(
            "backup recovered {backup_environments} synthetic environments, expected {}",
            plan.members.len()
        );
    }
    Ok((
        plan.clone(),
        FairnessReport {
            seed_digest: plan.seed_digest,
            first_failures: first.failures(),
            second_failures: second.failures(),
            failing_applied,
            healthy_results,
            backup_environments,
        },
    ))
}

async fn stored_postures(ctx: &mut Ctx) -> Result<BTreeMap<String, WorkloadPosture>> {
    let mut postures = BTreeMap::new();
    for entry in environment::list_environments(ctx).await? {
        let object = environment::environment(ctx, &entry.name).await?;
        let Some(value) = object.properties.get(PROPERTY_POSTURE) else {
            continue;
        };
        postures.insert(entry.name, WorkloadPosture::parse(value)?);
    }
    Ok(postures)
}

fn is_failing(posture: WorkloadPosture) -> bool {
    matches!(
        posture,
        WorkloadPosture::Unhealthy | WorkloadPosture::Blocked
    )
}

fn count_failing_applied(tick: &TickReport, postures: &BTreeMap<String, WorkloadPosture>) -> usize {
    tick.environments
        .iter()
        .filter(|result| {
            postures
                .get(&result.environment)
                .is_some_and(|posture| is_failing(*posture))
                && matches!(result.status, EnvironmentStatus::Applied { .. })
        })
        .count()
}

fn count_healthy_results(tick: &TickReport, postures: &BTreeMap<String, WorkloadPosture>) -> usize {
    tick.environments
        .iter()
        .filter(|result| {
            postures.get(&result.environment).is_some_and(|posture| {
                matches!(
                    posture,
                    WorkloadPosture::Current
                        | WorkloadPosture::Behind
                        | WorkloadPosture::Disconnected
                )
            })
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::PublishOptions;
    use crate::client::Ctx;
    use crate::fleet_workload::WORKLOAD_SIZE;

    fn spec() -> WorkloadSpec {
        WorkloadSpec {
            seed: "fair-seed".into(),
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

    #[tokio::test]
    async fn failing_envs_do_not_starve_or_false_succeed_and_backup_restores() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-fair-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        publish_signed(&mut ctx, &root, "1.0.0").await;
        publish_signed(&mut ctx, &root, "1.1.0").await;
        let actor = crate::auth_context::test_management_context("fair");
        crate::catalog::promote(&mut ctx, &actor, "scale-app@1.1.0", "stable")
            .await
            .unwrap();
        let backup = root.join("backup.db");
        let (plan, report) = observe(&mut ctx, &spec(), &backup).await.unwrap();
        assert_eq!(plan.members.len(), WORKLOAD_SIZE as usize);
        assert_eq!(report.failing_applied, 0);
        assert!(report.healthy_results > 0);
        assert_eq!(report.backup_environments, WORKLOAD_SIZE as usize);
        let text = format_report(&report);
        assert!(text.contains("failing_applied=0"), "{text}");
        let _ = std::fs::remove_dir_all(root);
    }
}
