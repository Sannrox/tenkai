//! Fairness and failure isolation for the thousand-environment workload (#301).
//!
//! Failing synthetic environments make only bounded retry progress. Healthy
//! cohorts must still plan. Recovery uses Tenkai-owned backup; a failed restore
//! does not rewrite live fleet state.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::environment;
use crate::fleet_workload::{self, WORKLOAD_SIZE, WorkloadPlan, WorkloadPosture, WorkloadSpec};
use crate::plan;
use crate::reconcile_fence::{FenceAdmission, ReconcileTickFence, SharedReconcileFence};
use crate::reconciler::{EnvironmentStatus, Reconciler, TickReport};
use crate::runtime_delivery::{RuntimeCompletion, RuntimeStepReceipt};

const PROPERTY_POSTURE: &str = "synthetic_workload.posture";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessReport {
    pub seed_digest: String,
    pub behind_progressed: usize,
    pub healthy_starved: usize,
    pub failing_applied: usize,
    pub deferred_failing: usize,
    pub runtime_waiting: usize,
    pub fence_busy: usize,
    pub rollback_isolated: bool,
    pub conflicting_receipt_rejected: bool,
    pub failed_restore_explicit: bool,
    pub backup_environments: usize,
}

pub fn format_report(report: &FairnessReport) -> String {
    format!(
        "fleet fairness seed_digest={} behind_progressed={} healthy_starved={} failing_applied={} deferred_failing={} runtime_waiting={} fence_busy={} rollback_isolated={} conflicting_receipt_rejected={} failed_restore_explicit={} backup_environments={}",
        report.seed_digest,
        report.behind_progressed,
        report.healthy_starved,
        report.failing_applied,
        report.deferred_failing,
        report.runtime_waiting,
        report.fence_busy,
        report.rollback_isolated,
        report.conflicting_receipt_rejected,
        report.failed_restore_explicit,
        report.backup_environments
    )
}

pub fn status_is_plan_progress(status: &EnvironmentStatus) -> bool {
    matches!(
        status,
        EnvironmentStatus::Applied { .. }
            | EnvironmentStatus::AwaitingApproval { .. }
            | EnvironmentStatus::AwaitingRuntime { .. }
    )
}

pub fn status_is_backoff(status: &EnvironmentStatus) -> bool {
    matches!(
        status,
        EnvironmentStatus::Deferred { .. } | EnvironmentStatus::Failed { .. }
    )
}

pub async fn observe(
    ctx: &mut Ctx,
    spec: &WorkloadSpec,
    backup: &Path,
    database: &Path,
) -> Result<(WorkloadPlan, FairnessReport)> {
    let plan = fleet_workload::materialize(ctx, spec).await?;
    let postures = stored_postures(ctx).await?;
    let behind = members_with(&plan, WorkloadPosture::Behind);
    let held = behind
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("workload is missing a behind environment"))?;
    let runtime_waiting_names = behind.iter().skip(1).cloned().collect::<Vec<_>>();
    let current = members_with(&plan, WorkloadPosture::Current)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("workload is missing a current environment"))?;

    let fence = SharedReconcileFence::new().into_arc();
    let now = crate::now_millis();
    match fence.try_begin(&held, "fairness-hold", now, 60_000)? {
        FenceAdmission::Started { .. } => {}
        other => bail!("failed to hold reconcile fence: {other:?}"),
    }

    let reconciler = Reconciler::new(
        ctx.clone(),
        crate::reconciler::Config {
            skip_gates: false,
            unapproved_development_reason: None,
            initial_backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(60),
            ..crate::reconciler::Config::default()
        },
    )?
    .with_runtime_environments(
        runtime_waiting_names
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
    )
    .with_shared_fence(fence);

    let first = reconciler.run_once().await?;
    let rollback_isolated = plan::rollback_step(ctx, &current, &plan.product)
        .await
        .is_err();
    let second = reconciler.run_once().await?;

    let failing_applied = count_matching(&first, &postures, is_failing, |status| {
        matches!(status, EnvironmentStatus::Applied { .. })
    }) + count_matching(&second, &postures, is_failing, |status| {
        matches!(status, EnvironmentStatus::Applied { .. })
    });
    if failing_applied > 0 {
        bail!("failing environments manufactured success ({failing_applied} applied)");
    }

    let behind_progressed = count_named(&first, &behind, status_is_plan_progress);
    if behind_progressed == 0 {
        bail!("behind cohort did not progress while failing environments were present");
    }

    let healthy_starved = count_matching(&second, &postures, is_healthy, status_is_backoff);
    if healthy_starved > 0 {
        bail!("failing environments starved {healthy_starved} healthy environment(s)");
    }

    let deferred_failing = count_matching(
        &second,
        &postures,
        is_failing,
        |status| matches!(status, EnvironmentStatus::Deferred { retry_at } if *retry_at > crate::now_millis()),
    );
    if deferred_failing == 0 {
        bail!("failing environments did not enter bounded retry backoff");
    }

    let runtime_waiting = count_named(&first, &runtime_waiting_names, |status| {
        matches!(status, EnvironmentStatus::AwaitingRuntime { .. })
    });
    let fence_busy = first
        .environments
        .iter()
        .filter(|result| {
            result.environment == held && matches!(result.status, EnvironmentStatus::Busy)
        })
        .count();
    if fence_busy != 1 {
        bail!("held fencing generation did not reject the overlapping tick");
    }

    let Some(progress) = first
        .environments
        .iter()
        .find(|result| matches!(result.status, EnvironmentStatus::AwaitingApproval { .. }))
    else {
        bail!("behind cohort produced no awaiting-approval plan to bind receipts");
    };
    let EnvironmentStatus::AwaitingApproval { plan_id, .. } = &progress.status else {
        unreachable!("filtered awaiting-approval");
    };
    let conflicting_receipt_rejected =
        reject_conflicting_completion(ctx, &progress.environment, plan_id).await?;
    ctx.backup_embedded(backup)?;
    let failed_restore_explicit = failed_restore_is_explicit(backup)?;
    Ctx::embedded(database).map_err(|error| {
        anyhow::anyhow!("live fleet store was damaged by the failed restore: {error}")
    })?;
    let mut restored = Ctx::embedded(backup)?;
    crate::ontology::register(&mut restored).await?;
    let backup_environments =
        fleet_workload::stored_posture_counts(&mut restored, &plan.seed_digest)
            .await?
            .values()
            .copied()
            .sum::<u32>() as usize;
    if backup_environments != WORKLOAD_SIZE as usize {
        bail!(
            "backup recovered {backup_environments} synthetic environments, expected {WORKLOAD_SIZE}"
        );
    }
    let live = fleet_workload::stored_posture_counts(ctx, &plan.seed_digest)
        .await?
        .values()
        .copied()
        .sum::<u32>() as usize;
    if live != WORKLOAD_SIZE as usize {
        bail!("live fleet lost synthetic environments after a failed restore attempt");
    }

    if behind_progressed as u32 + deferred_failing as u32 == 0 {
        bail!("workload produced no progress and no backoff");
    }

    Ok((
        plan.clone(),
        FairnessReport {
            seed_digest: plan.seed_digest,
            behind_progressed,
            healthy_starved,
            failing_applied,
            deferred_failing,
            runtime_waiting,
            fence_busy,
            rollback_isolated,
            conflicting_receipt_rejected,
            failed_restore_explicit,
            backup_environments,
        },
    ))
}

fn members_with(plan: &WorkloadPlan, posture: WorkloadPosture) -> Vec<String> {
    plan.members
        .iter()
        .filter(|member| member.posture == posture)
        .map(|member| member.name.clone())
        .collect()
}

fn is_failing(posture: WorkloadPosture) -> bool {
    matches!(
        posture,
        WorkloadPosture::Unhealthy | WorkloadPosture::Blocked
    )
}

fn is_healthy(posture: WorkloadPosture) -> bool {
    matches!(
        posture,
        WorkloadPosture::Current | WorkloadPosture::Behind | WorkloadPosture::Disconnected
    )
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

fn count_matching(
    tick: &TickReport,
    postures: &BTreeMap<String, WorkloadPosture>,
    posture_ok: fn(WorkloadPosture) -> bool,
    status_ok: fn(&EnvironmentStatus) -> bool,
) -> usize {
    tick.environments
        .iter()
        .filter(|result| {
            postures
                .get(&result.environment)
                .is_some_and(|posture| posture_ok(*posture))
                && status_ok(&result.status)
        })
        .count()
}

fn count_named(
    tick: &TickReport,
    names: &[String],
    status_ok: fn(&EnvironmentStatus) -> bool,
) -> usize {
    let set = names.iter().cloned().collect::<BTreeSet<_>>();
    tick.environments
        .iter()
        .filter(|result| set.contains(&result.environment) && status_ok(&result.status))
        .count()
}

async fn reject_conflicting_completion(
    ctx: &mut Ctx,
    environment: &str,
    plan_id: &str,
) -> Result<bool> {
    let stored = plan::load(ctx, plan_id).await?;
    let receipts = stored
        .steps
        .iter()
        .map(|step| RuntimeStepReceipt {
            step_id: step.id.clone(),
            succeeded: true,
            detail: "synthetic runtime completion".into(),
        })
        .collect::<Vec<_>>();
    let success = RuntimeCompletion {
        plan_id: plan_id.into(),
        generation: 1,
        succeeded: true,
        detail: "synthetic runtime completion".into(),
        receipts: receipts.clone(),
    };
    crate::runtime_delivery::complete_runtime_work(ctx, environment, &success).await?;
    crate::runtime_delivery::complete_runtime_work(ctx, environment, &success).await?;
    let conflict = RuntimeCompletion {
        succeeded: false,
        detail: "synthetic conflicting completion".into(),
        receipts: stored
            .steps
            .iter()
            .map(|step| RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: "synthetic conflicting completion".into(),
            })
            .collect(),
        ..success
    };
    match crate::runtime_delivery::complete_runtime_work(ctx, environment, &conflict).await {
        Err(error) => Ok(error.to_string().contains("conflict")),
        Ok(()) => bail!("conflicting runtime completion was accepted"),
    }
}

fn failed_restore_is_explicit(backup: &Path) -> Result<bool> {
    let damaged = backup.with_extension("damaged.db");
    std::fs::copy(backup, &damaged)?;
    std::fs::write(&damaged, b"not-a-sqlite-database")?;
    let failed = Ctx::embedded(&damaged).is_err();
    let _ = std::fs::remove_file(&damaged);
    if !failed {
        bail!("damaged backup opened as a live fleet");
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::PublishOptions;
    use crate::client::Ctx;

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

    #[test]
    fn plan_progress_excludes_tick_membership_and_backoff() {
        assert!(status_is_plan_progress(
            &EnvironmentStatus::AwaitingApproval {
                plan_id: "p".into(),
                steps: 1
            }
        ));
        assert!(status_is_plan_progress(&EnvironmentStatus::Applied {
            plan_id: "p".into(),
            steps: 1
        }));
        assert!(!status_is_plan_progress(&EnvironmentStatus::Current));
        assert!(!status_is_plan_progress(&EnvironmentStatus::Busy));
        assert!(status_is_backoff(&EnvironmentStatus::Deferred {
            retry_at: 1
        }));
        assert!(!status_is_backoff(&EnvironmentStatus::Current));
    }

    #[tokio::test]
    async fn healthy_cohorts_progress_while_faults_backoff_and_restore_fails_closed() {
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
        let (plan, report) = observe(&mut ctx, &spec(), &backup, &database)
            .await
            .unwrap();
        assert_eq!(plan.members.len(), WORKLOAD_SIZE as usize);
        assert_eq!(report.failing_applied, 0);
        assert!(report.behind_progressed > 0, "{report:?}");
        assert_eq!(report.healthy_starved, 0);
        assert!(report.deferred_failing > 0, "{report:?}");
        assert!(report.runtime_waiting > 0, "{report:?}");
        assert_eq!(report.fence_busy, 1);
        assert!(report.rollback_isolated);
        assert!(report.conflicting_receipt_rejected);
        assert!(report.failed_restore_explicit);
        assert_eq!(report.backup_environments, WORKLOAD_SIZE as usize);
        let text = format_report(&report);
        assert!(text.contains("behind_progressed="), "{text}");
        assert!(text.contains("deferred_failing="), "{text}");
        assert!(text.contains("failing_applied=0"), "{text}");
        let _ = std::fs::remove_dir_all(root);
    }
}
