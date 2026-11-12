//! Read-only admission blockers for one environment instance.
//!
//! Assembles the checks that already pause the next change, in the order
//! apply uses them. It does not write a plan or take a lease.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::environment::{
    EnvironmentInspectReport, EnvironmentMaintenanceInspect, EnvironmentPlanSummary, StatusRow,
};
use crate::plan::status;

/// Why one check currently blocks the next change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct InstanceExplainBlocker {
    /// Stable check name in admission order.
    pub check: String,
    pub evidence: String,
    /// Operator action that lifts this check.
    pub unblock: String,
}

/// What the next change would be if nothing blocked it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct InstanceNextChange {
    /// `install`, `upgrade`, `restart`, or `current`.
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub deployed: Option<String>,
    pub head: String,
}

/// Read-only explain view for one instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct InstanceExplainReport {
    pub environment: String,
    pub instance: String,
    pub blockers: Vec<InstanceExplainBlocker>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub next_change: Option<InstanceNextChange>,
}

/// Extra facts the store path loads that inspect/status do not carry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ExplainStoreFacts {
    pub recalled_release: Option<String>,
    pub superseded_plan: Option<String>,
    pub product_maintenance: Option<EnvironmentMaintenanceInspect>,
    /// Constrained desired version from planning; absent when selection failed.
    pub desired_version: Option<String>,
    pub selection_error: Option<String>,
    /// Durable `deployment_health` is `unknown` (host executor excepted).
    pub unknown_deployment: Option<String>,
    /// Non-host instance is unhealthy at the desired version, so planning restarts.
    pub unhealthy_restart: bool,
    /// Channel exists but has no promoted current_release.
    pub empty_channel: bool,
    /// Upgrade waiting on the channel's upgrade pace.
    pub upgrade_pace: Option<crate::upgrade_pace::PaceHold>,
}

/// List every check that currently blocks `instance` in `environment`.
pub async fn explain_instance(
    ctx: &mut Ctx,
    environment: &str,
    instance: &str,
) -> Result<InstanceExplainReport> {
    explain_instance_for_policy(
        ctx,
        environment,
        instance,
        crate::approval_policy::ExecutionPolicy::default(),
    )
    .await
}

/// Same as [`explain_instance`], using this host's execution policy for approval.
pub async fn explain_instance_for_policy(
    ctx: &mut Ctx,
    environment: &str,
    instance: &str,
    execution: crate::approval_policy::ExecutionPolicy,
) -> Result<InstanceExplainReport> {
    crate::ontology::validate_identifier("environment", environment)?;
    let rows = status(ctx, environment).await?;
    let inspect =
        crate::environment::inspect_environment_for_policy(ctx, environment, execution).await?;
    let row = match find_row(&rows, instance) {
        Some(row) => row.clone(),
        None => bail!("environment {environment} has no instance {instance}"),
    };
    let facts = load_store_facts(ctx, &row, instance, &inspect).await?;
    from_inspect(environment, instance, &inspect, &rows, facts)
}

/// Assemble the view from inspect and status, used by the store path and
/// tenant fixture projections.
pub(crate) fn from_inspect(
    environment: &str,
    instance: &str,
    inspect: &EnvironmentInspectReport,
    rows: &[StatusRow],
    facts: ExplainStoreFacts,
) -> Result<InstanceExplainReport> {
    let row = find_row(rows, instance)
        .cloned()
        .with_context(|| format!("environment {environment} has no instance {instance}"))?;
    let now_ms = crate::now_millis();
    let mut blockers = Vec::new();

    if let Some(retirement) = &inspect.retirement {
        blockers.push(InstanceExplainBlocker {
            check: "retirement".into(),
            evidence: format!(
                "retired at {} by {}: {}",
                retirement.retired_at, retirement.actor, retirement.reason
            ),
            unblock: "this environment no longer accepts delivery work".into(),
        });
    }

    if let Some(hold) = &inspect.delivery_hold {
        blockers.push(InstanceExplainBlocker {
            check: "delivery_hold".into(),
            evidence: format!(
                "environment:{environment} held at {} by {}: {}",
                hold.held_at, hold.actor, hold.reason
            ),
            unblock: format!("tenkaictl env hold {environment} clear"),
        });
    }
    if let Some(hold) = &row.delivery_hold {
        blockers.push(InstanceExplainBlocker {
            check: "delivery_hold".into(),
            evidence: format!(
                "channel:{}/{} held at {} by {}: {}",
                row.product, row.channel, hold.held_at, hold.actor, hold.reason
            ),
            unblock: format!(
                "tenkaictl channel hold {} {} clear",
                row.product, row.channel
            ),
        });
    }
    let mut freezes: Vec<_> = inspect
        .delivery_freezes
        .iter()
        .filter(|freeze| freeze.active_at(now_ms))
        .collect();
    freezes.sort_by(|left, right| {
        left.until_ms
            .cmp(&right.until_ms)
            .then(left.name.cmp(&right.name))
    });
    for freeze in freezes {
        blockers.push(InstanceExplainBlocker {
            check: "freeze".into(),
            evidence: format!(
                "{} until {} by {}: {}",
                freeze.name,
                crate::delivery_hold::format_freeze_instant(freeze.until_ms),
                freeze.actor,
                freeze.reason
            ),
            unblock: format!("tenkaictl env hold {environment} cancel {}", freeze.name),
        });
    }

    if let Some(error) = row.error.as_deref().filter(|error| {
        error.contains("automatic retry held") || error.starts_with("target failed")
    }) {
        blockers.push(InstanceExplainBlocker {
            check: "failed_target".into(),
            evidence: error.to_string(),
            unblock: format!("tenkaictl env retry {environment} {instance} --reason …"),
        });
    }

    if let Some(detail) = facts.unknown_deployment.clone() {
        blockers.push(InstanceExplainBlocker {
            check: "unknown_deployment".into(),
            evidence: detail,
            unblock: format!(
                "tenkaictl env reconcile {environment} {instance} (add --deployed <version> to record one)"
            ),
        });
    }

    // Stored hold, the same column status shows. Live compatibility is planning.
    if let Some(hold) = &row.dependency_hold {
        let contracts = hold
            .contracts
            .iter()
            .map(|contract| format!("{}>={}", contract.contract, contract.minimum))
            .collect::<Vec<_>>()
            .join(", ");
        blockers.push(InstanceExplainBlocker {
            check: "dependency_hold".into(),
            evidence: format!(
                "release {} waiting for {contracts} since {}",
                hold.release_id, hold.held_at
            ),
            unblock: format!("deploy or bind a provider that satisfies {contracts}"),
        });
    }

    if let Some(blocker) = maintenance_blocker(
        inspect.maintenance.as_ref(),
        facts.product_maintenance.as_ref(),
    ) {
        blockers.push(blocker);
    }

    let desired = facts
        .desired_version
        .as_deref()
        .unwrap_or(row.head.as_str());
    if let Some(hold) = &facts.upgrade_pace
        && let Some(deployed) = row.deployed.as_deref()
        && deployed != desired
        && desired == row.head
        && crate::plan::classify_change(deployed, desired) == crate::plan::Action::Upgrade
    {
        let until = crate::upgrade_pace::format_eligible_at(hold.eligible_at_ms);
        blockers.push(InstanceExplainBlocker {
            check: "upgrade_pace".into(),
            evidence: format!(
                "channel {}/{} admits {} of {} upgrades; this instance is eligible at {until}",
                hold.product, hold.channel, hold.admitted, hold.subscribed
            ),
            unblock: format!(
                "wait until {until} or tenkaictl channel admit {} {} {environment} {instance} --reason …",
                hold.product, hold.channel
            ),
        });
    }

    if facts.empty_channel {
        blockers.push(InstanceExplainBlocker {
            check: "channel_head".into(),
            evidence: format!(
                "channel {}/{} has no promoted release",
                row.product, row.channel
            ),
            unblock: format!("tenkaictl promote <release> {}", row.channel),
        });
    }

    if let Some(error) = facts.selection_error.clone() {
        blockers.push(InstanceExplainBlocker {
            check: "desired_release".into(),
            evidence: error,
            unblock: "correct the environment constraint or publish the selected release".into(),
        });
    }

    if let Some(release) = facts.recalled_release.clone() {
        blockers.push(InstanceExplainBlocker {
            check: "recall".into(),
            evidence: format!("head release {release} is recalled"),
            unblock: "promote a replacement that is not recalled".into(),
        });
    }

    if let Some(summary) = inspect
        .latest_plan
        .as_ref()
        .filter(|summary| plan_touches_instance(summary, instance) && plan_awaiting(summary))
    {
        let required = summary
            .approval
            .as_ref()
            .is_none_or(|approval| approval.source == "required");
        if required {
            let reason = summary
                .approval
                .as_ref()
                .and_then(|approval| approval.reason.clone())
                .unwrap_or_else(|| "approval is required".into());
            blockers.push(InstanceExplainBlocker {
                check: "approval".into(),
                evidence: format!("plan {} ({reason})", summary.id),
                unblock: format!("tenkaictl approval submit {}", summary.id),
            });
        }
    }

    if inspect.lease.held {
        let owner = inspect.lease.owner.as_deref().unwrap_or("unknown");
        blockers.push(InstanceExplainBlocker {
            check: "apply_lease".into(),
            evidence: format!(
                "held by {owner} generation {}",
                inspect
                    .lease
                    .generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "-".into())
            ),
            unblock: format!("tenkaictl env unlock {environment} after the holder finishes"),
        });
    }

    if let Some(plan_id) = facts.superseded_plan {
        blockers.push(InstanceExplainBlocker {
            check: "superseded_plan".into(),
            evidence: format!("stored plan {plan_id} is stale for current state"),
            unblock: format!("tenkaictl plan --env {environment}"),
        });
    }

    let next_change = if blockers.is_empty() {
        Some(next_change_from_row(
            &row,
            facts.desired_version.as_deref(),
            facts.unhealthy_restart,
        ))
    } else {
        None
    };
    Ok(InstanceExplainReport {
        environment: environment.into(),
        instance: instance.into(),
        blockers,
        next_change,
    })
}

fn find_row<'a>(rows: &'a [StatusRow], instance: &str) -> Option<&'a StatusRow> {
    rows.iter().find(|row| row_instance(row) == instance)
}

fn row_instance(row: &StatusRow) -> &str {
    if row.instance.is_empty() {
        &row.product
    } else {
        &row.instance
    }
}

fn plan_touches_instance(summary: &EnvironmentPlanSummary, instance: &str) -> bool {
    summary.steps.iter().any(|step| {
        step.instance == instance || (step.instance.is_empty() && step.product == instance)
    })
}

fn plan_awaiting(summary: &EnvironmentPlanSummary) -> bool {
    matches!(summary.state.as_str(), "computed" | "blocked")
}

fn next_change_from_row(
    row: &StatusRow,
    desired: Option<&str>,
    unhealthy_restart: bool,
) -> InstanceNextChange {
    let head = desired.unwrap_or(row.head.as_str()).to_string();
    match (
        row.deployed.as_deref(),
        row.overlay_stale || unhealthy_restart,
    ) {
        (None, _) => InstanceNextChange {
            action: "install".into(),
            deployed: None,
            head,
        },
        (Some(deployed), _) if deployed != head => InstanceNextChange {
            action: "upgrade".into(),
            deployed: Some(deployed.into()),
            head,
        },
        (Some(deployed), true) => InstanceNextChange {
            action: "restart".into(),
            deployed: Some(deployed.into()),
            head,
        },
        (Some(deployed), false) => InstanceNextChange {
            action: "current".into(),
            deployed: Some(deployed.into()),
            head,
        },
    }
}

fn maintenance_blocker(
    environment: Option<&EnvironmentMaintenanceInspect>,
    product: Option<&EnvironmentMaintenanceInspect>,
) -> Option<InstanceExplainBlocker> {
    let env_blocks = environment
        .filter(|maintenance| matches!(maintenance.eligibility.as_str(), "closed" | "invalid"));
    let product_blocks = product
        .filter(|maintenance| matches!(maintenance.eligibility.as_str(), "closed" | "invalid"));
    let maintenance = env_blocks.or(product_blocks)?;
    let evidence = match maintenance.eligibility.as_str() {
        "invalid" => format!(
            "invalid: {}",
            maintenance.detail.as_deref().unwrap_or("unreadable")
        ),
        _ => match maintenance.next_opens_at_ms {
            Some(opens) => format!(
                "closed; next opens at {}",
                crate::delivery_hold::format_freeze_instant(opens)
            ),
            None => "closed".into(),
        },
    };
    Some(InstanceExplainBlocker {
        check: "maintenance".into(),
        evidence,
        unblock: "wait until the window opens or correct the maintenance configuration".into(),
    })
}

async fn load_store_facts(
    ctx: &mut Ctx,
    row: &StatusRow,
    instance: &str,
    inspect: &EnvironmentInspectReport,
) -> Result<ExplainStoreFacts> {
    let env_obj = crate::environment::environment(ctx, &inspect.name).await?;
    let channel = ctx
        .get(&crate::ontology::channel_id(&row.product, &row.channel))
        .await?;
    let channel_version = channel
        .as_ref()
        .and_then(|channel| channel.properties.get("current_version"))
        .cloned()
        .unwrap_or_default();
    let channel_release = channel
        .as_ref()
        .and_then(|channel| channel.properties.get("current_release"))
        .map(String::as_str)
        .unwrap_or_default();
    let empty_channel = channel_version.is_empty() || channel_release.is_empty();
    let (desired_version, selected_release, selection_error) = if empty_channel {
        (None, None, None)
    } else {
        match crate::plan::resolve_subscription_selection(
            ctx,
            &env_obj,
            &inspect.name,
            &row.product,
            &channel_version,
            channel_release,
        )
        .await
        {
            Ok((version, release)) => (Some(version), Some(release), None),
            Err(error) => (None, None, Some(format!("{error:#}"))),
        }
    };
    let recalled_release = match selected_release.as_deref() {
        Some(release) if crate::catalog::release_is_recalled(ctx, release).await? => {
            Some(release.to_string())
        }
        _ => None,
    };
    // Host unknown/unhealthy lives on the applier record (ADR 0041); next change
    // still uses status deployed-versus-desired, matching this Issue.
    let host = match selected_release.as_deref() {
        Some(release) => crate::plan::readable_manifest(ctx, release)
            .await?
            .is_some_and(|manifest| {
                manifest.deploy.executor
                    == Some(crate::software_executor::SoftwareExecutorKind::Host)
            }),
        None => false,
    };
    let health = env_obj
        .properties
        .get(&format!("deployment_health.{instance}"))
        .map(String::as_str);
    let unknown_deployment = (!host && health == Some("unknown")).then(|| {
        env_obj
            .properties
            .get(&format!("deployment_error.{instance}"))
            .cloned()
            .unwrap_or_else(|| "deployment state requires manual reconciliation".into())
    });
    let unhealthy_restart = !host && health == Some("unhealthy");
    let now = chrono::DateTime::from_timestamp_millis(crate::now_millis())
        .context("current time is outside the supported maintenance-window range")?;
    let product_maintenance = Some(crate::environment::maintenance_inspect(
        crate::maintenance::list_product(ctx, &row.product).await,
        now,
    ));
    let superseded_plan = match inspect.latest_plan.as_ref() {
        Some(summary)
            if selection_error.is_none()
                && plan_touches_instance(summary, instance)
                && plan_awaiting(summary) =>
        {
            let plan = crate::plan::load(ctx, &summary.id).await?;
            match crate::apply::classify_candidate(ctx, &plan).await {
                Ok(crate::apply::CandidateAdmission::Superseded) => Some(plan.id),
                Ok(crate::apply::CandidateAdmission::Admissible) | Err(_) => None,
            }
        }
        _ => None,
    };
    let upgrade_pace = if empty_channel {
        None
    } else {
        crate::upgrade_pace::evaluate_instance(
            ctx,
            &row.product,
            &row.channel,
            &inspect.name,
            instance,
            crate::now_millis(),
        )
        .await?
    };
    Ok(ExplainStoreFacts {
        recalled_release,
        superseded_plan,
        product_maintenance,
        desired_version,
        selection_error,
        unknown_deployment,
        unhealthy_restart,
        empty_channel,
        upgrade_pace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::delivery_hold::HoldScope;
    use chrono::Datelike as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    async fn seeded(label: &str) -> (std::path::PathBuf, Ctx, std::path::PathBuf) {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let database = std::env::temp_dir().join(format!(
            "tenkai-explain-{label}-{}-{}-{n}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        let root = database.with_extension("manifest");
        std::fs::create_dir_all(&root).unwrap();
        let options = crate::catalog::PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        std::fs::write(
            root.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        crate::catalog::publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("explain");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        (database, ctx, root)
    }

    async fn current_release(ctx: &mut Ctx) -> String {
        ctx.get(&crate::ontology::channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap()
            .properties["current_release"]
            .clone()
    }

    fn checks(report: &InstanceExplainReport) -> Vec<&str> {
        report
            .blockers
            .iter()
            .map(|blocker| blocker.check.as_str())
            .collect()
    }

    #[tokio::test]
    async fn stacked_blockers_follow_admission_order() {
        let (database, mut ctx, root) = seeded("stack").await;
        let release = current_release(&mut ctx).await;
        crate::delivery_hold::set(
            &mut ctx,
            &HoldScope::environment("local"),
            "change freeze",
            "alice",
        )
        .await
        .unwrap();
        let now = crate::now_millis();
        crate::delivery_hold::schedule_freeze(
            &mut ctx,
            "local",
            "blackout",
            now - 1_000,
            now + 3_600_000,
            "holiday",
            "alice",
        )
        .await
        .unwrap();
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties
            .insert("failed_target.api".into(), release.clone());
        env.properties.insert(
            "dependency_hold.api".into(),
            "tenkai:release:db@1.0.0".into(),
        );
        env.properties.insert(
            "dependency_hold_contracts.api".into(),
            "database=1.0.0".into(),
        );
        env.properties
            .insert("dependency_hold_at.api".into(), now.to_string());
        ctx.put(env).await.unwrap();
        let today = chrono::Utc::now().weekday().number_from_monday();
        let other = if today == 1 { 2 } else { 1 };
        crate::maintenance::set(
            &mut ctx,
            "local",
            crate::maintenance::Window::new("off", "UTC", vec![other], "02:00", 60).unwrap(),
        )
        .await
        .unwrap();
        crate::apply::claim_environment(&mut ctx, "local", "owner-a")
            .await
            .unwrap();

        let report = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert_eq!(
            checks(&report),
            [
                "delivery_hold",
                "freeze",
                "failed_target",
                "dependency_hold",
                "maintenance",
                "apply_lease"
            ]
        );
        for blocker in &report.blockers {
            assert!(!blocker.unblock.is_empty(), "{blocker:?}");
        }
        assert!(report.next_change.is_none());
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn recall_and_stale_plan_are_named() {
        let (database, mut ctx, root) = seeded("recall").await;
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        let actor = crate::auth_context::test_management_context("explain-recall");
        crate::catalog::recall(&mut ctx, &actor, "api@1.0.0")
            .await
            .unwrap();
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties.insert("deployed.api".into(), "0.0.1".into());
        ctx.put(env).await.unwrap();

        let report = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert!(checks(&report).contains(&"recall"), "{report:?}");
        assert!(checks(&report).contains(&"approval"), "{report:?}");
        assert!(checks(&report).contains(&"superseded_plan"), "{report:?}");
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.check == "approval" && blocker.evidence.contains(&plan.id)),
            "{report:?}"
        );
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn clear_instance_names_next_change_and_writes_nothing() {
        let (database, mut ctx, root) = seeded("clear").await;
        let before_plan = crate::plan::latest_for_environment(&mut ctx, "local")
            .await
            .unwrap();
        let before_lease = crate::apply::inspect_environment_lease(&mut ctx, "local")
            .await
            .unwrap();

        let missing = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert!(missing.blockers.is_empty(), "{missing:?}");
        let next = missing.next_change.unwrap();
        assert_eq!(next.action, "install");
        assert_eq!(next.head, "1.0.0");

        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties.insert("deployed.api".into(), "1.0.0".into());
        ctx.put(env).await.unwrap();
        let current = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert_eq!(current.next_change.unwrap().action, "current");

        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties
            .insert("applied_config.api".into(), "stale".into());
        ctx.put(env).await.unwrap();
        let restart = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert_eq!(restart.next_change.unwrap().action, "restart");

        std::fs::write(
            root.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"1.1.0\"\n\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        let options = crate::catalog::PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        crate::catalog::publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("explain-upgrade");
        crate::catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties.remove("applied_config.api");
        ctx.put(env).await.unwrap();
        let upgrade = explain_instance(&mut ctx, "local", "api").await.unwrap();
        let next = upgrade.next_change.unwrap();
        assert_eq!(next.action, "upgrade");
        assert_eq!(next.deployed.as_deref(), Some("1.0.0"));
        assert_eq!(next.head, "1.1.0");

        let after_plan = crate::plan::latest_for_environment(&mut ctx, "local")
            .await
            .unwrap();
        let after_lease = crate::apply::inspect_environment_lease(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(
            before_plan.as_ref().map(|plan| plan.id.as_str()),
            after_plan.as_ref().map(|plan| plan.id.as_str())
        );
        assert_eq!(before_lease, after_lease);
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn paced_upgrade_is_a_named_blocker() {
        let (database, mut ctx, root) = seeded("pace").await;
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties.insert("deployed.api".into(), "1.0.0".into());
        env.properties.insert(
            "deployed_release.api".into(),
            crate::ontology::release_id("api", "1.0.0"),
        );
        ctx.put(env).await.unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"1.1.0\"\n\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        crate::catalog::publish(
            &mut ctx,
            &root.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        crate::upgrade_pace::configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("explain-pace");
        crate::catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();
        let report = explain_instance(&mut ctx, "local", "api").await.unwrap();
        let blocker = report
            .blockers
            .iter()
            .find(|blocker| blocker.check == "upgrade_pace")
            .expect("pace blocker");
        assert!(blocker.evidence.contains("api/stable"), "{blocker:?}");
        assert!(blocker.unblock.contains("channel admit"), "{blocker:?}");
        assert!(report.next_change.is_none(), "{report:?}");
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn paced_downgrade_is_not_a_named_blocker() {
        let (database, mut ctx, root) = seeded("pace-down").await;
        std::fs::write(
            root.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"1.1.0\"\n\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        crate::catalog::publish(
            &mut ctx,
            &root.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("explain-pace-down");
        crate::catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties.insert("deployed.api".into(), "1.1.0".into());
        env.properties.insert(
            "deployed_release.api".into(),
            crate::ontology::release_id("api", "1.1.0"),
        );
        ctx.put(env).await.unwrap();
        crate::upgrade_pace::configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        let report = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert!(
            report
                .blockers
                .iter()
                .all(|blocker| blocker.check != "upgrade_pace"),
            "{report:?}"
        );
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn unknown_instance_fails() {
        let (database, mut ctx, root) = seeded("missing").await;
        let error = explain_instance(&mut ctx, "local", "web")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("has no instance web"), "{error}");
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn pinned_current_is_not_an_upgrade() {
        let (database, mut ctx, root) = seeded("pin").await;
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties.insert("deployed.api".into(), "1.0.0".into());
        ctx.put(env).await.unwrap();
        crate::environment::set_environment_constraint(
            &mut ctx,
            "local",
            "version_pin",
            "api",
            "1.0.0",
        )
        .await
        .unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"1.1.0\"\n\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        let options = crate::catalog::PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        crate::catalog::publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("explain-pin");
        crate::catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();

        let report = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert!(report.blockers.is_empty(), "{report:?}");
        let next = report.next_change.unwrap();
        assert_eq!(next.action, "current");
        assert_eq!(next.head, "1.0.0");
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn unknown_deployment_is_named() {
        let (database, mut ctx, root) = seeded("unknown").await;
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties
            .insert("deployment_health.api".into(), "unknown".into());
        env.properties.insert(
            "deployment_error.api".into(),
            "restore needs manual recovery".into(),
        );
        ctx.put(env).await.unwrap();

        let report = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert_eq!(checks(&report), ["unknown_deployment"]);
        assert!(
            report.blockers[0]
                .evidence
                .contains("restore needs manual recovery"),
            "{report:?}"
        );
        assert!(
            report.blockers[0]
                .unblock
                .contains("tenkaictl env reconcile local api"),
            "{report:?}"
        );
        assert!(report.next_change.is_none());
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn recall_follows_the_pinned_release() {
        let (database, mut ctx, root) = seeded("pin-recall").await;
        crate::environment::set_environment_constraint(
            &mut ctx,
            "local",
            "version_pin",
            "api",
            "1.0.0",
        )
        .await
        .unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"1.1.0\"\n\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        let options = crate::catalog::PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        crate::catalog::publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("explain-pin-recall");
        crate::catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();
        crate::catalog::recall(&mut ctx, &actor, "api@1.0.0")
            .await
            .unwrap();

        let report = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert!(checks(&report).contains(&"recall"), "{report:?}");
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.check == "recall" && blocker.evidence.contains("1.0.0")),
            "{report:?}"
        );
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn unhealthy_at_head_is_a_restart() {
        let (database, mut ctx, root) = seeded("unhealthy").await;
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties.insert("deployed.api".into(), "1.0.0".into());
        env.properties
            .insert("deployment_health.api".into(), "unhealthy".into());
        ctx.put(env).await.unwrap();

        let report = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert!(report.blockers.is_empty(), "{report:?}");
        assert_eq!(report.next_change.unwrap().action, "restart");
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn invalid_pin_with_a_stored_plan_still_explains() {
        let (database, mut ctx, root) = seeded("pin-plan").await;
        crate::plan::create(&mut ctx, "local").await.unwrap();
        crate::environment::set_environment_constraint(
            &mut ctx,
            "local",
            "version_pin",
            "api",
            "9.9.9",
        )
        .await
        .unwrap();

        let report = explain_instance(&mut ctx, "local", "api").await.unwrap();
        assert!(checks(&report).contains(&"desired_release"), "{report:?}");
        assert!(report.next_change.is_none());
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }
}
