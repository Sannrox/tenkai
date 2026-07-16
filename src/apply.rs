//! Plan execution: eval gates, install commands, health probes, auto-rollback.
//!
//! Every execution writes plan and deployment objects into sekai, so the graph
//! answers "what ran, when, gated by what, and what happened" after the fact.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};

use crate::client::Ctx;
use crate::manifest::{self, Manifest};
use crate::ontology::*;
use crate::pb::chisei::ListEvalRunsRequest;
use crate::pb::sekai::Object;
use crate::plan::{self, Action, Plan, PlanState, Step};

pub struct Outcome {
    pub step: Step,
    pub status: String, // succeeded | failed | rolled_back
    pub detail: String,
}

async fn run_command(cmd: &str, workdir: &Path) -> Result<Result<(), String>> {
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(workdir)
        .output()
        .await
        .with_context(|| format!("spawning `{cmd}`"))?;
    if output.status.success() {
        Ok(Ok(()))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(Err(format!(
            "`{cmd}` exited with {} — {}",
            output.status,
            stderr.trim()
        )))
    }
}

/// Gate: the suite's latest eval run must exist and be fully passing.
async fn check_eval_gate(ctx: &mut Ctx, suite_id: &str) -> Result<()> {
    let runs = ctx
        .chisei
        .list_eval_runs(ListEvalRunsRequest {
            suite_id: suite_id.into(),
        })
        .await?
        .into_inner()
        .runs;
    let Some(latest) = runs.iter().max_by_key(|r| r.timestamp) else {
        bail!(
            "gate blocked: eval suite {suite_id} has no runs — run the suite in chisei first, or use --skip-gates"
        );
    };
    if latest.results.is_empty() {
        bail!("gate blocked: latest run of eval suite {suite_id} has no case results");
    }
    let failed: Vec<_> = latest
        .results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.case_id.clone())
        .collect();
    if !failed.is_empty() {
        bail!(
            "gate blocked: eval suite {suite_id} latest run failing cases: {}",
            failed.join(", ")
        );
    }
    Ok(())
}

struct ReleaseContent {
    manifest: Manifest,
    workdir: std::path::PathBuf,
}

async fn release_content(ctx: &mut Ctx, release_id: &str) -> Result<ReleaseContent> {
    let Some(obj) = ctx.get(release_id).await? else {
        bail!("release object {release_id} not found");
    };
    let raw = obj.properties.get("manifest").cloned().unwrap_or_default();
    let manifest = manifest::parse_raw(&raw)
        .with_context(|| format!("parsing stored manifest of {release_id}"))?;
    let workdir = obj
        .properties
        .get("workdir")
        .cloned()
        .unwrap_or_else(|| ".".into());
    Ok(ReleaseContent {
        manifest,
        workdir: workdir.into(),
    })
}

fn record(id: String, kind: &str, name: String, properties: HashMap<String, String>) -> Object {
    let now = crate::now_millis();
    Object {
        id,
        kind: kind.into(),
        name,
        namespace: NS.into(),
        external_id: String::new(),
        properties,
        created: now,
        updated: now,
    }
}

async fn set_env_deployed(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    version: &str,
    previous: Option<&str>,
) -> Result<()> {
    let Some(mut env_obj) = ctx.get(&env_id(env)).await? else {
        bail!("environment {env} disappeared during apply");
    };
    env_obj
        .properties
        .insert(format!("deployed.{product}"), version.to_string());
    env_obj.properties.insert(
        format!("deployed_release.{product}"),
        release_id(product, version),
    );
    if let Some(prev) = previous {
        env_obj
            .properties
            .insert(format!("deployed_prev.{product}"), prev.to_string());
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(())
}

async fn set_plan_state(
    ctx: &mut Ctx,
    plan: &mut Plan,
    state: PlanState,
    gates_skipped: bool,
) -> Result<()> {
    plan.state = state;
    plan.gates_skipped = Some(gates_skipped);
    plan::store(ctx, plan).await
}

/// Execute a stored plan's ordered steps, one product at a time.
pub async fn execute(ctx: &mut Ctx, plan_id: &str, skip_gates: bool) -> Result<Vec<Outcome>> {
    let mut stored_plan = plan::load(ctx, plan_id).await?;
    if stored_plan.state != PlanState::Computed {
        bail!(
            "plan {} is {}, only computed plans can be applied",
            stored_plan.id,
            stored_plan.state
        );
    }
    let env = stored_plan.environment.clone();
    let steps = stored_plan.steps.clone();
    set_plan_state(ctx, &mut stored_plan, PlanState::Running, skip_gates).await?;

    let mut outcomes = Vec::new();
    let mut plan_failed = false;

    for step in steps {
        let outcome = match execute_step(ctx, &env, plan_id, &step, skip_gates).await {
            Ok(outcome) => outcome,
            Err(error) => {
                set_plan_state(ctx, &mut stored_plan, PlanState::Failed, skip_gates).await?;
                return Err(error);
            }
        };
        if outcome.status != "succeeded" {
            plan_failed = true;
        }
        outcomes.push(outcome);
    }

    let final_state = if plan_failed {
        PlanState::Failed
    } else {
        PlanState::Succeeded
    };
    set_plan_state(ctx, &mut stored_plan, final_state, skip_gates).await?;

    Ok(outcomes)
}

async fn execute_step(
    ctx: &mut Ctx,
    env: &str,
    plan_oid: &str,
    step: &Step,
    skip_gates: bool,
) -> Result<Outcome> {
    let content = release_content(ctx, &step.release_id).await?;

    // Gate before touching anything. A blocked gate fails the step but is not
    // an execution error — it is the system working as intended.
    if !skip_gates
        && step.action != Action::Rollback
        && let Some(suite) = content
            .manifest
            .gate
            .eval_suite
            .as_deref()
            .filter(|s| !s.is_empty())
        && let Err(e) = check_eval_gate(ctx, suite).await
    {
        let outcome = Outcome {
            step: step.clone(),
            status: "failed".into(),
            detail: e.to_string(),
        };
        record_deployment(ctx, env, plan_oid, &outcome).await?;
        return Ok(outcome);
    }

    let install = run_command(&content.manifest.deploy.install, &content.workdir).await?;
    let health = match &install {
        Ok(()) => match &content.manifest.deploy.health {
            Some(cmd) if !cmd.is_empty() => run_command(cmd, &content.workdir).await?,
            _ => Ok(()),
        },
        Err(_) => Ok(()), // no point probing a failed install
    };

    let outcome = match (install, health) {
        (Ok(()), Ok(())) => {
            set_env_deployed(ctx, env, &step.product, &step.to, step.from.as_deref()).await?;
            Outcome {
                step: step.clone(),
                status: "succeeded".into(),
                detail: String::new(),
            }
        }
        (Err(detail), _) | (Ok(()), Err(detail)) => {
            // Install or health failed: try to restore the previous release.
            match &step.from {
                Some(prev) => {
                    let prev_content =
                        release_content(ctx, &release_id(&step.product, prev)).await?;
                    let restore =
                        run_command(&prev_content.manifest.deploy.install, &prev_content.workdir)
                            .await?;
                    let restore = match restore {
                        Ok(()) => match &prev_content.manifest.deploy.health {
                            Some(cmd) if !cmd.is_empty() => {
                                run_command(cmd, &prev_content.workdir).await?
                            }
                            _ => Ok(()),
                        },
                        error => error,
                    };
                    let detail = match restore {
                        Ok(()) => format!("{detail}; restored {prev}"),
                        Err(r) => {
                            format!("{detail}; restore or health check of {prev} also failed: {r}")
                        }
                    };
                    Outcome {
                        step: step.clone(),
                        status: "rolled_back".into(),
                        detail,
                    }
                }
                None => {
                    let detail = match content.manifest.deploy.uninstall.as_deref() {
                        Some(cmd) if !cmd.is_empty() => {
                            match run_command(cmd, &content.workdir).await? {
                                Ok(()) => format!("{detail}; cleaned up failed install"),
                                Err(cleanup) => {
                                    format!("{detail}; cleanup also failed: {cleanup}")
                                }
                            }
                        }
                        _ => detail,
                    };
                    Outcome {
                        step: step.clone(),
                        status: "failed".into(),
                        detail,
                    }
                }
            }
        }
    };

    record_deployment(ctx, env, plan_oid, &outcome).await?;
    Ok(outcome)
}

async fn record_deployment(
    ctx: &mut Ctx,
    env: &str,
    plan_oid: &str,
    outcome: &Outcome,
) -> Result<()> {
    let now = crate::now_millis();
    let did = deployment_id(env, &outcome.step.product, now);
    ctx.put(record(
        did.clone(),
        KIND_DEPLOYMENT,
        format!(
            "{} {} -> {} ({env})",
            outcome.step.product,
            outcome.step.from.clone().unwrap_or_else(|| "none".into()),
            outcome.step.to
        ),
        HashMap::from([
            ("environment".into(), env.to_string()),
            ("product".into(), outcome.step.product.clone()),
            (
                "from_version".into(),
                outcome.step.from.clone().unwrap_or_default(),
            ),
            ("to_version".into(), outcome.step.to.clone()),
            ("status".into(), outcome.status.clone()),
            ("detail".into(), outcome.detail.clone()),
        ]),
    ))
    .await?;
    ctx.link(&did, &outcome.step.release_id, REL_DEPLOYED_RELEASE)
        .await?;
    ctx.link(&did, &env_id(env), REL_IN_ENVIRONMENT).await?;
    ctx.link(&did, plan_oid, REL_PART_OF_PLAN).await?;
    Ok(())
}
