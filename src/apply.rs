//! Plan execution: eval gates, install commands, health probes, auto-rollback.
//!
//! Every execution writes plan and deployment objects into sekai, so the graph
//! answers "what ran, when, gated by what, and what happened" after the fact.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use prost::Message as _;
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::executor::{self, Executor, ExecutorInput};
use crate::manifest::{self, Manifest};
use crate::ontology::*;
use crate::pb::chisei::{
    EvalRun, EvalSuite, GetEvalRunRequest, GetEvalSuiteRequest, ListEvalRunsRequest,
};
use crate::pb::sekai::Object;
use crate::plan::{self, Action, Plan, PlanState, ReleasePin, Step};

pub struct Outcome {
    pub step: Step,
    pub status: String, // succeeded | failed | rolled_back
    pub detail: String,
}

enum GateDecision {
    Allowed,
    Denied(String),
    Unavailable(String),
}

fn evaluate_gate(runs: &[EvalRun], suite_id: &str, expected_cases: &[String]) -> GateDecision {
    let Some(latest) = runs.iter().max_by_key(|run| run.timestamp) else {
        return GateDecision::Denied(format!(
            "gate blocked: eval suite {suite_id} has no runs — run the suite in chisei first, or use --skip-gates"
        ));
    };
    if latest.results.is_empty() {
        return GateDecision::Denied(format!(
            "gate blocked: latest run of eval suite {suite_id} has no case results"
        ));
    }
    let expected: std::collections::HashSet<_> = expected_cases.iter().collect();
    let actual: std::collections::HashSet<_> = latest
        .results
        .iter()
        .map(|result| &result.case_id)
        .collect();
    if expected.is_empty() || actual.len() != latest.results.len() || actual != expected {
        return GateDecision::Denied(format!(
            "gate blocked: latest run of eval suite {suite_id} does not contain exactly one result for every current case"
        ));
    }
    let failed: Vec<_> = latest
        .results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| result.case_id.clone())
        .collect();
    if !failed.is_empty() {
        return GateDecision::Denied(format!(
            "gate blocked: eval suite {suite_id} latest run failing cases: {}",
            failed.join(", ")
        ));
    }
    GateDecision::Allowed
}

/// Gate: the suite's latest eval run must exist and be fully passing.
async fn check_eval_gate(
    ctx: &mut Ctx,
    suite_id: &str,
    release_digest: &str,
    artifact_digest: &str,
) -> GateDecision {
    let suite = match ctx
        .chisei
        .get_eval_suite(GetEvalSuiteRequest {
            id: suite_id.into(),
        })
        .await
    {
        Ok(response) => match response.into_inner().suite {
            Some(suite) => suite,
            None => {
                return GateDecision::Denied(format!(
                    "gate blocked: eval suite {suite_id} does not exist"
                ));
            }
        },
        Err(error) if error.code() == tonic::Code::NotFound => {
            return GateDecision::Denied(format!(
                "gate blocked: eval suite {suite_id} does not exist"
            ));
        }
        Err(error) => {
            return GateDecision::Unavailable(format!(
                "gate unavailable: could not read eval suite {suite_id}: {error}"
            ));
        }
    };
    let expected_cases = suite
        .cases
        .iter()
        .map(|case| case.id.clone())
        .collect::<Vec<_>>();
    let expected_ref = gate_config_ref(release_digest, artifact_digest, &suite);
    let summaries = match ctx
        .chisei
        .list_eval_runs(ListEvalRunsRequest {
            suite_id: suite_id.into(),
        })
        .await
    {
        Ok(response) => response.into_inner().runs,
        Err(error) => {
            return GateDecision::Unavailable(format!(
                "gate unavailable: could not read eval suite {suite_id}: {error}"
            ));
        }
    };
    let Some(latest) = summaries
        .iter()
        .filter(|run| run.config_ref == expected_ref)
        .filter(|run| run.timestamp > 0 && run.timestamp <= crate::now_millis() + 60_000)
        .max_by(|left, right| {
            left.timestamp
                .cmp(&right.timestamp)
                .then_with(|| left.id.cmp(&right.id))
        })
    else {
        return GateDecision::Denied(format!(
            "gate blocked: eval suite {suite_id} has no current run with config_ref {expected_ref}"
        ));
    };
    match ctx
        .chisei
        .get_eval_run(GetEvalRunRequest {
            id: latest.id.clone(),
        })
        .await
    {
        Ok(response) => match response.into_inner().run {
            Some(run)
                if run.config_ref == expected_ref
                    && run.timestamp == latest.timestamp
                    && run.timestamp > 0
                    && run.timestamp <= crate::now_millis() + 60_000 =>
            {
                evaluate_gate(&[run], suite_id, &expected_cases)
            }
            Some(_) => GateDecision::Unavailable(format!(
                "gate unavailable: eval run {} no longer references the current release and suite",
                latest.id
            )),
            None => GateDecision::Unavailable(format!(
                "gate unavailable: latest eval run {} disappeared",
                latest.id
            )),
        },
        Err(error) => GateDecision::Unavailable(format!(
            "gate unavailable: could not read latest eval run {}: {error}",
            latest.id
        )),
    }
}

fn gate_config_ref(release_digest: &str, artifact_digest: &str, suite: &EvalSuite) -> String {
    let suite_digest = format!("{:x}", Sha256::digest(suite.encode_to_vec()));
    let mut hasher = Sha256::new();
    for value in [
        b"tenkai-gate-v1".as_slice(),
        release_digest.as_bytes(),
        artifact_digest.as_bytes(),
        suite_digest.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    format!("tenkai:{:x}", hasher.finalize())
}

struct ReleaseContent {
    release_id: String,
    manifest: Manifest,
    artifact_digest: String,
    workdir: std::path::PathBuf,
    environment: String,
    product: String,
}

fn verify_content_integrity(content: &ReleaseContent) -> Result<()> {
    let actual = manifest::artifact_digest(&content.workdir, &content.manifest.deploy.inputs)?;
    if actual != content.artifact_digest {
        bail!("immutable deployment inputs changed while executing release");
    }
    Ok(())
}

fn executor_input(
    content: &ReleaseContent,
    step: &Step,
    action: Action,
    from_version: Option<String>,
) -> ExecutorInput {
    ExecutorInput {
        step_id: step.id.clone(),
        action,
        environment: content.environment.clone(),
        product: content.product.clone(),
        from_version,
        to_version: content.manifest.product.version.clone(),
        release_id: content.release_id.clone(),
        workdir: content.workdir.clone(),
        install: content.manifest.deploy.install.clone(),
        uninstall: content.manifest.deploy.uninstall.clone(),
        health: content.manifest.deploy.health.clone(),
    }
}

async fn activate(
    executor: &dyn Executor,
    input: &ExecutorInput,
    content: &ReleaseContent,
) -> Result<(), String> {
    let result = executor.activate(input).await;
    if !result.succeeded {
        return Err(result.detail);
    }
    match verify_content_integrity(content) {
        Ok(()) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

async fn deactivate(
    executor: &dyn Executor,
    input: &ExecutorInput,
    content: &ReleaseContent,
) -> Result<(), String> {
    let result = executor.deactivate(input).await;
    if !result.succeeded {
        return Err(result.detail);
    }
    match verify_content_integrity(content) {
        Ok(()) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

async fn restore_previous(
    executor: &dyn Executor,
    input: &ExecutorInput,
    content: &ReleaseContent,
    version: &str,
    failure: String,
) -> (bool, String) {
    match activate(executor, input, content).await {
        Ok(()) => (true, format!("{failure}; restored {version}")),
        Err(restore) => (
            false,
            format!("{failure}; restore or health check of {version} also failed: {restore}"),
        ),
    }
}

async fn cleanup_failed_install(
    executor: &dyn Executor,
    input: &ExecutorInput,
    content: &ReleaseContent,
    failure: String,
) -> (bool, String) {
    match content.manifest.deploy.uninstall.as_deref() {
        Some(_) => match deactivate(executor, input, content).await {
            Ok(()) => (true, format!("{failure}; cleaned up failed install")),
            Err(cleanup) => (false, format!("{failure}; cleanup also failed: {cleanup}")),
        },
        None => (false, failure),
    }
}

async fn compensate_activation(
    ctx: &mut Ctx,
    env: &str,
    step: &Step,
    content: &ReleaseContent,
    failure: &anyhow::Error,
) {
    let failure = format!("deployment bookkeeping failed after activation: {failure}");
    let target_executor = executor::select(content.manifest.deploy.executor);
    let target_input = executor_input(content, step, step.action, step.from.clone());
    let cleaned = deactivate(target_executor, &target_input, content)
        .await
        .is_ok();
    let mut restored = step.from.is_none();

    if let (Some(previous), Some(pin)) = (step.from.as_deref(), step.restore.as_ref())
        && let Ok(previous_content) = release_content(ctx, pin, env, &step.product).await
    {
        let previous_executor = executor::select(previous_content.manifest.deploy.executor);
        let previous_input = executor_input(
            &previous_content,
            step,
            Action::Rollback,
            Some(step.to.clone()),
        );
        if activate(previous_executor, &previous_input, &previous_content)
            .await
            .is_ok()
        {
            restored = set_env_deployed(ctx, env, &step.product, previous, Some(&step.to))
                .await
                .is_ok();
        }
    }

    // A graph write already failed, so this update is necessarily best effort.
    // Marking the target unknown is safer than claiming a version that may not
    // match the external deployment after incomplete compensation.
    if !cleaned || !restored || step.from.is_none() {
        let _ = set_env_unknown(ctx, env, &step.product, &failure).await;
    }
}

async fn release_content(
    ctx: &mut Ctx,
    pin: &ReleasePin,
    environment: &str,
    product: &str,
) -> Result<ReleaseContent> {
    let Some(obj) = ctx.get(&pin.release_id).await? else {
        bail!("release object {} not found", pin.release_id);
    };
    if obj.kind != KIND_RELEASE {
        bail!(
            "object {} is {}, not {KIND_RELEASE}",
            pin.release_id,
            obj.kind
        );
    }
    let raw = obj.properties.get("manifest").cloned().unwrap_or_default();
    let stored_digest = obj.properties.get("digest").cloned().unwrap_or_default();
    let actual_digest = manifest::digest(&raw);
    if stored_digest != pin.digest || actual_digest != pin.digest {
        bail!(
            "release {} content no longer matches pinned digest {}",
            pin.release_id,
            pin.digest
        );
    }
    let manifest = manifest::parse_raw(&raw)
        .with_context(|| format!("parsing stored manifest of {}", pin.release_id))?;
    let actual_artifact_digest =
        manifest::artifact_digest(Path::new(&pin.workdir), &manifest.deploy.inputs)?;
    if actual_artifact_digest != pin.artifact_digest {
        bail!(
            "release {} immutable deploy inputs no longer match pinned artifact digest {}",
            pin.release_id,
            pin.artifact_digest
        );
    }
    let workdir = if manifest.deploy.inputs.is_empty() {
        Path::new(&pin.workdir).canonicalize()?
    } else {
        manifest::execution_workdir(
            Path::new(&pin.workdir),
            &manifest.deploy.inputs,
            &pin.artifact_digest,
            environment,
            product,
        )?
    };
    Ok(ReleaseContent {
        release_id: pin.release_id.clone(),
        manifest,
        artifact_digest: pin.artifact_digest.clone(),
        workdir,
        environment: environment.to_string(),
        product: product.to_string(),
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
    env_obj
        .properties
        .remove(&format!("deployment_health.{product}"));
    env_obj
        .properties
        .remove(&format!("deployment_error.{product}"));
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(())
}

async fn set_env_unknown(ctx: &mut Ctx, env: &str, product: &str, detail: &str) -> Result<()> {
    let Some(mut environment) = ctx.get(&env_id(env)).await? else {
        bail!("environment {env} disappeared during apply");
    };
    environment
        .properties
        .remove(&format!("deployed.{product}"));
    environment
        .properties
        .remove(&format!("deployed_release.{product}"));
    environment
        .properties
        .insert(format!("deployment_health.{product}"), "unknown".into());
    environment
        .properties
        .insert(format!("deployment_error.{product}"), detail.to_string());
    environment.updated = crate::now_millis();
    ctx.put(environment).await?;
    Ok(())
}

async fn set_plan_state(
    ctx: &mut Ctx,
    plan: &mut Plan,
    state: PlanState,
    gates_skipped: bool,
    detail: impl Into<String>,
) -> Result<()> {
    plan.state = state;
    plan.gates_skipped = Some(gates_skipped);
    plan.status_detail = detail.into();
    plan::store(ctx, plan).await
}

async fn set_plan_state_confirmed(
    ctx: &mut Ctx,
    plan: &mut Plan,
    state: PlanState,
    gates_skipped: bool,
    detail: impl Into<String>,
) -> Result<()> {
    let detail = detail.into();
    if let Err(error) = set_plan_state(ctx, plan, state, gates_skipped, detail.clone()).await {
        let persisted = plan::load(ctx, &plan.id).await;
        if !matches!(
            persisted,
            Ok(ref stored)
                if stored.state == state
                    && stored.gates_skipped == Some(gates_skipped)
                    && stored.status_detail == detail
        ) {
            return Err(error);
        }
    }
    Ok(())
}

fn environment_claim_id(environment: &str) -> String {
    format!("{}:execution", env_id(environment))
}

const ENVIRONMENT_LEASE_MS: i64 = 2 * 60 * 60 * 1000;

struct EnvironmentLease {
    id: String,
    environment: String,
    owner: String,
}

fn lease_object(lease: &EnvironmentLease, now: i64) -> Object {
    record(
        lease.id.clone(),
        KIND_ENVIRONMENT_EXECUTION,
        format!("apply lease for {}", lease.environment),
        HashMap::from([
            ("environment".into(), lease.environment.clone()),
            ("owner".into(), lease.owner.clone()),
            (
                "expires_at".into(),
                (now + ENVIRONMENT_LEASE_MS).to_string(),
            ),
        ]),
    )
}

async fn claim_environment(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
) -> Result<EnvironmentLease> {
    let lease = EnvironmentLease {
        id: environment_claim_id(environment),
        environment: environment.to_string(),
        owner: owner.to_string(),
    };
    let now = crate::now_millis();
    match ctx.create_once(lease_object(&lease, now)).await {
        Ok(_) => return Ok(lease),
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE")) => {}
        Err(status) => return Err(status.into()),
    }
    let existing = ctx
        .get(&lease.id)
        .await?
        .with_context(|| format!("environment lease {} disappeared", lease.id))?;
    let expires_at = existing
        .properties
        .get("expires_at")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(i64::MAX);
    if expires_at <= now {
        bail!(
            "environment {environment} has an expired apply lease; verify no apply is running, then run `tenkaictl env unlock {environment}`"
        );
    }
    bail!("environment {environment} already has an apply in progress")
}

async fn refresh_environment_lease(ctx: &mut Ctx, lease: &EnvironmentLease) -> Result<()> {
    let existing = ctx
        .get(&lease.id)
        .await?
        .with_context(|| format!("environment lease {} disappeared", lease.id))?;
    if existing.properties.get("owner") != Some(&lease.owner) {
        bail!("environment lease {} is owned by another apply", lease.id);
    }
    ctx.put(lease_object(lease, crate::now_millis())).await?;
    Ok(())
}

async fn release_environment(ctx: &mut Ctx, lease: &EnvironmentLease) -> Result<()> {
    if let Some(existing) = ctx.get(&lease.id).await?
        && existing.properties.get("owner") == Some(&lease.owner)
    {
        ctx.delete(&lease.id).await?;
    }
    Ok(())
}

pub async fn unlock_environment(ctx: &mut Ctx, environment: &str) -> Result<String> {
    crate::ontology::validate_identifier("environment", environment)?;
    let id = environment_claim_id(environment);
    let Some(existing) = ctx.get(&id).await? else {
        return Ok(format!("environment {environment} has no apply lease"));
    };
    if existing.kind != KIND_ENVIRONMENT_EXECUTION {
        bail!(
            "object {id} is {}, not {KIND_ENVIRONMENT_EXECUTION}",
            existing.kind
        );
    }
    ctx.delete(&id).await?;
    Ok(format!("removed apply lease for environment {environment}"))
}

async fn validate_preconditions(ctx: &mut Ctx, plan: &Plan) -> Result<()> {
    let environment = ctx
        .get(&env_id(&plan.environment))
        .await?
        .with_context(|| format!("environment {} not found", plan.environment))?;
    for step in &plan.steps {
        if environment
            .properties
            .get(&format!("deployment_health.{}", step.product))
            .is_some_and(|health| health == "unknown")
        {
            bail!(
                "plan {} cannot apply {} while its deployment state is unknown; reconcile or roll back first",
                plan.id,
                step.product
            );
        }
        let actual = environment
            .properties
            .get(&format!("deployed.{}", step.product));
        if actual != step.from.as_ref() {
            bail!(
                "plan {} is stale for {}: expected deployed version {:?}, found {:?}",
                plan.id,
                step.product,
                step.from,
                actual
            );
        }
    }
    Ok(())
}

/// Execute a stored plan's ordered steps, one product at a time.
pub async fn execute(ctx: &mut Ctx, plan_id: &str, skip_gates: bool) -> Result<Vec<Outcome>> {
    let stored_plan = plan::load(ctx, plan_id).await?;
    if !matches!(stored_plan.state, PlanState::Computed | PlanState::Blocked) {
        bail!(
            "plan {} is {}, only computed or blocked plans can be applied",
            stored_plan.id,
            stored_plan.state
        );
    }
    let environment = stored_plan.environment.clone();
    let owner = stored_plan.id.clone();
    let lease = claim_environment(ctx, &environment, &owner).await?;
    let result = execute_locked(ctx, stored_plan, skip_gates, &lease).await;
    let unlock = release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(outcomes), Ok(())) => Ok(outcomes),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("releasing environment apply lock")),
    }
}

async fn execute_locked(
    ctx: &mut Ctx,
    mut stored_plan: Plan,
    skip_gates: bool,
    lease: &EnvironmentLease,
) -> Result<Vec<Outcome>> {
    validate_preconditions(ctx, &stored_plan).await?;
    let plan_id = stored_plan.id.clone();
    let env = stored_plan.environment.clone();
    let steps = stored_plan.steps.clone();
    if !skip_gates {
        for step in &steps {
            if step.action == Action::Rollback {
                continue;
            }
            let target = ReleasePin {
                release_id: step.release_id.clone(),
                digest: step.release_digest.clone(),
                artifact_digest: step.artifact_digest.clone(),
                workdir: step.workdir.clone(),
            };
            let content = release_content(ctx, &target, &env, &step.product).await?;
            let Some(suite) = content
                .manifest
                .gate
                .eval_suite
                .as_deref()
                .filter(|suite| !suite.is_empty())
            else {
                continue;
            };
            let decision =
                check_eval_gate(ctx, suite, &step.release_digest, &step.artifact_digest).await;
            let detail = match decision {
                GateDecision::Allowed => continue,
                GateDecision::Denied(detail) | GateDecision::Unavailable(detail) => detail,
            };
            let outcome = Outcome {
                step: step.clone(),
                status: "blocked".into(),
                detail: detail.clone(),
            };
            set_plan_state_confirmed(
                ctx,
                &mut stored_plan,
                PlanState::Blocked,
                skip_gates,
                detail,
            )
            .await?;
            return Ok(vec![outcome]);
        }
    }
    set_plan_state_confirmed(ctx, &mut stored_plan, PlanState::Running, skip_gates, "").await?;

    let mut outcomes = Vec::new();
    let mut plan_failed = false;
    let mut plan_blocked = false;
    let mut final_detail = String::new();

    for step in steps {
        if let Err(error) = refresh_environment_lease(ctx, lease).await {
            let detail = format!("refreshing environment apply lease failed: {error}");
            set_plan_state(
                ctx,
                &mut stored_plan,
                PlanState::Failed,
                skip_gates,
                &detail,
            )
            .await?;
            return Err(error.context(detail));
        }
        let outcome = match execute_step(ctx, &env, &plan_id, &step).await {
            Ok(outcome) => outcome,
            Err(error) => {
                set_plan_state(
                    ctx,
                    &mut stored_plan,
                    PlanState::Failed,
                    skip_gates,
                    error.to_string(),
                )
                .await?;
                return Err(error);
            }
        };
        if outcome.status == "blocked" {
            plan_blocked = true;
            final_detail = outcome.detail.clone();
        } else if outcome.status != "succeeded" {
            plan_failed = true;
            final_detail = outcome.detail.clone();
        }
        outcomes.push(outcome);
        if plan_blocked || plan_failed {
            break;
        }
    }

    let final_state = if plan_blocked {
        PlanState::Blocked
    } else if plan_failed {
        PlanState::Failed
    } else {
        PlanState::Succeeded
    };
    set_plan_state_confirmed(ctx, &mut stored_plan, final_state, skip_gates, final_detail).await?;

    Ok(outcomes)
}

async fn execute_step(ctx: &mut Ctx, env: &str, plan_oid: &str, step: &Step) -> Result<Outcome> {
    let target = ReleasePin {
        release_id: step.release_id.clone(),
        digest: step.release_digest.clone(),
        artifact_digest: step.artifact_digest.clone(),
        workdir: step.workdir.clone(),
    };
    let content = release_content(ctx, &target, env, &step.product).await?;
    let restore_content = match step.restore.as_ref() {
        Some(pin) => Some(release_content(ctx, pin, env, &step.product).await?),
        None => None,
    };

    if step.action == Action::Rollback
        && let Some(outgoing) = restore_content.as_ref()
        && outgoing
            .manifest
            .deploy
            .uninstall
            .as_deref()
            .is_some_and(|command| !command.is_empty())
    {
        let outgoing_executor = executor::select(outgoing.manifest.deploy.executor);
        let outgoing_input =
            executor_input(outgoing, step, Action::Rollback, Some(step.to.clone()));
        let cleanup_failure = deactivate(outgoing_executor, &outgoing_input, outgoing)
            .await
            .err();
        if let Some(detail) = cleanup_failure {
            let detail = format!("rollback blocked: outgoing release cleanup failed: {detail}");
            set_env_unknown(ctx, env, &step.product, &detail).await?;
            let outcome = Outcome {
                step: step.clone(),
                status: "failed".into(),
                detail,
            };
            record_deployment(ctx, env, plan_oid, &outcome).await?;
            return Ok(outcome);
        }
    }

    let target_executor = executor::select(content.manifest.deploy.executor);
    let target_input = executor_input(&content, step, step.action, step.from.clone());
    let activation = activate(target_executor, &target_input, &content).await;
    let outcome = match activation {
        Ok(()) => {
            let outcome = Outcome {
                step: step.clone(),
                status: "succeeded".into(),
                detail: String::new(),
            };
            if let Err(error) =
                set_env_deployed(ctx, env, &step.product, &step.to, step.from.as_deref()).await
            {
                compensate_activation(ctx, env, step, &content, &error).await;
                return Err(error);
            }
            if let Err(error) = record_deployment(ctx, env, plan_oid, &outcome).await {
                compensate_activation(ctx, env, step, &content, &error).await;
                return Err(error);
            }
            return Ok(outcome);
        }
        Err(detail) => {
            // Install or health failed: try to restore the previous release.
            match &step.from {
                Some(prev) => {
                    let (cleaned, detail) =
                        cleanup_failed_install(target_executor, &target_input, &content, detail)
                            .await;
                    let Some(prev_content) = restore_content.as_ref() else {
                        let detail =
                            format!("{detail}; step {} has no pinned restore release", step.id);
                        set_env_unknown(ctx, env, &step.product, &detail).await?;
                        let outcome = Outcome {
                            step: step.clone(),
                            status: "failed".into(),
                            detail,
                        };
                        record_deployment(ctx, env, plan_oid, &outcome).await?;
                        return Ok(outcome);
                    };
                    let previous_executor = executor::select(prev_content.manifest.deploy.executor);
                    let previous_input =
                        executor_input(prev_content, step, Action::Rollback, Some(step.to.clone()));
                    let (restored, detail) = restore_previous(
                        previous_executor,
                        &previous_input,
                        prev_content,
                        prev,
                        detail,
                    )
                    .await;
                    let recovered = cleaned && restored;
                    if !recovered {
                        set_env_unknown(ctx, env, &step.product, &detail).await?;
                    }
                    Outcome {
                        step: step.clone(),
                        status: if recovered { "rolled_back" } else { "failed" }.into(),
                        detail,
                    }
                }
                None => {
                    let (cleaned, detail) =
                        cleanup_failed_install(target_executor, &target_input, &content, detail)
                            .await;
                    if !cleaned {
                        set_env_unknown(ctx, env, &step.product, &detail).await?;
                    }
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
    let mut deployment = record(
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
            ("status".into(), "failed".into()),
            ("detail".into(), "deployment bookkeeping incomplete".into()),
        ]),
    );
    ctx.put(deployment.clone()).await?;
    ctx.link(&did, &outcome.step.release_id, REL_DEPLOYED_RELEASE)
        .await?;
    ctx.link(&did, &env_id(env), REL_IN_ENVIRONMENT).await?;
    ctx.link(&did, plan_oid, REL_PART_OF_PLAN).await?;
    deployment
        .properties
        .insert("status".into(), outcome.status.clone());
    deployment
        .properties
        .insert("detail".into(), outcome.detail.clone());
    deployment.updated = crate::now_millis();
    match ctx.put(deployment).await {
        Ok(_) => Ok(()),
        Err(error) => {
            let persisted = ctx.get(&did).await;
            if matches!(
                persisted,
                Ok(Some(ref object))
                    if object.properties.get("status") == Some(&outcome.status)
                        && object.properties.get("detail") == Some(&outcome.detail)
            ) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use crate::executor::{ExecutorFuture, ExecutorPhase, ExecutorResult};
    use crate::manifest::{DeploySection, GateSection, ProductSection};
    use crate::pb::chisei::CaseResult;

    fn test_dir(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tenkai-{name}-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn content(
        workdir: std::path::PathBuf,
        install: &str,
        health: Option<&str>,
        uninstall: Option<&str>,
    ) -> ReleaseContent {
        ReleaseContent {
            release_id: "release:api:1.0.0".into(),
            manifest: Manifest {
                product: ProductSection {
                    name: "api".into(),
                    version: "1.0.0".into(),
                    description: String::new(),
                },
                deploy: DeploySection {
                    executor: crate::executor::ExecutorKind::LocalShell,
                    workdir: ".".into(),
                    install: install.into(),
                    inputs: Vec::new(),
                    uninstall: uninstall.map(str::to_string),
                    health: health.map(str::to_string),
                },
                gate: GateSection::default(),
            },
            artifact_digest: manifest::artifact_digest(&workdir, &[]).unwrap(),
            workdir,
            environment: "test".into(),
            product: "api".into(),
        }
    }

    fn step() -> Step {
        Step {
            id: "plan:step:0".into(),
            order: 0,
            product: "api".into(),
            action: Action::Install,
            from: None,
            to: "1.0.0".into(),
            release_id: "release:api:1.0.0".into(),
            release_digest: "manifest".into(),
            artifact_digest: "artifact".into(),
            workdir: ".".into(),
            restore: None,
        }
    }

    struct FakeExecutor {
        results: Mutex<VecDeque<ExecutorResult>>,
    }

    impl FakeExecutor {
        fn returning(results: impl IntoIterator<Item = ExecutorResult>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
            }
        }

        fn next(&self) -> ExecutorResult {
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .expect("fake executor result")
        }
    }

    impl Executor for FakeExecutor {
        fn activate<'a>(&'a self, _input: &'a ExecutorInput) -> ExecutorFuture<'a> {
            let result = self.next();
            Box::pin(async move { result })
        }

        fn deactivate<'a>(&'a self, _input: &'a ExecutorInput) -> ExecutorFuture<'a> {
            let result = self.next();
            Box::pin(async move { result })
        }
    }

    #[test]
    fn gate_uses_latest_run_and_reports_failed_cases() {
        let runs = vec![
            EvalRun {
                timestamp: 1,
                results: vec![CaseResult {
                    case_id: "old".into(),
                    passed: true,
                    ..Default::default()
                }],
                ..Default::default()
            },
            EvalRun {
                timestamp: 2,
                results: vec![CaseResult {
                    case_id: "smoke".into(),
                    passed: false,
                    ..Default::default()
                }],
                ..Default::default()
            },
        ];
        match evaluate_gate(&runs, "suite", &["smoke".into()]) {
            GateDecision::Denied(detail) => assert!(detail.contains("smoke")),
            _ => panic!("latest failing run must deny the gate"),
        }
    }

    #[test]
    fn gate_rejects_incomplete_or_duplicate_case_results() {
        let run = EvalRun {
            results: vec![
                CaseResult {
                    case_id: "first".into(),
                    passed: true,
                    ..Default::default()
                },
                CaseResult {
                    case_id: "first".into(),
                    passed: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(matches!(
            evaluate_gate(&[run], "suite", &["first".into(), "second".into()]),
            GateDecision::Denied(detail) if detail.contains("exactly one result")
        ));
    }

    #[test]
    fn gate_reference_changes_with_artifact_or_suite_content() {
        let mut suite = EvalSuite {
            id: "suite".into(),
            name: "quality".into(),
            ..Default::default()
        };
        let original = gate_config_ref("manifest", "artifact-one", &suite);
        let changed_artifact = gate_config_ref("manifest", "artifact-two", &suite);
        suite.description = "tightened checks".into();
        let changed_suite = gate_config_ref("manifest", "artifact-one", &suite);

        assert_ne!(original, changed_artifact);
        assert_ne!(original, changed_suite);
    }

    #[tokio::test]
    async fn fake_executor_exercises_activation_success_without_commands() {
        let dir = test_dir("fake-success");
        let release = content(dir.clone(), "touch command-ran", None, None);
        let step = step();
        let input = executor_input(&release, &step, step.action, step.from.clone());
        let fake = FakeExecutor::returning([ExecutorResult::succeeded(ExecutorPhase::Install)]);

        assert_eq!(activate(&fake, &input, &release).await, Ok(()));
        assert!(!dir.join("command-ran").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn fake_executor_exercises_install_failure_without_commands() {
        let dir = test_dir("fake-failure");
        let release = content(dir.clone(), "touch command-ran", None, None);
        let step = step();
        let input = executor_input(&release, &step, step.action, step.from.clone());
        let fake = FakeExecutor::returning([ExecutorResult::failed(
            ExecutorPhase::Install,
            "install rejected",
        )]);

        assert_eq!(
            activate(&fake, &input, &release).await,
            Err("install rejected".into())
        );
        assert!(!dir.join("command-ran").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn fake_executor_exercises_health_failure_without_commands() {
        let dir = test_dir("fake-health");
        let release = content(
            dir.clone(),
            "touch command-ran",
            Some("touch health-ran"),
            None,
        );
        let step = step();
        let input = executor_input(&release, &step, step.action, step.from.clone());
        let fake = FakeExecutor::returning([ExecutorResult::failed(
            ExecutorPhase::Health,
            "health rejected",
        )]);

        assert_eq!(
            activate(&fake, &input, &release).await,
            Err("health rejected".into())
        );
        assert!(!dir.join("command-ran").exists());
        assert!(!dir.join("health-ran").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn fake_executor_exercises_restore_without_commands() {
        let dir = test_dir("fake-restore");
        let previous = content(dir.clone(), "touch command-ran", None, None);
        let step = step();
        let input = executor_input(&previous, &step, Action::Rollback, Some("2.0.0".into()));
        let fake = FakeExecutor::returning([ExecutorResult::succeeded(ExecutorPhase::Install)]);

        let (restored, detail) =
            restore_previous(&fake, &input, &previous, "1.0.0", "upgrade failed".into()).await;

        assert!(restored);
        assert!(detail.contains("restored 1.0.0"));
        assert!(!dir.join("command-ran").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn activation_runs_health_after_install() {
        let dir = test_dir("health");
        let release = content(
            dir.clone(),
            "touch installed",
            Some("test -f healthy"),
            None,
        );
        let step = step();
        let input = executor_input(&release, &step, step.action, step.from.clone());
        let failure = activate(
            executor::select(release.manifest.deploy.executor),
            &input,
            &release,
        )
        .await
        .unwrap_err();
        assert!(dir.join("installed").exists());
        assert!(failure.contains("deployment command exited"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn activation_rejects_mutated_immutable_inputs() {
        let dir = test_dir("immutable-inputs");
        std::fs::write(dir.join("deploy.sh"), "original\n").unwrap();
        let mut release = content(dir.clone(), "echo changed > deploy.sh", None, None);
        release.manifest.deploy.inputs = vec!["deploy.sh".into()];
        release.artifact_digest =
            manifest::artifact_digest(&release.workdir, &release.manifest.deploy.inputs).unwrap();

        let step = step();
        let input = executor_input(&release, &step, step.action, step.from.clone());
        let failure = activate(
            executor::select(release.manifest.deploy.executor),
            &input,
            &release,
        )
        .await
        .unwrap_err();

        assert!(failure.contains("immutable deployment inputs changed"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn restore_requires_the_previous_release_to_be_healthy() {
        let dir = test_dir("restore");
        let previous = content(dir.clone(), "touch restored", Some("false"), None);
        let step = step();
        let input = executor_input(&previous, &step, Action::Rollback, Some("2.0.0".into()));
        let (restored, detail) = restore_previous(
            executor::select(previous.manifest.deploy.executor),
            &input,
            &previous,
            "1.0.0",
            "upgrade failed".into(),
        )
        .await;
        assert!(!restored);
        assert!(dir.join("restored").exists());
        assert!(detail.contains("health check of 1.0.0 also failed"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_fresh_install_runs_cleanup() {
        let dir = test_dir("cleanup");
        let release = content(dir.clone(), "false", None, Some("touch cleaned"));
        let step = step();
        let input = executor_input(&release, &step, step.action, step.from.clone());
        let (cleaned, detail) = cleanup_failed_install(
            executor::select(release.manifest.deploy.executor),
            &input,
            &release,
            "install failed".into(),
        )
        .await;
        assert!(cleaned);
        assert!(dir.join("cleaned").exists());
        assert!(detail.contains("cleaned up failed install"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
