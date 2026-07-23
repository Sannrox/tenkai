//! Plan execution: eval gates, install commands, health probes, auto-rollback.
//!
//! Every execution writes durable plan and deployment objects so Tenkai can
//! answer "what ran, when, gated by what, and what happened" after the fact.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context as _, Result, bail};
use prost::Message as _;
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::maintenance::{self, Eligibility};
use crate::manifest::{self, Manifest};
use crate::ontology::*;
use crate::pb::chisei::{EvalRun, EvalSuite};
use crate::pb::sekai::{Lease, Link, Object};
use crate::plan::{self, Action, Plan, PlanState, ReleasePin, Step};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Outcome {
    pub step: Step,
    pub status: String, // succeeded | failed | rolled_back
    pub detail: String,
}

async fn maintenance_decision(
    ctx: &mut Ctx,
    environment: &str,
    emergency_reason: Option<&str>,
) -> Result<MaintenanceDecision> {
    let eligibility = match maintenance::list(ctx, environment).await {
        Ok(windows) => {
            let now = chrono::DateTime::from_timestamp_millis(crate::now_millis())
                .context("current time is outside the supported maintenance-window range")?;
            maintenance::evaluate(&windows, now)
        }
        Err(error) => Eligibility::Invalid {
            detail: format!("maintenance window configuration is invalid: {error}"),
        },
    };
    if let Some(reason) = emergency_reason {
        return Ok(MaintenanceDecision::EmergencyOverride(reason.into()));
    }
    Ok(match eligibility {
        Eligibility::Open { closes_at, .. } => MaintenanceDecision::Allowed { closes_at },
        Eligibility::Closed { next_opens_at } => {
            MaintenanceDecision::Denied(next_opens_at.map_or_else(
                || "maintenance window is closed".to_string(),
                |next| {
                    format!(
                        "maintenance window is closed; next opens at {}",
                        format_maintenance_timestamp(next)
                    )
                },
            ))
        }
        Eligibility::Invalid { detail } => MaintenanceDecision::Denied(format!(
            "maintenance window evaluation failed closed: {detail}"
        )),
    })
}

fn format_maintenance_timestamp(timestamp_millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(timestamp_millis).map_or_else(
        || format!("unrepresentable timestamp ({timestamp_millis} ms since epoch)"),
        |timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

async fn record_maintenance_decision(
    ctx: &mut Ctx,
    plan: &Plan,
    decision: &MaintenanceDecision,
) -> Result<()> {
    if let MaintenanceDecision::EmergencyOverride(reason) = decision {
        ctx.authorize_emergency_override(&plan.id, reason).await?;
    }
    Ok(())
}

async fn block_for_maintenance(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    skip_gates: bool,
    detail: &str,
) -> Result<Vec<Outcome>> {
    plan.state = PlanState::Blocked;
    plan.gates_skipped = Some(skip_gates);
    plan.status_detail = detail.into();
    plan.maintenance_blocked = true;
    ctx.guarded_update(
        plan.to_object()?,
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Err(MaintenanceBlocked(detail.to_string()).into())
}

#[cfg(test)]
fn is_maintenance_block_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<MaintenanceBlocked>().is_some()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExecutionOptions<'a> {
    pub skip_gates: bool,
    pub emergency_reason: Option<&'a str>,
    pub approval: Option<&'a Path>,
    pub approval_trust_roots: Option<&'a Path>,
    pub unapproved_development_reason: Option<&'a str>,
}

enum MaintenanceDecision {
    Allowed { closes_at: i64 },
    Denied(String),
    EmergencyOverride(String),
}

#[derive(Debug)]
struct MaintenanceBlocked(String);

impl std::fmt::Display for MaintenanceBlocked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for MaintenanceBlocked {}

fn validate_emergency_override(reason: Option<&str>) -> Result<Option<&str>> {
    let reason = reason.map(str::trim);
    if reason.is_some_and(str::is_empty) {
        bail!("emergency maintenance override requires a non-empty reason");
    }
    Ok(reason)
}

#[cfg(test)]
async fn run_command(
    cmd: &str,
    workdir: &Path,
    environment: &str,
    product: &str,
) -> Result<Result<(), String>> {
    let identity_digest = manifest::digest(&format!("{environment}\0{product}"));
    let compose_project = format!("tenkai-{}", &identity_digest[..16]);
    let mut command = tokio::process::Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .current_dir(workdir)
        .kill_on_drop(true)
        .env_remove("SEKAI_AUTH_TOKEN")
        .env("TENKAI_ENVIRONMENT", environment)
        .env("TENKAI_PRODUCT", product)
        .env("COMPOSE_PROJECT_NAME", compose_project)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().context("spawning deployment command")?;
    let process_group = child.id().map(|id| -(id as i32));
    let mut wait = Box::pin(child.wait());
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(600));
    tokio::pin!(timeout);
    let (status, interrupted) = tokio::select! {
        status = &mut wait => (Some(status?), None),
        _ = &mut timeout => (None, Some("deployment command exceeded the 10 minute timeout")),
        _ = interrupt.recv() => (None, Some("deployment command interrupted")),
        _ = terminate.recv() => (None, Some("deployment command terminated")),
    };
    if let Some(reason) = interrupted {
        if let Some(process_group) = process_group {
            // The shell is the process-group leader; a negative PID kills the full tree.
            unsafe {
                libc::kill(process_group, libc::SIGKILL);
            }
        }
        let _ = wait.await;
        return Ok(Err(reason.into()));
    }
    let status = status.expect("completed command has an exit status");
    if status.success() {
        Ok(Ok(()))
    } else {
        Ok(Err(format!("deployment command exited with {status}")))
    }
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
    let suite = match ctx.eval_suite(suite_id).await {
        Ok(Some(suite)) => suite,
        Ok(None) => {
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
    let summaries = match ctx.eval_runs(suite_id).await {
        Ok(runs) => runs,
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
    match ctx.eval_run(&latest.id).await {
        Ok(run) => match run {
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
    manifest: Manifest,
    artifact_digest: String,
    workdir: std::path::PathBuf,
    environment: String,
    product: String,
    mutation_lock: std::path::PathBuf,
}

fn verify_content_integrity(content: &ReleaseContent) -> Result<()> {
    let actual = manifest::artifact_digest(&content.workdir, &content.manifest.deploy.inputs)?;
    if actual != content.artifact_digest {
        bail!("immutable deployment inputs changed while executing release");
    }
    Ok(())
}

#[cfg(test)]
async fn activate(content: &ReleaseContent) -> Result<Result<(), String>> {
    let install = run_command(
        &content.manifest.deploy.install,
        &content.workdir,
        &content.environment,
        &content.product,
    )
    .await?;
    let result = match install {
        Ok(()) => match &content.manifest.deploy.health {
            Some(command) if !command.is_empty() => {
                run_command(
                    command,
                    &content.workdir,
                    &content.environment,
                    &content.product,
                )
                .await
            }
            _ => Ok(Ok(())),
        },
        error => Ok(error),
    }?;
    match verify_content_integrity(content) {
        Ok(()) => Ok(result),
        Err(error) => Ok(Err(error.to_string())),
    }
}

#[cfg(test)]
async fn deactivate(content: &ReleaseContent) -> Result<Result<(), String>> {
    match content.manifest.deploy.uninstall.as_deref() {
        Some(command) if !command.is_empty() => {
            let result = run_command(
                command,
                &content.workdir,
                &content.environment,
                &content.product,
            )
            .await?;
            match verify_content_integrity(content) {
                Ok(()) => Ok(result),
                Err(error) => Ok(Err(error.to_string())),
            }
        }
        _ => Ok(Err("release has no uninstall command".into())),
    }
}

async fn activate_fenced(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
) -> Result<Result<(), String>> {
    let install =
        run_mutation_command(ctx, lease, content, &content.manifest.deploy.install).await?;
    let result = match install {
        Ok(()) => match &content.manifest.deploy.health {
            Some(command) if !command.is_empty() => {
                run_mutation_command(ctx, lease, content, command).await
            }
            _ => Ok(Ok(())),
        },
        error => Ok(error),
    }?;
    match verify_content_integrity(content) {
        Ok(()) => Ok(result),
        Err(error) => Ok(Err(error.to_string())),
    }
}

async fn deactivate_fenced(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
) -> Result<Result<(), String>> {
    match content.manifest.deploy.uninstall.as_deref() {
        Some(command) if !command.is_empty() => {
            let result = run_mutation_command(ctx, lease, content, command).await?;
            match verify_content_integrity(content) {
                Ok(()) => Ok(result),
                Err(error) => Ok(Err(error.to_string())),
            }
        }
        _ => Ok(Err("release has no uninstall command".into())),
    }
}

async fn restore_previous_fenced(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    version: &str,
    failure: String,
) -> Result<(bool, String)> {
    Ok(match activate_fenced(ctx, lease, content).await {
        Ok(Ok(())) => (true, format!("{failure}; restored {version}")),
        Ok(Err(restore)) => (
            false,
            format!("{failure}; restore or health check of {version} also failed: {restore}"),
        ),
        Err(error) => (
            false,
            format!("{failure}; restore executor failed for {version}: {error}"),
        ),
    })
}

async fn cleanup_failed_install_fenced(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    failure: String,
) -> Result<(bool, String)> {
    Ok(match content.manifest.deploy.uninstall.as_deref() {
        Some(_) => match deactivate_fenced(ctx, lease, content).await {
            Ok(Ok(())) => (true, format!("{failure}; cleaned up failed install")),
            Ok(Err(cleanup)) => (false, format!("{failure}; cleanup also failed: {cleanup}")),
            Err(error) => (
                false,
                format!("{failure}; cleanup executor also failed: {error}"),
            ),
        },
        None => (false, failure),
    })
}

#[cfg(test)]
async fn restore_previous(
    content: &ReleaseContent,
    version: &str,
    failure: String,
) -> Result<(bool, String)> {
    Ok(match activate(content).await {
        Ok(Ok(())) => (true, format!("{failure}; restored {version}")),
        Ok(Err(restore)) => (
            false,
            format!("{failure}; restore or health check of {version} also failed: {restore}"),
        ),
        Err(error) => (
            false,
            format!("{failure}; restore executor failed for {version}: {error}"),
        ),
    })
}

#[cfg(test)]
async fn cleanup_failed_install(
    content: &ReleaseContent,
    failure: String,
) -> Result<(bool, String)> {
    Ok(match content.manifest.deploy.uninstall.as_deref() {
        Some(_) => match deactivate(content).await {
            Ok(Ok(())) => (true, format!("{failure}; cleaned up failed install")),
            Ok(Err(cleanup)) => (false, format!("{failure}; cleanup also failed: {cleanup}")),
            Err(error) => (
                false,
                format!("{failure}; cleanup executor also failed: {error}"),
            ),
        },
        None => (false, failure),
    })
}

async fn compensate_activation(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    env: &str,
    step: &Step,
    content: &ReleaseContent,
    failure: &anyhow::Error,
) {
    let failure = format!("deployment bookkeeping failed after activation: {failure}");
    let cleaned = matches!(deactivate_fenced(ctx, lease, content).await, Ok(Ok(())));
    let mut restored = step.from.is_none();

    if let (Some(previous), Some(pin)) = (step.from.as_deref(), step.restore.as_ref())
        && let Ok(previous_content) = release_content(ctx, pin, env, &step.product).await
        && matches!(
            activate_fenced(ctx, lease, &previous_content).await,
            Ok(Ok(()))
        )
    {
        restored = set_env_deployed(ctx, lease, env, &step.product, previous, Some(&step.to))
            .await
            .is_ok();
    }

    // A graph write already failed, so this update is necessarily best effort.
    // Marking the target unknown is safer than claiming a version that may not
    // match the external deployment after incomplete compensation.
    if !cleaned || !restored || step.from.is_none() {
        let _ = set_env_unknown(ctx, lease, env, &step.product, &failure).await;
    }
}

async fn release_content(
    ctx: &mut Ctx,
    pin: &ReleasePin,
    environment: &str,
    product: &str,
) -> Result<ReleaseContent> {
    use crate::catalog::CatalogReader as _;

    let descriptor = crate::catalog::EmbeddedCatalog::new(ctx)
        .lookup_release(&pin.release_id, environment)
        .await?;
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
    if obj
        .properties
        .get("recalled_at")
        .is_some_and(|value| !value.is_empty())
    {
        bail!("release {} is recalled", pin.release_id);
    }
    // Validate the exact snapshot consumed below as well as the Catalog
    // descriptor fetched above; the compatibility store does not yet provide
    // a transactional read spanning those records.
    crate::catalog::require_deployable_trust(ctx, &obj, environment).await?;
    let raw = obj.properties.get("manifest").cloned().unwrap_or_default();
    let stored_digest = obj.properties.get("digest").cloned().unwrap_or_default();
    let actual_digest = manifest::digest(&raw);
    if descriptor.manifest_digest != pin.digest
        || stored_digest != pin.digest
        || actual_digest != pin.digest
    {
        bail!(
            "release {} content no longer matches pinned digest {}",
            pin.release_id,
            pin.digest
        );
    }
    let manifest = manifest::parse_raw(&raw)
        .with_context(|| format!("parsing stored manifest of {}", pin.release_id))?;
    if descriptor.artifact_digest != pin.artifact_digest || descriptor.content_path != pin.workdir {
        bail!(
            "release {} descriptor no longer matches its plan pin",
            pin.release_id
        );
    }
    let actual_artifact_digest =
        manifest::artifact_digest(Path::new(&descriptor.content_path), &manifest.deploy.inputs)?;
    if actual_artifact_digest != descriptor.artifact_digest {
        bail!(
            "release {} immutable deploy inputs no longer match pinned artifact digest {}",
            pin.release_id,
            pin.artifact_digest
        );
    }
    let workdir = manifest::execution_workdir(
        Path::new(&descriptor.content_path),
        &manifest.deploy.inputs,
        &pin.artifact_digest,
        environment,
        product,
    )?;
    let state_dir = Path::new(&descriptor.content_path)
        .parent()
        .and_then(Path::parent)
        .context("release snapshot is not inside the Tenkai state directory")?;
    Ok(ReleaseContent {
        manifest,
        artifact_digest: pin.artifact_digest.clone(),
        workdir,
        environment: environment.to_string(),
        product: product.to_string(),
        mutation_lock: state_dir
            .join("runtime")
            .join(environment)
            .join(".mutation.lock"),
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
    lease: &EnvironmentLease,
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
    ctx.guarded_update(
        env_obj,
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

async fn set_env_unknown(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    env: &str,
    product: &str,
    detail: &str,
) -> Result<()> {
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
    ctx.guarded_update(
        environment,
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

async fn set_plan_state(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    state: PlanState,
    gates_skipped: bool,
    detail: impl Into<String>,
) -> Result<()> {
    plan.state = state;
    plan.gates_skipped = Some(gates_skipped);
    plan.status_detail = detail.into();
    plan.maintenance_blocked = false;
    ctx.guarded_update(
        plan.to_object()?,
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

async fn set_plan_state_confirmed(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    state: PlanState,
    gates_skipped: bool,
    detail: impl Into<String>,
) -> Result<()> {
    let detail = detail.into();
    if let Err(error) = set_plan_state(ctx, lease, plan, state, gates_skipped, detail.clone()).await
    {
        let persisted = plan::load(ctx, &plan.id).await;
        if !matches!(
            persisted,
            Ok(ref stored)
                if stored.state == state
                    && stored.gates_skipped == Some(gates_skipped)
                    && stored.status_detail == detail
                    && !stored.maintenance_blocked
        ) {
            return Err(error);
        }
    }
    Ok(())
}

fn legacy_environment_claim_id(environment: &str) -> String {
    format!("{}:execution", env_id(environment))
}

fn object_environment_claim_id(environment: &str) -> String {
    format!("{}:execution:v2", env_id(environment))
}

const ENVIRONMENT_LEASE_MS: i64 = 2 * 60 * 60 * 1000;
const EXECUTION_LEASE_MS: i64 = 30_000;
const MANUAL_UNLOCK_LEASE_MS: i64 = 5_000;
const ENVIRONMENT_LEASE_NAMESPACE: &str = "tenkai/environment-execution";
const REL_ACTIVE_ENVIRONMENT_EXECUTION: &str = "active_environment_execution";

pub(crate) struct EnvironmentLease {
    environment: String,
    owner: String,
    generation: u64,
    fencing_token: String,
    ttl_ms: i64,
}

fn object_environment_claim(environment: &str, owner: &str, expires_at_ms: i64) -> Object {
    record(
        object_environment_claim_id(environment),
        KIND_ENVIRONMENT_EXECUTION,
        format!("apply lease for {environment}"),
        HashMap::from([
            ("environment".into(), environment.into()),
            ("owner".into(), owner.into()),
            ("expires_at".into(), expires_at_ms.to_string()),
        ]),
    )
}

fn object_environment_claim_for_lease(lease: &EnvironmentLease, expires_at_ms: i64) -> Object {
    let mut object = object_environment_claim(&lease.environment, &lease.owner, expires_at_ms);
    object
        .properties
        .insert("generation".into(), lease.generation.to_string());
    object
}

fn object_environment_claim_link(environment: &str) -> Link {
    let environment_id = env_id(environment);
    let lease_id = object_environment_claim_id(environment);
    Link {
        id: format!("{environment_id}--{REL_ACTIVE_ENVIRONMENT_EXECUTION}--{lease_id}"),
        from_id: environment_id,
        to_id: lease_id,
        relation: REL_ACTIVE_ENVIRONMENT_EXECUTION.into(),
        created: crate::now_millis(),
    }
}

async fn release_object_environment_claim(ctx: &mut Ctx, environment: &str) -> Result<()> {
    let claim_id = object_environment_claim_id(environment);
    if let Some(mut existing) = ctx.get(&claim_id).await? {
        existing
            .properties
            .insert("owner".into(), "released".into());
        existing.properties.insert("expires_at".into(), "0".into());
        existing.updated = crate::now_millis();
        ctx.put(existing).await?;
    }
    ctx.unlink(
        &env_id(environment),
        &claim_id,
        REL_ACTIVE_ENVIRONMENT_EXECUTION,
    )
    .await?;
    Ok(())
}

async fn mark_object_environment_claim_released(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
) -> Result<()> {
    let mut claim = ctx
        .get(&object_environment_claim_id(&lease.environment))
        .await?
        .context("object-backed environment apply lease disappeared")?;
    claim.properties.insert("owner".into(), "released".into());
    claim.properties.insert("expires_at".into(), "0".into());
    claim.updated = crate::now_millis();
    ctx.guarded_update(
        claim,
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

pub(crate) async fn claim_environment(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
) -> Result<EnvironmentLease> {
    claim_environment_with_options(ctx, environment, owner, ENVIRONMENT_LEASE_MS, false).await
}

async fn claim_execution_environment(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
) -> Result<EnvironmentLease> {
    claim_environment_with_options(ctx, environment, owner, EXECUTION_LEASE_MS, true).await
}

async fn claim_environment_with_options(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
    ttl_ms: i64,
    automatic_takeover: bool,
) -> Result<EnvironmentLease> {
    let now = crate::now_millis();
    if let Some(existing) = ctx.get(&legacy_environment_claim_id(environment)).await? {
        let expires_at = existing
            .properties
            .get("expires_at")
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(i64::MAX);
        if expires_at <= now {
            bail!(
                "environment {environment} has an expired legacy apply lease; verify no apply is running, then run `tenkaictl env unlock {environment}`"
            );
        }
        bail!("environment {environment} already has a legacy apply in progress");
    }
    let object_claim_id = object_environment_claim_id(environment);
    let has_object_claim = ctx
        .links(&env_id(environment), REL_ACTIVE_ENVIRONMENT_EXECUTION)
        .await?
        .into_iter()
        .any(|link| link.to_id == object_claim_id);
    if has_object_claim {
        match get_environment_lease(ctx, environment).await? {
            Some(existing) if existing.status == "active" => {
                if existing.expires_at_ms > now {
                    bail!(
                        "environment {environment} already has an apply in progress owned by {}",
                        existing.owner
                    );
                }
            }
            _ => {
                let claim = ctx
                    .get(&object_claim_id)
                    .await?
                    .context("object-backed environment apply lease disappeared")?;
                if claim.properties.get("owner").map(String::as_str) != Some("released") {
                    bail!(
                        "environment {environment} has an object-backed apply lease without an active Tenkai lease; finish any older controller, then run `tenkaictl env unlock {environment}`"
                    );
                }
            }
        }
    }
    let lease = match ctx
        .acquire_lease(ENVIRONMENT_LEASE_NAMESPACE, environment, owner, ttl_ms)
        .await
    {
        Ok(lease) => lease,
        Err(error)
            if error
                .downcast_ref::<tonic::Status>()
                .is_some_and(|status| status.code() == tonic::Code::AlreadyExists) =>
        {
            if let Some(existing) = get_environment_lease(ctx, environment).await? {
                if existing.status == "active" && existing.expires_at_ms <= now {
                    if !automatic_takeover {
                        bail!(
                            "environment {environment} has an expired apply lease; verify no operation is running, then run `tenkaictl env unlock {environment}`"
                        );
                    }
                    ctx.takeover_expired_lease(
                        ENVIRONMENT_LEASE_NAMESPACE,
                        environment,
                        owner,
                        &existing.fencing_token,
                        existing.expires_at_ms,
                        ttl_ms,
                    )
                    .await?
                } else {
                    bail!(
                        "environment {environment} already has an apply in progress owned by {}",
                        existing.owner
                    );
                }
            } else {
                return Err(error);
            }
        }
        Err(error) => return Err(error),
    };
    let environment_lease = EnvironmentLease {
        environment: environment.into(),
        owner: owner.into(),
        generation: lease.generation,
        fencing_token: lease.fencing_token,
        ttl_ms,
    };
    let available = object_environment_claim(environment, "released", 0);
    match ctx.create_once(available).await {
        Ok(_) => {}
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && (status.message().contains("UNIQUE")
                        || status.message().contains("object IDs with audit history"))) => {}
        Err(status) => {
            let _ = release_environment_lease(ctx, &environment_lease).await;
            return Err(status.into());
        }
    }
    if !has_object_claim
        && let Err(status) = ctx
            .create_link_once(object_environment_claim_link(environment))
            .await
    {
        let _ = release_environment_lease(ctx, &environment_lease).await;
        if status.code() == tonic::Code::AlreadyExists
            || (status.code() == tonic::Code::Internal && status.message().contains("UNIQUE"))
        {
            bail!("environment {environment} already has an apply in progress");
        }
        return Err(status.into());
    }
    if let Err(error) = ctx
        .guarded_update(
            object_environment_claim_for_lease(&environment_lease, lease.expires_at_ms),
            ENVIRONMENT_LEASE_NAMESPACE,
            &environment_lease.environment,
            &environment_lease.fencing_token,
        )
        .await
    {
        let _ = release_environment_lease(ctx, &environment_lease).await;
        return Err(error);
    }
    Ok(environment_lease)
}

async fn refresh_environment_lease(ctx: &mut Ctx, lease: &EnvironmentLease) -> Result<()> {
    let refreshed = ctx
        .refresh_lease(
            ENVIRONMENT_LEASE_NAMESPACE,
            &lease.environment,
            &lease.fencing_token,
            lease.ttl_ms,
        )
        .await?;
    if refreshed.generation != lease.generation || refreshed.owner != lease.owner {
        bail!("Tenkai refreshed a different environment lease generation");
    }
    ctx.guarded_update(
        object_environment_claim_for_lease(lease, refreshed.expires_at_ms),
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

fn executor_guard_executable() -> Result<PathBuf> {
    if let Some(configured) = std::env::var_os("TENKAI_EXECUTOR_GUARD") {
        let configured = PathBuf::from(configured);
        if configured.is_file() {
            return Ok(configured);
        }
        bail!(
            "TENKAI_EXECUTOR_GUARD does not identify a file: {}",
            configured.display()
        );
    }
    let current = std::env::current_exe()?;
    if current
        .file_stem()
        .is_some_and(|name| name.to_string_lossy().starts_with("tenkaictl"))
    {
        return Ok(current);
    }
    for directory in current.ancestors().skip(1).take(2) {
        let candidate = directory.join("tenkai-executor-guard");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!(
        "tenkai-executor-guard was not found beside {}; install both Tenkai binaries or set TENKAI_EXECUTOR_GUARD",
        current.display()
    )
}

async fn run_mutation_command(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    cmd: &str,
) -> Result<Result<(), String>> {
    refresh_environment_lease(ctx, lease).await?;
    if let Some(parent) = content.mutation_lock.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut guard_command = tokio::process::Command::new(executor_guard_executable()?);
    if guard_command
        .as_std()
        .get_program()
        .to_string_lossy()
        .contains("tenkaictl")
    {
        guard_command.arg("__executor-guard");
    }
    guard_command
        .arg("--lock")
        .arg(&content.mutation_lock)
        .arg("--workdir")
        .arg(&content.workdir)
        .arg("--environment")
        .arg(&content.environment)
        .arg("--product")
        .arg(&content.product)
        .arg("--generation")
        .arg(lease.generation.to_string())
        .arg("--command")
        .arg(cmd)
        .kill_on_drop(true)
        .env_remove("SEKAI_AUTH_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guard = guard_command
        .spawn()
        .context("spawning deployment command guard")?;
    let mut control = guard
        .stdin
        .take()
        .context("deployment guard has no control pipe")?;
    let mut readiness = guard
        .stdout
        .take()
        .context("deployment guard has no readiness pipe")?;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut ready = [0_u8; 1];
    let mut ready_read = Box::pin(readiness.read_exact(&mut ready));
    let mut waiting_refresh = tokio::time::interval(std::time::Duration::from_secs(10));
    waiting_refresh.tick().await;
    loop {
        tokio::select! {
            result = &mut ready_read => {
                result?;
                break;
            }
            _ = waiting_refresh.tick() => refresh_environment_lease(ctx, lease).await?,
        }
    }
    drop(ready_read);
    if ready != *b"R" {
        bail!("deployment command guard failed to acquire the mutation fence");
    }
    refresh_environment_lease(ctx, lease).await?;
    control.write_all(b"G").await?;
    let mut wait = Box::pin(guard.wait());
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(600));
    tokio::pin!(timeout);
    let mut refresh = tokio::time::interval(std::time::Duration::from_secs(10));
    refresh.tick().await;
    let (status, interrupted) = loop {
        tokio::select! {
            status = &mut wait => break (Some(status?), None),
            _ = &mut timeout => break (None, Some("deployment command exceeded the 10 minute timeout".to_string())),
            _ = interrupt.recv() => break (None, Some("deployment command interrupted".to_string())),
            _ = terminate.recv() => break (None, Some("deployment command terminated".to_string())),
            _ = refresh.tick() => {
                if let Err(error) = refresh_environment_lease(ctx, lease).await {
                    break (None, Some(format!("deployment command lost its environment fence: {error}")));
                }
            }
        }
    };
    if let Some(reason) = interrupted {
        drop(control);
        let _ = wait.await;
        return Ok(Err(reason));
    }
    refresh_environment_lease(ctx, lease).await?;
    let status = status.expect("completed command has an exit status");
    Ok(if status.success() {
        Ok(())
    } else {
        Err(format!("deployment command exited with {status}"))
    })
}

/// Hidden executor supervisor used by `tenkaictl` itself. It owns the local
/// mutation lock, starts only after the controller proves its lease generation,
/// and kills the complete command group when the controller pipe closes.
pub async fn executor_guard(
    lock_path: &Path,
    workdir: &Path,
    environment: &str,
    product: &str,
    generation: u64,
    command: &str,
) -> Result<()> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    std::io::stdout().write_all(b"R")?;
    std::io::stdout().flush()?;
    let mut go = [0_u8; 1];
    std::io::stdin().read_exact(&mut go)?;
    if go != *b"G" {
        bail!("executor guard did not receive start authorization");
    }

    let identity_digest = manifest::digest(&format!("{environment}\0{product}"));
    let mut child = tokio::process::Command::new("sh");
    child
        .arg("-c")
        .arg(command)
        .current_dir(workdir)
        .kill_on_drop(true)
        .env_remove("SEKAI_AUTH_TOKEN")
        .env("TENKAI_ENVIRONMENT", environment)
        .env("TENKAI_PRODUCT", product)
        .env("TENKAI_FENCING_GENERATION", generation.to_string())
        .env(
            "COMPOSE_PROJECT_NAME",
            format!("tenkai-{}", &identity_digest[..16]),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    child.as_std_mut().process_group(0);
    let mut child = child.spawn().context("spawning deployment command")?;
    let process_group = child.id().context("deployment command has no process id")? as i32;
    let (closed_tx, mut controller_closed) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let result = std::io::stdin().read_to_end(&mut sink);
        let _ = closed_tx.send(result);
    });
    tokio::select! {
        status = child.wait() => {
            let status = status?;
            // Shell completion is not command-group completion: ordinary shell
            // background jobs retain the group. Terminate them before the
            // supervisor releases the environment mutation lock.
            unsafe { libc::kill(-process_group, libc::SIGKILL) };
            wait_for_process_group_exit(process_group).await?;
            if status.success() { Ok(()) } else { bail!("deployment command exited with {status}") }
        }
        _ = &mut controller_closed => {
            unsafe { libc::kill(-process_group, libc::SIGKILL) };
            let _ = child.wait().await;
            wait_for_process_group_exit(process_group).await?;
            bail!("deployment controller exited")
        }
    }
}

async fn wait_for_process_group_exit(process_group: i32) -> Result<()> {
    loop {
        if unsafe { libc::kill(-process_group, 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(error.into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn release_environment_lease(ctx: &mut Ctx, lease: &EnvironmentLease) -> Result<()> {
    ctx.release_lease(
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

pub(crate) async fn release_environment(ctx: &mut Ctx, lease: &EnvironmentLease) -> Result<()> {
    mark_object_environment_claim_released(ctx, lease).await?;
    release_environment_lease(ctx, lease).await?;
    Ok(())
}

pub(crate) struct EnvironmentLeaseStatus {
    pub owner: String,
}

async fn get_environment_lease(ctx: &mut Ctx, environment: &str) -> Result<Option<Lease>> {
    ctx.get_lease(ENVIRONMENT_LEASE_NAMESPACE, environment)
        .await
}

pub(crate) async fn environment_lease_status(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<Option<EnvironmentLeaseStatus>> {
    if let Some(lease) = ctx.get(&legacy_environment_claim_id(environment)).await? {
        let owner = lease
            .properties
            .get("owner")
            .cloned()
            .context("legacy environment apply lease has no owner")?;
        return Ok(Some(EnvironmentLeaseStatus { owner }));
    }
    let object_claim_id = object_environment_claim_id(environment);
    if ctx
        .links(&env_id(environment), REL_ACTIVE_ENVIRONMENT_EXECUTION)
        .await?
        .into_iter()
        .any(|link| link.to_id == object_claim_id)
    {
        let lease = ctx
            .get(&object_claim_id)
            .await?
            .context("object-backed environment apply lease disappeared")?;
        let owner = lease
            .properties
            .get("owner")
            .cloned()
            .context("object-backed environment apply lease has no owner")?;
        if owner != "released" {
            return Ok(Some(EnvironmentLeaseStatus { owner }));
        }
        // New controllers retain the compatibility link so an older binary
        // fails closed. The authoritative Tenkai lease determines whether the
        // released marker is merely idle or a new generation is being adopted.
        if let Some(active) = get_environment_lease(ctx, environment).await?
            && active.status == "active"
        {
            return Ok(Some(EnvironmentLeaseStatus {
                owner: active.owner,
            }));
        }
        return Ok(None);
    }
    let Some(lease) = get_environment_lease(ctx, environment).await? else {
        return Ok(None);
    };
    if lease.status != "active" {
        return Ok(None);
    }
    Ok(Some(EnvironmentLeaseStatus { owner: lease.owner }))
}

pub async fn unlock_environment(ctx: &mut Ctx, environment: &str) -> Result<String> {
    crate::ontology::validate_identifier("environment", environment)?;
    let legacy_id = legacy_environment_claim_id(environment);
    if ctx.get(&legacy_id).await?.is_some() {
        ctx.delete(&legacy_id).await?;
        return Ok(format!(
            "removed legacy apply lease for environment {environment}"
        ));
    }
    let object_claim_id = object_environment_claim_id(environment);
    let has_object_claim = ctx.get(&object_claim_id).await?.is_some()
        && ctx
            .links(&env_id(environment), REL_ACTIVE_ENVIRONMENT_EXECUTION)
            .await?
            .into_iter()
            .any(|link| link.to_id == object_claim_id);
    if has_object_claim
        && get_environment_lease(ctx, environment)
            .await?
            .is_none_or(|lease| lease.status != "active")
    {
        release_object_environment_claim(ctx, environment).await?;
        return Ok(format!(
            "removed object-backed apply lease for environment {environment}"
        ));
    }
    let Some(existing) = get_environment_lease(ctx, environment).await? else {
        return Ok(format!("environment {environment} has no apply lease"));
    };
    if existing.status != "active" {
        return Ok(format!("environment {environment} has no apply lease"));
    }
    if existing.expires_at_ms > crate::now_millis() {
        bail!(
            "environment {environment} has an unexpired apply lease owned by {}; stop that controller and retry after lease expiry at {}",
            existing.owner,
            existing.expires_at_ms
        );
    }
    let takeover = ctx
        .takeover_expired_lease(
            ENVIRONMENT_LEASE_NAMESPACE,
            environment,
            &format!("manual-unlock:{}", uuid::Uuid::new_v4()),
            &existing.fencing_token,
            existing.expires_at_ms,
            MANUAL_UNLOCK_LEASE_MS,
        )
        .await?;
    ctx.release_lease(
        ENVIRONMENT_LEASE_NAMESPACE,
        environment,
        &takeover.fencing_token,
    )
    .await?;
    if has_object_claim {
        release_object_environment_claim(ctx, environment).await?;
    }
    Ok(format!("removed apply lease for environment {environment}"))
}

pub(crate) async fn validate_preconditions(ctx: &mut Ctx, plan: &Plan) -> Result<()> {
    let environment = ctx
        .get(&env_id(&plan.environment))
        .await?
        .with_context(|| format!("environment {} not found", plan.environment))?;
    for step in &plan.steps {
        if step.action != Action::Rollback
            && environment
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
    for input in &plan.inputs {
        let channel = ctx
            .get(&input.channel_id)
            .await?
            .with_context(|| format!("channel {} not found", input.channel_id))?;
        if channel.properties.get("current_version") != Some(&input.desired_version)
            || channel.properties.get("current_release") != Some(&input.release_id)
        {
            bail!(
                "plan {} is stale for {}: channel {} no longer selects the approved release",
                plan.id,
                input.product,
                input.channel
            );
        }
    }
    Ok(())
}

/// Compatibility entry point retained so downstream crates receive an
/// actionable authorization error instead of a compile failure.
#[deprecated(note = "use execute_with_options with explicit plan approval")]
pub async fn execute(_ctx: &mut Ctx, _plan_id: &str, _skip_gates: bool) -> Result<Vec<Outcome>> {
    bail!(
        "plan execution now requires explicit approval; use execute_with_options with signed approval or a recorded local-development bypass"
    )
}

/// Execute a stored plan's ordered steps after explicit authorization.
pub async fn execute_with_options(
    ctx: &mut Ctx,
    plan_id: &str,
    options: ExecutionOptions<'_>,
) -> Result<Vec<Outcome>> {
    let emergency_reason = validate_emergency_override(options.emergency_reason)?;
    let mut stored_plan = plan::load(ctx, plan_id).await?;
    if !matches!(stored_plan.state, PlanState::Computed | PlanState::Blocked) {
        bail!(
            "plan {} is {}, only computed or blocked plans can be applied",
            stored_plan.id,
            stored_plan.state
        );
    }
    let now = crate::now_millis();
    let approval_evidence = match (
        options.approval,
        options.approval_trust_roots,
        options.unapproved_development_reason,
    ) {
        (Some(envelope), Some(roots), None) => {
            crate::plan_approval::verify(&stored_plan, envelope, roots, now, options.skip_gates)?
        }
        (None, None, Some(reason)) if ctx.is_embedded() => {
            crate::plan_approval::local_bypass(&stored_plan, reason, now)?
        }
        (None, None, Some(_)) => {
            bail!("unapproved development execution is available only in embedded mode")
        }
        (None, None, None) => bail!(
            "plan execution requires --approval and --approval-trust-roots; local development may explicitly use --allow-unapproved-development with --development-reason"
        ),
        (Some(_), None, _) | (None, Some(_), _) => {
            bail!("signed plan execution requires both an approval and approval trust roots")
        }
        _ => bail!("signed approval and the local-development bypass are mutually exclusive"),
    };
    crate::plan_approval::record(ctx, &approval_evidence).await?;
    let environment = stored_plan.environment.clone();
    let owner = stored_plan.id.clone();
    let lease = claim_execution_environment(ctx, &environment, &owner).await?;
    let authorization = async {
        let initial_maintenance =
            maintenance_decision(ctx, &stored_plan.environment, emergency_reason).await?;
        record_maintenance_decision(ctx, &stored_plan, &initial_maintenance).await?;
        if let MaintenanceDecision::Denied(detail) = &initial_maintenance {
            block_for_maintenance(ctx, &lease, &mut stored_plan, options.skip_gates, detail)
                .await
                .map(|_| ())?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = authorization {
        let error = if emergency_reason.is_some() {
            let detail = format!("emergency maintenance override was not authorized: {error}");
            match block_for_maintenance(ctx, &lease, &mut stored_plan, options.skip_gates, &detail)
                .await
            {
                Err(blocked) => blocked.context(detail),
                Ok(_) => unreachable!("maintenance authorization failure always blocks"),
            }
        } else {
            error
        };
        let unlock = release_environment(ctx, &lease).await;
        return match unlock {
            Ok(()) => Err(error),
            Err(unlock) => Err(error.context(format!(
                "releasing environment apply lease also failed: {unlock}"
            ))),
        };
    }
    let mut canary_finalization_error = None;
    let result = match crate::canary::begin_attempt(ctx, &stored_plan, options.skip_gates).await {
        Ok(attempt_id) => {
            let start_result = match attempt_id.as_deref() {
                Some(attempt_id) => crate::canary::mark_attempt_started(ctx, attempt_id)
                    .await
                    .context("marking canary attempt as started"),
                None => Ok(()),
            };
            match start_result {
                Err(error) => Err(error),
                Ok(()) => {
                    let result = execute_locked(
                        ctx,
                        stored_plan,
                        ExecutionOptions {
                            skip_gates: options.skip_gates,
                            emergency_reason,
                            approval: options.approval,
                            approval_trust_roots: options.approval_trust_roots,
                            unapproved_development_reason: options.unapproved_development_reason,
                        },
                        &lease,
                    )
                    .await;
                    if let Some(attempt_id) = attempt_id
                        // This executor has no reliable post-mutation error boundary. Keep
                        // errored attempts pending until explicit repair so promotion fails closed.
                        && let Err(error) = crate::canary::finish_attempt(
                            ctx,
                            plan_id,
                            &attempt_id,
                            false,
                            result.as_ref().ok().map(Vec::as_slice),
                        )
                        .await
                    {
                        canary_finalization_error = Some(error);
                    }
                    result
                }
            }
        }
        Err(error) => Err(error.context("snapshotting canary policies before execution")),
    };
    let unlock = release_environment(ctx, &lease).await;
    let released_result = match (result, unlock) {
        (Ok(outcomes), Ok(())) => Ok(outcomes),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing environment apply lease also failed: {unlock}; after verifying no apply is running, retry `tenkaictl env unlock {environment}` once the lease expires"
        ))),
        (Ok(_), Err(error)) => Err(error.context(format!(
            "releasing environment apply lease failed; after verifying no apply is running, retry `tenkaictl env unlock {environment}` once the lease expires"
        ))),
    };
    match (released_result, canary_finalization_error) {
        (Ok(outcomes), None) => Ok(outcomes),
        (Ok(_), Some(error)) => Err(error.context(format!(
            "apply completed but canary evidence finalization failed; run `tenkaictl canary repair {plan_id}`"
        ))),
        (Err(error), None) => Err(error),
        (Err(error), Some(finalization)) => Err(error.context(format!(
            "canary evidence finalization also failed: {finalization}"
        ))),
    }
}

async fn execute_locked(
    ctx: &mut Ctx,
    mut stored_plan: Plan,
    options: ExecutionOptions<'_>,
    lease: &EnvironmentLease,
) -> Result<Vec<Outcome>> {
    let skip_gates = options.skip_gates;
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
                lease,
                &mut stored_plan,
                PlanState::Blocked,
                skip_gates,
                detail,
            )
            .await?;
            return Ok(vec![outcome]);
        }
    }
    let final_maintenance =
        maintenance_decision(ctx, &stored_plan.environment, options.emergency_reason).await?;
    if let MaintenanceDecision::Denied(detail) = &final_maintenance {
        block_for_maintenance(ctx, lease, &mut stored_plan, skip_gates, detail).await?;
    }
    if let MaintenanceDecision::Allowed { closes_at } = &final_maintenance
        && crate::now_millis() >= *closes_at
    {
        block_for_maintenance(
            ctx,
            lease,
            &mut stored_plan,
            skip_gates,
            "maintenance window closed while start authorization was being recorded",
        )
        .await?;
    }
    set_plan_state_confirmed(
        ctx,
        lease,
        &mut stored_plan,
        PlanState::Running,
        skip_gates,
        "",
    )
    .await?;
    let running_maintenance =
        maintenance_decision(ctx, &stored_plan.environment, options.emergency_reason).await?;
    match running_maintenance {
        MaintenanceDecision::Denied(detail) => {
            block_for_maintenance(ctx, lease, &mut stored_plan, skip_gates, &detail).await?;
        }
        MaintenanceDecision::Allowed { closes_at } if crate::now_millis() >= closes_at => {
            block_for_maintenance(
                ctx,
                lease,
                &mut stored_plan,
                skip_gates,
                "maintenance window closed before execution entered the running state",
            )
            .await?;
        }
        MaintenanceDecision::Allowed { .. } | MaintenanceDecision::EmergencyOverride(_) => {}
    }

    let mut outcomes = Vec::new();
    let mut plan_failed = false;
    let mut plan_blocked = false;
    let mut final_detail = String::new();

    for step in steps {
        if let Err(error) = refresh_environment_lease(ctx, lease).await {
            let detail = format!("refreshing environment apply lease failed: {error}");
            set_plan_state(
                ctx,
                lease,
                &mut stored_plan,
                PlanState::Failed,
                skip_gates,
                &detail,
            )
            .await?;
            return Err(error.context(detail));
        }
        let outcome = match execute_step(ctx, lease, &env, &plan_id, &step).await {
            Ok(outcome) => outcome,
            Err(error) => {
                set_plan_state(
                    ctx,
                    lease,
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
    set_plan_state_confirmed(
        ctx,
        lease,
        &mut stored_plan,
        final_state,
        skip_gates,
        final_detail,
    )
    .await?;

    Ok(outcomes)
}

async fn execute_step(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    env: &str,
    plan_oid: &str,
    step: &Step,
) -> Result<Outcome> {
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
        let cleanup_failure = match deactivate_fenced(ctx, lease, outgoing).await {
            Ok(Ok(())) => None,
            Ok(Err(detail)) => Some(detail),
            Err(error) => Some(format!("cleanup executor failed: {error}")),
        };
        if let Some(detail) = cleanup_failure {
            let detail = format!("rollback blocked: outgoing release cleanup failed: {detail}");
            set_env_unknown(ctx, lease, env, &step.product, &detail).await?;
            let outcome = Outcome {
                step: step.clone(),
                status: "failed".into(),
                detail,
            };
            record_deployment(ctx, lease, env, plan_oid, &outcome).await?;
            return Ok(outcome);
        }
    }

    let activation = match activate_fenced(ctx, lease, &content).await {
        Ok(result) => result,
        Err(error) => Err(format!("deployment executor failed: {error}")),
    };
    let outcome = match activation {
        Ok(()) => {
            let outcome = Outcome {
                step: step.clone(),
                status: "succeeded".into(),
                detail: String::new(),
            };
            if let Err(error) = set_env_deployed(
                ctx,
                lease,
                env,
                &step.product,
                &step.to,
                step.from.as_deref(),
            )
            .await
            {
                compensate_activation(ctx, lease, env, step, &content, &error).await;
                return Err(error);
            }
            if let Err(error) = record_deployment(ctx, lease, env, plan_oid, &outcome).await {
                compensate_activation(ctx, lease, env, step, &content, &error).await;
                return Err(error);
            }
            return Ok(outcome);
        }
        Err(detail) => {
            // Install or health failed: try to restore the previous release.
            match &step.from {
                Some(prev) => {
                    let (cleaned, detail) =
                        cleanup_failed_install_fenced(ctx, lease, &content, detail).await?;
                    let Some(prev_content) = restore_content.as_ref() else {
                        let detail =
                            format!("{detail}; step {} has no pinned restore release", step.id);
                        set_env_unknown(ctx, lease, env, &step.product, &detail).await?;
                        let outcome = Outcome {
                            step: step.clone(),
                            status: "failed".into(),
                            detail,
                        };
                        record_deployment(ctx, lease, env, plan_oid, &outcome).await?;
                        return Ok(outcome);
                    };
                    let (restored, detail) =
                        restore_previous_fenced(ctx, lease, prev_content, prev, detail).await?;
                    let recovered = cleaned && restored;
                    if !recovered {
                        set_env_unknown(ctx, lease, env, &step.product, &detail).await?;
                    }
                    Outcome {
                        step: step.clone(),
                        status: if recovered { "rolled_back" } else { "failed" }.into(),
                        detail,
                    }
                }
                None => {
                    let (cleaned, detail) =
                        cleanup_failed_install_fenced(ctx, lease, &content, detail).await?;
                    if !cleaned {
                        set_env_unknown(ctx, lease, env, &step.product, &detail).await?;
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

    record_deployment(ctx, lease, env, plan_oid, &outcome).await?;
    Ok(outcome)
}

async fn record_deployment(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
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
            ("lease_generation".into(), lease.generation.to_string()),
        ]),
    );
    ctx.guarded_create(
        deployment.clone(),
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    // Links are append-only, deterministic audit enrichment for this immutable
    // generation-tagged attempt; they cannot overwrite active environment or
    // plan state. If takeover happens here, guarded finalization below fails
    // closed and leaves the attempt explicitly marked bookkeeping-incomplete.
    refresh_environment_lease(ctx, lease).await?;
    ctx.link(&did, &outcome.step.release_id, REL_DEPLOYED_RELEASE)
        .await?;
    refresh_environment_lease(ctx, lease).await?;
    ctx.link(&did, &env_id(env), REL_IN_ENVIRONMENT).await?;
    refresh_environment_lease(ctx, lease).await?;
    ctx.link(&did, plan_oid, REL_PART_OF_PLAN).await?;
    deployment
        .properties
        .insert("status".into(), outcome.status.clone());
    deployment
        .properties
        .insert("detail".into(), outcome.detail.clone());
    deployment.updated = crate::now_millis();
    match ctx
        .guarded_update(
            deployment,
            ENVIRONMENT_LEASE_NAMESPACE,
            &lease.environment,
            &lease.fencing_token,
        )
        .await
    {
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
    use crate::manifest::{DeploySection, GateSection, ProductSection};
    use crate::pb::chisei::CaseResult;

    #[test]
    fn emergency_override_requires_a_reason() {
        assert!(validate_emergency_override(Some("incident 42")).is_ok());
        assert!(validate_emergency_override(Some("  ")).is_err());
        assert_eq!(validate_emergency_override(None).unwrap(), None);
    }

    #[test]
    fn maintenance_block_errors_are_typed() {
        let maintenance = anyhow::Error::new(MaintenanceBlocked("window closed".into()));
        let unrelated = anyhow::anyhow!("maintenance window text from another error");
        assert!(is_maintenance_block_error(&maintenance));
        assert!(!is_maintenance_block_error(&unrelated));
    }

    #[test]
    fn maintenance_timestamps_are_operator_readable() {
        let timestamp = "2026-07-21T22:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            .timestamp_millis();
        assert_eq!(
            format_maintenance_timestamp(timestamp),
            "2026-07-21T22:00:00Z"
        );
    }

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
            manifest: Manifest {
                product: ProductSection {
                    name: "api".into(),
                    version: "1.0.0".into(),
                    description: String::new(),
                },
                deploy: DeploySection {
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
            mutation_lock: std::env::temp_dir().join("tenkai-test-mutation.lock"),
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
    async fn activation_runs_health_after_install() {
        let dir = test_dir("health");
        let release = content(
            dir.clone(),
            "touch installed",
            Some("test -f healthy"),
            None,
        );
        let failure = activate(&release).await.unwrap().unwrap_err();
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

        let failure = activate(&release).await.unwrap().unwrap_err();

        assert!(failure.contains("immutable deployment inputs changed"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn restore_requires_the_previous_release_to_be_healthy() {
        let dir = test_dir("restore");
        let previous = content(dir.clone(), "touch restored", Some("false"), None);
        let (restored, detail) = restore_previous(&previous, "1.0.0", "upgrade failed".into())
            .await
            .unwrap();
        assert!(!restored);
        assert!(dir.join("restored").exists());
        assert!(detail.contains("health check of 1.0.0 also failed"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_fresh_install_runs_cleanup() {
        let dir = test_dir("cleanup");
        let release = content(dir.clone(), "false", None, Some("touch cleaned"));
        let (cleaned, detail) = cleanup_failed_install(&release, "install failed".into())
            .await
            .unwrap();
        assert!(cleaned);
        assert!(dir.join("cleaned").exists());
        assert!(detail.contains("cleaned up failed install"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
