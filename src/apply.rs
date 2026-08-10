//! Plan execution: eval gates, install commands, health probes, auto-rollback.
//!
//! Every execution writes durable plan and deployment objects so Tenkai can
//! answer "what ran, when, gated by what, and what happened" after the fact.

use std::collections::HashMap;
use std::path::Path;

#[cfg(test)]
use std::os::unix::process::CommandExt as _;
#[cfg(test)]
use std::process::Stdio;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::maintenance::{self, Eligibility};
use crate::manifest::{self, Manifest, ProductKind};
use crate::model_runtime::ModelRuntimeExecutor as _;
use crate::ontology::*;
use crate::pb::chisei::{EvaluationGateCaseResult, GetEvaluationGateEvidenceRequest};
use crate::pb::sekai::Object;
use crate::plan::{self, Action, Plan, PlanState, ReleasePin, Step};
use crate::routing::RoutingConfigExecutor as _;

mod execution_attempt;
mod execution_lease;
mod product_execution;

pub(crate) use execution_lease::{
    ENVIRONMENT_LEASE_NAMESPACE, EnvironmentLease, claim_environment, environment_lease_status,
    refresh_environment_lease, release_environment,
};
pub use execution_lease::{EnvironmentLeaseInspect, inspect_environment_lease, unlock_environment};
use execution_lease::{claim_execution_environment, run_mutation_command};

#[allow(deprecated)]
pub use execution_attempt::{
    ExecutionAuthorization, ExecutionOptions, execute, execute_with_options,
};

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

fn evaluate_gate(
    results: &[EvaluationGateCaseResult],
    suite_id: &str,
    expected_cases: &[String],
) -> GateDecision {
    if results.is_empty() {
        return GateDecision::Denied(format!(
            "gate blocked: latest run of eval suite {suite_id} has no case results"
        ));
    }
    let expected: std::collections::HashSet<_> = expected_cases.iter().collect();
    let actual: std::collections::HashSet<_> =
        results.iter().map(|result| &result.case_id).collect();
    if expected.is_empty() || actual.len() != results.len() || actual != expected {
        return GateDecision::Denied(format!(
            "gate blocked: latest run of eval suite {suite_id} does not contain exactly one result for every current case"
        ));
    }
    let failed: Vec<_> = results
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

/// Gate: Chisei must return a server-owned, digest-bound, fully passing evidence projection.
async fn check_eval_gate(
    ctx: &mut Ctx,
    suite_id: &str,
    release_digest: &str,
    artifact_digest: &str,
) -> GateDecision {
    let max_timestamp_ms = crate::now_millis().saturating_add(60_000);
    let response = match ctx
        .evaluation_gate_evidence(GetEvaluationGateEvidenceRequest {
            suite_id: suite_id.into(),
            release_digest: release_digest.into(),
            artifact_digest: artifact_digest.into(),
            max_timestamp_ms,
        })
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return GateDecision::Unavailable(format!(
                "gate unavailable: could not read evaluation gate evidence for suite {suite_id}: {error}"
            ));
        }
    };
    match response.status.as_str() {
        "suite_not_found" => GateDecision::Denied(format!(
            "gate blocked: eval suite {suite_id} does not exist"
        )),
        "no_matching_run" => GateDecision::Denied(format!(
            "gate blocked: eval suite {suite_id} has no current run bound to this release and artifact"
        )),
        "found" => {
            let Some(evidence) = response.evidence else {
                return GateDecision::Unavailable(format!(
                    "gate unavailable: evaluation gate evidence for suite {suite_id} omitted its projection"
                ));
            };
            if evidence.suite_id != suite_id
                || evidence.release_digest != release_digest
                || evidence.artifact_digest != artifact_digest
                || evidence.suite_digest.is_empty()
                || evidence.config_ref
                    != gate_config_ref(release_digest, artifact_digest, &evidence.suite_digest)
                || evidence.run_id.is_empty()
                || evidence.run_timestamp <= 0
                || evidence.run_timestamp > max_timestamp_ms
            {
                return GateDecision::Unavailable(format!(
                    "gate unavailable: evaluation gate evidence for suite {suite_id} had an invalid binding"
                ));
            }
            evaluate_gate(&evidence.results, suite_id, &evidence.expected_case_ids)
        }
        status => GateDecision::Unavailable(format!(
            "gate unavailable: evaluation gate evidence for suite {suite_id} returned unknown status {status:?}"
        )),
    }
}

fn gate_config_ref(release_digest: &str, artifact_digest: &str, suite_digest: &str) -> String {
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
    routing_state: std::path::PathBuf,
    model_runtime_state: std::path::PathBuf,
}

fn verify_content_integrity(content: &ReleaseContent) -> Result<()> {
    let actual = manifest::artifact_digest(&content.workdir, &content.manifest.immutable_inputs())?;
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

async fn restore_previous_fenced(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    version: &str,
    failure: String,
) -> Result<(bool, String)> {
    let channel_note = crate::software_executor::rollback_channel_note(&content.product, version);
    // Tag activation failures during rollback as restore phase (#150).
    let restore_result = match product_execution::activate(ctx, lease, content).await {
        Ok(Ok(())) => Ok(Ok(())),
        Ok(Err(detail)) => Ok(Err(crate::software_executor::format_software_phase_error(
            crate::software_executor::SoftwareDeployPhase::Restore,
            &content.product,
            version,
            &content.environment,
            &detail,
        ))),
        Err(error) => Err(error),
    };
    Ok(match restore_result {
        Ok(Ok(())) => (
            true,
            format!("{failure}; restored {version}; {channel_note}"),
        ),
        Ok(Err(restore)) => (
            false,
            format!(
                "{failure}; restore or health check of {version} also failed: {restore}; {channel_note}"
            ),
        ),
        Err(error) => (
            false,
            format!(
                "{failure}; restore executor failed for {version}: {}; {channel_note}",
                crate::software_executor::format_software_phase_error(
                    crate::software_executor::SoftwareDeployPhase::Restore,
                    &content.product,
                    version,
                    &content.environment,
                    &error.to_string(),
                )
            ),
        ),
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
    let cleaned = matches!(
        product_execution::deactivate(ctx, lease, content).await,
        Ok(Ok(()))
    );
    let mut restored = step.from.is_none();

    if let (Some(previous), Some(pin)) = (step.from.as_deref(), step.restore.as_ref())
        && let Ok(previous_content) = release_content(ctx, pin, env, &step.product).await
        && matches!(
            product_execution::activate(ctx, lease, &previous_content).await,
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
    let actual_artifact_digest = manifest::artifact_digest(
        Path::new(&descriptor.content_path),
        &manifest.immutable_inputs(),
    )?;
    if actual_artifact_digest != descriptor.artifact_digest {
        bail!(
            "release {} immutable deploy inputs no longer match pinned artifact digest {}",
            pin.release_id,
            pin.artifact_digest
        );
    }
    let workdir = manifest::execution_workdir(
        Path::new(&descriptor.content_path),
        &manifest.immutable_inputs(),
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
        routing_state: state_dir
            .join("runtime")
            .join(environment)
            .join("routing")
            .join(format!("{product}.json")),
        model_runtime_state: state_dir
            .join("runtime")
            .join(environment)
            .join("model_runtime")
            .join(format!("{product}.json")),
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
    crate::environment::record_deployed(ctx, lease, env, product, version, previous).await
}

async fn set_env_unknown(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    env: &str,
    product: &str,
    detail: &str,
) -> Result<()> {
    crate::environment::record_unknown(ctx, lease, env, product, detail).await
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

async fn execute_locked(
    ctx: &mut Ctx,
    mut stored_plan: Plan,
    options: execution_attempt::AttemptExecutionPolicy<'_>,
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
        let cleanup_failure = match product_execution::deactivate(ctx, lease, outgoing).await {
            Ok(Ok(())) => None,
            Ok(Err(detail)) => Some(detail),
            Err(error) => Some(format!("cleanup executor failed: {error}")),
        };
        if let Some(detail) = cleanup_failure {
            let detail = format!("rollback blocked: outgoing release cleanup failed: {detail}");
            let outcome = Outcome {
                step: step.clone(),
                status: "failed".into(),
                detail,
            };
            record_deployment(
                ctx,
                lease,
                env,
                plan_oid,
                &outcome,
                crate::environment::DeploymentTransition::Unknown,
            )
            .await?;
            return Ok(outcome);
        }
    }

    let activation = match product_execution::activate(ctx, lease, &content).await {
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
            if let Err(error) = record_deployment(
                ctx,
                lease,
                env,
                plan_oid,
                &outcome,
                crate::environment::DeploymentTransition::Deployed {
                    version: step.to.clone(),
                    previous: step.from.clone(),
                },
            )
            .await
            {
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
                        product_execution::cleanup_failed_activation(ctx, lease, &content, detail)
                            .await?;
                    let Some(prev_content) = restore_content.as_ref() else {
                        let detail =
                            format!("{detail}; step {} has no pinned restore release", step.id);
                        let outcome = Outcome {
                            step: step.clone(),
                            status: "failed".into(),
                            detail,
                        };
                        record_deployment(
                            ctx,
                            lease,
                            env,
                            plan_oid,
                            &outcome,
                            crate::environment::DeploymentTransition::Unknown,
                        )
                        .await?;
                        return Ok(outcome);
                    };
                    let (restored, detail) =
                        restore_previous_fenced(ctx, lease, prev_content, prev, detail).await?;
                    let recovered = cleaned && restored;
                    (
                        Outcome {
                            step: step.clone(),
                            status: if recovered { "rolled_back" } else { "failed" }.into(),
                            detail,
                        },
                        if recovered {
                            crate::environment::DeploymentTransition::Unchanged
                        } else {
                            crate::environment::DeploymentTransition::Unknown
                        },
                    )
                }
                None => {
                    let (cleaned, detail) =
                        product_execution::cleanup_failed_activation(ctx, lease, &content, detail)
                            .await?;
                    (
                        Outcome {
                            step: step.clone(),
                            status: "failed".into(),
                            detail,
                        },
                        if cleaned {
                            crate::environment::DeploymentTransition::Unchanged
                        } else {
                            crate::environment::DeploymentTransition::Unknown
                        },
                    )
                }
            }
        }
    };

    let (outcome, environment_transition) = outcome;
    record_deployment(ctx, lease, env, plan_oid, &outcome, environment_transition).await?;
    Ok(outcome)
}

async fn record_deployment(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    env: &str,
    plan_oid: &str,
    outcome: &Outcome,
    environment_transition: crate::environment::DeploymentTransition,
) -> Result<()> {
    crate::environment::record_deployment_observation(
        ctx,
        lease,
        crate::environment::DeploymentObservation {
            environment: env,
            plan_id: plan_oid,
            step: &outcome.step,
            status: &outcome.status,
            detail: &outcome.detail,
            transition: environment_transition,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{DeploySection, GateSection, ProductSection};
    use crate::pb::chisei::EvaluationGateCaseResult;

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
                    kind: ProductKind::Software,
                },
                deploy: DeploySection {
                    workdir: ".".into(),
                    install: install.into(),
                    inputs: Vec::new(),
                    uninstall: uninstall.map(str::to_string),
                    health: health.map(str::to_string),
                },
                routing: None,
                model: None,
                runtime: None,
                requirements: None,
                model_health: None,
                policy: None,
                eval_suite_product: None,
                agent: None,
                gate: GateSection::default(),
            },
            artifact_digest: manifest::artifact_digest(&workdir, &[]).unwrap(),
            workdir,
            environment: "test".into(),
            product: "api".into(),
            mutation_lock: std::env::temp_dir().join("tenkai-test-mutation.lock"),
            routing_state: std::env::temp_dir().join("tenkai-test-routing-state.json"),
            model_runtime_state: std::env::temp_dir().join("tenkai-test-model-runtime-state.json"),
        }
    }

    #[test]
    fn gate_uses_latest_run_and_reports_failed_cases() {
        let results = vec![
            EvaluationGateCaseResult {
                case_id: "old".into(),
                passed: true,
            },
            EvaluationGateCaseResult {
                case_id: "smoke".into(),
                passed: false,
            },
        ];
        match evaluate_gate(&results, "suite", &["smoke".into(), "old".into()]) {
            GateDecision::Denied(detail) => assert!(detail.contains("smoke")),
            _ => panic!("a failing case must deny the gate"),
        }
    }

    #[test]
    fn gate_rejects_incomplete_or_duplicate_case_results() {
        let results = vec![
            EvaluationGateCaseResult {
                case_id: "first".into(),
                passed: true,
            },
            EvaluationGateCaseResult {
                case_id: "first".into(),
                passed: true,
            },
        ];
        assert!(matches!(
            evaluate_gate(&results, "suite", &["first".into(), "second".into()]),
            GateDecision::Denied(detail) if detail.contains("exactly one result")
        ));
    }

    #[test]
    fn gate_reference_changes_with_artifact_or_suite_content() {
        let original = gate_config_ref("manifest", "artifact-one", "suite-digest-one");
        let changed_artifact = gate_config_ref("manifest", "artifact-two", "suite-digest-one");
        let changed_suite = gate_config_ref("manifest", "artifact-one", "suite-digest-two");

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
