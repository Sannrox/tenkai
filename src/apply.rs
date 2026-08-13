//! Plan execution: eval gates, install commands, health probes, auto-rollback.
//!
//! Every execution writes durable plan and deployment objects so Tenkai can
//! answer "what ran, when, gated by what, and what happened" after the fact.

use std::collections::HashMap;
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
use std::os::unix::process::CommandExt as _;
#[cfg(test)]
use std::process::Stdio;

use crate::client::Ctx;
use crate::manifest::{self, Manifest};
use crate::model_runtime::ModelRuntimeExecutor as _;
use crate::ontology::*;
use crate::pb::sekai::Object;
use crate::plan::{self, Action, Plan, PlanState, ReleasePin, Step};
use crate::routing::RoutingConfigExecutor as _;
use anyhow::{Context as _, Result};

mod execution_admission;
mod execution_attempt;
mod execution_lease;
mod outcome;
mod plan_completion;
mod product_execution;
mod release_content;
mod start_admission;
mod step_lifecycle;

pub(crate) use execution_admission::{CandidateAdmission, classify_candidate};
pub(crate) use execution_lease::{
    ENVIRONMENT_LEASE_NAMESPACE, EnvironmentLease, claim_environment, environment_lease_status,
    refresh_environment_lease, release_environment,
};
pub use execution_lease::{EnvironmentLeaseInspect, inspect_environment_lease, unlock_environment};
use execution_lease::{claim_execution_environment, run_mutation_command};
pub use outcome::{Outcome, StepOutcomeStatus};
use release_content::{ReleaseContent, admit as admit_release, verify_integrity};

#[allow(deprecated)]
pub use execution_attempt::{
    ExecutionAuthorization, ExecutionOptions, execute, execute_with_options,
};

#[cfg(test)]
async fn run_command(
    cmd: &str,
    workdir: &Path,
    environment: &str,
    product: &str,
) -> Result<Result<(), String>> {
    let mut command = tokio::process::Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .current_dir(workdir)
        .kill_on_drop(true)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Match production deploy children: clear parent env and allowlist only.
    for (key, value) in crate::fenced_mutation::deploy_child_environment(environment, product, None)
    {
        command.env(key, value);
    }
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
    match verify_integrity(content) {
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
            match verify_integrity(content) {
                Ok(()) => Ok(result),
                Err(error) => Ok(Err(error.to_string())),
            }
        }
        _ => Ok(Err("release has no uninstall command".into())),
    }
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

async fn execute_locked(
    ctx: &mut Ctx,
    mut stored_plan: Plan,
    options: execution_attempt::AttemptExecutionPolicy<'_>,
    lease: &EnvironmentLease,
) -> Result<Vec<Outcome>> {
    let skip_gates = options.skip_gates;
    execution_admission::admit(ctx, &stored_plan).await?;
    let plan_id = stored_plan.id.clone();
    let env = stored_plan.environment.clone();
    let steps = stored_plan.steps.clone();
    if let Some(outcomes) = start_admission::admit(
        ctx,
        lease,
        &mut stored_plan,
        start_admission::AdmissionPolicy {
            skip_gates,
            emergency_reason: options.emergency_reason,
        },
    )
    .await?
    {
        return Ok(outcomes);
    }

    let mut completion = plan_completion::ExecutionCompletion::new();

    for step in steps {
        if let Err(error) = refresh_environment_lease(ctx, lease).await {
            let detail = format!("refreshing environment apply lease failed: {error}");
            plan_completion::fail(ctx, lease, &mut stored_plan, skip_gates, &detail).await?;
            return Err(error.context(detail));
        }
        let outcome = match step_lifecycle::execute(
            ctx,
            lease,
            &env,
            &plan_id,
            &step,
            options.software_executor,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                plan_completion::fail(ctx, lease, &mut stored_plan, skip_gates, error.to_string())
                    .await?;
                return Err(error);
            }
        };
        if completion.record(outcome)? {
            break;
        }
    }

    completion
        .finish(ctx, lease, &mut stored_plan, skip_gates)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{DeploySection, GateSection, ProductKind, ProductSection};

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
