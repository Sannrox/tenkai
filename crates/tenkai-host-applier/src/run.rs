//! Run one verified host step's command as its own process group (ADR 0041
//! §2, fencing).
//!
//! The command is the signed manifest's command for the step's action, run
//! by `/bin/sh -c` in the root-owned copy of the release workdir. Its
//! environment is built here from a fixed allowlist and verified values;
//! nothing the server supplied becomes an environment variable, an argument,
//! or a path. The applier's timeout and a `stop` (SIGTERM or SIGINT to the
//! applier) kill the whole process group while its leader is still unreaped,
//! so the group id cannot have been reused. What a command that exited on
//! its own leaves running is the unit's to stop: systemd kills the rest of
//! the unit's control group when the applier exits.

use std::future::Future;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result};
use tenkai::host_apply::VerifiedHostStep;
use tenkai::host_apply::state::HostApplyOutcome;

/// POSIX shell that runs the command.
const SHELL: &str = "/bin/sh";
/// `PATH` of every host command.
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// How a command ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEnd {
    pub outcome: HostApplyOutcome,
    pub exit_status: Option<i32>,
    pub detail: String,
}

/// The command's whole environment: the fixed allowlist plus values from
/// the verified step.
pub fn command_environment(step: &VerifiedHostStep) -> Vec<(&'static str, String)> {
    vec![
        ("PATH", PATH.into()),
        ("LANG", "C.UTF-8".into()),
        ("HOME", "/root".into()),
        ("TENKAI_ENVIRONMENT", step.environment.clone()),
        ("TENKAI_PRODUCT", step.product.clone()),
        ("TENKAI_VERSION", step.release.version.clone()),
        (
            "TENKAI_RELEASE_DIGEST",
            step.release.manifest_digest.clone(),
        ),
        ("TENKAI_HOST_ACTION", step.action.as_str().into()),
        ("TENKAI_PLAN_ID", step.plan_id.clone()),
    ]
}

/// Run `step`'s command in `workdir` until it exits, `timeout` passes, or
/// `stop` resolves; the last two kill its process group.
pub async fn run_command(
    step: &VerifiedHostStep,
    workdir: &Path,
    timeout: Duration,
    stop: impl Future<Output = ()>,
) -> Result<CommandEnd> {
    let mut command = tokio::process::Command::new(SHELL);
    command
        .arg("-c")
        .arg(&step.command)
        .current_dir(workdir)
        .env_clear()
        .envs(command_environment(step))
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = command.spawn().context("spawning the host command")?;
    let group = child
        .id()
        .and_then(|id| rustix::process::Pid::from_raw(id as i32))
        .context("the host command has no process id")?;
    tokio::pin!(stop);
    let killed = tokio::select! {
        status = child.wait() => {
            let status = status.context("waiting for the host command")?;
            return Ok(match status.code() {
                Some(0) => CommandEnd {
                    outcome: HostApplyOutcome::Succeeded,
                    exit_status: Some(0),
                    detail: "the command exited with status 0".into(),
                },
                code => CommandEnd {
                    outcome: HostApplyOutcome::Failed,
                    exit_status: code,
                    detail: format!("the command ended with {status}"),
                },
            });
        }
        _ = tokio::time::sleep(timeout) => CommandEnd {
            outcome: HostApplyOutcome::TimedOut,
            exit_status: None,
            detail: format!(
                "the command exceeded the applier's {}s timeout; its process group was killed",
                timeout.as_secs()
            ),
        },
        _ = &mut stop => CommandEnd {
            outcome: HostApplyOutcome::Stopped,
            exit_status: None,
            detail: "the step was stopped; its process group was killed".into(),
        },
    };
    // The leader is not reaped yet, so the group id is still ours.
    rustix::process::kill_process_group(group, rustix::process::Signal::KILL)
        .context("killing the host command's process group")?;
    child.wait().await.context("reaping the host command")?;
    Ok(killed)
}
