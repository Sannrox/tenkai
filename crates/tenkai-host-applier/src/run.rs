//! Run one verified host step's command as its own process group (ADR 0041
//! §2, fencing).
//!
//! The command is the signed manifest's command for the step's action, run
//! by `/bin/sh -c` in the root-owned copy of the release workdir. Its
//! environment is built here from a fixed allowlist and verified values;
//! nothing the server supplied becomes an environment variable, an argument,
//! or a path. The applier's timeout and a `stop` (SIGTERM or SIGINT to the
//! applier) kill the whole process group while its leader is still unreaped,
//! so the group id cannot have been reused.
//!
//! Nothing the command started may outlive the step, because the product
//! lock is released when the step is recorded. On Linux the applier is the
//! child subreaper ([`adopt_descendants`]): a process that detaches, changes
//! its process group, or double-forks reparents to the applier rather than
//! escaping it, so once the command ended the applier kills and reaps its
//! children until it has none left, before it returns.

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

/// How long the applier keeps killing what the command left behind before it
/// gives up and reports the step as failed.
const DESCENDANT_DEADLINE: Duration = Duration::from_secs(30);

/// Make the applier the child subreaper of everything it starts (Linux), so
/// descendants that leave the command's process group reparent to it. Call
/// before [`run_command`]. Elsewhere this does nothing and only the process
/// group is stopped.
pub fn adopt_descendants() -> Result<()> {
    #[cfg(target_os = "linux")]
    rustix::process::set_child_subreaper(Some(rustix::process::getpid()))
        .context("becoming the child subreaper")?;
    Ok(())
}

/// Run `step`'s command in `workdir` until it exits, `timeout` passes, or
/// `stop` resolves; the last two kill its process group. In every case,
/// whatever else the command started is stopped before this returns.
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
    let end = tokio::select! {
        status = child.wait() => {
            let status = status.context("waiting for the host command")?;
            match status.code() {
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
            }
        }
        _ = tokio::time::sleep(timeout) => {
            kill_group_and_reap(&mut child, group).await?;
            CommandEnd {
                outcome: HostApplyOutcome::TimedOut,
                exit_status: None,
                detail: format!(
                    "the command exceeded the applier's {}s timeout; its process group was killed",
                    timeout.as_secs()
                ),
            }
        }
        _ = &mut stop => {
            kill_group_and_reap(&mut child, group).await?;
            CommandEnd {
                outcome: HostApplyOutcome::Stopped,
                exit_status: None,
                detail: "the step was stopped; its process group was killed".into(),
            }
        }
    };
    match stop_descendants(DESCENDANT_DEADLINE) {
        Ok(()) => Ok(end),
        Err(error) => Ok(CommandEnd {
            outcome: HostApplyOutcome::Failed,
            exit_status: end.exit_status,
            detail: format!("{}; {error:#}", end.detail),
        }),
    }
}

/// Kill the command's process group, then reap its leader. The leader is
/// not reaped yet, so the group id is still the command's.
async fn kill_group_and_reap(
    child: &mut tokio::process::Child,
    group: rustix::process::Pid,
) -> Result<()> {
    rustix::process::kill_process_group(group, rustix::process::Signal::KILL)
        .context("killing the host command's process group")?;
    child.wait().await.context("reaping the host command")?;
    Ok(())
}

/// Kill and reap the applier's children until it has none. With
/// [`adopt_descendants`] that is every process the command started.
#[cfg(target_os = "linux")]
fn stop_descendants(deadline: Duration) -> Result<()> {
    use rustix::process::{Signal, WaitOptions, kill_process, wait};
    let started = std::time::Instant::now();
    loop {
        // Any child: `waitpid(None, ..)` would wait only for the applier's
        // own process group.
        match wait(WaitOptions::NOHANG) {
            Err(rustix::io::Errno::CHILD) => return Ok(()),
            Ok(Some(_)) => continue,
            Ok(None) => {
                for pid in children()? {
                    let _ = kill_process(pid, Signal::KILL);
                }
                if started.elapsed() > deadline {
                    anyhow::bail!("processes the command started are still running");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error).context("reaping what the command started"),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn stop_descendants(_deadline: Duration) -> Result<()> {
    Ok(())
}

/// The applier's live children, from `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn children() -> Result<Vec<rustix::process::Pid>> {
    let me = rustix::process::getpid().as_raw_nonzero().get();
    let mut children = Vec::new();
    for entry in std::fs::read_dir("/proc").context("listing /proc")? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        // A process may exit between the listing and the read.
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // `pid (comm) state ppid ...`; comm may contain spaces and parentheses.
        let ppid = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|ppid| ppid.parse::<i32>().ok());
        if ppid == Some(me)
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            children.push(pid);
        }
    }
    Ok(children)
}
