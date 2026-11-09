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
/// the verified step, and the directory of its sealed values when it writes
/// any.
pub fn command_environment(
    step: &VerifiedHostStep,
    secrets_dir: Option<&Path>,
) -> Vec<(&'static str, String)> {
    let mut environment = vec![
        ("PATH", PATH.into()),
        ("LANG", "C.UTF-8".into()),
        ("HOME", "/root".into()),
        ("TENKAI_ENVIRONMENT", step.environment.clone()),
        ("TENKAI_PRODUCT", step.product.clone()),
        (
            "TENKAI_INSTANCE",
            if step.product_instance.is_empty() {
                step.product.clone()
            } else {
                step.product_instance.clone()
            },
        ),
        ("TENKAI_VERSION", step.release.version.clone()),
        (
            "TENKAI_RELEASE_DIGEST",
            step.release.manifest_digest.clone(),
        ),
        ("TENKAI_HOST_ACTION", step.action.as_str().into()),
        ("TENKAI_PLAN_ID", step.plan_id.clone()),
    ];
    if let Some(dir) = secrets_dir {
        environment.push(("TENKAI_SECRETS_DIR", dir.display().to_string()));
    }
    environment
}

/// How long stopping what the command left behind may take before the
/// applier says, once, that it is still waiting.
#[cfg(target_os = "linux")]
const DESCENDANT_PATIENCE: Duration = Duration::from_secs(30);

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
    secrets_dir: Option<&Path>,
    timeout: Duration,
    stop: impl Future<Output = ()>,
) -> Result<CommandEnd> {
    let mut command = tokio::process::Command::new(SHELL);
    command
        .arg("-c")
        .arg(&step.command)
        .current_dir(workdir)
        .env_clear()
        .envs(command_environment(step, secrets_dir))
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
        status = child.wait() => match status {
            Ok(status) if status.success() => Ok(CommandEnd {
                outcome: HostApplyOutcome::Succeeded,
                exit_status: Some(0),
                detail: "the command exited with status 0".into(),
            }),
            Ok(status) => Ok(CommandEnd {
                outcome: HostApplyOutcome::Failed,
                exit_status: status.code(),
                detail: format!("the command ended with {status}"),
            }),
            Err(error) => Err(anyhow::Error::from(error).context("waiting for the host command")),
        },
        _ = tokio::time::sleep(timeout) => Ok(CommandEnd {
            outcome: HostApplyOutcome::TimedOut,
            exit_status: None,
            detail: format!(
                "the command exceeded the applier's {}s timeout; its process group was killed",
                timeout.as_secs()
            ),
        }),
        _ = &mut stop => Ok(CommandEnd {
            outcome: HostApplyOutcome::Stopped,
            exit_status: None,
            detail: "the step was stopped; its process group was killed".into(),
        }),
    };
    // Every path ends here. While the leader is unreaped the group id is
    // still the command's; a group already empty (ESRCH) is fine, and the
    // sweep below finds whatever left it.
    if child.try_wait().ok().flatten().is_none() {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    stop_descendants();
    end
}

/// Kill and reap the applier's children until it has none. With
/// [`adopt_descendants`] that is every process the command started. It never
/// gives up: the step is recorded, and the product lock released, only once
/// nothing the command started is left. A process stuck in the kernel keeps
/// the lock until it dies.
#[cfg(target_os = "linux")]
fn stop_descendants() {
    use rustix::process::{Signal, WaitOptions, kill_process, wait};
    let started = std::time::Instant::now();
    let mut warned = false;
    loop {
        // Any child: `waitpid(None, ..)` would wait only for the applier's
        // own process group.
        match wait(WaitOptions::NOHANG) {
            Err(rustix::io::Errno::CHILD) => return,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => {
                for pid in children() {
                    let _ = kill_process(pid, Signal::KILL);
                }
                if !warned && started.elapsed() > DESCENDANT_PATIENCE {
                    eprintln!(
                        "tenkai-host-applier: processes the command started are still running; holding the product lock until they are gone"
                    );
                    warned = true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn stop_descendants() {}

/// The applier's live children, from `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn children() -> Vec<rustix::process::Pid> {
    let me = rustix::process::getpid().as_raw_nonzero().get();
    let mut children = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return children;
    };
    for entry in entries {
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
    children
}
