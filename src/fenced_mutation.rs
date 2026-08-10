//! Generation-fenced local mutation supervision.
//!
//! This deep module owns executor-guard discovery, the controller/guard pipe
//! protocol, mutation locking, process-group cleanup, signals, and timeouts.
//! Callers retain lease ownership and expose only refresh plus generation.

use std::fs::OpenOptions;
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;

use anyhow::{Context as _, Result, bail};

pub trait MutationFence: Send {
    fn generation(&self) -> u64;
    fn refresh(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

pub struct MutationCommand<'a> {
    pub lock_path: &'a Path,
    pub workdir: &'a Path,
    pub environment: &'a str,
    pub product: &'a str,
    pub command: &'a str,
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

pub async fn run(
    fence: &mut dyn MutationFence,
    mutation: MutationCommand<'_>,
) -> Result<Result<(), String>> {
    fence.refresh().await?;
    if let Some(parent) = mutation.lock_path.parent() {
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
        .arg(mutation.lock_path)
        .arg("--workdir")
        .arg(mutation.workdir)
        .arg("--environment")
        .arg(mutation.environment)
        .arg("--product")
        .arg(mutation.product)
        .arg("--generation")
        .arg(fence.generation().to_string())
        .arg("--command")
        .arg(mutation.command)
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
        tokio::select! { result = &mut ready_read => { result?; break; }, _ = waiting_refresh.tick() => fence.refresh().await?, }
    }
    drop(ready_read);
    if ready != *b"R" {
        bail!("deployment command guard failed to acquire the mutation fence");
    }
    fence.refresh().await?;
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
            _ = refresh.tick() => if let Err(error) = fence.refresh().await { break (None, Some(format!("deployment command lost its environment fence: {error}"))); }
        }
    };
    if let Some(reason) = interrupted {
        drop(control);
        let _ = wait.await;
        return Ok(Err(reason));
    }
    fence.refresh().await?;
    let status = status.expect("completed command has an exit status");
    Ok(if status.success() {
        Ok(())
    } else {
        Err(format!("deployment command exited with {status}"))
    })
}

pub async fn supervise(mutation: MutationCommand<'_>, generation: u64) -> Result<()> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(mutation.lock_path)?;
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
    let identity_digest =
        crate::manifest::digest(&format!("{}\0{}", mutation.environment, mutation.product));
    let mut child = tokio::process::Command::new("sh");
    child
        .arg("-c")
        .arg(mutation.command)
        .current_dir(mutation.workdir)
        .kill_on_drop(true)
        .env_remove("SEKAI_AUTH_TOKEN")
        .env("TENKAI_ENVIRONMENT", mutation.environment)
        .env("TENKAI_PRODUCT", mutation.product)
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
        status = child.wait() => { let status = status?; unsafe { libc::kill(-process_group, libc::SIGKILL) }; wait_for_process_group_exit(process_group).await?; if status.success() { Ok(()) } else { bail!("deployment command exited with {status}") } }
        _ = &mut controller_closed => { unsafe { libc::kill(-process_group, libc::SIGKILL) }; let _ = child.wait().await; wait_for_process_group_exit(process_group).await?; bail!("deployment controller exited") }
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
