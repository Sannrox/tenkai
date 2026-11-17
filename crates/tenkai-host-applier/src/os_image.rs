//! The host's on-host updater as the applier reaches it (ADR 0051): the
//! root-owned booted-image reader and the current boot's id.
//!
//! The reader is the only witness of which image booted. It runs from the
//! root-owned `[os_image]` configuration, never from anything the server
//! supplied, with a cleared environment, a timeout, and bounded output that
//! is parsed strictly ([`tenkai::host_apply::os_image::BootedImage::parse`]).

use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use tenkai::host_apply::os_image::{BootedImage, MAX_READER_OUTPUT};

use crate::config::{OsImageConfig, require_trusted};
use crate::{ApplierConfig, ApplierPaths};

/// How long the reader may run before its process group is killed.
const READER_TIMEOUT: Duration = Duration::from_secs(60);
/// `PATH` of the updater commands, as for every host command.
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// What the updater reports now, through the reader in `host-applier.toml`.
pub fn read_booted(paths: &ApplierPaths) -> Result<BootedImage> {
    let config = ApplierConfig::load(paths)?;
    read_booted_with(config.os_image()?)
}

/// What the updater reports now, through `os_image.reader`.
pub fn read_booted_with(os_image: &OsImageConfig) -> Result<BootedImage> {
    let output =
        run_reader(&os_image.reader, READER_TIMEOUT).context("running the booted-image reader")?;
    BootedImage::parse(&output)
}

/// The current boot's id, which changes with every boot.
pub fn boot_id(paths: &ApplierPaths) -> Result<String> {
    let raw = std::fs::read_to_string(&paths.boot_id)
        .with_context(|| format!("reading {}", paths.boot_id.display()))?;
    let id = raw.trim();
    if id.is_empty() {
        bail!("{} is empty", paths.boot_id.display());
    }
    Ok(id.to_string())
}

/// A root updater command as a process: its trusted program, its fixed
/// arguments, and only the fixed environment.
pub fn updater_command(argv: &[String]) -> Result<Command> {
    let (program, args) = argv.split_first().context("empty updater command")?;
    require_trusted(Path::new(program))?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", PATH)
        .env("LANG", "C.UTF-8")
        .current_dir("/")
        .stdin(Stdio::null());
    Ok(command)
}

/// Run the reader in its own process group until it exits or `timeout`
/// passes, and return what it printed. More than [`MAX_READER_OUTPUT`]
/// bytes, a timeout, or a failed exit is an error.
fn run_reader(argv: &[String], timeout: Duration) -> Result<Vec<u8>> {
    let mut command = updater_command(argv)?;
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().context("spawning the reader")?;
    let bounded = |pipe: Option<_>| {
        pipe.map(|pipe: Box<dyn std::io::Read + Send>| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                // One byte past the bound tells an overlong output apart.
                let _ = pipe
                    .take(MAX_READER_OUTPUT as u64 + 1)
                    .read_to_end(&mut bytes);
                bytes
            })
        })
    };
    let stdout = bounded(child.stdout.take().map(|pipe| Box::new(pipe) as _));
    let stderr = bounded(child.stderr.take().map(|pipe| Box::new(pipe) as _));
    let pid = rustix::process::Pid::from_raw(child.id() as i32)
        .context("the reader has no process id")?;
    // Wait without reaping, so the group id stays the reader's until its
    // group is killed: whatever it left behind goes with it and the pipes
    // close.
    let started = Instant::now();
    let exited = loop {
        let options = rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOWAIT
            | rustix::process::WaitIdOptions::NOHANG;
        if rustix::process::waitid(rustix::process::WaitId::Pid(pid), options)?.is_some() {
            break true;
        }
        if started.elapsed() > timeout {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    let status = child.wait().context("waiting for the reader")?;
    let stdout = stdout.map(|thread| thread.join().unwrap_or_default());
    let stderr = stderr.map(|thread| thread.join().unwrap_or_default());
    if !exited {
        bail!("the reader did not finish within {}s", timeout.as_secs());
    }
    if !status.success() {
        let stderr = String::from_utf8_lossy(stderr.as_deref().unwrap_or_default());
        bail!("the reader ended with {status}: {}", stderr.trim());
    }
    Ok(stdout.unwrap_or_default())
}
