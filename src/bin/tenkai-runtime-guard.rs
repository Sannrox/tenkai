//! Private parent-death guard for environment-runtime executors.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context as _, Result};
use clap::Parser;
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;

#[derive(Parser)]
#[command(name = "tenkai-runtime-guard", hide = true, trailing_var_arg = true)]
struct Args {
    #[arg(long)]
    executor: PathBuf,
    #[arg(allow_hyphen_values = true)]
    arguments: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut command = Command::new(args.executor);
    command
        .args(args.arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The guard is already the group leader created by the runtime. Keep the
    // executor and every descendant in that same OS-enforced process group.
    let mut child = command.spawn().context("spawning runtime executor")?;
    let mut parent = tokio::io::stdin();
    let mut byte = [0_u8; 1];
    let status = tokio::select! {
        status = child.wait() => return status.context("waiting for runtime executor").and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                anyhow::bail!("runtime executor failed")
            }
        }),
        read = parent.read(&mut byte) => read,
        _ = shutdown_signal() => Ok(0),
    };
    let _ = status;
    terminate_group();
}

async fn shutdown_signal() {
    let mut interrupt =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = async {
            if let Some(signal) = interrupt.as_mut() {
                signal.recv().await;
            }
        } => {}
        _ = async {
            if let Some(signal) = terminate.as_mut() {
                signal.recv().await;
            }
        } => {}
    }
}

fn terminate_group() -> ! {
    let process_group = -(std::process::id() as i32);
    unsafe {
        libc::kill(process_group, libc::SIGKILL);
    }
    std::process::abort()
}
