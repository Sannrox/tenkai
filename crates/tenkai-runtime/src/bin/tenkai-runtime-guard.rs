//! Private parent-death guard for environment-runtime executors.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context as _, Result};
use clap::Parser;
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;
use tokio::signal::unix::{Signal, SignalKind, signal};

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
    // Handlers exist before the executor does, so a SIGINT or SIGTERM always
    // reaches `terminate_group` and never leaves the executor behind. A guard
    // that cannot register them refuses to start (#1337).
    let interrupt = signal(SignalKind::interrupt()).context("registering SIGINT handler")?;
    let terminate = signal(SignalKind::terminate()).context("registering SIGTERM handler")?;
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
        status = child.wait() => {
            // Exit here, not by returning: dropping the runtime waits for the
            // blocking stdin read, which never ends while the parent holds
            // the pipe open, so the parent would never see the exit.
            let code = match status {
                Ok(status) if status.success() => 0,
                Ok(_) => {
                    eprintln!("runtime executor failed");
                    1
                }
                Err(error) => {
                    eprintln!("waiting for runtime executor: {error}");
                    1
                }
            };
            std::process::exit(code);
        }
        read = parent.read(&mut byte) => read,
        _ = shutdown_signal(interrupt, terminate) => Ok(0),
    };
    let _ = status;
    terminate_group();
}

async fn shutdown_signal(mut interrupt: Signal, mut terminate: Signal) {
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
    }
}

fn terminate_group() -> ! {
    let process_group = -(std::process::id() as i32);
    unsafe {
        libc::kill(process_group, libc::SIGKILL);
    }
    std::process::abort()
}
