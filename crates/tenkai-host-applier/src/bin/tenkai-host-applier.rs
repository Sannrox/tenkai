//! `tenkai-host-applier run <instance>`: the root side of a privileged host
//! release step (ADR 0041 §2). `tenkai-host-apply@<instance>.service` runs
//! it; see `docs/host-releases.md`. Exit status: 0 succeeded, 1 the step
//! failed, 2 refused before anything started.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use tenkai_host_applier::{Applied, ApplierPaths, apply};

const USAGE: &str = "usage: tenkai-host-applier run <instance> [--config-dir DIR] [--state-dir DIR] [--run-dir DIR]";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some("--version" | "-V") => {
            println!("tenkai-host-applier {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    match run() {
        Ok(applied) => {
            match &applied {
                Applied::Result(result) => match serde_json::to_string(result) {
                    Ok(json) => println!("{json}"),
                    Err(error) => eprintln!("tenkai-host-applier: {error}"),
                },
                Applied::Refused(reason) => eprintln!("tenkai-host-applier: refused: {reason}"),
                Applied::Renewed => println!("renewed the workload certificate"),
            }
            ExitCode::from(applied.exit_code())
        }
        Err(error) => {
            eprintln!("tenkai-host-applier: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<Applied> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("run") {
        bail!("{USAGE}");
    }
    let instance = args.next().context(USAGE)?;
    let mut paths = ApplierPaths::default();
    while let Some(flag) = args.next() {
        let value = PathBuf::from(
            args.next()
                .with_context(|| format!("{flag} needs a value"))?,
        );
        match flag.as_str() {
            "--config-dir" => paths.config_dir = value,
            "--state-dir" => paths.state_dir = value,
            "--run-dir" => paths.run_dir = value,
            _ => bail!("unknown argument {flag}\n{USAGE}"),
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(apply(&paths, &instance, || {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        Ok(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        })
    }))
}
