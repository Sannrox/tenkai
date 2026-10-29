//! tenkaictl — embedded and remote delivery control-plane CLI.

mod args;
mod authorization;
mod bundle_args;
mod catalog_args;
mod dev_args;
mod embedded;
mod embedded_apply;
mod embedded_bundle;
mod embedded_catalog;
mod embedded_dev;
mod embedded_env;
mod embedded_env_config;
mod embedded_fleet;
mod embedded_hold;
mod embedded_migrate;
mod embedded_preflight;
mod embedded_product;
mod embedded_reconcile;
mod embedded_rollback;
mod embedded_topology;
mod embedded_upgrade;
mod embedded_wave;
mod env_args;
mod flags;
mod fleet_args;
mod fleet_watch;
mod keys;
mod login;
mod migrate_args;
mod output;
mod product_args;
mod remote;
mod remote_catalog;
mod remote_delivery;
mod remote_env_config;
mod remote_hold;
mod revocations;
mod self_upgrade;
#[cfg(test)]
mod tests;
mod token_cache;
mod topology_args;
mod upgrade_args;
mod wave_args;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use clap::error::ErrorKind;
use tenkai::command_result::{CommandName, CommandResultV1, RetryGuidance};

use args::{Cli, Command, OutputFormat, Target};
use output::{
    ReportedMachineFailure, command_name, machine_output_requested, mutation_retry,
    print_machine_result, remote_failure_result, reported_machine_failure,
};

#[tokio::main]
async fn main() -> ExitCode {
    tenkai_executor::install();
    let args = std::env::args_os().collect::<Vec<_>>();
    let requested_machine_output = machine_output_requested(&args);
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            if requested_machine_output {
                let result = CommandResultV1::failed(
                    CommandName::Invocation,
                    "invocation_rejected",
                    "The command line is invalid",
                    RetryGuidance::CorrectRequest,
                );
                if let Ok(encoded) = serde_json::to_string(&result) {
                    println!("{encoded}");
                }
            } else {
                let _ = error.print();
            }
            return ExitCode::from(error.exit_code().clamp(1, 255) as u8);
        }
    };
    let output = cli.output;
    let machine_command = command_name(&cli.command, cli.target).unwrap_or(CommandName::Invocation);
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if output == OutputFormat::JsonV1 {
                let remote = error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<tenkai_http::RemoteFailure>());
                let result = error
                    .downcast_ref::<ReportedMachineFailure>()
                    .map(|reported| reported.0.clone())
                    .or_else(|| {
                        remote.map(|failure| remote_failure_result(machine_command, failure))
                    })
                    .unwrap_or_else(|| {
                        CommandResultV1::failed(
                            machine_command,
                            "operation_failed",
                            "Tenkai rejected the operation",
                            mutation_retry(machine_command),
                        )
                    });
                let _ = print_machine_result(&result);
            } else {
                eprintln!("error: {error:#}");
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    tenkai::key_revocation::load_configured()?;
    if let Some(operation_id) = cli
        .operation_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        tenkai::telemetry::bind_process_operation_id(operation_id);
    }
    if cli.output == OutputFormat::JsonV1 && command_name(&cli.command, cli.target).is_none() {
        let (code, message) = match cli.target {
            Target::Embedded => (
                "unsupported_command",
                "This command does not support tenkai.command-result/v1",
            ),
            Target::Remote => (
                "unsupported_target",
                "This command has no tenkai.command-result/v1 result with --target remote",
            ),
        };
        return Err(reported_machine_failure(CommandResultV1::failed(
            CommandName::Invocation,
            code,
            message,
            RetryGuidance::CorrectRequest,
        )));
    }
    if let Command::ExecutorGuard {
        lock,
        workdir,
        environment,
        product,
        generation,
        command,
    } = &cli.command
    {
        let code = tenkai::fenced_mutation::guard(
            tenkai::fenced_mutation::MutationCommand {
                lock_path: lock,
                workdir,
                environment,
                product,
                command,
            },
            *generation,
        )
        .await;
        // The exit code carries the command's status or the guard's failure.
        std::process::exit(i32::from(code));
    }
    if matches!(cli.command, Command::Login { .. } | Command::Logout) {
        return login::run(cli).await;
    }
    if let Command::Revocations { command } = &cli.command {
        return revocations::run(command);
    }
    if let Command::Keys { command } = &cli.command {
        return keys::run(command);
    }
    if let Command::Registry {
        command:
            args::RegistryCommand::Serve {
                store,
                name,
                listen,
                tls_cert,
                tls_key,
            },
    } = &cli.command
    {
        // Needs no Tenkai store: it serves files that imports wrote.
        let router = tenkai_http::oci_registry::router(store, name)?;
        let tls = tenkai_http::oci_registry::tls_config(tls_cert, tls_key)?;
        let listener = tokio::net::TcpListener::bind(listen).await?;
        eprintln!(
            "seed registry {name} serving {} on {listen}",
            store.display()
        );
        return tenkai_http::oci_registry::serve_tls(listener, tls, router).await;
    }
    // Local only: a runner CA is two files written here.
    if let Command::RunnerCa {
        command: args::RunnerCaCommand::Init { dir, name },
    } = &cli.command
    {
        return init_runner_ca(dir, name);
    }
    // Local only: a server self-upgrade acts on this host's home and store.
    if let Command::SelfUpgrade { .. } = &cli.command {
        let Command::SelfUpgrade { command } = cli.command else {
            unreachable!("matched above");
        };
        return self_upgrade::run(command).await;
    }
    // Local only: host install needs the archive, trust roots, and dest.
    if let Command::Upgrade {
        command:
            upgrade_args::UpgradeCommand::InstallHosts {
                env,
                bundle,
                trust_roots,
                dest,
                platform,
            },
    } = &cli.command
    {
        return embedded_upgrade::install_hosts(
            env,
            bundle,
            trust_roots,
            dest,
            platform.as_deref(),
        );
    }
    // Local only: extracting a bundle's docs needs only the archive, trust
    // roots and destination, never a store (#646).
    if let Command::Bundle {
        command:
            bundle_args::BundleCommand::Docs {
                bundle,
                trust_roots,
                env,
                out,
            },
    } = &cli.command
    {
        return embedded_bundle::extract_docs(bundle, trust_roots, env, out);
    }
    // Local only: verifying a support bundle needs only the file.
    if let Command::SupportBundle {
        command:
            args::SupportBundleCommand::Verify {
                bundle,
                trust_roots,
            },
    } = &cli.command
    {
        let roots = tenkai::release_signing::TrustRoots::load(trust_roots)?;
        tenkai::support_bundle::verify(
            &tenkai::support_bundle::SupportBundle::load(bundle)?,
            &roots,
        )?;
        println!("support bundle {} verifies", bundle.display());
        return Ok(());
    }
    // Local only: audit exports read the embedded store and verify offline.
    if let Command::Audit { command } = &cli.command {
        return match command {
            args::AuditCommand::Export {
                dir,
                signing_key,
                trust_roots,
            } => {
                tenkai::storage::refuse_postgres_on_embedded()?;
                let store = tenkai::storage::SqliteStore::open(&cli.database)?;
                let rotated = trust_roots
                    .as_deref()
                    .map(tenkai::release_signing::TrustRoots::load)
                    .transpose()?;
                let export = tenkai::audit_export::export_next(
                    &store,
                    dir,
                    tenkai::now_millis(),
                    signing_key,
                    rotated.as_ref(),
                )?;
                println!(
                    "audit export {} ({} to {}) holds {} entries, digest {}",
                    export.statement.sequence,
                    export.statement.period_start_ms,
                    export.statement.period_end_ms,
                    export.statement.entries.len(),
                    export.digest()?
                );
                Ok(())
            }
            args::AuditCommand::ExportRange {
                dir,
                from,
                to,
                out,
                trust_roots,
            } => {
                let roots = tenkai::release_signing::TrustRoots::load(trust_roots)?;
                let range = tenkai::audit_export::range(dir, *from, *to, &roots)?;
                tenkai::audit_export::write_range(&range, out)?;
                println!(
                    "audit range {from} to {to} holds {} exports",
                    range.exports.len()
                );
                Ok(())
            }
            args::AuditCommand::Verify {
                exports,
                trust_roots,
                anchor,
            } => {
                let roots = tenkai::release_signing::TrustRoots::load(trust_roots)?;
                if let [single] = exports.as_slice() {
                    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(single)?)?;
                    if raw["schema"] == tenkai::audit_export::AUDIT_RANGE_SCHEMA {
                        let range = tenkai::audit_export::AuditRange::load(single)?;
                        tenkai::audit_export::verify_range(&range, &roots, anchor.as_deref())?;
                        println!(
                            "audit range {} to {} verifies as one chain",
                            range.from, range.to
                        );
                        return Ok(());
                    }
                }
                let loaded = exports
                    .iter()
                    .map(|path| tenkai::audit_export::AuditExport::load(path))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                tenkai::audit_export::verify_chain(&loaded, &roots, anchor.as_deref())?;
                println!("{} audit exports verify as one chain", loaded.len());
                Ok(())
            }
        };
    }
    // Local only: a drill reads backup files and never contacts a hub.
    if let Command::RestoreDrill {
        backup,
        scratch_dir,
        trust_roots,
    } = &cli.command
    {
        let scratch = scratch_dir.clone().unwrap_or_else(std::env::temp_dir);
        let roots = trust_roots
            .as_deref()
            .map(tenkai::release_signing::TrustRoots::load)
            .transpose()?;
        let evidence =
            tenkai::backup::drill(backup, &scratch, tenkai::now_millis(), roots.as_ref())?;
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        return Ok(());
    }
    // Local only: evidence goes into the backup directory the hub reads.
    if let Command::BackupEvidence {
        dir,
        backup,
        tool,
        taken_at_ms,
    } = &cli.command
    {
        let now = tenkai::now_millis();
        let evidence = tenkai::backup::evidence_for_file(backup, tool, taken_at_ms.unwrap_or(now))?;
        tenkai::backup::record_evidence(dir, evidence, now)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&tenkai::backup::read_status(dir)?)?
        );
        return Ok(());
    }
    if cli.target == Target::Remote {
        return remote::run(cli).await;
    }
    if matches!(cli.command, Command::Restore { .. }) {
        return embedded_dev::restore(&cli).await;
    }
    if matches!(cli.command, Command::Dev { .. }) {
        return embedded_dev::run_dev(&cli).await;
    }
    embedded::run(cli).await
}

/// Write a new runner CA into `dir`, refusing to replace an existing one.
fn init_runner_ca(dir: &std::path::Path, name: &str) -> Result<()> {
    use anyhow::Context as _;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let (cert, key) = tenkai::runner_ca::RunnerCa::generate(name)?;
    std::fs::create_dir_all(dir)?;
    for (file, contents, mode) in [
        ("runner-ca-key.pem", &key, 0o600),
        ("runner-ca.pem", &cert, 0o644),
    ] {
        let path = dir.join(file);
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .with_context(|| {
                format!(
                    "creating {} (an existing CA is never replaced)",
                    path.display()
                )
            })?;
        out.write_all(contents.as_bytes())?;
        out.sync_all()?;
    }
    println!(
        "wrote {}/runner-ca.pem and runner-ca-key.pem",
        dir.display()
    );
    Ok(())
}
