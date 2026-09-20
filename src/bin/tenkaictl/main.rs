//! tenkaictl — embedded and remote delivery control-plane CLI.

mod args;
mod authorization;
mod catalog_args;
mod dev_args;
mod embedded;
mod embedded_apply;
mod embedded_catalog;
mod embedded_dev;
mod embedded_env;
mod embedded_env_config;
mod embedded_fleet;
mod embedded_migrate;
mod embedded_product;
mod embedded_reconcile;
mod embedded_rollback;
mod embedded_upgrade;
mod embedded_wave;
mod env_args;
mod flags;
mod fleet_args;
mod fleet_watch;
mod migrate_args;
mod output;
mod product_args;
mod remote;
mod remote_catalog;
mod remote_delivery;
#[cfg(test)]
mod tests;
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
    print_machine_result, reported_machine_failure,
};

#[tokio::main]
async fn main() -> ExitCode {
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
    let machine_command = command_name(&cli.command).unwrap_or(CommandName::Invocation);
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if output == OutputFormat::JsonV1 {
                let result = error
                    .downcast_ref::<ReportedMachineFailure>()
                    .map(|reported| reported.0.clone())
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
    if let Some(operation_id) = cli
        .operation_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        tenkai::telemetry::bind_process_operation_id(operation_id);
    }
    if cli.output == OutputFormat::JsonV1 && command_name(&cli.command).is_none() {
        return Err(reported_machine_failure(CommandResultV1::failed(
            CommandName::Invocation,
            "unsupported_command",
            "This command does not support tenkai.command-result/v1",
            RetryGuidance::CorrectRequest,
        )));
    }
    if cli.output == OutputFormat::JsonV1 && cli.target == Target::Remote {
        return Err(reported_machine_failure(CommandResultV1::failed(
            command_name(&cli.command).unwrap_or(CommandName::Invocation),
            "unsupported_target",
            "Machine-readable results currently require --target embedded",
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
        return tenkai::fenced_mutation::supervise(
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
