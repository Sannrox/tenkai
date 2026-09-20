use std::ffi::OsString;

use anyhow::Result;
use tenkai::command_result::{CommandName, CommandResultV1, RetryGuidance};
use tenkai::{plan, reconciler};

use crate::args::Command;
use crate::catalog_args::ReleaseCommand;
use crate::env_args::EnvCommand;

pub(crate) fn print_steps(steps: &[plan::Step]) {
    for s in steps {
        let from = s.from.as_deref().unwrap_or("none");
        println!(
            "  {:<9} {:<24} {} -> {}",
            s.action.to_string(),
            s.product,
            from,
            s.to
        );
    }
}

#[derive(Debug)]
pub(crate) struct ReportedMachineFailure(pub(crate) CommandResultV1);

impl std::fmt::Display for ReportedMachineFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("machine-readable command failure")
    }
}

impl std::error::Error for ReportedMachineFailure {}

pub(crate) fn machine_output_requested(args: &[OsString]) -> bool {
    args.windows(2).any(|pair| {
        pair[0] == std::ffi::OsStr::new("--output") && pair[1] == std::ffi::OsStr::new("json-v1")
    }) || args
        .iter()
        .any(|arg| arg == std::ffi::OsStr::new("--output=json-v1"))
}

pub(crate) fn command_name(command: &Command) -> Option<CommandName> {
    match command {
        Command::Publish { .. } => Some(CommandName::Publish),
        Command::Promote { .. } => Some(CommandName::Promote),
        Command::Plan { .. } => Some(CommandName::Plan),
        Command::Apply { .. } => Some(CommandName::Apply),
        Command::Status { .. } => Some(CommandName::Status),
        Command::Env {
            command: EnvCommand::Inspect { .. },
        } => Some(CommandName::InspectEnvironment),
        Command::Rollback { .. } => Some(CommandName::Rollback),
        Command::Restart { .. } => Some(CommandName::Restart),
        Command::Release {
            command: ReleaseCommand::Recall { .. },
        } => Some(CommandName::Recall),
        _ => None,
    }
}

pub(crate) fn mutation_retry(command: CommandName) -> RetryGuidance {
    match command {
        CommandName::Publish
        | CommandName::Promote
        | CommandName::Plan
        | CommandName::Apply
        | CommandName::Rollback
        | CommandName::Restart
        | CommandName::Recall => RetryGuidance::ReconcileBeforeRetry,
        _ => RetryGuidance::CorrectRequest,
    }
}

pub(crate) fn print_machine_result(result: &CommandResultV1) -> Result<()> {
    result
        .validate()
        .map_err(|message| anyhow::anyhow!(message))?;
    println!("{}", serde_json::to_string(result)?);
    Ok(())
}

pub(crate) fn reported_machine_failure(result: CommandResultV1) -> anyhow::Error {
    ReportedMachineFailure(result).into()
}
pub(crate) fn print_reconcile_report(report: reconciler::TickReport) {
    for result in report.environments {
        match result.status {
            reconciler::EnvironmentStatus::Current => {
                println!("{:<24} current", result.environment);
            }
            reconciler::EnvironmentStatus::Applied { plan_id, steps } => {
                println!(
                    "{:<24} applied {steps} step(s) with {plan_id}",
                    result.environment
                );
            }
            reconciler::EnvironmentStatus::AwaitingRuntime { plan_id, steps } => {
                println!(
                    "{:<24} awaiting runtime for {steps} step(s) in {plan_id}",
                    result.environment
                );
            }
            reconciler::EnvironmentStatus::AwaitingApproval { plan_id, steps } => {
                println!(
                    "{:<24} awaiting signed approval for {steps} step(s) in {plan_id}",
                    result.environment
                );
            }
            reconciler::EnvironmentStatus::Failed { error } => {
                eprintln!("{:<24} FAILED {error}", result.environment);
            }
            reconciler::EnvironmentStatus::Deferred { retry_at } => {
                println!("{:<24} deferred until {retry_at}", result.environment);
            }
            reconciler::EnvironmentStatus::Busy => {
                println!("{:<24} already reconciling", result.environment);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cli, OutputFormat};
    use clap::Parser;
    use clap::error::ErrorKind;

    #[test]
    fn machine_output_flag_is_explicit_and_bounded_to_supported_commands() {
        let args = ["tenkaictl", "plan", "--output", "json-v1"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        assert!(machine_output_requested(&args));

        let cli = Cli::try_parse_from(["tenkaictl", "plan", "--output=json-v1"]).unwrap();
        assert_eq!(cli.output, OutputFormat::JsonV1);
        assert_eq!(command_name(&cli.command), Some(CommandName::Plan));

        let unsupported = Cli::try_parse_from(["tenkaictl", "init", "--output=json-v1"]).unwrap();
        assert_eq!(command_name(&unsupported.command), None);

        let help = Cli::try_parse_from(["tenkaictl", "plan", "--output=json-v1", "--help"])
            .err()
            .expect("help exits through Clap's display path");
        assert_eq!(help.kind(), ErrorKind::DisplayHelp);
        assert_eq!(help.exit_code(), 0);
    }

    #[test]
    fn every_machine_command_has_a_deterministic_bounded_envelope() {
        let cases = [
            (CommandName::Publish, "release"),
            (CommandName::Promote, "channel"),
            (CommandName::Plan, "plan"),
            (CommandName::Apply, "plan"),
            (CommandName::Status, "environment"),
            (CommandName::InspectEnvironment, "environment"),
            (CommandName::Rollback, "plan"),
            (CommandName::Restart, "plan"),
            (CommandName::Recall, "release"),
        ];
        for (command, resource_kind) in cases {
            let result = CommandResultV1::succeeded(command)
                .resource(resource_kind, "opaque")
                .counts(Some(1), Some(1));
            let first = serde_json::to_string(&result).unwrap();
            let second = serde_json::to_string(&result).unwrap();
            assert_eq!(first, second);
            assert_eq!(
                serde_json::from_str::<CommandResultV1>(&first).unwrap(),
                result
            );
            assert!(!first.contains('\n'));
            assert!(first.len() < 1024);
        }
    }
}
