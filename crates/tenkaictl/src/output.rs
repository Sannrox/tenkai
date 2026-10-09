use std::ffi::OsString;

use anyhow::Result;
use tenkai::command_result::{CommandName, CommandOutcome, CommandResultV1, RetryGuidance};
use tenkai::{plan, reconciler};

use crate::args::{Command, Target};
use crate::catalog_args::{ApprovalCommand, ReleaseCommand};
use crate::env_args::EnvCommand;
use crate::fleet_args::FleetCommand;

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

/// The `tenkai.command-result/v1` command name for `command` on `target`, or
/// `None` when that combination has no machine-readable result and must fail
/// closed. Remote mode supports every command the v1 HTTP API exposes.
pub(crate) fn command_name(command: &Command, target: Target) -> Option<CommandName> {
    let name = match command {
        Command::Publish { .. } => CommandName::Publish,
        Command::Promote { .. } => CommandName::Promote,
        Command::Plan { .. } => CommandName::Plan,
        Command::Apply { .. } => CommandName::Apply,
        Command::Status { .. } => CommandName::Status,
        Command::Env {
            command: EnvCommand::Inspect { .. },
        } => CommandName::InspectEnvironment,
        Command::Env {
            command: EnvCommand::Subscribe { .. },
        } => CommandName::Subscribe,
        Command::Env {
            command: EnvCommand::List,
        } => CommandName::ListEnvironments,
        Command::Fleet {
            command: FleetCommand::Status,
        } => CommandName::FleetStatus,
        Command::Approval {
            command: ApprovalCommand::Submit { .. },
        } => CommandName::Approve,
        Command::Rollback { .. } => CommandName::Rollback,
        Command::Restart { .. } if target == Target::Embedded => CommandName::Restart,
        Command::Release {
            command: ReleaseCommand::Recall { .. },
        } => CommandName::Recall,
        _ => return None,
    };
    Some(name)
}

fn is_mutation(command: CommandName) -> bool {
    matches!(
        command,
        CommandName::Publish
            | CommandName::Promote
            | CommandName::Plan
            | CommandName::Apply
            | CommandName::Rollback
            | CommandName::Restart
            | CommandName::Recall
            | CommandName::Approve
            | CommandName::Subscribe
    )
}

pub(crate) fn mutation_retry(command: CommandName) -> RetryGuidance {
    if is_mutation(command) {
        RetryGuidance::ReconcileBeforeRetry
    } else {
        RetryGuidance::CorrectRequest
    }
}

/// Classify a failed remote call without echoing server detail. A mutation
/// whose response was lost, or that hit a server error, has an unknown outcome.
pub(crate) fn remote_failure_result(
    command: CommandName,
    failure: &tenkai_http::RemoteFailure,
) -> CommandResultV1 {
    use tenkai_http::RemoteFailure;
    let mutation = is_mutation(command);
    let (code, message, retry, unknown) = match failure {
        RemoteFailure::NotSent(_) => (
            "transport_unavailable",
            "The request did not reach the Tenkai server",
            RetryGuidance::CorrectRequest,
            false,
        ),
        RemoteFailure::ResponseLost(_) => (
            "transport_interrupted",
            "The connection failed before a complete response arrived",
            RetryGuidance::ReconcileBeforeRetry,
            mutation,
        ),
        RemoteFailure::Rejected { status, .. } => match status {
            401 => (
                "authentication_refused",
                "The server did not accept the credential",
                RetryGuidance::CorrectRequest,
                false,
            ),
            403 => (
                "authorization_denied",
                "The credential is not allowed to perform this operation",
                RetryGuidance::CorrectRequest,
                false,
            ),
            409 => (
                "conflict",
                "The generation or lease is stale, or the state conflicts",
                RetryGuidance::ReconcileBeforeRetry,
                false,
            ),
            422 => (
                "execution_failed",
                "One or more delivery steps did not succeed",
                RetryGuidance::ReconcileBeforeRetry,
                false,
            ),
            400..=499 => (
                "domain_denied",
                "Tenkai rejected the request",
                RetryGuidance::CorrectRequest,
                false,
            ),
            _ => (
                "server_error",
                "The Tenkai server failed while handling the request",
                RetryGuidance::ReconcileBeforeRetry,
                mutation,
            ),
        },
    };
    let mut result = CommandResultV1::failed(command, code, message, retry);
    if unknown {
        result.outcome = CommandOutcome::Unknown;
    }
    result
}

/// Success envelopes shared by embedded and remote mode so both targets agree.
pub(crate) fn subscribe_result(env: &str, spec: &str) -> CommandResultV1 {
    CommandResultV1::succeeded(CommandName::Subscribe)
        .resource("environment", env)
        .resource("subscription", spec)
}

pub(crate) fn list_environments_result(count: usize) -> CommandResultV1 {
    CommandResultV1::succeeded(CommandName::ListEnvironments).counts(None, Some(count))
}

pub(crate) fn fleet_status_result(report: &plan::FleetStatusReport) -> CommandResultV1 {
    CommandResultV1::succeeded(CommandName::FleetStatus)
        .counts(None, Some(report.environment_count))
}

pub(crate) fn status_result(env: &str, rows: usize) -> CommandResultV1 {
    CommandResultV1::succeeded(CommandName::Status)
        .resource("environment", env)
        .counts(None, Some(rows))
}

pub(crate) fn inspect_result(report: &plan::EnvironmentInspectReport) -> CommandResultV1 {
    CommandResultV1::succeeded(CommandName::InspectEnvironment)
        .resource("environment", &report.id)
        .counts(None, Some(report.subscriptions.len()))
}

pub(crate) fn promote_result(spec: &str, channel: &str) -> CommandResultV1 {
    let product = spec.split_once('@').map_or(spec, |value| value.0);
    CommandResultV1::succeeded(CommandName::Promote)
        .resource("channel", format!("{product}/{channel}"))
}

pub(crate) fn approve_result(plan_id: &str, environment: &str) -> CommandResultV1 {
    CommandResultV1::succeeded(CommandName::Approve)
        .resource("plan", plan_id)
        .resource("environment", environment)
}

/// In json-v1 mode, turn a failed remote mutation into its envelope with the
/// resources it targeted, so the caller knows what to reconcile.
pub(crate) fn with_remote_resources(
    error: anyhow::Error,
    output: crate::args::OutputFormat,
    command: CommandName,
    resources: &[(&'static str, &str)],
) -> anyhow::Error {
    let failure = match error.downcast_ref::<tenkai_http::RemoteFailure>() {
        Some(failure) if output == crate::args::OutputFormat::JsonV1 => failure,
        _ => return error,
    };
    let result = resources.iter().fold(
        remote_failure_result(command, failure),
        |result, (kind, id)| result.resource(kind, *id),
    );
    reported_machine_failure(result)
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
            reconciler::EnvironmentStatus::Held {
                plan_id,
                steps,
                reason,
                scope,
            } => {
                println!(
                    "{:<24} held ({scope}) for {steps} step(s) in {plan_id}: {reason}",
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
        assert_eq!(
            command_name(&cli.command, Target::Embedded),
            Some(CommandName::Plan)
        );

        let unsupported = Cli::try_parse_from(["tenkaictl", "init", "--output=json-v1"]).unwrap();
        assert_eq!(command_name(&unsupported.command, Target::Remote), None);

        let help = Cli::try_parse_from(["tenkaictl", "plan", "--output=json-v1", "--help"])
            .err()
            .expect("help exits through Clap's display path");
        assert_eq!(help.kind(), ErrorKind::DisplayHelp);
        assert_eq!(help.exit_code(), 0);
    }

    #[test]
    fn remote_failures_never_report_an_interrupted_mutation_as_failed_or_succeeded() {
        use tenkai_http::RemoteFailure;
        let lost = RemoteFailure::ResponseLost("reset".into());
        let mutation = remote_failure_result(CommandName::Apply, &lost);
        assert_eq!(mutation.outcome, CommandOutcome::Unknown);
        assert_eq!(mutation.retry, RetryGuidance::ReconcileBeforeRetry);
        let read = remote_failure_result(CommandName::Status, &lost);
        assert_eq!(read.outcome, CommandOutcome::Failed);

        let not_sent = remote_failure_result(
            CommandName::Apply,
            &RemoteFailure::NotSent("refused".into()),
        );
        assert_eq!(not_sent.outcome, CommandOutcome::Failed);

        let rejected = |status| {
            let result = remote_failure_result(
                CommandName::Plan,
                &RemoteFailure::Rejected {
                    status,
                    detail: "secret server detail".into(),
                },
            );
            assert!(!serde_json::to_string(&result).unwrap().contains("secret"));
            (result.error.unwrap().code, result.outcome)
        };
        assert_eq!(
            rejected(401),
            ("authentication_refused".into(), CommandOutcome::Failed)
        );
        assert_eq!(
            rejected(403),
            ("authorization_denied".into(), CommandOutcome::Failed)
        );
        assert_eq!(rejected(409), ("conflict".into(), CommandOutcome::Failed));
        assert_eq!(
            rejected(422),
            ("execution_failed".into(), CommandOutcome::Failed)
        );
        assert_eq!(
            rejected(404),
            ("domain_denied".into(), CommandOutcome::Failed)
        );
        assert_eq!(
            rejected(500),
            ("server_error".into(), CommandOutcome::Unknown)
        );
    }

    #[test]
    fn remote_target_fails_closed_for_commands_without_a_remote_result() {
        let restart =
            Cli::try_parse_from(["tenkaictl", "restart", "api", "--env", "stage"]).unwrap();
        assert_eq!(
            command_name(&restart.command, Target::Embedded),
            Some(CommandName::Restart)
        );
        assert_eq!(command_name(&restart.command, Target::Remote), None);
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
            (CommandName::Approve, "plan"),
            (CommandName::Subscribe, "environment"),
            (CommandName::ListEnvironments, "environment"),
            (CommandName::FleetStatus, "environment"),
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
