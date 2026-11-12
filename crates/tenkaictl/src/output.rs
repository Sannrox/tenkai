use std::ffi::OsString;

use anyhow::Result;
use tenkai::command_result::{CommandName, CommandOutcome, CommandResultV1, RetryGuidance};
use tenkai::{plan, reconciler};

use crate::args::{Command, Target};
use crate::catalog_args::{ApprovalCommand, ReleaseCommand};
use crate::env_args::EnvCommand;
use crate::fleet_args::FleetCommand;

pub(crate) fn print_hold_view(view: &tenkai::delivery_hold::DeliveryHoldView) {
    match &view.hold {
        Some(hold) => println!(
            "held at {} by {}: {}",
            hold.held_at, hold.actor, hold.reason
        ),
        None => println!("no delivery hold"),
    }
    if let Some(threshold) = &view.threshold {
        println!(
            "threshold: more than {} failed targets in {}ms",
            threshold.count, threshold.window_ms
        );
    }
    print_delivery_freezes(None, &view.freezes);
    for event in &view.audit {
        println!(
            "{} {} by {}: {}",
            event.at, event.action, event.actor, event.reason
        );
    }
}

pub(crate) fn print_delivery_freezes(
    env: Option<&str>,
    freezes: &[tenkai::delivery_hold::DeliveryFreeze],
) {
    let now = tenkai::now_millis();
    let prefix = env.map(|name| format!("{name} ")).unwrap_or_default();
    for freeze in freezes {
        if freeze.active_at(now) {
            println!(
                "{prefix}freeze {} until {} by {}: {}",
                freeze.name,
                tenkai::delivery_hold::format_freeze_instant(freeze.until_ms),
                freeze.actor,
                freeze.reason
            );
        } else {
            println!(
                "{prefix}upcoming freeze {} from {} until {} by {}: {}",
                freeze.name,
                tenkai::delivery_hold::format_freeze_instant(freeze.from_ms),
                tenkai::delivery_hold::format_freeze_instant(freeze.until_ms),
                freeze.actor,
                freeze.reason
            );
        }
    }
}

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
        for change in &s.target_changes {
            if change.fields.is_empty() {
                continue;
            }
            for field in &change.fields {
                let from = field.from.as_deref().unwrap_or("-");
                let to = field.to.as_deref().unwrap_or("-");
                println!(
                    "    {} {} {}: {} -> {}",
                    change.kind, change.name, field.field, from, to
                );
            }
        }
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
        Command::Explain { .. } => CommandName::Explain,
        Command::Env {
            command: EnvCommand::Inspect { .. },
        } => CommandName::InspectEnvironment,
        Command::Env {
            command: EnvCommand::History { .. },
        } => CommandName::HistoryEnvironment,
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

pub(crate) fn print_explain(report: &tenkai::instance_explain::InstanceExplainReport) {
    if report.blockers.is_empty() {
        match report.next_change.as_ref() {
            Some(next) if next.action == "current" => {
                println!(
                    "{}/{} is current at {}",
                    report.environment, report.instance, next.head
                );
            }
            Some(next) if next.action == "install" => {
                println!(
                    "{}/{} next change: install {}",
                    report.environment, report.instance, next.head
                );
            }
            Some(next) if next.action == "upgrade" => {
                let deployed = next.deployed.as_deref().unwrap_or("-");
                println!(
                    "{}/{} next change: upgrade {deployed} -> {}",
                    report.environment, report.instance, next.head
                );
            }
            Some(next) if next.action == "restart" => {
                println!(
                    "{}/{} next change: restart {}",
                    report.environment, report.instance, next.head
                );
            }
            Some(next) => {
                println!(
                    "{}/{} next change: {}",
                    report.environment, report.instance, next.action
                );
            }
            None => println!("{}/{} has no blockers", report.environment, report.instance),
        }
        return;
    }
    println!("{}/{} blocked:", report.environment, report.instance);
    for blocker in &report.blockers {
        println!("  {:<18} {}", blocker.check, blocker.evidence);
        println!("  {:<18} unblock: {}", "", blocker.unblock);
    }
}

pub(crate) fn status_result(env: &str, rows: usize) -> CommandResultV1 {
    CommandResultV1::succeeded(CommandName::Status)
        .resource("environment", env)
        .counts(None, Some(rows))
}

/// One `status` line per failing or warning health check (#1057).
pub(crate) fn health_check_lines(checks: &[tenkai::instance_health::HealthCheck]) -> Vec<String> {
    checks
        .iter()
        .filter(|check| check.state >= tenkai::instance_health::HealthCheckState::Warning)
        .map(|check| {
            if check.message.is_empty() {
                format!("  health {}: {}", check.name, check.state.as_str())
            } else {
                format!(
                    "  health {}: {}: {}",
                    check.name,
                    check.state.as_str(),
                    check.message
                )
            }
        })
        .collect()
}

/// The status line of a workload certificate near expiry (ADR 0046 §3),
/// naming its expiry and why renewal has not cleared it.
pub(crate) fn certificate_line(
    certificate: &tenkai::certificate_reports::CertificateStatus,
) -> Option<String> {
    if !certificate.near_expiry {
        return None;
    }
    let reason = certificate.renewal_failure.as_deref().map_or_else(
        || "not renewed yet".to_owned(),
        |reason| format!("renewal failed: {reason}"),
    );
    Some(format!(
        "  certificate near expiry, expires {}: {reason}",
        format_attempt_time(certificate.expires_at.saturating_mul(1000))
    ))
}

pub(crate) fn print_spec_drift(drift: &tenkai::spec_drift::SpecDriftView) {
    if drift.status == tenkai::spec_drift::SPEC_DRIFT_UNKNOWN {
        return;
    }
    if drift.objects.is_empty() {
        println!("  spec {}", drift.status);
        return;
    }
    for object in &drift.objects {
        if object.status == tenkai::spec_drift::SPEC_DRIFT_CURRENT {
            continue;
        }
        if object.fields.is_empty() {
            println!("  {} {} {}", object.kind, object.name, object.status);
        } else {
            println!(
                "  {} {} {}: {}",
                object.kind,
                object.name,
                object.status,
                object.fields.join(", ")
            );
        }
    }
}

/// One `status` line for an environment's identity issuer (ADR 0046 §2).
pub(crate) fn issuer_line(
    env: &str,
    issuer: &tenkai::identity_issuer::IssuerStatus,
    waiting: &[String],
) -> String {
    let mut line = match &issuer.current {
        Some(current) if current.recipients.is_empty() => format!(
            "{env} identity issuer generation {} {} has no recipient left; prepare a new one",
            current.generation, current.fingerprint
        ),
        Some(current) => format!(
            "{env} identity issuer generation {} {}",
            current.generation, current.fingerprint
        ),
        None => format!("{env} has no identity issuer"),
    };
    match (&issuer.candidate, issuer.requested) {
        (Some(candidate), _) => line.push_str(&format!(
            "; candidate generation {} {} awaits an approved plan",
            candidate.generation, candidate.fingerprint
        )),
        (None, Some(generation)) => line.push_str(&format!(
            "; candidate generation {generation} awaits a runtime that names workload_identity"
        )),
        (None, None) => {}
    }
    if let Some(next) = &issuer.next {
        line.push_str(&format!(
            "; next generation {} {} is trusted and awaits an approved issue step",
            next.generation, next.fingerprint
        ));
    }
    if let Some(previous) = &issuer.previous {
        line.push_str(&format!(
            "; previous generation {} {} is still trusted and awaits an approved remove step",
            previous.generation, previous.fingerprint
        ));
    }
    if !waiting.is_empty() {
        line.push_str(&format!("; that step waits for {}", waiting.join(", ")));
    }
    line
}

pub(crate) fn inspect_result(report: &plan::EnvironmentInspectReport) -> CommandResultV1 {
    CommandResultV1::succeeded(CommandName::InspectEnvironment)
        .resource("environment", &report.id)
        .counts(None, Some(report.subscriptions.len()))
}

pub(crate) fn print_history_page(page: &tenkai::deployment_history::DeploymentHistoryPage) {
    if page.items.is_empty() {
        println!("no deployment attempts recorded");
        return;
    }
    println!(
        "{:<24} {:<16} {:<8} {:<8} {:<10} {:<12} {:<28} summary",
        "time", "instance", "from", "to", "action", "status", "plan"
    );
    for item in &page.items {
        let summary = item
            .cause
            .as_ref()
            .map(|cause| cause.summary.as_str())
            .filter(|summary| !summary.is_empty())
            .unwrap_or(item.detail.as_str());
        println!(
            "{:<24} {:<16} {:<8} {:<8} {:<10} {:<12} {:<28} {}",
            format_attempt_time(item.created_at),
            item.instance,
            item.from_version.as_deref().unwrap_or("none"),
            item.to_version,
            item.action.as_deref().unwrap_or("-"),
            item.status,
            item.plan_id.as_deref().unwrap_or("-"),
            summary
        );
    }
    if let Some(cursor) = &page.next_cursor {
        println!("next: --cursor {cursor}");
    }
}

fn format_attempt_time(millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(millis)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| millis.to_string())
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
            (CommandName::HistoryEnvironment, "environment"),
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
