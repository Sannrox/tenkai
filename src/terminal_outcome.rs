//! Pure classification of terminal delivery observations.

use crate::plan::Action;
use crate::providers::TerminalOutcomeState;

const RUNTIME_SKIPPED_DETAIL: &str = "not executed after an earlier step failed";
const CANCELLATION_PREFIXES: [&str; 2] = [
    "deployment command interrupted",
    "deployment command terminated",
];

/// Source facts that can prove a terminal delivery outcome.
///
/// Controller and runtime observations remain distinct because runtime receipts
/// do not encode automatic rollback or cancellation semantics.
pub(crate) enum Observation<'a> {
    Controller {
        status: &'a str,
        detail: &'a str,
        had_previous_release: bool,
    },
    Runtime {
        succeeded: bool,
        detail: &'a str,
    },
}

/// Classify the terminal evidence proved by one execution observation.
///
/// `None` means the observation is non-terminal or intentionally skipped.
pub(crate) fn classify(
    action: Action,
    observation: Observation<'_>,
) -> Option<TerminalOutcomeState> {
    match observation {
        Observation::Controller {
            status,
            detail,
            had_previous_release,
        } => classify_controller(action, status, detail, had_previous_release),
        Observation::Runtime { succeeded, detail } => classify_runtime(action, succeeded, detail),
    }
}

fn classify_controller(
    action: Action,
    status: &str,
    detail: &str,
    had_previous_release: bool,
) -> Option<TerminalOutcomeState> {
    if status == "failed"
        && CANCELLATION_PREFIXES
            .iter()
            .any(|marker| detail.starts_with(marker))
    {
        return Some(TerminalOutcomeState::ExecutionCancelled);
    }
    match (action, status) {
        (Action::Rollback, "succeeded") => Some(TerminalOutcomeState::RollbackSucceeded),
        (_, "succeeded") => Some(TerminalOutcomeState::DeploymentSucceeded),
        (_, "rolled_back") => Some(TerminalOutcomeState::AutomaticRollbackSucceeded),
        (Action::Rollback, "failed") => Some(TerminalOutcomeState::RollbackFailed),
        (_, "failed") if had_previous_release => Some(TerminalOutcomeState::RollbackFailed),
        (_, "failed") => Some(TerminalOutcomeState::DeploymentFailed),
        _ => None,
    }
}

fn classify_runtime(action: Action, succeeded: bool, detail: &str) -> Option<TerminalOutcomeState> {
    if detail == RUNTIME_SKIPPED_DETAIL {
        return None;
    }
    Some(match (action, succeeded) {
        (Action::Rollback, true) => TerminalOutcomeState::RollbackSucceeded,
        (_, true) => TerminalOutcomeState::DeploymentSucceeded,
        (Action::Rollback, false) => TerminalOutcomeState::RollbackFailed,
        (_, false) => TerminalOutcomeState::DeploymentFailed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_classification_preserves_terminal_semantics() {
        let cases = [
            (
                Action::Upgrade,
                "succeeded",
                "",
                true,
                Some(TerminalOutcomeState::DeploymentSucceeded),
            ),
            (
                Action::Install,
                "failed",
                "",
                false,
                Some(TerminalOutcomeState::DeploymentFailed),
            ),
            (
                Action::Upgrade,
                "rolled_back",
                "",
                true,
                Some(TerminalOutcomeState::AutomaticRollbackSucceeded),
            ),
            (
                Action::Rollback,
                "succeeded",
                "",
                true,
                Some(TerminalOutcomeState::RollbackSucceeded),
            ),
            (
                Action::Rollback,
                "failed",
                "",
                true,
                Some(TerminalOutcomeState::RollbackFailed),
            ),
            (
                Action::Upgrade,
                "failed",
                "deployment command interrupted by controller shutdown",
                true,
                Some(TerminalOutcomeState::ExecutionCancelled),
            ),
            (Action::Upgrade, "running", "", true, None),
        ];

        for (action, status, detail, had_previous_release, expected) in cases {
            assert_eq!(
                classify(
                    action,
                    Observation::Controller {
                        status,
                        detail,
                        had_previous_release,
                    }
                ),
                expected
            );
        }
    }

    #[test]
    fn runtime_classification_emits_only_proven_outcomes() {
        assert_eq!(
            classify(
                Action::Upgrade,
                Observation::Runtime {
                    succeeded: false,
                    detail: "executor failed",
                }
            ),
            Some(TerminalOutcomeState::DeploymentFailed)
        );
        assert_eq!(
            classify(
                Action::Rollback,
                Observation::Runtime {
                    succeeded: true,
                    detail: "executor completed successfully",
                }
            ),
            Some(TerminalOutcomeState::RollbackSucceeded)
        );
        assert_eq!(
            classify(
                Action::Rollback,
                Observation::Runtime {
                    succeeded: false,
                    detail: RUNTIME_SKIPPED_DETAIL,
                }
            ),
            None
        );
    }
}
