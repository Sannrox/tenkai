//! Pure classification of terminal delivery observations.

use crate::plan::Action;
use crate::providers::TerminalOutcomeState;

const RUNTIME_SKIPPED_DETAIL: &str = "not executed after an earlier step failed";
const CANCELLATION_PREFIXES: [&str; 2] = [
    "deployment command interrupted",
    "deployment command terminated",
];

/// Whether a controller detail records a cancelled deployment command.
pub(crate) fn is_cancellation(detail: &str) -> bool {
    CANCELLATION_PREFIXES
        .iter()
        .any(|marker| detail.starts_with(marker))
}

/// Classify the terminal evidence proved by one runtime receipt. Runtime
/// receipts do not encode automatic rollback or cancellation semantics.
///
/// `None` means the step was intentionally skipped.
pub(crate) fn classify_runtime(
    action: Action,
    succeeded: bool,
    detail: &str,
) -> Option<TerminalOutcomeState> {
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
    fn runtime_classification_emits_only_proven_outcomes() {
        assert_eq!(
            classify_runtime(Action::Upgrade, false, "executor failed"),
            Some(TerminalOutcomeState::DeploymentFailed)
        );
        assert_eq!(
            classify_runtime(Action::Rollback, true, "executor completed successfully"),
            Some(TerminalOutcomeState::RollbackSucceeded)
        );
        assert_eq!(
            classify_runtime(Action::Rollback, false, RUNTIME_SKIPPED_DETAIL),
            None
        );
    }
}
