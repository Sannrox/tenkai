//! Closed Step outcome vocabulary and caller-facing lifecycle classification.

use crate::plan::{PlanState, Step};

/// Durable status of one Plan Step execution.
///
/// Serialized spellings are part of the existing command and persistence
/// contracts, so new variants require an explicit compatibility decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcomeStatus {
    Succeeded,
    Blocked,
    Failed,
    RolledBack,
}

impl StepOutcomeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        }
    }

    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "succeeded" => Ok(Self::Succeeded),
            "blocked" => Ok(Self::Blocked),
            "failed" => Ok(Self::Failed),
            "rolled_back" => Ok(Self::RolledBack),
            other => anyhow::bail!("unknown persisted Step outcome status {other:?}"),
        }
    }

    pub(crate) fn plan_state(self) -> PlanState {
        match self {
            Self::Succeeded => PlanState::Succeeded,
            Self::Blocked => PlanState::Blocked,
            Self::Failed | Self::RolledBack => PlanState::Failed,
        }
    }

    pub fn is_success(self) -> bool {
        self == Self::Succeeded
    }
}

impl std::fmt::Display for StepOutcomeStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Outcome of one immutable Plan Step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Outcome {
    pub step: Step,
    pub status: String,
    pub detail: String,
}

impl Outcome {
    pub fn new(step: Step, status: StepOutcomeStatus, detail: impl Into<String>) -> Self {
        Self {
            step,
            status: status.as_str().into(),
            detail: detail.into(),
        }
    }

    pub fn classified_status(&self) -> anyhow::Result<StepOutcomeStatus> {
        StepOutcomeStatus::parse(&self.status)
    }

    pub(crate) fn plan_state(&self) -> anyhow::Result<PlanState> {
        Ok(self.classified_status()?.plan_state())
    }

    pub(crate) fn is_gate_blocked(&self) -> anyhow::Result<bool> {
        Ok(self.classified_status()? == StepOutcomeStatus::Blocked
            && self.detail.starts_with("gate "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step() -> Step {
        Step {
            id: "step-1".into(),
            order: 0,
            product: "api".into(),
            action: crate::plan::Action::Install,
            from: None,
            to: "1.0.0".into(),
            release_id: "tenkai:release:api@1.0.0".into(),
            release_digest: "sha256:release".into(),
            artifact_digest: "sha256:artifact".into(),
            workdir: ".".into(),
            restore: None,
        }
    }

    #[test]
    fn status_serialization_preserves_the_existing_contract() {
        assert_eq!(
            serde_json::to_string(&StepOutcomeStatus::RolledBack).unwrap(),
            "\"rolled_back\""
        );
        assert_eq!(
            serde_json::from_str::<StepOutcomeStatus>("\"blocked\"").unwrap(),
            StepOutcomeStatus::Blocked
        );
    }

    #[test]
    fn unknown_persisted_status_fails_closed() {
        assert!(StepOutcomeStatus::parse("unknown").is_err());
    }

    #[test]
    fn public_string_field_remains_compatible_but_classification_fails_closed() {
        let outcome = Outcome {
            step: step(),
            status: "future_status".into(),
            detail: String::new(),
        };

        assert!(outcome.classified_status().is_err());
    }
}
