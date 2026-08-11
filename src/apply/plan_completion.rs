//! Terminal classification and durable completion for one Plan execution.

use super::*;

/// Accumulates Step outcomes and hides their terminal Plan classification.
pub(super) struct ExecutionCompletion {
    outcomes: Vec<Outcome>,
    terminal_state: PlanState,
    detail: String,
}

impl ExecutionCompletion {
    pub(super) fn new() -> Self {
        Self {
            outcomes: Vec::new(),
            terminal_state: PlanState::Succeeded,
            detail: String::new(),
        }
    }

    /// Record one Step result and return whether Plan execution must stop.
    pub(super) fn record(&mut self, outcome: Outcome) -> Result<bool> {
        self.terminal_state = outcome.plan_state()?;
        if self.terminal_state != PlanState::Succeeded {
            self.detail = outcome.detail.clone();
        }
        self.outcomes.push(outcome);
        Ok(self.terminal_state != PlanState::Succeeded)
    }

    /// Persist the terminal state and return the collected Step outcomes.
    pub(super) async fn finish(
        self,
        ctx: &mut Ctx,
        lease: &EnvironmentLease,
        plan: &mut Plan,
        gates_skipped: bool,
    ) -> Result<Vec<Outcome>> {
        transition_confirmed(
            ctx,
            lease,
            plan,
            self.terminal_state,
            gates_skipped,
            self.detail,
        )
        .await?;
        Ok(self.outcomes)
    }
}

/// Record an execution error before returning it to the caller.
///
/// Persistence errors retain precedence because callers cannot safely report a
/// failed Plan transition that may not have become durable.
pub(super) async fn fail(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    gates_skipped: bool,
    detail: impl Into<String>,
) -> Result<()> {
    transition(ctx, lease, plan, PlanState::Failed, gates_skipped, detail).await
}

pub(super) async fn transition(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    state: PlanState,
    gates_skipped: bool,
    detail: impl Into<String>,
) -> Result<()> {
    plan::transition(
        ctx,
        plan,
        plan::Transition::execution(state, gates_skipped, detail),
        plan::Persistence::Guarded {
            namespace: ENVIRONMENT_LEASE_NAMESPACE,
            key: &lease.environment,
            fencing_token: &lease.fencing_token,
            confirm_ambiguous: false,
        },
    )
    .await
}

/// Confirm an ambiguous write by reading the exact intended terminal state.
pub(super) async fn transition_confirmed(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    state: PlanState,
    gates_skipped: bool,
    detail: impl Into<String>,
) -> Result<()> {
    plan::transition(
        ctx,
        plan,
        plan::Transition::execution(state, gates_skipped, detail),
        plan::Persistence::Guarded {
            namespace: ENVIRONMENT_LEASE_NAMESPACE,
            key: &lease.environment,
            fencing_token: &lease.fencing_token,
            confirm_ambiguous: true,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(status: StepOutcomeStatus, detail: &str) -> Outcome {
        Outcome::new(
            Step {
                id: "step-1".into(),
                order: 0,
                product: "api".into(),
                action: Action::Install,
                from: None,
                to: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "sha256:release".into(),
                artifact_digest: "sha256:artifact".into(),
                workdir: ".".into(),
                restore: None,
            },
            status,
            detail,
        )
    }

    #[test]
    fn completion_stops_on_blocked_and_preserves_detail() {
        let mut completion = ExecutionCompletion::new();

        assert!(
            !completion
                .record(outcome(StepOutcomeStatus::Succeeded, ""))
                .unwrap()
        );
        assert!(
            completion
                .record(outcome(StepOutcomeStatus::Blocked, "gate denied"))
                .unwrap()
        );
        assert_eq!(completion.terminal_state, PlanState::Blocked);
        assert_eq!(completion.detail, "gate denied");
        assert_eq!(completion.outcomes.len(), 2);
    }

    #[test]
    fn completion_treats_non_success_as_failure() {
        let mut completion = ExecutionCompletion::new();

        assert!(
            completion
                .record(outcome(StepOutcomeStatus::RolledBack, "activation failed"))
                .unwrap()
        );
        assert_eq!(completion.terminal_state, PlanState::Failed);
        assert_eq!(completion.detail, "activation failed");
    }
}
