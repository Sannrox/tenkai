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
            // Each step outcome already left its own observation (#802).
            &[],
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
    let detail = detail.into();
    // A plan-level failure commits no step outcome; it leaves its own
    // observation (#803). The detail is read for cancellation, never stored.
    let reason = if crate::terminal_outcome::is_cancellation(&detail) {
        crate::feedback_observation::Reason::Cancelled
    } else {
        crate::feedback_observation::Reason::PlanFailed
    };
    let observation = plan_observation(
        lease,
        plan,
        None,
        crate::feedback_observation::Operation::PlanFailed,
        "failed",
        reason,
    );
    transition(
        ctx,
        lease,
        plan,
        PlanState::Failed,
        gates_skipped,
        detail,
        &[observation],
    )
    .await
}

/// The observation of a plan-level block or failure under `lease` (#803).
/// `step` is the step that caused it, when one did (a release gate); a
/// plan-wide block or failure names none. One per plan, operation and lease
/// generation, so a retry of the same transition is idempotent and a later
/// attempt is told apart.
pub(super) fn plan_observation(
    lease: &EnvironmentLease,
    plan: &Plan,
    step: Option<&Step>,
    operation: crate::feedback_observation::Operation,
    status: &str,
    reason: crate::feedback_observation::Reason,
) -> crate::feedback_observation::FeedbackObservation {
    let observed_at_ms = crate::now_millis();
    crate::feedback_observation::FeedbackObservation::capture(
        crate::feedback_observation::Capture {
            id: &format!(
                "tenkai:plan:{}:{}:{}",
                plan.id,
                serde_json::to_value(operation)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                lease.generation
            ),
            operation,
            environment: &plan.environment,
            product: step.map_or("", |step| step.product.as_str()),
            plan_id: &plan.id,
            step_id: step.map_or("", |step| step.id.as_str()),
            action: step.map(|step| step.action),
            release_id: step.map_or("", |step| step.release_id.as_str()),
            status,
            reason,
            started_at_ms: None,
            lease_generation: lease.generation,
            observed_at_ms,
            context: crate::feedback_observation::RetryContext {
                takeover: lease.took_over,
                recovery_reason: plan.recalled_recovery_reason.clone(),
                ..Default::default()
            },
        },
    )
}

pub(super) async fn transition(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    state: PlanState,
    gates_skipped: bool,
    detail: impl Into<String>,
    observations: &[crate::feedback_observation::FeedbackObservation],
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
            observations,
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
    observations: &[crate::feedback_observation::FeedbackObservation],
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
            observations,
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
