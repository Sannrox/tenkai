//! Authorization, admission, execution, and finalization of one Plan attempt.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, bail};

use super::*;

/// The one authorization mode admitted for a Plan execution attempt.
#[derive(Debug, Clone, Copy)]
pub enum ExecutionAuthorization<'a> {
    /// Verify signed approval evidence against the supplied trust roots.
    Signed {
        approval: &'a Path,
        trust_roots: &'a Path,
    },
    /// Record an explicit embedded-only development bypass.
    LocalDevelopment { reason: &'a str },
}

/// Policy supplied to one Plan execution attempt.
#[derive(Clone)]
pub struct ExecutionOptions<'a> {
    pub skip_gates: bool,
    pub emergency_reason: Option<&'a str>,
    pub authorization: ExecutionAuthorization<'a>,
    /// Host-selected software adapter. `None` keeps the shell install path.
    pub software_executor: Option<Arc<dyn crate::software_executor::SoftwareExecutor>>,
}

impl std::fmt::Debug for ExecutionOptions<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionOptions")
            .field("skip_gates", &self.skip_gates)
            .field("emergency_reason", &self.emergency_reason)
            .field("authorization", &self.authorization)
            .field("software_executor", &self.software_executor.is_some())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub(super) struct AttemptExecutionPolicy<'a> {
    pub skip_gates: bool,
    pub emergency_reason: Option<&'a str>,
    pub software_executor: Option<&'a dyn crate::software_executor::SoftwareExecutor>,
}

/// Compatibility entry point retained so downstream crates receive an
/// actionable authorization error instead of a compile failure.
#[deprecated(note = "use execute_with_options with explicit plan approval")]
pub async fn execute(_ctx: &mut Ctx, _plan_id: &str, _skip_gates: bool) -> Result<Vec<Outcome>> {
    bail!(
        "plan execution now requires explicit approval; use execute_with_options with signed approval or a recorded local-development bypass"
    )
}

/// Execute one stored Plan attempt after explicit authorization.
pub async fn execute_with_options(
    ctx: &mut Ctx,
    plan_id: &str,
    options: ExecutionOptions<'_>,
) -> Result<Vec<Outcome>> {
    let emergency_reason = start_admission::validate_emergency_override(options.emergency_reason)?;
    let mut stored_plan = plan::load(ctx, plan_id).await?;
    if !matches!(stored_plan.state, PlanState::Computed | PlanState::Blocked) {
        bail!(
            "plan {} is {}, only computed or blocked plans can be applied",
            stored_plan.id,
            stored_plan.state
        );
    }
    let now = crate::now_millis();
    let approval_evidence = match options.authorization {
        ExecutionAuthorization::Signed {
            approval,
            trust_roots,
        } => crate::plan_approval::verify(
            &stored_plan,
            approval,
            trust_roots,
            now,
            options.skip_gates,
        )?,
        ExecutionAuthorization::LocalDevelopment { reason } if ctx.is_embedded() => {
            crate::plan_approval::local_bypass(&stored_plan, reason, now)?
        }
        ExecutionAuthorization::LocalDevelopment { .. } => {
            bail!("unapproved development execution is available only in embedded mode")
        }
    };
    crate::plan_approval::record(ctx, &approval_evidence).await?;

    let environment = stored_plan.environment.clone();
    let owner = stored_plan.id.clone();
    let lease = claim_execution_environment(ctx, &environment, &owner).await?;
    if let Err(error) = start_admission::authorize_maintenance(
        ctx,
        &lease,
        &mut stored_plan,
        options.skip_gates,
        emergency_reason,
    )
    .await
    {
        let unlock = release_environment(ctx, &lease).await;
        return match unlock {
            Ok(()) => Err(error),
            Err(unlock) => Err(error.context(format!(
                "releasing environment apply lease also failed: {unlock}"
            ))),
        };
    }

    let canary_plan = stored_plan.clone();
    let execution_lease = lease.clone();
    let execution_emergency_reason = emergency_reason.map(str::to_string);
    let skip_gates = options.skip_gates;
    let software_executor = options.software_executor;
    let canary_execution =
        crate::canary::execute_attempt(ctx, &canary_plan, options.skip_gates, move |ctx| {
            Box::pin(async move {
                execute_locked(
                    ctx,
                    stored_plan,
                    AttemptExecutionPolicy {
                        skip_gates,
                        emergency_reason: execution_emergency_reason.as_deref(),
                        software_executor: software_executor.as_deref(),
                    },
                    &execution_lease,
                )
                .await
            })
        })
        .await;
    let result = canary_execution.execution;
    let canary_finalization_error = canary_execution.finalization_error;
    let unlock = release_environment(ctx, &lease).await;
    let released_result = match (result, unlock) {
        (Ok(outcomes), Ok(())) => Ok(outcomes),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing environment apply lease also failed: {unlock}; after verifying no apply is running, retry `tenkaictl env unlock {environment}` once the lease expires"
        ))),
        (Ok(_), Err(error)) => Err(error.context(format!(
            "releasing environment apply lease failed; after verifying no apply is running, retry `tenkaictl env unlock {environment}` once the lease expires"
        ))),
    };
    match (released_result, canary_finalization_error) {
        (Ok(outcomes), None) => Ok(outcomes),
        (Ok(_), Some(error)) => Err(error.context(format!(
            "apply completed but canary evidence finalization failed; run `tenkaictl canary repair {plan_id}`"
        ))),
        (Err(error), None) => Err(error),
        (Err(error), Some(finalization)) => Err(error.context(format!(
            "canary evidence finalization also failed: {finalization}"
        ))),
    }
}
