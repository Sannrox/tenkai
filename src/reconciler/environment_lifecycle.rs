//! Reconcile one Environment from Plan selection through execution outcome.

use std::path::Path;

use anyhow::{Result, bail};

use crate::apply;
use crate::client::Ctx;
use crate::plan::{self, Plan, PlanState};

use super::EnvironmentStatus;

pub(super) struct Policy<'a> {
    pub(super) skip_gates: bool,
    pub(super) unapproved_development_reason: Option<&'a str>,
    pub(super) approval_directory: Option<&'a Path>,
    pub(super) approval_trust_roots: Option<&'a Path>,
}

pub(super) struct Request<'a> {
    pub(super) environment: &'a str,
    pub(super) runtime_managed: bool,
    pub(super) policy: Policy<'a>,
}

/// Advance one Environment through recovery, Plan selection, authorization,
/// and execution while keeping tick scheduling and shared fencing outside.
pub(super) async fn reconcile(ctx: &mut Ctx, request: Request<'_>) -> Result<EnvironmentStatus> {
    if request.runtime_managed {
        return reconcile_runtime_managed(ctx, request.environment).await;
    }
    if recover_or_detect_active_plan(ctx, request.environment).await? {
        return Ok(EnvironmentStatus::Busy);
    }

    let approval_required = request.policy.unapproved_development_reason.is_none()
        || request.environment != "local"
        || !ctx.is_embedded();
    let stored = select_plan(ctx, request.environment, approval_required).await?;
    if stored.steps.is_empty() {
        return Ok(EnvironmentStatus::Current);
    }
    execute(ctx, request, stored, approval_required).await
}

async fn reconcile_runtime_managed(ctx: &mut Ctx, environment: &str) -> Result<EnvironmentStatus> {
    if let Some(plan) =
        plan::oldest_for_environment(ctx, environment, &[PlanState::Computed, PlanState::Running])
            .await?
    {
        return Ok(awaiting_runtime(plan));
    }
    let stored = plan::create(ctx, environment).await?;
    if stored.steps.is_empty() {
        Ok(EnvironmentStatus::Current)
    } else {
        Ok(awaiting_runtime(stored))
    }
}

fn awaiting_runtime(plan: Plan) -> EnvironmentStatus {
    EnvironmentStatus::AwaitingRuntime {
        plan_id: plan.id,
        steps: plan.steps.len(),
    }
}

async fn select_plan(ctx: &mut Ctx, environment: &str, approval_required: bool) -> Result<Plan> {
    if !approval_required {
        return plan::create(ctx, environment).await;
    }
    for candidate in
        plan::list_for_environment(ctx, environment, Some(&[PlanState::Computed])).await?
    {
        if !candidate.steps.is_empty()
            && apply::classify_candidate(ctx, &candidate).await?
                == apply::CandidateAdmission::Admissible
        {
            return Ok(candidate);
        }
    }
    plan::create(ctx, environment).await
}

async fn execute(
    ctx: &mut Ctx,
    request: Request<'_>,
    stored: Plan,
    approval_required: bool,
) -> Result<EnvironmentStatus> {
    let plan_id = stored.id;
    let steps = stored.steps.len();
    if approval_required {
        let (Some(directory), Some(roots)) = (
            request.policy.approval_directory,
            request.policy.approval_trust_roots,
        ) else {
            return Ok(EnvironmentStatus::AwaitingApproval { plan_id, steps });
        };
        let envelope = directory.join(format!("{plan_id}.json"));
        if !envelope.is_file() {
            return Ok(EnvironmentStatus::AwaitingApproval { plan_id, steps });
        }
        return execute_authorized(
            ctx,
            request.environment,
            &plan_id,
            steps,
            request.policy.skip_gates,
            apply::ExecutionAuthorization::Signed {
                approval: &envelope,
                trust_roots: roots,
            },
        )
        .await;
    }
    let reason = request
        .policy
        .unapproved_development_reason
        .expect("authorization was classified as an embedded local-development bypass");
    execute_authorized(
        ctx,
        request.environment,
        &plan_id,
        steps,
        request.policy.skip_gates,
        apply::ExecutionAuthorization::LocalDevelopment { reason },
    )
    .await
}

async fn execute_authorized(
    ctx: &mut Ctx,
    environment: &str,
    plan_id: &str,
    steps: usize,
    skip_gates: bool,
    authorization: apply::ExecutionAuthorization<'_>,
) -> Result<EnvironmentStatus> {
    let outcomes = apply::execute_with_options(
        ctx,
        plan_id,
        apply::ExecutionOptions {
            skip_gates,
            emergency_reason: None,
            authorization,
        },
    )
    .await?;
    if let Some(failed) = outcomes
        .iter()
        .find(|outcome| outcome.status != "succeeded")
    {
        bail!(
            "environment {} failed while reconciling {}: {}",
            environment,
            failed.step.product,
            failed.detail
        );
    }
    Ok(EnvironmentStatus::Applied {
        plan_id: plan_id.into(),
        steps,
    })
}

/// Deterministically terminate Plans orphaned by a stopped controller. An
/// active generation-fenced lease proves another process still owns the Environment.
async fn recover_or_detect_active_plan(ctx: &mut Ctx, environment: &str) -> Result<bool> {
    let running = plan::list_for_environment(ctx, environment, Some(&[PlanState::Running])).await?;
    if running.is_empty() {
        return Ok(false);
    }
    if apply::environment_lease_status(ctx, environment)
        .await?
        .is_some()
    {
        return Ok(true);
    }
    for mut abandoned in running {
        plan::transition(
            ctx,
            &mut abandoned,
            plan::Transition::new(
                PlanState::Failed,
                "controller stopped after execution began; lease expired before recovery",
            ),
            plan::Persistence::Standard,
        )
        .await?;
    }
    Ok(false)
}
