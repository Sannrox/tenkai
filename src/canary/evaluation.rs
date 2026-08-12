//! Private Canary promotion evaluation.
//!
//! The interface loads pending and complete attempt evidence, verifies
//! outcome↔attempt↔plan↔deployment consistency, then evaluates an active
//! policy. Promotion authorization stays a thin caller of this interface.

use anyhow::{Context as _, Result, bail};

use super::*;

pub fn evaluate(
    active_policy: &ActiveCanaryPolicy,
    outcomes: &[VerifiedCanaryOutcome],
) -> Result<PromotionEvaluation> {
    let policy = &active_policy.policy;
    let policy_digest = active_policy.digest.clone();
    let mut cohort = BTreeMap::new();
    for environment in &policy.cohort {
        let mut matching = outcomes
            .iter()
            .map(VerifiedCanaryOutcome::outcome)
            .filter(|outcome| {
                outcome.environment == *environment
                    && outcome.release_id == policy.release_id
                    && outcome.policy_digest == policy_digest
                    && outcome.policy_activated_at == active_policy.activated_at
            })
            .cloned()
            .collect::<Vec<_>>();
        matching.sort();
        matching.dedup();
        let result = if matching.is_empty() {
            CohortResult::Missing
        } else if matching
            .iter()
            .all(|outcome| outcome.passes(policy, &policy_digest))
        {
            CohortResult::Passed { outcomes: matching }
        } else {
            CohortResult::Failed { outcomes: matching }
        };
        cohort.insert(environment.clone(), result);
    }
    let allowed = match policy.success_policy {
        SuccessPolicy::All => cohort
            .values()
            .all(|result| matches!(result, CohortResult::Passed { .. })),
    };
    Ok(PromotionEvaluation {
        policy_digest,
        policy_activated_at: active_policy.activated_at,
        allowed,
        cohort,
    })
}

pub async fn evaluate_active(
    ctx: &mut Ctx,
    active: &ActiveCanaryPolicy,
) -> Result<PromotionEvaluation> {
    for status in ["ready", "pending"] {
        for attempt in ctx
            .find_by_property(KIND_CANARY_ATTEMPT, "status", status)
            .await?
        {
            let snapshot: CanaryAttemptSnapshot =
                serde_json::from_str(object_property(&attempt, "policies")?)?;
            if snapshot.policies.iter().any(|policy| {
                policy.digest == active.digest && policy.activated_at == active.activated_at
            }) {
                bail!(
                    "canary attempt {} is {status}; finish or repair it before promotion",
                    attempt.id
                );
            }
        }
    }
    let mut terminal_failures = BTreeMap::<String, Vec<CanaryOutcome>>::new();
    for attempt in ctx
        .find_by_property(KIND_CANARY_ATTEMPT, "status", "complete")
        .await?
    {
        let snapshot: CanaryAttemptSnapshot =
            serde_json::from_str(object_property(&attempt, "policies")?)?;
        if !snapshot.policies.iter().any(|policy| {
            policy.digest == active.digest && policy.activated_at == active.activated_at
        }) {
            continue;
        }
        let plan_state = match object_property(&attempt, "plan_state")? {
            "succeeded" => continue,
            "failed" => EvidencePlanState::Failed,
            "blocked" => EvidencePlanState::Blocked,
            state => bail!(
                "canary attempt {} has invalid terminal state {state}",
                attempt.id
            ),
        };
        let plan_id = object_property(&attempt, "plan_id")?;
        let plan = crate::plan::load(ctx, plan_id).await?;
        let step_order = plan
            .steps
            .iter()
            .find(|step| evidence_release(step) == Some(active.policy.release_id.as_str()))
            .with_context(|| {
                format!(
                    "canary attempt {} has no step for {}",
                    attempt.id, active.policy.release_id
                )
            })?
            .order;
        let gates_skipped = object_property(&attempt, "gates_skipped")?
            .parse::<bool>()
            .with_context(|| format!("canary attempt {} has invalid gate state", attempt.id))?;
        let execution = if plan_state == EvidencePlanState::Blocked {
            ExecutionOutcome::Blocked
        } else {
            ExecutionOutcome::Failed
        };
        terminal_failures
            .entry(plan.environment.clone())
            .or_default()
            .push(CanaryOutcome {
                release_id: active.policy.release_id.clone(),
                release_digest: active.policy.release_digest.clone(),
                artifact_digest: active.policy.artifact_digest.clone(),
                policy_digest: active.digest.clone(),
                policy_activated_at: active.activated_at,
                environment: plan.environment,
                plan_id: plan.id,
                attempt_id: attempt.id.clone(),
                step_order,
                plan_state,
                deployment_id: None,
                executed_at: attempt.created,
                recorded_at: attempt.updated.max(attempt.created),
                gate: if gates_skipped {
                    GateOutcome::Skipped
                } else {
                    GateOutcome::Satisfied
                },
                execution,
                health: HealthOutcome::FailedOrUnknown,
                rollback: RollbackOutcome::FailedOrUnknown,
                detail: attempt
                    .properties
                    .get("status_detail")
                    .filter(|detail| !detail.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "canary apply did not complete successfully".into()),
            });
    }
    let objects = ctx
        .find_by_property(KIND_CANARY_OUTCOME, "policy_digest", &active.digest)
        .await?;
    let mut verified = Vec::new();
    for object in objects {
        let outcome: CanaryOutcome = serde_json::from_str(object_property(&object, "outcome")?)?;
        if outcome.policy_activated_at != active.activated_at {
            continue;
        }
        let indexed_step_order = object_property(&object, "step_order")?
            .parse::<u32>()
            .with_context(|| format!("canary outcome {} has invalid step order", object.id))?;
        if indexed_step_order != outcome.step_order {
            bail!(
                "canary outcome {} step index does not match its evidence",
                object.id
            );
        }
        let attempt = ctx
            .get(&outcome.attempt_id)
            .await?
            .with_context(|| format!("canary attempt {} not found", outcome.attempt_id))?;
        if attempt.kind != KIND_CANARY_ATTEMPT
            || object_property(&attempt, "status")? != "complete"
            || object_property(&attempt, "plan_id")? != outcome.plan_id
            || object_property(&attempt, "plan_state")?
                != match outcome.plan_state {
                    EvidencePlanState::Succeeded => "succeeded",
                    EvidencePlanState::Failed => "failed",
                    EvidencePlanState::Blocked => "blocked",
                }
        {
            bail!(
                "canary outcome references inconsistent attempt {}",
                outcome.attempt_id
            );
        }
        let gates_skipped = object_property(&attempt, "gates_skipped")?
            .parse::<bool>()
            .with_context(|| format!("canary attempt {} has invalid gate state", attempt.id))?;
        if gates_skipped != (outcome.gate == GateOutcome::Skipped) {
            bail!(
                "canary outcome gate state does not match attempt {}",
                attempt.id
            );
        }
        let attempt_evidence = CanaryAttemptEvidence {
            id: attempt.id.clone(),
            plan_id: object_property(&attempt, "plan_id")?.into(),
            plan_state: outcome.plan_state,
            gates_skipped,
            started_at: object_property(&attempt, "execution_started_at")?
                .parse::<i64>()
                .with_context(|| format!("canary attempt {} has invalid start time", attempt.id))?,
            finished_at: object_property(&attempt, "finished_at")?
                .parse::<i64>()
                .with_context(|| {
                    format!("canary attempt {} has invalid finish time", attempt.id)
                })?,
        };
        let plan = crate::plan::load(ctx, &outcome.plan_id).await?;
        let deployment = match outcome.deployment_id.as_deref() {
            Some(id) => ctx.get(id).await?,
            None => None,
        };
        let links_to_plan = match deployment.as_ref() {
            Some(deployment) => ctx
                .links(&deployment.id, REL_PART_OF_PLAN)
                .await?
                .iter()
                .any(|link| link.to_id == plan.id),
            None => false,
        };
        verified.push(VerifiedCanaryOutcome::verify(
            outcome,
            &plan,
            &attempt_evidence,
            deployment.as_ref(),
            links_to_plan,
            active,
        )?);
    }
    let mut evaluation = evaluate(active, &verified)?;
    for (environment, mut failures) in terminal_failures {
        let Some(result) = evaluation.cohort.get_mut(&environment) else {
            continue;
        };
        let mut outcomes = match std::mem::replace(result, CohortResult::Missing) {
            CohortResult::Passed { outcomes } | CohortResult::Failed { outcomes } => outcomes,
            CohortResult::Missing => Vec::new(),
        };
        outcomes.append(&mut failures);
        outcomes.sort();
        outcomes.dedup();
        *result = CohortResult::Failed { outcomes };
        evaluation.allowed = false;
    }
    Ok(evaluation)
}
