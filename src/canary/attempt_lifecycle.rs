//! Crash-safe Canary attempt execution and repair lifecycle.

use std::future::Future;
use std::pin::Pin;

use super::*;

fn evidence_status(
    plan: &Plan,
    outcome: &Outcome,
    gates_skipped: bool,
) -> (
    GateOutcome,
    ExecutionOutcome,
    HealthOutcome,
    RollbackOutcome,
) {
    let gate = if gates_skipped {
        GateOutcome::Skipped
    } else if outcome.status == "blocked" && outcome.detail.starts_with("gate ") {
        GateOutcome::Blocked
    } else {
        GateOutcome::Satisfied
    };
    if outcome.step.action == Action::Rollback && plan.state == PlanState::Succeeded {
        return (
            gate,
            ExecutionOutcome::Succeeded,
            HealthOutcome::PassedOrNotConfigured,
            RollbackOutcome::Succeeded,
        );
    }
    match outcome.status.as_str() {
        "succeeded" => (
            gate,
            ExecutionOutcome::Succeeded,
            HealthOutcome::PassedOrNotConfigured,
            RollbackOutcome::NotNeeded,
        ),
        "blocked" => (
            gate,
            ExecutionOutcome::Blocked,
            HealthOutcome::NotRun,
            RollbackOutcome::NotNeeded,
        ),
        "rolled_back" => (
            gate,
            ExecutionOutcome::Failed,
            HealthOutcome::FailedOrUnknown,
            RollbackOutcome::Succeeded,
        ),
        _ => (
            gate,
            ExecutionOutcome::Failed,
            HealthOutcome::FailedOrUnknown,
            RollbackOutcome::FailedOrUnknown,
        ),
    }
}

pub(crate) async fn begin_attempt(
    ctx: &mut Ctx,
    plan: &Plan,
    gates_skipped: bool,
) -> Result<Option<String>> {
    let products = plan
        .steps
        .iter()
        .filter(|step| evidence_release(step).is_some())
        .map(|step| step.product.clone())
        .collect::<BTreeSet<_>>();
    let owner = format!("attempt:{}:{}", plan.id, crate::now_millis());
    let mut locks = Vec::new();
    for product in &products {
        match claim_promotion_lock_with_retry(ctx, product, POLICY_DISCOVERY_LOCK_CHANNEL, &owner)
            .await
        {
            Ok(lock) => locks.push(lock),
            Err(error) => {
                for lock in locks.iter().rev() {
                    let _ = release_promotion_lock(ctx, lock).await;
                }
                return Err(error.context("serializing canary policy discovery with apply"));
            }
        }
    }
    let result = async {
        let mut policies = Vec::new();
        let mut seen = BTreeSet::new();
        for step in &plan.steps {
            let Some(release) = evidence_release(step) else {
                continue;
            };
            for active in policies_for_release(ctx, release).await? {
                let identity = (active.digest.clone(), active.activated_at);
                if active.policy.cohort.contains(&plan.environment) && seen.insert(identity) {
                    policies.push(active);
                }
            }
        }
        policies.sort_by(|left, right| {
            (
                &left.policy.release_id,
                &left.policy.target_channel,
                left.activated_at,
            )
                .cmp(&(
                    &right.policy.release_id,
                    &right.policy.target_channel,
                    right.activated_at,
                ))
        });
        let lock_keys = policies
            .iter()
            .map(|active| {
                (
                    active.policy.product.clone(),
                    active.policy.target_channel.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        for (product, target_channel) in lock_keys {
            locks.push(
                claim_promotion_lock_with_retry(ctx, &product, &target_channel, &owner)
                    .await
                    .context("serializing canary attempt with promotion")?,
            );
        }
        if let Some(attempt) = ctx
            .find_by_property(KIND_CANARY_ATTEMPT, "plan_id", &plan.id)
            .await?
            .into_iter()
            .find(|attempt| {
                attempt.properties.get("status").map(String::as_str) == Some("pending")
            })
        {
            bail!(
                "plan {} already has pending canary attempt {}; repair or recover it before retrying",
                plan.id,
                attempt.id
            );
        }
        for active in &policies {
            confirm_policy_active(ctx, active).await?;
        }
        if policies.is_empty() {
            Ok(None)
        } else {
            persist_attempt(ctx, plan, gates_skipped, policies).await
        }
    }
    .await;
    let mut unlock_error = None;
    for lock in locks.iter().rev() {
        if let Err(error) = release_promotion_lock(ctx, lock).await {
            unlock_error.get_or_insert(error);
        }
    }
    match (result, unlock_error) {
        (Ok(attempt), None) => Ok(attempt),
        (Err(error), None) => Err(error),
        (Err(error), Some(unlock)) => {
            Err(error.context(format!("releasing promotion locks also failed: {unlock}")))
        }
        (Ok(_), Some(error)) => Err(error.context("releasing promotion locks failed")),
    }
}

pub(crate) async fn mark_attempt_started(ctx: &mut Ctx, attempt_id: &str) -> Result<()> {
    let mut attempt = ctx
        .get(attempt_id)
        .await?
        .with_context(|| format!("canary attempt {attempt_id} not found"))?;
    if object_property(&attempt, "status")? != "pending" {
        bail!("canary attempt {attempt_id} is not pending");
    }
    let plan_id = object_property(&attempt, "plan_id")?.to_string();
    let started_at = crate::now_millis().max(attempt.created);
    attempt
        .properties
        .insert("execution_started_at".into(), started_at.to_string());
    attempt.updated = started_at;
    match ctx.put(attempt).await {
        Ok(_) => Ok(()),
        Err(start_error) => {
            let cleanup = async {
                let mut current = ctx
                    .get(attempt_id)
                    .await?
                    .with_context(|| format!("canary attempt {attempt_id} disappeared"))?;
                if object_property(&current, "status")? == "pending" {
                    current
                        .properties
                        .insert("status".into(), "abandoned".into());
                    current.updated = crate::now_millis().max(current.created);
                    ctx.put(current).await?;
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            match cleanup {
                Ok(()) => Err(start_error.context("abandoned canary attempt after start failed")),
                Err(cleanup_error) => Err(start_error.context(format!(
                    "abandoning canary attempt also failed: {cleanup_error}; run `tenkaictl canary repair {plan_id}`"
                ))),
            }
        }
    }
}

async fn persist_attempt(
    ctx: &mut Ctx,
    plan: &Plan,
    gates_skipped: bool,
    policies: Vec<ActiveCanaryPolicy>,
) -> Result<Option<String>> {
    let snapshot = CanaryAttemptSnapshot { policies };
    let started_at = snapshot
        .policies
        .iter()
        .map(|policy| policy.activated_at)
        .max()
        .unwrap_or_default()
        .max(crate::now_millis());
    let serialized = serde_json::to_string(&snapshot)?;
    for sequence in 0..1024_u16 {
        let id = format!("{}:canary-attempt:{sequence}", plan.id);
        let object = Object {
            id: id.clone(),
            kind: KIND_CANARY_ATTEMPT.into(),
            name: format!("{} canary attempt", plan.environment),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("plan_id".into(), plan.id.clone()),
                ("initial_plan_state".into(), plan.state.to_string()),
                ("gates_skipped".into(), gates_skipped.to_string()),
                ("status".into(), "pending".into()),
                ("policies".into(), serialized.clone()),
            ]),
            created: started_at,
            updated: started_at,
        };
        match ctx.create_once(object).await {
            Ok(_) => return Ok(Some(id)),
            Err(status)
                if status.code() == tonic::Code::AlreadyExists
                    || (status.code() == tonic::Code::Internal
                        && status.message().contains("UNIQUE")) => {}
            Err(status) => return Err(status.into()),
        }
    }
    bail!("could not allocate canary attempt for plan {}", plan.id)
}

fn reconstructed_outcomes(plan: &Plan, deployments: &[Object]) -> Vec<Outcome> {
    plan.steps
        .iter()
        .filter_map(|step| {
            let deployment = deployments
                .iter()
                .filter(|deployment| {
                    deployment.properties.get("step_id") == Some(&step.id)
                        || (!deployment.properties.contains_key("step_id")
                            && deployment.properties.get("product") == Some(&step.product)
                            && deployment.properties.get("to_version") == Some(&step.to))
                })
                .max_by_key(|deployment| deployment.created);
            deployment.map(|deployment| Outcome {
                step: step.clone(),
                status: deployment
                    .properties
                    .get("status")
                    .cloned()
                    .unwrap_or_else(|| "failed".into()),
                detail: deployment
                    .properties
                    .get("detail")
                    .cloned()
                    .unwrap_or_else(|| plan.status_detail.clone()),
            })
        })
        .collect()
}

pub(crate) async fn finish_attempt(
    ctx: &mut Ctx,
    plan_id: &str,
    attempt_id: &str,
    abandon_nonterminal: bool,
    completed_outcomes: Option<&[Outcome]>,
) -> Result<()> {
    let attempt = ctx
        .get(attempt_id)
        .await?
        .with_context(|| format!("canary attempt {attempt_id} not found"))?;
    if matches!(
        object_property(&attempt, "status")?,
        "complete" | "abandoned"
    ) {
        return Ok(());
    }
    let snapshot: CanaryAttemptSnapshot =
        serde_json::from_str(object_property(&attempt, "policies")?)?;
    let owner = format!("attempt-finalize:{attempt_id}:{}", crate::now_millis());
    let locks = claim_policy_locks(ctx, &snapshot.policies, &owner).await?;
    let result = finish_attempt_locked(
        ctx,
        plan_id,
        attempt_id,
        abandon_nonterminal,
        completed_outcomes,
    )
    .await;
    let unlock = release_policy_locks(ctx, &locks).await;
    match (result, unlock) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => {
            Err(error.context(format!("releasing promotion locks also failed: {unlock}")))
        }
        (Ok(()), Err(error)) => Err(error.context("releasing promotion locks failed")),
    }
}

pub(crate) struct AttemptExecution {
    pub execution: Result<Vec<Outcome>>,
    pub finalization_error: Option<anyhow::Error>,
}

/// Run the complete Canary attempt lifecycle around one apply execution.
/// Snapshot, start, and terminal evidence ordering are not exposed to callers.
pub(crate) async fn execute_attempt<F>(
    ctx: &mut Ctx,
    plan: &Plan,
    gates_skipped: bool,
    execute: F,
) -> AttemptExecution
where
    F: for<'a> FnOnce(
        &'a mut Ctx,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Outcome>>> + Send + 'a>>,
{
    let attempt_id = match begin_attempt(ctx, plan, gates_skipped).await {
        Ok(attempt_id) => attempt_id,
        Err(error) => {
            return AttemptExecution {
                execution: Err(error.context("snapshotting canary policies before execution")),
                finalization_error: None,
            };
        }
    };
    if let Some(attempt_id) = attempt_id.as_deref()
        && let Err(error) = mark_attempt_started(ctx, attempt_id).await
    {
        return AttemptExecution {
            execution: Err(error.context("marking canary attempt as started")),
            finalization_error: None,
        };
    }
    let execution = execute(ctx).await;
    let finalization_error = match attempt_id.as_deref() {
        Some(attempt_id) => finish_attempt(
            ctx,
            &plan.id,
            attempt_id,
            false,
            execution.as_ref().ok().map(Vec::as_slice),
        )
        .await
        .err(),
        None => None,
    };
    AttemptExecution {
        execution,
        finalization_error,
    }
}

async fn finish_attempt_locked(
    ctx: &mut Ctx,
    plan_id: &str,
    attempt_id: &str,
    abandon_nonterminal: bool,
    completed_outcomes: Option<&[Outcome]>,
) -> Result<()> {
    let plan = crate::plan::load(ctx, plan_id).await?;
    let mut attempt = ctx
        .get(attempt_id)
        .await?
        .with_context(|| format!("canary attempt {attempt_id} not found"))?;
    match object_property(&attempt, "status")? {
        "ready" => return repair_pending_locked(ctx, plan_id).await.map(|_| ()),
        "complete" | "abandoned" => return Ok(()),
        "pending" => {}
        status => bail!("canary attempt {attempt_id} has invalid status {status}"),
    }
    let unchanged_terminal_retry = object_property(&attempt, "initial_plan_state")?
        == plan.state.to_string()
        && plan.state == PlanState::Blocked;
    if abandon_nonterminal
        && (matches!(plan.state, PlanState::Computed | PlanState::Running)
            || unchanged_terminal_retry)
    {
        attempt
            .properties
            .insert("status".into(), "abandoned".into());
        attempt.updated = crate::now_millis().max(attempt.created);
        ctx.put(attempt).await?;
        return Ok(());
    }
    if matches!(plan.state, PlanState::Computed | PlanState::Running) {
        bail!("canary attempt {attempt_id} is still in progress or requires recovery");
    }
    attempt.properties.insert("status".into(), "ready".into());
    if let Some(outcomes) = completed_outcomes {
        attempt
            .properties
            .insert("outcomes".into(), serde_json::to_string(outcomes)?);
    }
    attempt
        .properties
        .insert("plan_state".into(), plan.state.to_string());
    attempt
        .properties
        .insert("status_detail".into(), plan.status_detail.clone());
    attempt.properties.insert(
        "finished_at".into(),
        crate::now_millis().max(attempt.created).to_string(),
    );
    attempt.updated = crate::now_millis().max(attempt.created);
    ctx.put(attempt).await?;
    repair_pending_locked(ctx, plan_id).await?;
    Ok(())
}

pub async fn repair_pending(ctx: &mut Ctx, plan_id: &str) -> Result<usize> {
    let attempts = ctx
        .find_by_property(KIND_CANARY_ATTEMPT, "plan_id", plan_id)
        .await?;
    let mut policies = Vec::new();
    for attempt in &attempts {
        let snapshot: CanaryAttemptSnapshot =
            serde_json::from_str(object_property(attempt, "policies")?)?;
        policies.extend(snapshot.policies);
    }
    let owner = format!("attempt-repair:{plan_id}:{}", crate::now_millis());
    let locks = claim_policy_locks(ctx, &policies, &owner).await?;
    let result = repair_pending_locked(ctx, plan_id).await;
    let unlock = release_policy_locks(ctx, &locks).await;
    match (result, unlock) {
        (Ok(repaired), Ok(())) => Ok(repaired),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => {
            Err(error.context(format!("releasing promotion locks also failed: {unlock}")))
        }
        (Ok(_), Err(error)) => Err(error.context("releasing promotion locks failed")),
    }
}

async fn repair_pending_locked(ctx: &mut Ctx, plan_id: &str) -> Result<usize> {
    let mut stored_plan = crate::plan::load(ctx, plan_id).await?;
    let deployments = ctx.linked(plan_id, REL_PART_OF_PLAN, "in").await?;
    let attempts = ctx
        .find_by_property(KIND_CANARY_ATTEMPT, "plan_id", plan_id)
        .await?;
    let has_pending = attempts
        .iter()
        .any(|attempt| attempt.properties.get("status").map(String::as_str) == Some("pending"));
    let has_started_pending = attempts.iter().any(|attempt| {
        attempt.properties.get("status").map(String::as_str) == Some("pending")
            && attempt.properties.contains_key("execution_started_at")
    });
    let environment_lease =
        crate::apply::environment_lease_status(ctx, &stored_plan.environment).await?;
    if has_pending && let Some(lease) = environment_lease {
        bail!(
            "environment {} still has an apply lease owned by {}; verify the process stopped and run `tenkaictl env unlock {}` before repairing plan {plan_id}",
            stored_plan.environment,
            lease.owner,
            stored_plan.environment
        );
    }
    if has_started_pending && stored_plan.state == PlanState::Running {
        stored_plan.state = PlanState::Failed;
        stored_plan.status_detail =
            "apply was interrupted; canary repair finalized the orphaned execution after its environment lease ended"
                .into();
        crate::plan::store(ctx, &stored_plan).await?;
    }
    let mut repaired = 0;
    for mut attempt in attempts {
        if attempt.properties.get("status").map(String::as_str) == Some("pending")
            && (!attempt.properties.contains_key("execution_started_at")
                || stored_plan.state == PlanState::Computed)
        {
            attempt
                .properties
                .insert("status".into(), "abandoned".into());
            attempt.updated = crate::now_millis().max(attempt.created);
            ctx.put(attempt).await?;
            repaired += 1;
            continue;
        }
        if attempt.properties.get("status").map(String::as_str) == Some("pending")
            && matches!(
                stored_plan.state,
                PlanState::Succeeded | PlanState::Failed | PlanState::Blocked
            )
            && attempt.properties.contains_key("execution_started_at")
        {
            attempt.properties.insert("status".into(), "ready".into());
            attempt
                .properties
                .insert("plan_state".into(), stored_plan.state.to_string());
            attempt
                .properties
                .insert("status_detail".into(), stored_plan.status_detail.clone());
            attempt.properties.insert(
                "finished_at".into(),
                crate::now_millis().max(attempt.created).to_string(),
            );
            attempt.updated = crate::now_millis().max(attempt.created);
            attempt = ctx.put(attempt).await?;
        }
        if attempt.properties.get("status").map(String::as_str) != Some("ready") {
            continue;
        }
        let mut plan = stored_plan.clone();
        plan.state = match object_property(&attempt, "plan_state")? {
            "succeeded" => PlanState::Succeeded,
            "failed" => PlanState::Failed,
            "blocked" => PlanState::Blocked,
            state => bail!(
                "canary attempt {} has invalid plan state {state}",
                attempt.id
            ),
        };
        plan.status_detail = attempt
            .properties
            .get("status_detail")
            .cloned()
            .unwrap_or_default();
        let finished_at = object_property(&attempt, "finished_at")?
            .parse::<i64>()
            .with_context(|| format!("canary attempt {} has invalid finish time", attempt.id))?;
        let execution_started_at = object_property(&attempt, "execution_started_at")?
            .parse::<i64>()
            .with_context(|| format!("canary attempt {} has invalid start time", attempt.id))?;
        let attempt_deployments = deployments
            .iter()
            .filter(|deployment| {
                deployment.created >= execution_started_at && deployment.created <= finished_at
            })
            .cloned()
            .collect::<Vec<_>>();
        let outcomes = match attempt.properties.get("outcomes") {
            Some(serialized) => serde_json::from_str(serialized).with_context(|| {
                format!(
                    "canary attempt {} has invalid execution outcomes",
                    attempt.id
                )
            })?,
            None => reconstructed_outcomes(&plan, &attempt_deployments),
        };
        let snapshot: CanaryAttemptSnapshot =
            serde_json::from_str(object_property(&attempt, "policies")?)?;
        let gates_skipped = object_property(&attempt, "gates_skipped")?
            .parse::<bool>()
            .with_context(|| format!("canary attempt {} has invalid gate state", attempt.id))?;
        let attempt_id = attempt.id.clone();
        record_plan_outcomes(
            ctx,
            &plan,
            &outcomes,
            gates_skipped,
            &snapshot.policies,
            execution_started_at,
            &attempt_id,
        )
        .await?;
        attempt
            .properties
            .insert("status".into(), "complete".into());
        attempt
            .properties
            .insert("plan_state".into(), plan.state.to_string());
        attempt.updated = crate::now_millis().max(attempt.created);
        ctx.put(attempt).await?;
        repaired += 1;
    }
    Ok(repaired)
}

async fn record_plan_outcomes(
    ctx: &mut Ctx,
    plan: &Plan,
    outcomes: &[Outcome],
    gates_skipped: bool,
    policies: &[ActiveCanaryPolicy],
    attempt_started_at: i64,
    attempt_id: &str,
) -> Result<()> {
    let deployments = ctx.linked(&plan.id, REL_PART_OF_PLAN, "in").await?;
    for outcome in outcomes {
        let Some(release) = evidence_release(&outcome.step) else {
            continue;
        };
        for active in policies
            .iter()
            .filter(|active| active.policy.release_id == release)
        {
            if !active.policy.cohort.contains(&plan.environment) {
                continue;
            }
            if let Some(existing) = ctx
                .find_by_property(KIND_CANARY_OUTCOME, "attempt_id", attempt_id)
                .await?
                .into_iter()
                .find(|object| {
                    object.properties.get("policy_digest") == Some(&active.digest)
                        && object.properties.get("release_id").map(String::as_str) == Some(release)
                        && object
                            .properties
                            .get("step_order")
                            .is_some_and(|order| order == &outcome.step.order.to_string())
                })
            {
                ctx.link(
                    &existing.id,
                    &active.policy.release_id,
                    REL_DEPLOYED_RELEASE,
                )
                .await?;
                ctx.link(
                    &existing.id,
                    &policy_record_id(active),
                    REL_EVIDENCE_FOR_POLICY,
                )
                .await?;
                ctx.link(&existing.id, &plan.id, REL_PART_OF_PLAN).await?;
                continue;
            }
            let deployment = deployments.iter().find(|deployment| {
                deployment.properties.get("product") == Some(&outcome.step.product)
                    && deployment.properties.get("to_version") == Some(&outcome.step.to)
                    && deployment.properties.get("status") == Some(&outcome.status)
            });
            let executed_at = deployment
                .map(|deployment| deployment.created)
                .unwrap_or_default()
                .max(attempt_started_at);
            let recorded_at = crate::now_millis().max(executed_at);
            let (gate, execution, health, rollback) = evidence_status(plan, outcome, gates_skipped);
            let evidence = CanaryOutcome {
                release_id: release.into(),
                release_digest: active.policy.release_digest.clone(),
                artifact_digest: active.policy.artifact_digest.clone(),
                policy_digest: active.digest.clone(),
                policy_activated_at: active.activated_at,
                environment: plan.environment.clone(),
                plan_id: plan.id.clone(),
                attempt_id: attempt_id.into(),
                step_order: outcome.step.order,
                plan_state: match plan.state {
                    PlanState::Succeeded => EvidencePlanState::Succeeded,
                    PlanState::Failed => EvidencePlanState::Failed,
                    PlanState::Blocked => EvidencePlanState::Blocked,
                    PlanState::Computed | PlanState::Running => {
                        bail!(
                            "cannot record canary evidence for non-terminal plan {}",
                            plan.id
                        )
                    }
                },
                deployment_id: deployment.map(|deployment| deployment.id.clone()),
                executed_at,
                recorded_at,
                gate,
                execution,
                health,
                rollback,
                detail: outcome.detail.clone(),
            };
            let serialized = serde_json::to_string(&evidence)?;
            let mut persisted_id = None;
            for sequence in 0..1024_u16 {
                let id = format!(
                    "{}:canary:{}:{}:{sequence}",
                    plan.id,
                    &active.digest[..12],
                    outcome.step.order
                );
                let object = Object {
                    id: id.clone(),
                    kind: KIND_CANARY_OUTCOME.into(),
                    name: format!("{} canary outcome", plan.environment),
                    namespace: NS.into(),
                    external_id: String::new(),
                    properties: HashMap::from([
                        ("release_id".into(), release.into()),
                        ("policy_digest".into(), active.digest.clone()),
                        (
                            "policy_activated_at".into(),
                            active.activated_at.to_string(),
                        ),
                        ("environment".into(), plan.environment.clone()),
                        ("plan_id".into(), plan.id.clone()),
                        ("attempt_id".into(), attempt_id.into()),
                        ("step_order".into(), outcome.step.order.to_string()),
                        (
                            "plan_state".into(),
                            format!("{:?}", evidence.plan_state).to_lowercase(),
                        ),
                        (
                            "deployment_id".into(),
                            evidence.deployment_id.clone().unwrap_or_default(),
                        ),
                        ("executed_at".into(), executed_at.to_string()),
                        ("recorded_at".into(), recorded_at.to_string()),
                        ("outcome".into(), serialized.clone()),
                    ]),
                    created: recorded_at,
                    updated: recorded_at,
                };
                match ctx.create_once(object).await {
                    Ok(_) => {
                        persisted_id = Some(id);
                        break;
                    }
                    Err(status)
                        if status.code() == tonic::Code::AlreadyExists
                            || (status.code() == tonic::Code::Internal
                                && status.message().contains("UNIQUE")) =>
                    {
                        let existing = ctx.get(&id).await?.context("canary outcome disappeared")?;
                        if object_property(&existing, "outcome")? == serialized {
                            persisted_id = Some(id);
                            break;
                        }
                    }
                    Err(status) => return Err(status.into()),
                }
            }
            let id = persisted_id.with_context(|| {
                format!(
                    "could not allocate canary evidence for plan {} step {}",
                    plan.id, outcome.step.order
                )
            })?;
            ctx.link(&id, &active.policy.release_id, REL_DEPLOYED_RELEASE)
                .await?;
            ctx.link(&id, &policy_record_id(active), REL_EVIDENCE_FOR_POLICY)
                .await?;
            ctx.link(&id, &plan.id, REL_PART_OF_PLAN).await?;
        }
    }
    Ok(())
}
