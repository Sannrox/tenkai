//! Private Canary promotion evaluation.
//!
//! The interface loads policy-scoped attempt evidence, verifies
//! outcome↔attempt↔plan↔deployment consistency, then evaluates an active
//! policy. Promotion authorization stays a thin caller of this interface.
//! Attempt discovery walks persist-time attempt→policy links instead of
//! catalog-wide status scans; attempt and plan objects are reused for the
//! rest of the authorize path.

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
    let mut attempts_by_id = HashMap::<String, Object>::new();
    let mut plans_by_id = HashMap::<String, Plan>::new();
    for attempt in
        catalog_linked(ctx, &policy_record_id(active), REL_ATTEMPT_FOR_POLICY, "in").await?
    {
        if attempt.kind != KIND_CANARY_ATTEMPT {
            bail!(
                "canary policy {} links to {} {}, not {KIND_CANARY_ATTEMPT}",
                policy_record_id(active),
                attempt.kind,
                attempt.id
            );
        }
        let status = object_property(&attempt, "status")?;
        if matches!(status, "ready" | "pending") {
            bail!(
                "canary attempt {} is {status}; finish or repair it before promotion",
                attempt.id
            );
        }
        attempts_by_id.insert(attempt.id.clone(), attempt);
    }
    let mut terminal_failures = BTreeMap::<String, Vec<CanaryOutcome>>::new();
    let complete_attempts = attempts_by_id.values().cloned().collect::<Vec<_>>();
    for attempt in complete_attempts {
        if object_property(&attempt, "status")? != "complete" {
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
        let plan_id = object_property(&attempt, "plan_id")?.to_string();
        let plan = load_plan_cached(ctx, &mut plans_by_id, &plan_id).await?;
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
                environment: plan.environment.clone(),
                plan_id: plan.id.clone(),
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
    let objects = catalog_find(ctx, KIND_CANARY_OUTCOME, "policy_digest", &active.digest).await?;
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
        let attempt = load_attempt_cached(ctx, &mut attempts_by_id, &outcome.attempt_id).await?;
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
        let plan = load_plan_cached(ctx, &mut plans_by_id, &outcome.plan_id).await?;
        let deployment = match outcome.deployment_id.as_deref() {
            Some(id) => catalog_get(ctx, id).await?,
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

fn record_get(id: &str) {
    #[cfg(test)]
    eval_io::record_get(id);
    let _ = id;
}

fn record_find(kind: &str, key: &str, value: &str) {
    #[cfg(test)]
    eval_io::record_find(kind, key, value);
    let _ = (kind, key, value);
}

fn record_linked(object_id: &str, relation: &str, direction: &str) {
    #[cfg(test)]
    eval_io::record_linked(object_id, relation, direction);
    let _ = (object_id, relation, direction);
}

async fn catalog_get(ctx: &mut Ctx, id: &str) -> Result<Option<Object>> {
    record_get(id);
    ctx.get(id).await
}

async fn catalog_find(ctx: &mut Ctx, kind: &str, key: &str, value: &str) -> Result<Vec<Object>> {
    record_find(kind, key, value);
    ctx.find_by_property(kind, key, value).await
}

async fn catalog_linked(
    ctx: &mut Ctx,
    object_id: &str,
    relation: &str,
    direction: &str,
) -> Result<Vec<Object>> {
    record_linked(object_id, relation, direction);
    ctx.linked(object_id, relation, direction).await
}

async fn load_attempt_cached(
    ctx: &mut Ctx,
    cache: &mut HashMap<String, Object>,
    id: &str,
) -> Result<Object> {
    if let Some(attempt) = cache.get(id) {
        return Ok(attempt.clone());
    }
    let attempt = catalog_get(ctx, id)
        .await?
        .with_context(|| format!("canary attempt {id} not found"))?;
    cache.insert(id.to_string(), attempt.clone());
    Ok(attempt)
}

async fn load_plan_cached(
    ctx: &mut Ctx,
    cache: &mut HashMap<String, Plan>,
    id: &str,
) -> Result<Plan> {
    if let Some(plan) = cache.get(id) {
        return Ok(plan.clone());
    }
    record_get(id);
    let plan = crate::plan::load(ctx, id).await?;
    cache.insert(id.to_string(), plan.clone());
    Ok(plan)
}

#[cfg(test)]
mod eval_io {
    use std::cell::RefCell;

    thread_local! {
        static LOG: RefCell<Option<EvalIoLog>> = const { RefCell::new(None) };
    }

    #[derive(Clone, Debug, Default)]
    pub struct EvalIoLog {
        pub gets: Vec<String>,
        pub finds: Vec<(String, String, String)>,
        pub linkeds: Vec<(String, String, String)>,
    }

    pub fn record_get(id: &str) {
        LOG.with(|log| {
            if let Some(log) = log.borrow_mut().as_mut() {
                log.gets.push(id.to_string());
            }
        });
    }

    pub fn record_find(kind: &str, key: &str, value: &str) {
        LOG.with(|log| {
            if let Some(log) = log.borrow_mut().as_mut() {
                log.finds
                    .push((kind.to_string(), key.to_string(), value.to_string()));
            }
        });
    }

    pub fn record_linked(object_id: &str, relation: &str, direction: &str) {
        LOG.with(|log| {
            if let Some(log) = log.borrow_mut().as_mut() {
                log.linkeds.push((
                    object_id.to_string(),
                    relation.to_string(),
                    direction.to_string(),
                ));
            }
        });
    }

    pub async fn capture<F, Fut, T>(f: F) -> (T, EvalIoLog)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        LOG.with(|log| *log.borrow_mut() = Some(EvalIoLog::default()));
        let result = f().await;
        let recorded = LOG.with(|log| log.borrow_mut().take().unwrap_or_default());
        (result, recorded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{DesiredStateInput, PLAN_FORMAT_VERSION, Step};
    use sha2::Sha256;

    fn policy() -> CanaryPolicy {
        CanaryPolicy {
            release_id: "tenkai:release:api@1.2.3".into(),
            release_digest: "manifest".into(),
            artifact_digest: "artifact".into(),
            product: "api".into(),
            version: "1.2.3".into(),
            target_channel: "stable".into(),
            cohort: vec!["canary-a".into()],
            success_policy: SuccessPolicy::All,
        }
    }

    fn active_policy(policy: &CanaryPolicy) -> ActiveCanaryPolicy {
        ActiveCanaryPolicy::new(policy.clone(), 1).unwrap()
    }

    fn context(name: &str) -> (Ctx, std::path::PathBuf) {
        let database = std::env::temp_dir().join(format!(
            "tenkai-canary-eval-{name}-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        (Ctx::embedded(&database).unwrap(), database)
    }

    fn plan_content_id(environment: &str, created_at: i64, steps: &[Step]) -> String {
        let mut normalized_steps = steps.to_vec();
        for step in &mut normalized_steps {
            step.id.clear();
        }
        let inputs: Vec<DesiredStateInput> = Vec::new();
        format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    PLAN_FORMAT_VERSION,
                    environment,
                    created_at,
                    inputs,
                    normalized_steps
                ))
                .unwrap()
            )
        )
    }

    fn addressed_plan(
        environment: &str,
        created_at: i64,
        state: PlanState,
        policy: &CanaryPolicy,
    ) -> Plan {
        let mut steps = vec![Step {
            id: String::new(),
            order: 0,
            product: policy.product.clone(),
            action: Action::Install,
            from: None,
            to: policy.version.clone(),
            release_id: policy.release_id.clone(),
            release_digest: policy.release_digest.clone(),
            artifact_digest: policy.artifact_digest.clone(),
            workdir: ".".into(),
            restore: None,
        }];
        let content_id = plan_content_id(environment, created_at, &steps);
        let id = plan_id(environment, created_at, &content_id);
        steps[0].id = format!("{id}:step:0");
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            id,
            content_id,
            environment: environment.into(),
            created_at,
            inputs: Vec::new(),
            steps,
            state,
            gates_skipped: Some(false),
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
        }
    }

    async fn put_attempt(
        ctx: &mut Ctx,
        active: &ActiveCanaryPolicy,
        plan: &Plan,
        status: &str,
        plan_state: Option<&str>,
        link: bool,
    ) -> String {
        let id = format!("{}:canary-attempt:0", plan.id);
        let snapshot = CanaryAttemptSnapshot {
            policies: vec![active.clone()],
        };
        let mut properties = HashMap::from([
            ("plan_id".into(), plan.id.clone()),
            ("initial_plan_state".into(), PlanState::Computed.to_string()),
            ("gates_skipped".into(), "false".into()),
            ("status".into(), status.into()),
            ("policies".into(), serde_json::to_string(&snapshot).unwrap()),
            ("execution_started_at".into(), "10".into()),
            ("finished_at".into(), "30".into()),
        ]);
        if let Some(plan_state) = plan_state {
            properties.insert("plan_state".into(), plan_state.into());
        }
        ctx.create_once(Object {
            id: id.clone(),
            kind: KIND_CANARY_ATTEMPT.into(),
            name: "canary attempt".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties,
            created: 10,
            updated: 30,
        })
        .await
        .unwrap();
        if link {
            ctx.link(&id, &policy_record_id(active), REL_ATTEMPT_FOR_POLICY)
                .await
                .unwrap();
        }
        id
    }

    async fn put_noise_attempts(ctx: &mut Ctx, count: usize) {
        for index in 0..count {
            ctx.create_once(Object {
                id: format!("tenkai:plan:noise-{index}:1:x:canary-attempt:0"),
                kind: KIND_CANARY_ATTEMPT.into(),
                name: "unrelated attempt".into(),
                namespace: NS.into(),
                external_id: String::new(),
                properties: HashMap::from([
                    ("plan_id".into(), format!("tenkai:plan:noise-{index}:1:x")),
                    ("initial_plan_state".into(), "computed".into()),
                    ("gates_skipped".into(), "false".into()),
                    (
                        "status".into(),
                        if index % 2 == 0 { "complete" } else { "ready" }.into(),
                    ),
                    ("policies".into(), "this is not attempt policy json".into()),
                    ("plan_state".into(), "failed".into()),
                ]),
                created: 1,
                updated: 1,
            })
            .await
            .unwrap();
        }
    }

    fn passing_outcome(
        policy: &CanaryPolicy,
        active: &ActiveCanaryPolicy,
        plan: &Plan,
        attempt_id: &str,
        deployment_id: &str,
    ) -> CanaryOutcome {
        CanaryOutcome {
            release_id: policy.release_id.clone(),
            release_digest: policy.release_digest.clone(),
            artifact_digest: policy.artifact_digest.clone(),
            policy_digest: active.digest.clone(),
            policy_activated_at: active.activated_at,
            environment: plan.environment.clone(),
            plan_id: plan.id.clone(),
            attempt_id: attempt_id.into(),
            step_order: 0,
            plan_state: EvidencePlanState::Succeeded,
            deployment_id: Some(deployment_id.into()),
            executed_at: 20,
            recorded_at: 30,
            gate: GateOutcome::Satisfied,
            execution: ExecutionOutcome::Succeeded,
            health: HealthOutcome::PassedOrNotConfigured,
            rollback: RollbackOutcome::NotNeeded,
            detail: String::new(),
        }
    }

    async fn put_outcome(ctx: &mut Ctx, active: &ActiveCanaryPolicy, outcome: &CanaryOutcome) {
        ctx.create_once(Object {
            id: format!(
                "{}:canary:{}:{}:0",
                outcome.plan_id,
                &active.digest[..12],
                outcome.step_order
            ),
            kind: KIND_CANARY_OUTCOME.into(),
            name: "canary outcome".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("release_id".into(), outcome.release_id.clone()),
                ("policy_digest".into(), active.digest.clone()),
                (
                    "policy_activated_at".into(),
                    active.activated_at.to_string(),
                ),
                ("environment".into(), outcome.environment.clone()),
                ("plan_id".into(), outcome.plan_id.clone()),
                ("attempt_id".into(), outcome.attempt_id.clone()),
                ("step_order".into(), outcome.step_order.to_string()),
                (
                    "plan_state".into(),
                    format!("{:?}", outcome.plan_state).to_lowercase(),
                ),
                (
                    "deployment_id".into(),
                    outcome.deployment_id.clone().unwrap_or_default(),
                ),
                ("executed_at".into(), outcome.executed_at.to_string()),
                ("recorded_at".into(), outcome.recorded_at.to_string()),
                ("outcome".into(), serde_json::to_string(outcome).unwrap()),
            ]),
            created: outcome.recorded_at,
            updated: outcome.recorded_at,
        })
        .await
        .unwrap();
    }

    async fn put_passing_member(
        ctx: &mut Ctx,
        policy: &CanaryPolicy,
        active: &ActiveCanaryPolicy,
        environment: &str,
        created_at: i64,
    ) -> (Plan, String) {
        let plan = addressed_plan(environment, created_at, PlanState::Succeeded, policy);
        crate::plan::store(ctx, &plan).await.unwrap();
        let attempt_id = put_attempt(ctx, active, &plan, "complete", Some("succeeded"), true).await;
        let deployment_id = format!("tenkai:deployment:{environment}:api:{created_at}");
        ctx.create_once(Object {
            id: deployment_id.clone(),
            kind: KIND_DEPLOYMENT.into(),
            name: "canary deployment".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("environment".into(), environment.into()),
                ("product".into(), policy.product.clone()),
                ("to_version".into(), policy.version.clone()),
                ("status".into(), "succeeded".into()),
            ]),
            created: 20,
            updated: 20,
        })
        .await
        .unwrap();
        ctx.link(&deployment_id, &plan.id, REL_PART_OF_PLAN)
            .await
            .unwrap();
        let outcome = passing_outcome(policy, active, &plan, &attempt_id, &deployment_id);
        put_outcome(ctx, active, &outcome).await;
        (plan, attempt_id)
    }

    fn assert_policy_scoped(log: &eval_io::EvalIoLog, active: &ActiveCanaryPolicy) {
        assert!(
            log.finds
                .iter()
                .all(|(kind, key, _)| { !(kind == KIND_CANARY_ATTEMPT && key == "status") }),
            "evaluate_active scanned canary attempts by status: {:?}",
            log.finds
        );
        assert_eq!(
            log.finds
                .iter()
                .filter(|(kind, _, _)| kind == KIND_CANARY_ATTEMPT)
                .count(),
            0,
            "evaluate_active loaded canary attempts by property scan: {:?}",
            log.finds
        );
        assert_eq!(
            log.linkeds,
            vec![(
                policy_record_id(active),
                REL_ATTEMPT_FOR_POLICY.to_string(),
                "in".into()
            )]
        );
        let mut seen_gets = BTreeSet::new();
        for id in &log.gets {
            assert!(
                seen_gets.insert(id.clone()),
                "evaluate_active fetched {id} more than once: {:?}",
                log.gets
            );
        }
    }

    #[tokio::test]
    async fn evaluate_active_scopes_attempts_to_the_policy_and_reuses_loaded_objects() {
        let (mut ctx, database) = context("scope");
        let policy = policy();
        let active = active_policy(&policy);
        put_noise_attempts(&mut ctx, 24).await;
        let (plan, attempt_id) =
            put_passing_member(&mut ctx, &policy, &active, "canary-a", 100).await;

        let (result, log) = eval_io::capture(|| evaluate_active(&mut ctx, &active)).await;
        let evaluation = result.unwrap();
        assert!(evaluation.allowed);
        assert!(matches!(
            evaluation.cohort["canary-a"],
            CohortResult::Passed { .. }
        ));
        assert_policy_scoped(&log, &active);
        assert!(
            !log.gets.iter().any(|id| id == &attempt_id),
            "linked attempt {} was fetched again: {:?}",
            attempt_id,
            log.gets
        );
        assert_eq!(
            log.gets.iter().filter(|id| **id == plan.id).count(),
            1,
            "plan {} should be loaded once: {:?}",
            plan.id,
            log.gets
        );
        assert!(
            !log.gets.iter().any(|id| id.contains("noise-")),
            "unrelated attempts or plans were loaded: {:?}",
            log.gets
        );

        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn evaluate_active_does_not_reload_failed_attempt_or_plan_for_its_outcome() {
        let (mut ctx, database) = context("reuse");
        let policy = policy();
        let active = active_policy(&policy);
        put_noise_attempts(&mut ctx, 16).await;
        let plan = addressed_plan("canary-a", 200, PlanState::Failed, &policy);
        crate::plan::store(&mut ctx, &plan).await.unwrap();
        let attempt_id =
            put_attempt(&mut ctx, &active, &plan, "complete", Some("failed"), true).await;
        let outcome = CanaryOutcome {
            release_id: policy.release_id.clone(),
            release_digest: policy.release_digest.clone(),
            artifact_digest: policy.artifact_digest.clone(),
            policy_digest: active.digest.clone(),
            policy_activated_at: active.activated_at,
            environment: plan.environment.clone(),
            plan_id: plan.id.clone(),
            attempt_id: attempt_id.clone(),
            step_order: 0,
            plan_state: EvidencePlanState::Failed,
            deployment_id: None,
            executed_at: 20,
            recorded_at: 30,
            gate: GateOutcome::Satisfied,
            execution: ExecutionOutcome::Failed,
            health: HealthOutcome::FailedOrUnknown,
            rollback: RollbackOutcome::FailedOrUnknown,
            detail: "failed".into(),
        };
        put_outcome(&mut ctx, &active, &outcome).await;

        let (result, log) = eval_io::capture(|| evaluate_active(&mut ctx, &active)).await;
        let evaluation = result.unwrap();
        assert!(!evaluation.allowed);
        assert!(matches!(
            evaluation.cohort["canary-a"],
            CohortResult::Failed { .. }
        ));
        assert_policy_scoped(&log, &active);
        assert!(
            !log.gets.contains(&attempt_id),
            "failed attempt {} was fetched after the policy-scoped walk: {:?}",
            attempt_id,
            log.gets
        );
        assert_eq!(
            log.gets.iter().filter(|id| **id == plan.id).count(),
            1,
            "failed plan {} should be loaded once: {:?}",
            plan.id,
            log.gets
        );

        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn evaluate_active_still_blocks_on_pending_and_failed_attempts() {
        let policy = policy();
        let active = active_policy(&policy);

        let (mut ctx, database) = context("pending");
        put_noise_attempts(&mut ctx, 8).await;
        let pending_plan = addressed_plan("canary-a", 300, PlanState::Running, &policy);
        crate::plan::store(&mut ctx, &pending_plan).await.unwrap();
        let pending_id = put_attempt(&mut ctx, &active, &pending_plan, "pending", None, true).await;
        let pending = evaluate_active(&mut ctx, &active)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            pending.contains(&pending_id) && pending.contains("pending"),
            "{pending}"
        );
        let _ = std::fs::remove_file(database);

        let (mut ctx, database) = context("ready");
        let ready_plan = addressed_plan("canary-a", 301, PlanState::Succeeded, &policy);
        crate::plan::store(&mut ctx, &ready_plan).await.unwrap();
        let ready_id = put_attempt(
            &mut ctx,
            &active,
            &ready_plan,
            "ready",
            Some("succeeded"),
            true,
        )
        .await;
        let ready = evaluate_active(&mut ctx, &active)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            ready.contains(&ready_id) && ready.contains("ready"),
            "{ready}"
        );
        let _ = std::fs::remove_file(database);

        let (mut ctx, database) = context("failed");
        put_noise_attempts(&mut ctx, 8).await;
        let failed_plan = addressed_plan("canary-a", 302, PlanState::Failed, &policy);
        crate::plan::store(&mut ctx, &failed_plan).await.unwrap();
        put_attempt(
            &mut ctx,
            &active,
            &failed_plan,
            "complete",
            Some("failed"),
            true,
        )
        .await;
        let failed = evaluate_active(&mut ctx, &active).await.unwrap();
        assert!(!failed.allowed);
        assert!(matches!(
            failed.cohort["canary-a"],
            CohortResult::Failed { .. }
        ));
        let _ = std::fs::remove_file(database);

        let (mut ctx, database) = context("foreign-pending");
        let mut other_policy = policy.clone();
        other_policy.target_channel = "beta".into();
        let other = active_policy(&other_policy);
        let other_plan = addressed_plan("canary-a", 303, PlanState::Running, &other_policy);
        crate::plan::store(&mut ctx, &other_plan).await.unwrap();
        put_attempt(&mut ctx, &other, &other_plan, "pending", None, true).await;
        put_passing_member(&mut ctx, &policy, &active, "canary-a", 304).await;
        let allowed = evaluate_active(&mut ctx, &active).await.unwrap();
        assert!(allowed.allowed);
        let _ = std::fs::remove_file(database);
    }
}
