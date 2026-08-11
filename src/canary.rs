//! Canary promotion policy and evidence evaluation.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::ontology::*;
use crate::pb::sekai::{Link, Object};
use crate::plan::{Action, Plan, PlanState};
use crate::{apply::Outcome, client::Ctx};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessPolicy {
    /// Every designated canary must report a passing result.
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryPolicy {
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub product: String,
    pub version: String,
    pub target_channel: String,
    pub cohort: Vec<String>,
    pub success_policy: SuccessPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveCanaryPolicy {
    policy: CanaryPolicy,
    digest: String,
    activated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CanaryAttemptSnapshot {
    policies: Vec<ActiveCanaryPolicy>,
}

impl ActiveCanaryPolicy {
    #[allow(dead_code, reason = "used by graph-backed policy loading")]
    pub(crate) fn new(policy: CanaryPolicy, activated_at: i64) -> Result<Self> {
        let policy = policy.canonicalized()?;
        let digest = policy.digest()?;
        Ok(Self {
            policy,
            digest,
            activated_at,
        })
    }

    pub fn policy(&self) -> &CanaryPolicy {
        &self.policy
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl CanaryPolicy {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("product", &self.product)?;
        validate_identifier("version", &self.version)?;
        validate_identifier("channel", &self.target_channel)?;
        if self.release_id.is_empty()
            || self.release_digest.is_empty()
            || self.artifact_digest.is_empty()
        {
            bail!("canary policy release pins must not be empty");
        }
        if self.release_id != release_id(&self.product, &self.version) {
            bail!(
                "canary policy release id does not match {}@{}",
                self.product,
                self.version
            );
        }
        if self.cohort.is_empty() {
            bail!("canary policy cohort must not be empty");
        }
        let mut unique = BTreeSet::new();
        for environment in &self.cohort {
            validate_identifier("environment", environment)?;
            if !unique.insert(environment) {
                bail!("canary cohort contains duplicate environment {environment}");
            }
        }
        Ok(())
    }

    pub fn canonicalized(mut self) -> Result<Self> {
        self.validate()?;
        self.cohort.sort();
        Ok(self)
    }

    pub fn digest(&self) -> Result<String> {
        let canonical = self.clone().canonicalized()?;
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&canonical)?)
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOutcome {
    Satisfied,
    Skipped,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Succeeded,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthOutcome {
    PassedOrNotConfigured,
    FailedOrUnknown,
    NotRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackOutcome {
    NotNeeded,
    Succeeded,
    FailedOrUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePlanState {
    Succeeded,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CanaryOutcome {
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub policy_digest: String,
    pub policy_activated_at: i64,
    pub environment: String,
    pub plan_id: String,
    pub attempt_id: String,
    pub step_order: u32,
    pub plan_state: EvidencePlanState,
    pub deployment_id: Option<String>,
    pub executed_at: i64,
    pub recorded_at: i64,
    pub gate: GateOutcome,
    pub execution: ExecutionOutcome,
    pub health: HealthOutcome,
    pub rollback: RollbackOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryAttemptEvidence {
    pub id: String,
    pub plan_id: String,
    pub plan_state: EvidencePlanState,
    pub gates_skipped: bool,
    pub started_at: i64,
    pub finished_at: i64,
}

impl CanaryOutcome {
    fn plan_matches_environment(&self) -> bool {
        let Some(identity) = self.plan_id.strip_prefix("tenkai:plan:") else {
            return false;
        };
        let mut parts = identity.split(':');
        matches!(
            (parts.next(), parts.next(), parts.next(), parts.next()),
            (Some(environment), Some(created_at), Some(content_id), None)
                if environment == self.environment
                    && created_at.parse::<i64>().is_ok()
                    && !content_id.is_empty()
        )
    }

    fn passes(&self, policy: &CanaryPolicy, policy_digest: &str) -> bool {
        self.release_id == policy.release_id
            && self.release_digest == policy.release_digest
            && self.artifact_digest == policy.artifact_digest
            && self.policy_digest == policy_digest
            && self.policy_activated_at <= self.executed_at
            && self.plan_matches_environment()
            && self.plan_state == EvidencePlanState::Succeeded
            && self.gate == GateOutcome::Satisfied
            && self.execution == ExecutionOutcome::Succeeded
            && self.health == HealthOutcome::PassedOrNotConfigured
            && self.rollback == RollbackOutcome::NotNeeded
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCanaryOutcome(CanaryOutcome);

impl VerifiedCanaryOutcome {
    #[allow(dead_code, reason = "used by graph-backed outcome loading")]
    pub(crate) fn verify(
        outcome: CanaryOutcome,
        plan: &Plan,
        attempt: &CanaryAttemptEvidence,
        deployment: Option<&Object>,
        deployment_links_to_plan: bool,
        active_policy: &ActiveCanaryPolicy,
    ) -> Result<Self> {
        if outcome.policy_digest != active_policy.digest
            || outcome.policy_activated_at != active_policy.activated_at
            || outcome.recorded_at < active_policy.activated_at
            || outcome.recorded_at < outcome.executed_at
        {
            bail!("canary outcome was not recorded under the active policy");
        }
        if outcome.plan_id != plan.id
            || outcome.environment != plan.environment
            || !outcome.plan_matches_environment()
        {
            bail!("canary outcome plan identity does not match the stored plan");
        }
        if outcome.attempt_id != attempt.id
            || outcome.plan_id != attempt.plan_id
            || outcome.plan_state != attempt.plan_state
            || attempt.started_at < active_policy.activated_at
            || attempt.finished_at < attempt.started_at
            || outcome.executed_at < attempt.started_at
            || outcome.executed_at > attempt.finished_at
            || outcome.recorded_at < attempt.finished_at
            || (outcome.gate == GateOutcome::Skipped) != attempt.gates_skipped
        {
            bail!("canary outcome does not match its immutable execution attempt");
        }
        if outcome.plan_state == EvidencePlanState::Succeeded
            && (plan.state != PlanState::Succeeded
                || plan.gates_skipped != Some(attempt.gates_skipped))
        {
            bail!("canary outcome does not match the stored plan result");
        }
        match outcome.plan_state {
            EvidencePlanState::Succeeded
                if outcome.execution != ExecutionOutcome::Succeeded
                    || outcome.health != HealthOutcome::PassedOrNotConfigured
                    || !matches!(
                        outcome.rollback,
                        RollbackOutcome::NotNeeded | RollbackOutcome::Succeeded
                    ) =>
            {
                bail!("succeeded canary plan has a non-passing deployment outcome")
            }
            EvidencePlanState::Blocked if outcome.execution != ExecutionOutcome::Blocked => {
                bail!("blocked canary plan has a non-blocked execution outcome")
            }
            _ => {}
        }
        let deployment_step = plan
            .steps
            .iter()
            .find(|step| step.order == outcome.step_order)
            .filter(|step| {
                let deploys_candidate = step.product == outcome.release_product()
                    && matches!(
                        step.action,
                        Action::Install | Action::Upgrade | Action::Downgrade
                    )
                    && step.to == outcome.release_version()
                    && step.release_id == outcome.release_id
                    && step.release_digest == outcome.release_digest
                    && step.artifact_digest == outcome.artifact_digest;
                let rolls_back_candidate = step.product == outcome.release_product()
                    && step.action == Action::Rollback
                    && step.from.as_deref() == Some(outcome.release_version())
                    && step.restore.as_ref().is_some_and(|restore| {
                        restore.release_id == outcome.release_id
                            && restore.digest == outcome.release_digest
                            && restore.artifact_digest == outcome.artifact_digest
                    });
                deploys_candidate || rolls_back_candidate
            });
        let Some(deployment_step) = deployment_step else {
            bail!("canary outcome release pins do not occur in the stored plan");
        };
        if deployment_step.action == Action::Rollback
            && outcome.rollback == RollbackOutcome::NotNeeded
        {
            bail!("explicit rollback plan claims that rollback was not needed");
        }
        if outcome.plan_state == EvidencePlanState::Succeeded {
            let deployment = deployment
                .filter(|_| deployment_links_to_plan)
                .ok_or_else(|| {
                    anyhow::anyhow!("passing canary outcome has no linked deployment")
                })?;
            if deployment.kind != KIND_DEPLOYMENT
                || outcome.deployment_id.as_deref() != Some(deployment.id.as_str())
                || outcome.executed_at > deployment.created
                || deployment.created > attempt.finished_at
                || deployment.created > outcome.recorded_at
                || deployment.updated < deployment.created
                || deployment.updated > attempt.finished_at
                || deployment.updated > outcome.recorded_at
                || deployment.created < active_policy.activated_at
                || deployment.properties.get("environment") != Some(&outcome.environment)
                || deployment.properties.get("product") != Some(&outcome.release_product().into())
                || deployment.properties.get("to_version") != Some(&deployment_step.to)
                || deployment.properties.get("status").map(String::as_str) != Some("succeeded")
            {
                bail!("passing canary outcome does not match its deployment evidence");
            }
        }
        Ok(Self(outcome))
    }

    fn outcome(&self) -> &CanaryOutcome {
        &self.0
    }
}

impl CanaryOutcome {
    #[allow(dead_code, reason = "used by verified plan linkage")]
    fn release_product(&self) -> &str {
        self.release_id
            .strip_prefix("tenkai:release:")
            .and_then(|identity| identity.split_once('@'))
            .map(|(product, _)| product)
            .unwrap_or("")
    }

    #[allow(dead_code, reason = "used by verified plan linkage")]
    fn release_version(&self) -> &str {
        self.release_id
            .strip_prefix("tenkai:release:")
            .and_then(|identity| identity.split_once('@'))
            .map(|(_, version)| version)
            .unwrap_or("")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortResult {
    Passed { outcomes: Vec<CanaryOutcome> },
    Failed { outcomes: Vec<CanaryOutcome> },
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionEvaluation {
    pub policy_digest: String,
    pub policy_activated_at: i64,
    pub allowed: bool,
    pub cohort: BTreeMap<String, CohortResult>,
}

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

mod promotion_lifecycle;

pub(crate) use promotion_lifecycle::guarded_promotion;
use promotion_lifecycle::{
    POLICY_DISCOVERY_LOCK_CHANNEL, claim_policy_locks, claim_promotion_lock_with_retry,
    object_property, policies_for_release, policy_record_id, release_policy_locks,
    release_promotion_lock,
};
pub use promotion_lifecycle::{
    active_policy, authorize_promotion, configure, confirm_policy_active, set_designated,
    unlock_promotion,
};

fn evidence_release(step: &crate::plan::Step) -> Option<&str> {
    match step.action {
        Action::Rollback => step.restore.as_ref().map(|pin| pin.release_id.as_str()),
        Action::Install | Action::Upgrade | Action::Downgrade => Some(&step.release_id),
    }
}

mod attempt_lifecycle;

pub(crate) use attempt_lifecycle::execute_attempt;
pub use attempt_lifecycle::repair_pending;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Action, PLAN_FORMAT_VERSION, PlanState, ReleasePin, Step};

    fn policy() -> CanaryPolicy {
        CanaryPolicy {
            release_id: "tenkai:release:api@1.2.3".into(),
            release_digest: "manifest".into(),
            artifact_digest: "artifact".into(),
            product: "api".into(),
            version: "1.2.3".into(),
            target_channel: "stable".into(),
            cohort: vec!["canary-b".into(), "canary-a".into()],
            success_policy: SuccessPolicy::All,
        }
    }

    fn active(policy: &CanaryPolicy) -> ActiveCanaryPolicy {
        ActiveCanaryPolicy::new(policy.clone(), 1).unwrap()
    }

    #[test]
    fn policy_record_identity_preserves_each_activation() {
        let policy = policy();
        let first = ActiveCanaryPolicy::new(policy.clone(), 1).unwrap();
        let second = ActiveCanaryPolicy::new(policy, 2).unwrap();

        assert_ne!(policy_record_id(&first), policy_record_id(&second));
        assert!(policy_record_id(&first).ends_with(&format!(":1:{}", first.digest)));
        assert!(policy_record_id(&second).ends_with(&format!(":2:{}", second.digest)));
    }

    fn passing(environment: &str, policy: &CanaryPolicy) -> CanaryOutcome {
        CanaryOutcome {
            release_id: policy.release_id.clone(),
            release_digest: policy.release_digest.clone(),
            artifact_digest: policy.artifact_digest.clone(),
            policy_digest: policy.digest().unwrap(),
            policy_activated_at: 1,
            environment: environment.into(),
            plan_id: format!("tenkai:plan:{environment}:1:content"),
            attempt_id: format!("tenkai:plan:{environment}:1:content:canary-attempt:0"),
            step_order: 0,
            plan_state: EvidencePlanState::Succeeded,
            deployment_id: Some(format!("tenkai:deployment:{environment}:api:1")),
            executed_at: 2,
            recorded_at: 2,
            gate: GateOutcome::Satisfied,
            execution: ExecutionOutcome::Succeeded,
            health: HealthOutcome::PassedOrNotConfigured,
            rollback: RollbackOutcome::NotNeeded,
            detail: String::new(),
        }
    }

    fn attempt_for(outcome: &CanaryOutcome) -> CanaryAttemptEvidence {
        CanaryAttemptEvidence {
            id: outcome.attempt_id.clone(),
            plan_id: outcome.plan_id.clone(),
            plan_state: outcome.plan_state,
            gates_skipped: outcome.gate == GateOutcome::Skipped,
            started_at: 1,
            finished_at: outcome.executed_at,
        }
    }

    fn plan_for(outcome: &CanaryOutcome) -> Plan {
        let state = match outcome.plan_state {
            EvidencePlanState::Succeeded => PlanState::Succeeded,
            EvidencePlanState::Failed => PlanState::Failed,
            EvidencePlanState::Blocked => PlanState::Blocked,
        };
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            id: outcome.plan_id.clone(),
            content_id: "content".into(),
            environment: outcome.environment.clone(),
            created_at: 1,
            inputs: Vec::new(),
            steps: vec![Step {
                id: format!("{}:step:0", outcome.plan_id),
                order: 0,
                product: outcome.release_product().into(),
                action: Action::Install,
                from: None,
                to: "1.2.3".into(),
                release_id: outcome.release_id.clone(),
                release_digest: outcome.release_digest.clone(),
                artifact_digest: outcome.artifact_digest.clone(),
                workdir: ".".into(),
                restore: None,
            }],
            state,
            gates_skipped: Some(false),
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
        }
    }

    fn deployment_for(outcome: &CanaryOutcome) -> Object {
        Object {
            id: outcome.deployment_id.clone().unwrap(),
            kind: KIND_DEPLOYMENT.into(),
            name: "canary deployment".into(),
            namespace: crate::ontology::NS.into(),
            external_id: String::new(),
            properties: BTreeMap::from([
                ("environment".into(), outcome.environment.clone()),
                ("product".into(), outcome.release_product().into()),
                ("to_version".into(), outcome.release_version().into()),
                ("status".into(), "succeeded".into()),
            ])
            .into_iter()
            .collect(),
            created: outcome.executed_at,
            updated: outcome.executed_at,
        }
    }

    fn verified(outcome: CanaryOutcome, policy: &CanaryPolicy) -> VerifiedCanaryOutcome {
        let plan = plan_for(&outcome);
        let attempt = attempt_for(&outcome);
        let deployment =
            (outcome.plan_state == EvidencePlanState::Succeeded).then(|| deployment_for(&outcome));
        VerifiedCanaryOutcome::verify(
            outcome,
            &plan,
            &attempt,
            deployment.as_ref(),
            deployment.is_some(),
            &active(policy),
        )
        .unwrap()
    }

    #[test]
    fn complete_passing_cohort_allows_promotion() {
        let policy = policy();
        let result = evaluate(
            &active(&policy),
            &[
                verified(passing("canary-a", &policy), &policy),
                verified(passing("canary-b", &policy), &policy),
            ],
        )
        .unwrap();
        assert!(result.allowed);
        assert_eq!(result.cohort.len(), 2);
    }

    #[test]
    fn missing_failed_rolled_back_and_stale_outcomes_block() {
        let policy = policy();
        let mut failed = passing("canary-a", &policy);
        failed.execution = ExecutionOutcome::Failed;
        failed.plan_state = EvidencePlanState::Failed;
        assert!(
            !evaluate(&active(&policy), &[verified(failed, &policy)])
                .unwrap()
                .allowed
        );

        let mut succeeded_before_failure = passing("canary-a", &policy);
        succeeded_before_failure.plan_state = EvidencePlanState::Failed;
        assert!(matches!(
            evaluate(
                &active(&policy),
                &[verified(succeeded_before_failure.clone(), &policy)]
            )
            .unwrap()
            .cohort["canary-a"],
            CohortResult::Failed { .. }
        ));
        let mut historical_plan = plan_for(&succeeded_before_failure);
        historical_plan.state = PlanState::Succeeded;
        let historical_attempt = attempt_for(&succeeded_before_failure);
        assert!(
            VerifiedCanaryOutcome::verify(
                succeeded_before_failure,
                &historical_plan,
                &historical_attempt,
                None,
                false,
                &active(&policy)
            )
            .is_ok()
        );

        let mut rolled_back = passing("canary-b", &policy);
        rolled_back.execution = ExecutionOutcome::Failed;
        rolled_back.rollback = RollbackOutcome::Succeeded;
        rolled_back.plan_state = EvidencePlanState::Failed;
        assert!(matches!(
            evaluate(
                &active(&policy),
                &[
                    verified(passing("canary-a", &policy), &policy),
                    verified(rolled_back, &policy)
                ]
            )
            .unwrap()
            .cohort["canary-b"],
            CohortResult::Failed { .. }
        ));

        let mut stale = passing("canary-a", &policy);
        stale.policy_digest = "old-policy".into();
        let stale_plan = plan_for(&stale);
        let stale_attempt = attempt_for(&stale);
        let stale_deployment = deployment_for(&stale);
        assert!(
            VerifiedCanaryOutcome::verify(
                stale,
                &stale_plan,
                &stale_attempt,
                Some(&stale_deployment),
                true,
                &active(&policy)
            )
            .is_err()
        );
    }

    #[test]
    fn policy_digest_is_stable_across_cohort_order() {
        let first = policy();
        let mut second = first.clone();
        second.cohort.reverse();
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    }

    #[test]
    fn identical_policy_reactivation_invalidates_prior_evidence() {
        let policy = policy();
        let prior = verified(passing("canary-a", &policy), &policy);
        let reactivated = ActiveCanaryPolicy::new(policy.clone(), 3).unwrap();
        assert!(matches!(
            evaluate(&reactivated, &[prior]).unwrap().cohort["canary-a"],
            CohortResult::Missing
        ));
    }

    #[test]
    fn explicit_rollback_is_verified_as_negative_evidence() {
        let policy = policy();
        let mut outcome = passing("canary-a", &policy);
        outcome.rollback = RollbackOutcome::Succeeded;
        let mut rollback = plan_for(&outcome);
        let candidate_pin = ReleasePin {
            release_id: outcome.release_id.clone(),
            digest: outcome.release_digest.clone(),
            artifact_digest: outcome.artifact_digest.clone(),
            workdir: ".".into(),
        };
        rollback.steps[0].action = Action::Rollback;
        rollback.steps[0].from = Some(policy.version.clone());
        rollback.steps[0].to = "1.1.0".into();
        rollback.steps[0].release_id = "tenkai:release:api@1.1.0".into();
        rollback.steps[0].release_digest = "old-manifest".into();
        rollback.steps[0].artifact_digest = "old-artifact".into();
        rollback.steps[0].restore = Some(candidate_pin);
        let mut deployment = deployment_for(&outcome);
        let attempt = attempt_for(&outcome);
        deployment
            .properties
            .insert("to_version".into(), "1.1.0".into());
        let verified = VerifiedCanaryOutcome::verify(
            outcome.clone(),
            &rollback,
            &attempt,
            Some(&deployment),
            true,
            &active(&policy),
        )
        .unwrap();
        assert!(matches!(
            evaluate(&active(&policy), &[verified]).unwrap().cohort["canary-a"],
            CohortResult::Failed { .. }
        ));

        let mut contradictory = outcome.clone();
        contradictory.rollback = RollbackOutcome::NotNeeded;
        assert!(
            VerifiedCanaryOutcome::verify(
                contradictory,
                &rollback,
                &attempt,
                Some(&deployment),
                true,
                &active(&policy)
            )
            .is_err()
        );

        outcome.plan_state = EvidencePlanState::Failed;
        outcome.execution = ExecutionOutcome::Failed;
        outcome.rollback = RollbackOutcome::FailedOrUnknown;
        rollback.state = PlanState::Failed;
        let attempt = attempt_for(&outcome);
        assert!(
            VerifiedCanaryOutcome::verify(
                outcome,
                &rollback,
                &attempt,
                None,
                false,
                &active(&policy)
            )
            .is_ok()
        );
    }

    #[test]
    fn every_attempt_is_retained_and_any_failure_blocks() {
        let policy = policy();
        let first_outcome = passing("canary-a", &policy);
        let mut second_outcome = first_outcome.clone();
        second_outcome.plan_id = "tenkai:plan:canary-a:2:content".into();
        second_outcome.plan_state = EvidencePlanState::Failed;
        second_outcome.execution = ExecutionOutcome::Failed;
        let first = verified(first_outcome, &policy);
        let second = verified(second_outcome, &policy);
        let result = evaluate(&active(&policy), &[second.clone(), first.clone()]).unwrap();
        assert_eq!(
            result.cohort["canary-a"],
            CohortResult::Failed {
                outcomes: vec![first.0, second.0]
            }
        );
        assert!(!result.allowed);
    }

    fn write_model_runtime_manifest(dir: &std::path::Path, product: &str, version: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let body = format!(
            r#"[product]
name = "{product}"
version = "{version}"
kind = "model_runtime"
description = "canary e2e fixture"

[model]
source = "hf://example/{product}"
revision = "fixture"
format = "gguf"
quantization = "Q4_K_M"
artifact_digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
license = "apache-2.0"

[runtime]
engine = "llama.cpp"
port = 18080
context_length = 4096

[requirements]
architecture = ["arm64", "x86_64"]
memory_gib = 8
accelerator = ["apple-metal", "cpu"]

[health]
endpoint = "http://127.0.0.1:18080/v1/models"
smoke_prompt = "OK"
max_startup_seconds = 30
"#
        );
        std::fs::write(dir.join("tenkai.toml"), body).unwrap();
    }

    async fn publish_unsigned_model(ctx: &mut Ctx, dir: &std::path::Path) -> String {
        let options = crate::catalog::PublishOptions {
            signature: None,
            trust_roots: None,
            allow_unsigned_development: true,
            provenance: Vec::new(),
            provenance_trust_roots: None,
        };
        crate::catalog::publish(ctx, &dir.join("tenkai.toml"), &options)
            .await
            .unwrap()
    }

    async fn apply_local_model_canary(ctx: &mut Ctx, product: &str, channel: &str) -> String {
        crate::plan::subscribe(ctx, "local", product, channel)
            .await
            .unwrap();
        crate::plan::set_environment_fact(ctx, "local", "architecture", "arm64")
            .await
            .unwrap();
        crate::plan::set_environment_fact(ctx, "local", "accelerator", "cpu")
            .await
            .unwrap();
        crate::plan::set_environment_fact(ctx, "local", "memory_gib", "16")
            .await
            .unwrap();
        let plan = crate::plan::create(ctx, "local").await.unwrap();
        assert!(
            !plan.steps.is_empty(),
            "expected model_runtime plan steps for local canary"
        );
        assert_eq!(plan.steps[0].product, product);
        let plan_id = plan.id.clone();
        // Do not skip gates: canary pass evidence requires GateOutcome::Satisfied.
        crate::apply::execute_with_options(
            ctx,
            &plan_id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "model_runtime canary e2e fixture",
                },
            },
        )
        .await
        .unwrap();
        plan_id
    }

    /// End-to-end: canary policy gates model_runtime promotion to a wider channel.
    ///
    /// Uses the built-in `local` environment (unsigned release + development apply
    /// bypass) and FakeInferenceEngine so default CI never needs a real llama binary.
    #[tokio::test]
    async fn model_runtime_canary_evidence_gates_stable_promotion() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-model-canary-e2e-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let manifest_dir = root.join("model");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        write_model_runtime_manifest(&manifest_dir, "qwen-canary", "1.0.0");

        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "canary host")
            .await
            .unwrap();
        // Second env exists for fleet realism; cohort uses only `local` because
        // unsigned development apply is restricted to that environment.
        crate::plan::env_add(&mut ctx, "stage", "wider env")
            .await
            .unwrap();

        publish_unsigned_model(&mut ctx, &manifest_dir).await;
        // Canary channel is free of promotion policy so the cohort can apply first.
        crate::catalog::promote(&mut ctx, "qwen-canary@1.0.0", "canary")
            .await
            .unwrap();

        set_designated(&mut ctx, "local", true).await.unwrap();
        configure(
            &mut ctx,
            "qwen-canary@1.0.0",
            "stable",
            vec!["local".into()],
            false,
        )
        .await
        .unwrap();

        // Missing canary evidence blocks wider promote with an actionable error.
        let missing = crate::catalog::promote(&mut ctx, "qwen-canary@1.0.0", "stable")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("canary promotion blocked") && missing.contains("local"),
            "expected missing-cohort error, got: {missing}"
        );

        // Successful model_runtime apply on the canary records policy-bound evidence.
        apply_local_model_canary(&mut ctx, "qwen-canary", "canary").await;

        let promoted = crate::catalog::promote(&mut ctx, "qwen-canary@1.0.0", "stable")
            .await
            .unwrap();
        assert!(
            promoted.contains("promoted") && promoted.contains("stable"),
            "{promoted}"
        );

        // Content/policy reactivation invalidates prior evidence (#7 invariant).
        configure(
            &mut ctx,
            "qwen-canary@1.0.0",
            "stable",
            vec!["local".into()],
            true,
        )
        .await
        .unwrap();
        let stale = crate::catalog::promote(&mut ctx, "qwen-canary@1.0.0", "stable")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            stale.contains("canary promotion blocked"),
            "expected stale evidence block after reactivate, got: {stale}"
        );

        // Failed cohort member: configure two-member policy; second env never applies.
        set_designated(&mut ctx, "stage", true).await.unwrap();
        // Promote a second model version without canary evidence to exercise missing.
        write_model_runtime_manifest(&manifest_dir, "qwen-canary", "1.1.0");
        publish_unsigned_model(&mut ctx, &manifest_dir).await;
        crate::catalog::promote(&mut ctx, "qwen-canary@1.1.0", "canary")
            .await
            .unwrap();
        configure(
            &mut ctx,
            "qwen-canary@1.1.0",
            "stable",
            vec!["local".into(), "stage".into()],
            false,
        )
        .await
        .unwrap();
        apply_local_model_canary(&mut ctx, "qwen-canary", "canary").await;
        let incomplete = crate::catalog::promote(&mut ctx, "qwen-canary@1.1.0", "stable")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            incomplete.contains("canary promotion blocked") && incomplete.contains("stage"),
            "expected incomplete multi-env cohort block, got: {incomplete}"
        );

        // No secrets in promote error text.
        for sample in [&missing, &stale, &incomplete] {
            assert!(!sample.contains("Bearer"));
            assert!(!sample.contains("token="));
            assert!(!sample.contains("TENKAI_MANAGEMENT_TOKEN"));
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn contradictory_release_and_unlinked_evidence_are_rejected() {
        let mut contradictory = policy();
        contradictory.release_id = "tenkai:release:other@1.2.3".into();
        assert!(contradictory.validate().is_err());

        let policy = policy();
        let mut outcome = passing("canary-a", &policy);
        let plan = plan_for(&outcome);
        let attempt = attempt_for(&outcome);
        outcome.plan_id.clear();
        assert!(
            VerifiedCanaryOutcome::verify(outcome, &plan, &attempt, None, false, &active(&policy))
                .is_err()
        );

        let mut wrong_environment = passing("canary-a", &policy);
        wrong_environment.plan_id = "tenkai:plan:canary-b:1:content".into();
        assert!(std::panic::catch_unwind(|| verified(wrong_environment, &policy)).is_err());

        let outcome = passing("canary-a", &policy);
        let attempt = attempt_for(&outcome);
        let deployment = deployment_for(&outcome);
        let mut inconsistent_plan = plan_for(&outcome);
        inconsistent_plan.state = PlanState::Failed;
        assert!(
            VerifiedCanaryOutcome::verify(
                outcome.clone(),
                &inconsistent_plan,
                &attempt,
                Some(&deployment),
                true,
                &active(&policy)
            )
            .is_err()
        );
        inconsistent_plan.state = PlanState::Succeeded;
        inconsistent_plan.gates_skipped = Some(true);
        assert!(
            VerifiedCanaryOutcome::verify(
                outcome,
                &inconsistent_plan,
                &attempt,
                Some(&deployment),
                true,
                &active(&policy)
            )
            .is_err()
        );
        inconsistent_plan.gates_skipped = Some(false);
        let mut late_deployment = deployment.clone();
        late_deployment.created = attempt.finished_at + 1;
        late_deployment.updated = late_deployment.created;
        assert!(
            VerifiedCanaryOutcome::verify(
                passing("canary-a", &policy),
                &inconsistent_plan,
                &attempt,
                Some(&late_deployment),
                true,
                &active(&policy)
            )
            .is_err()
        );
        let mut late_update = deployment.clone();
        late_update.updated = attempt.finished_at + 1;
        assert!(
            VerifiedCanaryOutcome::verify(
                passing("canary-a", &policy),
                &inconsistent_plan,
                &attempt,
                Some(&late_update),
                true,
                &active(&policy)
            )
            .is_err()
        );
        let unfinished_outcome = passing("canary-a", &policy);
        let mut unfinished_attempt = attempt.clone();
        unfinished_attempt.finished_at = unfinished_outcome.recorded_at + 1;
        assert!(
            VerifiedCanaryOutcome::verify(
                unfinished_outcome,
                &inconsistent_plan,
                &unfinished_attempt,
                Some(&deployment),
                true,
                &active(&policy)
            )
            .is_err()
        );

        let outcome = passing("canary-a", &policy);
        let mut rollback = plan_for(&outcome);
        let attempt = attempt_for(&outcome);
        rollback.steps[0].action = Action::Rollback;
        rollback.steps[0].from = Some("1.2.3".into());
        rollback.steps[0].restore = Some(ReleasePin {
            release_id: outcome.release_id.clone(),
            digest: outcome.release_digest.clone(),
            artifact_digest: outcome.artifact_digest.clone(),
            workdir: ".".into(),
        });
        assert!(
            VerifiedCanaryOutcome::verify(
                outcome,
                &rollback,
                &attempt,
                None,
                false,
                &active(&policy)
            )
            .is_err()
        );
    }
}
