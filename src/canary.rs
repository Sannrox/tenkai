//! Canary promotion policy and evidence evaluation.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::ontology::KIND_DEPLOYMENT;
use crate::ontology::{release_id, validate_identifier};
use crate::pb::sekai::Object;
use crate::plan::{Action, Plan, PlanState};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveCanaryPolicy {
    policy: CanaryPolicy,
    digest: String,
    activated_at: i64,
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

    fn passing(environment: &str, policy: &CanaryPolicy) -> CanaryOutcome {
        CanaryOutcome {
            release_id: policy.release_id.clone(),
            release_digest: policy.release_digest.clone(),
            artifact_digest: policy.artifact_digest.clone(),
            policy_digest: policy.digest().unwrap(),
            policy_activated_at: 1,
            environment: environment.into(),
            plan_id: format!("tenkai:plan:{environment}:1:content"),
            attempt_id: format!("tenkai:plan:{environment}:1:content:attempt:0"),
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
