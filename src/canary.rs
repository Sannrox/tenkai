//! Canary promotion policy and evidence evaluation.

use std::collections::{BTreeMap, BTreeSet, HashMap};

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

fn policy_id(product: &str, version: &str, target_channel: &str) -> String {
    format!("tenkai:canary-policy:{product}@{version}:{target_channel}")
}

fn policy_record_id(active: &ActiveCanaryPolicy) -> String {
    format!(
        "{}:{}:{}",
        policy_id(
            &active.policy.product,
            &active.policy.version,
            &active.policy.target_channel
        ),
        active.activated_at,
        active.digest
    )
}

fn designation_id(environment: &str) -> String {
    format!("tenkai:canary-designation:{environment}")
}

const POLICY_DISCOVERY_LOCK_CHANNEL: &str = "_policy-index";
const RELEASED_PROMOTION_LOCK_OWNER: &str = "released";
const REL_ACTIVE_PROMOTION_LOCK: &str = "active_promotion_lock";

pub(crate) struct PromotionLock {
    id: String,
    owner: String,
}

fn promotion_lock_link(lock_id: &str) -> Link {
    Link {
        id: format!("{lock_id}--{REL_ACTIVE_PROMOTION_LOCK}"),
        from_id: lock_id.into(),
        to_id: lock_id.into(),
        relation: REL_ACTIVE_PROMOTION_LOCK.into(),
        created: crate::now_millis(),
    }
}

pub(crate) async fn claim_promotion_lock(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
    owner: &str,
) -> Result<PromotionLock> {
    crate::ontology::require_canary_schema(ctx).await?;
    let now = crate::now_millis();
    let lock = PromotionLock {
        id: format!("tenkai:promotion-lock:{product}:{target_channel}"),
        owner: owner.into(),
    };
    let mut object = Object {
        id: lock.id.clone(),
        kind: KIND_PROMOTION_LOCK.into(),
        name: format!("{product}/{target_channel} promotion lock"),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([("owner".into(), RELEASED_PROMOTION_LOCK_OWNER.into())]),
        created: now,
        updated: now,
    };
    if ctx.get(&lock.id).await?.is_none() {
        match ctx.create_once(object.clone()).await {
            Ok(_) => {}
            Err(status)
                if status.code() == tonic::Code::AlreadyExists
                    || (status.code() == tonic::Code::Internal
                        && status.message().contains("UNIQUE")) => {}
            Err(status) => return Err(status.into()),
        }
    }
    match ctx.create_link_once(promotion_lock_link(&lock.id)).await {
        Ok(_) => {
            object.properties.insert("owner".into(), lock.owner.clone());
            object.updated = crate::now_millis();
            if let Err(error) = ctx.put(object).await {
                let _ = ctx
                    .unlink(&lock.id, &lock.id, REL_ACTIVE_PROMOTION_LOCK)
                    .await;
                return Err(error);
            }
            Ok(lock)
        }
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE")) =>
        {
            bail!("promotion or policy update already in progress for {product}/{target_channel}")
        }
        Err(status) => Err(status.into()),
    }
}

async fn claim_promotion_lock_with_retry(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
    owner: &str,
) -> Result<PromotionLock> {
    const MAX_ATTEMPTS: usize = 100;
    for attempt in 0..MAX_ATTEMPTS {
        match claim_promotion_lock(ctx, product, target_channel, owner).await {
            Ok(lock) => return Ok(lock),
            Err(error)
                if attempt + 1 < MAX_ATTEMPTS
                    && error.to_string().contains("already in progress") =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded lock retry loop always returns")
}

pub(crate) async fn confirm_promotion_lock(ctx: &mut Ctx, lock: &PromotionLock) -> Result<()> {
    let object = ctx
        .get(&lock.id)
        .await?
        .with_context(|| format!("promotion lock {} was lost", lock.id))?;
    if !ctx
        .links(&lock.id, REL_ACTIVE_PROMOTION_LOCK)
        .await?
        .iter()
        .any(|link| link.to_id == lock.id)
        || object.properties.get("owner") != Some(&lock.owner)
    {
        bail!(
            "promotion lock {} is no longer owned by this operation",
            lock.id
        );
    }
    Ok(())
}

pub async fn unlock_promotion(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
) -> Result<String> {
    validate_identifier("product", product)?;
    if target_channel != POLICY_DISCOVERY_LOCK_CHANNEL {
        validate_identifier("channel", target_channel)?;
    }
    let id = format!("tenkai:promotion-lock:{product}:{target_channel}");
    let active_link = promotion_lock_link(&id);
    if !ctx
        .links(&id, REL_ACTIVE_PROMOTION_LOCK)
        .await?
        .iter()
        .any(|link| link.id == active_link.id)
    {
        return Ok(format!(
            "no promotion lock exists for {product}/{target_channel}"
        ));
    }
    if let Some(mut object) = ctx.get(&id).await? {
        object
            .properties
            .insert("owner".into(), RELEASED_PROMOTION_LOCK_OWNER.into());
        object.updated = crate::now_millis();
        ctx.put(object).await?;
    }
    ctx.unlink(&id, &id, REL_ACTIVE_PROMOTION_LOCK).await?;
    Ok(format!(
        "promotion lock removed for {product}/{target_channel}"
    ))
}

pub(crate) async fn release_promotion_lock(ctx: &mut Ctx, lock: &PromotionLock) -> Result<()> {
    if let Some(object) = ctx.get(&lock.id).await?
        && object.properties.get("owner") == Some(&lock.owner)
    {
        let mut object = object;
        object
            .properties
            .insert("owner".into(), RELEASED_PROMOTION_LOCK_OWNER.into());
        object.updated = crate::now_millis();
        ctx.put(object).await?;
        ctx.unlink(&lock.id, &lock.id, REL_ACTIVE_PROMOTION_LOCK)
            .await?;
    }
    Ok(())
}

async fn claim_policy_locks(
    ctx: &mut Ctx,
    policies: &[ActiveCanaryPolicy],
    owner: &str,
) -> Result<Vec<PromotionLock>> {
    let keys = policies
        .iter()
        .map(|active| {
            (
                active.policy.product.clone(),
                active.policy.target_channel.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut locks = Vec::new();
    for (product, target_channel) in keys {
        match claim_promotion_lock_with_retry(ctx, &product, &target_channel, owner).await {
            Ok(lock) => locks.push(lock),
            Err(error) => {
                for lock in locks.iter().rev() {
                    let _ = release_promotion_lock(ctx, lock).await;
                }
                return Err(error);
            }
        }
    }
    Ok(locks)
}

async fn release_policy_locks(ctx: &mut Ctx, locks: &[PromotionLock]) -> Result<()> {
    let mut first_error = None;
    for lock in locks.iter().rev() {
        if let Err(error) = release_promotion_lock(ctx, lock).await {
            first_error.get_or_insert(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(())
}

fn object_property<'a>(object: &'a Object, name: &str) -> Result<&'a str> {
    object
        .properties
        .get(name)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .with_context(|| format!("object {} has no {name}", object.id))
}

fn active_from_object(object: &Object) -> Result<ActiveCanaryPolicy> {
    if object.kind != KIND_CANARY_POLICY {
        bail!(
            "object {} is {}, not {KIND_CANARY_POLICY}",
            object.id,
            object.kind
        );
    }
    if object_property(object, "active")? != "true" {
        bail!("canary policy object {} is not active", object.id);
    }
    let policy: CanaryPolicy = serde_json::from_str(object_property(object, "policy")?)
        .with_context(|| format!("canary policy object {} has invalid JSON", object.id))?;
    let active = ActiveCanaryPolicy::new(policy, object.updated)?;
    if object.id != policy_record_id(&active)
        || object_property(object, "policy_digest")? != active.digest
        || object_property(object, "release_id")? != active.policy.release_id
    {
        bail!(
            "canary policy object {} has inconsistent identity",
            object.id
        );
    }
    Ok(active)
}

async fn active_from_pointer(ctx: &mut Ctx, pointer: &Object) -> Result<ActiveCanaryPolicy> {
    if pointer.kind != KIND_CANARY_POLICY_POINTER {
        bail!(
            "object {} is {}, not {KIND_CANARY_POLICY_POINTER}",
            pointer.id,
            pointer.kind
        );
    }
    let policy_object_id = object_property(pointer, "policy_id")?;
    let object = ctx
        .get(policy_object_id)
        .await?
        .with_context(|| format!("active canary policy {policy_object_id} is missing"))?;
    let active = active_from_object(&object)?;
    if pointer.id
        != policy_id(
            &active.policy.product,
            &active.policy.version,
            &active.policy.target_channel,
        )
        || object_property(pointer, "release_id")? != active.policy.release_id
        || object_property(pointer, "target_channel")? != active.policy.target_channel
        || object_property(pointer, "policy_digest")? != active.digest
    {
        bail!(
            "canary policy pointer {} has inconsistent identity",
            pointer.id
        );
    }
    Ok(active)
}

pub async fn set_designated(ctx: &mut Ctx, environment: &str, designated: bool) -> Result<String> {
    crate::ontology::require_canary_schema(ctx).await?;
    validate_identifier("environment", environment)?;
    let id = env_id(environment);
    let owner = format!("canary-designation:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = async {
        let environment_object = ctx
            .get(&id)
            .await?
            .with_context(|| format!("environment {environment} is not registered"))?;
        if environment_object.kind != KIND_ENVIRONMENT {
            bail!(
                "object {id} is {}, not {KIND_ENVIRONMENT}",
                environment_object.kind
            );
        }
        let designation_id = designation_id(environment);
        if designated {
            let now = crate::now_millis();
            ctx.put(Object {
                id: designation_id,
                kind: KIND_CANARY_DESIGNATION.into(),
                name: format!("{environment} canary designation"),
                namespace: NS.into(),
                external_id: String::new(),
                properties: HashMap::from([("environment".into(), environment.into())]),
                created: now,
                updated: now,
            })
            .await?;
        } else if ctx.get(&designation_id).await?.is_some() {
            ctx.delete(&designation_id).await?;
        }
        Ok::<_, anyhow::Error>(format!(
            "environment {environment} {} as canary",
            if designated { "designated" } else { "removed" }
        ))
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing canary designation lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing canary designation lease failed")),
    }
}

async fn is_designated(ctx: &mut Ctx, environment: &str, product: &str) -> Result<bool> {
    let object = ctx
        .get(&env_id(environment))
        .await?
        .with_context(|| format!("environment {environment} is not registered"))?;
    if let Some(designation) = ctx.get(&designation_id(environment)).await? {
        if designation.kind != KIND_CANARY_DESIGNATION
            || designation
                .properties
                .get("environment")
                .map(String::as_str)
                != Some(environment)
        {
            bail!("canary designation for {environment} is inconsistent");
        }
        return Ok(true);
    }
    Ok(ctx
        .linked(&object.id, REL_SUBSCRIBES, "out")
        .await?
        .iter()
        .any(|channel| {
            channel
                .properties
                .get("product")
                .is_some_and(|value| value == product)
                && channel
                    .properties
                    .get("channel")
                    .is_some_and(|value| value == "canary")
        }))
}

pub async fn configure(
    ctx: &mut Ctx,
    spec: &str,
    target_channel: &str,
    cohort: Vec<String>,
    reactivate: bool,
) -> Result<ActiveCanaryPolicy> {
    let product = spec
        .split_once('@')
        .map(|(product, _)| product)
        .unwrap_or(spec);
    validate_identifier("product", product)?;
    validate_identifier("channel", target_channel)?;
    let owner = format!("policy:{spec}:{}", crate::now_millis());
    let discovery =
        claim_promotion_lock(ctx, product, POLICY_DISCOVERY_LOCK_CHANNEL, &owner).await?;
    let target = match claim_promotion_lock(ctx, product, target_channel, &owner).await {
        Ok(lock) => lock,
        Err(error) => {
            let release = release_promotion_lock(ctx, &discovery).await;
            return match release {
                Ok(()) => Err(error),
                Err(unlock) => Err(error.context(format!(
                    "releasing policy discovery lock also failed: {unlock}"
                ))),
            };
        }
    };
    let result = configure_locked(ctx, spec, target_channel, cohort, reactivate, &target).await;
    let mut unlock_error = release_promotion_lock(ctx, &target).await.err();
    if let Err(error) = release_promotion_lock(ctx, &discovery).await {
        unlock_error.get_or_insert(error);
    }
    match (result, unlock_error) {
        (Ok(policy), None) => Ok(policy),
        (Err(error), None) => Err(error),
        (Err(error), Some(unlock)) => {
            Err(error.context(format!("releasing policy locks also failed: {unlock}")))
        }
        (Ok(_), Some(error)) => Err(error.context("releasing policy locks failed")),
    }
}

async fn configure_locked(
    ctx: &mut Ctx,
    spec: &str,
    target_channel: &str,
    cohort: Vec<String>,
    reactivate: bool,
    lock: &PromotionLock,
) -> Result<ActiveCanaryPolicy> {
    let (product, version) = spec
        .split_once('@')
        .with_context(|| format!("expected <product>@<version>, got {spec:?}"))?;
    validate_identifier("product", product)?;
    validate_identifier("version", version)?;
    validate_identifier("channel", target_channel)?;
    let release_id = release_id(product, version);
    let release = ctx
        .get(&release_id)
        .await?
        .with_context(|| format!("release {spec} is not published"))?;
    for environment in &cohort {
        if !is_designated(ctx, environment, product).await? {
            bail!(
                "environment {environment} is not designated as a canary or subscribed to {product}/canary"
            );
        }
    }
    let policy = CanaryPolicy {
        release_id: release_id.clone(),
        release_digest: object_property(&release, "digest")?.into(),
        artifact_digest: object_property(&release, "artifact_digest")?.into(),
        product: product.into(),
        version: version.into(),
        target_channel: target_channel.into(),
        cohort,
        success_policy: SuccessPolicy::All,
    }
    .canonicalized()?;
    let pointer_id = policy_id(product, version, target_channel);
    let existing = ctx.get(&pointer_id).await?;
    if let Some(pointer) = existing.as_ref() {
        let current = active_from_pointer(ctx, pointer).await?;
        if current.policy == policy && !reactivate {
            return Ok(current);
        }
    }
    let now = crate::now_millis();
    let activated_at = existing
        .as_ref()
        .map_or(now, |pointer| now.max(pointer.updated.saturating_add(1)));
    let active = ActiveCanaryPolicy::new(policy, activated_at)?;
    let record_id = policy_record_id(&active);
    let object = Object {
        id: record_id.clone(),
        kind: KIND_CANARY_POLICY.into(),
        name: format!("{spec} promotion to {target_channel}"),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("release_id".into(), active.policy.release_id.clone()),
            (
                "release_digest".into(),
                active.policy.release_digest.clone(),
            ),
            (
                "artifact_digest".into(),
                active.policy.artifact_digest.clone(),
            ),
            ("target_channel".into(), target_channel.into()),
            ("policy_digest".into(), active.digest.clone()),
            ("active".into(), "true".into()),
            ("policy".into(), serde_json::to_string(&active.policy)?),
        ]),
        created: activated_at,
        updated: activated_at,
    };
    confirm_promotion_lock(ctx, lock).await?;
    ctx.create_once(object).await?;
    ctx.link(&record_id, &release_id, REL_GOVERNS_RELEASE)
        .await?;
    let pointer = Object {
        id: pointer_id,
        kind: KIND_CANARY_POLICY_POINTER.into(),
        name: format!("active {spec} promotion to {target_channel}"),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("release_id".into(), active.policy.release_id.clone()),
            ("target_channel".into(), target_channel.into()),
            ("policy_id".into(), record_id),
            ("policy_digest".into(), active.digest.clone()),
        ]),
        created: existing
            .as_ref()
            .map_or(activated_at, |pointer| pointer.created),
        updated: activated_at,
    };
    confirm_promotion_lock(ctx, lock).await?;
    ctx.put(pointer).await?;
    Ok(active)
}

pub async fn active_policy(
    ctx: &mut Ctx,
    product: &str,
    version: &str,
    target_channel: &str,
) -> Result<ActiveCanaryPolicy> {
    let id = policy_id(product, version, target_channel);
    let object = ctx.get(&id).await?.with_context(|| {
        format!("no canary policy configured for {product}@{version} -> {target_channel}")
    })?;
    active_from_pointer(ctx, &object).await
}

async fn policies_for_release(ctx: &mut Ctx, release: &str) -> Result<Vec<ActiveCanaryPolicy>> {
    let pointers = ctx
        .find_by_property(KIND_CANARY_POLICY_POINTER, "release_id", release)
        .await?;
    let mut policies = Vec::with_capacity(pointers.len());
    for pointer in &pointers {
        policies.push(active_from_pointer(ctx, pointer).await?);
    }
    Ok(policies)
}

async fn maybe_active_policy(
    ctx: &mut Ctx,
    product: &str,
    version: &str,
    target_channel: &str,
) -> Result<Option<ActiveCanaryPolicy>> {
    let pointer = ctx
        .get(&policy_id(product, version, target_channel))
        .await?;
    match pointer.as_ref() {
        Some(pointer) => Ok(Some(active_from_pointer(ctx, pointer).await?)),
        None => Ok(None),
    }
}

async fn record_promotion_audit(
    ctx: &mut Ctx,
    active: &ActiveCanaryPolicy,
    evaluation: &PromotionEvaluation,
) -> Result<()> {
    let evaluated_at = crate::now_millis();
    let serialized = serde_json::to_string(evaluation)?;
    let policy_object_id = policy_record_id(active);
    for sequence in 0..1024_u16 {
        let id = format!(
            "{}:promotion-audit:{}:{evaluated_at}:{sequence}",
            active.policy.release_id, active.policy.target_channel
        );
        let object = Object {
            id: id.clone(),
            kind: KIND_PROMOTION_AUDIT.into(),
            name: format!(
                "{} promotion to {}",
                active.policy.release_id, active.policy.target_channel
            ),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("release_id".into(), active.policy.release_id.clone()),
                (
                    "target_channel".into(),
                    active.policy.target_channel.clone(),
                ),
                ("policy_digest".into(), active.digest.clone()),
                (
                    "policy_activated_at".into(),
                    evaluation.policy_activated_at.to_string(),
                ),
                ("allowed".into(), evaluation.allowed.to_string()),
                ("evaluated_at".into(), evaluated_at.to_string()),
                ("evaluation".into(), serialized.clone()),
            ]),
            created: evaluated_at,
            updated: evaluated_at,
        };
        match ctx.create_once(object).await {
            Ok(_) => {
                ctx.link(&id, &active.policy.release_id, REL_AUDITS_PROMOTION)
                    .await?;
                ctx.link(&id, &policy_object_id, REL_EVIDENCE_FOR_POLICY)
                    .await?;
                return Ok(());
            }
            Err(status)
                if status.code() == tonic::Code::AlreadyExists
                    || (status.code() == tonic::Code::Internal
                        && status.message().contains("UNIQUE")) => {}
            Err(status) => return Err(status.into()),
        }
    }
    bail!(
        "could not allocate promotion audit for {}",
        active.policy.release_id
    )
}

pub async fn authorize_promotion(
    ctx: &mut Ctx,
    product: &str,
    version: &str,
    target_channel: &str,
) -> Result<Option<ActiveCanaryPolicy>> {
    let Some(active) = maybe_active_policy(ctx, product, version, target_channel).await? else {
        return Ok(None);
    };
    let evaluation = evaluate_active(ctx, &active).await?;
    record_promotion_audit(ctx, &active, &evaluation).await?;
    if !evaluation.allowed {
        let blocked = evaluation
            .cohort
            .iter()
            .filter_map(|(environment, result)| {
                (!matches!(result, CohortResult::Passed { .. })).then_some(environment.as_str())
            })
            .collect::<Vec<_>>();
        bail!(
            "canary promotion blocked for {product}@{version} -> {target_channel}: {}",
            blocked.join(", ")
        );
    }
    Ok(Some(active))
}

pub async fn confirm_policy_active(ctx: &mut Ctx, expected: &ActiveCanaryPolicy) -> Result<()> {
    let current = active_policy(
        ctx,
        &expected.policy.product,
        &expected.policy.version,
        &expected.policy.target_channel,
    )
    .await?;
    if current != *expected {
        bail!("canary policy changed after promotion authorization");
    }
    Ok(())
}

fn evidence_release(step: &crate::plan::Step) -> Option<&str> {
    match step.action {
        Action::Rollback => step.restore.as_ref().map(|pin| pin.release_id.as_str()),
        Action::Install | Action::Upgrade | Action::Downgrade => Some(&step.release_id),
    }
}

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
