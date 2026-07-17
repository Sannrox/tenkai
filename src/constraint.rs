//! Typed, graph-backed constraints and their environment-scoped lifecycle.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::ontology::*;
use crate::pb::sekai::Object;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum ConstraintTarget {
    Environment {
        environment: String,
    },
    Subscription {
        environment: String,
        channel_id: String,
    },
}

impl ConstraintTarget {
    pub fn environment(&self) -> &str {
        match self {
            Self::Environment { environment } | Self::Subscription { environment, .. } => {
                environment
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    pub id: String,
    pub identity: String,
    pub kind: String,
    pub parameters: BTreeMap<String, String>,
    pub enabled: bool,
    pub reason: String,
    pub target: ConstraintTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationResult {
    Allow,
    Deny,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintEvaluation {
    pub constraint_id: String,
    pub identity: String,
    pub kind: String,
    pub parameters: BTreeMap<String, String>,
    pub enabled: bool,
    pub reason: String,
    pub target: ConstraintTarget,
    pub result: EvaluationResult,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintEvaluationSnapshot {
    pub evaluated_at: i64,
    pub evaluations: Vec<ConstraintEvaluation>,
}

pub async fn record_execution_evaluation(
    ctx: &mut Ctx,
    plan_id: &str,
    environment: &str,
    evaluations: Vec<ConstraintEvaluation>,
) -> Result<()> {
    validate_identifier("environment", environment)?;
    let evaluated_at = crate::now_millis();
    let snapshot = ConstraintEvaluationSnapshot {
        evaluated_at,
        evaluations,
    };
    let existing = ctx
        .links(plan_id, REL_HAS_CONSTRAINT_EVALUATION)
        .await?
        .len() as u64;
    for sequence in existing..existing.saturating_add(1024) {
        let id = format!("{plan_id}:constraint-evaluation:{sequence}");
        let object = Object {
            id: id.clone(),
            kind: KIND_CONSTRAINT_EVALUATION.into(),
            name: format!("{environment} constraint evaluation {sequence}"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("plan_id".into(), plan_id.into()),
                ("environment".into(), environment.into()),
                ("evaluated_at".into(), evaluated_at.to_string()),
                ("sequence".into(), sequence.to_string()),
                ("evaluations".into(), serde_json::to_string(&snapshot)?),
            ]),
            created: evaluated_at,
            updated: evaluated_at,
        };
        match ctx.create_once(object).await {
            Ok(_) => {
                ctx.link(plan_id, &id, REL_HAS_CONSTRAINT_EVALUATION)
                    .await
                    .context("linking execution-time constraint evidence to its plan")?;
                return Ok(());
            }
            Err(status)
                if status.code() == tonic::Code::AlreadyExists
                    || (status.code() == tonic::Code::Internal
                        && status.message().contains("UNIQUE")) => {}
            Err(status) => {
                return Err(status)
                    .context("persisting immutable execution-time constraint evidence");
            }
        }
    }
    bail!("could not allocate an execution-time constraint evaluation id for plan {plan_id}")
}

impl Constraint {
    fn to_object(&self, now: i64) -> Result<Object> {
        let (target_kind, environment, channel_id) = match &self.target {
            ConstraintTarget::Environment { environment } => {
                ("environment", environment.as_str(), None)
            }
            ConstraintTarget::Subscription {
                environment,
                channel_id,
            } => (
                "subscription",
                environment.as_str(),
                Some(channel_id.as_str()),
            ),
        };
        let mut properties = HashMap::from([
            ("identity".into(), self.identity.clone()),
            ("constraint_kind".into(), self.kind.clone()),
            (
                "parameters".into(),
                serde_json::to_string(&self.parameters)?,
            ),
            ("enabled".into(), self.enabled.to_string()),
            ("reason".into(), self.reason.clone()),
            ("target_kind".into(), target_kind.into()),
            ("environment".into(), environment.into()),
        ]);
        if let Some(channel_id) = channel_id {
            properties.insert("channel_id".into(), channel_id.into());
        }
        Ok(Object {
            id: self.id.clone(),
            kind: KIND_CONSTRAINT.into(),
            name: format!("{} constraint {}", environment, self.identity),
            namespace: NS.into(),
            external_id: String::new(),
            properties,
            created: now,
            updated: now,
        })
    }

    fn from_object(object: &Object) -> Result<Self> {
        if object.kind != KIND_CONSTRAINT {
            bail!(
                "object {} is {}, not {KIND_CONSTRAINT}",
                object.id,
                object.kind
            );
        }
        let property = |name: &str| {
            object
                .properties
                .get(name)
                .filter(|value| !value.is_empty())
                .with_context(|| format!("constraint object {} has no {name}", object.id))
        };
        let identity = property("identity")?.clone();
        let environment = property("environment")?.clone();
        let expected_id = constraint_id(&environment, &identity);
        if object.id != expected_id {
            bail!(
                "constraint object {} does not match identity {} in environment {}",
                object.id,
                identity,
                environment
            );
        }
        let target = match property("target_kind")?.as_str() {
            "environment" => ConstraintTarget::Environment {
                environment: environment.clone(),
            },
            "subscription" => ConstraintTarget::Subscription {
                environment: environment.clone(),
                channel_id: property("channel_id")?.clone(),
            },
            other => bail!("constraint {} has unknown target kind {other:?}", object.id),
        };
        let enabled = property("enabled")?
            .parse::<bool>()
            .with_context(|| format!("constraint {} has invalid enabled state", object.id))?;
        let parameters = serde_json::from_str::<BTreeMap<String, String>>(property("parameters")?)
            .with_context(|| format!("constraint {} has invalid parameters", object.id))?;
        Ok(Self {
            id: object.id.clone(),
            identity,
            kind: property("constraint_kind")?.clone(),
            parameters,
            enabled,
            reason: property("reason")?.clone(),
            target,
        })
    }
}

fn validate(constraint: &Constraint) -> Result<()> {
    validate_identifier("constraint identity", &constraint.identity)?;
    validate_identifier("constraint kind", &constraint.kind)?;
    validate_identifier("environment", constraint.target.environment())?;
    if constraint.reason.trim().is_empty() {
        bail!("constraint reason must not be empty");
    }
    for key in constraint.parameters.keys() {
        validate_identifier("constraint parameter", key)?;
    }
    if constraint.id != constraint_id(constraint.target.environment(), &constraint.identity) {
        bail!("constraint id does not match its environment and identity");
    }
    Ok(())
}

async fn target_exists(ctx: &mut Ctx, target: &ConstraintTarget) -> Result<()> {
    let environment = target.environment();
    let eid = env_id(environment);
    if ctx.get(&eid).await?.is_none() {
        bail!("environment {environment} is not registered (tenkaictl env add {environment})");
    }
    if let ConstraintTarget::Subscription { channel_id, .. } = target {
        let links = ctx.links(&eid, REL_SUBSCRIBES).await?;
        if !links.iter().any(|link| link.to_id == *channel_id) {
            bail!("environment {environment} is not subscribed to channel object {channel_id}");
        }
    }
    Ok(())
}

fn constraints_from_environment(
    object: &Object,
    environment: &str,
) -> Result<BTreeMap<String, Constraint>> {
    if object.kind != KIND_ENVIRONMENT {
        bail!(
            "object {} is {}, not {KIND_ENVIRONMENT}",
            object.id,
            object.kind
        );
    }
    let constraints = match object.properties.get("constraints") {
        Some(raw) => serde_json::from_str::<BTreeMap<String, Constraint>>(raw)
            .with_context(|| format!("environment {environment} has invalid constraints"))?,
        None => BTreeMap::new(),
    };
    for (identity, constraint) in &constraints {
        validate(constraint)?;
        if identity != &constraint.identity || constraint.target.environment() != environment {
            bail!("environment {environment} has inconsistent constraint {identity}");
        }
    }
    Ok(constraints)
}

async fn project_constraint(
    ctx: &mut Ctx,
    constraint: &Constraint,
    expected_previous: Option<&Constraint>,
) -> Result<()> {
    let now = crate::now_millis();
    let mut projection = constraint.to_object(now)?;
    if let Some(existing) = ctx.get(&constraint.id).await? {
        let existing_constraint = Constraint::from_object(&existing).with_context(|| {
            format!(
                "constraint projection id {} is already in use",
                constraint.id
            )
        })?;
        if existing_constraint != *constraint && expected_previous != Some(&existing_constraint) {
            bail!(
                "constraint projection id {} contains conflicting content",
                constraint.id
            );
        }
        projection.created = existing.created;
    }
    if let Err(error) = ctx.put(projection).await {
        let confirmed = ctx.get(&constraint.id).await?.is_some_and(|object| {
            matches!(
                Constraint::from_object(&object),
                Ok(ref existing) if existing == constraint
            )
        });
        if !confirmed {
            return Err(error.context("projecting constraint into the graph"));
        }
    }
    repair_links(ctx, constraint).await
}

async fn remove_projection(ctx: &mut Ctx, constraint: &Constraint) -> Result<()> {
    let mut failures = Vec::new();
    let environment_id = env_id(constraint.target.environment());
    if let Err(error) = ctx
        .unlink(&constraint.id, &environment_id, REL_CONSTRAINS_ENVIRONMENT)
        .await
    {
        failures.push(format!("unlinking environment projection: {error}"));
    }
    if let ConstraintTarget::Subscription { channel_id, .. } = &constraint.target
        && let Err(error) = ctx
            .unlink(&constraint.id, channel_id, REL_CONSTRAINS_SUBSCRIPTION)
            .await
    {
        failures.push(format!("unlinking subscription projection: {error}"));
    }
    match ctx.get(&constraint.id).await {
        Ok(Some(_)) => {
            if let Err(error) = ctx.delete(&constraint.id).await {
                failures.push(format!("deleting constraint projection: {error}"));
            }
        }
        Ok(None) => {}
        Err(error) => failures.push(format!("checking constraint projection: {error}")),
    }
    match ctx.get(&constraint.id).await {
        Ok(None) => {}
        Ok(Some(_)) => failures.push("constraint projection still exists after cleanup".into()),
        Err(error) => failures.push(format!("verifying constraint projection cleanup: {error}")),
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("; "))
    }
}

async fn create_locked(ctx: &mut Ctx, constraint: &Constraint) -> Result<()> {
    target_exists(ctx, &constraint.target).await?;
    let environment = constraint.target.environment();
    let mut object = ctx
        .get(&env_id(environment))
        .await?
        .with_context(|| format!("environment {environment} is not registered"))?;
    let mut constraints = constraints_from_environment(&object, environment)?;
    let previous_constraints = constraints.clone();
    if let Some(existing) = constraints.get(&constraint.identity) {
        if existing != constraint {
            bail!(
                "constraint {} already exists with different content",
                constraint.identity
            );
        }
        return project_constraint(ctx, constraint, None).await;
    }
    let projection_existed = ctx.get(&constraint.id).await?.is_some();
    if let Err(error) = project_constraint(ctx, constraint, None).await {
        if projection_existed {
            return Err(error);
        }
        return match remove_projection(ctx, constraint).await {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "cleaning up failed constraint projection also failed: {cleanup}"
            ))),
        };
    }
    constraints.insert(constraint.identity.clone(), constraint.clone());
    object
        .properties
        .insert("constraints".into(), serde_json::to_string(&constraints)?);
    object.updated = crate::now_millis();
    if let Err(error) = ctx.put(object).await {
        match ctx.get(&env_id(environment)).await {
            Ok(Some(current)) => match constraints_from_environment(&current, environment) {
                Ok(current) if current == constraints => return Ok(()),
                Ok(current) if current == previous_constraints => {}
                Ok(_) => {
                    return Err(error.context(
                        "persisting canonical constraint had an ambiguous outcome: canonical state changed unexpectedly; projection left in the requested state for retry reconciliation",
                    ));
                }
                Err(read_error) => {
                    return Err(error.context(format!(
                        "persisting canonical constraint had an ambiguous outcome and rereading canonical state failed validation: {read_error}; projection left in the requested state for retry reconciliation"
                    )));
                }
            },
            Ok(None) => {
                return Err(error.context(
                    "persisting canonical constraint had an ambiguous outcome: environment disappeared; projection left in the requested state for retry reconciliation",
                ));
            }
            Err(read_error) => {
                return Err(error.context(format!(
                    "persisting canonical constraint had an ambiguous outcome and rereading canonical state failed: {read_error}; projection left in the requested state for retry reconciliation"
                )));
            }
        }
        if projection_existed {
            return Err(error.context("persisting canonical constraint"));
        }
        return match remove_projection(ctx, constraint).await {
            Ok(()) => Err(error.context("persisting canonical constraint")),
            Err(cleanup) => Err(error.context(format!(
                "persisting canonical constraint failed and projection cleanup also failed: {cleanup}"
            ))),
        };
    }
    Ok(())
}

async fn repair_links(ctx: &mut Ctx, constraint: &Constraint) -> Result<()> {
    let environment_id = env_id(constraint.target.environment());
    ctx.link(&constraint.id, &environment_id, REL_CONSTRAINS_ENVIRONMENT)
        .await
        .context("linking constraint to its environment")?;
    if let ConstraintTarget::Subscription { channel_id, .. } = &constraint.target {
        ctx.link(&constraint.id, channel_id, REL_CONSTRAINS_SUBSCRIPTION)
            .await
            .context("linking constraint to its subscription")?;
    }
    Ok(())
}

pub async fn create(
    ctx: &mut Ctx,
    identity: &str,
    kind: &str,
    parameters: BTreeMap<String, String>,
    enabled: bool,
    reason: &str,
    target: ConstraintTarget,
) -> Result<Constraint> {
    let constraint = Constraint {
        id: constraint_id(target.environment(), identity),
        identity: identity.into(),
        kind: kind.into(),
        parameters,
        enabled,
        reason: reason.trim().into(),
        target,
    };
    validate(&constraint)?;
    let environment = constraint.target.environment().to_string();
    let owner = format!("constraint-create:{identity}:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, &environment, &owner).await?;
    let result = create_locked(ctx, &constraint).await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(()), Ok(())) => Ok(constraint),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing environment constraint lease also failed: {unlock}"
        ))),
        (Ok(()), Err(error)) => Err(error.context("releasing environment constraint lease")),
    }
}

pub async fn list(ctx: &mut Ctx, environment: &str) -> Result<Vec<Constraint>> {
    validate_identifier("environment", environment)?;
    let object = ctx.get(&env_id(environment)).await?.with_context(|| {
        format!("environment {environment} is not registered (tenkaictl env add {environment})")
    })?;
    Ok(constraints_from_environment(&object, environment)?
        .into_values()
        .collect())
}

async fn set_enabled_locked(
    ctx: &mut Ctx,
    environment: &str,
    identity: &str,
    enabled: bool,
) -> Result<Constraint> {
    let mut object = ctx
        .get(&env_id(environment))
        .await?
        .with_context(|| format!("environment {environment} is not registered"))?;
    let mut constraints = constraints_from_environment(&object, environment)?;
    let mut constraint = constraints
        .get(identity)
        .cloned()
        .with_context(|| format!("constraint {identity} not found in environment {environment}"))?;
    if constraint.enabled == enabled {
        project_constraint(ctx, &constraint, None).await?;
        return Ok(constraint);
    }
    let previous = constraint.clone();
    let previous_constraints = constraints.clone();
    constraint.enabled = enabled;
    if let Err(error) = project_constraint(ctx, &constraint, Some(&previous)).await {
        return match project_constraint(ctx, &previous, Some(&constraint)).await {
            Ok(()) => Err(error),
            Err(restore) => Err(error.context(format!(
                "restoring previous constraint projection also failed: {restore}"
            ))),
        };
    }
    constraints.insert(identity.into(), constraint.clone());
    object
        .properties
        .insert("constraints".into(), serde_json::to_string(&constraints)?);
    object.updated = crate::now_millis();
    if let Err(error) = ctx.put(object).await {
        match ctx.get(&env_id(environment)).await {
            Ok(Some(current)) => match constraints_from_environment(&current, environment) {
                Ok(current) if current == constraints => {}
                Ok(current) if current == previous_constraints => {
                    return match project_constraint(ctx, &previous, Some(&constraint)).await {
                        Ok(()) => Err(error.context("persisting canonical constraint state")),
                        Err(restore) => Err(error.context(format!(
                            "persisting canonical constraint state failed and restoring its projection also failed: {restore}"
                        ))),
                    };
                }
                Ok(_) => {
                    return Err(error.context(
                        "persisting canonical constraint state had an ambiguous outcome: canonical state changed unexpectedly; projection left in the requested state for retry reconciliation",
                    ));
                }
                Err(read_error) => {
                    return Err(error.context(format!(
                        "persisting canonical constraint state had an ambiguous outcome and rereading canonical state failed validation: {read_error}; projection left in the requested state for retry reconciliation"
                    )));
                }
            },
            Ok(None) => {
                return Err(error.context(
                    "persisting canonical constraint state had an ambiguous outcome: environment disappeared; projection left in the requested state for retry reconciliation",
                ));
            }
            Err(read_error) => {
                return Err(error.context(format!(
                    "persisting canonical constraint state had an ambiguous outcome and rereading canonical state failed: {read_error}; projection left in the requested state for retry reconciliation"
                )));
            }
        }
    }
    Ok(constraint)
}

pub async fn set_enabled(
    ctx: &mut Ctx,
    environment: &str,
    identity: &str,
    enabled: bool,
) -> Result<Constraint> {
    validate_identifier("environment", environment)?;
    validate_identifier("constraint identity", identity)?;
    let owner = format!("constraint-update:{identity}:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = set_enabled_locked(ctx, environment, identity, enabled).await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(constraint), Ok(())) => Ok(constraint),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing environment constraint lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing environment constraint lease")),
    }
}

fn evaluate_one(
    constraint: Constraint,
    subscribed_channel_ids: &HashSet<String>,
) -> ConstraintEvaluation {
    let applicable = match &constraint.target {
        ConstraintTarget::Environment { .. } => true,
        ConstraintTarget::Subscription { channel_id, .. } => {
            subscribed_channel_ids.contains(channel_id)
        }
    };
    let (result, detail) = if !constraint.enabled {
        (
            EvaluationResult::NotApplicable,
            "constraint is disabled".into(),
        )
    } else if !applicable {
        (
            EvaluationResult::NotApplicable,
            "target subscription is not active".into(),
        )
    } else if !constraint.parameters.is_empty() {
        (
            EvaluationResult::Deny,
            format!(
                "constraint kind {} does not accept parameters",
                constraint.kind
            ),
        )
    } else {
        match constraint.kind.as_str() {
            "always.allow" => (EvaluationResult::Allow, constraint.reason.clone()),
            "always.deny" => (EvaluationResult::Deny, constraint.reason.clone()),
            unknown => (
                EvaluationResult::Deny,
                format!("unknown enabled constraint kind {unknown:?}"),
            ),
        }
    };
    ConstraintEvaluation {
        constraint_id: constraint.id,
        identity: constraint.identity,
        kind: constraint.kind,
        parameters: constraint.parameters,
        enabled: constraint.enabled,
        reason: constraint.reason,
        target: constraint.target,
        result,
        detail,
    }
}

pub fn evaluate_all(
    mut constraints: Vec<Constraint>,
    subscribed_channel_ids: &HashSet<String>,
) -> Vec<ConstraintEvaluation> {
    constraints.sort_by(|left, right| left.id.cmp(&right.id));
    constraints
        .into_iter()
        .map(|constraint| evaluate_one(constraint, subscribed_channel_ids))
        .collect()
}

pub async fn evaluate_environment(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<Vec<ConstraintEvaluation>> {
    evaluate_environment_with_channels(ctx, environment, std::iter::empty::<String>()).await
}

pub async fn evaluate_environment_with_channels(
    ctx: &mut Ctx,
    environment: &str,
    additional_channel_ids: impl IntoIterator<Item = String>,
) -> Result<Vec<ConstraintEvaluation>> {
    let constraints = list(ctx, environment).await?;
    let mut subscribed_channel_ids = ctx
        .links(&env_id(environment), REL_SUBSCRIBES)
        .await?
        .into_iter()
        .map(|link| link.to_id)
        .collect::<HashSet<_>>();
    subscribed_channel_ids.extend(additional_channel_ids);
    Ok(evaluate_all(constraints, &subscribed_channel_ids))
}

pub fn denied(evaluations: &[ConstraintEvaluation]) -> bool {
    evaluations
        .iter()
        .any(|evaluation| evaluation.result == EvaluationResult::Deny)
}

pub fn denial_detail(evaluations: &[ConstraintEvaluation]) -> String {
    evaluations
        .iter()
        .filter(|evaluation| evaluation.result == EvaluationResult::Deny)
        .map(|evaluation| format!("{}: {}", evaluation.identity, evaluation.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constraint_objects_round_trip() {
        let constraint = Constraint {
            id: constraint_id("prod", "freeze"),
            identity: "freeze".into(),
            kind: "always.deny".into(),
            parameters: BTreeMap::new(),
            enabled: true,
            reason: "release freeze".into(),
            target: ConstraintTarget::Subscription {
                environment: "prod".into(),
                channel_id: channel_id("api", "stable"),
            },
        };
        validate(&constraint).unwrap();
        let object = constraint.to_object(42).unwrap();
        assert_eq!(Constraint::from_object(&object).unwrap(), constraint);
    }

    #[test]
    fn environment_property_is_the_canonical_constraint_set() {
        let constraint = Constraint {
            id: constraint_id("prod", "freeze"),
            identity: "freeze".into(),
            kind: "always.deny".into(),
            parameters: BTreeMap::new(),
            enabled: true,
            reason: "release freeze".into(),
            target: ConstraintTarget::Environment {
                environment: "prod".into(),
            },
        };
        let mut object = Object {
            id: env_id("prod"),
            kind: KIND_ENVIRONMENT.into(),
            ..Default::default()
        };
        object.properties.insert(
            "constraints".into(),
            serde_json::to_string(&BTreeMap::from([(
                constraint.identity.clone(),
                constraint.clone(),
            )]))
            .unwrap(),
        );
        assert_eq!(
            constraints_from_environment(&object, "prod").unwrap(),
            BTreeMap::from([("freeze".into(), constraint)])
        );
    }

    #[test]
    fn constraints_require_a_reason_and_canonical_identity() {
        let constraint = Constraint {
            id: constraint_id("prod", "freeze"),
            identity: "freeze".into(),
            kind: "always.deny".into(),
            parameters: BTreeMap::new(),
            enabled: true,
            reason: " ".into(),
            target: ConstraintTarget::Environment {
                environment: "prod".into(),
            },
        };
        assert!(validate(&constraint).is_err());
    }

    fn constraint(identity: &str, kind: &str, enabled: bool) -> Constraint {
        Constraint {
            id: constraint_id("prod", identity),
            identity: identity.into(),
            kind: kind.into(),
            parameters: BTreeMap::new(),
            enabled,
            reason: format!("reason for {identity}"),
            target: ConstraintTarget::Environment {
                environment: "prod".into(),
            },
        }
    }

    #[test]
    fn evaluation_is_stable_and_unknown_kinds_fail_closed() {
        let constraints = vec![
            constraint("z-disabled", "future.kind", false),
            constraint("b-unknown", "future.kind", true),
            constraint("a-allow", "always.allow", true),
        ];
        let mut reversed = constraints.clone();
        reversed.reverse();
        let first = evaluate_all(constraints, &HashSet::new());
        let second = evaluate_all(reversed, &HashSet::new());
        assert_eq!(first, second);
        assert_eq!(first[0].result, EvaluationResult::Allow);
        assert_eq!(first[1].result, EvaluationResult::Deny);
        assert_eq!(first[2].result, EvaluationResult::NotApplicable);
        assert!(denied(&first));
    }

    #[test]
    fn inactive_subscription_constraints_are_not_applicable() {
        let mut constraint = constraint("freeze", "always.deny", true);
        constraint.target = ConstraintTarget::Subscription {
            environment: "prod".into(),
            channel_id: channel_id("api", "stable"),
        };
        let inactive = evaluate_all(vec![constraint.clone()], &HashSet::new());
        assert_eq!(inactive[0].result, EvaluationResult::NotApplicable);

        let active_channels = HashSet::from([channel_id("api", "stable")]);
        let active = evaluate_all(vec![constraint], &active_channels);
        assert_eq!(active[0].result, EvaluationResult::Deny);
    }
}
