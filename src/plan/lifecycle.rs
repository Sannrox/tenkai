//! Immutable Plan encoding, lifecycle transitions, reads, and durable effects.

use std::collections::HashMap;

use serde::Deserialize;

use super::*;

pub(crate) struct Transition {
    state: PlanState,
    gates_skipped: Option<bool>,
    status_detail: String,
    maintenance_blocked: bool,
}

impl Transition {
    pub(crate) fn new(state: PlanState, status_detail: impl Into<String>) -> Self {
        Self {
            state,
            gates_skipped: None,
            status_detail: status_detail.into(),
            maintenance_blocked: false,
        }
    }

    pub(crate) fn execution(
        state: PlanState,
        gates_skipped: bool,
        status_detail: impl Into<String>,
    ) -> Self {
        Self {
            state,
            gates_skipped: Some(gates_skipped),
            status_detail: status_detail.into(),
            maintenance_blocked: false,
        }
    }

    pub(crate) fn maintenance_blocked(
        gates_skipped: bool,
        status_detail: impl Into<String>,
    ) -> Self {
        Self {
            state: PlanState::Blocked,
            gates_skipped: Some(gates_skipped),
            status_detail: status_detail.into(),
            maintenance_blocked: true,
        }
    }

    fn apply(self, plan: &mut Plan) {
        plan.state = self.state;
        if let Some(gates_skipped) = self.gates_skipped {
            plan.gates_skipped = Some(gates_skipped);
        }
        plan.status_detail = self.status_detail;
        plan.maintenance_blocked = self.maintenance_blocked;
    }
}

pub(crate) enum Persistence<'a> {
    Standard,
    WithProviderEvents(&'a [crate::storage::ProviderEventRecord]),
    WithEnvironmentAndProviderEvents {
        environment: Object,
        provider_events: &'a [crate::storage::ProviderEventRecord],
    },
    Guarded {
        namespace: &'a str,
        key: &'a str,
        fencing_token: &'a str,
        confirm_ambiguous: bool,
    },
}

pub(crate) async fn transition(
    ctx: &mut Ctx,
    plan: &mut Plan,
    update: Transition,
    persistence: Persistence<'_>,
) -> Result<()> {
    update.apply(plan);
    match persistence {
        Persistence::Standard => store(ctx, plan).await,
        Persistence::WithProviderEvents(events) => {
            store_with_provider_events(ctx, plan, events).await
        }
        Persistence::WithEnvironmentAndProviderEvents {
            environment,
            provider_events,
        } => {
            store_with_environment_and_provider_events(ctx, plan, environment, provider_events)
                .await
        }
        Persistence::Guarded {
            namespace,
            key,
            fencing_token,
            confirm_ambiguous,
        } => {
            let intended = (
                plan.state,
                plan.gates_skipped,
                plan.status_detail.clone(),
                plan.maintenance_blocked,
            );
            if let Err(error) = ctx
                .guarded_update(plan.to_object()?, namespace, key, fencing_token)
                .await
            {
                if !confirm_ambiguous {
                    return Err(error);
                }
                let persisted = load(ctx, &plan.id).await;
                if !matches!(
                    persisted,
                    Ok(ref stored)
                        if (stored.state, stored.gates_skipped, stored.status_detail.clone(), stored.maintenance_blocked)
                            == intended
                ) {
                    return Err(error);
                }
            }
            Ok(())
        }
    }
}

pub(super) fn to_object(plan: &Plan) -> Result<Object> {
    Ok(Object {
        id: plan.id.clone(),
        kind: KIND_PLAN.into(),
        name: format!("{} plan {}", plan.environment, plan.created_at),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("format_version".into(), plan.format_version.to_string()),
            ("environment".into(), plan.environment.clone()),
            ("created_at".into(), plan.created_at.to_string()),
            ("content_digest".into(), plan.executable_digest()?),
            ("plan".into(), serde_json::to_string(plan)?),
            ("status".into(), plan.state.to_string()),
            (
                "has_steps".into(),
                if plan.steps.is_empty() {
                    "false".into()
                } else {
                    "true".into()
                },
            ),
        ]),
        created: plan.created_at,
        updated: crate::now_millis(),
    })
}

pub(super) fn from_object(object: &Object) -> Result<Plan> {
    if object.kind != KIND_PLAN {
        bail!("object {} is {}, not {KIND_PLAN}", object.id, object.kind);
    }
    let raw = object
        .properties
        .get("plan")
        .with_context(|| format!("plan object {} has no serialized plan", object.id))?;
    let plan: Plan =
        serde_json::from_str(raw).with_context(|| format!("parsing stored plan {}", object.id))?;
    if plan.format_version != PLAN_FORMAT_VERSION {
        bail!(
            "plan {} uses unsupported format version {}",
            object.id,
            plan.format_version
        );
    }
    if plan.maintenance_blocked && plan.state != PlanState::Blocked {
        bail!(
            "plan {} has a maintenance-block marker outside the blocked state",
            plan.id
        );
    }
    if plan.id != object.id {
        bail!(
            "stored plan id {} does not match object id {}",
            plan.id,
            object.id
        );
    }
    let expected_content_id = content_address(
        &plan.environment,
        plan.created_at,
        &plan.inputs,
        &plan.steps,
        plan.recalled_recovery_reason.as_deref(),
    )?;
    if plan.content_id != expected_content_id
        || plan.id != plan_id(&plan.environment, plan.created_at, &expected_content_id)
    {
        bail!(
            "stored plan {} does not match its content-addressed id",
            object.id
        );
    }
    for (order, step) in plan.steps.iter().enumerate() {
        if step.order != order as u32 || step.id != format!("{}:step:{order}", plan.id) {
            bail!("stored plan {} has invalid step ordering or ids", object.id);
        }
    }
    let status = object
        .properties
        .get("status")
        .with_context(|| format!("plan object {} has no lifecycle status", object.id))?;
    if status != &plan.state.to_string() {
        bail!("stored plan {} has inconsistent lifecycle state", object.id);
    }
    let stored_digest = object
        .properties
        .get("content_digest")
        .with_context(|| format!("plan object {} has no content digest", object.id))?;
    if plan.executable_digest()? != *stored_digest {
        bail!("stored plan {} executable content was mutated", object.id);
    }
    let indexed_created_at = object
        .properties
        .get("created_at")
        .with_context(|| format!("plan object {} has no created_at index", object.id))?;
    let indexed_created_at: i64 = indexed_created_at
        .parse()
        .with_context(|| format!("plan {} created_at index is not an integer", object.id))?;
    if indexed_created_at != plan.created_at {
        bail!(
            "plan {} created_at index {indexed_created_at} does not match payload {}",
            object.id,
            plan.created_at
        );
    }
    let expected_has_steps = if plan.steps.is_empty() {
        "false"
    } else {
        "true"
    };
    if let Some(indexed_has_steps) = object.properties.get("has_steps")
        && indexed_has_steps != expected_has_steps
    {
        bail!(
            "plan {} has_steps index {indexed_has_steps} does not match payload steps",
            object.id
        );
    }
    Ok(plan)
}

pub(super) async fn store(ctx: &mut Ctx, plan: &Plan) -> Result<()> {
    store_with_provider_events(ctx, plan, &[]).await
}

pub(super) async fn store_with_provider_events(
    ctx: &mut Ctx,
    plan: &Plan,
    provider_events: &[crate::storage::ProviderEventRecord],
) -> Result<()> {
    let object = validated_plan_object(ctx, plan).await?;
    ctx.put_with_provider_events(object, provider_events)
        .await?;
    Ok(())
}

pub(super) async fn store_with_environment_and_provider_events(
    ctx: &mut Ctx,
    plan: &Plan,
    environment: Object,
    provider_events: &[crate::storage::ProviderEventRecord],
) -> Result<()> {
    let plan_object = validated_plan_object(ctx, plan).await?;
    ctx.put_objects_with_provider_events(&[plan_object, environment], provider_events)
        .await
}

async fn validated_plan_object(ctx: &mut Ctx, plan: &Plan) -> Result<Object> {
    let existing = ctx.get(&plan.id).await?;
    if let Some(existing) = existing.as_ref() {
        let stored = from_object(existing)?;
        if stored.executable_digest()? != plan.executable_digest()? {
            bail!("plan {} executable content is immutable", plan.id);
        }
        if stored.state == plan.state
            && stored.state != PlanState::Blocked
            && (stored.gates_skipped != plan.gates_skipped
                || stored.status_detail != plan.status_detail
                || stored.maintenance_blocked != plan.maintenance_blocked)
        {
            bail!("plan {} lifecycle audit fields are immutable", plan.id);
        }
        let valid_transition = stored.state == plan.state
            || matches!(
                (stored.state, plan.state),
                (PlanState::Computed, PlanState::Running)
                    | (PlanState::Computed, PlanState::Blocked)
                    | (PlanState::Blocked, PlanState::Running)
                    | (PlanState::Running, PlanState::Blocked)
                    | (PlanState::Running, PlanState::Succeeded)
                    | (PlanState::Running, PlanState::Failed)
            )
            || (stored.steps.is_empty()
                && plan.steps.is_empty()
                && stored.state == PlanState::Computed
                && plan.state == PlanState::Succeeded);
        if !valid_transition {
            bail!(
                "plan {} cannot transition from {} to {}",
                plan.id,
                stored.state,
                plan.state
            );
        }
    }
    let mut object = to_object(plan)?;
    if let Some(existing) = existing.as_ref() {
        for property in [
            "last_emergency_override_reason",
            "last_emergency_override_correlation",
        ] {
            if let Some(value) = existing.properties.get(property) {
                object.properties.insert(property.into(), value.clone());
            }
        }
    }
    Ok(object)
}

pub(super) async fn load(ctx: &mut Ctx, id: &str) -> Result<Plan> {
    let object = ctx
        .get(id)
        .await?
        .with_context(|| format!("plan {id} not found"))?;
    from_object(&object)
}

pub(super) async fn list_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: Option<&[PlanState]>,
) -> Result<Vec<Plan>> {
    load_for_environment(ctx, environment, statuses, false, None, None).await
}

pub(super) async fn oldest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Option<Plan>> {
    let mut plans =
        load_for_environment(ctx, environment, Some(statuses), false, Some(1), Some(true)).await?;
    Ok(plans.pop())
}

pub(super) async fn executable_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Vec<Plan>> {
    load_for_environment(ctx, environment, Some(statuses), false, None, Some(true)).await
}

pub(super) async fn latest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<Option<Plan>> {
    // Visit every environment plan's created_at index and payload peek so a
    // depressed newest index cannot hide behind LIMIT 1. Full Plan decode
    // (steps, content digest) runs only for the newest validated row.
    let objects = plan_objects_for_environment(ctx, environment, None, true, None, None).await?;
    let mut newest: Option<(i64, Object)> = None;
    for object in objects {
        let peek = require_indexed_created_at_matches_payload(&object)?;
        if peek.environment != environment {
            bail!(
                "plan {} property index returned environment {}, expected {environment}",
                object.id,
                peek.environment
            );
        }
        if newest
            .as_ref()
            .is_none_or(|(best, _)| peek.created_at > *best)
        {
            newest = Some((peek.created_at, object));
        }
    }
    newest.map(|(_, object)| from_object(&object)).transpose()
}

/// Retire stored zero-step Computed/Running plans so they leave work selection.
pub(crate) async fn retire_empty_executable_plans(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<usize> {
    let mut retired = 0;
    for mut plan in load_for_environment(
        ctx,
        environment,
        Some(&[PlanState::Computed, PlanState::Running]),
        false,
        None,
        Some(false),
    )
    .await?
    {
        if !plan.steps.is_empty() {
            bail!(
                "plan {} has_steps index selected an executable plan for empty retirement",
                plan.id
            );
        }
        transition(
            ctx,
            &mut plan,
            Transition::new(PlanState::Succeeded, NO_OP_STATUS_DETAIL),
            Persistence::Standard,
        )
        .await?;
        retired += 1;
    }
    Ok(retired)
}

#[derive(Debug, Deserialize)]
struct PlanPayloadPeek {
    created_at: i64,
    environment: String,
}

fn peek_plan_payload(object: &Object) -> Result<PlanPayloadPeek> {
    let raw = object
        .properties
        .get("plan")
        .with_context(|| format!("plan object {} has no serialized plan", object.id))?;
    serde_json::from_str(raw).with_context(|| format!("parsing stored plan identity {}", object.id))
}

fn require_indexed_created_at_matches_payload(object: &Object) -> Result<PlanPayloadPeek> {
    let indexed = object
        .properties
        .get("created_at")
        .with_context(|| format!("plan object {} has no created_at index", object.id))?;
    let indexed: i64 = indexed
        .parse()
        .with_context(|| format!("plan {} created_at index is not an integer", object.id))?;
    let peek = peek_plan_payload(object)?;
    if indexed != peek.created_at {
        bail!(
            "plan {} created_at index {indexed} does not match payload {}",
            object.id,
            peek.created_at
        );
    }
    Ok(peek)
}

async fn plan_objects_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: Option<&[PlanState]>,
    descending: bool,
    limit: Option<u32>,
    has_steps: Option<bool>,
) -> Result<Vec<Object>> {
    anyhow::ensure!(
        !environment.trim().is_empty(),
        "environment is required for plan work selection"
    );
    let status_labels: Vec<String> = statuses
        .unwrap_or(&[])
        .iter()
        .map(ToString::to_string)
        .collect();
    let status_refs: Vec<&str> = status_labels.iter().map(String::as_str).collect();
    let (matching_key, matching_values) = if statuses.is_some() {
        (Some("status"), status_refs.as_slice())
    } else {
        (None, &[][..])
    };
    let (equals_key, equals_value) = match has_steps {
        Some(true) => (Some("has_steps"), Some("true")),
        Some(false) => (Some("has_steps"), Some("false")),
        None => (None, None),
    };
    ctx.find_by_property_matching(crate::embedded::PropertyIndexQuery {
        matching_key,
        matching_values,
        equals_key,
        equals_value,
        order_key: Some("created_at"),
        descending,
        limit,
        ..crate::embedded::PropertyIndexQuery::new(KIND_PLAN, "environment", environment)
    })
    .await
}

async fn load_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: Option<&[PlanState]>,
    descending: bool,
    limit: Option<u32>,
    has_steps: Option<bool>,
) -> Result<Vec<Plan>> {
    let objects =
        plan_objects_for_environment(ctx, environment, statuses, descending, limit, has_steps)
            .await?;
    let mut plans = Vec::with_capacity(objects.len());
    for object in objects {
        let plan = from_object(&object)?;
        if plan.environment != environment {
            bail!(
                "plan {} property index returned environment {}, expected {environment}",
                plan.id,
                plan.environment
            );
        }
        if let Some(allowed) = statuses
            && !allowed.contains(&plan.state)
        {
            bail!(
                "plan {} property index returned status {}, outside the requested filter",
                plan.id,
                plan.state
            );
        }
        if let Some(want_steps) = has_steps
            && plan.steps.is_empty() == want_steps
        {
            continue;
        }
        plans.push(plan);
    }
    Ok(plans)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(created_at: i64) -> Plan {
        let environment = "lifecycle-test".to_string();
        let inputs = Vec::new();
        let steps = Vec::new();
        let content_id = content_address(&environment, created_at, &inputs, &steps, None).unwrap();
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            id: plan_id(&environment, created_at, &content_id),
            content_id,
            environment,
            created_at,
            inputs,
            steps,
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
        }
    }

    fn context(name: &str) -> (Ctx, std::path::PathBuf) {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-lifecycle-{name}-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        (Ctx::embedded(&database).unwrap(), database)
    }

    #[tokio::test]
    async fn transition_intent_owns_legal_lifecycle_changes() {
        let (mut ctx, database) = context("legal");
        let mut plan = plan(10);
        store(&mut ctx, &plan).await.unwrap();

        transition(
            &mut ctx,
            &mut plan,
            Transition::execution(PlanState::Running, false, "admitted"),
            Persistence::Standard,
        )
        .await
        .unwrap();
        transition(
            &mut ctx,
            &mut plan,
            Transition::execution(PlanState::Succeeded, false, "complete"),
            Persistence::Standard,
        )
        .await
        .unwrap();

        let stored = load(&mut ctx, &plan.id).await.unwrap();
        assert_eq!(stored.state, PlanState::Succeeded);
        assert_eq!(stored.gates_skipped, Some(false));
        assert_eq!(stored.status_detail, "complete");
        assert!(!stored.maintenance_blocked);
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn transition_intent_rejects_terminal_reentry_and_audit_rewrite() {
        let (mut ctx, database) = context("invalid");
        let mut plan = plan(20);
        store(&mut ctx, &plan).await.unwrap();
        transition(
            &mut ctx,
            &mut plan,
            Transition::new(PlanState::Running, "claimed"),
            Persistence::Standard,
        )
        .await
        .unwrap();
        transition(
            &mut ctx,
            &mut plan,
            Transition::new(PlanState::Failed, "failed"),
            Persistence::Standard,
        )
        .await
        .unwrap();

        let terminal_error = transition(
            &mut ctx,
            &mut plan,
            Transition::new(PlanState::Running, "retry"),
            Persistence::Standard,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(terminal_error.contains("cannot transition from failed to running"));

        let mut stored = load(&mut ctx, &plan.id).await.unwrap();
        let audit_error = transition(
            &mut ctx,
            &mut stored,
            Transition::new(PlanState::Failed, "changed failure"),
            Persistence::Standard,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(audit_error.contains("lifecycle audit fields are immutable"));
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn empty_computed_plan_can_retire_to_succeeded() {
        let (mut ctx, database) = context("empty-retire");
        let mut plan = plan(30);
        store(&mut ctx, &plan).await.unwrap();
        transition(
            &mut ctx,
            &mut plan,
            Transition::new(PlanState::Succeeded, NO_OP_STATUS_DETAIL),
            Persistence::Standard,
        )
        .await
        .unwrap();
        let stored = load(&mut ctx, &plan.id).await.unwrap();
        assert_eq!(stored.state, PlanState::Succeeded);
        assert_eq!(stored.status_detail, NO_OP_STATUS_DETAIL);
        assert!(stored.steps.is_empty());
        let _ = std::fs::remove_file(database);
    }

    #[test]
    fn from_object_rejects_created_at_index_drift() {
        let plan = plan(10);
        let object = to_object(&plan).unwrap();
        assert_eq!(from_object(&object).unwrap().created_at, 10);

        let mut missing = object.clone();
        missing.properties.remove("created_at");
        assert!(
            from_object(&missing)
                .unwrap_err()
                .to_string()
                .contains("no created_at index")
        );

        let mut non_integer = object.clone();
        non_integer
            .properties
            .insert("created_at".into(), "later".into());
        assert!(
            from_object(&non_integer)
                .unwrap_err()
                .to_string()
                .contains("not an integer")
        );

        let mut mismatch = object.clone();
        mismatch.properties.insert("created_at".into(), "99".into());
        let error = from_object(&mismatch).unwrap_err().to_string();
        assert!(error.contains("does not match payload"), "{error}");

        let peek_error = require_indexed_created_at_matches_payload(&mismatch)
            .unwrap_err()
            .to_string();
        assert!(
            peek_error.contains("does not match payload"),
            "{peek_error}"
        );
        assert_eq!(
            require_indexed_created_at_matches_payload(&object)
                .unwrap()
                .created_at,
            10
        );
    }

    #[test]
    fn from_object_rejects_has_steps_index_drift() {
        let empty = plan(10);
        let object = to_object(&empty).unwrap();
        assert_eq!(
            object.properties.get("has_steps").map(String::as_str),
            Some("false")
        );

        let mut missing = object.clone();
        missing.properties.remove("has_steps");
        assert!(from_object(&missing).unwrap().steps.is_empty());

        let mut mismatch = object.clone();
        mismatch
            .properties
            .insert("has_steps".into(), "true".into());
        assert!(
            from_object(&mismatch)
                .unwrap_err()
                .to_string()
                .contains("does not match payload steps")
        );
    }
}
