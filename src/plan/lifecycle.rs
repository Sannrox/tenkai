//! Immutable Plan encoding, lifecycle transitions, reads, and durable effects.

use std::collections::HashMap;

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
            );
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
    anyhow::ensure!(
        !environment.trim().is_empty(),
        "environment is required for plan work selection"
    );
    let objects = ctx
        .find_by_property(KIND_PLAN, "environment", environment)
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
            continue;
        }
        plans.push(plan);
    }
    plans.sort_by_key(|plan| plan.created_at);
    Ok(plans)
}

pub(super) async fn oldest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Option<Plan>> {
    let plans = list_for_environment(ctx, environment, Some(statuses)).await?;
    Ok(plans.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(created_at: i64) -> Plan {
        let environment = "lifecycle-test".to_string();
        let inputs = Vec::new();
        let steps = Vec::new();
        let content_id = content_address(&environment, created_at, &inputs, &steps).unwrap();
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
}
