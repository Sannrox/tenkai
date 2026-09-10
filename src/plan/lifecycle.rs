//! Immutable Plan encoding, lifecycle transitions, reads, and durable effects.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::value::RawValue;

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
    require_has_steps_index(object, plan.steps.is_empty())?;
    let indexed_environment = object
        .properties
        .get("environment")
        .with_context(|| format!("plan object {} has no environment index", object.id))?;
    if indexed_environment != &plan.environment {
        bail!(
            "plan {} environment index {indexed_environment} does not match payload {}",
            object.id,
            plan.environment
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
    require_environment_indexes_match_payloads(ctx, environment).await?;
    load_for_environment(ctx, environment, statuses, false, None, None, None).await
}

pub(super) async fn oldest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Option<Plan>> {
    require_environment_indexes_match_payloads(ctx, environment).await?;
    load_oldest_for_environment(ctx, environment, statuses).await
}

/// Oldest stepped plan for `environment` in `statuses` without repeating the
/// catalog-wide index check. Callers that already ran
/// `require_environment_indexes_match_payloads` for this tick use this.
pub(crate) async fn load_oldest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Option<Plan>> {
    let mut plans = load_for_environment(
        ctx,
        environment,
        Some(statuses),
        false,
        Some(1),
        None,
        Some(true),
    )
    .await?;
    Ok(plans.pop())
}

#[cfg(test)]
pub(super) async fn executable_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Vec<Plan>> {
    require_environment_indexes_match_payloads(ctx, environment).await?;
    load_for_environment(
        ctx,
        environment,
        Some(statuses),
        false,
        None,
        None,
        Some(true),
    )
    .await
}

pub(super) async fn executable_batch_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
    limit: u32,
    offset: u32,
) -> Result<Vec<Plan>> {
    load_for_environment(
        ctx,
        environment,
        Some(statuses),
        false,
        Some(limit),
        Some(offset),
        Some(true),
    )
    .await
}

pub(super) async fn latest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<Option<Plan>> {
    // Catalog-wide retarget detection, then one environment walk: identity
    // peeks (created_at/environment/status/has_steps) pick the newest
    // validated row so a depressed newest index cannot hide behind LIMIT 1.
    // Full Plan decode runs only for that row, on the same blocking pool as
    // the catalog query.
    reject_environment_index_retarget(ctx, environment).await?;
    let owned_environment = environment.to_string();
    map_environment_plan_objects(
        ctx,
        environment,
        None,
        true,
        None,
        None,
        None,
        move |objects| newest_plan_from_objects(objects, &owned_environment),
    )
    .await
}

/// Fail closed when environment/status/`has_steps` indexes disagree with
/// payloads, including equality-filter omit-success (retargeted environment).
pub(super) async fn require_environment_indexes_match_payloads(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<()> {
    reject_environment_index_retarget(ctx, environment).await?;
    let owned_environment = environment.to_string();
    map_environment_plan_objects(ctx, environment, None, true, None, None, None, move |objects| {
        for object in &objects {
            let peek = require_indexed_identity(object)?;
            if peek.environment != owned_environment {
                bail!(
                    "plan {} property index returned environment {}, expected {owned_environment}",
                    object.id,
                    peek.environment
                );
            }
        }
        Ok(())
    })
    .await
}

/// Retire stored zero-step Computed/Running plans so they leave work selection.
///
/// Does not repeat the catalog-wide index check. Reconcile ticks call
/// `require_environment_indexes_match_payloads` once before retirement.
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
    state: PlanState,
    #[serde(default)]
    steps: PeekedSteps,
}

/// Identity-only step presence: capture raw JSON and test array emptiness
/// without materializing step `Value` trees.
#[derive(Debug)]
struct PeekedSteps {
    empty: bool,
}

impl Default for PeekedSteps {
    fn default() -> Self {
        Self { empty: true }
    }
}

impl PeekedSteps {
    fn is_empty(&self) -> bool {
        self.empty
    }
}

impl<'de> Deserialize<'de> for PeekedSteps {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        Ok(Self {
            empty: json_array_is_empty(raw.get()).map_err(serde::de::Error::custom)?,
        })
    }
}

fn json_array_is_empty(raw: &str) -> Result<bool, &'static str> {
    let trimmed = raw.trim();
    let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        return Err("plan steps must be a JSON array");
    };
    Ok(inner.trim().is_empty())
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

fn require_indexed_identity(object: &Object) -> Result<PlanPayloadPeek> {
    let peek = require_indexed_created_at_matches_payload(object)?;
    let indexed_environment = object
        .properties
        .get("environment")
        .with_context(|| format!("plan object {} has no environment index", object.id))?;
    if indexed_environment != &peek.environment {
        bail!(
            "plan {} environment index {indexed_environment} does not match payload {}",
            object.id,
            peek.environment
        );
    }
    let indexed_status = object
        .properties
        .get("status")
        .with_context(|| format!("plan object {} has no lifecycle status", object.id))?;
    if indexed_status != &peek.state.to_string() {
        bail!(
            "plan {} status index {indexed_status} does not match payload {}",
            object.id,
            peek.state
        );
    }
    require_has_steps_index(object, peek.steps.is_empty())?;
    Ok(peek)
}

fn require_has_steps_index(object: &Object, steps_empty: bool) -> Result<()> {
    let expected = if steps_empty { "false" } else { "true" };
    match object.properties.get("has_steps") {
        Some(indexed) if indexed == expected => Ok(()),
        Some(indexed) => bail!(
            "plan {} has_steps index {indexed} does not match payload steps",
            object.id
        ),
        None => bail!("plan object {} has no has_steps index", object.id),
    }
}

async fn reject_environment_index_retarget(ctx: &mut Ctx, environment: &str) -> Result<()> {
    // FindByProperty(environment=…) cannot see rows retargeted off this
    // index (ADR 0025). Kind-wide list_kind / ListObjects can: peek payload
    // environment, then fail closed when the index no longer matches.
    if let Some(store) = ctx.embedded_arc() {
        let environment = environment.to_string();
        return crate::client::block_embedded(store, move |store| {
            reject_retargeted_environment_index(store.list_kind(KIND_PLAN)?, &environment)
        })
        .await;
    }
    reject_retargeted_environment_index(ctx.list_kind(KIND_PLAN).await?, environment)
}

fn reject_retargeted_environment_index(
    objects: impl IntoIterator<Item = Object>,
    environment: &str,
) -> Result<()> {
    for object in objects {
        let peek = match peek_plan_environment(&object) {
            Ok(peek) => peek,
            Err(error) => match object.properties.get("environment") {
                Some(indexed) if indexed == environment => return Err(error),
                _ => continue,
            },
        };
        if peek.environment != environment {
            continue;
        }
        match object.properties.get("environment") {
            Some(indexed) if indexed == environment => {}
            Some(indexed) => bail!(
                "plan {} environment index {indexed} does not match payload {environment}",
                object.id
            ),
            None => bail!("plan object {} has no environment index", object.id),
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct PlanEnvironmentPeek {
    environment: String,
}

fn peek_plan_environment(object: &Object) -> Result<PlanEnvironmentPeek> {
    let raw = object
        .properties
        .get("plan")
        .with_context(|| format!("plan object {} has no serialized plan", object.id))?;
    serde_json::from_str(raw)
        .with_context(|| format!("parsing stored plan environment {}", object.id))
}

fn newest_plan_from_objects(objects: Vec<Object>, environment: &str) -> Result<Option<Plan>> {
    let mut newest: Option<(i64, Object)> = None;
    for object in objects {
        let peek = require_indexed_identity(&object)?;
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

fn plans_from_objects(
    objects: Vec<Object>,
    environment: &str,
    statuses: Option<&[PlanState]>,
    has_steps: Option<bool>,
) -> Result<Vec<Plan>> {
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

#[allow(clippy::too_many_arguments)]
fn environment_plan_index_query<'a>(
    environment: &'a str,
    matching_key: Option<&'a str>,
    matching_values: &'a [&'a str],
    equals_key: Option<&'a str>,
    equals_value: Option<&'a str>,
    descending: bool,
    limit: Option<u32>,
    offset: Option<u32>,
) -> crate::embedded::PropertyIndexQuery<'a> {
    crate::embedded::PropertyIndexQuery {
        matching_key,
        matching_values,
        equals_key,
        equals_value,
        order_key: Some("created_at"),
        descending,
        limit,
        offset,
        ..crate::embedded::PropertyIndexQuery::new(KIND_PLAN, "environment", environment)
    }
}

#[allow(clippy::too_many_arguments)]
async fn map_environment_plan_objects<T, F>(
    ctx: &mut Ctx,
    environment: &str,
    statuses: Option<&[PlanState]>,
    descending: bool,
    limit: Option<u32>,
    offset: Option<u32>,
    has_steps: Option<bool>,
    map: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Vec<Object>) -> Result<T> + Send + 'static,
{
    anyhow::ensure!(
        !environment.trim().is_empty(),
        "environment is required for plan work selection"
    );
    let environment = environment.to_string();
    let status_labels: Vec<String> = statuses
        .unwrap_or(&[])
        .iter()
        .map(ToString::to_string)
        .collect();
    let filter_statuses = statuses.is_some();
    let equals_key = has_steps.map(|_| "has_steps");
    let equals_value = match has_steps {
        Some(true) => Some("true"),
        Some(false) => Some("false"),
        None => None,
    };
    if let Some(store) = ctx.embedded_arc() {
        return crate::client::block_embedded(store, move |store| {
            let status_refs: Vec<&str> = status_labels.iter().map(String::as_str).collect();
            let (matching_key, matching_values) = if filter_statuses {
                (Some("status"), status_refs.as_slice())
            } else {
                (None, &[][..])
            };
            let objects = store.find_by_property_matching(environment_plan_index_query(
                &environment,
                matching_key,
                matching_values,
                equals_key,
                equals_value,
                descending,
                limit,
                offset,
            ))?;
            map(objects)
        })
        .await;
    }
    let status_refs: Vec<&str> = status_labels.iter().map(String::as_str).collect();
    let (matching_key, matching_values) = if filter_statuses {
        (Some("status"), status_refs.as_slice())
    } else {
        (None, &[][..])
    };
    let objects = ctx
        .find_by_property_matching(environment_plan_index_query(
            &environment,
            matching_key,
            matching_values,
            equals_key,
            equals_value,
            descending,
            limit,
            offset,
        ))
        .await?;
    tokio::task::spawn_blocking(move || map(objects))
        .await
        .unwrap_or_else(|error| Err(anyhow::anyhow!("plan decode blocking task failed: {error}")))
}

pub(crate) async fn load_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: Option<&[PlanState]>,
    descending: bool,
    limit: Option<u32>,
    offset: Option<u32>,
    has_steps: Option<bool>,
) -> Result<Vec<Plan>> {
    let owned_environment = environment.to_string();
    let status_filter = statuses.map(<[PlanState]>::to_vec);
    map_environment_plan_objects(
        ctx,
        environment,
        statuses,
        descending,
        limit,
        offset,
        has_steps,
        move |objects| {
            plans_from_objects(
                objects,
                &owned_environment,
                status_filter.as_deref(),
                has_steps,
            )
        },
    )
    .await
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
        let missing_error = from_object(&missing).unwrap_err().to_string();
        assert!(
            missing_error.contains("no has_steps index"),
            "{missing_error}"
        );
        assert!(
            require_indexed_identity(&missing)
                .unwrap_err()
                .to_string()
                .contains("no has_steps index")
        );

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
        assert!(
            require_indexed_identity(&mismatch)
                .unwrap_err()
                .to_string()
                .contains("does not match payload steps")
        );

        let mut stepped = object;
        let mut payload: serde_json::Value =
            serde_json::from_str(stepped.properties.get("plan").unwrap()).unwrap();
        payload["steps"] = serde_json::json!([{"opaque": true}]);
        stepped
            .properties
            .insert("plan".into(), payload.to_string());
        stepped.properties.remove("has_steps");
        let stepped_missing = require_indexed_identity(&stepped).unwrap_err().to_string();
        assert!(
            stepped_missing.contains("no has_steps index"),
            "{stepped_missing}"
        );
    }

    #[test]
    fn identity_peek_does_not_materialize_typed_step_bodies() {
        let empty = plan(10);
        let object = to_object(&empty).unwrap();
        assert!(require_indexed_identity(&object).unwrap().steps.is_empty());

        let mut untyped = object;
        let mut payload: serde_json::Value =
            serde_json::from_str(untyped.properties.get("plan").unwrap()).unwrap();
        payload["steps"] = serde_json::json!([
            {"opaque": true, "blob": "x".repeat(4096)},
            {"nested": {"more": [1, 2, 3]}}
        ]);
        untyped
            .properties
            .insert("plan".into(), payload.to_string());
        assert!(
            require_indexed_identity(&untyped)
                .unwrap_err()
                .to_string()
                .contains("does not match payload steps")
        );
        untyped.properties.insert("has_steps".into(), "true".into());
        let peek = require_indexed_identity(&untyped).unwrap();
        assert!(!peek.steps.is_empty());
        assert_eq!(peek.environment, "lifecycle-test");

        let mut not_array = untyped;
        let mut payload: serde_json::Value =
            serde_json::from_str(not_array.properties.get("plan").unwrap()).unwrap();
        payload["steps"] = serde_json::json!({"not": "an array"});
        not_array
            .properties
            .insert("plan".into(), payload.to_string());
        let error = format!("{:#}", require_indexed_identity(&not_array).unwrap_err());
        assert!(error.contains("plan steps must be a JSON array"), "{error}");
    }

    #[test]
    fn identity_peek_treats_whitespace_only_steps_array_as_empty() {
        let empty = plan(10);
        let mut object = to_object(&empty).unwrap();
        let raw = object
            .properties
            .get("plan")
            .unwrap()
            .replace("\"steps\":[]", "\"steps\":[\n  \n]");
        object.properties.insert("plan".into(), raw);
        assert!(require_indexed_identity(&object).unwrap().steps.is_empty());
    }

    #[test]
    fn from_object_rejects_environment_index_drift() {
        let plan = plan(10);
        let object = to_object(&plan).unwrap();
        assert_eq!(from_object(&object).unwrap().environment, "lifecycle-test");

        let mut missing = object.clone();
        missing.properties.remove("environment");
        assert!(
            from_object(&missing)
                .unwrap_err()
                .to_string()
                .contains("no environment index")
        );

        let mut mismatch = object.clone();
        mismatch
            .properties
            .insert("environment".into(), "other".into());
        let error = from_object(&mismatch).unwrap_err().to_string();
        assert!(error.contains("does not match payload"), "{error}");
        let identity_error = require_indexed_identity(&mismatch).unwrap_err().to_string();
        assert!(
            identity_error.contains("does not match payload"),
            "{identity_error}"
        );
    }

    #[test]
    fn retarget_scan_fails_closed_when_index_leaves_payload_environment() {
        let mut retargeted = to_object(&plan(10)).unwrap();
        retargeted
            .properties
            .insert("environment".into(), "other".into());
        let error = reject_retargeted_environment_index(vec![retargeted], "lifecycle-test")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("environment index other does not match payload lifecycle-test"),
            "{error}"
        );

        let mut missing = to_object(&plan(10)).unwrap();
        missing.properties.remove("environment");
        let missing_error = reject_retargeted_environment_index(vec![missing], "lifecycle-test")
            .unwrap_err()
            .to_string();
        assert!(
            missing_error.contains("no environment index"),
            "{missing_error}"
        );
    }

    #[test]
    fn retarget_scan_skips_unreadable_foreign_plans() {
        let local = to_object(&plan(10)).unwrap();
        let mut foreign = to_object(&plan(20)).unwrap();
        foreign
            .properties
            .insert("environment".into(), "other".into());
        foreign.properties.insert("plan".into(), "not-json".into());
        reject_retargeted_environment_index(vec![local.clone(), foreign], "lifecycle-test")
            .unwrap();

        let mut indexed_here = local;
        indexed_here
            .properties
            .insert("plan".into(), "not-json".into());
        let error = reject_retargeted_environment_index(vec![indexed_here], "lifecycle-test")
            .unwrap_err()
            .to_string();
        assert!(error.contains("parsing stored plan environment"), "{error}");
    }

    #[test]
    fn newest_plan_from_objects_decodes_the_newest_validated_row() {
        let older = to_object(&plan(10)).unwrap();
        let newer = to_object(&plan(20)).unwrap();
        let latest = newest_plan_from_objects(vec![older, newer], "lifecycle-test")
            .unwrap()
            .unwrap();
        assert_eq!(latest.created_at, 20);
        let error = newest_plan_from_objects(vec![to_object(&plan(10)).unwrap()], "other")
            .unwrap_err()
            .to_string();
        assert!(error.contains("expected other"), "{error}");
    }

    #[tokio::test]
    async fn environment_plan_decode_join_failure_is_explicit() {
        let (mut ctx, database) = context("decode-join");
        let error = map_environment_plan_objects(
            &mut ctx,
            "lifecycle-test",
            None,
            true,
            None,
            None,
            None,
            |_| -> Result<Option<Plan>> { panic!("forced plan decode panic") },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("embedded store blocking task failed"),
            "{error}"
        );
        let _ = std::fs::remove_file(database);
    }
}
