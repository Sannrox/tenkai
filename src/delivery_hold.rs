//! Environment and channel delivery hold: the reconciler plans, but does not execute.
//!
//! A hold is its own catalog object, one per scope, so environment and channel
//! writes (promote, subscribe, deploy) never have to carry it forward. Every
//! set and clear also appends an immutable audit event with reason, actor, and
//! time; clearing deletes the hold but never its history.
//!
//! A dated change freeze is a separate catalog object per environment name.
//! It starts and ends by the clock; no write happens at either instant.
//! Schedule and cancel append the same set/clear audit events as a hold.
//!
//! A failure threshold is one catalog object per environment. When more than
//! N `failed_target.*` rows fall inside the window, the reconciler sets the
//! environment hold with actor [`AUTOMATIC_HOLD_ACTOR`]. It never replaces or
//! clears an operator hold.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};

use crate::client::Ctx;
use crate::ontology::{KIND_CHANNEL, NS, channel_id, validate_identifier};
use crate::pb::sekai::Object;

pub const HOLD_KIND: &str = "tenkai.delivery_hold";
pub const HOLD_AUDIT_KIND: &str = "tenkai.delivery_hold_audit";
pub const FREEZE_KIND: &str = "tenkai.delivery_freeze";
pub const THRESHOLD_KIND: &str = "tenkai.delivery_failure_threshold";
/// Actor stored on an automatic environment hold set by a failure threshold.
pub const AUTOMATIC_HOLD_ACTOR: &str = "automatic";

/// What a hold pauses: one environment, or every environment subscribed to a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldScope {
    Environment(String),
    Channel { product: String, channel: String },
}

impl HoldScope {
    pub fn environment(env: &str) -> Self {
        Self::Environment(env.into())
    }

    pub fn channel(product: &str, channel: &str) -> Self {
        Self::Channel {
            product: product.into(),
            channel: channel.into(),
        }
    }

    /// Stable scope key used in object ids, audit events, and reconcile status
    /// (`environment:<env>` or `channel:<product>/<channel>`).
    pub fn key(&self) -> String {
        match self {
            Self::Environment(env) => format!("environment:{env}"),
            Self::Channel { product, channel } => format!("channel:{product}/{channel}"),
        }
    }

    fn hold_id(&self) -> String {
        format!("tenkai:delivery_hold:{}", self.key())
    }

    async fn require_exists(&self, ctx: &mut Ctx) -> Result<()> {
        match self {
            Self::Environment(env) => {
                validate_identifier("environment", env)?;
                crate::environment::environment(ctx, env).await?;
            }
            Self::Channel { product, channel } => {
                validate_identifier("product", product)?;
                validate_identifier("channel", channel)?;
                match ctx.get(&channel_id(product, channel)).await? {
                    Some(object) if object.kind == KIND_CHANNEL => {}
                    Some(object) => bail!(
                        "object {} is {}, not {KIND_CHANNEL}",
                        object.id,
                        object.kind
                    ),
                    None => bail!("channel {product}/{channel} is not published"),
                }
            }
        }
        Ok(())
    }
}

/// Durable evidence that delivery is paused for a scope.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct DeliveryHold {
    pub reason: String,
    pub actor: String,
    pub held_at: i64,
}

/// One immutable set, clear, or retry transition.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct HoldAuditEvent {
    pub action: String,
    pub reason: String,
    pub actor: String,
    pub at: i64,
}

/// Active hold plus set/clear/retry history for one scope.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct DeliveryHoldView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub hold: Option<DeliveryHold>,
    pub audit: Vec<HoldAuditEvent>,
    /// Active and upcoming environment freezes. Omitted when empty, including
    /// on channel hold views.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub freezes: Vec<DeliveryFreeze>,
    /// Declared failure threshold. Omitted when unset, including on channel
    /// hold views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub threshold: Option<FailureThreshold>,
}

/// Declared count and window that can set an automatic environment hold.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct FailureThreshold {
    pub environment: String,
    pub count: u32,
    pub window_ms: i64,
    pub actor: String,
    pub set_at: i64,
}

/// A named environment freeze with a start and an end, evaluated by the clock.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct DeliveryFreeze {
    pub name: String,
    pub environment: String,
    pub from_ms: i64,
    pub until_ms: i64,
    pub reason: String,
    pub actor: String,
    pub scheduled_at: i64,
}

impl DeliveryFreeze {
    pub fn active_at(&self, now_ms: i64) -> bool {
        self.from_ms <= now_ms && now_ms < self.until_ms
    }

    pub fn upcoming_at(&self, now_ms: i64) -> bool {
        self.from_ms > now_ms
    }
}

/// Why a plan is paused: an operator hold, or a freeze that covers `now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryPause {
    Hold {
        hold: DeliveryHold,
        scope: HoldScope,
    },
    Freeze(DeliveryFreeze),
}

impl DeliveryPause {
    pub fn reason(&self) -> String {
        match self {
            Self::Hold { hold, .. } => hold.reason.clone(),
            Self::Freeze(freeze) => format!(
                "freeze {} until {}: {}",
                freeze.name,
                format_freeze_instant(freeze.until_ms),
                freeze.reason
            ),
        }
    }

    pub fn scope_key(&self) -> String {
        match self {
            Self::Hold { scope, .. } => scope.key(),
            Self::Freeze(freeze) => HoldScope::environment(&freeze.environment).key(),
        }
    }
}

/// Active hold and history for `scope`.
pub async fn view(ctx: &mut Ctx, scope: &HoldScope) -> Result<DeliveryHoldView> {
    let (freezes, threshold) = match scope {
        HoldScope::Environment(env) => (
            visible_freezes(ctx, env, crate::now_millis()).await?,
            get_failure_threshold(ctx, env).await?,
        ),
        HoldScope::Channel { .. } => (Vec::new(), None),
    };
    Ok(DeliveryHoldView {
        hold: get(ctx, scope).await?,
        audit: audit(ctx, scope).await?,
        freezes,
        threshold,
    })
}

/// Parse an RFC 3339 freeze bound. The label names the flag in refusals.
pub fn parse_freeze_instant(label: &str, value: &str) -> Result<i64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{label} {value:?} is not RFC 3339"))?;
    Ok(parsed.timestamp_millis())
}

/// RFC 3339 UTC, or the raw millis when the instant is out of range.
pub fn format_freeze_instant(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| ms.to_string())
}

/// Record a failed-target retry on the environment scope without changing the hold object.
pub async fn record_retry(
    ctx: &mut Ctx,
    environment: &str,
    reason: &str,
    actor: &str,
) -> Result<()> {
    require_embedded(ctx)?;
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "retry reason must not be empty");
    anyhow::ensure!(reason.len() <= 1024, "retry reason exceeds 1024 bytes");
    let actor = validate_actor(actor)?;
    append_audit(
        ctx,
        &HoldScope::environment(environment),
        "retry",
        &DeliveryHold {
            reason: reason.into(),
            actor: actor.into(),
            held_at: crate::now_millis(),
        },
    )
    .await
}

/// Pause new execution for `scope`. In-flight applies are unchanged.
pub async fn set(
    ctx: &mut Ctx,
    scope: &HoldScope,
    reason: &str,
    actor: &str,
) -> Result<DeliveryHold> {
    require_embedded(ctx)?;
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "delivery hold reason must not be empty");
    anyhow::ensure!(
        reason.len() <= 1024,
        "delivery hold reason exceeds 1024 bytes"
    );
    let actor = validate_actor(actor)?;
    anyhow::ensure!(
        actor != AUTOMATIC_HOLD_ACTOR,
        "delivery hold actor {AUTOMATIC_HOLD_ACTOR} is reserved for failure-threshold holds"
    );
    scope.require_exists(ctx).await?;
    let hold = DeliveryHold {
        reason: reason.into(),
        actor: actor.into(),
        held_at: crate::now_millis(),
    };
    // Keep a live apply-cancel marker. `set` pauses new work; it must not
    // resume remaining steps of an apply that already recorded cancel.
    ctx.put_keeping_property(hold_object(scope, &hold, None), "cancel_generation")
        .await?;
    append_audit(ctx, scope, "set", &hold).await?;
    Ok(hold)
}

/// Set an environment hold only while `fencing_token` still owns the apply lease.
///
/// Existing holds are left unchanged. A lost fence is a no-op.
pub(crate) async fn set_if_absent_fenced(
    ctx: &mut Ctx,
    environment: &str,
    reason: &str,
    actor: &str,
    generation: u64,
    fencing_token: &str,
) -> Result<Option<DeliveryHold>> {
    require_embedded(ctx)?;
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "delivery hold reason must not be empty");
    anyhow::ensure!(
        reason.len() <= 1024,
        "delivery hold reason exceeds 1024 bytes"
    );
    let actor = validate_actor(actor)?;
    anyhow::ensure!(
        actor != AUTOMATIC_HOLD_ACTOR,
        "delivery hold actor {AUTOMATIC_HOLD_ACTOR} is reserved for failure-threshold holds"
    );
    let scope = HoldScope::environment(environment);
    scope.require_exists(ctx).await?;
    if get(ctx, &scope).await?.is_some() {
        return Ok(None);
    }
    if apply_fence_lost(ctx, environment, generation, fencing_token).await? {
        return Ok(None);
    }
    let hold = DeliveryHold {
        reason: reason.into(),
        actor: actor.into(),
        held_at: crate::now_millis(),
    };
    match ctx
        .guarded_create(
            hold_object(&scope, &hold, None),
            crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
            environment,
            fencing_token,
        )
        .await
    {
        Ok(_) => {}
        Err(error) if is_already_exists(&error) => return get(ctx, &scope).await,
        Err(_) if apply_fence_lost(ctx, environment, generation, fencing_token).await? => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }
    append_audit(ctx, &scope, "set", &hold).await?;
    Ok(Some(hold))
}

/// Pause new execution and ask the apply of `generation` to skip later steps.
///
/// The hold write is fenced by the live apply lease: a takeover or expiry
/// makes this a no-op, and a newer `cancel_generation` is never overwritten.
pub async fn set_cancel(
    ctx: &mut Ctx,
    scope: &HoldScope,
    reason: &str,
    actor: &str,
    generation: u64,
    fencing_token: &str,
) -> Result<Option<DeliveryHold>> {
    require_embedded(ctx)?;
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "delivery hold reason must not be empty");
    anyhow::ensure!(
        reason.len() <= 1024,
        "delivery hold reason exceeds 1024 bytes"
    );
    let actor = validate_actor(actor)?;
    anyhow::ensure!(
        actor != AUTOMATIC_HOLD_ACTOR,
        "delivery hold actor {AUTOMATIC_HOLD_ACTOR} is reserved for failure-threshold holds"
    );
    scope.require_exists(ctx).await?;
    let HoldScope::Environment(environment) = scope else {
        bail!("apply cancel is environment-scoped");
    };
    if apply_fence_lost(ctx, environment, generation, fencing_token).await? {
        return Ok(None);
    }
    if let Some(existing) = cancel_generation(ctx, environment).await? {
        if existing > generation {
            return Ok(None);
        }
        if existing == generation {
            return get(ctx, scope).await;
        }
    }
    let hold = DeliveryHold {
        reason: reason.into(),
        actor: actor.into(),
        held_at: crate::now_millis(),
    };
    let object = hold_object(scope, &hold, Some(generation));
    let namespace = crate::apply::ENVIRONMENT_LEASE_NAMESPACE;
    if get(ctx, scope).await?.is_some() {
        match ctx
            .guarded_update(object, namespace, environment, fencing_token)
            .await
        {
            Ok(_) => {}
            Err(_) if apply_fence_lost(ctx, environment, generation, fencing_token).await? => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    } else {
        match ctx
            .guarded_create(object, namespace, environment, fencing_token)
            .await
        {
            Ok(_) => {}
            Err(error) if is_already_exists(&error) => {
                if let Some(existing) = cancel_generation(ctx, environment).await? {
                    if existing > generation {
                        return Ok(None);
                    }
                    if existing == generation {
                        return get(ctx, scope).await;
                    }
                }
                match ctx
                    .guarded_update(
                        hold_object(scope, &hold, Some(generation)),
                        namespace,
                        environment,
                        fencing_token,
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(_)
                        if apply_fence_lost(ctx, environment, generation, fencing_token)
                            .await? =>
                    {
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(_) if apply_fence_lost(ctx, environment, generation, fencing_token).await? => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    }
    append_audit(ctx, scope, "set", &hold).await?;
    Ok(Some(hold))
}

fn is_already_exists(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<crate::storage::StoreError>()
            .is_some_and(crate::storage::StoreError::is_already_exists)
    })
}

async fn apply_fence_lost(
    ctx: &mut Ctx,
    environment: &str,
    generation: u64,
    fencing_token: &str,
) -> Result<bool> {
    let Some(lease) = ctx
        .get_lease(crate::apply::ENVIRONMENT_LEASE_NAMESPACE, environment)
        .await?
    else {
        return Ok(true);
    };
    Ok(lease.status != "active"
        || lease.generation != generation
        || lease.fencing_token != fencing_token
        || lease.expires_at_ms <= crate::now_millis())
}

/// Apply-lease generation recorded on the environment hold, if any.
pub(crate) async fn cancel_generation(ctx: &mut Ctx, environment: &str) -> Result<Option<u64>> {
    let Some(object) = ctx
        .get(&HoldScope::environment(environment).hold_id())
        .await?
    else {
        return Ok(None);
    };
    if object.kind != HOLD_KIND {
        bail!("object {} is {}, not {HOLD_KIND}", object.id, object.kind);
    }
    match object.properties.get("cancel_generation") {
        Some(value) if !value.is_empty() => Ok(Some(value.parse()?)),
        _ => Ok(None),
    }
}

/// Remove the hold so the next tick may execute; returns the hold that was cleared.
pub async fn clear(ctx: &mut Ctx, scope: &HoldScope, actor: &str) -> Result<DeliveryHold> {
    require_embedded(ctx)?;
    let actor = validate_actor(actor)?;
    scope.require_exists(ctx).await?;
    let Some(cleared) = get(ctx, scope).await? else {
        bail!("{} has no delivery hold", scope.key());
    };
    ctx.delete(&scope.hold_id()).await?;
    append_audit(
        ctx,
        scope,
        "clear",
        &DeliveryHold {
            reason: cleared.reason.clone(),
            actor: actor.into(),
            held_at: crate::now_millis(),
        },
    )
    .await?;
    Ok(cleared)
}

/// Clear the hold only while its reason is still `reason`.
///
/// The property check and delete share one store transaction so a concurrent
/// set or cancel cannot be removed by this call. A replacement that still
/// has this reason is another hold of the same kind (rollback `--no-hold`
/// skips the post-rollback pause; cancel's default reason is not `rollback`).
pub async fn clear_if_reason(
    ctx: &mut Ctx,
    scope: &HoldScope,
    actor: &str,
    reason: &str,
) -> Result<Option<DeliveryHold>> {
    require_embedded(ctx)?;
    let actor = validate_actor(actor)?;
    scope.require_exists(ctx).await?;
    let Some(cleared) = get(ctx, scope).await? else {
        return Ok(None);
    };
    if cleared.reason != reason {
        return Ok(None);
    }
    if !ctx
        .delete_if_property(&scope.hold_id(), "reason", reason)
        .await?
    {
        return Ok(None);
    }
    append_audit(
        ctx,
        scope,
        "clear",
        &DeliveryHold {
            reason: cleared.reason.clone(),
            actor: actor.into(),
            held_at: crate::now_millis(),
        },
    )
    .await?;
    Ok(Some(cleared))
}

/// The active hold for `scope`, if any.
pub async fn get(ctx: &mut Ctx, scope: &HoldScope) -> Result<Option<DeliveryHold>> {
    let Some(object) = ctx.get(&scope.hold_id()).await? else {
        return Ok(None);
    };
    if object.kind != HOLD_KIND {
        bail!("object {} is {}, not {HOLD_KIND}", object.id, object.kind);
    }
    Ok(Some(DeliveryHold {
        reason: required(&object, "reason")?.into(),
        actor: required(&object, "actor")?.into(),
        held_at: required(&object, "held_at")?.parse()?,
    }))
}

/// The first hold that pauses `plan`: its environment, then each input channel.
/// Rollback-only plans are recovery and never held.
pub async fn active_for_plan(
    ctx: &mut Ctx,
    plan: &crate::plan::Plan,
) -> Result<Option<DeliveryPause>> {
    active_for_plan_at(ctx, plan, crate::now_millis()).await
}

/// Evaluate holds and freezes at `now_ms` so two replicas of the same instant
/// agree without writing at start or end.
pub async fn active_for_plan_at(
    ctx: &mut Ctx,
    plan: &crate::plan::Plan,
    now_ms: i64,
) -> Result<Option<DeliveryPause>> {
    if plan
        .steps
        .iter()
        .all(|step| step.action == crate::plan::Action::Rollback)
    {
        return Ok(None);
    }
    let scopes = std::iter::once(HoldScope::environment(&plan.environment)).chain(
        plan.inputs
            .iter()
            .map(|input| HoldScope::channel(&input.product, &input.channel)),
    );
    for scope in scopes {
        if let Some(hold) = get(ctx, &scope).await? {
            return Ok(Some(DeliveryPause::Hold { hold, scope }));
        }
    }
    if let Some(freeze) = active_freeze(ctx, &plan.environment, now_ms).await? {
        return Ok(Some(DeliveryPause::Freeze(freeze)));
    }
    Ok(None)
}

/// Refuse to start `plan` while a hold or freeze pauses it.
pub async fn require_not_held(ctx: &mut Ctx, plan: &crate::plan::Plan) -> Result<()> {
    require_not_held_at(ctx, plan, crate::now_millis()).await
}

pub async fn require_not_held_at(
    ctx: &mut Ctx,
    plan: &crate::plan::Plan,
    now_ms: i64,
) -> Result<()> {
    match active_for_plan_at(ctx, plan, now_ms).await? {
        Some(DeliveryPause::Hold { hold, scope }) => bail!(
            "plan {} is paused by delivery hold {} set by {}: {}; clear the hold to execute",
            plan.id,
            scope.key(),
            hold.actor,
            hold.reason
        ),
        Some(DeliveryPause::Freeze(freeze)) => bail!(
            "plan {} is paused by freeze {} until {}: {}; cancel the freeze to execute",
            plan.id,
            freeze.name,
            format_freeze_instant(freeze.until_ms),
            freeze.reason
        ),
        None => Ok(()),
    }
}

/// True when an operator hold or an active freeze pauses `environment`.
pub async fn environment_delivery_held(
    ctx: &mut Ctx,
    environment: &str,
    now_ms: i64,
) -> Result<bool> {
    if get(ctx, &HoldScope::environment(environment))
        .await?
        .is_some()
    {
        return Ok(true);
    }
    Ok(active_freeze(ctx, environment, now_ms).await?.is_some())
}

/// Record a named freeze. `until_ms` must be after `from_ms`.
pub async fn schedule_freeze(
    ctx: &mut Ctx,
    environment: &str,
    name: &str,
    from_ms: i64,
    until_ms: i64,
    reason: &str,
    actor: &str,
) -> Result<DeliveryFreeze> {
    require_embedded(ctx)?;
    let reason = reason.trim();
    anyhow::ensure!(
        !reason.is_empty(),
        "delivery freeze reason must not be empty"
    );
    anyhow::ensure!(
        reason.len() <= 1024,
        "delivery freeze reason exceeds 1024 bytes"
    );
    let actor = validate_actor(actor)?;
    validate_identifier("environment", environment)?;
    validate_identifier("freeze", name)?;
    crate::environment::environment(ctx, environment).await?;
    anyhow::ensure!(until_ms > from_ms, "--until must be after --from");
    let freeze = DeliveryFreeze {
        name: name.into(),
        environment: environment.into(),
        from_ms,
        until_ms,
        reason: reason.into(),
        actor: actor.into(),
        scheduled_at: crate::now_millis(),
    };
    ctx.put(freeze_object(&freeze)).await?;
    append_audit(
        ctx,
        &HoldScope::environment(environment),
        "set",
        &DeliveryHold {
            reason: format!("{}: {}", freeze.name, freeze.reason),
            actor: freeze.actor.clone(),
            held_at: freeze.scheduled_at,
        },
    )
    .await?;
    Ok(freeze)
}

/// Remove a freeze. An operator hold on the same environment is unchanged.
pub async fn cancel_freeze(
    ctx: &mut Ctx,
    environment: &str,
    name: &str,
    actor: &str,
) -> Result<DeliveryFreeze> {
    require_embedded(ctx)?;
    let actor = validate_actor(actor)?;
    validate_identifier("environment", environment)?;
    validate_identifier("freeze", name)?;
    crate::environment::environment(ctx, environment).await?;
    let Some(cleared) = get_freeze(ctx, environment, name).await? else {
        bail!("environment {environment} has no freeze {name}");
    };
    ctx.delete(&freeze_id(environment, name)).await?;
    append_audit(
        ctx,
        &HoldScope::environment(environment),
        "clear",
        &DeliveryHold {
            reason: format!("{}: {}", cleared.name, cleared.reason),
            actor: actor.into(),
            held_at: crate::now_millis(),
        },
    )
    .await?;
    Ok(cleared)
}

/// Active freeze covering `now_ms`, if any. Earliest `until`, then name.
pub async fn active_freeze(
    ctx: &mut Ctx,
    environment: &str,
    now_ms: i64,
) -> Result<Option<DeliveryFreeze>> {
    let mut active: Vec<DeliveryFreeze> = list_freezes(ctx, environment)
        .await?
        .into_iter()
        .filter(|freeze| freeze.active_at(now_ms))
        .collect();
    active.sort_by(|left, right| {
        left.until_ms
            .cmp(&right.until_ms)
            .then(left.name.cmp(&right.name))
    });
    Ok(active.into_iter().next())
}

/// Active and upcoming freezes for `environment`, soonest first.
pub async fn visible_freezes(
    ctx: &mut Ctx,
    environment: &str,
    now_ms: i64,
) -> Result<Vec<DeliveryFreeze>> {
    let mut freezes: Vec<DeliveryFreeze> = list_freezes(ctx, environment)
        .await?
        .into_iter()
        .filter(|freeze| freeze.active_at(now_ms) || freeze.upcoming_at(now_ms))
        .collect();
    freezes.sort_by(|left, right| {
        left.from_ms
            .cmp(&right.from_ms)
            .then(left.until_ms.cmp(&right.until_ms))
            .then(left.name.cmp(&right.name))
    });
    Ok(freezes)
}

async fn list_freezes(ctx: &mut Ctx, environment: &str) -> Result<Vec<DeliveryFreeze>> {
    let mut freezes = Vec::new();
    for object in ctx.list_kind(FREEZE_KIND).await? {
        if object.properties.get("environment") != Some(&environment.to_string()) {
            continue;
        }
        freezes.push(freeze_from_object(&object)?);
    }
    Ok(freezes)
}

async fn get_freeze(
    ctx: &mut Ctx,
    environment: &str,
    name: &str,
) -> Result<Option<DeliveryFreeze>> {
    let Some(object) = ctx.get(&freeze_id(environment, name)).await? else {
        return Ok(None);
    };
    if object.kind != FREEZE_KIND {
        bail!("object {} is {}, not {FREEZE_KIND}", object.id, object.kind);
    }
    Ok(Some(freeze_from_object(&object)?))
}

fn freeze_id(environment: &str, name: &str) -> String {
    format!("tenkai:delivery_freeze:environment:{environment}:{name}")
}

fn freeze_from_object(object: &Object) -> Result<DeliveryFreeze> {
    Ok(DeliveryFreeze {
        name: required(object, "name")?.into(),
        environment: required(object, "environment")?.into(),
        from_ms: required(object, "from")?.parse()?,
        until_ms: required(object, "until")?.parse()?,
        reason: required(object, "reason")?.into(),
        actor: required(object, "actor")?.into(),
        scheduled_at: required(object, "scheduled_at")?.parse()?,
    })
}

fn freeze_object(freeze: &DeliveryFreeze) -> Object {
    Object {
        id: freeze_id(&freeze.environment, &freeze.name),
        kind: FREEZE_KIND.into(),
        name: freeze.name.clone(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("environment".into(), freeze.environment.clone()),
            ("name".into(), freeze.name.clone()),
            ("from".into(), freeze.from_ms.to_string()),
            ("until".into(), freeze.until_ms.to_string()),
            ("reason".into(), freeze.reason.clone()),
            ("actor".into(), freeze.actor.clone()),
            ("scheduled_at".into(), freeze.scheduled_at.to_string()),
        ]),
        created: freeze.scheduled_at,
        updated: freeze.scheduled_at,
    }
}

/// Parse `--window`: integer milliseconds, or a count with `ms`, `s`, `m`, or `h`.
pub fn parse_failure_window(value: &str) -> Result<i64> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "--window must not be empty");
    let (digits, multiplier) = if let Some(digits) = value.strip_suffix("ms") {
        (digits, 1_i64)
    } else if let Some(digits) = value.strip_suffix('s') {
        (digits, 1_000)
    } else if let Some(digits) = value.strip_suffix('m') {
        (digits, 60_000)
    } else if let Some(digits) = value.strip_suffix('h') {
        (digits, 3_600_000)
    } else {
        (value, 1)
    };
    let amount: i64 = digits
        .trim()
        .parse()
        .with_context(|| format!("--window {value:?} is not a duration"))?;
    anyhow::ensure!(amount > 0, "--window must be greater than zero");
    amount
        .checked_mul(multiplier)
        .filter(|ms| *ms > 0)
        .ok_or_else(|| anyhow::anyhow!("--window {value:?} overflows milliseconds"))
}

fn threshold_id(environment: &str) -> String {
    format!("tenkai:delivery_failure_threshold:environment:{environment}")
}

/// Record the failure threshold for `environment`. Unset means the feature is off.
pub async fn set_failure_threshold(
    ctx: &mut Ctx,
    environment: &str,
    count: u32,
    window_ms: i64,
    actor: &str,
) -> Result<FailureThreshold> {
    require_embedded(ctx)?;
    anyhow::ensure!(count >= 1, "--count must be at least 1");
    anyhow::ensure!(window_ms > 0, "--window must be greater than zero");
    let actor = validate_actor(actor)?;
    validate_identifier("environment", environment)?;
    crate::environment::environment(ctx, environment).await?;
    let threshold = FailureThreshold {
        environment: environment.into(),
        count,
        window_ms,
        actor: actor.into(),
        set_at: crate::now_millis(),
    };
    ctx.put(threshold_object(&threshold)).await?;
    Ok(threshold)
}

/// Remove the failure threshold. An active hold is unchanged.
pub async fn clear_failure_threshold(
    ctx: &mut Ctx,
    environment: &str,
    actor: &str,
) -> Result<FailureThreshold> {
    require_embedded(ctx)?;
    let _actor = validate_actor(actor)?;
    validate_identifier("environment", environment)?;
    crate::environment::environment(ctx, environment).await?;
    let Some(cleared) = get_failure_threshold(ctx, environment).await? else {
        bail!("environment {environment} has no failure threshold");
    };
    ctx.delete(&threshold_id(environment)).await?;
    Ok(cleared)
}

/// Declared threshold for `environment`, if any.
pub async fn get_failure_threshold(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<Option<FailureThreshold>> {
    let Some(object) = ctx.get(&threshold_id(environment)).await? else {
        return Ok(None);
    };
    if object.kind != THRESHOLD_KIND {
        bail!(
            "object {} is {}, not {THRESHOLD_KIND}",
            object.id,
            object.kind
        );
    }
    Ok(Some(FailureThreshold {
        environment: required(&object, "environment")?.into(),
        count: required(&object, "count")?.parse()?,
        window_ms: required(&object, "window_ms")?.parse()?,
        actor: required(&object, "actor")?.into(),
        set_at: required(&object, "set_at")?.parse()?,
    }))
}

fn threshold_object(threshold: &FailureThreshold) -> Object {
    Object {
        id: threshold_id(&threshold.environment),
        kind: THRESHOLD_KIND.into(),
        name: threshold.environment.clone(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("environment".into(), threshold.environment.clone()),
            ("count".into(), threshold.count.to_string()),
            ("window_ms".into(), threshold.window_ms.to_string()),
            ("actor".into(), threshold.actor.clone()),
            ("set_at".into(), threshold.set_at.to_string()),
        ]),
        created: threshold.set_at,
        updated: threshold.set_at,
    }
}

/// Set or lift the automatic environment hold from the declared threshold.
///
/// An operator hold is never replaced or cleared. `create_once` refuses to
/// overwrite a hold that already exists; lift deletes only while actor is
/// still `automatic`, in one store transaction.
pub async fn evaluate_failure_threshold(
    ctx: &mut Ctx,
    environment: &str,
    now_ms: i64,
) -> Result<()> {
    let Some(threshold) = get_failure_threshold(ctx, environment).await? else {
        return Ok(());
    };
    let env = crate::environment::environment(ctx, environment).await?;
    let failures = in_window_failed_targets(&env.properties, now_ms, threshold.window_ms);
    let scope = HoldScope::environment(environment);
    if failures.len() > threshold.count as usize {
        try_set_automatic_hold(ctx, &scope, &failures).await
    } else {
        try_clear_automatic_hold(ctx, &scope).await
    }
}

async fn try_set_automatic_hold(
    ctx: &mut Ctx,
    scope: &HoldScope,
    failures: &[(String, String)],
) -> Result<()> {
    require_embedded(ctx)?;
    if get(ctx, scope).await?.is_some() {
        return Ok(());
    }
    let reason = automatic_hold_reason(failures);
    let hold = DeliveryHold {
        reason,
        actor: AUTOMATIC_HOLD_ACTOR.into(),
        held_at: crate::now_millis(),
    };
    match ctx.create_once(hold_object(scope, &hold, None)).await {
        Ok(_) => {
            append_audit(ctx, scope, "set", &hold).await?;
            announce_automatic_hold(ctx, scope, &hold).await;
            Ok(())
        }
        Err(status) if crate::client::is_unique_conflict(&status) => Ok(()),
        Err(status) => Err(status.into()),
    }
}

async fn announce_automatic_hold(ctx: &mut Ctx, scope: &HoldScope, hold: &DeliveryHold) {
    let Some(store) = ctx.embedded_arc() else {
        return;
    };
    // Automatic holds are environment-scoped; channel holds are operator-set.
    let HoldScope::Environment(env) = scope else {
        return;
    };
    let endpoints = crate::owner::environment_notification_endpoints(ctx, env)
        .await
        .unwrap_or_default();
    if endpoints.is_empty() && crate::smtp_digest::installed().is_empty() {
        return;
    }
    let scope_key = scope.key();
    let key = hold.held_at.to_string();
    crate::operational_events::announce(
        store.as_ref(),
        &endpoints,
        &crate::operational_events::Transition {
            event: crate::deploy_webhook::OperationalEvent::AutomaticHold,
            scope: env,
            resource: &scope_key,
            code: "automatic",
            key: &key,
        },
        crate::now_millis(),
    );
}

async fn try_clear_automatic_hold(ctx: &mut Ctx, scope: &HoldScope) -> Result<()> {
    require_embedded(ctx)?;
    let Some(existing) = get(ctx, scope).await? else {
        return Ok(());
    };
    if existing.actor != AUTOMATIC_HOLD_ACTOR {
        return Ok(());
    }
    let deleted = ctx
        .delete_if_property(&scope.hold_id(), "actor", AUTOMATIC_HOLD_ACTOR)
        .await?;
    if !deleted {
        return Ok(());
    }
    append_audit(
        ctx,
        scope,
        "clear",
        &DeliveryHold {
            reason: existing.reason,
            actor: AUTOMATIC_HOLD_ACTOR.into(),
            held_at: crate::now_millis(),
        },
    )
    .await
}

fn in_window_failed_targets(
    properties: &HashMap<String, String>,
    now_ms: i64,
    window_ms: i64,
) -> Vec<(String, String)> {
    let mut failures = Vec::new();
    for (key, release) in properties {
        let Some(instance) = key.strip_prefix("failed_target.") else {
            continue;
        };
        if instance.is_empty() {
            continue;
        }
        let Some(at) = properties
            .get(&format!("failed_target_at.{instance}"))
            .and_then(|value| value.parse::<i64>().ok())
        else {
            continue;
        };
        if at > now_ms || now_ms.saturating_sub(at) > window_ms {
            continue;
        }
        let cause = properties
            .get(&format!("failed_target_error.{instance}"))
            .and_then(|value| value.split_once('\n').map(|(_, detail)| detail))
            .filter(|detail| !detail.is_empty())
            .unwrap_or(release.as_str());
        failures.push((instance.to_string(), cause.to_string()));
    }
    failures.sort_by(|left, right| left.0.cmp(&right.0));
    failures
}

fn automatic_hold_reason(failures: &[(String, String)]) -> String {
    let mut reason = format!("automatic: {} failed target(s)", failures.len());
    for (instance, cause) in failures {
        let next = format!("; {instance} ({cause})");
        if reason.len() + next.len() > 1024 {
            break;
        }
        reason.push_str(&next);
    }
    reason
}

/// Set and clear events for `scope`, oldest first.
pub async fn audit(ctx: &mut Ctx, scope: &HoldScope) -> Result<Vec<HoldAuditEvent>> {
    let key = scope.key();
    let mut events = Vec::new();
    for object in ctx.list_kind(HOLD_AUDIT_KIND).await? {
        if object.properties.get("scope") != Some(&key) {
            continue;
        }
        events.push(HoldAuditEvent {
            action: required(&object, "action")?.into(),
            reason: required(&object, "reason")?.into(),
            actor: required(&object, "actor")?.into(),
            at: required(&object, "at")?.parse()?,
        });
    }
    events.sort_by_key(|event| event.at);
    Ok(events)
}

fn validate_actor(actor: &str) -> Result<&str> {
    let actor = actor.trim();
    anyhow::ensure!(!actor.is_empty(), "delivery hold actor must not be empty");
    anyhow::ensure!(actor.len() <= 256, "delivery hold actor exceeds 256 bytes");
    Ok(actor)
}

fn require_embedded(ctx: &Ctx) -> Result<()> {
    anyhow::ensure!(
        ctx.is_embedded(),
        "delivery hold through a remote catalog must use the authenticated management route"
    );
    Ok(())
}

fn required<'a>(object: &'a Object, key: &str) -> Result<&'a str> {
    object
        .properties
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("{} has no {key}", object.id))
}

fn hold_object(scope: &HoldScope, hold: &DeliveryHold, cancel_generation: Option<u64>) -> Object {
    let mut properties = HashMap::from([
        ("scope".into(), scope.key()),
        ("reason".into(), hold.reason.clone()),
        ("actor".into(), hold.actor.clone()),
        ("held_at".into(), hold.held_at.to_string()),
    ]);
    if let Some(generation) = cancel_generation {
        properties.insert("cancel_generation".into(), generation.to_string());
    }
    Object {
        id: scope.hold_id(),
        kind: HOLD_KIND.into(),
        name: scope.key(),
        namespace: NS.into(),
        external_id: String::new(),
        properties,
        created: hold.held_at,
        updated: hold.held_at,
    }
}

async fn append_audit(
    ctx: &mut Ctx,
    scope: &HoldScope,
    action: &str,
    event: &DeliveryHold,
) -> Result<()> {
    let key = scope.key();
    for sequence in 0..1024_u16 {
        let id = format!(
            "tenkai:delivery_hold_audit:{key}:{}:{sequence}",
            event.held_at
        );
        let object = Object {
            id: id.clone(),
            kind: HOLD_AUDIT_KIND.into(),
            name: format!("{action} {key}"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("scope".into(), key.clone()),
                ("action".into(), action.into()),
                ("reason".into(), event.reason.clone()),
                ("actor".into(), event.actor.clone()),
                ("at".into(), event.held_at.to_string()),
            ]),
            created: event.held_at,
            updated: event.held_at,
        };
        match ctx.create_once(object).await {
            Ok(_) => return Ok(()),
            Err(status) if crate::client::is_unique_conflict(&status) => {}
            Err(status) => return Err(status.into()),
        }
    }
    bail!("could not allocate a delivery hold audit event for {key}")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn temp_ctx(label: &str) -> (std::path::PathBuf, Ctx) {
        let database = std::env::temp_dir().join(format!(
            "tenkai-delivery-hold-{label}-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        (database, ctx)
    }

    #[tokio::test]
    async fn set_keeps_a_live_cancel_generation() {
        let (database, mut ctx) = temp_ctx("preserve-cancel").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        let lease = crate::apply::claim_environment(&mut ctx, "lab", "plan-1")
            .await
            .unwrap();
        let scope = HoldScope::environment("lab");
        set_cancel(
            &mut ctx,
            &scope,
            "stop",
            "alice",
            lease.generation,
            &lease.fencing_token,
        )
        .await
        .unwrap();
        set(&mut ctx, &scope, "maintenance", "bob").await.unwrap();
        assert_eq!(
            cancel_generation(&mut ctx, "lab").await.unwrap(),
            Some(lease.generation)
        );
        crate::apply::release_environment(&mut ctx, &lease)
            .await
            .unwrap();
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn clear_if_reason_leaves_a_replaced_hold() {
        let (database, mut ctx) = temp_ctx("clear-if-reason").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        let scope = HoldScope::environment("lab");
        set(&mut ctx, &scope, "rollback", "alice").await.unwrap();
        set(&mut ctx, &scope, "maintenance", "bob").await.unwrap();
        assert!(
            clear_if_reason(&mut ctx, &scope, "alice", "rollback")
                .await
                .unwrap()
                .is_none()
        );
        let kept = get(&mut ctx, &scope).await.unwrap().unwrap();
        assert_eq!(kept.reason, "maintenance");
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn set_cancel_without_the_live_fence_is_a_noop() {
        let (database, mut ctx) = temp_ctx("cancel-fence").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        let lease = crate::apply::claim_environment(&mut ctx, "lab", "plan-1")
            .await
            .unwrap();
        let wrote = set_cancel(
            &mut ctx,
            &HoldScope::environment("lab"),
            "stop",
            "alice",
            lease.generation,
            "not-the-token",
        )
        .await
        .unwrap();
        assert!(wrote.is_none());
        assert!(
            get(&mut ctx, &HoldScope::environment("lab"))
                .await
                .unwrap()
                .is_none()
        );
        crate::apply::release_environment(&mut ctx, &lease)
            .await
            .unwrap();
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn set_and_clear_are_audited_and_clear_keeps_history() {
        let (database, mut ctx) = temp_ctx("env").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        let scope = HoldScope::Environment("lab".into());
        let hold = set(&mut ctx, &scope, "freeze", "alice").await.unwrap();
        assert_eq!(get(&mut ctx, &scope).await.unwrap(), Some(hold.clone()));

        let cleared = clear(&mut ctx, &scope, "bob").await.unwrap();
        assert_eq!(cleared, hold);
        assert_eq!(get(&mut ctx, &scope).await.unwrap(), None);
        let history = audit(&mut ctx, &scope).await.unwrap();
        let actions: Vec<_> = history
            .iter()
            .map(|event| (event.action.as_str(), event.actor.as_str()))
            .collect();
        assert_eq!(actions, [("set", "alice"), ("clear", "bob")]);

        let error = clear(&mut ctx, &scope, "bob").await.unwrap_err();
        assert!(error.to_string().contains("no delivery hold"), "{error}");
        let error = set(&mut ctx, &scope, "  ", "alice").await.unwrap_err();
        assert!(error.to_string().contains("reason"), "{error}");
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn channel_hold_survives_promote() {
        let (database, mut ctx) = temp_ctx("channel").await;
        let root = database.with_extension("manifest");
        std::fs::create_dir_all(&root).unwrap();
        let options = crate::catalog::PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        let actor = crate::auth_context::test_management_context("hold-promote");
        for version in ["1.0.0", "1.1.0"] {
            std::fs::write(
                root.join("tenkai.toml"),
                format!(
                    "[product]\nname = \"hold-demo\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\n"
                ),
            )
            .unwrap();
            crate::catalog::publish(&mut ctx, &root.join("tenkai.toml"), &options)
                .await
                .unwrap();
        }
        crate::catalog::promote(&mut ctx, &actor, "hold-demo@1.0.0", "stable")
            .await
            .unwrap();
        let scope = HoldScope::Channel {
            product: "hold-demo".into(),
            channel: "stable".into(),
        };
        let hold = set(&mut ctx, &scope, "pause", "carol").await.unwrap();
        crate::catalog::promote(&mut ctx, &actor, "hold-demo@1.1.0", "stable")
            .await
            .unwrap();
        assert_eq!(get(&mut ctx, &scope).await.unwrap(), Some(hold));
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn retry_plans_a_held_failed_target() {
        let (database, mut ctx) = temp_ctx("retry").await;
        let root = database.with_extension("manifest");
        std::fs::create_dir_all(&root).unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        let options = crate::catalog::PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        std::fs::write(
            root.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        crate::catalog::publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("hold-retry");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        let channel = ctx
            .get(&crate::ontology::channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap();
        let release = channel.properties["current_release"].clone();
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties
            .insert("failed_target.api".into(), release.clone());
        ctx.put(env).await.unwrap();

        let plan = crate::plan::create_for_held_target(&mut ctx, "local", "api", &release)
            .await
            .unwrap();
        record_retry(&mut ctx, "local", "retry after fix", "alice")
            .await
            .unwrap();
        assert!(
            plan.steps
                .iter()
                .any(|step| step.product == "api" && step.release_id == release),
            "{plan:?}"
        );
        let history = audit(&mut ctx, &HoldScope::environment("local"))
            .await
            .unwrap();
        assert_eq!(history.last().unwrap().action, "retry");
        assert_eq!(history.last().unwrap().reason, "retry after fix");
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn retry_excludes_a_held_target_after_the_channel_moves() {
        let (database, mut ctx) = temp_ctx("retry-moved").await;
        let root = database.with_extension("manifest");
        std::fs::create_dir_all(&root).unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        let options = crate::catalog::PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        let actor = crate::auth_context::test_management_context("hold-retry");
        for version in ["1.0.0", "1.1.0"] {
            std::fs::write(
                root.join("tenkai.toml"),
                format!(
                    "[product]\nname = \"api\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\n"
                ),
            )
            .unwrap();
            crate::catalog::publish(&mut ctx, &root.join("tenkai.toml"), &options)
                .await
                .unwrap();
        }
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        let channel = ctx
            .get(&crate::ontology::channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap();
        let held = channel.properties["current_release"].clone();
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties
            .insert("failed_target.api".into(), held.clone());
        ctx.put(env).await.unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();

        let error = crate::plan::create_for_held_target(&mut ctx, "local", "api", &held)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("did not include held failed target"),
            "{error}"
        );
        assert!(
            audit(&mut ctx, &HoldScope::environment("local"))
                .await
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn deploy_plan(env: &str) -> crate::plan::Plan {
        crate::plan::Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: "tenkai:plan:freeze-test".into(),
            content_id: "c".into(),
            environment: env.into(),
            created_at: 1,
            inputs: Vec::new(),
            steps: vec![crate::plan::Step {
                id: "s".into(),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action: crate::plan::Action::Upgrade,
                from: None,
                to: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "sha256:x".into(),
                artifact_digest: "sha256:y".into(),
                workdir: "/".into(),
                restore: None,
                host: None,
                sealed: Vec::new(),
                rewrap: None,
                issuer: None,
                identity: None,
                restore_identity: None,
                target_changes: Vec::new(),
            }],
            state: crate::plan::PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
            approval_brief: None,
        }
    }

    #[tokio::test]
    async fn freeze_refuses_inside_range_and_admits_outside() {
        let (database, mut ctx) = temp_ctx("freeze-range").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        let from = 1_000;
        let until = 2_000;
        schedule_freeze(
            &mut ctx,
            "lab",
            "black-friday",
            from,
            until,
            "holiday",
            "alice",
        )
        .await
        .unwrap();
        let plan = deploy_plan("lab");
        assert!(
            active_for_plan_at(&mut ctx, &plan, from)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            active_for_plan_at(&mut ctx, &plan, until - 1)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            active_for_plan_at(&mut ctx, &plan, from - 1)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            active_for_plan_at(&mut ctx, &plan, until)
                .await
                .unwrap()
                .is_none()
        );
        let first = active_for_plan_at(&mut ctx, &plan, 1_500).await.unwrap();
        let second = active_for_plan_at(&mut ctx, &plan, 1_500).await.unwrap();
        assert_eq!(first, second);
        let error = require_not_held_at(&mut ctx, &plan, 1_500)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("freeze black-friday"), "{error}");
        assert!(error.contains("cancel the freeze"), "{error}");
        let mut rollback = plan.clone();
        rollback.steps[0].action = crate::plan::Action::Rollback;
        require_not_held_at(&mut ctx, &rollback, 1_500)
            .await
            .unwrap();
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn freeze_and_hold_are_independent() {
        let (database, mut ctx) = temp_ctx("freeze-hold").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        let scope = HoldScope::environment("lab");
        set(&mut ctx, &scope, "operator", "alice").await.unwrap();
        schedule_freeze(&mut ctx, "lab", "holiday", 1_000, 2_000, "freeze", "bob")
            .await
            .unwrap();
        cancel_freeze(&mut ctx, "lab", "holiday", "carol")
            .await
            .unwrap();
        assert!(get(&mut ctx, &scope).await.unwrap().is_some());
        set(&mut ctx, &scope, "operator", "alice").await.unwrap();
        schedule_freeze(&mut ctx, "lab", "holiday", 1_000, 2_000, "freeze", "bob")
            .await
            .unwrap();
        clear(&mut ctx, &scope, "alice").await.unwrap();
        assert!(
            active_freeze(&mut ctx, "lab", 1_500)
                .await
                .unwrap()
                .is_some()
        );
        let error = schedule_freeze(&mut ctx, "lab", "bad", 2_000, 2_000, "same", "alice")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("--until must be after --from"), "{error}");
        let _ = std::fs::remove_file(&database);
    }

    #[test]
    fn freeze_instant_is_rfc3339() {
        assert!(parse_freeze_instant("--from", "not-a-time").is_err());
        let ms = parse_freeze_instant("--until", "2026-11-28T00:00:00Z").unwrap();
        assert_eq!(format_freeze_instant(ms), "2026-11-28T00:00:00Z");
    }

    async fn mark_failed(ctx: &mut Ctx, env: &str, instance: &str, at: i64, cause: &str) {
        let mut object = crate::environment::environment(ctx, env).await.unwrap();
        let release = format!("tenkai:release:{instance}@1.0.0");
        object
            .properties
            .insert(format!("failed_target.{instance}"), release.clone());
        object
            .properties
            .insert(format!("failed_target_at.{instance}"), at.to_string());
        object.properties.insert(
            format!("failed_target_error.{instance}"),
            format!("{release}\n{cause}"),
        );
        ctx.put(object).await.unwrap();
    }

    #[tokio::test]
    async fn crossing_threshold_sets_one_automatic_hold() {
        let (database, mut ctx) = temp_ctx("threshold-set").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        set_failure_threshold(&mut ctx, "lab", 1, 60_000, "alice")
            .await
            .unwrap();
        let now = 100_000;
        mark_failed(&mut ctx, "lab", "api", now - 1_000, "probe failed").await;
        mark_failed(&mut ctx, "lab", "web", now - 2_000, "crash").await;
        evaluate_failure_threshold(&mut ctx, "lab", now)
            .await
            .unwrap();
        evaluate_failure_threshold(&mut ctx, "lab", now)
            .await
            .unwrap();
        let scope = HoldScope::environment("lab");
        let hold = get(&mut ctx, &scope).await.unwrap().unwrap();
        assert_eq!(hold.actor, AUTOMATIC_HOLD_ACTOR);
        assert!(hold.reason.contains("api"), "{}", hold.reason);
        assert!(hold.reason.contains("web"), "{}", hold.reason);
        let history = audit(&mut ctx, &scope).await.unwrap();
        assert_eq!(history.len(), 1, "{history:?}");
        assert_eq!(history[0].action, "set");
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn dropping_count_clears_automatic_hold_and_leaves_operator_hold() {
        let (database, mut ctx) = temp_ctx("threshold-lift").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        set_failure_threshold(&mut ctx, "lab", 1, 60_000, "alice")
            .await
            .unwrap();
        let now = 100_000;
        mark_failed(&mut ctx, "lab", "api", now - 1_000, "probe failed").await;
        mark_failed(&mut ctx, "lab", "web", now - 2_000, "crash").await;
        evaluate_failure_threshold(&mut ctx, "lab", now)
            .await
            .unwrap();
        let mut env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        env.properties.remove("failed_target.web");
        env.properties.remove("failed_target_at.web");
        env.properties.remove("failed_target_error.web");
        ctx.put(env).await.unwrap();
        evaluate_failure_threshold(&mut ctx, "lab", now)
            .await
            .unwrap();
        let scope = HoldScope::environment("lab");
        assert_eq!(get(&mut ctx, &scope).await.unwrap(), None);

        set(&mut ctx, &scope, "operator", "bob").await.unwrap();
        mark_failed(&mut ctx, "lab", "web", now - 2_000, "crash").await;
        evaluate_failure_threshold(&mut ctx, "lab", now)
            .await
            .unwrap();
        let hold = get(&mut ctx, &scope).await.unwrap().unwrap();
        assert_eq!(hold.actor, "bob");
        assert_eq!(hold.reason, "operator");
        env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        env.properties.remove("failed_target.web");
        env.properties.remove("failed_target_at.web");
        ctx.put(env).await.unwrap();
        evaluate_failure_threshold(&mut ctx, "lab", now)
            .await
            .unwrap();
        let hold = get(&mut ctx, &scope).await.unwrap().unwrap();
        assert_eq!(hold.actor, "bob");
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn no_threshold_never_sets_an_environment_hold() {
        let (database, mut ctx) = temp_ctx("threshold-off").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        let now = 100_000;
        mark_failed(&mut ctx, "lab", "api", now, "probe failed").await;
        mark_failed(&mut ctx, "lab", "web", now, "crash").await;
        evaluate_failure_threshold(&mut ctx, "lab", now)
            .await
            .unwrap();
        assert_eq!(
            get(&mut ctx, &HoldScope::environment("lab")).await.unwrap(),
            None
        );
        let _ = std::fs::remove_file(&database);
    }

    #[test]
    fn failure_window_parses_units() {
        assert_eq!(parse_failure_window("15m").unwrap(), 15 * 60_000);
        assert_eq!(parse_failure_window("2h").unwrap(), 2 * 3_600_000);
        assert_eq!(parse_failure_window("1500").unwrap(), 1500);
        assert!(parse_failure_window("0").is_err());
        assert!(parse_failure_window("nope").is_err());
    }

    #[tokio::test]
    async fn operator_set_refuses_the_automatic_actor() {
        let (database, mut ctx) = temp_ctx("threshold-actor").await;
        crate::environment::env_add(&mut ctx, "lab", "Lab")
            .await
            .unwrap();
        let error = set(
            &mut ctx,
            &HoldScope::environment("lab"),
            "pause",
            AUTOMATIC_HOLD_ACTOR,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("reserved for failure-threshold holds"),
            "{error}"
        );
        let _ = std::fs::remove_file(&database);
    }
}
