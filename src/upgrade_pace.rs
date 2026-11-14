//! Channel upgrade pace: admit a bounded share of subscribed instances as
//! counted maintenance-window time elapses after a promotion.
//!
//! Duration lives on the channel object (same family as soak/health-gate
//! overlays). Admission is a reconciler blocker like a hold: upgrades wait,
//! rollbacks, removals, installs, and restarts do not. Early admission is one
//! audited exemption object per (channel head, instance).

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::ontology::{
    KIND_CHANNEL, KIND_ENVIRONMENT, KIND_INSTANCE, KIND_UPGRADE_PACE_ADMIT,
    KIND_UPGRADE_PACE_ADMIT_AUDIT, NS, REL_SUBSCRIBES, channel_id, env_id, upgrade_pace_admit_id,
    validate_identifier,
};
use crate::pb::sekai::Object;
use crate::plan::{Action, Plan};

/// Configured pace duration on the channel object. Absent means off.
pub const PACE_MS_PROPERTY: &str = "upgrade_pace_ms";
/// Duration frozen for the current head. Changing the configured duration
/// applies on the next promotion; enable/disable uses [`PACE_MS_PROPERTY`].
pub const PACE_APPLIED_MS_PROPERTY: &str = "upgrade_pace_applied_ms";
/// Unix-ms stamp when the current head was set. Survives overlay writes.
pub const PROMOTED_AT_PROPERTY: &str = "promoted_at";

/// Why an upgrade is waiting for the channel pace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaceHold {
    pub product: String,
    pub channel: String,
    pub environment: String,
    pub instance: String,
    pub eligible_at_ms: i64,
    pub admitted: usize,
    pub subscribed: usize,
}

/// One immutable early-admission event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaceAdmitAudit {
    pub action: String,
    pub reason: String,
    pub actor: String,
    pub at: i64,
}

/// Upgrade pacing on a channel's current head (#1276). Only upgrades wait;
/// rollbacks, recall removals, installs, and restarts are never paced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaceProgress {
    /// Release id of the channel head being paced.
    pub release: String,
    /// Counted maintenance-window time over which all instances start.
    pub duration_ms: i64,
    pub promoted_at_ms: i64,
    pub instances: Vec<PaceInstanceProgress>,
}

/// Where one subscribed instance stands in the pace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaceInstanceProgress {
    pub environment: String,
    pub instance: String,
    pub state: PaceInstanceState,
    /// Server time the instance may start, while `waiting` or `paused`:
    /// its remaining counted time projected through the maintenance
    /// windows. Omitted when the windows cannot be projected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub eligible_at_ms: Option<i64>,
    /// When the closed maintenance window next opens, while `paused` and known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub next_opens_at_ms: Option<i64>,
    /// The audited early admission of this instance on this head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub early_admission: Option<PaceAdmitAudit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PaceInstanceState {
    /// Already runs the head.
    Started,
    /// May upgrade now: its slot came or it was admitted early, and its
    /// maintenance windows are open.
    Admitted,
    /// Waits for its slot; `eligible_at_ms` says when.
    Waiting,
    /// Waits while its maintenance window is closed; pace time is not counted.
    /// An admitted instance whose window is closed reads as paused too.
    Paused,
}

/// Copy pace overlay properties so a channel put does not drop them.
pub fn copy_channel_properties(dst: &mut HashMap<String, String>, src: &Object) {
    for key in [
        PACE_MS_PROPERTY,
        PACE_APPLIED_MS_PROPERTY,
        PROMOTED_AT_PROPERTY,
    ] {
        if let Some(value) = src.properties.get(key).filter(|value| !value.is_empty()) {
            dst.insert(key.into(), value.clone());
        }
    }
}

/// Freeze the configured duration and stamp `promoted_at` when the head moves.
pub fn snapshot_on_head_move(dst: &mut HashMap<String, String>, now_ms: i64) {
    dst.insert(PROMOTED_AT_PROPERTY.into(), now_ms.to_string());
    match dst.get(PACE_MS_PROPERTY).cloned() {
        Some(ms) if !ms.is_empty() => {
            dst.insert(PACE_APPLIED_MS_PROPERTY.into(), ms);
        }
        _ => {
            dst.remove(PACE_APPLIED_MS_PROPERTY);
        }
    }
}

/// Parse `--upgrade-pace` as milliseconds, or `off` to clear. A bare number is seconds.
pub fn parse_pace(value: &str) -> Result<Option<i64>> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("off") || value == "0" {
        return Ok(None);
    }
    Ok(Some(parse_duration_ms(value, "upgrade pace")?))
}

fn parse_duration_ms(value: &str, label: &str) -> Result<i64> {
    let value = value.trim();
    let (number, factor) = if let Some(ms) = value.strip_suffix("ms") {
        (ms, 1_i64)
    } else if let Some(hours) = value.strip_suffix('h') {
        (hours, 3_600_000)
    } else if let Some(minutes) = value.strip_suffix('m') {
        (minutes, 60_000)
    } else if let Some(seconds) = value.strip_suffix('s') {
        (seconds, 1_000)
    } else {
        (value, 1_000)
    };
    let amount: i64 = number
        .trim()
        .parse()
        .with_context(|| format!("{label} {value:?} is not a number"))?;
    let ms = amount
        .checked_mul(factor)
        .with_context(|| format!("{label} overflow"))?;
    if ms <= 0 {
        bail!("{label} must be greater than zero");
    }
    Ok(ms)
}

/// Set or clear the channel's upgrade pace. Disable takes effect at once.
pub async fn configure(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    pace_ms: Option<i64>,
) -> Result<Option<i64>> {
    require_local_catalog(ctx)?;
    validate_identifier("product", product)?;
    validate_identifier("channel", channel)?;
    if let Some(ms) = pace_ms
        && ms <= 0
    {
        bail!("upgrade pace must be greater than zero");
    }
    let owner = format!("upgrade-pace:{product}/{channel}:{}", crate::now_millis());
    let lock = crate::canary::claim_promotion_lock(ctx, product, channel, &owner).await?;
    let result = async {
        let id = channel_id(product, channel);
        let mut object = ctx
            .get(&id)
            .await?
            .with_context(|| format!("channel {product}/{channel} is not published"))?;
        if object.kind != KIND_CHANNEL {
            bail!(
                "object {} is {}, not {KIND_CHANNEL}",
                object.id,
                object.kind
            );
        }
        match pace_ms {
            Some(ms) => {
                object
                    .properties
                    .insert(PACE_MS_PROPERTY.into(), ms.to_string());
                // Freeze this head's duration and stamp so later duration
                // changes wait for the next promotion, and overlay writes
                // cannot reset counted time.
                if parse_optional_i64(object.properties.get(PACE_APPLIED_MS_PROPERTY)).is_none() {
                    object
                        .properties
                        .insert(PACE_APPLIED_MS_PROPERTY.into(), ms.to_string());
                }
                if parse_optional_i64(object.properties.get(PROMOTED_AT_PROPERTY)).is_none() {
                    object
                        .properties
                        .insert(PROMOTED_AT_PROPERTY.into(), crate::now_millis().to_string());
                }
            }
            None => {
                object.properties.remove(PACE_MS_PROPERTY);
                object.properties.remove(PACE_APPLIED_MS_PROPERTY);
            }
        }
        crate::canary::fenced_put(ctx, std::slice::from_ref(&lock), object).await?;
        Ok(pace_ms)
    }
    .await;
    let unlock = crate::canary::release_promotion_lock(ctx, &lock).await;
    match (result, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => {
            Err(error.context(format!("releasing promotion lock also failed: {unlock}")))
        }
        (Ok(_), Err(error)) => Err(error.context("releasing promotion lock failed")),
    }
}

/// Admit one instance onto the current head before its paced slot. Audited.
pub async fn admit_early(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    environment: &str,
    instance: &str,
    reason: &str,
    actor: &str,
) -> Result<PaceAdmitAudit> {
    require_local_catalog(ctx)?;
    validate_identifier("product", product)?;
    validate_identifier("channel", channel)?;
    validate_identifier("environment", environment)?;
    crate::ontology::validate_instance_name(instance)
        .or_else(|_| validate_identifier("instance", instance))?;
    let reason = validate_reason(reason)?;
    let actor = validate_actor(actor)?;
    crate::environment::environment(ctx, environment).await?;
    let channel_obj = require_channel(ctx, product, channel).await?;
    let subscribed = list_subscribers(ctx, product, channel).await?;
    if !subscribed
        .iter()
        .any(|(env, name)| env == environment && name == instance)
    {
        bail!("instance {environment}/{instance} is not subscribed to {product}/{channel}");
    }
    let release = channel_obj
        .properties
        .get("current_release")
        .filter(|value| !value.is_empty())
        .cloned()
        .with_context(|| format!("channel {product}/{channel} has no promoted release"))?;
    let id = upgrade_pace_admit_id(product, channel, environment, instance, &release);
    if let Some(existing) = ctx.get(&id).await? {
        return Ok(PaceAdmitAudit {
            action: "set".into(),
            reason: required(&existing, "reason")?.into(),
            actor: required(&existing, "actor")?.into(),
            at: required(&existing, "at")?.parse()?,
        });
    }
    let at = crate::now_millis();
    let event = PaceAdmitAudit {
        action: "set".into(),
        reason: reason.to_string(),
        actor: actor.to_string(),
        at,
    };
    append_audit(
        ctx,
        product,
        channel,
        environment,
        instance,
        &release,
        &event,
    )
    .await?;
    match ctx
        .create_once(Object {
            id: id.clone(),
            kind: KIND_UPGRADE_PACE_ADMIT.into(),
            name: format!("{environment}/{instance}"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("product".into(), product.into()),
                ("channel".into(), channel.into()),
                ("environment".into(), environment.into()),
                ("instance".into(), instance.into()),
                ("release".into(), release.clone()),
                ("reason".into(), event.reason.clone()),
                ("actor".into(), event.actor.clone()),
                ("at".into(), at.to_string()),
            ]),
            created: at,
            updated: at,
        })
        .await
    {
        Ok(_) => {}
        Err(status) if crate::client::is_unique_conflict(&status) => {}
        Err(status) => return Err(status.into()),
    }
    Ok(event)
}

/// Audit events for one instance on the current head, oldest first.
pub async fn admit_audit(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    environment: &str,
    instance: &str,
) -> Result<Vec<PaceAdmitAudit>> {
    let Some(channel_obj) = ctx.get(&channel_id(product, channel)).await? else {
        return Ok(Vec::new());
    };
    let Some(release) = channel_obj
        .properties
        .get("current_release")
        .filter(|value| !value.is_empty())
        .cloned()
    else {
        return Ok(Vec::new());
    };
    let mut events = Vec::new();
    for object in ctx.list_kind(KIND_UPGRADE_PACE_ADMIT_AUDIT).await? {
        if object.properties.get("product").map(String::as_str) != Some(product)
            || object.properties.get("channel").map(String::as_str) != Some(channel)
            || object.properties.get("environment").map(String::as_str) != Some(environment)
            || object.properties.get("instance").map(String::as_str) != Some(instance)
            || object.properties.get("release").map(String::as_str) != Some(release.as_str())
        {
            continue;
        }
        events.push(PaceAdmitAudit {
            action: required(&object, "action")?.into(),
            reason: required(&object, "reason")?.into(),
            actor: required(&object, "actor")?.into(),
            at: required(&object, "at")?.parse()?,
        });
    }
    events.sort_by_key(|event| event.at);
    Ok(events)
}

/// Whether any channel currently has an upgrade pace configured.
pub async fn any_configured(ctx: &mut Ctx) -> Result<bool> {
    for object in ctx.list_kind(KIND_CHANNEL).await? {
        if parse_optional_i64(object.properties.get(PACE_MS_PROPERTY)).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Hold for an upgrade of `instance` in `environment` onto `release_id`.
///
/// Only the subscribed channel's current head is paced. An upgrade onto
/// another selected release is not delayed by this head's `promoted_at`.
pub async fn holds_upgrade(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
    instance: &str,
    release_id: &str,
    now_ms: i64,
) -> Result<Option<PaceHold>> {
    let env_obj = crate::environment::environment(ctx, environment).await?;
    let Some(sub) = crate::environment::list_subscriptions(ctx, &env_obj)
        .await?
        .into_iter()
        .find(|sub| sub.product == product && sub.instance == instance)
    else {
        return Ok(None);
    };
    let channel_name = sub
        .channel
        .properties
        .get("channel")
        .cloned()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            sub.channel
                .id
                .strip_prefix("tenkai:channel:")
                .and_then(|rest| rest.split_once('/'))
                .map(|(_, name)| name.to_string())
        })
        .unwrap_or_default();
    let Some(channel_obj) = ctx.get(&channel_id(product, &channel_name)).await? else {
        return Ok(None);
    };
    match channel_obj.properties.get("current_release") {
        Some(head) if head == release_id => {}
        _ => return Ok(None),
    }
    evaluate_instance(ctx, product, &channel_name, environment, instance, now_ms).await
}

/// Same as [`holds_upgrade`] when the channel is already known.
pub async fn evaluate_instance(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    environment: &str,
    instance: &str,
    now_ms: i64,
) -> Result<Option<PaceHold>> {
    let Some(decision) = evaluate_channel(ctx, product, channel, now_ms).await? else {
        return Ok(None);
    };
    if decision
        .admitted
        .contains(&(environment.to_string(), instance.to_string()))
    {
        return Ok(None);
    }
    Ok(Some(PaceHold {
        product: product.into(),
        channel: channel.into(),
        environment: environment.into(),
        instance: instance.into(),
        eligible_at_ms: decision.eligible_at_ms(environment, instance),
        admitted: decision.admitted.len(),
        subscribed: decision.ranked.len(),
    }))
}

/// Pacing progress of every subscribed instance, or an error when the
/// channel has no pace on its current head.
pub async fn progress(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    now_ms: i64,
) -> Result<PaceProgress> {
    validate_identifier("product", product)?;
    validate_identifier("channel", channel)?;
    require_channel(ctx, product, channel).await?;
    // Every reported field comes from this one head snapshot, so a concurrent
    // promotion cannot mix the old release with the new head's admissions.
    let Some(mut decision) = evaluate_channel(ctx, product, channel, now_ms).await? else {
        bail!("channel {product}/{channel} has no upgrade pace on its current head");
    };
    let release = std::mem::take(&mut decision.release);
    let mut early = std::mem::take(&mut decision.early);
    let product_windows = crate::maintenance::list_product(ctx, product).await?;
    let now = chrono::DateTime::from_timestamp_millis(now_ms)
        .context("pace progress clock is out of range")?;
    let mut instances = Vec::with_capacity(decision.ranked.len());
    for (environment, instance) in &decision.ranked {
        let key = (environment.clone(), instance.clone());
        let early_admission = early.remove(&key);
        let (state, eligible_at_ms, next_opens_at_ms) =
            if instance_started(ctx, environment, instance, &release).await? {
                (PaceInstanceState::Started, None, None)
            } else {
                // An admitted instance still waits for a joint open window,
                // so it reads as admitted only while it could start now.
                let admitted = decision.admitted.contains(&key);
                let remaining_ms = if admitted {
                    0
                } else {
                    decision.remaining_ms(environment, instance)
                };
                let env_windows = crate::maintenance::list(ctx, environment).await?;
                let eligible_at_ms =
                    project_counted(&env_windows, &product_windows, now_ms, remaining_ms);
                match crate::maintenance::intersect(
                    crate::maintenance::evaluate(&env_windows, now),
                    crate::maintenance::evaluate(&product_windows, now),
                ) {
                    crate::maintenance::Eligibility::Open { .. } if admitted => {
                        (PaceInstanceState::Admitted, None, None)
                    }
                    crate::maintenance::Eligibility::Open { .. } => {
                        (PaceInstanceState::Waiting, eligible_at_ms, None)
                    }
                    crate::maintenance::Eligibility::Closed { .. } => (
                        PaceInstanceState::Paused,
                        eligible_at_ms,
                        next_joint_opening(&env_windows, &product_windows, now_ms),
                    ),
                    crate::maintenance::Eligibility::Invalid { .. } => {
                        (PaceInstanceState::Paused, None, None)
                    }
                }
            };
        instances.push(PaceInstanceProgress {
            environment: environment.clone(),
            instance: instance.clone(),
            state,
            eligible_at_ms,
            next_opens_at_ms,
            early_admission,
        });
    }
    Ok(PaceProgress {
        release,
        duration_ms: decision.duration_ms,
        promoted_at_ms: decision.promoted_at_ms,
        instances,
    })
}

/// Refuse to start a plan that still contains a paced-out upgrade.
pub async fn require_for_plan(ctx: &mut Ctx, plan: &Plan, now_ms: i64) -> Result<()> {
    for step in &plan.steps {
        if step.action != Action::Upgrade {
            continue;
        }
        if let Some(hold) = holds_upgrade(
            ctx,
            &plan.environment,
            &step.product,
            step.instance_name(),
            &step.release_id,
            now_ms,
        )
        .await?
        {
            bail!(
                "plan {} is paused by upgrade pace on {}/{} until {}; admit the instance or wait",
                plan.id,
                hold.product,
                hold.channel,
                format_eligible_at(hold.eligible_at_ms)
            );
        }
    }
    Ok(())
}

struct ChannelDecision {
    release: String,
    promoted_at_ms: i64,
    early: HashMap<(String, String), PaceAdmitAudit>,
    ranked: Vec<(String, String)>,
    admitted: BTreeSet<(String, String)>,
    duration_ms: i64,
    now_ms: i64,
    elapsed_by_instance: HashMap<(String, String), i64>,
}

impl ChannelDecision {
    fn eligible_at_ms(&self, environment: &str, instance: &str) -> i64 {
        self.now_ms
            .saturating_add(self.remaining_ms(environment, instance))
    }

    /// Counted window time the instance still needs before its slot.
    fn remaining_ms(&self, environment: &str, instance: &str) -> i64 {
        let key = (environment.to_string(), instance.to_string());
        let Some(index) = self
            .ranked
            .iter()
            .position(|row| row.0 == environment && row.1 == instance)
        else {
            return self.duration_ms;
        };
        let slot = slot_elapsed_ms(index, self.ranked.len(), self.duration_ms);
        let elapsed = self.elapsed_by_instance.get(&key).copied().unwrap_or(0);
        slot.saturating_sub(elapsed).max(0)
    }
}

/// Most window transitions [`project_counted`] walks before giving up.
const MAX_PROJECTED_WINDOWS: usize = 64;

/// Server time at which `remaining_ms` of counted time (inside both window
/// sets) has passed after `now_ms`. `None` when the windows are invalid, never
/// reopen, or need more than [`MAX_PROJECTED_WINDOWS`] transitions.
fn project_counted(
    env_windows: &[crate::maintenance::Window],
    product_windows: &[crate::maintenance::Window],
    now_ms: i64,
    remaining_ms: i64,
) -> Option<i64> {
    use crate::maintenance::{Eligibility, evaluate, intersect};
    let mut at = now_ms;
    let mut remaining = remaining_ms.max(0);
    for _ in 0..MAX_PROJECTED_WINDOWS {
        if remaining == 0 {
            // Windows close exclusively, so a slot earned at a closing edge
            // starts at the next joint opening.
            return next_joint_opening(env_windows, product_windows, at);
        }
        let instant = chrono::DateTime::from_timestamp_millis(at)?;
        match intersect(
            evaluate(env_windows, instant),
            evaluate(product_windows, instant),
        ) {
            Eligibility::Open { closes_at, .. } if closes_at > at => {
                let open = closes_at - at;
                if remaining < open {
                    return Some(at + remaining);
                }
                remaining -= open;
                at = closes_at;
            }
            Eligibility::Closed {
                next_opens_at: Some(next),
            } if next > at => at = next,
            _ => return None,
        }
    }
    None
}

/// First server time at or after `from_ms` when both window sets are open.
/// The operands' own hints may name an opening where the other set is still
/// closed, so this walks forward until they agree. `None` when the windows are
/// invalid, never overlap, or need more than [`MAX_PROJECTED_WINDOWS`] steps.
fn next_joint_opening(
    env_windows: &[crate::maintenance::Window],
    product_windows: &[crate::maintenance::Window],
    from_ms: i64,
) -> Option<i64> {
    use crate::maintenance::{Eligibility, evaluate, intersect};
    let mut at = from_ms;
    for _ in 0..MAX_PROJECTED_WINDOWS {
        let instant = chrono::DateTime::from_timestamp_millis(at)?;
        match intersect(
            evaluate(env_windows, instant),
            evaluate(product_windows, instant),
        ) {
            Eligibility::Open { .. } => return Some(at),
            Eligibility::Closed {
                next_opens_at: Some(next),
            } if next > at => at = next,
            _ => return None,
        }
    }
    None
}

/// How many of `n` instances may start after `elapsed_ms` of a `duration_ms` pace.
pub fn allowed_count(elapsed_ms: i64, duration_ms: i64, n: usize) -> usize {
    if n == 0 || duration_ms <= 0 {
        return n;
    }
    if elapsed_ms >= duration_ms {
        return n;
    }
    if elapsed_ms <= 0 {
        return 0;
    }
    let n = n as u128;
    let elapsed = elapsed_ms.max(0) as u128;
    let duration = duration_ms as u128;
    (n * elapsed / duration) as usize
}

fn slot_elapsed_ms(index: usize, n: usize, duration_ms: i64) -> i64 {
    if n == 0 || duration_ms <= 0 {
        return 0;
    }
    let n = n as i128;
    let duration = duration_ms as i128;
    // Ceiling, so the slot is the first elapsed time `allowed_count` admits.
    let slot = ((index as i128 + 1) * duration + n - 1).div_euclid(n);
    i64::try_from(slot).unwrap_or(i64::MAX)
}

async fn evaluate_channel(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    now_ms: i64,
) -> Result<Option<ChannelDecision>> {
    let channel_obj = match ctx.get(&channel_id(product, channel)).await? {
        Some(object) if object.kind == KIND_CHANNEL => object,
        _ => return Ok(None),
    };
    let Some(configured) = parse_optional_i64(channel_obj.properties.get(PACE_MS_PROPERTY)) else {
        return Ok(None);
    };
    if configured <= 0 {
        return Ok(None);
    }
    let duration_ms = parse_optional_i64(channel_obj.properties.get(PACE_APPLIED_MS_PROPERTY))
        .unwrap_or(configured);
    if duration_ms <= 0 {
        return Ok(None);
    }
    let release = match channel_obj.properties.get("current_release") {
        Some(release) if !release.is_empty() => release.clone(),
        _ => return Ok(None),
    };
    let promoted_at = parse_optional_i64(channel_obj.properties.get(PROMOTED_AT_PROPERTY))
        .unwrap_or(channel_obj.updated);
    let ranked = list_subscribers(ctx, product, channel).await?;
    if ranked.is_empty() {
        return Ok(Some(ChannelDecision {
            release,
            promoted_at_ms: promoted_at,
            early: HashMap::new(),
            ranked,
            admitted: BTreeSet::new(),
            duration_ms,
            now_ms,
            elapsed_by_instance: HashMap::new(),
        }));
    }
    let early = load_early(ctx, product, channel, &release).await?;
    let mut elapsed_by_env = HashMap::new();
    let mut elapsed_by_instance = HashMap::new();
    let mut admitted = BTreeSet::new();
    for (index, (environment, instance)) in ranked.iter().enumerate() {
        let elapsed = match elapsed_by_env.get(environment) {
            Some(ms) => *ms,
            None => {
                let ms = counted_elapsed(ctx, product, environment, promoted_at, now_ms).await?;
                elapsed_by_env.insert(environment.clone(), ms);
                ms
            }
        };
        elapsed_by_instance.insert((environment.clone(), instance.clone()), elapsed);
        let started = instance_started(ctx, environment, instance, &release).await?;
        let is_early = early.contains_key(&(environment.clone(), instance.clone()));
        if started || is_early || index < allowed_count(elapsed, duration_ms, ranked.len()) {
            admitted.insert((environment.clone(), instance.clone()));
        }
    }
    Ok(Some(ChannelDecision {
        release,
        promoted_at_ms: promoted_at,
        early,
        ranked,
        admitted,
        duration_ms,
        now_ms,
        elapsed_by_instance,
    }))
}

async fn counted_elapsed(
    ctx: &mut Ctx,
    product: &str,
    environment: &str,
    promoted_at: i64,
    now_ms: i64,
) -> Result<i64> {
    let env_windows = crate::maintenance::list(ctx, environment).await?;
    let product_windows = crate::maintenance::list_product(ctx, product).await?;
    crate::maintenance::elapsed_open_intersect_ms(
        &env_windows,
        &product_windows,
        promoted_at,
        now_ms,
    )
}

async fn list_subscribers(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
) -> Result<Vec<(String, String)>> {
    let cid = channel_id(product, channel);
    let mut rows = Vec::new();
    for subscriber in ctx.linked(&cid, REL_SUBSCRIBES, "in").await? {
        let row = if subscriber.kind == KIND_ENVIRONMENT {
            (subscriber.name.clone(), product.to_string())
        } else if subscriber.kind == KIND_INSTANCE {
            let environment = subscriber
                .properties
                .get("environment")
                .cloned()
                .unwrap_or_default();
            let instance = subscriber
                .properties
                .get("name")
                .cloned()
                .unwrap_or_else(|| subscriber.name.clone());
            if environment.is_empty() || instance.is_empty() {
                continue;
            }
            (environment, instance)
        } else {
            continue;
        };
        rows.push(row);
    }
    rows.sort();
    rows.dedup();
    Ok(rows)
}

/// Early admissions on `release`, keyed by (environment, instance).
async fn load_early(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    release: &str,
) -> Result<HashMap<(String, String), PaceAdmitAudit>> {
    let mut early = HashMap::new();
    for object in ctx.list_kind(KIND_UPGRADE_PACE_ADMIT).await? {
        if object.properties.get("product").map(String::as_str) != Some(product)
            || object.properties.get("channel").map(String::as_str) != Some(channel)
            || object.properties.get("release").map(String::as_str) != Some(release)
        {
            continue;
        }
        let Some(environment) = object.properties.get("environment").cloned() else {
            continue;
        };
        let Some(instance) = object.properties.get("instance").cloned() else {
            continue;
        };
        early.insert(
            (environment, instance),
            // Pacing decisions read only the key; a damaged audit field
            // must not stop the reconciler.
            PaceAdmitAudit {
                action: "set".into(),
                reason: object.properties.get("reason").cloned().unwrap_or_default(),
                actor: object.properties.get("actor").cloned().unwrap_or_default(),
                at: parse_optional_i64(object.properties.get("at")).unwrap_or(object.created),
            },
        );
    }
    Ok(early)
}

async fn instance_started(
    ctx: &mut Ctx,
    environment: &str,
    instance: &str,
    release: &str,
) -> Result<bool> {
    let Some(env) = ctx.get(&env_id(environment)).await? else {
        return Ok(false);
    };
    Ok(env
        .properties
        .get(&format!("deployed_release.{instance}"))
        .map(String::as_str)
        == Some(release))
}

async fn require_channel(ctx: &mut Ctx, product: &str, channel: &str) -> Result<Object> {
    match ctx.get(&channel_id(product, channel)).await? {
        Some(object) if object.kind == KIND_CHANNEL => Ok(object),
        Some(object) => bail!(
            "object {} is {}, not {KIND_CHANNEL}",
            object.id,
            object.kind
        ),
        None => bail!("channel {product}/{channel} is not published"),
    }
}

async fn append_audit(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    environment: &str,
    instance: &str,
    release: &str,
    event: &PaceAdmitAudit,
) -> Result<()> {
    for sequence in 0..32 {
        let id = format!(
            "tenkai:upgrade_pace_admit_audit:{product}/{channel}:{environment}:{instance}:{release}:{sequence}"
        );
        let object = Object {
            id,
            kind: KIND_UPGRADE_PACE_ADMIT_AUDIT.into(),
            name: format!("{environment}/{instance}"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("product".into(), product.into()),
                ("channel".into(), channel.into()),
                ("environment".into(), environment.into()),
                ("instance".into(), instance.into()),
                ("release".into(), release.into()),
                ("action".into(), event.action.clone()),
                ("reason".into(), event.reason.clone()),
                ("actor".into(), event.actor.clone()),
                ("at".into(), event.at.to_string()),
            ]),
            created: event.at,
            updated: event.at,
        };
        match ctx.create_once(object).await {
            Ok(_) => return Ok(()),
            Err(status) if crate::client::is_unique_conflict(&status) => {}
            Err(status) => return Err(status.into()),
        }
    }
    bail!("could not allocate an upgrade-pace admit audit event")
}

fn parse_optional_i64(value: Option<&String>) -> Option<i64> {
    value
        .and_then(|value| value.parse().ok())
        .filter(|ms| *ms > 0)
}

fn validate_reason(reason: &str) -> Result<&str> {
    let reason = reason.trim();
    anyhow::ensure!(
        !reason.is_empty(),
        "upgrade-pace admit reason must not be empty"
    );
    anyhow::ensure!(
        reason.len() <= 1024,
        "upgrade-pace admit reason exceeds 1024 bytes"
    );
    Ok(reason)
}

fn validate_actor(actor: &str) -> Result<&str> {
    let actor = actor.trim();
    anyhow::ensure!(
        !actor.is_empty(),
        "upgrade-pace admit actor must not be empty"
    );
    anyhow::ensure!(
        actor.len() <= 256,
        "upgrade-pace admit actor exceeds 256 bytes"
    );
    Ok(actor)
}

fn require_local_catalog(ctx: &Ctx) -> Result<()> {
    anyhow::ensure!(
        ctx.is_embedded() || ctx.is_tenant_hub(),
        "upgrade pace through a remote catalog must use the authenticated management route"
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

pub fn format_eligible_at(timestamp_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(timestamp_ms).map_or_else(
        || format!("unrepresentable timestamp ({timestamp_ms} ms since epoch)"),
        |timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_context::AuthenticatedRequestContext;
    use crate::catalog::PublishOptions;
    use crate::ontology::release_id;

    fn daily(start: &str) -> crate::maintenance::Window {
        crate::maintenance::Window {
            identity: format!("w{}", start.replace(':', "")),
            timezone: "UTC".into(),
            weekdays: (1..=7).collect(),
            start: start.into(),
            duration_minutes: 60,
        }
    }

    #[test]
    fn slot_is_the_first_elapsed_time_that_admits_the_instance() {
        for (n, duration) in [(2, 119_999), (6, 10_800_000), (7, 1_000)] {
            for index in 0..n {
                let slot = slot_elapsed_ms(index, n, duration);
                assert!(allowed_count(slot, duration, n) > index);
                assert!(allowed_count(slot - 1, duration, n) <= index);
            }
        }
    }

    #[test]
    fn projection_earned_at_a_closing_edge_waits_for_the_next_opening() {
        // 2023-11-14 02:00 UTC, inside a daily 02:00-03:00 window.
        let two = 1_699_927_200_000;
        let hour = 3_600_000;
        let window = [daily("02:00")];
        assert_eq!(
            project_counted(&window, &[], two, hour - 1),
            Some(two + hour - 1)
        );
        assert_eq!(
            project_counted(&window, &[], two, hour),
            Some(two + 24 * hour)
        );
    }

    #[test]
    fn next_joint_opening_needs_both_window_sets_open() {
        // 2023-11-14 00:00 UTC.
        let midnight = 1_699_920_000_000;
        let hour = 3_600_000;
        assert_eq!(
            next_joint_opening(&[daily("01:00")], &[daily("01:30")], midnight),
            Some(midnight + 90 * 60_000)
        );
        assert_eq!(
            next_joint_opening(&[daily("01:00")], &[daily("03:00")], midnight),
            None,
            "windows that never overlap have no joint opening"
        );
        assert_eq!(
            next_joint_opening(&[daily("01:00")], &[], midnight + hour + 1),
            Some(midnight + hour + 1)
        );
    }

    #[test]
    fn allowed_count_spreads_six_instances_over_three_hours() {
        let hour = 3_600_000;
        let duration = 3 * hour;
        assert_eq!(allowed_count(0, duration, 6), 0);
        assert_eq!(allowed_count(hour - 1, duration, 6), 1);
        assert_eq!(allowed_count(hour, duration, 6), 2);
        assert_eq!(allowed_count(2 * hour, duration, 6), 4);
        assert_eq!(allowed_count(duration, duration, 6), 6);
        assert_eq!(allowed_count(duration + hour, duration, 6), 6);
    }

    #[test]
    fn pace_parser_accepts_suffixes_and_off() {
        assert_eq!(parse_pace("3h").unwrap(), Some(10_800_000));
        assert_eq!(parse_pace("30").unwrap(), Some(30_000));
        assert_eq!(parse_pace("off").unwrap(), None);
        assert_eq!(parse_pace("0").unwrap(), None);
    }

    async fn fixture(label: &str) -> (std::path::PathBuf, Ctx, AuthenticatedRequestContext) {
        let root = std::env::temp_dir().join(format!(
            "tenkai-upgrade-pace-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let actor = crate::auth_context::test_management_context(label);
        (root, ctx, actor)
    }

    async fn publish(ctx: &mut Ctx, root: &std::path::Path, version: &str) {
        std::fs::write(
            root.join("tenkai.toml"),
            format!(
                "[product]\nname = \"api\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\n"
            ),
        )
        .unwrap();
        crate::catalog::publish(
            ctx,
            &root.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    async fn subscribe_fleet(ctx: &mut Ctx, actor: &AuthenticatedRequestContext) {
        crate::catalog::promote(ctx, actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        for name in ["env-a", "env-b", "env-c", "env-d", "env-e", "env-f"] {
            crate::environment::env_add(ctx, name, name).await.unwrap();
            crate::plan::subscribe(ctx, name, "api", "stable")
                .await
                .unwrap();
            mark_deployed(ctx, name, "1.0.0").await;
        }
    }

    async fn mark_deployed(ctx: &mut Ctx, env: &str, version: &str) {
        let mut object = ctx.get(&env_id(env)).await.unwrap().unwrap();
        object
            .properties
            .insert("deployed.api".into(), version.into());
        object
            .properties
            .insert("deployed_release.api".into(), release_id("api", version));
        ctx.put(object).await.unwrap();
    }

    async fn stamp_promoted_at(ctx: &mut Ctx, at: i64) {
        let mut channel = ctx
            .get(&channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap();
        channel
            .properties
            .insert(PROMOTED_AT_PROPERTY.into(), at.to_string());
        ctx.put(channel).await.unwrap();
    }

    fn action_plan(env: &str, action: Action) -> Plan {
        Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: "tenkai:plan:pace-test".into(),
            content_id: "c".into(),
            environment: env.into(),
            created_at: 1,
            inputs: Vec::new(),
            steps: vec![crate::plan::Step {
                id: "s".into(),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action,
                from: Some("2.0.0".into()),
                to: "1.0.0".into(),
                release_id: release_id("api", "1.0.0"),
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

    async fn current_head(ctx: &mut Ctx) -> String {
        ctx.get(&channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap()
            .properties
            .get("current_release")
            .cloned()
            .unwrap()
    }

    async fn admitted_at(ctx: &mut Ctx, now: i64) -> Vec<String> {
        let release = current_head(ctx).await;
        let mut names = Vec::new();
        for name in ["env-a", "env-b", "env-c", "env-d", "env-e", "env-f"] {
            if holds_upgrade(ctx, name, "api", "api", &release, now)
                .await
                .unwrap()
                .is_none()
            {
                names.push(name.to_string());
            }
        }
        names
    }

    #[tokio::test]
    async fn first_counted_hour_admits_two_of_six() {
        let (root, mut ctx, actor) = fixture("first-hour").await;
        publish(&mut ctx, &root, "1.0.0").await;
        publish(&mut ctx, &root, "2.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        let promoted_at = 1_700_000_000_000;
        stamp_promoted_at(&mut ctx, promoted_at).await;
        let first = admitted_at(&mut ctx, promoted_at + 3_600_000).await;
        assert_eq!(first, ["env-a", "env-b"], "{first:?}");
        let again = admitted_at(&mut ctx, promoted_at + 3_600_000).await;
        assert_eq!(first, again);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn rollback_and_remove_are_not_paced() {
        let (root, mut ctx, actor) = fixture("rollback").await;
        publish(&mut ctx, &root, "1.0.0").await;
        publish(&mut ctx, &root, "2.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        let promoted_at = 1_700_000_000_000;
        stamp_promoted_at(&mut ctx, promoted_at).await;
        let rollback = action_plan("env-f", Action::Rollback);
        require_for_plan(&mut ctx, &rollback, promoted_at)
            .await
            .unwrap();
        let mut remove = rollback.clone();
        remove.steps[0].action = Action::Remove;
        require_for_plan(&mut ctx, &remove, promoted_at)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn early_admit_is_audited_and_releases_the_instance() {
        let (root, mut ctx, actor) = fixture("early").await;
        publish(&mut ctx, &root, "1.0.0").await;
        publish(&mut ctx, &root, "2.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        let promoted_at = 1_700_000_000_000;
        stamp_promoted_at(&mut ctx, promoted_at).await;
        let head = current_head(&mut ctx).await;
        assert!(
            holds_upgrade(&mut ctx, "env-f", "api", "api", &head, promoted_at)
                .await
                .unwrap()
                .is_some()
        );
        let event = admit_early(
            &mut ctx,
            "api",
            "stable",
            "env-f",
            "api",
            "canary host",
            "alice",
        )
        .await
        .unwrap();
        assert_eq!(event.reason, "canary host");
        assert_eq!(event.actor, "alice");
        let again = admit_early(
            &mut ctx,
            "api",
            "stable",
            "env-f",
            "api",
            "retry after lost response",
            "bob",
        )
        .await
        .unwrap();
        assert_eq!(again.reason, "canary host");
        assert_eq!(again.actor, "alice");
        assert!(
            holds_upgrade(&mut ctx, "env-f", "api", "api", &head, promoted_at)
                .await
                .unwrap()
                .is_none()
        );
        let audit = admit_audit(&mut ctx, "api", "stable", "env-f", "api")
            .await
            .unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].reason, "canary host");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn progress_reports_started_admitted_waiting_and_paused() {
        let (root, mut ctx, actor) = fixture("progress").await;
        publish(&mut ctx, &root, "1.0.0").await;
        publish(&mut ctx, &root, "2.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        // Tuesday 22:13:20 UTC; env-e opens daily at 02:00 UTC for an hour.
        let promoted_at = 1_700_000_000_000;
        stamp_promoted_at(&mut ctx, promoted_at).await;
        mark_deployed(&mut ctx, "env-a", "2.0.0").await;
        admit_early(
            &mut ctx,
            "api",
            "stable",
            "env-f",
            "api",
            "canary host",
            "alice",
        )
        .await
        .unwrap();
        crate::maintenance::set(
            &mut ctx,
            "env-e",
            crate::maintenance::Window::new("nightly", "UTC", (1..=7).collect(), "02:00", 60)
                .unwrap(),
        )
        .await
        .unwrap();

        let paced = progress(&mut ctx, "api", "stable", promoted_at + 3_600_000)
            .await
            .unwrap();
        assert_eq!(paced.release, release_id("api", "2.0.0"));
        assert_eq!(paced.duration_ms, 10_800_000);
        let state = |env: &str| {
            paced
                .instances
                .iter()
                .find(|row| row.environment == env)
                .unwrap()
                .clone()
        };
        assert_eq!(state("env-a").state, PaceInstanceState::Started);
        assert_eq!(state("env-b").state, PaceInstanceState::Admitted);
        // Third of six slots: half of three counted hours.
        let waiting = state("env-c");
        assert_eq!(waiting.state, PaceInstanceState::Waiting);
        assert_eq!(waiting.eligible_at_ms, Some(promoted_at + 5_400_000));
        let paused = state("env-e");
        assert_eq!(paused.state, PaceInstanceState::Paused);
        // Two and a half counted hours through daily one-hour windows:
        // Wednesday, Thursday, then half of Friday's.
        assert_eq!(paused.eligible_at_ms, Some(1_700_188_200_000));
        assert_eq!(paused.next_opens_at_ms, Some(1_700_013_600_000));
        let early = state("env-f");
        assert_eq!(early.state, PaceInstanceState::Admitted);
        let admission = early.early_admission.unwrap();
        assert_eq!(
            (admission.actor.as_str(), admission.reason.as_str()),
            ("alice", "canary host")
        );

        // Admission does not open a closed window.
        admit_early(&mut ctx, "api", "stable", "env-e", "api", "hotfix", "alice")
            .await
            .unwrap();
        let paced = progress(&mut ctx, "api", "stable", promoted_at + 3_600_000)
            .await
            .unwrap();
        let admitted = paced
            .instances
            .iter()
            .find(|row| row.environment == "env-e")
            .unwrap();
        assert_eq!(admitted.state, PaceInstanceState::Paused);
        assert_eq!(admitted.eligible_at_ms, Some(1_700_013_600_000));
        assert_eq!(admitted.next_opens_at_ms, Some(1_700_013_600_000));

        configure(&mut ctx, "api", "stable", None).await.unwrap();
        let off = progress(&mut ctx, "api", "stable", promoted_at)
            .await
            .unwrap_err()
            .to_string();
        assert!(off.contains("has no upgrade pace"), "{off}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn early_admit_refuses_an_unsubscribed_instance() {
        let (root, mut ctx, actor) = fixture("unsubscribed").await;
        publish(&mut ctx, &root, "1.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "other", "other")
            .await
            .unwrap();
        let error = admit_early(
            &mut ctx,
            "api",
            "stable",
            "other",
            "api",
            "canary host",
            "alice",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("not subscribed"), "{error}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn disable_takes_effect_at_once() {
        let (root, mut ctx, actor) = fixture("disable").await;
        publish(&mut ctx, &root, "1.0.0").await;
        publish(&mut ctx, &root, "2.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        let promoted_at = 1_700_000_000_000;
        stamp_promoted_at(&mut ctx, promoted_at).await;
        let head = current_head(&mut ctx).await;
        assert!(
            holds_upgrade(&mut ctx, "env-f", "api", "api", &head, promoted_at)
                .await
                .unwrap()
                .is_some()
        );
        configure(&mut ctx, "api", "stable", None).await.unwrap();
        assert!(
            holds_upgrade(&mut ctx, "env-f", "api", "api", &head, promoted_at)
                .await
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn reenable_after_disable_uses_the_new_duration() {
        let (root, mut ctx, actor) = fixture("reenable").await;
        publish(&mut ctx, &root, "1.0.0").await;
        publish(&mut ctx, &root, "2.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        let promoted_at = 1_700_000_000_000;
        stamp_promoted_at(&mut ctx, promoted_at).await;
        configure(&mut ctx, "api", "stable", None).await.unwrap();
        configure(&mut ctx, "api", "stable", Some(3_600_000))
            .await
            .unwrap();
        let one_hour_pace = admitted_at(&mut ctx, promoted_at + 1_800_000).await;
        assert_eq!(one_hour_pace, ["env-a", "env-b", "env-c"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn duration_change_applies_on_the_next_promotion() {
        let (root, mut ctx, actor) = fixture("duration").await;
        publish(&mut ctx, &root, "1.0.0").await;
        publish(&mut ctx, &root, "2.0.0").await;
        publish(&mut ctx, &root, "3.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        let first = 1_700_000_000_000;
        stamp_promoted_at(&mut ctx, first).await;
        configure(&mut ctx, "api", "stable", Some(3_600_000))
            .await
            .unwrap();
        let still_three_hour = admitted_at(&mut ctx, first + 3_600_000).await;
        assert_eq!(still_three_hour, ["env-a", "env-b"]);
        crate::catalog::promote(&mut ctx, &actor, "api@3.0.0", "stable")
            .await
            .unwrap();
        let second = 1_700_010_800_000;
        stamp_promoted_at(&mut ctx, second).await;
        let one_hour_pace = admitted_at(&mut ctx, second + 1_800_000).await;
        assert_eq!(one_hour_pace, ["env-a", "env-b", "env-c"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn duration_change_after_enable_on_current_head_waits_for_next_promotion() {
        let (root, mut ctx, actor) = fixture("enable-then-duration").await;
        publish(&mut ctx, &root, "1.0.0").await;
        publish(&mut ctx, &root, "2.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        let first = 1_700_000_000_000;
        stamp_promoted_at(&mut ctx, first).await;
        configure(&mut ctx, "api", "stable", Some(3_600_000))
            .await
            .unwrap();
        let still_three_hour = admitted_at(&mut ctx, first + 3_600_000).await;
        assert_eq!(still_three_hour, ["env-a", "env-b"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn upgrade_onto_another_release_is_not_paced() {
        let (root, mut ctx, actor) = fixture("other-head").await;
        publish(&mut ctx, &root, "1.0.0").await;
        publish(&mut ctx, &root, "2.0.0").await;
        publish(&mut ctx, &root, "3.0.0").await;
        subscribe_fleet(&mut ctx, &actor).await;
        configure(&mut ctx, "api", "stable", Some(10_800_000))
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@2.0.0", "stable")
            .await
            .unwrap();
        let promoted_at = 1_700_000_000_000;
        stamp_promoted_at(&mut ctx, promoted_at).await;
        let head = current_head(&mut ctx).await;
        assert_eq!(head, release_id("api", "2.0.0"));
        assert!(
            holds_upgrade(&mut ctx, "env-f", "api", "api", &head, promoted_at)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            holds_upgrade(
                &mut ctx,
                "env-f",
                "api",
                "api",
                &release_id("api", "3.0.0"),
                promoted_at
            )
            .await
            .unwrap()
            .is_none()
        );
        let mut other = action_plan("env-f", Action::Upgrade);
        other.steps[0].from = Some("1.0.0".into());
        other.steps[0].to = "3.0.0".into();
        other.steps[0].release_id = release_id("api", "3.0.0");
        require_for_plan(&mut ctx, &other, promoted_at)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }
}
