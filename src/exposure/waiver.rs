//! Advisory waivers and exposure grace (#1064).
//!
//! A waiver is one catalog object, hold-like: create and remove are audited.
//! Narrowest matching scope wins. Grace is an environment or channel property
//! counted from the durable first-seen stamp, not from the check clock.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::ontology::{KIND_CHANNEL, NS, channel_id, validate_identifier};
use crate::pb::sekai::Object;

use super::{KIND_DEPLOYED_EXPOSURE, MatchedExposure};

/// Catalog kind for an active advisory waiver.
pub const KIND_EXPOSURE_WAIVER: &str = "tenkai.exposure_waiver";
/// Immutable set or clear event for an advisory waiver.
pub const KIND_EXPOSURE_WAIVER_AUDIT: &str = "tenkai.exposure_waiver_audit";
/// Environment or channel property: grace window in milliseconds.
pub const GRACE_MS_PROPERTY: &str = "exposure.grace_ms";

/// How broadly a waiver applies. Narrower ranks higher.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WaiverScopeKind {
    Global = 0,
    Product = 1,
    Component = 2,
    Release = 3,
}

/// Why the operator waived the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WaiverCategory {
    FalsePositive,
    Mitigated,
    UpstreamDependency,
}

impl WaiverCategory {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "false_positive" => Ok(Self::FalsePositive),
            "mitigated" => Ok(Self::Mitigated),
            "upstream_dependency" => Ok(Self::UpstreamDependency),
            other => bail!("unknown waiver category {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalsePositive => "false_positive",
            Self::Mitigated => "mitigated",
            Self::UpstreamDependency => "upstream_dependency",
        }
    }
}

impl WaiverScopeKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "global" => Ok(Self::Global),
            "product" => Ok(Self::Product),
            "component" => Ok(Self::Component),
            "release" => Ok(Self::Release),
            other => bail!("unknown waiver scope {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Product => "product",
            Self::Component => "component",
            Self::Release => "release",
        }
    }
}

/// Active waiver plus the fields query and inspect show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExposureWaiver {
    pub advisory_id: String,
    pub scope: WaiverScopeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub release_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub component: Option<String>,
    pub category: WaiverCategory,
    pub reason: String,
    pub actor: String,
    pub expires_at: i64,
}

/// Query parameters for `GET /v1/exposures/waivers`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExposureWaiverListQuery {
    /// Also return waivers whose expiry has passed but are not yet cleared.
    #[serde(default)]
    pub include_expired: bool,
}

/// Waivers returned by `GET /v1/exposures/waivers`, active ones only unless
/// expired ones were requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExposureWaiverList {
    pub waivers: Vec<ExposureWaiver>,
}

/// Grace on one open finding in one environment. `grace_ends_at` is the
/// first-seen stamp plus the environment's (or its channel's) grace window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnvironmentGrace {
    pub environment: String,
    pub grace_ends_at: i64,
    pub in_grace: bool,
}

/// Copy grace and scan-age so a channel put does not drop them.
pub fn copy_channel_properties(dst: &mut HashMap<String, String>, src: &Object) {
    for key in [GRACE_MS_PROPERTY, super::MAX_INVENTORY_AGE_PROPERTY] {
        if let Some(value) = src.properties.get(key).filter(|value| !value.is_empty()) {
            dst.insert(key.into(), value.clone());
        }
    }
}

/// Record or replace a waiver. Expiry is required and must be in the future.
///
/// The audit event is durable before the active object, so a crash cannot
/// enable a waiver without the transition record. A retry appends another
/// event and completes the put.
pub async fn set(ctx: &mut Ctx, waiver: ExposureWaiver, now_ms: i64) -> Result<ExposureWaiver> {
    require_local_catalog(ctx)?;
    let waiver = validate_waiver(waiver, now_ms)?;
    let id = waiver_id(&waiver);
    if let Some(existing) = ctx.get(&id).await? {
        anyhow::ensure!(
            existing.kind == KIND_EXPOSURE_WAIVER,
            "object {id} is {}, not {KIND_EXPOSURE_WAIVER}",
            existing.kind
        );
    }
    append_audit(ctx, &id, "set", &waiver, now_ms).await?;
    ctx.put(waiver_object(&id, &waiver, now_ms)).await?;
    Ok(waiver)
}

/// Remove a waiver. Missing is success so a retry is safe.
///
/// `category` and `expires_at` are unused; identity, actor, and reason are.
/// The clear event is durable before delete, so a crash retries without an
/// unaudited removal.
pub async fn clear(ctx: &mut Ctx, waiver: ExposureWaiver, now_ms: i64) -> Result<()> {
    require_local_catalog(ctx)?;
    let actor = validate_actor(&waiver.actor)?.to_string();
    let reason = validate_reason(&waiver.reason)?.to_string();
    let waiver = validate_scope(ExposureWaiver {
        advisory_id: waiver.advisory_id.trim().into(),
        actor,
        reason,
        expires_at: now_ms.saturating_add(1),
        ..waiver
    })?;
    let id = waiver_id(&waiver);
    append_audit(ctx, &id, "clear", &waiver, now_ms).await?;
    if let Some(existing) = ctx.get(&id).await? {
        anyhow::ensure!(
            existing.kind == KIND_EXPOSURE_WAIVER,
            "object {id} is {}, not {KIND_EXPOSURE_WAIVER}",
            existing.kind
        );
        ctx.delete(&id).await?;
    }
    Ok(())
}

/// Narrowest unexpired matching waiver for this finding, if any.
pub async fn matching(
    ctx: &mut Ctx,
    advisory_id: &str,
    release_id: &str,
    product: &str,
    component: &str,
    now_ms: i64,
) -> Result<Option<ExposureWaiver>> {
    let mut best: Option<ExposureWaiver> = None;
    for object in ctx.list_kind(KIND_EXPOSURE_WAIVER).await? {
        let Ok(Some(waiver)) = parse_waiver(&object) else {
            continue;
        };
        if waiver.advisory_id != advisory_id {
            continue;
        }
        if !scope_matches(&waiver, release_id, product, component) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|current| waiver.scope > current.scope)
        {
            best = Some(waiver);
        }
    }
    Ok(best.filter(|waiver| waiver.expires_at > now_ms))
}

/// Every stored waiver, ordered by advisory then scope. Expired waivers stay
/// stored until cleared; they are returned only when `include_expired`.
pub async fn list(
    ctx: &mut Ctx,
    now_ms: i64,
    include_expired: bool,
) -> Result<Vec<ExposureWaiver>> {
    let mut waivers = load_waivers(ctx).await?;
    waivers.retain(|waiver| include_expired || waiver.expires_at > now_ms);
    waivers.sort_by_cached_key(|waiver| (waiver.advisory_id.clone(), waiver_id(waiver)));
    Ok(waivers)
}

/// True when counted time since first-seen is still inside the declared grace.
///
/// Missing first-seen is not grace: the stamp is written when the finding is
/// stored, not when a check runs.
pub async fn in_grace(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
    release_id: &str,
    advisory_id: &str,
    now_ms: i64,
) -> Result<bool> {
    let Some(grace_ms) = grace_ms(ctx, environment, product).await? else {
        return Ok(false);
    };
    let Some(first_seen) = first_seen_at(ctx, release_id, advisory_id).await? else {
        return Ok(false);
    };
    Ok(now_ms.saturating_sub(first_seen) < grace_ms)
}

/// Set or clear grace on an environment under the apply lease.
///
/// `fence` sees the generation `env inspect` reported (the value claim
/// superseded). Remote callers refuse a stale inspect; embedded callers
/// pass a no-op.
pub async fn configure_environment(
    ctx: &mut Ctx,
    environment: &str,
    grace_ms: Option<i64>,
    fence: impl FnOnce(u64) -> Result<()>,
) -> Result<Option<i64>> {
    require_local_catalog(ctx)?;
    validate_identifier("environment", environment)?;
    if let Some(ms) = grace_ms
        && ms <= 0
    {
        bail!("exposure grace must be greater than zero");
    }
    let owner = format!("exposure-grace:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = async {
        fence(lease.generation.saturating_sub(1))?;
        let mut object = crate::environment::environment(ctx, environment).await?;
        match grace_ms {
            Some(ms) => {
                object
                    .properties
                    .insert(GRACE_MS_PROPERTY.into(), ms.to_string());
            }
            None => {
                object.properties.remove(GRACE_MS_PROPERTY);
            }
        }
        ctx.put(object).await?;
        Ok(grace_ms)
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing the environment exposure-grace lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing the environment exposure-grace lease")),
    }
}

/// Set or clear grace on a channel under the promotion lock.
pub async fn configure_channel(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    grace_ms: Option<i64>,
) -> Result<Option<i64>> {
    require_local_catalog(ctx)?;
    validate_identifier("product", product)?;
    validate_identifier("channel", channel)?;
    if let Some(ms) = grace_ms
        && ms <= 0
    {
        bail!("exposure grace must be greater than zero");
    }
    let owner = format!("exposure-grace:{product}/{channel}:{}", crate::now_millis());
    let lock = crate::canary::claim_promotion_lock(ctx, product, channel, &owner).await?;
    let result = async {
        let mut object = ctx
            .get(&channel_id(product, channel))
            .await?
            .with_context(|| format!("channel {product}/{channel} is not published"))?;
        if object.kind != KIND_CHANNEL {
            bail!(
                "object {} is {}, not {KIND_CHANNEL}",
                object.id,
                object.kind
            );
        }
        match grace_ms {
            Some(ms) => {
                object
                    .properties
                    .insert(GRACE_MS_PROPERTY.into(), ms.to_string());
            }
            None => {
                object.properties.remove(GRACE_MS_PROPERTY);
            }
        }
        crate::canary::fenced_put(ctx, std::slice::from_ref(&lock), object).await?;
        Ok(grace_ms)
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

/// Attach the active waiver, if any, to each match.
pub async fn annotate_matches(
    ctx: &mut Ctx,
    matches: &mut [MatchedExposure],
    now_ms: i64,
) -> Result<()> {
    if matches.is_empty() {
        return Ok(());
    }
    let waivers = load_waivers(ctx).await?;
    for matched in matches {
        let product = product_of(&matched.release_id, &matched.release);
        matched.waiver = narrowest(
            &waivers,
            &matched.advisory_id,
            &matched.release_id,
            &product,
            &matched.component,
            now_ms,
        );
    }
    Ok(())
}

pub fn parse_grace(value: &str) -> Result<Option<i64>> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("off") || value == "0" {
        return Ok(None);
    }
    Ok(Some(parse_duration_ms(value, "exposure grace")?))
}

pub fn parse_expiry(value: &str, now_ms: i64) -> Result<i64> {
    let value = value.trim();
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(value) {
        let ms = parsed.timestamp_millis();
        if ms <= now_ms {
            bail!("waiver expiry must be in the future");
        }
        return Ok(ms);
    }
    let ms = now_ms.saturating_add(parse_duration_ms(value, "waiver expiry")?);
    if ms <= now_ms {
        bail!("waiver expiry must be in the future");
    }
    Ok(ms)
}

/// Grace window that applies to `product` in `environment`: the environment's
/// own, else the subscribed channel's.
pub(super) async fn grace_ms(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
) -> Result<Option<i64>> {
    let env = crate::environment::environment(ctx, environment).await?;
    if let Some(ms) = parse_optional_positive(env.properties.get(GRACE_MS_PROPERTY)) {
        return Ok(Some(ms));
    }
    let Some(sub) = crate::environment::list_subscriptions(ctx, &env)
        .await?
        .into_iter()
        .find(|sub| sub.product == product)
    else {
        return Ok(None);
    };
    Ok(parse_optional_positive(
        sub.channel.properties.get(GRACE_MS_PROPERTY),
    ))
}

async fn first_seen_at(ctx: &mut Ctx, release_id: &str, advisory_id: &str) -> Result<Option<i64>> {
    let id = format!("tenkai:exposure:{release_id}:{advisory_id}");
    let Some(object) = ctx.get(&id).await? else {
        return Ok(None);
    };
    if object.kind != KIND_DEPLOYED_EXPOSURE {
        return Ok(None);
    }
    if object.properties.contains_key("closed_at") {
        return Ok(None);
    }
    Ok(object
        .properties
        .get("first_seen_at")
        .and_then(|value| value.parse().ok())
        .filter(|ms| *ms > 0))
}

async fn load_waivers(ctx: &mut Ctx) -> Result<Vec<ExposureWaiver>> {
    let mut rows = Vec::new();
    for object in ctx.list_kind(KIND_EXPOSURE_WAIVER).await? {
        if let Ok(Some(waiver)) = parse_waiver(&object) {
            rows.push(waiver);
        }
    }
    Ok(rows)
}

fn narrowest(
    waivers: &[ExposureWaiver],
    advisory_id: &str,
    release_id: &str,
    product: &str,
    component: &str,
    now_ms: i64,
) -> Option<ExposureWaiver> {
    waivers
        .iter()
        .filter(|waiver| waiver.advisory_id == advisory_id)
        .filter(|waiver| scope_matches(waiver, release_id, product, component))
        .max_by_key(|waiver| waiver.scope)
        .filter(|waiver| waiver.expires_at > now_ms)
        .cloned()
}

fn scope_matches(
    waiver: &ExposureWaiver,
    release_id: &str,
    product: &str,
    component: &str,
) -> bool {
    match waiver.scope {
        WaiverScopeKind::Global => true,
        WaiverScopeKind::Product => waiver.product.as_deref() == Some(product),
        WaiverScopeKind::Component => waiver.component.as_deref() == Some(component),
        WaiverScopeKind::Release => waiver.release_id.as_deref() == Some(release_id),
    }
}

pub(super) fn product_of(release_id: &str, spec: &str) -> String {
    release_id
        .strip_prefix("tenkai:release:")
        .and_then(|rest| rest.split_once('@'))
        .map(|(product, _)| product.to_string())
        .or_else(|| spec.split_once('@').map(|(product, _)| product.to_string()))
        .unwrap_or_default()
}

fn validate_waiver(waiver: ExposureWaiver, now_ms: i64) -> Result<ExposureWaiver> {
    let advisory_id = waiver.advisory_id.trim();
    anyhow::ensure!(!advisory_id.is_empty(), "waiver advisory id is required");
    anyhow::ensure!(
        advisory_id.len() <= 256,
        "waiver advisory id exceeds 256 bytes"
    );
    anyhow::ensure!(
        !advisory_id.contains(':'),
        "waiver advisory id must not contain ':'"
    );
    if waiver.expires_at <= now_ms {
        bail!("waiver expiry must be in the future");
    }
    let reason = validate_reason(&waiver.reason)?.to_string();
    let actor = validate_actor(&waiver.actor)?.to_string();
    validate_scope(ExposureWaiver {
        advisory_id: advisory_id.into(),
        reason,
        actor,
        ..waiver
    })
}

fn validate_scope(waiver: ExposureWaiver) -> Result<ExposureWaiver> {
    anyhow::ensure!(
        !waiver.advisory_id.contains(':'),
        "waiver advisory id must not contain ':'"
    );
    match waiver.scope {
        WaiverScopeKind::Global => {
            anyhow::ensure!(
                waiver.release_id.is_none()
                    && waiver.product.is_none()
                    && waiver.component.is_none(),
                "global waiver names no release, product, or component"
            );
        }
        WaiverScopeKind::Product => {
            let product = waiver.product.as_deref().unwrap_or("");
            validate_identifier("product", product)?;
            anyhow::ensure!(
                waiver.release_id.is_none() && waiver.component.is_none(),
                "product waiver names only a product"
            );
        }
        WaiverScopeKind::Component => {
            let component = waiver.component.as_deref().unwrap_or("");
            anyhow::ensure!(
                !component.is_empty(),
                "component waiver requires a component"
            );
            anyhow::ensure!(component.len() <= 256, "waiver component exceeds 256 bytes");
            anyhow::ensure!(
                !component.contains(':'),
                "waiver component must not contain ':'"
            );
            anyhow::ensure!(
                waiver.release_id.is_none() && waiver.product.is_none(),
                "component waiver names only a component"
            );
        }
        WaiverScopeKind::Release => {
            let release_id = waiver.release_id.as_deref().unwrap_or("");
            anyhow::ensure!(!release_id.is_empty(), "release waiver requires a release");
            let Some((product, version)) = release_id
                .strip_prefix("tenkai:release:")
                .and_then(|rest| rest.split_once('@'))
            else {
                bail!("release waiver requires a tenkai:release:product@version id");
            };
            validate_identifier("product", product)?;
            anyhow::ensure!(
                !version.is_empty() && !version.contains(':'),
                "release waiver version is invalid"
            );
            anyhow::ensure!(
                waiver.product.is_none() && waiver.component.is_none(),
                "release waiver names only a release"
            );
        }
    }
    Ok(waiver)
}

fn waiver_id(waiver: &ExposureWaiver) -> String {
    match waiver.scope {
        WaiverScopeKind::Global => {
            format!("tenkai:exposure_waiver:global:{}", waiver.advisory_id)
        }
        WaiverScopeKind::Product => format!(
            "tenkai:exposure_waiver:product:{}:{}",
            waiver.product.as_deref().unwrap_or(""),
            waiver.advisory_id
        ),
        WaiverScopeKind::Component => format!(
            "tenkai:exposure_waiver:component:{}:{}",
            waiver.component.as_deref().unwrap_or(""),
            waiver.advisory_id
        ),
        WaiverScopeKind::Release => format!(
            "tenkai:exposure_waiver:release:{}:{}",
            waiver.release_id.as_deref().unwrap_or(""),
            waiver.advisory_id
        ),
    }
}

fn waiver_object(id: &str, waiver: &ExposureWaiver, now_ms: i64) -> Object {
    let mut properties = HashMap::from([
        ("advisory_id".into(), waiver.advisory_id.clone()),
        ("scope".into(), waiver.scope.as_str().into()),
        ("category".into(), waiver.category.as_str().into()),
        ("reason".into(), waiver.reason.clone()),
        ("actor".into(), waiver.actor.clone()),
        ("expires_at".into(), waiver.expires_at.to_string()),
    ]);
    if let Some(release_id) = &waiver.release_id {
        properties.insert("release_id".into(), release_id.clone());
    }
    if let Some(product) = &waiver.product {
        properties.insert("product".into(), product.clone());
    }
    if let Some(component) = &waiver.component {
        properties.insert("component".into(), component.clone());
    }
    Object {
        id: id.into(),
        kind: KIND_EXPOSURE_WAIVER.into(),
        name: waiver.advisory_id.clone(),
        namespace: NS.into(),
        external_id: String::new(),
        properties,
        created: now_ms,
        updated: now_ms,
    }
}

fn parse_waiver(object: &Object) -> Result<Option<ExposureWaiver>> {
    if object.kind != KIND_EXPOSURE_WAIVER {
        return Ok(None);
    }
    let scope = WaiverScopeKind::parse(required(object, "scope")?)?;
    Ok(Some(ExposureWaiver {
        advisory_id: required(object, "advisory_id")?.into(),
        scope,
        release_id: object.properties.get("release_id").cloned(),
        product: object.properties.get("product").cloned(),
        component: object.properties.get("component").cloned(),
        category: WaiverCategory::parse(required(object, "category")?)?,
        reason: required(object, "reason")?.into(),
        actor: required(object, "actor")?.into(),
        expires_at: required(object, "expires_at")?
            .parse()
            .context("waiver expires_at is not an integer")?,
    }))
}

async fn append_audit(
    ctx: &mut Ctx,
    waiver_id: &str,
    action: &str,
    waiver: &ExposureWaiver,
    now_ms: i64,
) -> Result<()> {
    for sequence in 0..1024_u16 {
        let id = format!("{waiver_id}:audit:{now_ms}:{sequence}");
        let object = Object {
            id,
            kind: KIND_EXPOSURE_WAIVER_AUDIT.into(),
            name: waiver.advisory_id.clone(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: {
                let mut properties = HashMap::from([
                    ("action".into(), action.into()),
                    ("advisory_id".into(), waiver.advisory_id.clone()),
                    ("scope".into(), waiver.scope.as_str().into()),
                    ("reason".into(), waiver.reason.clone()),
                    ("actor".into(), waiver.actor.clone()),
                    ("at".into(), now_ms.to_string()),
                ]);
                if action == "set" {
                    properties.insert("category".into(), waiver.category.as_str().into());
                    properties.insert("expires_at".into(), waiver.expires_at.to_string());
                }
                if let Some(release_id) = &waiver.release_id {
                    properties.insert("release_id".into(), release_id.clone());
                }
                if let Some(product) = &waiver.product {
                    properties.insert("product".into(), product.clone());
                }
                if let Some(component) = &waiver.component {
                    properties.insert("component".into(), component.clone());
                }
                properties
            },
            created: now_ms,
            updated: now_ms,
        };
        match ctx.create_once(object).await {
            Ok(_) => return Ok(()),
            Err(status) if crate::client::is_unique_conflict(&status) => {}
            Err(status) => return Err(status.into()),
        }
    }
    bail!("could not allocate an exposure-waiver audit event")
}

fn required<'a>(object: &'a Object, key: &str) -> Result<&'a str> {
    object
        .properties
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("{} has no {key}", object.id))
}

fn validate_reason(reason: &str) -> Result<&str> {
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "waiver reason must not be empty");
    anyhow::ensure!(reason.len() <= 1024, "waiver reason exceeds 1024 bytes");
    Ok(reason)
}

fn validate_actor(actor: &str) -> Result<&str> {
    let actor = actor.trim();
    anyhow::ensure!(!actor.is_empty(), "waiver actor must not be empty");
    anyhow::ensure!(actor.len() <= 256, "waiver actor exceeds 256 bytes");
    Ok(actor)
}

fn require_local_catalog(ctx: &Ctx) -> Result<()> {
    anyhow::ensure!(
        ctx.is_embedded() || ctx.is_tenant_hub(),
        "exposure waivers through a remote catalog must use the authenticated management route"
    );
    Ok(())
}

/// Positive grace window stored on an environment or channel object.
pub fn grace_property(object: &Object) -> Option<i64> {
    parse_optional_positive(object.properties.get(GRACE_MS_PROPERTY))
}

fn parse_optional_positive(value: Option<&String>) -> Option<i64> {
    value
        .and_then(|value| value.parse().ok())
        .filter(|ms| *ms > 0)
}

fn parse_duration_ms(value: &str, label: &str) -> Result<i64> {
    let value = value.trim();
    let (number, factor) = if let Some(ms) = value.strip_suffix("ms") {
        (ms, 1_i64)
    } else if let Some(days) = value.strip_suffix('d') {
        (days, 86_400_000)
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
