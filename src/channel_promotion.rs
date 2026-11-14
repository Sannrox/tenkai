//! Channel promotion policy: soak, evidence, pause, reconciler execution.
//!
//! One versioned policy per product target channel. The reconciler evaluates
//! it each tick and, once soak and evidence hold, performs the same guarded
//! promotion a human `promote` performs. The promotion record names the
//! policy id and version as the actor.

use std::cell::Cell;
use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::auth_context::{
    AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, DeliveryCapability,
    PrincipalIdentity, PrincipalKind,
};
use crate::client::Ctx;
#[cfg(test)]
use crate::ontology::release_id;
use crate::ontology::{
    KIND_CHANNEL_PROMOTION_DECISION, KIND_CHANNEL_PROMOTION_POLICY,
    KIND_CHANNEL_PROMOTION_POLICY_POINTER, KIND_CHANNEL_PROMOTION_SOAK, KIND_ENVIRONMENT,
    KIND_INSTANCE, NS, REL_SUBSCRIBES, channel_id, env_id, validate_identifier,
};
use crate::pb::sekai::Object;
use crate::storage::OperationalStore;

/// Authenticator id stamped on policy-driven promotions.
pub const POLICY_AUTHENTICATOR: &str = "channel-promotion-policy";
/// Actor kind stored on the channel head. Unknown values fail closed.
pub const ACTOR_KIND: &str = "channel_promotion_policy";
const PRINCIPAL_ACTOR_KIND: &str = "principal";

thread_local! {
    static NOW_MS: Cell<Option<i64>> = const { Cell::new(None) };
}

fn now_ms() -> i64 {
    NOW_MS.with(Cell::get).unwrap_or_else(crate::now_millis)
}

/// Who moved a channel head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionActorKind {
    Principal,
    ChannelPromotionPolicy,
}

impl PromotionActorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => PRINCIPAL_ACTOR_KIND,
            Self::ChannelPromotionPolicy => ACTOR_KIND,
        }
    }

    /// Missing is a principal (records from before this kind). Unknown fails closed.
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None | Some(PRINCIPAL_ACTOR_KIND) => Ok(Self::Principal),
            Some(ACTOR_KIND) => Ok(Self::ChannelPromotionPolicy),
            Some(other) => bail!("unknown promotion actor kind {other}"),
        }
    }
}

/// Evidence the soak must keep true.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelPromotionEvidence {
    #[serde(default)]
    pub canary: bool,
    #[serde(default)]
    pub health_slo: bool,
    #[serde(default)]
    pub evaluation: bool,
    /// Minimum share of soak time with every replica healthy (0.0–1.0).
    #[serde(default = "one")]
    pub healthy_min_share: f64,
    /// Maximum share of soak time with any replica failing (0.0–1.0).
    #[serde(default)]
    pub failing_max_share: f64,
    /// When true, exceeding `failing_max_share` recalls the soaking source
    /// release instead of only resetting the soak.
    #[serde(default)]
    pub recall_on_failing: bool,
}

fn one() -> f64 {
    1.0
}

impl Default for ChannelPromotionEvidence {
    fn default() -> Self {
        Self {
            canary: false,
            health_slo: false,
            evaluation: false,
            healthy_min_share: 1.0,
            failing_max_share: 0.0,
            recall_on_failing: false,
        }
    }
}

/// Declared policy for one product target channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelPromotionPolicy {
    pub product: String,
    pub target_channel: String,
    pub source_channel: String,
    pub soak_duration_ms: i64,
    #[serde(default)]
    pub stale_after_ms: i64,
    pub evidence: ChannelPromotionEvidence,
}

impl ChannelPromotionPolicy {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("product", &self.product)?;
        validate_identifier("channel", &self.target_channel)?;
        validate_identifier("channel", &self.source_channel)?;
        if self.source_channel == self.target_channel {
            bail!(
                "channel promotion policy source {} must differ from target {}",
                self.source_channel,
                self.target_channel
            );
        }
        if self.soak_duration_ms <= 0 {
            bail!("channel promotion policy soak duration must be greater than zero");
        }
        if self.stale_after_ms < 0 {
            bail!("channel promotion policy stale-after must not be negative");
        }
        let healthy = self.evidence.healthy_min_share;
        let failing = self.evidence.failing_max_share;
        if !(0.0..=1.0).contains(&healthy) {
            bail!("healthy_min_share must be between 0 and 1");
        }
        if !(0.0..=1.0).contains(&failing) {
            bail!("failing_max_share must be between 0 and 1");
        }
        Ok(())
    }

    fn with_defaults(mut self) -> Result<Self> {
        self.validate()?;
        if self.stale_after_ms == 0 {
            self.stale_after_ms = self.soak_duration_ms;
        }
        Ok(self)
    }
}

/// Active versioned policy plus pause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveChannelPromotionPolicy {
    pub policy: ChannelPromotionPolicy,
    pub version: u64,
    pub paused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_at: Option<i64>,
}

impl ActiveChannelPromotionPolicy {
    pub fn id(&self) -> String {
        policy_record_id(
            &self.policy.product,
            &self.policy.target_channel,
            self.version,
        )
    }
}

/// Operator-visible soak row for `fleet status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelPromotionPolicyStatus {
    pub product: String,
    pub target_channel: String,
    pub source_channel: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub paused: bool,
    /// `waiting` | `soaking` | `ready` | `reset` | `refused` | `promoted` | `recalled`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances_without_evidence: Vec<String>,
}

/// Policy rules, pause actor, and soak progress for `GET /v1/products/{product}/channels/{channel}/policy`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelPromotionPolicyView {
    pub product: String,
    pub target_channel: String,
    pub source_channel: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub paused: bool,
    /// `waiting` | `soaking` | `ready` | `reset` | `refused` | `promoted` | `recalled`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances_without_evidence: Vec<String>,
    pub soak_duration_ms: i64,
    pub evidence: ChannelPromotionEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub paused_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub paused_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub soaking_release: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub elapsed_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub healthy_share: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub failing_share: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_reset_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_reset_cause: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub promoted_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub promoted_by_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SoakState {
    source_release: String,
    policy_version: u64,
    started_at: i64,
    last_tick_at: i64,
    healthy_ms: i64,
    failing_ms: i64,
    other_ms: i64,
    last_reason: String,
    last_reset_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthClass {
    AllHealthy,
    AnyFailing,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TickOutcome {
    Paused,
    Waiting {
        reason: String,
        missing: Vec<String>,
    },
    Soaking {
        reason: String,
        missing: Vec<String>,
    },
    Reset {
        reason: String,
        missing: Vec<String>,
    },
    Refused {
        reason: String,
    },
    Promoted {
        spec: String,
    },
    Recalled {
        spec: String,
        reason: String,
    },
}

/// Authenticated context used only for the guarded promotion path.
pub fn policy_request_context(
    policy_id: &str,
    policy_version: u64,
) -> Result<AuthenticatedRequestContext> {
    AuthenticatedRequestContextBuilder::new(
        format!("{POLICY_AUTHENTICATOR}:{policy_id}:{policy_version}"),
        PrincipalIdentity {
            id: format!("{policy_id}:{policy_version}"),
            kind: PrincipalKind::Service,
        },
        POLICY_AUTHENTICATOR,
    )
    .with_delivery_capabilities([DeliveryCapability::Read, DeliveryCapability::Publish])
    .build()
    .map_err(|error| anyhow::anyhow!("{error}"))
}

fn policy_recall_context(
    policy_id: &str,
    policy_version: u64,
) -> Result<AuthenticatedRequestContext> {
    AuthenticatedRequestContextBuilder::new(
        format!("{POLICY_AUTHENTICATOR}:{policy_id}:{policy_version}"),
        PrincipalIdentity {
            id: format!("{policy_id}:{policy_version}"),
            kind: PrincipalKind::Service,
        },
        POLICY_AUTHENTICATOR,
    )
    .with_delivery_capabilities([
        DeliveryCapability::Read,
        DeliveryCapability::Publish,
        DeliveryCapability::Management,
    ])
    .build()
    .map_err(|error| anyhow::anyhow!("{error}"))
}

pub fn actor_kind_for(actor: &AuthenticatedRequestContext) -> &'static str {
    if actor.authenticator_id == POLICY_AUTHENTICATOR {
        ACTOR_KIND
    } else {
        PRINCIPAL_ACTOR_KIND
    }
}

/// Recheck the pointer under the promotion lock so a pause or replace
/// cannot still move the channel.
pub(crate) async fn require_live_for_promote(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
    principal_id: &str,
) -> Result<()> {
    let Some(active) = load_active(ctx, product, target_channel).await? else {
        bail!("channel promotion policy for {product}/{target_channel} is gone");
    };
    if active.paused {
        bail!("channel promotion policy for {product}/{target_channel} is paused");
    }
    let expected = format!("{}:{}", active.id(), active.version);
    if principal_id != expected {
        bail!("channel promotion policy for {product}/{target_channel} was replaced");
    }
    Ok(())
}

/// Recheck soak under the promotion lock so a reset after evaluate released
/// cannot still move the channel.
pub(crate) async fn require_soak_still_ready(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
    source_release: &str,
    principal_id: &str,
) -> Result<()> {
    require_live_for_promote(ctx, product, target_channel, principal_id).await?;
    let Some(active) = load_active(ctx, product, target_channel).await? else {
        bail!("channel promotion policy for {product}/{target_channel} is gone");
    };
    let source_head = channel_head(ctx, product, &active.policy.source_channel).await?;
    if source_head.as_deref() != Some(source_release) {
        bail!("channel promotion source head for {product}/{target_channel} changed");
    }
    let Some(soak) = load_soak(ctx, product, target_channel).await? else {
        bail!("channel promotion soak for {product}/{target_channel} is gone");
    };
    if soak.source_release != source_release
        || soak.policy_version != active.version
        || soak.last_reason != "ready"
        || soak.started_at == 0
    {
        bail!("channel promotion soak for {product}/{target_channel} is no longer ready");
    }
    let now = now_ms();
    if active.policy.stale_after_ms > 0
        && now.saturating_sub(soak.last_tick_at) > active.policy.stale_after_ms
    {
        bail!("channel promotion soak for {product}/{target_channel} observation is stale");
    }
    let (health, missing, _) = classify_health(
        ctx,
        product,
        &active.policy.source_channel,
        source_release,
        now,
        active.policy.stale_after_ms,
    )
    .await?;
    if health != HealthClass::AllHealthy || !missing.is_empty() {
        bail!(
            "channel promotion soak for {product}/{target_channel} instance health is no longer healthy"
        );
    }
    let spec = spec_from_release_id(source_release)
        .with_context(|| format!("channel head {source_release} is not a release id"))?;
    let Some((_, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec}");
    };
    let release = ctx
        .get(source_release)
        .await?
        .with_context(|| format!("release {spec} is not published"))?;
    if !crate::family_release::stored_gate_flags(&release)?.is_empty() {
        bail!("channel promotion soak for {product}/{target_channel} has gate flags");
    }
    if active.policy.evidence.canary {
        match canary_allows(ctx, product, version, target_channel).await? {
            CanaryEvidence::Allowed => {}
            CanaryEvidence::Missing | CanaryEvidence::Blocked(_) => {
                bail!(
                    "channel promotion soak for {product}/{target_channel} canary evidence is gone"
                );
            }
        }
    }
    if active.policy.evidence.evaluation {
        crate::model_release_evidence::require_published_model_evaluation(ctx, &release)
            .await
            .with_context(|| {
                format!(
                    "channel promotion soak for {product}/{target_channel} evaluation evidence is gone"
                )
            })?;
    }
    if active.policy.evidence.health_slo {
        match health_slo_allows(ctx, source_release, now, active.policy.stale_after_ms).await? {
            SloEvidence::Passed => {}
            SloEvidence::Missing | SloEvidence::Failed(_) | SloEvidence::Stale(_) => {
                bail!(
                    "channel promotion soak for {product}/{target_channel} health/SLO evidence is no longer passing"
                );
            }
        }
    }
    let id = decision_id(product, target_channel, source_release, active.version);
    if let Some(decision) = ctx.get(&id).await?
        && decision.properties.get("committed").map(String::as_str) == Some("true")
    {
        let at_head = channel_head(ctx, product, target_channel).await?;
        if at_head.as_deref() != Some(source_release) {
            bail!("channel promotion decision for {product}/{target_channel} already committed");
        }
    }
    Ok(())
}

/// Decision object with `committed=true` for the same fenced write as the channel head.
pub(crate) async fn committed_decision_object(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
    source_release: &str,
) -> Result<Object> {
    let Some(active) = load_active(ctx, product, target_channel).await? else {
        bail!("channel promotion policy for {product}/{target_channel} is gone");
    };
    let id = decision_id(product, target_channel, source_release, active.version);
    let Some(mut object) = ctx.get(&id).await? else {
        bail!("channel promotion decision {id} is missing");
    };
    object.properties.insert("committed".into(), "true".into());
    object.updated = now_ms();
    Ok(object)
}

fn pointer_id(product: &str, target: &str) -> String {
    format!("tenkai:channel-promotion-policy:{product}/{target}")
}

fn policy_record_id(product: &str, target: &str, version: u64) -> String {
    format!("tenkai:channel-promotion-policy:{product}/{target}:{version}")
}

fn soak_id(product: &str, target: &str) -> String {
    format!("tenkai:channel-promotion-soak:{product}/{target}")
}

fn decision_id(product: &str, target: &str, source_release: &str, version: u64) -> String {
    format!("tenkai:channel-promotion-decision:{product}/{target}:{source_release}:{version}")
}

fn object(id: String, kind: &str, name: String, properties: HashMap<String, String>) -> Object {
    let now = now_ms();
    Object {
        id,
        kind: kind.into(),
        name,
        namespace: NS.into(),
        external_id: String::new(),
        properties,
        created: now,
        updated: now,
    }
}

/// Declare or replace the policy for `product`/`target_channel`.
pub async fn configure(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    policy: ChannelPromotionPolicy,
) -> Result<ActiveChannelPromotionPolicy> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let policy = policy.with_defaults()?;
    let owner = format!(
        "channel-promotion-policy:{}/{}:configure:{}",
        policy.product,
        policy.target_channel,
        now_ms()
    );
    let lock =
        crate::canary::claim_promotion_lock(ctx, &policy.product, &policy.target_channel, &owner)
            .await?;
    let result = async {
        let pointer_id = pointer_id(&policy.product, &policy.target_channel);
        let existing = ctx.get(&pointer_id).await?;
        let mut version = match existing.as_ref() {
            Some(pointer) => pointer
                .properties
                .get("version")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_add(1),
            None => 1,
        };
        let paused = existing
            .as_ref()
            .and_then(|pointer| pointer.properties.get("paused"))
            .is_some_and(|value| value == "true");
        for _ in 0..16 {
            let (paused_by, paused_at) = if paused {
                existing
                    .as_ref()
                    .map(pointer_pause_actor)
                    .unwrap_or((None, None))
            } else {
                (None, None)
            };
            let active = ActiveChannelPromotionPolicy {
                policy: policy.clone(),
                version,
                paused,
                paused_by,
                paused_at,
            };
            if persist_policy_record(ctx, &active).await? {
                persist_pointer(ctx, &active, existing.as_ref(), std::slice::from_ref(&lock))
                    .await?;
                return Ok(active);
            }
            version = version.saturating_add(1);
        }
        bail!(
            "could not allocate a channel promotion policy version for {}/{}",
            policy.product,
            policy.target_channel
        )
    }
    .await;
    crate::canary::finish_locked(
        result,
        crate::canary::release_promotion_lock(ctx, &lock).await,
    )
}

/// Pause or resume an existing policy. A pause is durable and does not
/// delete soak state.
pub async fn set_paused(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    product: &str,
    target_channel: &str,
    paused: bool,
) -> Result<ActiveChannelPromotionPolicy> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let owner = format!(
        "channel-promotion-policy:{product}/{target_channel}:pause:{}",
        now_ms()
    );
    let lock = crate::canary::claim_promotion_lock(ctx, product, target_channel, &owner).await?;
    let result = async {
        let mut active = load_active(ctx, product, target_channel)
            .await?
            .with_context(|| {
                format!("no channel promotion policy for {product}/{target_channel}")
            })?;
        active.paused = paused;
        if paused {
            active.paused_by = Some(actor.principal_id().to_string());
            active.paused_at = Some(now_ms());
        } else {
            active.paused_by = None;
            active.paused_at = None;
        }
        let pointer = ctx
            .get(&pointer_id(product, target_channel))
            .await?
            .context("channel promotion policy pointer missing")?;
        let locks = std::slice::from_ref(&lock);
        let mut objects = vec![pointer_record(&active, Some(&pointer))];
        if let Some(existing) = ctx.get(&soak_id(product, target_channel)).await? {
            let mut soak = soak_from_object(&existing);
            soak.last_tick_at = now_ms();
            objects.push(soak_record(product, target_channel, soak, Some(&existing)));
        }
        crate::canary::fenced_put_objects(ctx, locks, objects).await?;
        Ok(active)
    }
    .await;
    crate::canary::finish_locked(
        result,
        crate::canary::release_promotion_lock(ctx, &lock).await,
    )
}

/// Returns true when this version is now the durable policy record.
async fn persist_policy_record(
    ctx: &mut Ctx,
    active: &ActiveChannelPromotionPolicy,
) -> Result<bool> {
    let record_id = active.id();
    let encoded = serde_json::to_string(&active.policy)?;
    let record = object(
        record_id.clone(),
        KIND_CHANNEL_PROMOTION_POLICY,
        format!(
            "{} {} <- {}",
            active.policy.product, active.policy.target_channel, active.policy.source_channel
        ),
        HashMap::from([
            ("product".into(), active.policy.product.clone()),
            (
                "target_channel".into(),
                active.policy.target_channel.clone(),
            ),
            (
                "source_channel".into(),
                active.policy.source_channel.clone(),
            ),
            ("version".into(), active.version.to_string()),
            ("policy".into(), encoded.clone()),
        ]),
    );
    match ctx.create_once(record).await {
        Ok(_) => Ok(true),
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let stored = ctx.get(&record_id).await?.with_context(|| {
                format!("channel promotion policy {record_id} conflicted then disappeared")
            })?;
            Ok(stored.properties.get("policy") == Some(&encoded))
        }
        Err(status) => Err(status.into()),
    }
}

fn pointer_record(
    active: &ActiveChannelPromotionPolicy,
    existing_pointer: Option<&Object>,
) -> Object {
    let now = now_ms();
    Object {
        id: pointer_id(&active.policy.product, &active.policy.target_channel),
        kind: KIND_CHANNEL_PROMOTION_POLICY_POINTER.into(),
        name: format!(
            "active {} promotion to {}",
            active.policy.product, active.policy.target_channel
        ),
        namespace: NS.into(),
        external_id: String::new(),
        properties: {
            let mut properties = HashMap::from([
                ("product".into(), active.policy.product.clone()),
                (
                    "target_channel".into(),
                    active.policy.target_channel.clone(),
                ),
                ("policy_id".into(), active.id()),
                ("version".into(), active.version.to_string()),
                (
                    "paused".into(),
                    if active.paused { "true" } else { "false" }.into(),
                ),
            ]);
            if let Some(paused_by) = &active.paused_by {
                properties.insert("paused_by".into(), paused_by.clone());
            }
            if let Some(paused_at) = active.paused_at {
                properties.insert("paused_at".into(), paused_at.to_string());
            }
            properties
        },
        created: existing_pointer.map_or(now, |pointer| pointer.created),
        updated: now,
    }
}

async fn persist_pointer(
    ctx: &mut Ctx,
    active: &ActiveChannelPromotionPolicy,
    existing_pointer: Option<&Object>,
    locks: &[crate::canary::PromotionLock],
) -> Result<()> {
    crate::canary::fenced_put(ctx, locks, pointer_record(active, existing_pointer)).await?;
    Ok(())
}

async fn load_active(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
) -> Result<Option<ActiveChannelPromotionPolicy>> {
    let Some(pointer) = ctx.get(&pointer_id(product, target_channel)).await? else {
        return Ok(None);
    };
    active_from_pointer(ctx, &pointer).await.map(Some)
}

async fn active_from_pointer(
    ctx: &mut Ctx,
    pointer: &Object,
) -> Result<ActiveChannelPromotionPolicy> {
    let policy_id = pointer
        .properties
        .get("policy_id")
        .filter(|value| !value.is_empty())
        .with_context(|| {
            format!(
                "channel promotion policy pointer {} has no policy_id",
                pointer.id
            )
        })?;
    let record = ctx
        .get(policy_id)
        .await?
        .with_context(|| format!("channel promotion policy {policy_id} is missing"))?;
    if record.kind != KIND_CHANNEL_PROMOTION_POLICY {
        bail!(
            "channel promotion policy pointer {} names {} {}, not {KIND_CHANNEL_PROMOTION_POLICY}",
            pointer.id,
            record.kind,
            record.id
        );
    }
    let encoded = record
        .properties
        .get("policy")
        .with_context(|| format!("channel promotion policy {} has no policy", record.id))?;
    let policy: ChannelPromotionPolicy = serde_json::from_str(encoded)
        .with_context(|| format!("channel promotion policy {} has invalid JSON", record.id))?;
    let version = pointer
        .properties
        .get("version")
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let paused = pointer
        .properties
        .get("paused")
        .is_some_and(|value| value == "true");
    let (paused_by, paused_at) = if paused {
        pointer_pause_actor(pointer)
    } else {
        (None, None)
    };
    Ok(ActiveChannelPromotionPolicy {
        policy,
        version,
        paused,
        paused_by,
        paused_at,
    })
}

fn pointer_pause_actor(pointer: &Object) -> (Option<String>, Option<i64>) {
    let paused_by = pointer
        .properties
        .get("paused_by")
        .filter(|value| !value.is_empty())
        .cloned();
    let paused_at = pointer
        .properties
        .get("paused_at")
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0);
    (paused_by, paused_at)
}

/// Policy rules, pause actor, soak progress, and promotion actor for one channel.
pub async fn view(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
) -> Result<ChannelPromotionPolicyView> {
    let active = load_active(ctx, product, target_channel)
        .await?
        .with_context(|| format!("no channel promotion policy for {product}/{target_channel}"))?;
    let status = status_for(ctx, &active).await?;
    let soak = load_soak(ctx, product, target_channel).await?;
    let channel = ctx.get(&channel_id(product, target_channel)).await?;
    Ok(view_from_parts(
        &active,
        status,
        soak.as_ref(),
        channel.as_ref(),
    ))
}

fn view_from_parts(
    active: &ActiveChannelPromotionPolicy,
    status: ChannelPromotionPolicyStatus,
    soak: Option<&SoakState>,
    channel: Option<&Object>,
) -> ChannelPromotionPolicyView {
    let mut soaking_release = None;
    let mut elapsed_ms = None;
    let mut healthy_share = None;
    let mut failing_share = None;
    let mut last_reset_at = None;
    let mut last_reset_cause = None;
    if let Some(soak) = soak {
        soaking_release = spec_from_release_id(&soak.source_release)
            .or_else(|| (!soak.source_release.is_empty()).then(|| soak.source_release.clone()));
        let elapsed = soak
            .healthy_ms
            .saturating_add(soak.failing_ms)
            .saturating_add(soak.other_ms);
        elapsed_ms = Some(elapsed);
        if elapsed > 0 {
            healthy_share = Some(soak.healthy_ms as f64 / elapsed as f64);
            failing_share = Some(soak.failing_ms as f64 / elapsed as f64);
        } else {
            healthy_share = Some(0.0);
            failing_share = Some(0.0);
        }
        if soak.last_reset_at > 0 {
            last_reset_at = Some(soak.last_reset_at);
        }
        if soak.last_reason.starts_with("reset:") {
            last_reset_cause = Some(soak.last_reason.clone());
        }
    }
    ChannelPromotionPolicyView {
        product: status.product,
        target_channel: status.target_channel,
        source_channel: status.source_channel,
        policy_id: status.policy_id,
        policy_version: status.policy_version,
        paused: status.paused,
        state: status.state,
        reason: status.reason,
        instances_without_evidence: status.instances_without_evidence,
        soak_duration_ms: active.policy.soak_duration_ms,
        evidence: active.policy.evidence.clone(),
        paused_by: active.paused_by.clone(),
        paused_at: active.paused_at,
        soaking_release,
        elapsed_ms,
        healthy_share,
        failing_share,
        last_reset_at,
        last_reset_cause,
        promoted_by: channel.and_then(|channel| channel.properties.get("promoted_by").cloned()),
        promoted_by_kind: channel
            .and_then(|channel| channel.properties.get("promoted_by_kind").cloned()),
    }
}

/// Load every active policy for fleet status and the reconciler.
pub async fn list_active(ctx: &mut Ctx) -> Result<Vec<ActiveChannelPromotionPolicy>> {
    let mut pointers = ctx.list_kind(KIND_CHANNEL_PROMOTION_POLICY_POINTER).await?;
    pointers.sort_by(|left, right| left.id.cmp(&right.id));
    let mut policies = Vec::new();
    for pointer in pointers {
        policies.push(active_from_pointer(ctx, &pointer).await?);
    }
    Ok(policies)
}

/// Reconciler entry: evaluate every policy once. A replica that does not
/// advertise the feature must pass `enabled = false`.
pub async fn reconcile_tick(
    ctx: &mut Ctx,
    enabled: bool,
) -> Result<Vec<ChannelPromotionPolicyStatus>> {
    if !enabled {
        return Ok(Vec::new());
    }
    let policies = list_active(ctx).await?;
    let mut statuses = Vec::with_capacity(policies.len());
    for active in policies {
        statuses.push(evaluate_one(ctx, &active).await?);
    }
    Ok(statuses)
}

/// Snapshot for `fleet status` without mutating soak clocks.
pub async fn status_snapshot(ctx: &mut Ctx) -> Result<Vec<ChannelPromotionPolicyStatus>> {
    let policies = list_active(ctx).await?;
    let mut statuses = Vec::with_capacity(policies.len());
    for active in policies {
        statuses.push(status_for(ctx, &active).await?);
    }
    Ok(statuses)
}

async fn status_for(
    ctx: &mut Ctx,
    active: &ActiveChannelPromotionPolicy,
) -> Result<ChannelPromotionPolicyStatus> {
    if active.paused {
        return Ok(status_row(active, "waiting", Some("paused"), Vec::new()));
    }
    let Some(source) =
        channel_head(ctx, &active.policy.product, &active.policy.source_channel).await?
    else {
        return Ok(status_row(
            active,
            "waiting",
            Some("source channel has no head"),
            Vec::new(),
        ));
    };
    if let Some(target) =
        channel_head(ctx, &active.policy.product, &active.policy.target_channel).await?
        && target == source
    {
        return Ok(status_row(active, "promoted", None, Vec::new()));
    }
    let soak = load_soak(ctx, &active.policy.product, &active.policy.target_channel).await?;
    let reason = soak.as_ref().map(|soak| soak.last_reason.as_str());
    let state = match reason {
        Some(reason) if reason.starts_with("reset:") => "reset",
        Some(reason) if reason.starts_with("refused:") => "refused",
        Some(_) if soak.as_ref().is_some_and(|soak| soak.started_at > 0) => "soaking",
        _ => "waiting",
    };
    let (_, missing, _) = classify_health(
        ctx,
        &active.policy.product,
        &active.policy.source_channel,
        &source,
        now_ms(),
        active.policy.stale_after_ms,
    )
    .await?;
    Ok(status_row(active, state, reason, missing))
}

async fn evaluate_one(
    ctx: &mut Ctx,
    active: &ActiveChannelPromotionPolicy,
) -> Result<ChannelPromotionPolicyStatus> {
    let outcome = match evaluate_ready(ctx, active).await {
        Ok(outcome) => outcome,
        Err(error) => TickOutcome::Refused {
            reason: error.to_string(),
        },
    };
    match outcome {
        TickOutcome::Paused => Ok(status_row(active, "waiting", Some("paused"), Vec::new())),
        TickOutcome::Waiting { reason, missing } => {
            Ok(status_row(active, "waiting", Some(&reason), missing))
        }
        TickOutcome::Soaking { reason, missing } => {
            Ok(status_row(active, "soaking", Some(&reason), missing))
        }
        TickOutcome::Reset { reason, missing } => {
            emit_reset(ctx, active, &reason)?;
            Ok(status_row(active, "reset", Some(&reason), missing))
        }
        TickOutcome::Refused { reason } => {
            Ok(status_row(active, "refused", Some(&reason), Vec::new()))
        }
        TickOutcome::Promoted { spec } => Ok(status_row(
            active,
            "promoted",
            Some(&format!("promoted {spec}")),
            Vec::new(),
        )),
        TickOutcome::Recalled { spec, reason } => Ok(status_row(
            active,
            "recalled",
            Some(&format!("recalled {spec}: {reason}")),
            Vec::new(),
        )),
    }
}

fn status_row(
    active: &ActiveChannelPromotionPolicy,
    state: &str,
    reason: Option<&str>,
    missing: Vec<String>,
) -> ChannelPromotionPolicyStatus {
    ChannelPromotionPolicyStatus {
        product: active.policy.product.clone(),
        target_channel: active.policy.target_channel.clone(),
        source_channel: active.policy.source_channel.clone(),
        policy_id: active.id(),
        policy_version: active.version,
        paused: active.paused,
        state: state.into(),
        reason: reason.map(str::to_owned),
        instances_without_evidence: missing,
    }
}

enum LockedTick {
    Outcome(TickOutcome),
    Promote {
        spec: String,
        source_release: String,
    },
}

async fn evaluate_ready(
    ctx: &mut Ctx,
    active: &ActiveChannelPromotionPolicy,
) -> Result<TickOutcome> {
    if active.paused {
        return Ok(TickOutcome::Paused);
    }
    let product = active.policy.product.as_str();
    let target = active.policy.target_channel.as_str();
    let source = active.policy.source_channel.as_str();
    let Some(source_release) = channel_head(ctx, product, source).await? else {
        return Ok(TickOutcome::Waiting {
            reason: "source channel has no head".into(),
            missing: Vec::new(),
        });
    };
    if let Some(target_release) = channel_head(ctx, product, target).await?
        && target_release == source_release
    {
        mark_decision_committed_active(ctx, active, &source_release).await?;
        return Ok(TickOutcome::Promoted {
            spec: spec_from_release_id(&source_release).unwrap_or(source_release),
        });
    }
    let owner = format!(
        "channel-promotion-policy:{product}/{target}:evaluate:{}",
        now_ms()
    );
    let lock = match crate::canary::claim_promotion_lock(ctx, product, target, &owner).await {
        Ok(lock) => lock,
        Err(error) if error.to_string().contains("already in progress") => {
            return Ok(TickOutcome::Waiting {
                reason: "waiting: promotion lock busy".into(),
                missing: Vec::new(),
            });
        }
        Err(error) => return Err(error),
    };
    let result =
        evaluate_ready_locked(ctx, active, &source_release, std::slice::from_ref(&lock)).await;
    let locked = crate::canary::finish_locked(
        result,
        crate::canary::release_promotion_lock(ctx, &lock).await,
    )?;
    match locked {
        LockedTick::Outcome(outcome) => Ok(outcome),
        LockedTick::Promote {
            spec,
            source_release,
        } => {
            let actor = policy_request_context(&active.id(), active.version)?;
            crate::catalog::promote(ctx, &actor, &spec, target).await?;
            emit_promoted(ctx, &spec, &active.id())?;
            mark_decision_committed_active(ctx, active, &source_release).await?;
            Ok(TickOutcome::Promoted { spec })
        }
    }
}

async fn evaluate_ready_locked(
    ctx: &mut Ctx,
    active: &ActiveChannelPromotionPolicy,
    source_release: &str,
    locks: &[crate::canary::PromotionLock],
) -> Result<LockedTick> {
    let product = active.policy.product.as_str();
    let target = active.policy.target_channel.as_str();
    let source = active.policy.source_channel.as_str();
    let Some(live) = load_active(ctx, product, target).await? else {
        return Ok(LockedTick::Outcome(TickOutcome::Refused {
            reason: format!("channel promotion policy for {product}/{target} is gone"),
        }));
    };
    if live.paused {
        return Ok(LockedTick::Outcome(TickOutcome::Paused));
    }
    if live.version != active.version {
        return Ok(LockedTick::Outcome(TickOutcome::Waiting {
            reason: "waiting: policy replaced".into(),
            missing: Vec::new(),
        }));
    }
    if let Some(target_release) = channel_head(ctx, product, target).await?
        && target_release == source_release
    {
        mark_decision_committed_active(ctx, active, source_release).await?;
        return Ok(LockedTick::Outcome(TickOutcome::Promoted {
            spec: spec_from_release_id(source_release)
                .unwrap_or_else(|| source_release.to_string()),
        }));
    }
    let spec = spec_from_release_id(source_release)
        .with_context(|| format!("channel head {source_release} is not a release id"))?;
    let Some((_, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec}");
    };
    let release = ctx
        .get(source_release)
        .await?
        .with_context(|| format!("release {spec} is not published"))?;
    let flags = crate::family_release::stored_gate_flags(&release)?;
    if !flags.is_empty() {
        let reason = format!(
            "refused: gate flags {} require a human --approve-gates",
            crate::family_release::join_flags(&flags)
        );
        persist_soak(
            ctx,
            product,
            target,
            SoakState {
                source_release: source_release.to_string(),
                policy_version: active.version,
                started_at: 0,
                last_tick_at: now_ms(),
                healthy_ms: 0,
                failing_ms: 0,
                other_ms: 0,
                last_reason: reason.clone(),
                last_reset_at: now_ms(),
            },
            locks,
        )
        .await?;
        return Ok(LockedTick::Outcome(TickOutcome::Refused { reason }));
    }

    let (health, missing, failing_labels) = classify_health(
        ctx,
        product,
        source,
        source_release,
        now_ms(),
        active.policy.stale_after_ms,
    )
    .await?;
    let mut evidence_fail: Option<String> = None;
    if active.policy.evidence.canary {
        match canary_allows(ctx, product, version, target).await? {
            CanaryEvidence::Allowed => {}
            CanaryEvidence::Missing => {
                touch_soak_clock(ctx, product, target, locks).await?;
                return Ok(LockedTick::Outcome(TickOutcome::Waiting {
                    reason: "waiting: no canary policy".into(),
                    missing,
                }));
            }
            CanaryEvidence::Blocked(detail) => {
                evidence_fail = Some(format!("reset: canary blocked ({detail})"));
            }
        }
    }
    if evidence_fail.is_none()
        && active.policy.evidence.evaluation
        && let Err(error) =
            crate::model_release_evidence::require_published_model_evaluation(ctx, &release).await
    {
        evidence_fail = Some(format!("reset: evaluation evidence ({error})"));
    }
    if evidence_fail.is_none() && active.policy.evidence.health_slo {
        match health_slo_allows(ctx, source_release, now_ms(), active.policy.stale_after_ms).await?
        {
            SloEvidence::Passed => {}
            SloEvidence::Missing => {
                touch_soak_clock(ctx, product, target, locks).await?;
                return Ok(LockedTick::Outcome(TickOutcome::Waiting {
                    reason: "waiting: no health/SLO evidence".into(),
                    missing,
                }));
            }
            SloEvidence::Failed(detail) | SloEvidence::Stale(detail) => {
                evidence_fail = Some(format!("reset: health/SLO {detail}"));
            }
        }
    }

    let now = now_ms();
    let mut soak = load_soak(ctx, product, target)
        .await?
        .filter(|soak| {
            soak.source_release == source_release && soak.policy_version == active.version
        })
        .unwrap_or_else(|| SoakState {
            source_release: source_release.to_string(),
            policy_version: active.version,
            started_at: 0,
            last_tick_at: now,
            healthy_ms: 0,
            failing_ms: 0,
            other_ms: 0,
            last_reason: String::new(),
            last_reset_at: 0,
        });
    let dt = if soak.started_at == 0 {
        0
    } else {
        now.saturating_sub(soak.last_tick_at).max(0)
    };

    if let Some(reason) = evidence_fail {
        soak = reset_soak(soak, source_release.to_string(), now, reason.clone());
        persist_soak(ctx, product, target, soak, locks).await?;
        return Ok(LockedTick::Outcome(TickOutcome::Reset { reason, missing }));
    }

    match health {
        HealthClass::AllHealthy => {
            if soak.started_at > 0
                && active.policy.stale_after_ms > 0
                && dt > active.policy.stale_after_ms
            {
                soak.last_tick_at = now;
                soak.last_reason = "waiting: observation gap".into();
                persist_soak(ctx, product, target, soak, locks).await?;
                return Ok(LockedTick::Outcome(TickOutcome::Waiting {
                    reason: "waiting: observation gap".into(),
                    missing,
                }));
            }
            if soak.started_at == 0 {
                soak.started_at = now;
            }
            soak.healthy_ms = soak.healthy_ms.saturating_add(dt);
        }
        HealthClass::AnyFailing => {
            if soak.started_at == 0 {
                soak.last_tick_at = now;
                soak.last_reason = "waiting: instance health failing".into();
                persist_soak(ctx, product, target, soak, locks).await?;
                return Ok(LockedTick::Outcome(TickOutcome::Waiting {
                    reason: "waiting: instance health failing".into(),
                    missing,
                }));
            }
            soak.failing_ms = soak.failing_ms.saturating_add(dt);
        }
        HealthClass::Incomplete => {
            soak.last_tick_at = now;
            soak.last_reason = "waiting: instances without health evidence".into();
            persist_soak(ctx, product, target, soak, locks).await?;
            return Ok(LockedTick::Outcome(TickOutcome::Waiting {
                reason: "waiting: instances without health evidence".into(),
                missing,
            }));
        }
    }
    soak.last_tick_at = now;
    let elapsed = soak
        .healthy_ms
        .saturating_add(soak.failing_ms)
        .saturating_add(soak.other_ms);
    if soak.started_at > 0 {
        let healthy_share = if elapsed == 0 {
            0.0
        } else {
            soak.healthy_ms as f64 / elapsed as f64
        };
        let failing_share = if elapsed == 0 {
            0.0
        } else {
            soak.failing_ms as f64 / elapsed as f64
        };
        if failing_share > active.policy.evidence.failing_max_share {
            if active.policy.evidence.recall_on_failing {
                let reason = format!("failing share {failing_share:.3}");
                if crate::catalog::release_is_recalled(ctx, source_release).await? {
                    return Ok(LockedTick::Outcome(TickOutcome::Recalled { spec, reason }));
                }
                let actor = policy_recall_context(&active.id(), active.version)?;
                let fence = locks
                    .first()
                    .map(crate::canary::PromotionLock::write_fence)
                    .ok_or_else(|| {
                        anyhow::anyhow!("channel promotion recall requires a promotion lock")
                    })?;
                crate::catalog::persist_recall_claim_with_fence(
                    ctx,
                    &actor,
                    source_release,
                    Some(fence),
                    &[
                        ("policy_id".into(), active.id()),
                        ("policy_version".into(), active.version.to_string()),
                        ("reason".into(), reason.clone()),
                        ("failing_instances".into(), failing_labels.join(",")),
                    ],
                )
                .await?;
                soak = reset_soak(
                    soak,
                    source_release.to_string(),
                    now,
                    format!("recalled: {reason}"),
                );
                persist_soak(ctx, product, target, soak, locks).await?;
                emit_reset(ctx, active, &format!("recalled: {reason}"))?;
                emit_recall(ctx, &spec)?;
                return Ok(LockedTick::Outcome(TickOutcome::Recalled { spec, reason }));
            }
            let reason = format!("reset: failing share {failing_share:.3}");
            soak = reset_soak(soak, source_release.to_string(), now, reason.clone());
            persist_soak(ctx, product, target, soak, locks).await?;
            return Ok(LockedTick::Outcome(TickOutcome::Reset { reason, missing }));
        }
        if elapsed >= active.policy.soak_duration_ms
            && healthy_share + f64::EPSILON >= active.policy.evidence.healthy_min_share
            && missing.is_empty()
        {
            soak.last_reason = "ready".into();
            if !persist_soak(ctx, product, target, soak, locks).await? {
                return Ok(LockedTick::Outcome(TickOutcome::Soaking {
                    reason: "soaking: concurrent update".into(),
                    missing,
                }));
            }
            match admit_decision(ctx, active, source_release).await? {
                DecisionAdmit::Done => {
                    let reason = "refused: promotion already committed".to_string();
                    if let Some(mut soak) = load_soak(ctx, product, target).await? {
                        soak.last_reason = reason.clone();
                        persist_soak(ctx, product, target, soak, locks).await?;
                    }
                    return Ok(LockedTick::Outcome(TickOutcome::Refused { reason }));
                }
                DecisionAdmit::Fresh | DecisionAdmit::Pending => {}
            }
            return Ok(LockedTick::Promote {
                spec,
                source_release: source_release.to_string(),
            });
        }
        soak.last_reason = format!("soaking: elapsed {elapsed}ms healthy_share {healthy_share:.3}");
        persist_soak(ctx, product, target, soak, locks).await?;
        return Ok(LockedTick::Outcome(TickOutcome::Soaking {
            reason: format!("soaking: elapsed {elapsed}ms healthy_share {healthy_share:.3}"),
            missing,
        }));
    }
    persist_soak(ctx, product, target, soak, locks).await?;
    Ok(LockedTick::Outcome(TickOutcome::Waiting {
        reason: "waiting: soak not started".into(),
        missing,
    }))
}

fn reset_soak(mut soak: SoakState, source_release: String, now: i64, reason: String) -> SoakState {
    soak.source_release = source_release;
    soak.started_at = 0;
    soak.last_tick_at = now;
    soak.healthy_ms = 0;
    soak.failing_ms = 0;
    soak.other_ms = 0;
    soak.last_reason = reason;
    soak.last_reset_at = now;
    soak
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecisionAdmit {
    Fresh,
    Pending,
    Done,
}

async fn admit_decision(
    ctx: &mut Ctx,
    active: &ActiveChannelPromotionPolicy,
    source_release: &str,
) -> Result<DecisionAdmit> {
    let id = decision_id(
        &active.policy.product,
        &active.policy.target_channel,
        source_release,
        active.version,
    );
    let decision = object(
        id.clone(),
        KIND_CHANNEL_PROMOTION_DECISION,
        format!(
            "{} -> {}",
            active.policy.product, active.policy.target_channel
        ),
        HashMap::from([
            ("policy_id".into(), active.id()),
            ("policy_version".into(), active.version.to_string()),
            ("source_release".into(), source_release.into()),
            (
                "target_channel".into(),
                active.policy.target_channel.clone(),
            ),
            (
                "evidence".into(),
                serde_json::to_string(&active.policy.evidence)?,
            ),
            ("committed".into(), "false".into()),
        ]),
    );
    match ctx.create_once(decision).await {
        Ok(_) => Ok(DecisionAdmit::Fresh),
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let stored = ctx.get(&id).await?.with_context(|| {
                format!("channel promotion decision {id} conflicted then disappeared")
            })?;
            if stored.properties.get("committed").map(String::as_str) == Some("true") {
                Ok(DecisionAdmit::Done)
            } else {
                Ok(DecisionAdmit::Pending)
            }
        }
        Err(status) => Err(status.into()),
    }
}

async fn mark_decision_committed_active(
    ctx: &mut Ctx,
    active: &ActiveChannelPromotionPolicy,
    source_release: &str,
) -> Result<()> {
    let id = decision_id(
        &active.policy.product,
        &active.policy.target_channel,
        source_release,
        active.version,
    );
    let Some(mut object) = ctx.get(&id).await? else {
        return Ok(());
    };
    if object.properties.get("committed").map(String::as_str) == Some("true") {
        return Ok(());
    }
    object.properties.insert("committed".into(), "true".into());
    object.updated = now_ms();
    ctx.put(object).await?;
    Ok(())
}

fn emit_promoted(ctx: &mut Ctx, spec: &str, policy_id: &str) -> Result<()> {
    let Some(store) = ctx.embedded_arc() else {
        return Ok(());
    };
    store.append_change_event(
        now_ms(),
        crate::change_stream::ChangeEventKind::ReleasePromoted.as_str(),
        &format!("{spec} {policy_id}"),
        "",
    )?;
    Ok(())
}

fn emit_reset(ctx: &mut Ctx, active: &ActiveChannelPromotionPolicy, reason: &str) -> Result<()> {
    let Some(store) = ctx.embedded_arc() else {
        return Ok(());
    };
    let resource = format!(
        "{}/{}:{reason}",
        active.policy.product, active.policy.target_channel
    );
    store.append_change_event(
        now_ms(),
        crate::change_stream::ChangeEventKind::PromotionSoakReset.as_str(),
        &resource,
        "",
    )?;
    Ok(())
}

fn emit_recall(ctx: &mut Ctx, spec: &str) -> Result<()> {
    let Some(store) = ctx.embedded_arc() else {
        return Ok(());
    };
    store.append_change_event(
        now_ms(),
        crate::change_stream::ChangeEventKind::ReleaseRecalled.as_str(),
        spec,
        "",
    )?;
    Ok(())
}

async fn channel_head(ctx: &mut Ctx, product: &str, channel: &str) -> Result<Option<String>> {
    let Some(object) = ctx.get(&channel_id(product, channel)).await? else {
        return Ok(None);
    };
    Ok(object
        .properties
        .get("current_release")
        .cloned()
        .filter(|value| !value.is_empty()))
}

fn spec_from_release_id(release: &str) -> Option<String> {
    release.strip_prefix("tenkai:release:").map(str::to_string)
}

enum CanaryEvidence {
    Allowed,
    Missing,
    Blocked(String),
}

async fn canary_allows(
    ctx: &mut Ctx,
    product: &str,
    version: &str,
    target: &str,
) -> Result<CanaryEvidence> {
    let Some(active) = crate::canary::maybe_active_policy(ctx, product, version, target).await?
    else {
        return Ok(CanaryEvidence::Missing);
    };
    let evaluation = crate::canary::evaluate_active(ctx, &active).await?;
    if evaluation.allowed {
        Ok(CanaryEvidence::Allowed)
    } else {
        Ok(CanaryEvidence::Blocked(format!(
            "policy {}",
            evaluation.policy_digest
        )))
    }
}

enum SloEvidence {
    Passed,
    Missing,
    Failed(String),
    Stale(String),
}

async fn health_slo_allows(
    ctx: &mut Ctx,
    release_id: &str,
    now: i64,
    stale_after_ms: i64,
) -> Result<SloEvidence> {
    let mut latest_by_env: HashMap<String, (i64, String)> = HashMap::new();
    for object in ctx
        .list_kind(crate::ontology::KIND_HEALTH_GATE_EVIDENCE)
        .await?
    {
        if object.properties.get("release_id").map(String::as_str) != Some(release_id) {
            continue;
        }
        let env = object
            .properties
            .get("environment")
            .cloned()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| object.id.clone());
        let observed_at = object
            .properties
            .get("observed_at")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let verdict = object
            .properties
            .get("verdict")
            .cloned()
            .unwrap_or_default();
        let entry = latest_by_env
            .entry(env)
            .or_insert((observed_at, verdict.clone()));
        if observed_at >= entry.0 {
            *entry = (observed_at, verdict);
        }
    }
    if latest_by_env.is_empty() {
        return Ok(SloEvidence::Missing);
    }
    for (env, (observed_at, verdict)) in latest_by_env {
        if stale_after_ms > 0 && now.saturating_sub(observed_at) > stale_after_ms {
            return Ok(SloEvidence::Stale(format!(
                "environment {env} observed_at {observed_at} older than {stale_after_ms}ms"
            )));
        }
        if verdict != "pass" {
            return Ok(SloEvidence::Failed(format!("environment {env} {verdict}")));
        }
    }
    Ok(SloEvidence::Passed)
}

async fn classify_health(
    ctx: &mut Ctx,
    product: &str,
    source_channel: &str,
    source_release: &str,
    now: i64,
    stale_after_ms: i64,
) -> Result<(HealthClass, Vec<String>, Vec<String>)> {
    let cid = channel_id(product, source_channel);
    let subscribers = ctx.linked(&cid, REL_SUBSCRIBES, "in").await?;
    let mut missing = Vec::new();
    let mut failing_labels = Vec::new();
    let mut saw_failing = false;
    let mut saw_healthy = false;
    let mut any = false;
    let mut observations_by_env = HashMap::new();
    let deployed_digest = match ctx.get(source_release).await? {
        Some(release) => release.properties.get("artifact_digest").cloned(),
        None => None,
    };
    for subscriber in subscribers {
        let (env_name, instance_key, label) = if subscriber.kind == KIND_ENVIRONMENT {
            (
                subscriber.name.clone(),
                product.to_string(),
                subscriber.name.clone(),
            )
        } else if subscriber.kind == KIND_INSTANCE {
            let env_name = subscriber
                .properties
                .get("environment")
                .cloned()
                .unwrap_or_default();
            let instance_key = subscriber
                .properties
                .get("name")
                .cloned()
                .unwrap_or_else(|| subscriber.name.clone());
            if env_name.is_empty() || instance_key.is_empty() {
                missing.push(subscriber.id);
                continue;
            }
            let label = format!("{env_name}/{instance_key}");
            (env_name, instance_key, label)
        } else {
            continue;
        };
        any = true;
        let Some(env) = ctx.get(&env_id(&env_name)).await? else {
            missing.push(label);
            continue;
        };
        if env
            .properties
            .get(&format!("deployed_release.{instance_key}"))
            .map(String::as_str)
            != Some(source_release)
        {
            missing.push(label);
            continue;
        }
        if !observations_by_env.contains_key(&env_name) {
            let reports = crate::instance_health::reported(ctx, &env_name).await?;
            observations_by_env.insert(env_name.clone(), reports);
        }
        let observation = observations_by_env
            .get(&env_name)
            .and_then(|reports| reports.get(&instance_key));
        let live_observation = observation
            .filter(|report| deployed_digest.as_deref() == Some(report.artifact_digest.as_str()));
        let apply_health = env
            .properties
            .get(&format!("deployment_health.{instance_key}"))
            .cloned();
        let crate::instance_health::HealthStatus { health, checks, .. } =
            crate::instance_health::overlay(
                apply_health,
                observation,
                deployed_digest.as_deref(),
                now,
                crate::instance_health::max_age_ms(&env),
            );
        if live_observation.is_none()
            && stale_after_ms > 0
            && now.saturating_sub(env.updated) > stale_after_ms
        {
            missing.push(label);
            continue;
        }
        match health.as_deref() {
            Some("unhealthy") => {
                saw_failing = true;
                let messages: Vec<String> = checks
                    .iter()
                    .filter(|check| {
                        check.state >= crate::instance_health::HealthCheckState::Failing
                    })
                    .map(|check| {
                        if check.message.is_empty() {
                            check.name.clone()
                        } else {
                            format!("{}: {}", check.name, check.message)
                        }
                    })
                    .collect();
                if messages.is_empty() {
                    failing_labels.push(label);
                } else {
                    failing_labels.push(format!("{label} ({})", messages.join("; ")));
                }
            }
            Some("healthy") => saw_healthy = true,
            _ => missing.push(label),
        }
    }
    if !any {
        return Ok((HealthClass::Incomplete, missing, failing_labels));
    }
    if saw_failing {
        return Ok((HealthClass::AnyFailing, missing, failing_labels));
    }
    if missing.is_empty() && saw_healthy {
        Ok((HealthClass::AllHealthy, missing, failing_labels))
    } else {
        Ok((HealthClass::Incomplete, missing, failing_labels))
    }
}

async fn load_soak(ctx: &mut Ctx, product: &str, target: &str) -> Result<Option<SoakState>> {
    let Some(object) = ctx.get(&soak_id(product, target)).await? else {
        return Ok(None);
    };
    Ok(Some(soak_from_object(&object)))
}

fn soak_from_object(object: &Object) -> SoakState {
    SoakState {
        source_release: object
            .properties
            .get("source_release")
            .cloned()
            .unwrap_or_default(),
        policy_version: object
            .properties
            .get("policy_version")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        started_at: parse_i64(object.properties.get("started_at")),
        last_tick_at: parse_i64(object.properties.get("last_tick_at")),
        healthy_ms: parse_i64(object.properties.get("healthy_ms")),
        failing_ms: parse_i64(object.properties.get("failing_ms")),
        other_ms: parse_i64(object.properties.get("other_ms")),
        last_reason: object
            .properties
            .get("last_reason")
            .cloned()
            .unwrap_or_default(),
        last_reset_at: parse_i64(object.properties.get("last_reset_at")),
    }
}

fn soak_record(product: &str, target: &str, soak: SoakState, existing: Option<&Object>) -> Object {
    let now = now_ms();
    let mut object = existing.cloned().unwrap_or_else(|| {
        object(
            soak_id(product, target),
            KIND_CHANNEL_PROMOTION_SOAK,
            format!("{product}/{target} soak"),
            HashMap::new(),
        )
    });
    object.kind = KIND_CHANNEL_PROMOTION_SOAK.into();
    object.updated = now;
    object.properties = HashMap::from([
        ("product".into(), product.into()),
        ("target_channel".into(), target.into()),
        ("source_release".into(), soak.source_release),
        ("policy_version".into(), soak.policy_version.to_string()),
        ("started_at".into(), soak.started_at.to_string()),
        ("last_tick_at".into(), soak.last_tick_at.to_string()),
        ("healthy_ms".into(), soak.healthy_ms.to_string()),
        ("failing_ms".into(), soak.failing_ms.to_string()),
        ("other_ms".into(), soak.other_ms.to_string()),
        ("last_reason".into(), soak.last_reason),
        ("last_reset_at".into(), soak.last_reset_at.to_string()),
    ]);
    object
}

async fn touch_soak_clock(
    ctx: &mut Ctx,
    product: &str,
    target: &str,
    locks: &[crate::canary::PromotionLock],
) -> Result<()> {
    let Some(mut soak) = load_soak(ctx, product, target).await? else {
        return Ok(());
    };
    soak.last_tick_at = now_ms();
    persist_soak(ctx, product, target, soak, locks).await?;
    Ok(())
}

/// Returns false when a newer soak already won, so this tick must not promote.
async fn persist_soak(
    ctx: &mut Ctx,
    product: &str,
    target: &str,
    soak: SoakState,
    locks: &[crate::canary::PromotionLock],
) -> Result<bool> {
    let id = soak_id(product, target);
    let existing = ctx.get(&id).await?;
    let last_reset_at = soak.last_reset_at;
    let last_tick_at = soak.last_tick_at;
    let object = soak_record(product, target, soak, existing.as_ref());
    let new_source = object
        .properties
        .get("source_release")
        .cloned()
        .unwrap_or_default();
    let new_version = object
        .properties
        .get("policy_version")
        .cloned()
        .unwrap_or_default();
    if let Some(existing) = &existing {
        let same_generation = existing.properties.get("source_release") == Some(&new_source)
            && existing.properties.get("policy_version") == Some(&new_version);
        if same_generation
            && (parse_i64(existing.properties.get("last_reset_at")) > last_reset_at
                || parse_i64(existing.properties.get("last_tick_at")) > last_tick_at)
        {
            return Ok(false);
        }
    }
    crate::canary::fenced_put(ctx, locks, object).await?;
    Ok(true)
}

fn parse_i64(value: Option<&String>) -> i64 {
    value.and_then(|value| value.parse().ok()).unwrap_or(0)
}

/// Parse `--soak` as milliseconds. A bare number is seconds; `ms`/`s`/`m`/`h` suffixes work.
pub fn parse_soak(value: &str) -> Result<i64> {
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
        .with_context(|| format!("soak duration {value:?} is not a number"))?;
    let ms = amount
        .checked_mul(factor)
        .context("soak duration overflow")?;
    if ms <= 0 {
        bail!("soak duration must be greater than zero");
    }
    Ok(ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::PublishOptions;

    struct Clock;

    impl Clock {
        fn set(ms: i64) {
            NOW_MS.with(|now| now.set(Some(ms)));
        }
    }

    impl Drop for Clock {
        fn drop(&mut self) {
            NOW_MS.with(|now| now.set(None));
        }
    }

    async fn fixture(label: &str) -> (std::path::PathBuf, Ctx, AuthenticatedRequestContext) {
        let root = std::env::temp_dir().join(format!(
            "tenkai-channel-promotion-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let actor = crate::auth_context::test_management_context(label);
        (root, ctx, actor)
    }

    async fn publish(ctx: &mut Ctx, root: &std::path::Path, product: &str, version: &str) {
        std::fs::write(
            root.join("tenkai.toml"),
            format!(
                "[product]\nname = \"{product}\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\n"
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

    fn policy(product: &str, soak_ms: i64) -> ChannelPromotionPolicy {
        ChannelPromotionPolicy {
            product: product.into(),
            target_channel: "stable".into(),
            source_channel: "candidate".into(),
            soak_duration_ms: soak_ms,
            stale_after_ms: soak_ms,
            evidence: ChannelPromotionEvidence::default(),
        }
    }

    async fn head(ctx: &mut Ctx, product: &str, channel: &str) -> Option<String> {
        channel_head(ctx, product, channel).await.unwrap()
    }

    async fn observe(ctx: &mut Ctx, env: &str, product: &str, version: &str, healthy: bool) {
        crate::environment::record_observed_health(
            ctx,
            env,
            product,
            healthy,
            if healthy { "" } else { "boom" },
        )
        .await
        .unwrap();
        let mut object = ctx.get(&env_id(env)).await.unwrap().unwrap();
        object.properties.insert(
            format!("deployed_release.{product}"),
            release_id(product, version),
        );
        ctx.put(object).await.unwrap();
    }

    #[test]
    fn unknown_actor_kind_fails_closed() {
        assert_eq!(
            PromotionActorKind::parse(None).unwrap(),
            PromotionActorKind::Principal
        );
        assert_eq!(
            PromotionActorKind::parse(Some("channel_promotion_policy")).unwrap(),
            PromotionActorKind::ChannelPromotionPolicy
        );
        let error = PromotionActorKind::parse(Some("agent")).unwrap_err();
        assert!(
            error.to_string().contains("unknown promotion actor kind"),
            "{error}"
        );
    }

    #[test]
    fn soak_parser_accepts_suffixes() {
        assert_eq!(parse_soak("30").unwrap(), 30_000);
        assert_eq!(parse_soak("250ms").unwrap(), 250);
        assert_eq!(parse_soak("2m").unwrap(), 120_000);
        assert!(parse_soak("0").is_err());
    }

    #[tokio::test]
    async fn policy_met_promotes_once_and_names_the_policy_actor() {
        let _clock = Clock;
        Clock::set(1_000);
        let (root, mut ctx, actor) = fixture("promote-once").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        let active = configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(1_000);
        let first = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(first[0].state, "soaking", "{first:?}");
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        Clock::set(2_000);
        let second = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(second[0].state, "promoted", "{second:?}");
        assert_eq!(
            head(&mut ctx, "promo", "stable").await.unwrap(),
            release_id("promo", "1.0.0")
        );
        Clock::set(3_000);
        let third = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(third[0].state, "promoted", "{third:?}");
        let channel = ctx
            .get(&channel_id("promo", "stable"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            channel
                .properties
                .get("promoted_by_kind")
                .map(String::as_str),
            Some(ACTOR_KIND)
        );
        assert!(
            channel
                .properties
                .get("promoted_by")
                .is_some_and(|value| value.contains(&active.id())),
            "{channel:?}"
        );
        let events = ctx
            .embedded_arc()
            .unwrap()
            .list_change_events_after(0, 20)
            .unwrap();
        assert!(
            events.iter().any(|event| {
                event.kind == crate::change_stream::ChangeEventKind::ReleasePromoted
                    && event.resource.contains(&active.id())
            }),
            "{events:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn evidence_failure_mid_soak_resets() {
        let _clock = Clock;
        Clock::set(10_000);
        let (root, mut ctx, actor) = fixture("reset").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        configure(&mut ctx, &actor, policy("promo", 5_000))
            .await
            .unwrap();
        Clock::set(10_000);
        reconcile_tick(&mut ctx, true).await.unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", false).await;
        Clock::set(12_000);
        let reset = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(reset[0].state, "reset", "{reset:?}");
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let events = ctx
            .embedded_arc()
            .unwrap()
            .list_change_events_after(0, 20)
            .unwrap();
        assert!(
            events.iter().any(
                |event| event.kind == crate::change_stream::ChangeEventKind::PromotionSoakReset
            ),
            "{events:?}"
        );
        let viewed = view(&mut ctx, "promo", "stable").await.unwrap();
        assert_eq!(viewed.state, "reset", "{viewed:?}");
        assert!(
            viewed
                .last_reset_cause
                .as_ref()
                .is_some_and(|cause| cause.starts_with("reset:")),
            "{viewed:?}"
        );
        assert!(viewed.last_reset_at.is_some(), "{viewed:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn policy_replace_after_reset_starts_a_new_soak() {
        let _clock = Clock;
        Clock::set(10_000);
        let (root, mut ctx, actor) = fixture("replace-soak").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        configure(&mut ctx, &actor, policy("promo", 5_000))
            .await
            .unwrap();
        Clock::set(10_000);
        reconcile_tick(&mut ctx, true).await.unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", false).await;
        Clock::set(12_000);
        let reset = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(reset[0].state, "reset", "{reset:?}");
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        configure(&mut ctx, &actor, policy("promo", 5_000))
            .await
            .unwrap();
        Clock::set(13_000);
        let soaking = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(soaking[0].state, "soaking", "{soaking:?}");
        assert_eq!(soaking[0].policy_version, 2, "{soaking:?}");
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn missing_health_waits_and_does_not_promote_on_time() {
        let _clock = Clock;
        Clock::set(50_000);
        let (root, mut ctx, actor) = fixture("wait").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(50_000);
        let waiting = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(waiting[0].state, "waiting", "{waiting:?}");
        Clock::set(60_000);
        let still = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(still[0].state, "waiting", "{still:?}");
        assert!(
            still[0]
                .instances_without_evidence
                .iter()
                .any(|name| name == "lab"),
            "{still:?}"
        );
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let snap = status_snapshot(&mut ctx).await.unwrap();
        assert!(
            snap[0]
                .instances_without_evidence
                .iter()
                .any(|name| name == "lab"),
            "{snap:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn health_on_a_different_release_does_not_start_soak() {
        let _clock = Clock;
        Clock::set(70_000);
        let (root, mut ctx, actor) = fixture("wrong-release").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        let mut env = ctx.get(&env_id("lab")).await.unwrap().unwrap();
        env.properties.insert(
            "deployed_release.promo".into(),
            "tenkai:release:promo:0.9.0".into(),
        );
        ctx.put(env).await.unwrap();
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(70_000);
        reconcile_tick(&mut ctx, true).await.unwrap();
        Clock::set(80_000);
        let still = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(still[0].state, "waiting", "{still:?}");
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn stale_instance_health_does_not_start_soak() {
        let _clock = Clock;
        Clock::set(80_000);
        let (root, mut ctx, actor) = fixture("stale-health").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        let mut env = ctx.get(&env_id("lab")).await.unwrap().unwrap();
        env.updated = 1;
        ctx.put(env).await.unwrap();
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(80_000);
        let waiting = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(waiting[0].state, "waiting", "{waiting:?}");
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn failing_soak_with_recall_opt_in_recalls_once() {
        let _clock = Clock;
        Clock::set(10_000);
        let (root, mut ctx, actor) = fixture("recall-failing").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        let mut policy = policy("promo", 5_000);
        policy.evidence.recall_on_failing = true;
        configure(&mut ctx, &actor, policy).await.unwrap();
        Clock::set(10_000);
        reconcile_tick(&mut ctx, true).await.unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", false).await;
        Clock::set(12_000);
        let recalled = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(recalled[0].state, "recalled", "{recalled:?}");
        let rid = release_id("promo", "1.0.0");
        assert!(
            crate::catalog::release_is_recalled(&mut ctx, &rid)
                .await
                .unwrap()
        );
        let claim = ctx
            .get(&crate::ontology::release_recall_id(&rid))
            .await
            .unwrap()
            .unwrap();
        assert!(
            claim
                .properties
                .get("reason")
                .is_some_and(|reason| reason.contains("failing share")),
            "{claim:?}"
        );
        assert!(
            claim
                .properties
                .get("policy_id")
                .is_some_and(|id| !id.is_empty()),
            "{claim:?}"
        );
        assert_eq!(
            claim.properties.get("policy_version").map(String::as_str),
            Some("1")
        );
        let events = ctx
            .embedded_arc()
            .unwrap()
            .list_change_events_after(0, 20)
            .unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind
                    == crate::change_stream::ChangeEventKind::ReleaseRecalled)
                .count(),
            1,
            "{events:?}"
        );
        assert!(
            events.iter().any(|event| {
                event.kind == crate::change_stream::ChangeEventKind::PromotionSoakReset
                    && event.resource.contains("recalled")
            }),
            "{events:?}"
        );
        Clock::set(13_000);
        reconcile_tick(&mut ctx, true).await.unwrap();
        let again = ctx
            .find_by_property(crate::ontology::KIND_RELEASE_RECALL, "release_id", &rid)
            .await
            .unwrap();
        assert_eq!(again.len(), 1, "{again:?}");
        let events_after = ctx
            .embedded_arc()
            .unwrap()
            .list_change_events_after(0, 20)
            .unwrap();
        assert_eq!(
            events_after
                .iter()
                .filter(|event| event.kind
                    == crate::change_stream::ChangeEventKind::ReleaseRecalled)
                .count(),
            1,
            "{events_after:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn missing_health_evidence_does_not_recall() {
        let _clock = Clock;
        Clock::set(10_000);
        let (root, mut ctx, actor) = fixture("recall-missing").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        let mut env = ctx.get(&env_id("lab")).await.unwrap().unwrap();
        env.properties.insert(
            "deployed_release.promo".into(),
            release_id("promo", "1.0.0"),
        );
        ctx.put(env).await.unwrap();
        let mut policy = policy("promo", 1_000);
        policy.evidence.recall_on_failing = true;
        configure(&mut ctx, &actor, policy).await.unwrap();
        Clock::set(12_000);
        let waiting = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(waiting[0].state, "waiting", "{waiting:?}");
        assert!(
            !crate::catalog::release_is_recalled(&mut ctx, &release_id("promo", "1.0.0"))
                .await
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn paused_policy_does_nothing() {
        let _clock = Clock;
        Clock::set(80_000);
        let (root, mut ctx, actor) = fixture("pause").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        set_paused(&mut ctx, &actor, "promo", "stable", true)
            .await
            .unwrap();
        Clock::set(82_000);
        let paused = reconcile_tick(&mut ctx, true).await.unwrap();
        assert!(paused[0].paused, "{paused:?}");
        assert_eq!(paused[0].state, "waiting", "{paused:?}");
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let viewed = view(&mut ctx, "promo", "stable").await.unwrap();
        assert_eq!(viewed.paused_by.as_deref(), Some(actor.principal_id()));
        assert_eq!(viewed.paused_at, Some(80_000));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn pause_does_not_credit_elapsed_time() {
        let _clock = Clock;
        Clock::set(1_000);
        let (root, mut ctx, actor) = fixture("pause-clock").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(1_000);
        let started = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(started[0].state, "soaking", "{started:?}");
        set_paused(&mut ctx, &actor, "promo", "stable", true)
            .await
            .unwrap();
        Clock::set(5_000);
        set_paused(&mut ctx, &actor, "promo", "stable", false)
            .await
            .unwrap();
        let resumed = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(resumed[0].state, "soaking", "{resumed:?}");
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        Clock::set(6_000);
        let promoted = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(promoted[0].state, "promoted", "{promoted:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn gate_flagged_release_is_refused() {
        let _clock = Clock;
        Clock::set(90_000);
        let (root, mut ctx, actor) = fixture("gates").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        let rid = release_id("promo", "1.0.0");
        let mut release = ctx.get(&rid).await.unwrap().unwrap();
        release.properties.insert(
            crate::family_release::GATE_FLAGS_PROPERTY.into(),
            "breaking".into(),
        );
        ctx.put(release).await.unwrap();
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(92_000);
        let refused = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(refused[0].state, "refused", "{refused:?}");
        assert!(
            refused[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("gate flags")),
            "{refused:?}"
        );
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn replica_without_the_feature_does_not_evaluate() {
        let (root, mut ctx, actor) = fixture("disabled").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        let none = reconcile_tick(&mut ctx, false).await.unwrap();
        assert!(none.is_empty(), "{none:?}");
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn crash_before_commit_lets_the_other_replica_finish_once() {
        let _clock = Clock;
        Clock::set(100_000);
        let (root, mut ctx, actor) = fixture("crash").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        let active = configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(100_000);
        reconcile_tick(&mut ctx, true).await.unwrap();
        Clock::set(101_000);
        let source = release_id("promo", "1.0.0");
        let mut soak = load_soak(&mut ctx, "promo", "stable")
            .await
            .unwrap()
            .expect("soak started");
        soak.last_tick_at = 101_000;
        soak.healthy_ms = 1_000;
        soak.last_reason = "ready".into();
        persist_soak(&mut ctx, "promo", "stable", soak, &[])
            .await
            .unwrap();
        admit_decision(&mut ctx, &active, &source).await.unwrap();
        let mut other = ctx.clone();
        let actor = policy_request_context(&active.id(), active.version).unwrap();
        crate::catalog::promote(&mut other, &actor, "promo@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "stable")
            .await
            .unwrap();
        assert_eq!(head(&mut ctx, "promo", "stable").await.unwrap(), source);
        let decisions = ctx
            .list_kind(KIND_CHANNEL_PROMOTION_DECISION)
            .await
            .unwrap();
        assert_eq!(decisions.len(), 1, "{decisions:?}");
        assert!(
            decisions[0]
                .properties
                .get("evidence")
                .is_some_and(|value| value.contains("healthy_min_share")),
            "{decisions:?}"
        );
        assert_eq!(
            decisions[0].properties.get("committed").map(String::as_str),
            Some("true"),
            "{decisions:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn stale_health_slo_fails_closed() {
        let _clock = Clock;
        Clock::set(200_000);
        let (root, mut ctx, actor) = fixture("stale-slo").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        let source = release_id("promo", "1.0.0");
        ctx.put(object(
            "tenkai:health-gate-evidence:stale-slo".into(),
            crate::ontology::KIND_HEALTH_GATE_EVIDENCE,
            "stale slo".into(),
            HashMap::from([
                ("release_id".into(), source),
                ("verdict".into(), "pass".into()),
                ("observed_at".into(), "1".into()),
            ]),
        ))
        .await
        .unwrap();
        let mut policy = policy("promo", 1_000);
        policy.evidence.health_slo = true;
        configure(&mut ctx, &actor, policy).await.unwrap();
        Clock::set(202_000);
        let reset = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(reset[0].state, "reset", "{reset:?}");
        assert!(
            reset[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("health/SLO")),
            "{reset:?}"
        );
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn observation_gap_does_not_credit_healthy_time() {
        let _clock = Clock;
        Clock::set(1_000);
        let (root, mut ctx, actor) = fixture("obs-gap").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(1_000);
        let started = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(started[0].state, "soaking", "{started:?}");
        Clock::set(5_000);
        let gap = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(gap[0].state, "waiting", "{gap:?}");
        assert!(
            gap[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("observation gap")),
            "{gap:?}"
        );
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        Clock::set(6_000);
        let soaking = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(soaking[0].state, "promoted", "{soaking:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn observation_gap_with_failing_health_resets() {
        let _clock = Clock;
        Clock::set(1_000);
        let (root, mut ctx, actor) = fixture("gap-fail").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(1_000);
        let started = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(started[0].state, "soaking", "{started:?}");
        observe(&mut ctx, "lab", "promo", "1.0.0", false).await;
        Clock::set(5_000);
        let reset = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(reset[0].state, "reset", "{reset:?}");
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn health_slo_fail_in_one_environment_fails_closed() {
        let _clock = Clock;
        Clock::set(300_000);
        let (root, mut ctx, actor) = fixture("slo-env").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        let source = release_id("promo", "1.0.0");
        ctx.put(object(
            "tenkai:health-gate-evidence:slo-lab".into(),
            crate::ontology::KIND_HEALTH_GATE_EVIDENCE,
            "lab slo".into(),
            HashMap::from([
                ("release_id".into(), source.clone()),
                ("environment".into(), "lab".into()),
                ("verdict".into(), "pass".into()),
                ("observed_at".into(), "300000".into()),
            ]),
        ))
        .await
        .unwrap();
        ctx.put(object(
            "tenkai:health-gate-evidence:slo-prod".into(),
            crate::ontology::KIND_HEALTH_GATE_EVIDENCE,
            "prod slo".into(),
            HashMap::from([
                ("release_id".into(), source),
                ("environment".into(), "prod".into()),
                ("verdict".into(), "fail".into()),
                ("observed_at".into(), "301000".into()),
            ]),
        ))
        .await
        .unwrap();
        let mut policy = policy("promo", 1_000);
        policy.evidence.health_slo = true;
        configure(&mut ctx, &actor, policy).await.unwrap();
        Clock::set(302_000);
        let reset = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(reset[0].state, "reset", "{reset:?}");
        assert!(
            reset[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("health/SLO")),
            "{reset:?}"
        );
        assert!(head(&mut ctx, "promo", "stable").await.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn committed_decision_does_not_re_promote_after_rollback() {
        let _clock = Clock;
        Clock::set(1_000);
        let (root, mut ctx, actor) = fixture("committed").await;
        publish(&mut ctx, &root, "promo", "1.0.0").await;
        publish(&mut ctx, &root, "promo", "1.0.1").await;
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.0", "candidate")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "lab", "lab")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "lab", "promo", "candidate")
            .await
            .unwrap();
        observe(&mut ctx, "lab", "promo", "1.0.0", true).await;
        configure(&mut ctx, &actor, policy("promo", 1_000))
            .await
            .unwrap();
        Clock::set(1_000);
        reconcile_tick(&mut ctx, true).await.unwrap();
        Clock::set(2_000);
        let promoted = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(promoted[0].state, "promoted", "{promoted:?}");
        crate::catalog::promote(&mut ctx, &actor, "promo@1.0.1", "stable")
            .await
            .unwrap();
        assert_eq!(
            head(&mut ctx, "promo", "stable").await.unwrap(),
            release_id("promo", "1.0.1")
        );
        Clock::set(3_000);
        let refused = reconcile_tick(&mut ctx, true).await.unwrap();
        assert_eq!(refused[0].state, "refused", "{refused:?}");
        assert!(
            refused[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("already committed")),
            "{refused:?}"
        );
        let snap = status_snapshot(&mut ctx).await.unwrap();
        assert_eq!(snap[0].state, "refused", "{snap:?}");
        assert_eq!(
            head(&mut ctx, "promo", "stable").await.unwrap(),
            release_id("promo", "1.0.1")
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
