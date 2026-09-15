//! Preview environments bound to a content-addressed governance branch pin.
//!
//! A preview environment is a `tenkai.environment` with `environment_kind=preview`.
//! It is not a channel subscriber, cannot be promoted onto a channel, and is
//! torn down on expiry or recorded branch close. Teardown never deletes the
//! environment object and never mutates a non-preview environment.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::Path;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::{KIND_ENVIRONMENT, NS, env_id, validate_identifier};
use crate::pb::sekai::Object;
use crate::signature_verification;

pub const PIN_CONTRACT: &str = "tenkai.branch_pin.v1";
pub const ENVIRONMENT_KIND_PREVIEW: &str = "preview";
pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_TORN_DOWN: &str = "torn_down";
pub const TEARDOWN_EXPIRED: &str = "expired";
pub const TEARDOWN_BRANCH_CLOSED: &str = "branch_closed";

const MAX_PIN_BYTES: u64 = 16 * 1024;
const MAX_TEXT_BYTES: usize = 256;

const PROP_KIND: &str = "environment_kind";
const PROP_PIN: &str = "preview_pin";
const PROP_PIN_DIGEST: &str = "preview_pin_digest";
const PROP_PLAN_DIGEST: &str = "preview_plan_digest";
const PROP_EXPIRES_AT: &str = "preview_expires_at";
const PROP_STATUS: &str = "preview_status";
const PROP_TEARDOWN_REASON: &str = "preview_teardown_reason";
const PROP_TEARDOWN_AT: &str = "preview_teardown_at";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchPin {
    pub contract: String,
    pub namespace: String,
    pub branch_id: String,
    pub head_revision: String,
    pub pin_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewInspect {
    pub pin_digest: String,
    pub plan_digest: String,
    pub expires_at: i64,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeardownEvidence {
    pub environment: String,
    pub pin_digest: String,
    pub plan_digest: String,
    pub reason: String,
    pub torn_down_at: i64,
}

impl BranchPin {
    pub fn load_file(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        if !file.metadata()?.is_file() {
            bail!("branch pin must be a regular file");
        }
        let mut raw = Vec::new();
        file.take(MAX_PIN_BYTES + 1).read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_PIN_BYTES {
            bail!("branch pin exceeds {MAX_PIN_BYTES} bytes");
        }
        let pin: Self = serde_json::from_slice(&raw)?;
        pin.validate()?;
        Ok(pin)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract != PIN_CONTRACT {
            bail!(
                "unknown branch pin contract {:?}; expected {PIN_CONTRACT}",
                self.contract
            );
        }
        validate_text("branch pin namespace", &self.namespace)?;
        validate_text("branch pin branch_id", &self.branch_id)?;
        validate_text("branch pin head_revision", &self.head_revision)?;
        signature_verification::validate_prefixed_digest(
            "branch pin pin_digest",
            &self.pin_digest,
        )?;
        Ok(())
    }

    pub fn plan_digest(&self) -> Result<String> {
        self.validate()?;
        let mut output = b"TENKAI-PREVIEW-PLAN-V1\0".to_vec();
        for value in [
            &self.contract,
            &self.namespace,
            &self.branch_id,
            &self.head_revision,
            &self.pin_digest,
        ] {
            signature_verification::push_len_prefixed(&mut output, value.as_bytes());
        }
        Ok(format!("sha256:{:x}", Sha256::digest(output)))
    }

    fn canonical_json(&self) -> Result<String> {
        self.validate()?;
        Ok(serde_json::to_string(self)?)
    }
}

pub fn is_preview(object: &Object) -> bool {
    object.properties.get(PROP_KIND).map(String::as_str) == Some(ENVIRONMENT_KIND_PREVIEW)
}

pub fn refuse_channel_promotion(object: &Object) -> Result<()> {
    if is_preview(object) {
        bail!(
            "preview environment {} cannot be promoted to a channel",
            object.name
        );
    }
    Ok(())
}

pub fn inspect_from_object(object: &Object) -> Result<Option<PreviewInspect>> {
    if !is_preview(object) {
        return Ok(None);
    }
    Ok(Some(stored_inspect(object)?))
}

pub fn admit_plan(object: &Object, now: i64) -> Result<()> {
    let Some(preview) = inspect_from_object(object)? else {
        return Ok(());
    };
    match preview.status.as_str() {
        STATUS_TORN_DOWN => bail!(
            "preview environment {} is torn down ({})",
            object.name,
            preview
                .teardown_reason
                .as_deref()
                .unwrap_or("recorded teardown")
        ),
        STATUS_ACTIVE if preview.expires_at <= now => bail!(
            "preview environment {} expired at {}; teardown required",
            object.name,
            preview.expires_at
        ),
        STATUS_ACTIVE => Ok(()),
        other => bail!(
            "preview environment {} has unknown status {other:?}",
            object.name
        ),
    }
}

pub async fn provision(
    ctx: &mut Ctx,
    name: &str,
    pin: BranchPin,
    expires_at: i64,
    description: &str,
    now: i64,
) -> Result<String> {
    validate_identifier("environment", name)?;
    pin.validate()?;
    if expires_at <= now {
        bail!("preview environment {name} expiry must be in the future");
    }
    let plan_digest = pin.plan_digest()?;
    let pin_json = pin.canonical_json()?;
    let id = env_id(name);
    if let Some(existing) = ctx.get(&id).await? {
        return replay_or_conflict(existing, name, &pin, &plan_digest, expires_at);
    }
    let description = if description.is_empty() {
        format!("preview environment bound to {}", pin.pin_digest)
    } else {
        description.to_string()
    };
    let object = Object {
        id: id.clone(),
        kind: KIND_ENVIRONMENT.into(),
        name: name.into(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("description".into(), description),
            (PROP_KIND.into(), ENVIRONMENT_KIND_PREVIEW.into()),
            (PROP_PIN.into(), pin_json),
            (PROP_PIN_DIGEST.into(), pin.pin_digest.clone()),
            (PROP_PLAN_DIGEST.into(), plan_digest.clone()),
            (PROP_EXPIRES_AT.into(), expires_at.to_string()),
            (PROP_STATUS.into(), STATUS_ACTIVE.into()),
        ]),
        created: now,
        updated: now,
    };
    match ctx.create_once(object).await {
        Ok(_) => {}
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE")) =>
        {
            let Some(existing) = ctx.get(&id).await? else {
                bail!("preview environment {name} disappeared after create conflict");
            };
            return replay_or_conflict(existing, name, &pin, &plan_digest, expires_at);
        }
        Err(status) => return Err(status.into()),
    }
    crate::maintenance::ensure_configuration(ctx, name).await?;
    Ok(format!(
        "preview environment {name} registered; pin {}; plan digest {plan_digest}; expires at {expires_at}",
        pin.pin_digest
    ))
}

pub async fn teardown_due(ctx: &mut Ctx, env: &str, now: i64) -> Result<Option<TeardownEvidence>> {
    validate_identifier("environment", env)?;
    let Some(object) = ctx.get(&env_id(env)).await? else {
        return Ok(None);
    };
    if !is_preview(&object) {
        return Ok(None);
    }
    let preview = stored_inspect(&object)?;
    if preview.status == STATUS_TORN_DOWN {
        return Ok(None);
    }
    if preview.expires_at > now {
        return Ok(None);
    }
    Ok(Some(
        persist_teardown(ctx, object, TEARDOWN_EXPIRED, now).await?,
    ))
}

pub async fn close_branch(ctx: &mut Ctx, env: &str, now: i64) -> Result<TeardownEvidence> {
    validate_identifier("environment", env)?;
    let object = crate::environment::environment(ctx, env).await?;
    if !is_preview(&object) {
        bail!("environment {env} is not a preview environment");
    }
    let preview = stored_inspect(&object)?;
    if preview.status == STATUS_TORN_DOWN {
        return Ok(TeardownEvidence {
            environment: env.to_string(),
            pin_digest: preview.pin_digest,
            plan_digest: preview.plan_digest,
            reason: preview
                .teardown_reason
                .unwrap_or_else(|| TEARDOWN_BRANCH_CLOSED.into()),
            torn_down_at: preview.teardown_at.unwrap_or(now),
        });
    }
    persist_teardown(ctx, object, TEARDOWN_BRANCH_CLOSED, now).await
}

fn replay_or_conflict(
    existing: Object,
    name: &str,
    pin: &BranchPin,
    plan_digest: &str,
    expires_at: i64,
) -> Result<String> {
    if existing.kind != KIND_ENVIRONMENT {
        bail!(
            "object {} is {}, not {KIND_ENVIRONMENT}",
            existing.id,
            existing.kind
        );
    }
    if !is_preview(&existing) {
        bail!("environment {name} is already registered and is not a preview environment");
    }
    let stored = stored_inspect(&existing)?;
    if stored.pin_digest != pin.pin_digest || stored.plan_digest != *plan_digest {
        bail!("preview environment {name} already exists with a different branch pin");
    }
    if stored.status == STATUS_TORN_DOWN {
        bail!(
            "preview environment {name} was torn down ({}); choose a new environment name",
            stored
                .teardown_reason
                .as_deref()
                .unwrap_or("recorded teardown")
        );
    }
    if stored.expires_at != expires_at {
        bail!("preview environment {name} already exists with a different expiry");
    }
    Ok(format!(
        "preview environment {name} already registered for pin {}",
        pin.pin_digest
    ))
}

fn stored_inspect(object: &Object) -> Result<PreviewInspect> {
    let pin_raw = object.properties.get(PROP_PIN).ok_or_else(|| {
        anyhow::anyhow!("preview environment {} is missing preview_pin", object.name)
    })?;
    let pin: BranchPin = serde_json::from_str(pin_raw)?;
    pin.validate()?;
    let pin_digest = required_prop(object, PROP_PIN_DIGEST)?;
    if pin_digest != pin.pin_digest {
        bail!(
            "preview environment {} pin digest does not match its stored pin",
            object.name
        );
    }
    let plan_digest = required_prop(object, PROP_PLAN_DIGEST)?;
    if plan_digest != pin.plan_digest()? {
        bail!(
            "preview environment {} plan digest does not match its stored pin",
            object.name
        );
    }
    let expires_at = required_prop(object, PROP_EXPIRES_AT)?
        .parse::<i64>()
        .map_err(|_| {
            anyhow::anyhow!("preview environment {} has a malformed expiry", object.name)
        })?;
    let status = required_prop(object, PROP_STATUS)?;
    match status.as_str() {
        STATUS_ACTIVE | STATUS_TORN_DOWN => {}
        other => bail!(
            "preview environment {} has unknown status {other:?}",
            object.name
        ),
    }
    Ok(PreviewInspect {
        pin_digest,
        plan_digest,
        expires_at,
        status,
        teardown_reason: object.properties.get(PROP_TEARDOWN_REASON).cloned(),
        teardown_at: match object.properties.get(PROP_TEARDOWN_AT) {
            None => None,
            Some(value) => Some(value.parse::<i64>().map_err(|_| {
                anyhow::anyhow!(
                    "preview environment {} has a malformed teardown timestamp",
                    object.name
                )
            })?),
        },
    })
}

fn required_prop(object: &Object, key: &str) -> Result<String> {
    object
        .properties
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("preview environment {} is missing {key}", object.name))
}

async fn persist_teardown(
    ctx: &mut Ctx,
    mut object: Object,
    reason: &str,
    now: i64,
) -> Result<TeardownEvidence> {
    if !is_preview(&object) {
        bail!(
            "refusing to tear down environment {}; expiry must never delete a non-preview environment",
            object.name
        );
    }
    let preview = stored_inspect(&object)?;
    let keys: Vec<String> = object
        .properties
        .keys()
        .filter(|key| {
            key.starts_with("deployed.")
                || key.starts_with("deployed_release.")
                || key.starts_with("deployed_prev.")
                || key.starts_with("deployment_")
        })
        .cloned()
        .collect();
    for key in keys {
        object.properties.remove(&key);
    }
    object
        .properties
        .insert(PROP_STATUS.into(), STATUS_TORN_DOWN.into());
    object
        .properties
        .insert(PROP_TEARDOWN_REASON.into(), reason.into());
    object
        .properties
        .insert(PROP_TEARDOWN_AT.into(), now.to_string());
    object.updated = now;
    let evidence = TeardownEvidence {
        environment: object.name.clone(),
        pin_digest: preview.pin_digest,
        plan_digest: preview.plan_digest,
        reason: reason.into(),
        torn_down_at: now,
    };
    ctx.put(object).await?;
    Ok(evidence)
}

fn validate_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
        || value.contains("://")
        || value.contains('/')
        || value.contains('\\')
    {
        bail!("{label} is empty, oversized, or not an opaque identifier");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::ontology::{KIND_CHANNEL, channel_id};

    fn sample_pin() -> BranchPin {
        BranchPin {
            contract: PIN_CONTRACT.into(),
            namespace: "acme".into(),
            branch_id: "types".into(),
            head_revision: "rev-1".into(),
            pin_digest: format!("sha256:{}", "a".repeat(64)),
        }
    }

    fn other_pin() -> BranchPin {
        let mut pin = sample_pin();
        pin.branch_id = "policies".into();
        pin.pin_digest = format!("sha256:{}", "b".repeat(64));
        pin
    }

    async fn ctx() -> Ctx {
        let path = std::env::temp_dir().join(format!("tenkai-preview-{}.db", uuid::Uuid::new_v4()));
        let mut ctx = Ctx::embedded(path).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        ctx
    }

    #[tokio::test]
    async fn same_pin_produces_the_same_plan_digest() {
        let mut ctx = ctx().await;
        let pin = sample_pin();
        let digest = pin.plan_digest().unwrap();
        let now = 1_000;
        let expires = crate::now_millis() + 86_400_000;
        provision(&mut ctx, "review-a", pin.clone(), expires, "", now)
            .await
            .unwrap();
        provision(&mut ctx, "review-b", pin.clone(), expires, "", now)
            .await
            .unwrap();
        let replay = provision(&mut ctx, "review-a", pin.clone(), expires, "", now)
            .await
            .unwrap();
        assert!(replay.contains("already registered"), "{replay}");

        let left = inspect_from_object(
            &crate::environment::environment(&mut ctx, "review-a")
                .await
                .unwrap(),
        )
        .unwrap()
        .unwrap();
        let right = inspect_from_object(
            &crate::environment::environment(&mut ctx, "review-b")
                .await
                .unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(left.plan_digest, digest);
        assert_eq!(right.plan_digest, digest);
        assert_eq!(left.pin_digest, pin.pin_digest);
        crate::plan::create(&mut ctx, "review-a").await.unwrap();
        crate::plan::create(&mut ctx, "review-b").await.unwrap();
    }

    #[tokio::test]
    async fn different_pin_on_the_same_name_conflicts() {
        let mut ctx = ctx().await;
        let expires = crate::now_millis() + 86_400_000;
        provision(&mut ctx, "review", sample_pin(), expires, "", 1_000)
            .await
            .unwrap();
        let error = provision(&mut ctx, "review", other_pin(), expires, "", 1_000)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("different branch pin"), "{error}");
    }

    #[tokio::test]
    async fn standard_environment_cannot_become_preview() {
        let mut ctx = ctx().await;
        crate::environment::env_add(&mut ctx, "local", "this machine")
            .await
            .unwrap();
        let error = provision(
            &mut ctx,
            "local",
            sample_pin(),
            crate::now_millis() + 86_400_000,
            "",
            1_000,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a preview environment"), "{error}");
    }

    #[tokio::test]
    async fn promotion_and_subscribe_are_refused() {
        let mut ctx = ctx().await;
        provision(&mut ctx, "review", sample_pin(), 10_000, "", 1_000)
            .await
            .unwrap();
        let env = crate::environment::environment(&mut ctx, "review")
            .await
            .unwrap();
        let refused = refuse_channel_promotion(&env).unwrap_err().to_string();
        assert!(
            refused.contains("cannot be promoted to a channel"),
            "{refused}"
        );

        ctx.create_once(Object {
            id: channel_id("api", "stable"),
            kind: KIND_CHANNEL.into(),
            name: "api/stable".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("product".into(), "api".into()),
                ("channel".into(), "stable".into()),
                ("current_version".into(), "1.0.0".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .await
        .unwrap();
        let subscribe = crate::environment::subscribe(&mut ctx, "review", "api", "stable")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            subscribe.contains("cannot be promoted to a channel"),
            "{subscribe}"
        );
    }

    #[tokio::test]
    async fn expiry_tears_down_preview_and_records_evidence() {
        let mut ctx = ctx().await;
        let pin = sample_pin();
        provision(&mut ctx, "review", pin.clone(), 5_000, "", 1_000)
            .await
            .unwrap();
        assert!(
            teardown_due(&mut ctx, "review", 4_999)
                .await
                .unwrap()
                .is_none()
        );
        let evidence = teardown_due(&mut ctx, "review", 5_000)
            .await
            .unwrap()
            .expect("expired preview");
        assert_eq!(evidence.reason, TEARDOWN_EXPIRED);
        assert_eq!(evidence.pin_digest, pin.pin_digest);
        assert_eq!(evidence.plan_digest, pin.plan_digest().unwrap());
        let stored = crate::environment::environment(&mut ctx, "review")
            .await
            .unwrap();
        let inspect = inspect_from_object(&stored).unwrap().unwrap();
        assert_eq!(inspect.status, STATUS_TORN_DOWN);
        assert_eq!(inspect.teardown_reason.as_deref(), Some(TEARDOWN_EXPIRED));
        let plan = crate::plan::create(&mut ctx, "review")
            .await
            .unwrap_err()
            .to_string();
        assert!(plan.contains("torn down"), "{plan}");
        assert!(
            ctx.get(&env_id("review")).await.unwrap().is_some(),
            "teardown must retain the environment object"
        );
    }

    #[tokio::test]
    async fn expiry_never_tears_down_a_standard_environment() {
        let mut ctx = ctx().await;
        crate::environment::env_add(&mut ctx, "local", "this machine")
            .await
            .unwrap();
        let mut object = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        object.properties.insert(PROP_EXPIRES_AT.into(), "1".into());
        object
            .properties
            .insert(PROP_STATUS.into(), STATUS_ACTIVE.into());
        ctx.put(object).await.unwrap();
        assert!(
            teardown_due(&mut ctx, "local", 10_000)
                .await
                .unwrap()
                .is_none()
        );
        let stored = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert!(!is_preview(&stored));
        assert_eq!(
            stored.properties.get("description").map(String::as_str),
            Some("this machine")
        );
        close_branch(&mut ctx, "local", 10_000).await.unwrap_err();
    }

    #[tokio::test]
    async fn branch_close_tears_down_preview() {
        let mut ctx = ctx().await;
        provision(&mut ctx, "review", sample_pin(), 50_000, "", 1_000)
            .await
            .unwrap();
        let evidence = close_branch(&mut ctx, "review", 2_000).await.unwrap();
        assert_eq!(evidence.reason, TEARDOWN_BRANCH_CLOSED);
        assert_eq!(evidence.torn_down_at, 2_000);
        let inspect = inspect_from_object(
            &crate::environment::environment(&mut ctx, "review")
                .await
                .unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(inspect.status, STATUS_TORN_DOWN);
        assert_eq!(
            inspect.teardown_reason.as_deref(),
            Some(TEARDOWN_BRANCH_CLOSED)
        );
    }

    #[test]
    fn unknown_contract_fails_closed() {
        let mut pin = sample_pin();
        pin.contract = "tenkai.branch_pin.v0".into();
        let error = pin.validate().unwrap_err().to_string();
        assert!(error.contains("unknown branch pin contract"), "{error}");
    }
}
