//! Environment and channel delivery hold: the reconciler plans, but does not execute.
//!
//! A hold is its own catalog object, one per scope, so environment and channel
//! writes (promote, subscribe, deploy) never have to carry it forward. Every
//! set and clear also appends an immutable audit event with reason, actor, and
//! time; clearing deletes the hold but never its history.

use std::collections::HashMap;

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::ontology::{KIND_CHANNEL, NS, channel_id, validate_identifier};
use crate::pb::sekai::Object;

pub const HOLD_KIND: &str = "tenkai.delivery_hold";
pub const HOLD_AUDIT_KIND: &str = "tenkai.delivery_hold_audit";

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

/// One immutable set or clear transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldAuditEvent {
    pub action: String,
    pub reason: String,
    pub actor: String,
    pub at: i64,
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
    scope.require_exists(ctx).await?;
    let hold = DeliveryHold {
        reason: reason.into(),
        actor: actor.into(),
        held_at: crate::now_millis(),
    };
    ctx.put(hold_object(scope, &hold)).await?;
    append_audit(ctx, scope, "set", &hold).await?;
    Ok(hold)
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
) -> Result<Option<(DeliveryHold, HoldScope)>> {
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
            return Ok(Some((hold, scope)));
        }
    }
    Ok(None)
}

/// Refuse to start `plan` while a hold pauses it.
pub async fn require_not_held(ctx: &mut Ctx, plan: &crate::plan::Plan) -> Result<()> {
    if let Some((hold, scope)) = active_for_plan(ctx, plan).await? {
        bail!(
            "plan {} is paused by delivery hold {} set by {}: {}; clear the hold to execute",
            plan.id,
            scope.key(),
            hold.actor,
            hold.reason
        );
    }
    Ok(())
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

fn hold_object(scope: &HoldScope, hold: &DeliveryHold) -> Object {
    Object {
        id: scope.hold_id(),
        kind: HOLD_KIND.into(),
        name: scope.key(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("scope".into(), scope.key()),
            ("reason".into(), hold.reason.clone()),
            ("actor".into(), hold.actor.clone()),
            ("held_at".into(), hold.held_at.to_string()),
        ]),
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
}
