//! Environments, subscriptions, and plan computation (desired vs deployed).

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::*;
use crate::pb::sekai::Object;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Install,
    Upgrade,
    Downgrade,
    Rollback,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Action::Install => "install",
            Action::Upgrade => "upgrade",
            Action::Downgrade => "downgrade",
            Action::Rollback => "rollback",
        };
        f.write_str(s)
    }
}

pub const PLAN_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub id: String,
    pub order: u32,
    pub product: String,
    pub action: Action,
    pub from: Option<String>,
    pub to: String,
    pub release_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredStateInput {
    pub product: String,
    pub channel: String,
    pub channel_id: String,
    pub desired_version: String,
    pub release_id: String,
    pub deployed_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanState {
    Computed,
    Running,
    Succeeded,
    Failed,
}

impl std::fmt::Display for PlanState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Computed => "computed",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub format_version: u32,
    pub id: String,
    pub environment: String,
    pub created_at: i64,
    pub inputs: Vec<DesiredStateInput>,
    pub steps: Vec<Step>,
    pub state: PlanState,
    pub gates_skipped: Option<bool>,
}

#[derive(Serialize)]
struct ExecutableContent<'a> {
    format_version: u32,
    id: &'a str,
    environment: &'a str,
    created_at: i64,
    inputs: &'a [DesiredStateInput],
    steps: &'a [Step],
}

impl Plan {
    fn executable_digest(&self) -> Result<String> {
        let content = ExecutableContent {
            format_version: self.format_version,
            id: &self.id,
            environment: &self.environment,
            created_at: self.created_at,
            inputs: &self.inputs,
            steps: &self.steps,
        };
        let bytes = serde_json::to_vec(&content)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn to_object(&self) -> Result<Object> {
        let now = crate::now_millis();
        Ok(Object {
            id: self.id.clone(),
            kind: KIND_PLAN.into(),
            name: format!("{} plan {}", self.environment, self.created_at),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("format_version".into(), self.format_version.to_string()),
                ("environment".into(), self.environment.clone()),
                ("created_at".into(), self.created_at.to_string()),
                ("content_digest".into(), self.executable_digest()?),
                ("plan".into(), serde_json::to_string(self)?),
                ("status".into(), self.state.to_string()),
            ]),
            created: self.created_at,
            updated: now,
        })
    }

    fn from_object(object: &Object) -> Result<Self> {
        if object.kind != KIND_PLAN {
            bail!("object {} is {}, not {KIND_PLAN}", object.id, object.kind);
        }
        let raw = object
            .properties
            .get("plan")
            .with_context(|| format!("plan object {} has no serialized plan", object.id))?;
        let plan: Self = serde_json::from_str(raw)
            .with_context(|| format!("parsing stored plan {}", object.id))?;
        if plan.format_version != PLAN_FORMAT_VERSION {
            bail!(
                "plan {} uses unsupported format version {}",
                object.id,
                plan.format_version
            );
        }
        if plan.id != object.id {
            bail!(
                "stored plan id {} does not match object id {}",
                plan.id,
                object.id
            );
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
}

pub async fn store(ctx: &mut Ctx, plan: &Plan) -> Result<()> {
    if let Some(existing) = ctx.get(&plan.id).await? {
        let stored = Plan::from_object(&existing)?;
        if stored.executable_digest()? != plan.executable_digest()? {
            bail!("plan {} executable content is immutable", plan.id);
        }
        let valid_transition = stored.state == plan.state
            || matches!(
                (stored.state, plan.state),
                (PlanState::Computed, PlanState::Running)
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
    ctx.put(plan.to_object()?).await?;
    Ok(())
}

pub async fn load(ctx: &mut Ctx, id: &str) -> Result<Plan> {
    let object = ctx
        .get(id)
        .await?
        .with_context(|| format!("plan {id} not found"))?;
    Plan::from_object(&object)
}

pub async fn env_add(ctx: &mut Ctx, name: &str, description: &str) -> Result<String> {
    let now = crate::now_millis();
    ctx.put(Object {
        id: env_id(name),
        kind: KIND_ENVIRONMENT.into(),
        name: name.into(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([("description".into(), description.to_string())]),
        created: now,
        updated: now,
    })
    .await?;
    Ok(format!("environment {name} registered"))
}

/// Subscribe an environment to a product channel. The channel must exist.
pub async fn subscribe(ctx: &mut Ctx, env: &str, product: &str, channel: &str) -> Result<String> {
    let eid = env_id(env);
    if ctx.get(&eid).await?.is_none() {
        bail!("environment {env} is not registered (tenkaictl env add {env})");
    }
    let cid = channel_id(product, channel);
    if ctx.get(&cid).await?.is_none() {
        bail!("channel {product}/{channel} does not exist — promote a release into it first");
    }
    ctx.link(&eid, &cid, REL_SUBSCRIBES).await?;
    Ok(format!("{env} subscribed to {product}/{channel}"))
}

async fn environment(ctx: &mut Ctx, env: &str) -> Result<Object> {
    match ctx.get(&env_id(env)).await? {
        Some(o) => Ok(o),
        None => bail!("environment {env} is not registered (tenkaictl env add {env})"),
    }
}

async fn compute_snapshot(ctx: &mut Ctx, env: &str) -> Result<(Vec<DesiredStateInput>, Vec<Step>)> {
    let env_obj = environment(ctx, env).await?;
    let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;

    let mut inputs = Vec::new();
    let mut pending = Vec::new();
    for ch in channels {
        let product = ch.properties.get("product").cloned().unwrap_or_default();
        let channel = ch.properties.get("channel").cloned().unwrap_or_default();
        let desired = ch
            .properties
            .get("current_version")
            .cloned()
            .unwrap_or_default();
        let release = ch
            .properties
            .get("current_release")
            .cloned()
            .unwrap_or_default();
        if desired.is_empty() || release.is_empty() {
            continue; // channel exists but nothing promoted yet
        }
        let deployed = env_obj
            .properties
            .get(&format!("deployed.{product}"))
            .cloned();
        inputs.push(DesiredStateInput {
            product: product.clone(),
            channel,
            channel_id: ch.id,
            desired_version: desired.clone(),
            release_id: release.clone(),
            deployed_version: deployed.clone(),
        });
        match deployed {
            Some(v) if v == desired => {}
            Some(v) => pending.push((product, Action::Upgrade, Some(v), desired, release)),
            None => pending.push((product, Action::Install, None, desired, release)),
        }
    }
    inputs.sort_by(|a, b| a.product.cmp(&b.product));
    pending.sort_by(|a, b| a.0.cmp(&b.0));
    let steps = pending
        .into_iter()
        .enumerate()
        .map(|(index, (product, action, from, to, release_id))| Step {
            id: format!("{}:step:{index}", env_id(env)),
            order: index as u32,
            product,
            action,
            from,
            to,
            release_id,
        })
        .collect();
    Ok((inputs, steps))
}

/// Compute the steps that converge the environment on its subscribed channels.
pub async fn compute(ctx: &mut Ctx, env: &str) -> Result<Vec<Step>> {
    Ok(compute_snapshot(ctx, env).await?.1)
}

/// Compute and persist an immutable executable plan before any step is run.
pub async fn create(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    let (inputs, mut steps) = compute_snapshot(ctx, env).await?;
    create_with_content(ctx, env, inputs, &mut steps).await
}

/// Persist an explicitly constructed operation, such as a rollback, as a plan.
pub async fn create_from_steps(ctx: &mut Ctx, env: &str, mut steps: Vec<Step>) -> Result<Plan> {
    environment(ctx, env).await?;
    create_with_content(ctx, env, Vec::new(), &mut steps).await
}

async fn create_with_content(
    ctx: &mut Ctx,
    env: &str,
    inputs: Vec<DesiredStateInput>,
    steps: &mut [Step],
) -> Result<Plan> {
    let created_at = crate::now_millis();
    let id = plan_id(env, created_at);
    for (order, step) in steps.iter_mut().enumerate() {
        step.id = format!("{id}:step:{order}");
        step.order = order as u32;
    }
    let plan = Plan {
        format_version: PLAN_FORMAT_VERSION,
        id,
        environment: env.to_string(),
        created_at,
        inputs,
        steps: steps.to_vec(),
        state: PlanState::Computed,
        gates_skipped: None,
    };
    store(ctx, &plan).await?;
    Ok(plan)
}

/// A rollback step to the previously deployed version of one product.
pub async fn rollback_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    let env_obj = environment(ctx, env).await?;
    let current = env_obj
        .properties
        .get(&format!("deployed.{product}"))
        .cloned();
    let Some(prev) = env_obj
        .properties
        .get(&format!("deployed_prev.{product}"))
        .cloned()
        .filter(|v| !v.is_empty())
    else {
        bail!("no previous version of {product} recorded in {env} — nothing to roll back to");
    };
    Ok(Step {
        id: format!("{}:rollback:{product}", env_id(env)),
        order: 0,
        release_id: release_id(product, &prev),
        product: product.into(),
        action: Action::Rollback,
        from: current,
        to: prev,
    })
}

pub struct StatusRow {
    pub product: String,
    pub channel: String,
    pub deployed: Option<String>,
    pub head: String,
}

pub async fn status(ctx: &mut Ctx, env: &str) -> Result<Vec<StatusRow>> {
    let env_obj = environment(ctx, env).await?;
    let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;
    let mut rows = Vec::new();
    for ch in channels {
        let product = ch.properties.get("product").cloned().unwrap_or_default();
        rows.push(StatusRow {
            deployed: env_obj
                .properties
                .get(&format!("deployed.{product}"))
                .cloned(),
            channel: ch.properties.get("channel").cloned().unwrap_or_default(),
            head: ch
                .properties
                .get("current_version")
                .cloned()
                .unwrap_or_else(|| "-".into()),
            product,
        });
    }
    rows.sort_by(|a, b| a.product.cmp(&b.product));
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_plan() -> Plan {
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            id: "tenkai:plan:prod:123".into(),
            environment: "prod".into(),
            created_at: 123,
            inputs: vec![DesiredStateInput {
                product: "api".into(),
                channel: "stable".into(),
                channel_id: "tenkai:channel:api/stable".into(),
                desired_version: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                deployed_version: Some("1.0.0".into()),
            }],
            steps: vec![Step {
                id: "tenkai:plan:prod:123:step:0".into(),
                order: 0,
                product: "api".into(),
                action: Action::Upgrade,
                from: Some("1.0.0".into()),
                to: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
            }],
            state: PlanState::Computed,
            gates_skipped: None,
        }
    }

    #[test]
    fn serialized_plan_round_trips() {
        let plan = example_plan();
        let object = plan.to_object().unwrap();
        assert_eq!(Plan::from_object(&object).unwrap(), plan);
    }

    #[test]
    fn lifecycle_changes_do_not_change_executable_digest() {
        let plan = example_plan();
        let mut running = plan.clone();
        running.state = PlanState::Running;
        assert_eq!(
            plan.executable_digest().unwrap(),
            running.executable_digest().unwrap()
        );
    }

    #[test]
    fn executable_mutation_is_detected() {
        let plan = example_plan();
        let mut object = plan.to_object().unwrap();
        let mut changed = plan;
        changed.steps[0].to = "3.0.0".into();
        object
            .properties
            .insert("plan".into(), serde_json::to_string(&changed).unwrap());
        let error = Plan::from_object(&object).unwrap_err().to_string();
        assert!(error.contains("executable content was mutated"));
    }
}
