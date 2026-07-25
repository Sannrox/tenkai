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

fn classify_change(current: &str, desired: &str) -> Action {
    match (
        semver::Version::parse(current),
        semver::Version::parse(desired),
    ) {
        (Ok(current), Ok(target)) if target < current => Action::Downgrade,
        _ => Action::Upgrade,
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
    pub release_digest: String,
    pub artifact_digest: String,
    pub workdir: String,
    pub restore: Option<ReleasePin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePin {
    pub release_id: String,
    pub digest: String,
    pub artifact_digest: String,
    pub workdir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredStateInput {
    pub product: String,
    pub channel: String,
    pub channel_id: String,
    pub desired_version: String,
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub deployed_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanState {
    Computed,
    Running,
    Blocked,
    Succeeded,
    Failed,
}

impl std::fmt::Display for PlanState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Computed => "computed",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub format_version: u32,
    pub id: String,
    pub content_id: String,
    pub environment: String,
    pub created_at: i64,
    pub inputs: Vec<DesiredStateInput>,
    pub steps: Vec<Step>,
    pub state: PlanState,
    pub gates_skipped: Option<bool>,
    pub status_detail: String,
    #[serde(default)]
    pub maintenance_blocked: bool,
}

#[derive(Serialize)]
struct ExecutableContent<'a> {
    format_version: u32,
    id: &'a str,
    content_id: &'a str,
    environment: &'a str,
    created_at: i64,
    inputs: &'a [DesiredStateInput],
    steps: &'a [Step],
}

fn content_address(
    environment: &str,
    created_at: i64,
    inputs: &[DesiredStateInput],
    steps: &[Step],
) -> Result<String> {
    let mut normalized_steps = steps.to_vec();
    for step in &mut normalized_steps {
        step.id.clear();
    }
    let bytes = serde_json::to_vec(&(
        PLAN_FORMAT_VERSION,
        environment,
        created_at,
        inputs,
        normalized_steps,
    ))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl Plan {
    pub fn executable_digest(&self) -> Result<String> {
        let content = ExecutableContent {
            format_version: self.format_version,
            id: &self.id,
            content_id: &self.content_id,
            environment: &self.environment,
            created_at: self.created_at,
            inputs: &self.inputs,
            steps: &self.steps,
        };
        let bytes = serde_json::to_vec(&content)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub(crate) fn to_object(&self) -> Result<Object> {
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
}

pub async fn store(ctx: &mut Ctx, plan: &Plan) -> Result<()> {
    let existing = ctx.get(&plan.id).await?;
    if let Some(existing) = existing.as_ref() {
        let stored = Plan::from_object(existing)?;
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
    let mut object = plan.to_object()?;
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
    ctx.put(object).await?;
    Ok(())
}

pub async fn load(ctx: &mut Ctx, id: &str) -> Result<Plan> {
    let object = ctx
        .get(id)
        .await?
        .with_context(|| format!("plan {id} not found"))?;
    Plan::from_object(&object)
}

fn environment_record(
    existing: Option<Object>,
    name: &str,
    description: &str,
    now: i64,
) -> Result<Object> {
    let id = env_id(name);
    Ok(match existing {
        Some(mut existing) => {
            if existing.kind != KIND_ENVIRONMENT {
                bail!("object {id} is {}, not {KIND_ENVIRONMENT}", existing.kind);
            }
            existing
                .properties
                .insert("description".into(), description.to_string());
            existing.updated = now;
            existing
        }
        None => Object {
            id,
            kind: KIND_ENVIRONMENT.into(),
            name: name.into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([("description".into(), description.to_string())]),
            created: now,
            updated: now,
        },
    })
}

pub async fn env_add(ctx: &mut Ctx, name: &str, description: &str) -> Result<String> {
    validate_identifier("environment", name)?;
    let now = crate::now_millis();
    let id = env_id(name);
    if let Some(existing) = ctx.get(&id).await? {
        if existing.kind != KIND_ENVIRONMENT {
            bail!("object {id} is {}, not {KIND_ENVIRONMENT}", existing.kind);
        }
        crate::maintenance::ensure_configuration(ctx, name).await?;
        return Ok(format!("environment {name} already registered"));
    }
    let object = environment_record(None, name, description, now)?;
    match ctx.create_once(object).await {
        Ok(_) => {}
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE")) => {}
        Err(status) => return Err(status.into()),
    }
    crate::maintenance::ensure_configuration(ctx, name).await?;
    Ok(format!("environment {name} registered"))
}

pub async fn reconcile_deployment(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    deployed: Option<&str>,
) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("product", product)?;
    if crate::apply::environment_lease_status(ctx, env)
        .await?
        .is_some()
    {
        bail!("environment {env} has an apply in progress");
    }
    let mut object = environment(ctx, env).await?;
    match deployed {
        Some(version) => {
            validate_identifier("version", version)?;
            let release = release_id(product, version);
            if ctx.get(&release).await?.is_none() {
                bail!("release {product}@{version} is not published");
            }
            object
                .properties
                .insert(format!("deployed.{product}"), version.into());
            object
                .properties
                .insert(format!("deployed_release.{product}"), release);
        }
        None => {
            object.properties.remove(&format!("deployed.{product}"));
            object
                .properties
                .remove(&format!("deployed_release.{product}"));
        }
    }
    object
        .properties
        .remove(&format!("deployment_health.{product}"));
    object
        .properties
        .remove(&format!("deployment_error.{product}"));
    object
        .properties
        .remove(&format!("deployed_prev.{product}"));
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(match deployed {
        Some(version) => format!("recorded {product}@{version} as deployed in {env}"),
        None => format!("cleared unknown deployment state for {product} in {env}"),
    })
}

/// Subscribe an environment to a product channel. The channel must exist.
pub async fn subscribe(ctx: &mut Ctx, env: &str, product: &str, channel: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("product", product)?;
    validate_identifier("channel", channel)?;
    let eid = env_id(env);
    if ctx.get(&eid).await?.is_none() {
        bail!("environment {env} is not registered (tenkaictl env add {env})");
    }
    let cid = channel_id(product, channel);
    if ctx.get(&cid).await?.is_none() {
        bail!("channel {product}/{channel} does not exist — promote a release into it first");
    }
    let links = ctx.links(&eid, REL_SUBSCRIBES).await?;
    let mut existing = Vec::new();
    for link in links {
        let channel = ctx
            .get(&link.to_id)
            .await?
            .with_context(|| format!("subscription link {} has no channel", link.id))?;
        if channel.properties.get("product").map(String::as_str) == Some(product) {
            existing.push(link);
        }
    }
    if existing.len() > 1 {
        bail!("environment {env} has conflicting subscriptions for {product}");
    }
    if existing.first().is_some_and(|link| link.to_id == cid) {
        return Ok(format!("{env} already subscribed to {product}/{channel}"));
    }
    let mut params = HashMap::from([("id".into(), eid), ("channel_id".into(), cid)]);
    let action = if let Some(link) = existing.first() {
        params.insert("old_link_id".into(), link.id.clone());
        ACTION_REPLACE_SUBSCRIPTION
    } else {
        ACTION_SUBSCRIBE
    };
    ctx.execute_action(action, params).await?;
    Ok(format!("{env} subscribed to {product}/{channel}"))
}

async fn environment(ctx: &mut Ctx, env: &str) -> Result<Object> {
    validate_identifier("environment", env)?;
    match ctx.get(&env_id(env)).await? {
        Some(o) => Ok(o),
        None => bail!("environment {env} is not registered (tenkaictl env add {env})"),
    }
}

async fn pin_release(ctx: &mut Ctx, id: &str, environment: &str) -> Result<ReleasePin> {
    use crate::catalog::CatalogReader as _;

    let descriptor = crate::catalog::EmbeddedCatalog::new(ctx)
        .lookup_release(id, environment)
        .await?;
    Ok(ReleasePin {
        release_id: descriptor.release_id,
        digest: descriptor.manifest_digest,
        artifact_digest: descriptor.artifact_digest,
        workdir: descriptor.content_path,
    })
}

/// Resolve channel head against environment version pin/range constraints.
///
/// - `constraint.version_pin.<product>` forces that exact published version
///   (overrides channel head when different).
/// - `constraint.version_range.<product>` is `min..max` (semver, min inclusive,
///   max exclusive). Selected version must lie in the range.
async fn resolve_constrained_release(
    ctx: &mut Ctx,
    env_obj: &Object,
    env: &str,
    product: &str,
    channel_version: &str,
    channel_release: &str,
) -> Result<(String, String)> {
    let pin_key = format!("constraint.version_pin.{product}");
    let range_key = format!("constraint.version_range.{product}");
    if let Some(pin) = env_obj.properties.get(&pin_key) {
        if pin.trim().is_empty() {
            bail!("constraint version pin for {product} must not be empty");
        }
        let pinned_release = release_id(product, pin);
        if ctx.get(&pinned_release).await?.is_none() {
            bail!(
                "version pin {pin} for {product} in {env} is not published (constraint {pin_key})"
            );
        }
        if pin != channel_version {
            // Pin selects a specific release; channel head is advisory when it differs.
            return Ok((pin.clone(), pinned_release));
        }
        return Ok((channel_version.into(), channel_release.into()));
    }
    if let Some(range) = env_obj.properties.get(&range_key)
        && !version_in_range(channel_version, range)?
    {
        bail!(
            "channel head {channel_version} for {product} in {env} violates version range constraint {range:?} ({range_key})"
        );
    }
    Ok((channel_version.into(), channel_release.into()))
}

fn version_in_range(version: &str, range: &str) -> Result<bool> {
    let Some((min, max)) = range.split_once("..") else {
        bail!("version range must be min..max, got {range:?}");
    };
    let version =
        semver::Version::parse(version).with_context(|| format!("invalid version {version:?}"))?;
    let min = semver::Version::parse(min.trim())
        .with_context(|| format!("invalid version range minimum in {range:?}"))?;
    let max = semver::Version::parse(max.trim())
        .with_context(|| format!("invalid version range maximum in {range:?}"))?;
    if min >= max {
        bail!("version range minimum must be less than maximum in {range:?}");
    }
    Ok(version >= min && version < max)
}

async fn enforce_capability_constraints(ctx: &mut Ctx, env_obj: &Object, env: &str) -> Result<()> {
    for (key, expected) in &env_obj.properties {
        let Some(fact_key) = key.strip_prefix("constraint.require_fact.") else {
            continue;
        };
        validate_fact_key(fact_key)?;
        let actual = require_environment_fact(ctx, env, fact_key).await?;
        if expected != "*" && expected != &actual {
            bail!(
                "environment {env} fact {fact_key}={actual} does not satisfy constraint {expected:?} ({key})"
            );
        }
    }
    Ok(())
}

/// Set a version pin, version range, or required-fact constraint.
pub async fn set_environment_constraint(
    ctx: &mut Ctx,
    env: &str,
    kind: &str,
    name: &str,
    value: &str,
) -> Result<String> {
    validate_identifier("environment", env)?;
    if value.trim().is_empty() {
        bail!("constraint value must not be empty");
    }
    let property = match kind {
        "version_pin" => {
            validate_identifier("product", name)?;
            semver::Version::parse(value)
                .with_context(|| format!("version pin must be valid semver, got {value:?}"))?;
            format!("constraint.version_pin.{name}")
        }
        "version_range" => {
            validate_identifier("product", name)?;
            let (min, max) = value
                .split_once("..")
                .context("version range must be min..max")?;
            let min_v = semver::Version::parse(min.trim())
                .with_context(|| format!("invalid version range minimum in {value:?}"))?;
            let max_v = semver::Version::parse(max.trim())
                .with_context(|| format!("invalid version range maximum in {value:?}"))?;
            if min_v >= max_v {
                bail!("version range minimum must be less than maximum");
            }
            format!("constraint.version_range.{name}")
        }
        "require_fact" => {
            validate_fact_key(name)?;
            if value != "*" {
                validate_fact_value(name, value)?;
            }
            format!("constraint.require_fact.{name}")
        }
        other => bail!(
            "unknown constraint kind {other:?}; expected version_pin, version_range, or require_fact"
        ),
    };
    let mut env_obj = environment(ctx, env).await?;
    env_obj.properties.insert(property.clone(), value.into());
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} constraint {property}={value}"))
}

pub async fn clear_environment_constraint(
    ctx: &mut Ctx,
    env: &str,
    kind: &str,
    name: &str,
) -> Result<String> {
    let property = match kind {
        "version_pin" => format!("constraint.version_pin.{name}"),
        "version_range" => format!("constraint.version_range.{name}"),
        "require_fact" => format!("constraint.require_fact.{name}"),
        other => bail!("unknown constraint kind {other:?}"),
    };
    let mut env_obj = environment(ctx, env).await?;
    if env_obj.properties.remove(&property).is_none() {
        bail!("environment {env} has no constraint {property}");
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("cleared {env} constraint {property}"))
}

pub async fn list_environment_constraints(
    ctx: &mut Ctx,
    env: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let env_obj = environment(ctx, env).await?;
    let mut out = std::collections::BTreeMap::new();
    for (key, value) in &env_obj.properties {
        if key.starts_with("constraint.") {
            out.insert(key.clone(), value.clone());
        }
    }
    Ok(out)
}

async fn compute_snapshot(ctx: &mut Ctx, env: &str) -> Result<(Vec<DesiredStateInput>, Vec<Step>)> {
    let env_obj = environment(ctx, env).await?;
    let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;

    let mut products = std::collections::HashSet::new();
    for channel in &channels {
        let product = channel
            .properties
            .get("product")
            .cloned()
            .unwrap_or_default();
        if !products.insert(product.clone()) {
            bail!(
                "environment {env} has multiple channel subscriptions for {product}; subscribe again after concurrent updates settle"
            );
        }
    }

    let mut inputs = Vec::new();
    let mut pending = Vec::new();
    for ch in channels {
        let product = ch.properties.get("product").cloned().unwrap_or_default();
        let channel = ch.properties.get("channel").cloned().unwrap_or_default();
        let channel_version = ch
            .properties
            .get("current_version")
            .cloned()
            .unwrap_or_default();
        let channel_release = ch
            .properties
            .get("current_release")
            .cloned()
            .unwrap_or_default();
        if channel_version.is_empty() || channel_release.is_empty() {
            continue; // channel exists but nothing promoted yet
        }
        let (desired, release) = resolve_constrained_release(
            ctx,
            &env_obj,
            env,
            &product,
            &channel_version,
            &channel_release,
        )
        .await?;
        enforce_capability_constraints(ctx, &env_obj, env).await?;
        let target = pin_release(ctx, &release, env).await?;
        if env_obj
            .properties
            .get(&format!("deployment_health.{product}"))
            .is_some_and(|health| health == "unknown")
        {
            let detail = env_obj
                .properties
                .get(&format!("deployment_error.{product}"))
                .map(String::as_str)
                .unwrap_or("deployment state requires manual reconciliation");
            bail!(
                "deployment state for {product} in {env} is unknown: {detail}; reconcile it or use rollback before creating a new plan"
            );
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
            release_digest: target.digest.clone(),
            artifact_digest: target.artifact_digest.clone(),
            deployed_version: deployed.clone(),
        });
        match deployed {
            Some(v) if v == desired => {}
            Some(v) => {
                let action = classify_change(&v, &desired);
                let restore = pin_release(ctx, &release_id(&product, &v), env).await?;
                pending.push((product, action, Some(v), desired, target, Some(restore)));
            }
            None => pending.push((product, Action::Install, None, desired, target, None)),
        }
    }
    inputs.sort_by(|a, b| a.product.cmp(&b.product));
    pending.sort_by(|a, b| a.0.cmp(&b.0));
    let steps = pending
        .into_iter()
        .enumerate()
        .map(
            |(index, (product, action, from, to, release, restore))| Step {
                id: format!("{}:step:{index}", env_id(env)),
                order: index as u32,
                product,
                action,
                from,
                to,
                release_id: release.release_id,
                release_digest: release.digest,
                artifact_digest: release.artifact_digest,
                workdir: release.workdir,
                restore,
            },
        )
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
    for (order, step) in steps.iter_mut().enumerate() {
        step.order = order as u32;
    }
    let content_id = content_address(env, created_at, &inputs, steps)?;
    let id = plan_id(env, created_at, &content_id);
    for (order, step) in steps.iter_mut().enumerate() {
        step.id = format!("{id}:step:{order}");
    }
    let plan = Plan {
        format_version: PLAN_FORMAT_VERSION,
        id,
        content_id,
        environment: env.to_string(),
        created_at,
        inputs,
        steps: steps.to_vec(),
        state: PlanState::Computed,
        gates_skipped: None,
        status_detail: String::new(),
        maintenance_blocked: false,
    };
    store(ctx, &plan).await?;
    Ok(plan)
}

/// A rollback step to the previously deployed version of one product.
pub async fn rollback_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    validate_identifier("product", product)?;
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
    let target = pin_release(ctx, &release_id(product, &prev), env).await?;
    let restore = match current.as_deref() {
        Some(version) => Some(pin_release(ctx, &release_id(product, version), env).await?),
        None => None,
    };
    Ok(Step {
        id: format!("{}:rollback:{product}", env_id(env)),
        order: 0,
        release_id: target.release_id,
        release_digest: target.digest,
        artifact_digest: target.artifact_digest,
        workdir: target.workdir,
        restore,
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
    pub health: Option<String>,
    pub error: Option<String>,
    pub head: String,
}

/// Summary row for fleet listing (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentListEntry {
    pub name: String,
    pub id: String,
    pub description: String,
    pub subscription_count: usize,
    pub deployed_product_count: usize,
    pub lease_held: bool,
}

/// Initial capability/inventory fact keys admitted for environments.
pub const ENVIRONMENT_FACT_KEYS: &[&str] =
    &["architecture", "memory_gib", "accelerator", "free_disk_gib"];

const ENVIRONMENT_FACT_PREFIX: &str = "fact.";

/// Detailed inspect report for one environment (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentInspectReport {
    pub name: String,
    pub id: String,
    pub description: String,
    pub subscriptions: Vec<EnvironmentSubscriptionView>,
    pub facts: std::collections::BTreeMap<String, String>,
    pub lease: crate::apply::EnvironmentLeaseInspect,
    /// Most recent plan for this environment by `created_at`, if any.
    pub latest_plan: Option<EnvironmentPlanSummary>,
    /// Execution ownership note: Tenkai never prints runtime bearer tokens.
    pub execution_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSubscriptionView {
    pub product: String,
    pub channel: String,
    pub head: String,
    pub deployed: Option<String>,
    pub health: Option<String>,
    pub error: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPlanSummary {
    pub id: String,
    pub state: String,
    pub created_at: i64,
    pub step_count: usize,
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
            health: env_obj
                .properties
                .get(&format!("deployment_health.{product}"))
                .cloned(),
            error: env_obj
                .properties
                .get(&format!("deployment_error.{product}"))
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

/// List registered environments with compact delivery summaries.
pub async fn list_environments(ctx: &mut Ctx) -> Result<Vec<EnvironmentListEntry>> {
    let mut environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    let mut entries = Vec::with_capacity(environments.len());
    for env_obj in environments {
        let name = env_obj.name.clone();
        let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;
        let deployed_product_count = env_obj
            .properties
            .keys()
            .filter(|key| key.starts_with("deployed.") && !key.starts_with("deployed_"))
            .count();
        let lease = crate::apply::inspect_environment_lease(ctx, &name).await?;
        entries.push(EnvironmentListEntry {
            name,
            id: env_obj.id,
            description: env_obj
                .properties
                .get("description")
                .cloned()
                .unwrap_or_default(),
            subscription_count: channels.len(),
            deployed_product_count,
            lease_held: lease.held,
        });
    }
    Ok(entries)
}

/// Inspect one environment's subscriptions, lease/fence, and latest plan.
pub async fn inspect_environment(ctx: &mut Ctx, env: &str) -> Result<EnvironmentInspectReport> {
    let env_obj = environment(ctx, env).await?;
    let rows = status(ctx, env).await?;
    let subscriptions = rows
        .into_iter()
        .map(|row| {
            let state = match (&row.deployed, row.health.as_deref()) {
                (_, Some("unknown")) => "unknown",
                (Some(version), _) if *version == row.head => "current",
                (Some(_), _) => "behind",
                (None, _) => "missing",
            }
            .to_string();
            EnvironmentSubscriptionView {
                product: row.product,
                channel: row.channel,
                head: row.head,
                deployed: row.deployed,
                health: row.health,
                error: row.error,
                state,
            }
        })
        .collect();
    let facts = environment_facts_from_object(&env_obj);
    let lease = crate::apply::inspect_environment_lease(ctx, env).await?;
    let latest_plan = latest_plan_for_environment(ctx, env).await?;
    Ok(EnvironmentInspectReport {
        name: env_obj.name,
        id: env_obj.id,
        description: env_obj
            .properties
            .get("description")
            .cloned()
            .unwrap_or_default(),
        subscriptions,
        facts,
        lease,
        latest_plan,
        execution_note: "Apply leases and runtime credentials are distinct; inspect never prints bearer tokens. Server-side runtime-token environments are not executed by the embedded server executor."
            .into(),
    })
}

fn environment_facts_from_object(env_obj: &Object) -> std::collections::BTreeMap<String, String> {
    let mut facts = std::collections::BTreeMap::new();
    for (key, value) in &env_obj.properties {
        if let Some(name) = key.strip_prefix(ENVIRONMENT_FACT_PREFIX) {
            facts.insert(name.to_string(), value.clone());
        }
    }
    facts
}

fn validate_fact_key(key: &str) -> Result<()> {
    if !ENVIRONMENT_FACT_KEYS.contains(&key) {
        bail!(
            "unknown environment fact {key:?}; allowed: {}",
            ENVIRONMENT_FACT_KEYS.join(", ")
        );
    }
    Ok(())
}

fn validate_fact_value(key: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("environment fact {key} must not be empty");
    }
    if value
        .chars()
        .any(|c| c.is_control() || c == '\n' || c == '\r')
    {
        bail!("environment fact {key} must not contain control characters");
    }
    // Reject values that look like secrets/credentials.
    let lower = value.to_ascii_lowercase();
    for needle in ["bearer ", "password=", "secret=", "token="] {
        if lower.contains(needle) {
            bail!("environment fact {key} must not contain credential material");
        }
    }
    if matches!(key, "memory_gib" | "free_disk_gib") {
        let parsed: u64 = value
            .parse()
            .with_context(|| format!("environment fact {key} must be a non-negative integer"))?;
        if parsed == 0 {
            bail!("environment fact {key} must be greater than zero");
        }
    }
    Ok(())
}

/// Set a capability/inventory fact on an environment.
pub async fn set_environment_fact(
    ctx: &mut Ctx,
    env: &str,
    key: &str,
    value: &str,
) -> Result<String> {
    validate_fact_key(key)?;
    validate_fact_value(key, value)?;
    let mut env_obj = environment(ctx, env).await?;
    env_obj
        .properties
        .insert(format!("{ENVIRONMENT_FACT_PREFIX}{key}"), value.to_string());
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} fact {key}={value}"))
}

/// Clear one capability/inventory fact from an environment.
pub async fn clear_environment_fact(ctx: &mut Ctx, env: &str, key: &str) -> Result<String> {
    validate_fact_key(key)?;
    let mut env_obj = environment(ctx, env).await?;
    let property = format!("{ENVIRONMENT_FACT_PREFIX}{key}");
    if env_obj.properties.remove(&property).is_none() {
        bail!("environment {env} has no fact {key}");
    }
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("cleared {env} fact {key}"))
}

/// List capability/inventory facts for an environment.
pub async fn list_environment_facts(
    ctx: &mut Ctx,
    env: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let env_obj = environment(ctx, env).await?;
    Ok(environment_facts_from_object(&env_obj))
}

/// Require a named fact for planning; fail closed when missing.
pub async fn require_environment_fact(ctx: &mut Ctx, env: &str, key: &str) -> Result<String> {
    validate_fact_key(key)?;
    let facts = list_environment_facts(ctx, env).await?;
    facts.get(key).cloned().with_context(|| {
        format!("environment {env} is missing required fact {key}; set it with `tenkaictl env facts set {env} {key}=…`")
    })
}

async fn latest_plan_for_environment(
    ctx: &mut Ctx,
    env: &str,
) -> Result<Option<EnvironmentPlanSummary>> {
    let plans = ctx.list_kind(KIND_PLAN).await?;
    let mut best: Option<EnvironmentPlanSummary> = None;
    for object in plans {
        let Ok(plan) = Plan::from_object(&object) else {
            continue;
        };
        if plan.environment != env {
            continue;
        }
        let summary = EnvironmentPlanSummary {
            id: plan.id,
            state: plan.state.to_string(),
            created_at: plan.created_at,
            step_count: plan.steps.len(),
        };
        match &best {
            Some(current) if current.created_at >= summary.created_at => {}
            _ => best = Some(summary),
        }
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_plan() -> Plan {
        let mut plan = Plan {
            format_version: PLAN_FORMAT_VERSION,
            id: String::new(),
            content_id: String::new(),
            environment: "prod".into(),
            created_at: 123,
            inputs: vec![DesiredStateInput {
                product: "api".into(),
                channel: "stable".into(),
                channel_id: "tenkai:channel:api/stable".into(),
                desired_version: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "target-digest".into(),
                artifact_digest: "target-artifact-digest".into(),
                deployed_version: Some("1.0.0".into()),
            }],
            steps: vec![Step {
                id: String::new(),
                order: 0,
                product: "api".into(),
                action: Action::Upgrade,
                from: Some("1.0.0".into()),
                to: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "target-digest".into(),
                artifact_digest: "target-artifact-digest".into(),
                workdir: "/srv/api".into(),
                restore: Some(ReleasePin {
                    release_id: "tenkai:release:api@1.0.0".into(),
                    digest: "restore-digest".into(),
                    artifact_digest: "restore-artifact-digest".into(),
                    workdir: "/srv/api".into(),
                }),
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
        };
        plan.content_id = content_address(
            &plan.environment,
            plan.created_at,
            &plan.inputs,
            &plan.steps,
        )
        .unwrap();
        plan.id = plan_id(&plan.environment, plan.created_at, &plan.content_id);
        plan.steps[0].id = format!("{}:step:0", plan.id);
        plan
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
        let mut blocked = plan.clone();
        blocked.state = PlanState::Blocked;
        blocked.maintenance_blocked = true;
        assert_eq!(
            plan.executable_digest().unwrap(),
            blocked.executable_digest().unwrap()
        );
        assert!(
            Plan::from_object(&blocked.to_object().unwrap())
                .unwrap()
                .maintenance_blocked
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
        assert!(error.contains("content-addressed id"));
    }

    #[test]
    fn semantic_version_direction_is_recorded() {
        assert_eq!(classify_change("2.0.0", "1.9.0"), Action::Downgrade);
        assert_eq!(classify_change("1.9.0", "2.0.0"), Action::Upgrade);
    }

    #[test]
    fn version_range_is_half_open() {
        assert!(version_in_range("1.0.0", "1.0.0..2.0.0").unwrap());
        assert!(version_in_range("1.9.9", "1.0.0..2.0.0").unwrap());
        assert!(!version_in_range("2.0.0", "1.0.0..2.0.0").unwrap());
        assert!(!version_in_range("0.9.0", "1.0.0..2.0.0").unwrap());
        assert!(version_in_range("bad", "1.0.0..2.0.0").is_err());
        assert!(version_in_range("1.0.0", "2.0.0..1.0.0").is_err());
    }

    #[test]
    fn environment_record_initializes_without_deployment_state() {
        let record = environment_record(None, "prod", "production", 20).unwrap();
        assert_eq!(record.properties.get("description").unwrap(), "production");
        assert_eq!(record.created, 20);
        assert_eq!(record.updated, 20);
    }

    #[tokio::test]
    async fn list_and_inspect_cover_multiple_environments() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-env-list-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        assert!(list_environments(&mut ctx).await.unwrap().is_empty());

        env_add(&mut ctx, "alpha", "first").await.unwrap();
        env_add(&mut ctx, "beta", "second").await.unwrap();
        let listed = list_environments(&mut ctx).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].name, "alpha");
        assert_eq!(listed[1].name, "beta");
        assert!(!listed[0].lease_held);
        assert_eq!(listed[0].subscription_count, 0);
        assert_eq!(listed[0].deployed_product_count, 0);

        let missing = inspect_environment(&mut ctx, "missing").await;
        assert!(missing.is_err());
        assert!(missing.unwrap_err().to_string().contains("not registered"));

        let report = inspect_environment(&mut ctx, "alpha").await.unwrap();
        assert_eq!(report.name, "alpha");
        assert!(report.subscriptions.is_empty());
        assert!(!report.lease.held);
        // No active apply: either no lease row ("absent") or a non-active row
        // (e.g. "released") — never held.
        assert!(
            report.lease.status == "absent" || report.lease.status == "released",
            "unexpected lease status {}",
            report.lease.status
        );
        assert!(report.latest_plan.is_none());
        assert!(!report.execution_note.contains("Bearer"));
        assert!(!report.execution_note.to_lowercase().contains("token="));
        // Runtime-token vs embedded executor split is documented, not a secret surface.
        assert!(report.execution_note.contains("runtime-token"));

        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("Bearer "));
        assert!(!encoded.contains("management-secret"));

        set_environment_fact(&mut ctx, "alpha", "architecture", "arm64")
            .await
            .unwrap();
        set_environment_fact(&mut ctx, "alpha", "memory_gib", "32")
            .await
            .unwrap();
        assert!(
            set_environment_fact(&mut ctx, "alpha", "memory_gib", "0")
                .await
                .is_err()
        );
        assert!(
            set_environment_fact(&mut ctx, "alpha", "token", "x")
                .await
                .is_err()
        );
        assert!(
            set_environment_fact(&mut ctx, "alpha", "architecture", "token=abc")
                .await
                .is_err()
        );
        let facts = list_environment_facts(&mut ctx, "alpha").await.unwrap();
        assert_eq!(facts.get("architecture").map(String::as_str), Some("arm64"));
        assert_eq!(
            require_environment_fact(&mut ctx, "alpha", "architecture")
                .await
                .unwrap(),
            "arm64"
        );
        assert!(
            require_environment_fact(&mut ctx, "alpha", "accelerator")
                .await
                .unwrap_err()
                .to_string()
                .contains("missing required fact")
        );
        clear_environment_fact(&mut ctx, "alpha", "architecture")
            .await
            .unwrap();
        assert!(
            !list_environment_facts(&mut ctx, "alpha")
                .await
                .unwrap()
                .contains_key("architecture")
        );

        let _ = std::fs::remove_file(&database);
    }
}
