//! Environments, subscriptions, and plan computation (desired vs deployed).

use std::collections::{BTreeMap, HashMap};

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
    /// Advisory prior warnings (optional planner intelligence). Never hard-blocks.
    #[serde(default)]
    pub prior_warnings: Vec<String>,
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

/// Resolve channel head against environment version pin/range constraints and,
/// for `model_runtime` products, hardware-class requirements vs environment facts.
///
/// - `constraint.version_pin.<product>` forces that exact published version
///   (overrides channel head when different). The pin must still satisfy
///   model_runtime requirements when the product is a model runtime.
/// - `constraint.version_range.<product>` is `min..max` (semver, min inclusive,
///   max exclusive). Selected version must lie in the range.
/// - Related `model_runtime` variants are **all published releases of the same
///   product name**. Among candidates in range (or only the pin), plan selects
///   the highest semver whose `[requirements]` fit environment facts, and fails
///   closed when none fit.
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
    let pin = env_obj.properties.get(&pin_key).cloned();
    let range = env_obj.properties.get(&range_key).cloned();

    if let Some(pin) = pin.as_ref() {
        if pin.trim().is_empty() {
            bail!("constraint version pin for {product} must not be empty");
        }
        let pinned_release = release_id(product, pin);
        if ctx.get(&pinned_release).await?.is_none() {
            bail!(
                "version pin {pin} for {product} in {env} is not published (constraint {pin_key})"
            );
        }
        if let Some(range) = range.as_ref()
            && !version_in_range(pin, range)?
        {
            bail!(
                "version pin {pin} for {product} in {env} violates version range constraint {range:?} ({range_key})"
            );
        }
        // Pin forces one release; still fail closed if model requirements miss.
        ensure_model_runtime_fits(ctx, env, product, pin, &pinned_release).await?;
        if pin != channel_version {
            return Ok((pin.clone(), pinned_release));
        }
        return Ok((channel_version.into(), channel_release.into()));
    }

    if let Some(range) = range.as_ref()
        && !version_in_range(channel_version, range)?
    {
        // Channel head out of range: still try hardware selection among in-range
        // model_runtime siblings; for non-model products fail as before.
        if !release_is_model_runtime(ctx, channel_release).await? {
            bail!(
                "channel head {channel_version} for {product} in {env} violates version range constraint {range:?} ({range_key})"
            );
        }
    }

    if release_is_model_runtime(ctx, channel_release).await?
        || product_has_model_runtime_release(ctx, product).await?
    {
        return select_model_runtime_variant(
            ctx,
            env,
            product,
            channel_version,
            channel_release,
            range.as_deref(),
        )
        .await;
    }

    if let Some(range) = range.as_ref()
        && !version_in_range(channel_version, range)?
    {
        bail!(
            "channel head {channel_version} for {product} in {env} violates version range constraint {range:?} ({range_key})"
        );
    }
    Ok((channel_version.into(), channel_release.into()))
}

async fn release_is_model_runtime(ctx: &mut Ctx, release: &str) -> Result<bool> {
    let Some(object) = ctx.get(release).await? else {
        return Ok(false);
    };
    let Some(raw) = object.properties.get("manifest") else {
        return Ok(false);
    };
    let manifest = crate::manifest::parse_raw(raw)
        .with_context(|| format!("parsing stored manifest of {release}"))?;
    Ok(manifest.product.kind == crate::manifest::ProductKind::ModelRuntime)
}

async fn product_has_model_runtime_release(ctx: &mut Ctx, product: &str) -> Result<bool> {
    let pid = product_id(product);
    let releases = ctx.linked(&pid, REL_RELEASE_OF, "in").await?;
    for release in releases {
        if release_is_model_runtime(ctx, &release.id).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Match model_runtime `[requirements]` against environment capability facts.
///
/// - `architecture` fact must be one of `requirements.architecture`
/// - `memory_gib` fact must be an integer ≥ `requirements.memory_gib`
/// - when `requirements.accelerator` is non-empty, `accelerator` fact must be
///   one of those values
pub fn model_requirements_fit(
    env: &str,
    product: &str,
    version: &str,
    facts: &std::collections::BTreeMap<String, String>,
    requirements: &crate::manifest::ModelRequirementsSection,
) -> Result<()> {
    let architecture = facts.get("architecture").ok_or_else(|| {
        anyhow::anyhow!(
            "model_runtime {product}@{version} requires environment fact architecture for {env}; set it with `tenkaictl env facts set {env} architecture=…`"
        )
    })?;
    if !requirements
        .architecture
        .iter()
        .any(|allowed| allowed == architecture)
    {
        bail!(
            "model_runtime {product}@{version} requirements.architecture {:?} does not include environment {env} fact architecture={architecture}",
            requirements.architecture
        );
    }

    let memory_raw = facts.get("memory_gib").ok_or_else(|| {
        anyhow::anyhow!(
            "model_runtime {product}@{version} requires environment fact memory_gib for {env}; set it with `tenkaictl env facts set {env} memory_gib=…`"
        )
    })?;
    let memory: u32 = memory_raw.parse().with_context(|| {
        format!("environment {env} fact memory_gib={memory_raw:?} is not a non-negative integer")
    })?;
    if memory < requirements.memory_gib {
        bail!(
            "model_runtime {product}@{version} requires memory_gib>={} but environment {env} fact memory_gib={memory}",
            requirements.memory_gib
        );
    }

    if !requirements.accelerator.is_empty() {
        let accelerator = facts.get("accelerator").ok_or_else(|| {
            anyhow::anyhow!(
                "model_runtime {product}@{version} requires environment fact accelerator for {env}; set it with `tenkaictl env facts set {env} accelerator=…`"
            )
        })?;
        if !requirements
            .accelerator
            .iter()
            .any(|allowed| allowed == accelerator)
        {
            bail!(
                "model_runtime {product}@{version} requirements.accelerator {:?} does not include environment {env} fact accelerator={accelerator}",
                requirements.accelerator
            );
        }
    }
    Ok(())
}

async fn ensure_model_runtime_fits(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    version: &str,
    release: &str,
) -> Result<()> {
    let Some(object) = ctx.get(release).await? else {
        bail!("release {release} is not published");
    };
    let Some(raw) = object.properties.get("manifest") else {
        return Ok(());
    };
    let manifest = crate::manifest::parse_raw(raw)
        .with_context(|| format!("parsing stored manifest of {release}"))?;
    if manifest.product.kind != crate::manifest::ProductKind::ModelRuntime {
        return Ok(());
    }
    let requirements = manifest.requirements.as_ref().ok_or_else(|| {
        anyhow::anyhow!("model_runtime {product}@{version} has no [requirements] section")
    })?;
    let facts = list_environment_facts(ctx, env).await?;
    model_requirements_fit(env, product, version, &facts, requirements)
}

async fn select_model_runtime_variant(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    channel_version: &str,
    channel_release: &str,
    range: Option<&str>,
) -> Result<(String, String)> {
    let facts = list_environment_facts(ctx, env).await?;
    let pid = product_id(product);
    let linked = ctx.linked(&pid, REL_RELEASE_OF, "in").await?;
    let channel_semver = semver::Version::parse(channel_version).ok();
    let mut candidates = Vec::new();
    for release in linked {
        let Some(version) = release.properties.get("version").cloned() else {
            continue;
        };
        if let Some(range) = range
            && !version_in_range(&version, range)?
        {
            continue;
        }
        // Channel head is the rollout ceiling: only published siblings at or
        // below the promoted head are eligible fallback variants.
        if let (Some(head), Ok(candidate)) = (&channel_semver, semver::Version::parse(&version))
            && candidate > *head
        {
            continue;
        }
        let Some(raw) = release.properties.get("manifest") else {
            continue;
        };
        let manifest = crate::manifest::parse_raw(raw)
            .with_context(|| format!("parsing stored manifest of {}", release.id))?;
        if manifest.product.kind != crate::manifest::ProductKind::ModelRuntime {
            continue;
        }
        let Some(requirements) = manifest.requirements.as_ref() else {
            continue;
        };
        if model_requirements_fit(env, product, &version, &facts, requirements).is_ok() {
            candidates.push((version, release.id));
        }
    }

    if candidates.is_empty() {
        // Prefer a precise error from the channel head when it is a model_runtime.
        if let Err(head_error) =
            ensure_model_runtime_fits(ctx, env, product, channel_version, channel_release).await
        {
            bail!(
                "no model_runtime variant of {product} fits environment {env} facts (architecture/memory_gib/accelerator); channel head rejected: {head_error}"
            );
        }
        bail!(
            "no model_runtime variant of {product} fits environment {env} facts (architecture/memory_gib/accelerator); publish a feasible variant or relax constraints"
        );
    }

    // Deterministic: highest semver wins; fall back to version string order.
    candidates.sort_by(|(a, _), (b, _)| {
        match (semver::Version::parse(a), semver::Version::parse(b)) {
            (Ok(av), Ok(bv)) => av.cmp(&bv),
            _ => a.cmp(b),
        }
    });
    let (version, release) = candidates
        .pop()
        .expect("candidates non-empty after empty check");
    Ok((version, release))
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
        let kind = release_product_kind(ctx, &release).await?;
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
                pending.push((
                    product,
                    action,
                    Some(v),
                    desired,
                    target,
                    Some(restore),
                    kind,
                ));
            }
            None => pending.push((product, Action::Install, None, desired, target, None, kind)),
        }
    }
    inputs.sort_by(|a, b| a.product.cmp(&b.product));
    // Enforce model_runtime ↔ routing_config rollout order (see docs).
    pending.sort_by(|a, b| {
        model_routing_rollout_rank(a.6, a.1)
            .cmp(&model_routing_rollout_rank(b.6, b.1))
            .then_with(|| a.0.cmp(&b.0))
    });
    validate_model_routing_rollout_order(
        &pending
            .iter()
            .map(|entry| (entry.6, entry.1))
            .collect::<Vec<_>>(),
    )?;
    let steps = pending
        .into_iter()
        .enumerate()
        .map(
            |(index, (product, action, from, to, release, restore, _kind))| Step {
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

async fn release_product_kind(
    ctx: &mut Ctx,
    release: &str,
) -> Result<crate::manifest::ProductKind> {
    let object = ctx
        .get(release)
        .await?
        .with_context(|| format!("release {release} not found for product kind lookup"))?;
    let raw = object
        .properties
        .get("manifest")
        .with_context(|| format!("release {release} has no stored manifest"))?;
    let manifest = crate::manifest::parse_raw(raw)
        .with_context(|| format!("parsing stored manifest of {release}"))?;
    Ok(manifest.product.kind)
}

/// Deterministic step ranking for coordinated model_runtime + routing_config
/// rollouts without merging the product kinds.
///
/// Forward (install/upgrade): model_runtime first, then routing_config.
/// Reverse (downgrade/rollback): routing_config first (drain traffic), then
/// model_runtime (retire generation). Other products keep a neutral rank and
/// sort by product name among themselves.
pub fn model_routing_rollout_rank(kind: crate::manifest::ProductKind, action: Action) -> u8 {
    use crate::manifest::ProductKind;
    match (kind, action) {
        (ProductKind::ModelRuntime, Action::Install | Action::Upgrade) => 0,
        (ProductKind::RoutingConfig, Action::Install | Action::Upgrade) => 1,
        (ProductKind::RoutingConfig, Action::Downgrade | Action::Rollback) => 0,
        (ProductKind::ModelRuntime, Action::Downgrade | Action::Rollback) => 1,
        _ => 2,
    }
}

/// Reject unsafe model/routing step order (routing switch before model ready,
/// or model retire while routes still target it).
pub fn validate_model_routing_rollout_order(
    steps: &[(crate::manifest::ProductKind, Action)],
) -> Result<()> {
    use crate::manifest::ProductKind;
    let mut last_forward_model = None;
    let mut last_forward_routing = None;
    let mut last_reverse_routing = None;
    let mut last_reverse_model = None;
    for (index, (kind, action)) in steps.iter().enumerate() {
        match (kind, action) {
            (ProductKind::ModelRuntime, Action::Install | Action::Upgrade) => {
                last_forward_model = Some(index);
            }
            (ProductKind::RoutingConfig, Action::Install | Action::Upgrade) => {
                last_forward_routing = Some(index);
            }
            (ProductKind::RoutingConfig, Action::Downgrade | Action::Rollback) => {
                last_reverse_routing = Some(index);
            }
            (ProductKind::ModelRuntime, Action::Downgrade | Action::Rollback) => {
                last_reverse_model = Some(index);
            }
            _ => {}
        }
    }
    if let (Some(model_i), Some(routing_i)) = (last_forward_model, last_forward_routing)
        && model_i > routing_i
    {
        bail!(
            "unsafe rollout order: routing_config step at {routing_i} precedes model_runtime step at {model_i}; install/verify model before switching routes"
        );
    }
    if let (Some(routing_i), Some(model_i)) = (last_reverse_routing, last_reverse_model)
        && routing_i > model_i
    {
        bail!(
            "unsafe rollback order: model_runtime step at {model_i} precedes routing_config step at {routing_i}; switch routes away before retiring the model"
        );
    }
    Ok(())
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
        prior_warnings: Vec::new(),
    };
    // Optional advisory priors (default off). Never hard-block or change steps.
    let mut plan = plan;
    if let Ok(inspect) = inspect_environment(ctx, env).await {
        let _ = crate::plan_priors::annotate_plan_with_priors(
            &mut plan,
            &inspect,
            &crate::plan_priors::PriorConfig::from_env(),
        );
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// One environment row in a fleet-wide delivery status report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetEnvironmentRow {
    pub name: String,
    pub id: String,
    pub description: String,
    pub subscription_count: usize,
    /// Subscribed products whose deployed version matches channel head.
    pub products_current: usize,
    /// Subscribed products with a deployment that is not the channel head.
    pub products_behind: usize,
    /// Subscribed products with no deployed version.
    pub products_missing: usize,
    /// True when any subscription has health `unknown` or a non-empty error.
    pub unhealthy: bool,
    /// `ok` | `unknown` | `error` | `n/a` (no subscriptions).
    pub health_summary: String,
    pub lease_held: bool,
    /// Latest plan state when a plan exists.
    pub latest_plan_state: Option<String>,
    /// Aggregate posture: `empty` | `unhealthy` | `behind` | `current`.
    pub posture: String,
}

/// Fleet-wide delivery posture (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStatusReport {
    pub environments: Vec<FleetEnvironmentRow>,
    pub environment_count: usize,
    pub environments_current: usize,
    pub environments_behind: usize,
    pub environments_unhealthy: usize,
    pub environments_empty: usize,
}

/// Summarize delivery posture for every registered environment.
///
/// Complements `list_environments` / `inspect_environment` and server reconcile
/// diagnostics: this is the operator fleet table (drift, health, lease, plan).
pub async fn fleet_status(ctx: &mut Ctx) -> Result<FleetStatusReport> {
    let listed = list_environments(ctx).await?;
    let mut environments = Vec::with_capacity(listed.len());
    for entry in listed {
        let report = inspect_environment(ctx, &entry.name).await?;
        environments.push(fleet_row_from_inspect(&report));
    }
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(aggregate_fleet_report(environments))
}

/// Build a fleet report from inspect reports (used by tests and filtered hosts).
pub fn fleet_status_from_inspects(reports: Vec<EnvironmentInspectReport>) -> FleetStatusReport {
    let mut environments: Vec<_> = reports.iter().map(fleet_row_from_inspect).collect();
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    aggregate_fleet_report(environments)
}

fn fleet_row_from_inspect(report: &EnvironmentInspectReport) -> FleetEnvironmentRow {
    let mut products_current = 0usize;
    let mut products_behind = 0usize;
    let mut products_missing = 0usize;
    let mut saw_unknown = false;
    let mut saw_error = false;
    for sub in &report.subscriptions {
        match sub.state.as_str() {
            "current" => products_current += 1,
            "behind" => products_behind += 1,
            "missing" => products_missing += 1,
            "unknown" => {
                // Health unknown: still count version drift when known.
                if sub.deployed.as_ref() == Some(&sub.head) {
                    products_current += 1;
                } else if sub.deployed.is_some() {
                    products_behind += 1;
                } else {
                    products_missing += 1;
                }
            }
            _ => {
                if sub.deployed.as_ref() == Some(&sub.head) {
                    products_current += 1;
                } else if sub.deployed.is_some() {
                    products_behind += 1;
                } else {
                    products_missing += 1;
                }
            }
        }
        if sub.health.as_deref() == Some("unknown") {
            saw_unknown = true;
        }
        if sub.error.as_ref().is_some_and(|error| !error.is_empty()) {
            saw_error = true;
        }
    }
    let unhealthy = saw_unknown || saw_error;
    let health_summary = if report.subscriptions.is_empty() {
        "n/a".into()
    } else if saw_error {
        "error".into()
    } else if saw_unknown {
        "unknown".into()
    } else {
        "ok".into()
    };
    let posture = if report.subscriptions.is_empty() {
        "empty"
    } else if unhealthy {
        "unhealthy"
    } else if products_behind > 0 || products_missing > 0 {
        "behind"
    } else {
        "current"
    }
    .to_string();
    FleetEnvironmentRow {
        name: report.name.clone(),
        id: report.id.clone(),
        description: report.description.clone(),
        subscription_count: report.subscriptions.len(),
        products_current,
        products_behind,
        products_missing,
        unhealthy,
        health_summary,
        lease_held: report.lease.held,
        latest_plan_state: report.latest_plan.as_ref().map(|plan| plan.state.clone()),
        posture,
    }
}

/// Recompute fleet aggregates after filtering rows (e.g. tenant scope).
pub fn fleet_status_from_rows(environments: Vec<FleetEnvironmentRow>) -> FleetStatusReport {
    aggregate_fleet_report(environments)
}

/// Compact posture snapshot for baseline files and drift watch (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetPostureSnapshot {
    /// Schema marker for optional JSON baseline files.
    #[serde(default = "fleet_posture_snapshot_schema")]
    pub schema: String,
    /// Environment name → posture (`empty` | `unhealthy` | `behind` | `current`).
    pub postures: BTreeMap<String, String>,
}

impl Default for FleetPostureSnapshot {
    fn default() -> Self {
        Self {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::new(),
        }
    }
}

fn fleet_posture_snapshot_schema() -> String {
    "tenkai.fleet-posture.v1".into()
}

/// Deterministic delta between two posture samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetDriftSummary {
    pub previous: FleetPostureSnapshot,
    pub current: FleetPostureSnapshot,
    pub entered_behind: Vec<String>,
    pub left_behind: Vec<String>,
    pub entered_unhealthy: Vec<String>,
    pub left_unhealthy: Vec<String>,
    pub entered_empty: Vec<String>,
    pub left_empty: Vec<String>,
    pub entered_current: Vec<String>,
    pub left_current: Vec<String>,
    pub appeared: Vec<String>,
    pub disappeared: Vec<String>,
    /// Environments that newly entered `behind` or `unhealthy` vs the baseline.
    pub new_hard_drift: Vec<String>,
    pub has_new_hard_drift: bool,
    pub has_any_posture_change: bool,
    /// True when any current environment is `behind` or `unhealthy`.
    pub has_any_hard_drift: bool,
}

/// Build a baseline-friendly posture snapshot from a fleet status report.
pub fn fleet_posture_snapshot(report: &FleetStatusReport) -> FleetPostureSnapshot {
    let mut postures = BTreeMap::new();
    for row in &report.environments {
        postures.insert(row.name.clone(), row.posture.clone());
    }
    FleetPostureSnapshot {
        schema: fleet_posture_snapshot_schema(),
        postures,
    }
}

/// True for postures that count as hard delivery drift for watch exit codes.
pub fn is_hard_drift_posture(posture: &str) -> bool {
    matches!(posture, "behind" | "unhealthy")
}

/// Compare two posture samples and list environments that entered/left each class.
pub fn compare_fleet_posture(
    previous: &FleetPostureSnapshot,
    current: &FleetPostureSnapshot,
) -> FleetDriftSummary {
    let mut all_names = previous
        .postures
        .keys()
        .chain(current.postures.keys())
        .cloned()
        .collect::<Vec<_>>();
    all_names.sort();
    all_names.dedup();

    let mut entered_behind = Vec::new();
    let mut left_behind = Vec::new();
    let mut entered_unhealthy = Vec::new();
    let mut left_unhealthy = Vec::new();
    let mut entered_empty = Vec::new();
    let mut left_empty = Vec::new();
    let mut entered_current = Vec::new();
    let mut left_current = Vec::new();
    let mut appeared = Vec::new();
    let mut disappeared = Vec::new();
    let mut new_hard_drift = Vec::new();
    let mut has_any_posture_change = false;
    let mut has_any_hard_drift = false;

    for name in all_names {
        let prev = previous.postures.get(&name).map(String::as_str);
        let curr = current.postures.get(&name).map(String::as_str);
        match (prev, curr) {
            (None, Some(c)) => {
                appeared.push(name.clone());
                has_any_posture_change = true;
                track_enter(
                    c,
                    &name,
                    &mut entered_behind,
                    &mut entered_unhealthy,
                    &mut entered_empty,
                    &mut entered_current,
                );
                if is_hard_drift_posture(c) {
                    new_hard_drift.push(name.clone());
                }
            }
            (Some(p), None) => {
                disappeared.push(name.clone());
                has_any_posture_change = true;
                track_leave(
                    p,
                    &name,
                    &mut left_behind,
                    &mut left_unhealthy,
                    &mut left_empty,
                    &mut left_current,
                );
            }
            (Some(p), Some(c)) if p != c => {
                has_any_posture_change = true;
                track_leave(
                    p,
                    &name,
                    &mut left_behind,
                    &mut left_unhealthy,
                    &mut left_empty,
                    &mut left_current,
                );
                track_enter(
                    c,
                    &name,
                    &mut entered_behind,
                    &mut entered_unhealthy,
                    &mut entered_empty,
                    &mut entered_current,
                );
                if is_hard_drift_posture(c) && !is_hard_drift_posture(p) {
                    new_hard_drift.push(name.clone());
                } else if is_hard_drift_posture(c) && p != c {
                    // behind ↔ unhealthy still counts as new hard drift for alerts
                    new_hard_drift.push(name.clone());
                }
            }
            (Some(_), Some(c)) => {
                // unchanged
                if is_hard_drift_posture(c) {
                    // existing hard drift is not "new"
                }
            }
            (None, None) => {}
        }
        if let Some(c) = curr
            && is_hard_drift_posture(c)
        {
            has_any_hard_drift = true;
        }
    }

    let has_new_hard_drift = !new_hard_drift.is_empty();
    FleetDriftSummary {
        previous: previous.clone(),
        current: current.clone(),
        entered_behind,
        left_behind,
        entered_unhealthy,
        left_unhealthy,
        entered_empty,
        left_empty,
        entered_current,
        left_current,
        appeared,
        disappeared,
        new_hard_drift,
        has_new_hard_drift,
        has_any_posture_change,
        has_any_hard_drift,
    }
}

fn track_enter(
    posture: &str,
    name: &str,
    behind: &mut Vec<String>,
    unhealthy: &mut Vec<String>,
    empty: &mut Vec<String>,
    current: &mut Vec<String>,
) {
    match posture {
        "behind" => behind.push(name.to_string()),
        "unhealthy" => unhealthy.push(name.to_string()),
        "empty" => empty.push(name.to_string()),
        "current" => current.push(name.to_string()),
        _ => {}
    }
}

fn track_leave(
    posture: &str,
    name: &str,
    behind: &mut Vec<String>,
    unhealthy: &mut Vec<String>,
    empty: &mut Vec<String>,
    current: &mut Vec<String>,
) {
    match posture {
        "behind" => behind.push(name.to_string()),
        "unhealthy" => unhealthy.push(name.to_string()),
        "empty" => empty.push(name.to_string()),
        "current" => current.push(name.to_string()),
        _ => {}
    }
}

/// Load a posture baseline from a JSON file (missing file → empty snapshot).
pub fn load_fleet_posture_baseline(path: &std::path::Path) -> Result<FleetPostureSnapshot> {
    if !path.exists() {
        return Ok(FleetPostureSnapshot::default());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read fleet posture baseline {}", path.display()))?;
    let snapshot: FleetPostureSnapshot = serde_json::from_str(&raw)
        .with_context(|| format!("parse fleet posture baseline {}", path.display()))?;
    Ok(snapshot)
}

/// Persist a posture baseline as JSON (no secrets; names and postures only).
pub fn write_fleet_posture_baseline(
    path: &std::path::Path,
    snapshot: &FleetPostureSnapshot,
) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create baseline directory {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(snapshot).context("encode fleet posture baseline")?;
    std::fs::write(path, format!("{raw}\n"))
        .with_context(|| format!("write fleet posture baseline {}", path.display()))?;
    Ok(())
}

fn aggregate_fleet_report(environments: Vec<FleetEnvironmentRow>) -> FleetStatusReport {
    let environment_count = environments.len();
    let environments_current = environments
        .iter()
        .filter(|row| row.posture == "current")
        .count();
    let environments_behind = environments
        .iter()
        .filter(|row| row.posture == "behind")
        .count();
    let environments_unhealthy = environments
        .iter()
        .filter(|row| row.posture == "unhealthy")
        .count();
    let environments_empty = environments
        .iter()
        .filter(|row| row.posture == "empty")
        .count();
    FleetStatusReport {
        environments,
        environment_count,
        environments_current,
        environments_behind,
        environments_unhealthy,
        environments_empty,
    }
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

/// Apply admitted inventory facts from a runtime heartbeat report (#136).
///
/// Only [`ENVIRONMENT_FACT_KEYS`] are accepted (via [`set_environment_fact`]).
/// Unknown keys and credential-like values fail closed before any write.
pub async fn apply_runtime_inventory_facts(
    ctx: &mut Ctx,
    env: &str,
    facts: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<String>> {
    // Validate all first so a bad key never partially mutates.
    for (key, value) in facts {
        validate_fact_key(key)?;
        validate_fact_value(key, value)?;
    }
    let mut applied = Vec::with_capacity(facts.len());
    for (key, value) in facts {
        set_environment_fact(ctx, env, key, value).await?;
        applied.push(key.clone());
    }
    applied.sort();
    Ok(applied)
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
            prior_warnings: Vec::new(),
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

    #[test]
    fn fleet_status_classifies_current_behind_unhealthy_and_empty() {
        let current = EnvironmentInspectReport {
            name: "alpha".into(),
            id: "tenkai:env:alpha".into(),
            description: "ok".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),
                channel: "stable".into(),
                head: "1.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("healthy".into()),
                error: None,
                state: "current".into(),
            }],
            facts: Default::default(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: Some(EnvironmentPlanSummary {
                id: "plan-a".into(),
                state: "succeeded".into(),
                created_at: 1,
                step_count: 1,
            }),
            execution_note: "fixture".into(),
        };
        let behind = EnvironmentInspectReport {
            name: "beta".into(),
            id: "tenkai:env:beta".into(),
            description: "drift".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),
                channel: "stable".into(),
                head: "2.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("healthy".into()),
                error: None,
                state: "behind".into(),
            }],
            facts: Default::default(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: true,
                owner: Some("owner".into()),
                generation: Some(1),
                expires_at_ms: Some(99),
                status: "active".into(),
            },
            latest_plan: None,
            execution_note: "fixture".into(),
        };
        let unhealthy = EnvironmentInspectReport {
            name: "gamma".into(),
            id: "tenkai:env:gamma".into(),
            description: "bad".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),
                channel: "stable".into(),
                head: "1.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("unknown".into()),
                error: Some("probe failed".into()),
                state: "unknown".into(),
            }],
            facts: Default::default(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            execution_note: "fixture".into(),
        };
        let empty = EnvironmentInspectReport {
            name: "delta".into(),
            id: "tenkai:env:delta".into(),
            description: "idle".into(),
            subscriptions: Vec::new(),
            facts: Default::default(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            execution_note: "fixture".into(),
        };
        let report = fleet_status_from_inspects(vec![behind, empty, unhealthy, current]);
        assert_eq!(report.environment_count, 4);
        assert_eq!(report.environments_current, 1);
        assert_eq!(report.environments_behind, 1);
        assert_eq!(report.environments_unhealthy, 1);
        assert_eq!(report.environments_empty, 1);
        let by_name = |name: &str| {
            report
                .environments
                .iter()
                .find(|row| row.name == name)
                .unwrap()
        };
        assert_eq!(by_name("alpha").posture, "current");
        assert_eq!(by_name("beta").posture, "behind");
        assert!(by_name("beta").lease_held);
        assert_eq!(by_name("gamma").posture, "unhealthy");
        assert_eq!(by_name("gamma").health_summary, "error");
        assert_eq!(by_name("delta").posture, "empty");
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("Bearer"));
        assert!(!encoded.contains("token="));
    }

    #[test]
    fn fleet_drift_reports_new_behind_and_unhealthy_transitions() {
        let previous = FleetPostureSnapshot {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::from([
                ("alpha".into(), "current".into()),
                ("beta".into(), "current".into()),
                ("gamma".into(), "current".into()),
            ]),
        };
        let current = FleetPostureSnapshot {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::from([
                ("alpha".into(), "current".into()),
                ("beta".into(), "behind".into()),
                ("gamma".into(), "unhealthy".into()),
            ]),
        };
        let delta = compare_fleet_posture(&previous, &current);
        assert_eq!(delta.entered_behind, vec!["beta".to_string()]);
        assert_eq!(delta.entered_unhealthy, vec!["gamma".to_string()]);
        assert_eq!(
            delta.new_hard_drift,
            vec!["beta".to_string(), "gamma".to_string()]
        );
        assert!(delta.has_new_hard_drift);
        assert!(delta.has_any_hard_drift);
        assert!(delta.has_any_posture_change);
        assert!(delta.left_current.contains(&"beta".to_string()));
        assert!(delta.left_current.contains(&"gamma".to_string()));
        assert!(delta.entered_empty.is_empty());
        assert!(delta.appeared.is_empty());
        assert!(delta.disappeared.is_empty());

        let stable = compare_fleet_posture(&current, &current);
        assert!(!stable.has_new_hard_drift);
        assert!(stable.has_any_hard_drift);
        assert!(!stable.has_any_posture_change);
        assert!(stable.new_hard_drift.is_empty());

        let recovered = FleetPostureSnapshot {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::from([
                ("alpha".into(), "current".into()),
                ("beta".into(), "current".into()),
                ("gamma".into(), "current".into()),
            ]),
        };
        let back = compare_fleet_posture(&current, &recovered);
        assert!(!back.has_new_hard_drift);
        assert!(!back.has_any_hard_drift);
        assert_eq!(back.left_behind, vec!["beta".to_string()]);
        assert_eq!(back.left_unhealthy, vec!["gamma".to_string()]);
        assert_eq!(back.entered_current.len(), 2);

        let from_status = fleet_posture_snapshot(&fleet_status_from_inspects(vec![]));
        assert!(from_status.postures.is_empty());
        assert_eq!(from_status.schema, "tenkai.fleet-posture.v1");

        let encoded = serde_json::to_string(&delta).unwrap();
        assert!(!encoded.contains("Bearer"));
        assert!(!encoded.contains("token="));
        assert!(!encoded.contains("TENKAI_MANAGEMENT_TOKEN"));
    }

    #[test]
    fn fleet_posture_baseline_round_trip_without_secrets() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-fleet-baseline-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        let snapshot = FleetPostureSnapshot {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::from([
                ("alpha".into(), "current".into()),
                ("beta".into(), "behind".into()),
            ]),
        };
        write_fleet_posture_baseline(&path, &snapshot).unwrap();
        let loaded = load_fleet_posture_baseline(&path).unwrap();
        assert_eq!(loaded, snapshot);
        let missing = load_fleet_posture_baseline(&dir.join("missing.json")).unwrap();
        assert!(missing.postures.is_empty());
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("Bearer"));
        assert!(!raw.contains("secret"));
        let _ = std::fs::remove_dir_all(&dir);
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
        let mut runtime_facts = std::collections::BTreeMap::new();
        runtime_facts.insert("architecture".into(), "x86_64".into());
        runtime_facts.insert("memory_gib".into(), "64".into());
        let applied = apply_runtime_inventory_facts(&mut ctx, "alpha", &runtime_facts)
            .await
            .unwrap();
        assert_eq!(
            applied,
            vec!["architecture".to_string(), "memory_gib".to_string()]
        );
        let listed = list_environment_facts(&mut ctx, "alpha").await.unwrap();
        assert_eq!(
            listed.get("architecture").map(String::as_str),
            Some("x86_64")
        );
        assert_eq!(listed.get("memory_gib").map(String::as_str), Some("64"));
        let mut bad = std::collections::BTreeMap::new();
        bad.insert("not_a_key".into(), "x".into());
        assert!(
            apply_runtime_inventory_facts(&mut ctx, "alpha", &bad)
                .await
                .is_err()
        );
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
        assert_eq!(
            facts.get("architecture").map(String::as_str),
            Some("x86_64")
        );
        assert_eq!(
            require_environment_fact(&mut ctx, "alpha", "architecture")
                .await
                .unwrap(),
            "x86_64"
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

    #[test]
    fn model_routing_forward_order_requires_model_before_routing() {
        use crate::manifest::ProductKind;
        validate_model_routing_rollout_order(&[
            (ProductKind::ModelRuntime, Action::Install),
            (ProductKind::RoutingConfig, Action::Upgrade),
        ])
        .unwrap();
        let err = validate_model_routing_rollout_order(&[
            (ProductKind::RoutingConfig, Action::Upgrade),
            (ProductKind::ModelRuntime, Action::Install),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("unsafe rollout order"), "{err}");
    }

    #[test]
    fn model_routing_rollback_order_requires_routing_before_model() {
        use crate::manifest::ProductKind;
        validate_model_routing_rollout_order(&[
            (ProductKind::RoutingConfig, Action::Rollback),
            (ProductKind::ModelRuntime, Action::Downgrade),
        ])
        .unwrap();
        let err = validate_model_routing_rollout_order(&[
            (ProductKind::ModelRuntime, Action::Downgrade),
            (ProductKind::RoutingConfig, Action::Rollback),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("unsafe rollback order"), "{err}");
    }

    #[test]
    fn model_routing_rank_orders_forward_and_reverse() {
        use crate::manifest::ProductKind;
        assert!(
            model_routing_rollout_rank(ProductKind::ModelRuntime, Action::Install)
                < model_routing_rollout_rank(ProductKind::RoutingConfig, Action::Install)
        );
        assert!(
            model_routing_rollout_rank(ProductKind::RoutingConfig, Action::Rollback)
                < model_routing_rollout_rank(ProductKind::ModelRuntime, Action::Rollback)
        );
    }

    #[test]
    fn model_requirements_match_architecture_memory_and_accelerator() {
        let mut facts = std::collections::BTreeMap::new();
        facts.insert("architecture".into(), "arm64".into());
        facts.insert("memory_gib".into(), "32".into());
        facts.insert("accelerator".into(), "apple-metal".into());
        let requirements = crate::manifest::ModelRequirementsSection {
            architecture: vec!["arm64".into(), "x86_64".into()],
            memory_gib: 24,
            accelerator: vec!["apple-metal".into()],
        };
        model_requirements_fit("local", "qwen", "1.0.0", &facts, &requirements).unwrap();

        facts.insert("memory_gib".into(), "8".into());
        let err = model_requirements_fit("local", "qwen", "1.0.0", &facts, &requirements)
            .unwrap_err()
            .to_string();
        assert!(err.contains("memory_gib"), "{err}");

        facts.insert("memory_gib".into(), "32".into());
        facts.insert("architecture".into(), "riscv".into());
        let err = model_requirements_fit("local", "qwen", "1.0.0", &facts, &requirements)
            .unwrap_err()
            .to_string();
        assert!(err.contains("architecture"), "{err}");
    }

    fn write_model_runtime_manifest(
        dir: &std::path::Path,
        version: &str,
        memory_gib: u32,
        quantization: &str,
    ) {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let body = format!(
            r#"[product]
name = "qwen-coder"
version = "{version}"
kind = "model_runtime"
description = "variant fixture"

[model]
source = "file:///tmp/weights.bin"
revision = "fixture"
format = "gguf"
quantization = "{quantization}"
artifact_digest = "{digest}"
license = "apache-2.0"

[runtime]
engine = "llama.cpp"
port = 8080
context_length = 8192

[requirements]
architecture = ["arm64"]
memory_gib = {memory_gib}
accelerator = ["apple-metal"]

[health]
endpoint = "http://127.0.0.1:8080/v1/models"
smoke_prompt = "OK"
max_startup_seconds = 60
"#
        );
        std::fs::write(dir.join("tenkai.toml"), body).unwrap();
    }

    #[tokio::test]
    async fn plan_selects_feasible_model_runtime_variant() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-variant-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let q4_dir = root.join("q4");
        let q8_dir = root.join("q8");
        std::fs::create_dir_all(&q4_dir).unwrap();
        std::fs::create_dir_all(&q8_dir).unwrap();
        write_model_runtime_manifest(&q4_dir, "1.0.0", 16, "Q4_K_M");
        write_model_runtime_manifest(&q8_dir, "1.1.0", 48, "Q8_0");

        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = crate::catalog::PublishOptions {
            signature: None,
            trust_roots: None,
            allow_unsigned_development: true,
        };
        crate::catalog::publish(&mut ctx, &q4_dir.join("tenkai.toml"), &options)
            .await
            .unwrap();
        crate::catalog::publish(&mut ctx, &q8_dir.join("tenkai.toml"), &options)
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, "qwen-coder@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, "qwen-coder@1.1.0", "stable")
            .await
            .unwrap();

        env_add(&mut ctx, "local", "fixture").await.unwrap();
        subscribe(&mut ctx, "local", "qwen-coder", "stable")
            .await
            .unwrap();
        set_environment_fact(&mut ctx, "local", "architecture", "arm64")
            .await
            .unwrap();
        set_environment_fact(&mut ctx, "local", "accelerator", "apple-metal")
            .await
            .unwrap();
        // Only enough memory for Q4; channel head is Q8 (1.1.0).
        set_environment_fact(&mut ctx, "local", "memory_gib", "24")
            .await
            .unwrap();

        let plan = create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].product, "qwen-coder");
        assert_eq!(plan.steps[0].to, "1.0.0");
        assert_eq!(plan.steps[0].release_id, release_id("qwen-coder", "1.0.0"));

        // Infeasible: too little memory for any published variant.
        set_environment_fact(&mut ctx, "local", "memory_gib", "8")
            .await
            .unwrap();
        let err = create(&mut ctx, "local").await.unwrap_err().to_string();
        assert!(
            err.contains("no model_runtime variant") || err.contains("memory_gib"),
            "{err}"
        );

        // High memory selects channel head Q8.
        set_environment_fact(&mut ctx, "local", "memory_gib", "64")
            .await
            .unwrap();
        let plan = create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps[0].to, "1.1.0");

        let _ = std::fs::remove_dir_all(&root);
    }
}
