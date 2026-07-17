//! Environments, subscriptions, and plan computation (desired vs deployed).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::*;
use crate::pb::sekai::Object;
use crate::planner::{Candidate, Dependency, Request};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Install,
    Upgrade,
    Downgrade,
    Rollback,
    Remove,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Action::Install => "install",
            Action::Upgrade => "upgrade",
            Action::Downgrade => "downgrade",
            Action::Rollback => "rollback",
            Action::Remove => "remove",
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

pub const PLAN_FORMAT_VERSION: u32 = 5;

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
    pub dependency_managed: bool,
    pub desired_version: String,
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub workdir: String,
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
    fn executable_digest(&self) -> Result<String> {
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
        let stored_format = object
            .properties
            .get("format_version")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1);
        if stored_format != PLAN_FORMAT_VERSION {
            bail!(
                "plan {} uses legacy format version {stored_format}; create a new plan with `tenkaictl plan --env {}`",
                object.id,
                object
                    .properties
                    .get("environment")
                    .map(String::as_str)
                    .unwrap_or("<environment>")
            );
        }
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
    if let Some(existing) = ctx.get(&plan.id).await? {
        let stored = Plan::from_object(&existing)?;
        if stored.executable_digest()? != plan.executable_digest()? {
            bail!("plan {} executable content is immutable", plan.id);
        }
        if stored.state == plan.state
            && stored.state != PlanState::Blocked
            && (stored.gates_skipped != plan.gates_skipped
                || stored.status_detail != plan.status_detail)
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
        let owner = format!("environment-update:{}", crate::now_millis());
        let lease = crate::apply::claim_environment(ctx, name, &owner).await?;
        let result = async {
            let latest = ctx.get(&id).await?;
            let effective_description = if description.is_empty() {
                latest
                    .as_ref()
                    .and_then(|object| object.properties.get("description"))
                    .cloned()
                    .unwrap_or_default()
            } else {
                description.to_string()
            };
            let object =
                environment_record(latest, name, &effective_description, crate::now_millis())?;
            ctx.put(object).await?;
            Ok::<_, anyhow::Error>(format!("environment {name} updated"))
        }
        .await;
        let unlock = crate::apply::release_environment(ctx, &lease).await;
        return match (result, unlock) {
            (Ok(message), Ok(())) => Ok(message),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(unlock)) => Err(error.context(format!(
                "releasing environment update lease also failed: {unlock}; run `tenkaictl env unlock {name}` after verifying no mutation is running"
            ))),
            (Ok(_), Err(error)) => Err(error.context(format!(
                "releasing environment update lease failed; run `tenkaictl env unlock {name}` after verifying no mutation is running"
            ))),
        };
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
    let owner = format!("reconcile:{product}:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, env, &owner).await?;
    let result = reconcile_deployment_locked(ctx, env, product, deployed).await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing environment reconciliation lease also failed: {unlock}; run `tenkaictl env unlock {env}` after verifying no mutation is running"
        ))),
        (Ok(_), Err(error)) => Err(error.context(format!(
            "releasing environment reconciliation lease failed; run `tenkaictl env unlock {env}` after verifying no mutation is running"
        ))),
    }
}

async fn reconcile_deployment_locked(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    deployed: Option<&str>,
) -> Result<String> {
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
    object
        .properties
        .remove(&format!("dependency_managed.{product}"));
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
    let owner = format!("subscribe:{product}:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, env, &owner).await?;
    let result = subscribe_locked(ctx, env, product, channel).await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing environment subscription lease also failed: {unlock}; run `tenkaictl env unlock {env}` after verifying no mutation is running"
        ))),
        (Ok(_), Err(error)) => Err(error.context(format!(
            "releasing environment subscription lease failed; run `tenkaictl env unlock {env}` after verifying no mutation is running"
        ))),
    }
}

async fn subscribe_locked(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    channel: &str,
) -> Result<String> {
    let eid = env_id(env);
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

async fn pin_release(ctx: &mut Ctx, id: &str) -> Result<ReleasePin> {
    let mut object = ctx
        .get(id)
        .await?
        .with_context(|| format!("release object {id} not found"))?;
    if object.kind != KIND_RELEASE {
        bail!("object {id} is {}, not {KIND_RELEASE}", object.kind);
    }
    let digest = object
        .properties
        .get("digest")
        .filter(|value| !value.is_empty())
        .with_context(|| format!("release object {id} has no digest"))?
        .clone();
    let workdir = object
        .properties
        .get("workdir")
        .filter(|value| !value.is_empty())
        .with_context(|| format!("release object {id} has no workdir"))?
        .clone();
    let artifact_digest = match object
        .properties
        .get("artifact_digest")
        .filter(|value| !value.is_empty())
    {
        Some(digest) => digest.clone(),
        None => {
            let raw = object
                .properties
                .get("manifest")
                .cloned()
                .with_context(|| format!("release object {id} has no manifest"))?;
            let manifest = crate::manifest::parse_raw(&raw)
                .with_context(|| format!("parsing legacy release manifest {id}"))?;
            let digest = crate::manifest::artifact_digest(
                std::path::Path::new(&workdir),
                &manifest.deploy.inputs,
            )
            .with_context(|| {
                format!(
                    "backfilling artifact digest for legacy release {id}; republish it if its workdir moved"
                )
            })?;
            object
                .properties
                .insert("artifact_digest".into(), digest.clone());
            object.updated = crate::now_millis();
            ctx.put(object).await?;
            digest
        }
    };
    Ok(ReleasePin {
        release_id: id.to_string(),
        digest,
        artifact_digest,
        workdir,
    })
}

#[derive(Clone)]
struct ChannelRoot {
    product: String,
    channel: String,
    channel_id: String,
    version: String,
}

fn add_retained_roots(
    roots: &mut BTreeMap<String, ChannelRoot>,
    deployed: &BTreeMap<String, String>,
    properties: &HashMap<String, String>,
    subscribed_products: &BTreeSet<String>,
) {
    for (product, version) in deployed {
        if !roots.contains_key(product)
            && semver::Version::parse(version).is_ok()
            && (subscribed_products.contains(product)
                || properties
                    .get(&format!("dependency_managed.{product}"))
                    .map(String::as_str)
                    != Some("true"))
        {
            roots.insert(
                product.clone(),
                ChannelRoot {
                    product: product.clone(),
                    channel: String::new(),
                    channel_id: String::new(),
                    version: version.clone(),
                },
            );
        }
    }
}

fn rollback_root_version(env: &Object, channel: &Object, product: &str) -> Result<String> {
    if let Some(version) = env
        .properties
        .get(&format!("deployed.{product}"))
        .filter(|version| !version.is_empty())
    {
        return Ok(version.clone());
    }
    let version = channel
        .properties
        .get("current_version")
        .filter(|version| !version.is_empty())
        .with_context(|| format!("subscribed product {product} has no channel head"))?;
    let release = channel
        .properties
        .get("current_release")
        .filter(|release| !release.is_empty())
        .with_context(|| format!("subscribed product {product} has no channel release"))?;
    if release != &release_id(product, version) {
        bail!("subscribed product {product} has inconsistent channel release {release}");
    }
    Ok(version.clone())
}

fn legacy_rollback_content(
    product: &str,
    previous: String,
    current: Option<String>,
    dependency_managed: bool,
    target: ReleasePin,
    restore: Option<ReleasePin>,
) -> (DesiredStateInput, Step) {
    (
        DesiredStateInput {
            product: product.into(),
            channel: String::new(),
            channel_id: String::new(),
            dependency_managed,
            desired_version: previous.clone(),
            release_id: target.release_id.clone(),
            release_digest: target.digest.clone(),
            artifact_digest: target.artifact_digest.clone(),
            workdir: target.workdir.clone(),
            deployed_version: current.clone(),
        },
        Step {
            id: String::new(),
            order: 0,
            product: product.into(),
            action: Action::Rollback,
            from: current,
            to: previous,
            release_id: target.release_id,
            release_digest: target.digest,
            artifact_digest: target.artifact_digest,
            workdir: target.workdir,
            restore,
        },
    )
}

fn validate_legacy_rollback_release(release: &Object) -> Result<()> {
    let candidate = candidate_from_release(release)?;
    if !candidate.dependencies.is_empty() {
        bail!(
            "legacy rollback release {} declares dependencies; republish it with a semver version before rollback",
            release.id
        );
    }
    Ok(())
}

fn candidate_from_release(release: &Object) -> Result<Candidate> {
    if release.kind != KIND_RELEASE {
        bail!(
            "object {} is {}, not {KIND_RELEASE}",
            release.id,
            release.kind
        );
    }
    let product = release
        .properties
        .get("product")
        .filter(|value| !value.is_empty())
        .with_context(|| format!("release {} has no product", release.id))?
        .clone();
    let version = release
        .properties
        .get("version")
        .filter(|value| !value.is_empty())
        .with_context(|| format!("release {} has no version", release.id))?
        .clone();
    let raw = release
        .properties
        .get("manifest")
        .with_context(|| format!("release {} has no manifest", release.id))?;
    let manifest = crate::manifest::parse_raw(raw)
        .with_context(|| format!("parsing release manifest {}", release.id))?;
    crate::manifest::validate_dependencies(&manifest)?;
    if manifest.product.name != product || manifest.product.version != version {
        bail!(
            "release {} metadata does not match manifest identity {}@{}",
            release.id,
            manifest.product.name,
            manifest.product.version
        );
    }
    Ok(Candidate {
        product,
        version,
        dependencies: manifest
            .dependencies
            .into_iter()
            .map(|dependency| Dependency {
                product: dependency.product,
                requirement: dependency.version,
            })
            .collect(),
        required_facts: BTreeMap::new(),
    })
}

async fn catalog_candidates(ctx: &mut Ctx, roots: &[ChannelRoot]) -> Result<Vec<Candidate>> {
    let mut queue = roots
        .iter()
        .map(|root| root.product.clone())
        .collect::<VecDeque<_>>();
    let mut visited = BTreeSet::new();
    let mut candidates = Vec::new();
    while let Some(product) = queue.pop_front() {
        if !visited.insert(product.clone()) {
            continue;
        }
        let releases = ctx
            .linked(&product_id(&product), REL_RELEASE_OF, "in")
            .await?;
        for release in releases {
            let candidate = candidate_from_release(&release)?;
            for dependency in &candidate.dependencies {
                if !visited.contains(&dependency.product) {
                    queue.push_back(dependency.product.clone());
                }
            }
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

async fn deployed_dependencies(
    ctx: &mut Ctx,
    deployed: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut dependencies = BTreeMap::<String, Vec<String>>::new();
    for (product, version) in deployed {
        let id = release_id(product, version);
        let release = ctx
            .get(&id)
            .await?
            .with_context(|| format!("deployed release {id} is not published"))?;
        let candidate = candidate_from_release(&release)?;
        dependencies.insert(
            product.clone(),
            candidate
                .dependencies
                .into_iter()
                .filter(|dependency| deployed.contains_key(&dependency.product))
                .map(|dependency| dependency.product)
                .collect(),
        );
    }
    Ok(dependencies)
}

fn removal_order_from_dependencies(
    products: BTreeSet<String>,
    dependencies: BTreeMap<String, Vec<String>>,
) -> Result<Vec<String>> {
    let mut dependents = BTreeMap::<String, BTreeSet<String>>::new();
    let mut indegree = products
        .iter()
        .map(|product| (product.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for (product, product_dependencies) in dependencies {
        for dependency in product_dependencies {
            if products.contains(&dependency)
                && dependents
                    .entry(dependency)
                    .or_default()
                    .insert(product.clone())
            {
                *indegree.get_mut(&product).expect("deployed product") += 1;
            }
        }
    }
    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(product, _)| product.clone())
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(products.len());
    while let Some(product) = ready.pop_first() {
        order.push(product.clone());
        for dependent in dependents.get(&product).into_iter().flatten() {
            let degree = indegree.get_mut(dependent).expect("deployed dependent");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    if order.len() != products.len() {
        bail!("deployed dependency graph contains a cycle");
    }
    order.reverse();
    Ok(order)
}

fn obsolete_dependency_products(
    deployed: &BTreeMap<String, String>,
    properties: &HashMap<String, String>,
    desired: &BTreeSet<String>,
    subscribed: &BTreeSet<String>,
) -> BTreeSet<String> {
    deployed
        .keys()
        .filter(|product| {
            properties.contains_key(&format!("dependency_managed.{product}"))
                && !desired.contains(*product)
                && !subscribed.contains(*product)
        })
        .cloned()
        .collect()
}

fn retain_required_dependencies(
    deployed: &BTreeMap<String, String>,
    dependencies: &BTreeMap<String, Vec<String>>,
    mut removable: BTreeSet<String>,
) -> BTreeSet<String> {
    loop {
        let required_by_retained = deployed
            .keys()
            .filter(|product| !removable.contains(*product))
            .flat_map(|product| dependencies.get(product).into_iter().flatten())
            .filter(|dependency| removable.contains(*dependency))
            .cloned()
            .collect::<BTreeSet<_>>();
        if required_by_retained.is_empty() {
            return removable;
        }
        for product in required_by_retained {
            removable.remove(&product);
        }
    }
}

fn dependency_closure(
    dependencies: &BTreeMap<String, Vec<String>>,
    product: &str,
) -> BTreeSet<String> {
    let mut pending = dependencies
        .get(product)
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    let mut closure = BTreeSet::new();
    while let Some(dependency) = pending.pop() {
        if closure.insert(dependency.clone()) {
            pending.extend(dependencies.get(&dependency).into_iter().flatten().cloned());
        }
    }
    closure
}

fn dependency_dependents(
    dependencies: &BTreeMap<String, Vec<String>>,
    target: &str,
) -> BTreeSet<String> {
    dependencies
        .keys()
        .filter(|product| product.as_str() != target)
        .filter(|product| dependency_closure(dependencies, product).contains(target))
        .cloned()
        .collect()
}

pub(crate) async fn validate_legacy_deployment_isolation(
    ctx: &mut Ctx,
    environment: &Object,
    product: &str,
    version: &str,
) -> Result<()> {
    if semver::Version::parse(version).is_ok() {
        return Ok(());
    }
    let deployed = environment
        .properties
        .iter()
        .filter_map(|(key, deployed_version)| {
            key.strip_prefix("deployed.")
                .map(|deployed_product| (deployed_product.to_string(), deployed_version.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let current_dependencies = deployed_dependencies(ctx, &deployed).await?;
    if let Some(dependency) = dependency_closure(&current_dependencies, product)
        .into_iter()
        .next()
    {
        bail!(
            "legacy deployment {product}@{version} has deployed dependency {dependency}; reconcile it to a semver release before dependency planning or rollback"
        );
    }
    if let Some(dependent) = dependency_dependents(&current_dependencies, product)
        .into_iter()
        .next()
    {
        bail!(
            "legacy deployment {product}@{version} has deployed dependent {dependent}; reconcile it to a semver release before dependency planning or rollback"
        );
    }
    Ok(())
}

fn validate_legacy_planned_isolation(
    candidate: &Candidate,
    planned_dependencies: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    if let Some(dependency) = candidate
        .dependencies
        .iter()
        .map(|dependency| dependency.product.as_str())
        .find(|dependency| planned_dependencies.contains_key(*dependency))
    {
        bail!(
            "legacy deployment {}@{} has planned dependency {dependency}; reconcile it to a semver release before dependency planning or rollback",
            candidate.product,
            candidate.version
        );
    }
    if let Some(dependent) = dependency_dependents(planned_dependencies, &candidate.product)
        .into_iter()
        .next()
    {
        bail!(
            "legacy deployment {}@{} has planned dependent {dependent}; reconcile it to a semver release before dependency planning or rollback",
            candidate.product,
            candidate.version
        );
    }
    Ok(())
}

async fn validate_retained_legacy_isolation(
    ctx: &mut Ctx,
    environment: &Object,
    product: &str,
    version: &str,
    planned_dependencies: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    validate_legacy_deployment_isolation(ctx, environment, product, version).await?;
    let id = release_id(product, version);
    let release = ctx
        .get(&id)
        .await?
        .with_context(|| format!("deployed release {id} is not published"))?;
    validate_legacy_planned_isolation(&candidate_from_release(&release)?, planned_dependencies)
}

fn transition_execution_order(
    current_dependencies: &BTreeMap<String, Vec<String>>,
    final_dependencies: &BTreeMap<String, Vec<String>>,
    actions: &BTreeMap<String, Action>,
) -> Result<Vec<String>> {
    let mut outgoing = actions
        .keys()
        .map(|product| (product.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut indegree = actions
        .keys()
        .map(|product| (product.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for (dependent, dependent_action) in actions {
        let rollback_current_closure = (*dependent_action == Action::Rollback)
            .then(|| dependency_closure(current_dependencies, dependent));
        if let Some(current_closure) = &rollback_current_closure {
            let final_closure = dependency_closure(final_dependencies, dependent);
            if let Some(dependency) =
                final_closure
                    .intersection(current_closure)
                    .find(|dependency| {
                        actions.get(*dependency).is_some_and(|action| {
                            matches!(
                                action,
                                Action::Upgrade | Action::Downgrade | Action::Rollback
                            )
                        })
                    })
            {
                bail!(
                    "rollback of {dependent} cannot atomically change retained dependency {dependency}"
                );
            }
        }
        let mut paths = BTreeMap::<String, u8>::new();
        let mut pending = final_dependencies
            .get(dependent)
            .into_iter()
            .flatten()
            .map(|dependency| {
                (
                    dependency.clone(),
                    action_requires_prerequisites(*dependent_action)
                        || actions
                            .get(dependency)
                            .is_some_and(|action| action_requires_prerequisites(*action))
                        || rollback_current_closure
                            .as_ref()
                            .is_some_and(|current| !current.contains(dependency)),
                )
            })
            .collect::<Vec<_>>();
        let mut visited = BTreeSet::new();
        while let Some((dependency, path_has_install)) = pending.pop() {
            if !visited.insert((dependency.clone(), path_has_install)) {
                continue;
            }
            if actions.contains_key(&dependency) {
                let path_mode = if path_has_install { 0b10 } else { 0b01 };
                paths
                    .entry(dependency.clone())
                    .and_modify(|modes| *modes |= path_mode)
                    .or_insert(path_mode);
            }
            for transitive in final_dependencies.get(&dependency).into_iter().flatten() {
                pending.push((
                    transitive.clone(),
                    path_has_install
                        || actions
                            .get(transitive)
                            .is_some_and(|action| action_requires_prerequisites(*action))
                        || rollback_current_closure
                            .as_ref()
                            .is_some_and(|current| !current.contains(transitive)),
                ));
            }
        }
        let mut current_pending = current_dependencies
            .get(dependent)
            .into_iter()
            .flatten()
            .map(|dependency| {
                (
                    dependency.clone(),
                    final_dependencies
                        .get(dependent)
                        .is_some_and(|finals| finals.contains(dependency)),
                )
            })
            .collect::<Vec<_>>();
        let mut current_visited = BTreeSet::new();
        while let Some((dependency, path_retained)) = current_pending.pop() {
            if !current_visited.insert((dependency.clone(), path_retained)) {
                continue;
            }
            if actions.contains_key(&dependency) {
                if !path_retained {
                    paths
                        .entry(dependency.clone())
                        .and_modify(|modes| *modes |= 0b01)
                        .or_insert(0b01);
                } else {
                    continue;
                }
            }
            for transitive in current_dependencies.get(&dependency).into_iter().flatten() {
                current_pending.push((
                    transitive.clone(),
                    path_retained
                        && final_dependencies
                            .get(&dependency)
                            .is_some_and(|finals| finals.contains(transitive)),
                ));
            }
        }
        for (dependency, path_modes) in paths {
            if path_modes == 0b11 {
                bail!(
                    "dependency changes require conflicting execution order between {dependent} and {dependency}"
                );
            }
            let (before, after) = if path_modes == 0b10 {
                (&dependency, dependent)
            } else {
                (dependent, &dependency)
            };
            if outgoing
                .get_mut(before)
                .expect("changed product")
                .insert(after.clone())
            {
                *indegree.get_mut(after).expect("changed product") += 1;
            }
        }
    }
    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(product, _)| product.clone())
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(actions.len());
    while let Some(product) = ready.pop_first() {
        order.push(product.clone());
        for dependent in &outgoing[&product] {
            let degree = indegree.get_mut(dependent).expect("changed product");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    if order.len() != actions.len() {
        bail!("dependency changes require conflicting execution order");
    }
    Ok(order)
}

fn action_requires_prerequisites(action: Action) -> bool {
    matches!(action, Action::Install | Action::Upgrade)
}

async fn compute_snapshot(ctx: &mut Ctx, env: &str) -> Result<(Vec<DesiredStateInput>, Vec<Step>)> {
    let env_obj = environment(ctx, env).await?;
    let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;
    let mut roots = BTreeMap::<String, ChannelRoot>::new();
    let mut subscribed_products = BTreeSet::new();
    for channel in channels {
        let product = channel
            .properties
            .get("product")
            .cloned()
            .unwrap_or_default();
        if !subscribed_products.insert(product.clone()) {
            bail!(
                "environment {env} has multiple channel subscriptions for {product}; subscribe again after concurrent updates settle"
            );
        }
        let version = channel
            .properties
            .get("current_version")
            .cloned()
            .unwrap_or_default();
        let release = channel
            .properties
            .get("current_release")
            .cloned()
            .unwrap_or_default();
        if version.is_empty() || release.is_empty() {
            continue;
        }
        if release != release_id(&product, &version) {
            bail!(
                "channel {} points to inconsistent release {release} for {product}@{version}",
                channel.id
            );
        }
        roots.insert(
            product.clone(),
            ChannelRoot {
                product,
                channel: channel
                    .properties
                    .get("channel")
                    .cloned()
                    .unwrap_or_default(),
                channel_id: channel.id,
                version,
            },
        );
    }

    let deployed = env_obj
        .properties
        .iter()
        .filter_map(|(key, version)| {
            key.strip_prefix("deployed.")
                .map(|product| (product.to_string(), version.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    add_retained_roots(
        &mut roots,
        &deployed,
        &env_obj.properties,
        &subscribed_products,
    );
    let root_values = roots.values().cloned().collect::<Vec<_>>();
    let candidates = catalog_candidates(ctx, &root_values).await?;
    let resolution = crate::planner::resolve(&Request {
        roots: roots
            .iter()
            .map(|(product, root)| (product.clone(), root.version.clone()))
            .collect(),
        candidates: candidates.clone(),
        ..Request::default()
    })
    .with_context(|| format!("cannot resolve dependencies for environment {env}"))?;
    let selected_dependencies = resolution
        .selected
        .iter()
        .map(|(product, version)| {
            let candidate = candidates
                .iter()
                .find(|candidate| candidate.product == *product && candidate.version == *version)
                .expect("resolved release must come from catalog candidates");
            (
                product.clone(),
                candidate
                    .dependencies
                    .iter()
                    .map(|dependency| dependency.product.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let desired_products = resolution.selected.keys().cloned().collect::<BTreeSet<_>>();
    let mut inputs = Vec::new();
    for (product, version) in deployed.iter().filter(|(product, version)| {
        semver::Version::parse(version).is_err()
            && !resolution.selected.contains_key(*product)
            && (subscribed_products.contains(*product)
                || env_obj
                    .properties
                    .get(&format!("dependency_managed.{product}"))
                    .map(String::as_str)
                    != Some("true"))
    }) {
        validate_retained_legacy_isolation(ctx, &env_obj, product, version, &selected_dependencies)
            .await?;
        let pin = pin_release(ctx, &release_id(product, version)).await?;
        inputs.push(DesiredStateInput {
            product: product.clone(),
            channel: String::new(),
            channel_id: String::new(),
            dependency_managed: false,
            desired_version: version.clone(),
            release_id: pin.release_id,
            release_digest: pin.digest,
            artifact_digest: pin.artifact_digest,
            workdir: pin.workdir,
            deployed_version: Some(version.clone()),
        });
    }
    let mut steps = Vec::new();
    let mut resolved_steps = BTreeMap::<String, Step>::new();
    for product in resolution.install_order {
        let desired = resolution
            .selected
            .get(&product)
            .expect("ordered product must be selected")
            .clone();
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
        let target = pin_release(ctx, &release_id(&product, &desired)).await?;
        let root = roots.get(&product);
        inputs.push(DesiredStateInput {
            product: product.clone(),
            channel: root.map(|root| root.channel.clone()).unwrap_or_default(),
            channel_id: root.map(|root| root.channel_id.clone()).unwrap_or_default(),
            dependency_managed: root.is_none(),
            desired_version: desired.clone(),
            release_id: target.release_id.clone(),
            release_digest: target.digest.clone(),
            artifact_digest: target.artifact_digest.clone(),
            workdir: target.workdir.clone(),
            deployed_version: deployed.clone(),
        });
        let (action, from, restore) = match deployed {
            Some(version) if version == desired => continue,
            Some(version) => {
                let action = classify_change(&version, &desired);
                let restore = pin_release(ctx, &release_id(&product, &version)).await?;
                (action, Some(version), Some(restore))
            }
            None => (Action::Install, None, None),
        };
        resolved_steps.insert(
            product.clone(),
            Step {
                id: String::new(),
                order: 0,
                product,
                action,
                from,
                to: desired,
                release_id: target.release_id,
                release_digest: target.digest,
                artifact_digest: target.artifact_digest,
                workdir: target.workdir,
                restore,
            },
        );
    }
    let obsolete = obsolete_dependency_products(
        &deployed,
        &env_obj.properties,
        &desired_products,
        &subscribed_products,
    );
    let current_dependencies = if resolved_steps.len() > 1 || !obsolete.is_empty() {
        deployed_dependencies(ctx, &deployed).await?
    } else {
        BTreeMap::new()
    };
    if !obsolete.is_empty() {
        let mut dependencies = current_dependencies.clone();
        for (product, final_dependencies) in &selected_dependencies {
            if deployed.contains_key(product) {
                dependencies.insert(product.clone(), final_dependencies.clone());
            }
        }
        let obsolete = retain_required_dependencies(&deployed, &dependencies, obsolete);
        for product in removal_order_from_dependencies(obsolete.clone(), dependencies)
            .with_context(|| format!("cannot order removals for environment {env}"))?
            .into_iter()
        {
            let version = deployed[&product].clone();
            let target = pin_release(ctx, &release_id(&product, &version)).await?;
            resolved_steps.insert(
                product.clone(),
                Step {
                    id: String::new(),
                    order: 0,
                    product,
                    action: Action::Remove,
                    from: Some(version),
                    to: String::new(),
                    release_id: target.release_id.clone(),
                    release_digest: target.digest.clone(),
                    artifact_digest: target.artifact_digest.clone(),
                    workdir: target.workdir.clone(),
                    restore: Some(target),
                },
            );
        }
    }
    let actions = resolved_steps
        .iter()
        .map(|(product, step)| (product.clone(), step.action))
        .collect::<BTreeMap<_, _>>();
    for product in
        transition_execution_order(&current_dependencies, &selected_dependencies, &actions)?
    {
        let mut step = resolved_steps
            .remove(&product)
            .expect("transition order only contains changed products");
        step.order = steps.len() as u32;
        step.id = format!("{}:step:{}", env_id(env), step.order);
        steps.push(step);
    }
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
    };
    store(ctx, &plan).await?;
    Ok(plan)
}

/// Resolve and persist a rollback with the target release's dependency graph.
pub async fn create_rollback(ctx: &mut Ctx, env: &str, product: &str) -> Result<Plan> {
    validate_identifier("product", product)?;
    let env_obj = environment(ctx, env).await?;
    if env_obj
        .properties
        .get(&format!("deployment_health.{product}"))
        .is_some_and(|health| health == "unknown")
    {
        bail!(
            "deployment state for {product} in {env} is unknown; reconcile the external target before rollback"
        );
    }
    let Some(prev) = env_obj
        .properties
        .get(&format!("deployed_prev.{product}"))
        .cloned()
        .filter(|v| !v.is_empty())
    else {
        bail!("no previous version of {product} recorded in {env} — nothing to roll back to");
    };
    let subscription_channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;
    let mut subscribed_products = BTreeSet::new();
    for channel in &subscription_channels {
        let subscribed_product = channel
            .properties
            .get("product")
            .cloned()
            .unwrap_or_default();
        if !subscribed_products.insert(subscribed_product.clone()) {
            bail!("environment {env} has multiple channel subscriptions for {subscribed_product}");
        }
    }
    if semver::Version::parse(&prev).is_err() {
        let current = env_obj
            .properties
            .get(&format!("deployed.{product}"))
            .cloned();
        validate_legacy_deployment_isolation(ctx, &env_obj, product, &prev).await?;
        let target_id = release_id(product, &prev);
        let target_object = ctx
            .get(&target_id)
            .await?
            .with_context(|| format!("release object {target_id} not found"))?;
        if target_object.kind != KIND_RELEASE {
            bail!(
                "object {target_id} is {}, not {KIND_RELEASE}",
                target_object.kind
            );
        }
        validate_legacy_rollback_release(&target_object)?;
        let target = pin_release(ctx, &target_id).await?;
        let restore = match current.as_deref() {
            Some(version) => Some(pin_release(ctx, &release_id(product, version)).await?),
            None => None,
        };
        let dependency_managed = env_obj
            .properties
            .get(&format!("dependency_managed.{product}"))
            .is_some_and(|managed| managed == "true")
            && !subscribed_products.contains(product);
        let (input, step) =
            legacy_rollback_content(product, prev, current, dependency_managed, target, restore);
        let mut steps = vec![step];
        return create_with_content(ctx, env, vec![input], &mut steps).await;
    }
    let mut rollback_roots = BTreeMap::<String, ChannelRoot>::new();
    for channel in subscription_channels {
        let subscribed_product = channel
            .properties
            .get("product")
            .cloned()
            .unwrap_or_default();
        if subscribed_product == product {
            continue;
        }
        if env_obj
            .properties
            .get(&format!("deployment_health.{subscribed_product}"))
            .is_some_and(|health| health == "unknown")
        {
            bail!(
                "cannot roll back {product} while {subscribed_product} has unknown deployment state; reconcile the external target first"
            );
        }
        let version = rollback_root_version(&env_obj, &channel, &subscribed_product)?;
        rollback_roots.insert(
            subscribed_product.clone(),
            ChannelRoot {
                product: subscribed_product,
                channel: String::new(),
                channel_id: String::new(),
                version,
            },
        );
    }
    rollback_roots.insert(
        product.to_string(),
        ChannelRoot {
            product: product.to_string(),
            channel: String::new(),
            channel_id: String::new(),
            version: prev,
        },
    );
    let deployed = env_obj
        .properties
        .iter()
        .filter_map(|(key, version)| {
            key.strip_prefix("deployed.")
                .map(|deployed_product| (deployed_product.to_string(), version.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    add_retained_roots(
        &mut rollback_roots,
        &deployed,
        &env_obj.properties,
        &subscribed_products,
    );
    let rollback_root_values = rollback_roots.values().cloned().collect::<Vec<_>>();
    let candidates = catalog_candidates(ctx, &rollback_root_values).await?;
    let preferred_versions = deployed.clone();
    let resolution = crate::planner::resolve(&Request {
        roots: rollback_roots
            .iter()
            .map(|(root_product, root)| (root_product.clone(), root.version.clone()))
            .collect(),
        candidates: candidates.clone(),
        preferred_versions,
        ..Request::default()
    })
    .with_context(|| format!("cannot resolve rollback dependencies for {product} in {env}"))?;
    let selected_dependencies = resolution
        .selected
        .iter()
        .map(|(selected_product, version)| {
            let candidate = candidates
                .iter()
                .find(|candidate| {
                    candidate.product == *selected_product && candidate.version == *version
                })
                .expect("resolved rollback release must come from catalog candidates");
            (
                selected_product.clone(),
                candidate
                    .dependencies
                    .iter()
                    .map(|dependency| dependency.product.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let desired_products = resolution.selected.keys().cloned().collect::<BTreeSet<_>>();
    let mut inputs = Vec::new();
    for (retained_product, version) in deployed.iter().filter(|(deployed_product, version)| {
        semver::Version::parse(version).is_err()
            && !resolution.selected.contains_key(*deployed_product)
            && (subscribed_products.contains(*deployed_product)
                || env_obj
                    .properties
                    .get(&format!("dependency_managed.{deployed_product}"))
                    .map(String::as_str)
                    != Some("true"))
    }) {
        validate_retained_legacy_isolation(
            ctx,
            &env_obj,
            retained_product,
            version,
            &selected_dependencies,
        )
        .await?;
        let pin = pin_release(ctx, &release_id(retained_product, version)).await?;
        inputs.push(DesiredStateInput {
            product: retained_product.clone(),
            channel: String::new(),
            channel_id: String::new(),
            dependency_managed: false,
            desired_version: version.clone(),
            release_id: pin.release_id,
            release_digest: pin.digest,
            artifact_digest: pin.artifact_digest,
            workdir: pin.workdir,
            deployed_version: Some(version.clone()),
        });
    }
    let mut steps = Vec::new();
    let install_order = resolution.install_order;
    let mut resolved_steps = BTreeMap::<String, Step>::new();
    for selected_product in &install_order {
        let desired = resolution.selected[selected_product].clone();
        let deployed = env_obj
            .properties
            .get(&format!("deployed.{selected_product}"))
            .cloned();
        let target = pin_release(ctx, &release_id(selected_product, &desired)).await?;
        inputs.push(DesiredStateInput {
            product: selected_product.clone(),
            channel: String::new(),
            channel_id: String::new(),
            dependency_managed: !subscribed_products.contains(selected_product)
                && (env_obj
                    .properties
                    .get(&format!("dependency_managed.{selected_product}"))
                    .is_some_and(|managed| managed == "true")
                    || !rollback_roots.contains_key(selected_product)),
            desired_version: desired.clone(),
            release_id: target.release_id.clone(),
            release_digest: target.digest.clone(),
            artifact_digest: target.artifact_digest.clone(),
            workdir: target.workdir.clone(),
            deployed_version: deployed.clone(),
        });
        let (action, from, restore) = match deployed {
            Some(version) if version == desired => continue,
            Some(version) => {
                let action = if selected_product == product {
                    Action::Rollback
                } else {
                    classify_change(&version, &desired)
                };
                let restore = pin_release(ctx, &release_id(selected_product, &version)).await?;
                (action, Some(version), Some(restore))
            }
            None => (Action::Install, None, None),
        };
        resolved_steps.insert(
            selected_product.clone(),
            Step {
                id: String::new(),
                order: 0,
                product: selected_product.clone(),
                action,
                from,
                to: desired,
                release_id: target.release_id,
                release_digest: target.digest,
                artifact_digest: target.artifact_digest,
                workdir: target.workdir,
                restore,
            },
        );
    }
    let obsolete = obsolete_dependency_products(
        &deployed,
        &env_obj.properties,
        &desired_products,
        &subscribed_products,
    );
    let current_dependencies = if resolved_steps.len() > 1 || !obsolete.is_empty() {
        deployed_dependencies(ctx, &deployed).await?
    } else {
        BTreeMap::new()
    };
    if !obsolete.is_empty() {
        let mut dependencies = current_dependencies.clone();
        for (selected_product, final_dependencies) in &selected_dependencies {
            if deployed.contains_key(selected_product) {
                dependencies.insert(selected_product.clone(), final_dependencies.clone());
            }
        }
        let obsolete = retain_required_dependencies(&deployed, &dependencies, obsolete);
        for removed_product in removal_order_from_dependencies(obsolete.clone(), dependencies)? {
            let version = deployed[&removed_product].clone();
            let target = pin_release(ctx, &release_id(&removed_product, &version)).await?;
            resolved_steps.insert(
                removed_product.clone(),
                Step {
                    id: String::new(),
                    order: 0,
                    product: removed_product,
                    action: Action::Remove,
                    from: Some(version),
                    to: String::new(),
                    release_id: target.release_id.clone(),
                    release_digest: target.digest.clone(),
                    artifact_digest: target.artifact_digest.clone(),
                    workdir: target.workdir.clone(),
                    restore: Some(target),
                },
            );
        }
    }
    let actions = resolved_steps
        .iter()
        .map(|(product, step)| (product.clone(), step.action))
        .collect::<BTreeMap<_, _>>();
    for selected_product in
        transition_execution_order(&current_dependencies, &selected_dependencies, &actions)?
    {
        steps.push(
            resolved_steps
                .remove(&selected_product)
                .expect("rollback order only contains changed products"),
        );
    }
    create_with_content(ctx, env, inputs, &mut steps).await
}

pub struct StatusRow {
    pub product: String,
    pub channel: String,
    pub deployed: Option<String>,
    pub health: Option<String>,
    pub error: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn release_object(product: &str, version: &str, manifest: &str) -> Object {
        Object {
            id: release_id(product, version),
            kind: KIND_RELEASE.into(),
            name: format!("{product}@{version}"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("product".into(), product.into()),
                ("version".into(), version.into()),
                ("manifest".into(), manifest.into()),
            ]),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn catalog_release_dependencies_feed_the_resolver() {
        let release = release_object(
            "api",
            "2.0.0",
            r#"
[product]
name = "api"
version = "2.0.0"

[deploy]
install = "true"

[[dependencies]]
product = "runtime"
version = ">=1, <2"
"#,
        );
        let candidate = candidate_from_release(&release).unwrap();
        assert_eq!(candidate.product, "api");
        assert_eq!(candidate.version, "2.0.0");
        assert_eq!(
            candidate.dependencies,
            [Dependency {
                product: "runtime".into(),
                requirement: ">=1, <2".into(),
            }]
        );
    }

    #[test]
    fn catalog_release_identity_must_match_its_manifest() {
        let release = release_object(
            "api",
            "2.0.0",
            r#"
[product]
name = "other"
version = "2.0.0"

[deploy]
install = "true"
"#,
        );
        assert!(
            candidate_from_release(&release)
                .unwrap_err()
                .to_string()
                .contains("does not match manifest identity")
        );
    }

    #[test]
    fn retained_roots_constrain_dependency_selection() {
        let mut roots = BTreeMap::from([(
            "app".into(),
            ChannelRoot {
                product: "app".into(),
                channel: "stable".into(),
                channel_id: "channel:app:stable".into(),
                version: "1.0.0".into(),
            },
        )]);
        let deployed = BTreeMap::from([
            ("legacy".into(), "legacy_build".into()),
            ("worker".into(), "1.0.0".into()),
            ("runtime".into(), "2.0.0".into()),
        ]);
        let properties = HashMap::from([("dependency_managed.runtime".into(), "true".into())]);
        add_retained_roots(
            &mut roots,
            &deployed,
            &properties,
            &BTreeSet::from(["app".into()]),
        );

        let resolution = crate::planner::resolve(&Request {
            roots: roots
                .iter()
                .map(|(product, root)| (product.clone(), root.version.clone()))
                .collect(),
            candidates: vec![
                Candidate {
                    product: "app".into(),
                    version: "1.0.0".into(),
                    dependencies: vec![Dependency {
                        product: "runtime".into(),
                        requirement: ">=1".into(),
                    }],
                    required_facts: BTreeMap::new(),
                },
                Candidate {
                    product: "worker".into(),
                    version: "1.0.0".into(),
                    dependencies: vec![Dependency {
                        product: "runtime".into(),
                        requirement: "<2".into(),
                    }],
                    required_facts: BTreeMap::new(),
                },
                Candidate {
                    product: "runtime".into(),
                    version: "2.0.0".into(),
                    dependencies: Vec::new(),
                    required_facts: BTreeMap::new(),
                },
                Candidate {
                    product: "runtime".into(),
                    version: "1.0.0".into(),
                    dependencies: Vec::new(),
                    required_facts: BTreeMap::new(),
                },
            ],
            ..Request::default()
        })
        .unwrap();

        assert_eq!(resolution.selected["runtime"], "1.0.0");
        assert!(roots.contains_key("worker"));
        assert!(!roots.contains_key("legacy"));
        assert!(!roots.contains_key("runtime"));
    }

    #[test]
    fn retained_legacy_rejects_dependencies_introduced_by_the_plan() {
        let legacy = Candidate {
            product: "legacy".into(),
            version: "legacy_build".into(),
            dependencies: vec![Dependency {
                product: "runtime".into(),
                requirement: ">=1".into(),
            }],
            required_facts: BTreeMap::new(),
        };
        let planned_dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), Vec::new()),
        ]);

        assert!(
            validate_legacy_planned_isolation(&legacy, &planned_dependencies)
                .unwrap_err()
                .to_string()
                .contains("planned dependency runtime")
        );
    }

    #[test]
    fn retained_legacy_rejects_dependents_introduced_by_the_plan() {
        let legacy = Candidate {
            product: "legacy".into(),
            version: "legacy_build".into(),
            dependencies: Vec::new(),
            required_facts: BTreeMap::new(),
        };
        let planned_dependencies = BTreeMap::from([
            ("app".into(), vec!["worker".into()]),
            ("worker".into(), vec!["legacy".into()]),
        ]);

        assert!(
            validate_legacy_planned_isolation(&legacy, &planned_dependencies)
                .unwrap_err()
                .to_string()
                .contains("planned dependent app")
        );
    }

    #[test]
    fn rollback_roots_missing_subscriptions_at_their_channel_head() {
        let env = Object {
            id: "env:prod".into(),
            kind: KIND_ENVIRONMENT.into(),
            name: "prod".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        let channel = Object {
            id: "channel:runtime:stable".into(),
            kind: KIND_CHANNEL.into(),
            name: "runtime stable".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("current_version".into(), "2.0.0".into()),
                ("current_release".into(), release_id("runtime", "2.0.0")),
            ]),
            created: 1,
            updated: 1,
        };

        assert_eq!(
            rollback_root_version(&env, &channel, "runtime").unwrap(),
            "2.0.0"
        );
    }

    #[test]
    fn legacy_rollback_content_preserves_the_recorded_release() {
        let target = ReleasePin {
            release_id: release_id("app", "legacy_build"),
            digest: "release-digest".into(),
            artifact_digest: "artifact-digest".into(),
            workdir: "/tmp/app".into(),
        };
        let restore = ReleasePin {
            release_id: release_id("app", "2.0.0"),
            digest: "restore-release-digest".into(),
            artifact_digest: "restore-artifact-digest".into(),
            workdir: "/tmp/app".into(),
        };

        let (input, step) = legacy_rollback_content(
            "app",
            "legacy_build".into(),
            Some("2.0.0".into()),
            true,
            target,
            Some(restore),
        );

        assert_eq!(input.desired_version, "legacy_build");
        assert_eq!(input.deployed_version.as_deref(), Some("2.0.0"));
        assert!(input.dependency_managed);
        assert_eq!(step.action, Action::Rollback);
        assert_eq!(step.to, "legacy_build");
        assert_eq!(step.from.as_deref(), Some("2.0.0"));
        assert!(step.restore.is_some());
    }

    #[test]
    fn legacy_rollback_rejects_dependency_bearing_releases() {
        let manifest = r#"
[product]
name = "app"
version = "legacy_build"

[deploy]
install = "true"

[[dependencies]]
product = "runtime"
version = "<2"
"#;
        let release = release_object("app", "legacy_build", manifest);

        assert!(
            validate_legacy_rollback_release(&release)
                .unwrap_err()
                .to_string()
                .contains("declares dependencies")
        );
    }

    #[test]
    fn legacy_rollback_detects_transitive_deployed_dependents() {
        let dependencies = BTreeMap::from([
            ("worker".into(), vec!["app".into()]),
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), Vec::new()),
        ]);

        assert_eq!(
            dependency_dependents(&dependencies, "runtime"),
            BTreeSet::from(["app".into(), "worker".into()])
        );
        assert_eq!(
            dependency_closure(&dependencies, "app"),
            BTreeSet::from(["runtime".into()])
        );
    }

    #[test]
    fn deployed_products_are_removed_before_their_dependencies() {
        let order = removal_order_from_dependencies(
            BTreeSet::from(["app".into(), "runtime".into(), "database".into()]),
            BTreeMap::from([
                ("app".into(), vec!["runtime".into()]),
                ("runtime".into(), vec!["database".into()]),
                ("database".into(), Vec::new()),
            ]),
        )
        .unwrap();
        assert_eq!(order, ["app", "runtime", "database"]);
    }

    #[test]
    fn only_planner_managed_dependencies_become_obsolete() {
        let deployed = BTreeMap::from([
            ("managed".into(), "1.0.0".into()),
            ("reconciled".into(), "2.0.0".into()),
        ]);
        let properties = HashMap::from([
            ("deployed.managed".into(), "1.0.0".into()),
            ("dependency_managed.managed".into(), "true".into()),
            ("deployed.reconciled".into(), "2.0.0".into()),
        ]);

        assert_eq!(
            obsolete_dependency_products(
                &deployed,
                &properties,
                &BTreeSet::new(),
                &BTreeSet::new(),
            ),
            BTreeSet::from(["managed".into()])
        );
    }

    #[test]
    fn dependencies_required_by_retained_deployments_are_not_removed() {
        let deployed = BTreeMap::from([
            ("worker".into(), "1.0.0".into()),
            ("runtime".into(), "1.0.0".into()),
            ("database".into(), "1.0.0".into()),
        ]);
        let dependencies = BTreeMap::from([
            ("worker".into(), vec!["runtime".into()]),
            ("runtime".into(), vec!["database".into()]),
            ("database".into(), Vec::new()),
        ]);

        assert!(
            retain_required_dependencies(
                &deployed,
                &dependencies,
                BTreeSet::from(["runtime".into(), "database".into()]),
            )
            .is_empty()
        );
    }

    #[test]
    fn dependencies_dropped_by_selected_upgrades_are_removed() {
        let deployed = BTreeMap::from([
            ("app".into(), "1.0.0".into()),
            ("runtime".into(), "1.0.0".into()),
        ]);
        let final_dependencies =
            BTreeMap::from([("app".into(), Vec::new()), ("runtime".into(), Vec::new())]);

        assert_eq!(
            retain_required_dependencies(
                &deployed,
                &final_dependencies,
                BTreeSet::from(["runtime".into()]),
            ),
            BTreeSet::from(["runtime".into()])
        );
    }

    #[test]
    fn rollback_prepares_final_only_dependency_paths_before_activation() {
        let dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), vec!["database".into()]),
            ("database".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("database".into(), Action::Install),
            ("runtime".into(), Action::Downgrade),
            ("app".into(), Action::Rollback),
        ]);

        assert_eq!(
            transition_execution_order(&BTreeMap::new(), &dependencies, &actions).unwrap(),
            ["database", "runtime", "app"]
        );
    }

    #[test]
    fn rollback_rejects_changes_to_retained_dependencies() {
        let dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("runtime".into(), Action::Downgrade),
            ("app".into(), Action::Rollback),
        ]);

        assert!(
            transition_execution_order(&dependencies, &dependencies, &actions)
                .unwrap_err()
                .to_string()
                .contains("cannot atomically change retained dependency runtime")
        );
    }

    #[test]
    fn channel_downgrades_change_dependents_before_dependencies() {
        let dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("app".into(), Action::Downgrade),
            ("runtime".into(), Action::Downgrade),
        ]);

        assert_eq!(
            transition_execution_order(&BTreeMap::new(), &dependencies, &actions).unwrap(),
            ["app", "runtime"]
        );
    }

    #[test]
    fn channel_downgrades_preserve_dependencies_dropped_by_the_target() {
        let current_dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), Vec::new()),
        ]);
        let final_dependencies =
            BTreeMap::from([("app".into(), Vec::new()), ("runtime".into(), Vec::new())]);
        let actions = BTreeMap::from([
            ("app".into(), Action::Downgrade),
            ("runtime".into(), Action::Downgrade),
        ]);

        assert_eq!(
            transition_execution_order(&current_dependencies, &final_dependencies, &actions,)
                .unwrap(),
            ["app", "runtime"]
        );
    }

    #[test]
    fn retained_dependency_paths_allow_prerequisite_upgrades() {
        let dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("app".into(), Action::Upgrade),
            ("runtime".into(), Action::Upgrade),
        ]);

        assert_eq!(
            transition_execution_order(&dependencies, &dependencies, &actions).unwrap(),
            ["runtime", "app"]
        );
    }

    #[test]
    fn changed_intermediates_retire_their_own_dropped_dependencies() {
        let current_dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), vec!["database".into()]),
            ("database".into(), Vec::new()),
        ]);
        let final_dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into(), "database".into()]),
            ("runtime".into(), Vec::new()),
            ("database".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("app".into(), Action::Upgrade),
            ("runtime".into(), Action::Upgrade),
            ("database".into(), Action::Upgrade),
        ]);

        assert_eq!(
            transition_execution_order(&current_dependencies, &final_dependencies, &actions,)
                .unwrap(),
            ["runtime", "database", "app"]
        );
    }

    #[test]
    fn dropped_intermediates_preserve_their_transitive_dependencies() {
        let current_dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), vec!["database".into()]),
            ("database".into(), Vec::new()),
        ]);
        let final_dependencies = BTreeMap::from([
            ("app".into(), Vec::new()),
            ("runtime".into(), vec!["database".into()]),
            ("database".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("app".into(), Action::Upgrade),
            ("runtime".into(), Action::Upgrade),
            ("database".into(), Action::Upgrade),
        ]);

        assert_eq!(
            transition_execution_order(&current_dependencies, &final_dependencies, &actions,)
                .unwrap(),
            ["app", "database", "runtime"]
        );
    }

    #[test]
    fn obsolete_dependents_are_removed_before_prerequisites_change() {
        let current_dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), Vec::new()),
        ]);
        let final_dependencies = BTreeMap::from([("runtime".into(), Vec::new())]);
        let actions = BTreeMap::from([
            ("app".into(), Action::Remove),
            ("runtime".into(), Action::Upgrade),
        ]);

        assert_eq!(
            transition_execution_order(&current_dependencies, &final_dependencies, &actions,)
                .unwrap(),
            ["app", "runtime"]
        );
    }

    #[test]
    fn rerouted_dependency_paths_fail_on_conflicting_transition_order() {
        let current_dependencies = BTreeMap::from([
            ("app".into(), vec!["old_runtime".into()]),
            ("old_runtime".into(), vec!["database".into()]),
            ("database".into(), Vec::new()),
        ]);
        let final_dependencies = BTreeMap::from([
            ("app".into(), vec!["sidecar".into()]),
            ("sidecar".into(), vec!["database".into()]),
            ("database".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("app".into(), Action::Upgrade),
            ("sidecar".into(), Action::Install),
            ("database".into(), Action::Upgrade),
        ]);

        assert!(
            transition_execution_order(&current_dependencies, &final_dependencies, &actions,)
                .unwrap_err()
                .to_string()
                .contains("conflicting execution order between app and database")
        );
    }

    #[test]
    fn rollback_preserves_prerequisites_for_new_dependencies() {
        let dependencies = BTreeMap::from([
            ("app".into(), vec!["sidecar".into()]),
            ("sidecar".into(), vec!["runtime".into()]),
            ("runtime".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("runtime".into(), Action::Downgrade),
            ("sidecar".into(), Action::Install),
            ("app".into(), Action::Rollback),
        ]);

        assert_eq!(
            transition_execution_order(&BTreeMap::new(), &dependencies, &actions).unwrap(),
            ["runtime", "sidecar", "app"]
        );
    }

    #[test]
    fn rollback_upgrades_dependencies_before_dependents() {
        let dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("runtime".into(), Action::Upgrade),
            ("app".into(), Action::Rollback),
        ]);

        assert_eq!(
            transition_execution_order(&BTreeMap::new(), &dependencies, &actions).unwrap(),
            ["runtime", "app"]
        );
    }

    #[test]
    fn rollback_preserves_installs_through_unchanged_dependencies() {
        let dependencies = BTreeMap::from([
            ("app".into(), vec!["runtime".into()]),
            ("runtime".into(), vec!["database".into()]),
            ("database".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("database".into(), Action::Install),
            ("app".into(), Action::Rollback),
        ]);

        assert_eq!(
            transition_execution_order(&BTreeMap::new(), &dependencies, &actions).unwrap(),
            ["database", "app"]
        );
    }

    #[test]
    fn unchanged_diamond_edges_do_not_create_rollback_conflicts() {
        let dependencies = BTreeMap::from([
            ("app".into(), vec!["new_dep".into(), "unchanged_dep".into()]),
            ("new_dep".into(), vec!["shared".into()]),
            ("unchanged_dep".into(), vec!["shared".into()]),
            ("shared".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("new_dep".into(), Action::Install),
            ("app".into(), Action::Rollback),
        ]);

        assert_eq!(
            transition_execution_order(&BTreeMap::new(), &dependencies, &actions).unwrap(),
            ["new_dep", "app"]
        );
    }

    #[test]
    fn rollback_orders_shared_final_only_prerequisites_before_mixed_paths() {
        let dependencies = BTreeMap::from([
            ("app".into(), vec!["new_dep".into(), "unchanged_dep".into()]),
            ("new_dep".into(), vec!["shared".into()]),
            ("unchanged_dep".into(), vec!["shared".into()]),
            ("shared".into(), Vec::new()),
        ]);
        let actions = BTreeMap::from([
            ("new_dep".into(), Action::Install),
            ("shared".into(), Action::Downgrade),
            ("app".into(), Action::Rollback),
        ]);

        assert_eq!(
            transition_execution_order(&BTreeMap::new(), &dependencies, &actions).unwrap(),
            ["shared", "new_dep", "app"]
        );
    }

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
                dependency_managed: false,
                desired_version: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "target-digest".into(),
                artifact_digest: "target-artifact-digest".into(),
                workdir: "/srv/api".into(),
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
    fn legacy_plan_formats_require_recomputation() {
        let plan = example_plan();
        let mut object = plan.to_object().unwrap();
        object
            .properties
            .insert("format_version".into(), "2".into());

        let error = Plan::from_object(&object).unwrap_err().to_string();
        assert!(error.contains("legacy format version 2"));
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
        assert!(error.contains("content-addressed id"));
    }

    #[test]
    fn semantic_version_direction_is_recorded() {
        assert_eq!(classify_change("2.0.0", "1.9.0"), Action::Downgrade);
        assert_eq!(classify_change("1.9.0", "2.0.0"), Action::Upgrade);
    }

    #[test]
    fn environment_record_initializes_without_deployment_state() {
        let record = environment_record(None, "prod", "production", 20).unwrap();
        assert_eq!(record.properties.get("description").unwrap(), "production");
        assert_eq!(record.created, 20);
        assert_eq!(record.updated, 20);
    }
}
