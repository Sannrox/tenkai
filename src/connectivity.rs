//! Connectivity-class upgrade coordinator (ADR 0020).
//!
//! One Tenkai-owned upgrade carries a signed release and approved plan across
//! connected, intermittent, and isolated environments. Class adapters never
//! become a second executor, promoter, or recovery store.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::apply::{self, ExecutionAuthorization, ExecutionOptions};
use crate::client::Ctx;
use crate::ontology::{
    KIND_CHANNEL, KIND_CONNECTIVITY_UPGRADE, NS, channel_id, connectivity_upgrade_id, env_id,
    release_id, require_connectivity_upgrade_schema, validate_identifier,
};
use crate::pb::sekai::Object;
use crate::plan::{self, Plan, PlanState};

pub const UPGRADE_FORMAT_VERSION: u32 = 1;
pub const CONNECTIVITY_CLASS_PROPERTY: &str = "connectivity_class";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityClass {
    Connected,
    Intermittent,
    Isolated,
}

impl ConnectivityClass {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "connected" => Ok(Self::Connected),
            "intermittent" => Ok(Self::Intermittent),
            "isolated" => Ok(Self::Isolated),
            other => bail!("unknown connectivity class {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Intermittent => "intermittent",
            Self::Isolated => "isolated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeStatus {
    Admitted,
    Running,
    Interrupted,
    Succeeded,
    Failed,
    Conflicted,
    RolledBack,
    RecoveryRequired,
}

impl UpgradeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Running => "running",
            Self::Interrupted => "interrupted",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Conflicted => "conflicted",
            Self::RolledBack => "rolled_back",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeEnvironmentStatus {
    Pending,
    Interrupted,
    Applied,
    Conflicted,
    RolledBack,
    RecoveryRequired,
}

impl UpgradeEnvironmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Interrupted => "interrupted",
            Self::Applied => "applied",
            Self::Conflicted => "conflicted",
            Self::RolledBack => "rolled_back",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferCheckpoint {
    pub plan_id: String,
    pub plan_digest: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub generation: u64,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolatedEvidence {
    pub bundle_digest: String,
    pub receipt_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeEnvironmentRecord {
    pub name: String,
    pub class: ConnectivityClass,
    pub status: UpgradeEnvironmentStatus,
    pub plan_id: Option<String>,
    pub detail: String,
    pub transfer: Option<TransferCheckpoint>,
    pub isolated: Option<IsolatedEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeSpec {
    pub name: String,
    pub product: String,
    pub version: String,
    pub channel: String,
    pub environments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeRecord {
    pub format_version: u32,
    pub id: String,
    pub name: String,
    pub identity_digest: String,
    pub product: String,
    pub version: String,
    pub channel: String,
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub status: UpgradeStatus,
    pub environments: Vec<UpgradeEnvironmentRecord>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl UpgradeSpec {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("upgrade name", &self.name)?;
        validate_identifier("product", &self.product)?;
        validate_identifier("version", &self.version)?;
        validate_identifier("channel", &self.channel)?;
        if self.environments.is_empty() {
            bail!("upgrade cohort must not be empty");
        }
        let mut seen = std::collections::BTreeSet::new();
        for environment in &self.environments {
            validate_identifier("environment", environment)?;
            if !seen.insert(environment) {
                bail!("upgrade cohort contains duplicate environment {environment}");
            }
        }
        Ok(())
    }
}

pub async fn set_connectivity_class(
    ctx: &mut Ctx,
    env: &str,
    class: ConnectivityClass,
) -> Result<String> {
    validate_identifier("environment", env)?;
    let mut object = crate::environment::environment(ctx, env).await?;
    object
        .properties
        .insert(CONNECTIVITY_CLASS_PROPERTY.into(), class.as_str().into());
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(format!("set {env} connectivity class {}", class.as_str()))
}

pub async fn connectivity_class(ctx: &mut Ctx, env: &str) -> Result<ConnectivityClass> {
    let object = crate::environment::environment(ctx, env).await?;
    let Some(value) = object.properties.get(CONNECTIVITY_CLASS_PROPERTY) else {
        bail!("environment {env} has no connectivity class");
    };
    ConnectivityClass::parse(value)
}

pub fn format_upgrade(record: &UpgradeRecord) -> String {
    let mut lines = vec![format!(
        "upgrade {} {} {}@{} channel {} status {}",
        record.name,
        record.id,
        record.product,
        record.version,
        record.channel,
        record.status.as_str()
    )];
    for environment in &record.environments {
        lines.push(format!(
            "  {} {} {} {}",
            environment.name,
            environment.class.as_str(),
            environment.status.as_str(),
            environment.detail
        ));
    }
    lines.join("\n")
}

pub async fn start_or_resume(ctx: &mut Ctx, spec: &UpgradeSpec) -> Result<UpgradeRecord> {
    require_connectivity_upgrade_schema(ctx).await?;
    spec.validate()?;
    let pin = resolve_release_pin(ctx, spec).await?;
    let identity = identity_digest(spec, &pin)?;
    let id = connectivity_upgrade_id(&spec.name);
    if let Some(existing) = ctx.get(&id).await? {
        let record = record_from_object(&existing)?;
        if record.identity_digest != identity {
            bail!(
                "upgrade {} already exists with a conflicting identity",
                spec.name
            );
        }
        return Ok(record);
    }
    let mut environments = Vec::new();
    for name in &spec.environments {
        let class = connectivity_class(ctx, name).await?;
        let env = crate::environment::environment(ctx, name).await?;
        if env.id != env_id(name) {
            bail!("environment {name} has conflicting identity");
        }
        let plan = plan::create(ctx, name).await?;
        environments.push(UpgradeEnvironmentRecord {
            name: name.clone(),
            class,
            status: UpgradeEnvironmentStatus::Pending,
            plan_id: Some(plan.id),
            detail: "awaiting class adapter".into(),
            transfer: None,
            isolated: None,
        });
    }
    let now = crate::now_millis();
    let record = UpgradeRecord {
        format_version: UPGRADE_FORMAT_VERSION,
        id,
        name: spec.name.clone(),
        identity_digest: identity,
        product: spec.product.clone(),
        version: spec.version.clone(),
        channel: spec.channel.clone(),
        release_id: pin.release_id,
        release_digest: pin.release_digest,
        artifact_digest: pin.artifact_digest,
        status: UpgradeStatus::Admitted,
        environments,
        created_at: now,
        updated_at: now,
    };
    ctx.create_once(upgrade_object(&record)?)
        .await
        .map_err(|status| anyhow::anyhow!("{status}"))?;
    Ok(record)
}

pub async fn load_upgrade(ctx: &mut Ctx, name: &str) -> Result<UpgradeRecord> {
    require_connectivity_upgrade_schema(ctx).await?;
    validate_identifier("upgrade name", name)?;
    let object = ctx
        .get(&connectivity_upgrade_id(name))
        .await?
        .ok_or_else(|| anyhow::anyhow!("upgrade {name} is not registered"))?;
    record_from_object(&object)
}

pub async fn interrupt_transfer(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
) -> Result<UpgradeRecord> {
    let mut record = load_upgrade(ctx, name).await?;
    let index = env_index(&record, environment)?;
    if record.environments[index].class != ConnectivityClass::Intermittent {
        bail!("environment {environment} is not intermittent");
    }
    if record.environments[index].status == UpgradeEnvironmentStatus::Applied {
        bail!("environment {environment} already applied");
    }
    let plan = ensure_plan(ctx, &record, environment).await?;
    let generation = current_generation(ctx, environment).await?;
    record.environments[index].plan_id = Some(plan.id.clone());
    record.environments[index].transfer = Some(TransferCheckpoint {
        plan_id: plan.id,
        plan_digest: record.release_digest.clone(),
        release_digest: record.release_digest.clone(),
        artifact_digest: record.artifact_digest.clone(),
        generation,
        verified: false,
    });
    record.environments[index].status = UpgradeEnvironmentStatus::Interrupted;
    record.environments[index].detail =
        "transfer interrupted before verified content boundary".into();
    record.status = UpgradeStatus::Interrupted;
    persist(ctx, &record).await?;
    Ok(record)
}

pub async fn resume_transfer(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
) -> Result<UpgradeRecord> {
    let mut record = load_upgrade(ctx, name).await?;
    revalidate(&record, ctx).await?;
    let index = env_index(&record, environment)?;
    if record.environments[index].class != ConnectivityClass::Intermittent {
        bail!("environment {environment} is not intermittent");
    }
    let generation = current_generation(ctx, environment).await?;
    let Some(checkpoint) = record.environments[index].transfer.clone() else {
        bail!("environment {environment} has no transfer checkpoint to resume");
    };
    if checkpoint.generation != generation {
        record.environments[index].status = UpgradeEnvironmentStatus::Conflicted;
        record.environments[index].detail =
            "stale fencing generation cannot resume an interrupted transfer".into();
        record.status = UpgradeStatus::Conflicted;
        persist(ctx, &record).await?;
        bail!("{}", record.environments[index].detail);
    }
    if checkpoint.release_digest != record.release_digest
        || checkpoint.artifact_digest != record.artifact_digest
    {
        bail!("interrupted transfer no longer matches the pinned release content");
    }
    let mut checkpoint = checkpoint;
    checkpoint.verified = true;
    record.environments[index].transfer = Some(checkpoint);
    record.environments[index].detail = "transfer verified; ready to apply".into();
    persist(ctx, &record).await?;
    Ok(record)
}

pub async fn advance(
    ctx: &mut Ctx,
    name: &str,
    authorization: ExecutionAuthorization<'_>,
) -> Result<UpgradeRecord> {
    let mut record = load_upgrade(ctx, name).await?;
    revalidate(&record, ctx).await?;
    let Some(index) = record.environments.iter().position(|environment| {
        matches!(
            environment.status,
            UpgradeEnvironmentStatus::Pending | UpgradeEnvironmentStatus::Interrupted
        )
    }) else {
        record.status = summarize(&record);
        persist(ctx, &record).await?;
        return Ok(record);
    };
    record.status = UpgradeStatus::Running;
    let environment = record.environments[index].name.clone();
    let class = record.environments[index].class;
    let plan = ensure_plan(ctx, &record, &environment).await?;
    record.environments[index].plan_id = Some(plan.id.clone());
    match class {
        ConnectivityClass::Connected => {
            apply_plan(ctx, &plan.id, authorization).await?;
            mark_applied(&mut record, index, "connected apply completed");
        }
        ConnectivityClass::Intermittent => {
            let generation = current_generation(ctx, &environment).await?;
            match record.environments[index].transfer.as_ref() {
                None => {
                    record.environments[index].transfer = Some(TransferCheckpoint {
                        plan_id: plan.id.clone(),
                        plan_digest: record.release_digest.clone(),
                        release_digest: record.release_digest.clone(),
                        artifact_digest: record.artifact_digest.clone(),
                        generation,
                        verified: false,
                    });
                    record.environments[index].status = UpgradeEnvironmentStatus::Interrupted;
                    record.environments[index].detail =
                        "intermittent transfer requires resume after verified content".into();
                    record.status = UpgradeStatus::Interrupted;
                }
                Some(checkpoint) if !checkpoint.verified => {
                    record.environments[index].status = UpgradeEnvironmentStatus::Interrupted;
                    record.environments[index].detail =
                        "intermittent transfer is not yet verified".into();
                    record.status = UpgradeStatus::Interrupted;
                }
                Some(checkpoint) if checkpoint.generation != generation => {
                    record.environments[index].status = UpgradeEnvironmentStatus::Conflicted;
                    record.environments[index].detail =
                        "stale fencing generation rejected reconnecting runtime".into();
                    record.status = UpgradeStatus::Conflicted;
                    persist(ctx, &record).await?;
                    bail!("{}", record.environments[index].detail);
                }
                Some(_) => {
                    apply_plan(ctx, &plan.id, authorization).await?;
                    mark_applied(
                        &mut record,
                        index,
                        "intermittent apply resumed after verified transfer",
                    );
                }
            }
        }
        ConnectivityClass::Isolated => {
            if record.environments[index].isolated.is_none() {
                record.environments[index].status = UpgradeEnvironmentStatus::Interrupted;
                record.environments[index].detail =
                    "isolated environment requires a verified offline bundle".into();
                record.status = UpgradeStatus::Interrupted;
            } else if record.environments[index]
                .isolated
                .as_ref()
                .is_some_and(|evidence| evidence.receipt_digest.is_none())
            {
                record.environments[index].status = UpgradeEnvironmentStatus::Interrupted;
                record.environments[index].detail =
                    "isolated environment requires a signed receipt import".into();
                record.status = UpgradeStatus::Interrupted;
            } else {
                apply_plan(ctx, &plan.id, authorization).await?;
                mark_applied(&mut record, index, "isolated receipt imported and applied");
            }
        }
    }
    if record
        .environments
        .iter()
        .all(|environment| environment.status == UpgradeEnvironmentStatus::Applied)
    {
        record.status = UpgradeStatus::Succeeded;
    } else if !matches!(
        record.status,
        UpgradeStatus::Interrupted | UpgradeStatus::Conflicted | UpgradeStatus::Failed
    ) {
        record.status = summarize(&record);
    }
    persist(ctx, &record).await?;
    Ok(record)
}

pub async fn bind_isolated_bundle(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    bundle: &crate::offline_bundle::BundleEnvelope,
    trust_roots: &crate::release_signing::TrustRoots,
) -> Result<UpgradeRecord> {
    let verified = bundle.verify(
        trust_roots,
        crate::ontology::NS,
        environment,
        crate::now_millis(),
    )?;
    let bundle_digest = verified.digest().to_string();
    let mut record = load_upgrade(ctx, name).await?;
    revalidate(&record, ctx).await?;
    let index = env_index(&record, environment)?;
    if record.environments[index].class != ConnectivityClass::Isolated {
        bail!("environment {environment} is not isolated");
    }
    let expected_plan = record.environments[index]
        .plan_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("isolated environment {environment} has no plan"))?;
    if verified.statement().plan_id != expected_plan {
        bail!(
            "offline bundle plan {} does not match upgrade plan {expected_plan}",
            verified.statement().plan_id
        );
    }
    if let Some(existing) = record.environments[index]
        .isolated
        .as_ref()
        .filter(|evidence| evidence.bundle_digest != bundle_digest)
    {
        bail!(
            "isolated bundle digest conflict: stored {} vs {bundle_digest}",
            existing.bundle_digest
        );
    }
    record.environments[index].isolated = Some(IsolatedEvidence {
        bundle_digest,
        receipt_digest: record.environments[index]
            .isolated
            .as_ref()
            .and_then(|evidence| evidence.receipt_digest.clone()),
    });
    record.environments[index].detail = "verified offline bundle bound".into();
    persist(ctx, &record).await?;
    Ok(record)
}

pub async fn import_isolated_receipt(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    receipt: &crate::offline_bundle::ReceiptEnvelope,
    bundle: &crate::offline_bundle::BundleEnvelope,
    trust_roots: &crate::release_signing::TrustRoots,
) -> Result<UpgradeRecord> {
    if receipt.key_id == bundle.key_id {
        bail!("offline receipt must not be signed by the bundle exporter");
    }
    let scope = crate::offline_bundle::ReceiptTrustScope {
        tenant_id: crate::ontology::NS.into(),
        environment_id: environment.into(),
        runtime_id: receipt.statement.runtime_id.clone(),
        key_id: receipt.key_id.clone(),
    };
    let verified_bundle = bundle.verify(
        trust_roots,
        crate::ontology::NS,
        environment,
        crate::now_millis(),
    )?;
    let verified_receipt =
        receipt.verify(trust_roots, &scope, &verified_bundle, crate::now_millis())?;
    if !verified_receipt.statement().succeeded
        || verified_receipt
            .statement()
            .receipts
            .iter()
            .any(|step| !step.succeeded)
    {
        bail!("offline receipt is not a successful completion");
    }
    let bundle_digest = verified_bundle.digest().to_string();
    let receipt_digest = verified_receipt.statement().digest()?;
    let mut record = load_upgrade(ctx, name).await?;
    revalidate(&record, ctx).await?;
    let index = env_index(&record, environment)?;
    if record.environments[index].class != ConnectivityClass::Isolated {
        bail!("environment {environment} is not isolated");
    }
    let Some(evidence) = record.environments[index].isolated.clone() else {
        bail!("isolated environment {environment} has no bound bundle");
    };
    if evidence.bundle_digest != bundle_digest {
        bail!("imported receipt does not bind the stored offline bundle");
    }
    match evidence.receipt_digest {
        Some(existing) if existing == receipt_digest => {
            record.environments[index].detail =
                "duplicate isolated receipt import is idempotent".into();
        }
        Some(existing) => {
            record.environments[index].status = UpgradeEnvironmentStatus::Conflicted;
            record.environments[index].detail =
                format!("conflicting isolated receipt cannot overwrite first accepted {existing}");
            record.status = UpgradeStatus::Conflicted;
            persist(ctx, &record).await?;
            bail!("{}", record.environments[index].detail);
        }
        None => {
            record.environments[index].isolated = Some(IsolatedEvidence {
                bundle_digest,
                receipt_digest: Some(receipt_digest),
            });
            record.environments[index].detail = "isolated receipt accepted".into();
        }
    }
    persist(ctx, &record).await?;
    Ok(record)
}

pub async fn rollback_upgrade(
    ctx: &mut Ctx,
    name: &str,
    authorization: ExecutionAuthorization<'_>,
) -> Result<UpgradeRecord> {
    let mut record = load_upgrade(ctx, name).await?;
    for index in (0..record.environments.len()).rev() {
        if record.environments[index].status != UpgradeEnvironmentStatus::Applied {
            continue;
        }
        let environment = record.environments[index].name.clone();
        match plan::rollback_step(ctx, &environment, &record.product).await {
            Ok(step) => {
                let rollback = plan::create_from_steps(ctx, &environment, vec![step]).await?;
                match apply_plan(ctx, &rollback.id, authorization).await {
                    Ok(()) => {
                        record.environments[index].status = UpgradeEnvironmentStatus::RolledBack;
                        record.environments[index].detail =
                            "rolled back through Tenkai plan".into();
                    }
                    Err(error) => {
                        record.environments[index].status =
                            UpgradeEnvironmentStatus::RecoveryRequired;
                        record.environments[index].detail =
                            format!("rollback failed; recovery-required: {error}");
                        record.status = UpgradeStatus::RecoveryRequired;
                        persist(ctx, &record).await?;
                        return Ok(record);
                    }
                }
            }
            Err(error) => {
                record.environments[index].status = UpgradeEnvironmentStatus::RecoveryRequired;
                record.environments[index].detail =
                    format!("rollback plan unavailable; recovery-required: {error}");
                record.status = UpgradeStatus::RecoveryRequired;
                persist(ctx, &record).await?;
                return Ok(record);
            }
        }
    }
    record.status = UpgradeStatus::RolledBack;
    persist(ctx, &record).await?;
    Ok(record)
}

fn mark_applied(record: &mut UpgradeRecord, index: usize, detail: &str) {
    record.environments[index].status = UpgradeEnvironmentStatus::Applied;
    record.environments[index].detail = detail.into();
}

fn env_index(record: &UpgradeRecord, environment: &str) -> Result<usize> {
    record
        .environments
        .iter()
        .position(|candidate| candidate.name == environment)
        .ok_or_else(|| anyhow::anyhow!("upgrade does not include environment {environment}"))
}

fn summarize(record: &UpgradeRecord) -> UpgradeStatus {
    if record
        .environments
        .iter()
        .any(|environment| environment.status == UpgradeEnvironmentStatus::RecoveryRequired)
    {
        UpgradeStatus::RecoveryRequired
    } else if record
        .environments
        .iter()
        .any(|environment| environment.status == UpgradeEnvironmentStatus::Conflicted)
    {
        UpgradeStatus::Conflicted
    } else if record
        .environments
        .iter()
        .any(|environment| environment.status == UpgradeEnvironmentStatus::Interrupted)
    {
        UpgradeStatus::Interrupted
    } else if record
        .environments
        .iter()
        .all(|environment| environment.status == UpgradeEnvironmentStatus::Applied)
    {
        UpgradeStatus::Succeeded
    } else if record
        .environments
        .iter()
        .all(|environment| environment.status == UpgradeEnvironmentStatus::RolledBack)
    {
        UpgradeStatus::RolledBack
    } else {
        UpgradeStatus::Running
    }
}

struct ReleasePin {
    release_id: String,
    release_digest: String,
    artifact_digest: String,
}

async fn resolve_release_pin(ctx: &mut Ctx, spec: &UpgradeSpec) -> Result<ReleasePin> {
    let rid = release_id(&spec.product, &spec.version);
    let release = ctx.get(&rid).await?.ok_or_else(|| {
        anyhow::anyhow!("release {}@{} is not published", spec.product, spec.version)
    })?;
    if crate::catalog::release_is_recalled(ctx, &rid).await? {
        bail!("release {rid} is recalled and cannot admit an upgrade");
    }
    let release_digest = release
        .properties
        .get("digest")
        .cloned()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("release {rid} is missing its manifest digest"))?;
    let artifact_digest = release
        .properties
        .get("artifact_digest")
        .cloned()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("release {rid} is missing its artifact digest"))?;
    let channel = ctx
        .get(&channel_id(&spec.product, &spec.channel))
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("channel {}/{} does not exist", spec.product, spec.channel)
        })?;
    if channel.kind != KIND_CHANNEL {
        bail!(
            "channel {}/{} has conflicting catalog identity",
            spec.product,
            spec.channel
        );
    }
    let head = channel
        .properties
        .get("current_release")
        .cloned()
        .unwrap_or_default();
    if head != rid {
        bail!(
            "channel {}/{} no longer points at {rid}",
            spec.product,
            spec.channel
        );
    }
    Ok(ReleasePin {
        release_id: rid,
        release_digest,
        artifact_digest,
    })
}

async fn revalidate(record: &UpgradeRecord, ctx: &mut Ctx) -> Result<()> {
    let spec = UpgradeSpec {
        name: record.name.clone(),
        product: record.product.clone(),
        version: record.version.clone(),
        channel: record.channel.clone(),
        environments: record
            .environments
            .iter()
            .map(|environment| environment.name.clone())
            .collect(),
    };
    let pin = resolve_release_pin(ctx, &spec).await?;
    if pin.release_digest != record.release_digest || pin.artifact_digest != record.artifact_digest
    {
        bail!(
            "pinned release content changed under upgrade {}",
            record.name
        );
    }
    for environment in &record.environments {
        let class = connectivity_class(ctx, &environment.name).await?;
        if class != environment.class {
            bail!(
                "environment {} connectivity class changed from {} to {}",
                environment.name,
                environment.class.as_str(),
                class.as_str()
            );
        }
    }
    Ok(())
}

async fn ensure_plan(ctx: &mut Ctx, record: &UpgradeRecord, environment: &str) -> Result<Plan> {
    if let Some(plan_id) = record
        .environments
        .iter()
        .find(|candidate| candidate.name == environment)
        .and_then(|candidate| candidate.plan_id.clone())
    {
        return plan::load(ctx, &plan_id).await;
    }
    plan::create(ctx, environment).await
}

async fn apply_plan(
    ctx: &mut Ctx,
    plan_id: &str,
    authorization: ExecutionAuthorization<'_>,
) -> Result<()> {
    apply::execute_with_options(
        ctx,
        plan_id,
        ExecutionOptions {
            skip_gates: false,
            emergency_reason: None,
            authorization,
            software_executor: crate::software_executor::selected_software_executor()
                .map(std::sync::Arc::from),
            delivery_adapter: None,
            delivery_fence: None,
        },
    )
    .await?;
    let plan = plan::load(ctx, plan_id).await?;
    if plan.state == PlanState::Failed {
        bail!("plan {plan_id} failed during connectivity-class apply");
    }
    Ok(())
}

async fn current_generation(ctx: &mut Ctx, environment: &str) -> Result<u64> {
    Ok(apply::inspect_environment_lease(ctx, environment)
        .await?
        .generation
        .unwrap_or(1))
}

fn identity_digest(spec: &UpgradeSpec, pin: &ReleasePin) -> Result<String> {
    let mut payload = Vec::new();
    for value in [
        spec.name.as_bytes(),
        spec.product.as_bytes(),
        spec.version.as_bytes(),
        spec.channel.as_bytes(),
        pin.release_id.as_bytes(),
        pin.release_digest.as_bytes(),
        pin.artifact_digest.as_bytes(),
    ] {
        crate::signature_verification::push_len_prefixed(&mut payload, value);
    }
    payload.extend_from_slice(&(spec.environments.len() as u64).to_be_bytes());
    for environment in &spec.environments {
        crate::signature_verification::push_len_prefixed(&mut payload, environment.as_bytes());
    }
    Ok(format!("sha256:{:x}", Sha256::digest(payload)))
}

fn upgrade_object(record: &UpgradeRecord) -> Result<Object> {
    let now = crate::now_millis();
    Ok(Object {
        id: record.id.clone(),
        kind: KIND_CONNECTIVITY_UPGRADE.into(),
        name: record.name.clone(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("name".into(), record.name.clone()),
            ("identity_digest".into(), record.identity_digest.clone()),
            ("product".into(), record.product.clone()),
            ("version".into(), record.version.clone()),
            ("channel".into(), record.channel.clone()),
            ("status".into(), record.status.as_str().into()),
            ("record".into(), serde_json::to_string(record)?),
        ]),
        created: record.created_at,
        updated: now,
    })
}

fn record_from_object(object: &Object) -> Result<UpgradeRecord> {
    if object.kind != KIND_CONNECTIVITY_UPGRADE {
        bail!("object {} is not a connectivity upgrade", object.id);
    }
    let raw = object
        .properties
        .get("record")
        .ok_or_else(|| anyhow::anyhow!("upgrade {} is missing its canonical record", object.id))?;
    let record: UpgradeRecord = serde_json::from_str(raw)
        .with_context(|| format!("decoding upgrade record {}", object.id))?;
    if record.format_version != UPGRADE_FORMAT_VERSION {
        bail!(
            "upgrade {} has unsupported format version {}",
            record.id,
            record.format_version
        );
    }
    Ok(record)
}

async fn persist(ctx: &mut Ctx, record: &UpgradeRecord) -> Result<()> {
    let mut object = upgrade_object(record)?;
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(())
}

pub fn export_isolated_bundle(
    environment: &str,
    plan_id: &str,
    release_id: &str,
    payload: &[u8],
    exporter: &ed25519_dalek::SigningKey,
    now_unix_ms: i64,
) -> Result<crate::offline_bundle::BundleEnvelope> {
    let plan_bytes = format!("{{\"plan\":\"{plan_id}\"}}").into_bytes();
    let approval_bytes = format!("{{\"approval\":\"{plan_id}\"}}").into_bytes();
    let plan_digest = format!("sha256:{:x}", Sha256::digest(&plan_bytes));
    let approval_digest = format!("sha256:{:x}", Sha256::digest(&approval_bytes));
    let safe_release = release_id.replace([':', '@'], "-");
    let mut payloads = BTreeMap::new();
    payloads.insert(
        format!("releases/{safe_release}/payload.bin"),
        ("application/octet-stream".into(), payload.to_vec()),
    );
    payloads.insert(
        format!("plans/{plan_id}.json"),
        ("application/json".into(), plan_bytes),
    );
    payloads.insert(
        format!("approvals/{plan_id}.json"),
        ("application/json".into(), approval_bytes),
    );
    crate::offline_bundle::BundleEnvelope::create(
        crate::offline_bundle::BundleStatement {
            tenant_id: crate::ontology::NS.into(),
            environment_id: environment.into(),
            plan_id: plan_id.into(),
            plan_digest,
            approval_digest,
            release_ids: vec![safe_release],
            exporter_identity: "exporter".into(),
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: now_unix_ms.saturating_add(3_600_000),
            entries: Vec::new(),
        },
        payloads,
        exporter,
    )
}

pub fn export_isolated_receipt(
    bundle: &crate::offline_bundle::VerifiedBundle,
    runtime: &ed25519_dalek::SigningKey,
    runtime_id: &str,
    step_id: &str,
    result: &[u8],
    now_unix_ms: i64,
) -> Result<crate::offline_bundle::ReceiptEnvelope> {
    export_isolated_receipt_outcome(
        bundle,
        runtime,
        runtime_id,
        step_id,
        result,
        true,
        now_unix_ms,
    )
}

pub fn export_isolated_receipt_outcome(
    bundle: &crate::offline_bundle::VerifiedBundle,
    runtime: &ed25519_dalek::SigningKey,
    runtime_id: &str,
    step_id: &str,
    result: &[u8],
    succeeded: bool,
    now_unix_ms: i64,
) -> Result<crate::offline_bundle::ReceiptEnvelope> {
    crate::offline_bundle::ReceiptEnvelope::create(
        crate::offline_bundle::ReceiptStatement {
            bundle_digest: bundle.digest().into(),
            tenant_id: bundle.statement().tenant_id.clone(),
            environment_id: bundle.statement().environment_id.clone(),
            runtime_id: runtime_id.into(),
            plan_id: bundle.statement().plan_id.clone(),
            plan_digest: bundle.statement().plan_digest.clone(),
            generation: 1,
            succeeded,
            detail: if succeeded {
                "offline execution completed".into()
            } else {
                "offline execution failed".into()
            },
            completed_at_unix_ms: now_unix_ms,
            receipts: vec![crate::offline_bundle::OfflineStepReceipt {
                receipt_id: crate::offline_bundle::offline_receipt_id(
                    &bundle.statement().environment_id,
                    &bundle.statement().plan_id,
                    step_id,
                    1,
                ),
                step_id: step_id.into(),
                attempt: 1,
                succeeded,
                result_digest: format!("sha256:{:x}", Sha256::digest(result)),
            }],
        },
        runtime,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::PublishOptions;
    use crate::client::Ctx;

    use crate::release_signing::{TRUST_ROOT_VERSION, TrustedSigner};
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tenkai-upgrade-{name}-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    async fn published_software(ctx: &mut Ctx, root: &std::path::Path, version: &str) {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "edge-app"
version = "{version}"

[deploy]
install = "true"
"#
            ),
        )
        .unwrap();
        let keys = root.join("keys");
        let signature = dir.join("release.sig.json");
        let trust = dir.join("release-trust.toml");
        crate::dev_sign::sign_release(&keys, &dir.join("tenkai.toml"), &signature, &trust).unwrap();
        crate::catalog::publish(
            ctx,
            &dir.join("tenkai.toml"),
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                allow_unsigned_development: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    async fn prepare_env(
        ctx: &mut Ctx,
        name: &str,
        class: ConnectivityClass,
        actor: &crate::auth_context::AuthenticatedRequestContext,
    ) {
        plan::env_add(ctx, name, "fixture").await.unwrap();
        set_connectivity_class(ctx, name, class).await.unwrap();
        crate::catalog::promote(ctx, actor, "edge-app@1.0.0", "stable")
            .await
            .ok();
        plan::subscribe(ctx, name, "edge-app", "stable")
            .await
            .unwrap();
    }

    async fn sign_plans(
        keys: &std::path::Path,
        db: &std::path::Path,
        approval_dir: &std::path::Path,
        trust: &std::path::Path,
        record: &UpgradeRecord,
    ) {
        std::fs::create_dir_all(approval_dir).unwrap();
        for environment in &record.environments {
            let Some(plan_id) = &environment.plan_id else {
                continue;
            };
            let envelope = approval_dir.join(format!("{}.json", plan_id.replace(':', "_")));
            if envelope.exists() {
                continue;
            }
            crate::dev_sign::sign_plan_approval(keys, db, plan_id, &envelope, trust, 3600)
                .await
                .unwrap();
        }
    }

    fn approval_path(
        record: &UpgradeRecord,
        environment: &str,
        approval_dir: &std::path::Path,
    ) -> std::path::PathBuf {
        let plan_id = record
            .environments
            .iter()
            .find(|candidate| candidate.name == environment)
            .and_then(|candidate| candidate.plan_id.clone())
            .unwrap();
        approval_dir.join(format!("{}.json", plan_id.replace(':', "_")))
    }

    fn isolated_trust_roots(
        exporter: &SigningKey,
        runtime: Option<&SigningKey>,
    ) -> crate::release_signing::TrustRoots {
        let mut signers = vec![TrustedSigner {
            key_id: crate::signature_verification::key_id(&exporter.verifying_key().to_bytes()),
            identity: "exporter".into(),
            public_key: base64::engine::general_purpose::STANDARD
                .encode(exporter.verifying_key().to_bytes()),
        }];
        if let Some(runtime) = runtime {
            signers.push(TrustedSigner {
                key_id: crate::signature_verification::key_id(&runtime.verifying_key().to_bytes()),
                identity: "airgap-runtime".into(),
                public_key: base64::engine::general_purpose::STANDARD
                    .encode(runtime.verifying_key().to_bytes()),
            });
        }
        crate::release_signing::TrustRoots {
            version: TRUST_ROOT_VERSION,
            signers,
        }
    }

    #[tokio::test]
    async fn connected_intermittent_and_isolated_complete_one_signed_upgrade() {
        let root = temp_root("three-class");
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        let actor = crate::auth_context::test_management_context("upgrade");
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        prepare_env(&mut ctx, "site-a", ConnectivityClass::Connected, &actor).await;
        prepare_env(&mut ctx, "site-b", ConnectivityClass::Intermittent, &actor).await;
        prepare_env(&mut ctx, "site-c", ConnectivityClass::Isolated, &actor).await;

        let spec = UpgradeSpec {
            name: "fleet-1".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["site-a".into(), "site-b".into(), "site-c".into()],
        };
        let first = start_or_resume(&mut ctx, &spec).await.unwrap();
        let replay = start_or_resume(&mut ctx, &spec).await.unwrap();
        assert_eq!(first.identity_digest, replay.identity_digest);
        let keys = root.join("1.0.0").parent().unwrap().join("keys");
        let approval_dir = root.join("approvals");
        let trust = root.join("1.0.0").join("release-trust.toml");
        sign_plans(
            &keys,
            &root.join("tenkai.db"),
            &approval_dir,
            &trust,
            &first,
        )
        .await;
        let site_a = approval_path(&first, "site-a", &approval_dir);
        let connected = advance(
            &mut ctx,
            "fleet-1",
            ExecutionAuthorization::Signed {
                approval: &site_a,
                trust_roots: &trust,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            connected.environments[0].status,
            UpgradeEnvironmentStatus::Applied
        );

        let interrupted = interrupt_transfer(&mut ctx, "fleet-1", "site-b")
            .await
            .unwrap();
        assert_eq!(
            interrupted.environments[1].status,
            UpgradeEnvironmentStatus::Interrupted
        );
        resume_transfer(&mut ctx, "fleet-1", "site-b")
            .await
            .unwrap();
        let site_b = approval_path(&first, "site-b", &approval_dir);
        let resumed = advance(
            &mut ctx,
            "fleet-1",
            ExecutionAuthorization::Signed {
                approval: &site_b,
                trust_roots: &trust,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            resumed.environments[1].status,
            UpgradeEnvironmentStatus::Applied
        );

        let site_c = approval_path(&first, "site-c", &approval_dir);
        let isolated = advance(
            &mut ctx,
            "fleet-1",
            ExecutionAuthorization::Signed {
                approval: &site_c,
                trust_roots: &trust,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            isolated.environments[2].status,
            UpgradeEnvironmentStatus::Interrupted
        );
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let runtime = SigningKey::from_bytes(&[9; 32]);
        let bundle = export_isolated_bundle(
            "site-c",
            isolated.environments[2]
                .plan_id
                .as_deref()
                .unwrap_or("pending"),
            &isolated.release_id,
            b"immutable payload",
            &exporter,
            crate::now_millis(),
        )
        .unwrap();
        let roots = isolated_trust_roots(&exporter, Some(&runtime));
        bind_isolated_bundle(&mut ctx, "fleet-1", "site-c", &bundle, &roots)
            .await
            .unwrap();
        let verified = bundle
            .verify(&roots, crate::ontology::NS, "site-c", crate::now_millis())
            .unwrap();
        let receipt = export_isolated_receipt(
            &verified,
            &runtime,
            "runtime-1",
            "step-1",
            b"installed",
            crate::now_millis(),
        )
        .unwrap();
        import_isolated_receipt(&mut ctx, "fleet-1", "site-c", &receipt, &bundle, &roots)
            .await
            .unwrap();
        let finished = advance(
            &mut ctx,
            "fleet-1",
            ExecutionAuthorization::Signed {
                approval: &site_c,
                trust_roots: &trust,
            },
        )
        .await
        .unwrap();
        assert_eq!(finished.status, UpgradeStatus::Succeeded);
        assert!(
            finished
                .environments
                .iter()
                .all(|environment| { environment.status == UpgradeEnvironmentStatus::Applied })
        );
        let status = format_upgrade(&finished);
        assert!(status.contains("site-a connected applied"));
        assert!(status.contains("site-b intermittent applied"));
        assert!(status.contains("site-c isolated applied"));

        let conflicting = export_isolated_receipt(
            &verified,
            &runtime,
            "runtime-1",
            "step-1",
            b"different result",
            crate::now_millis(),
        )
        .unwrap();
        let conflict =
            import_isolated_receipt(&mut ctx, "fleet-1", "site-c", &conflicting, &bundle, &roots)
                .await
                .unwrap_err()
                .to_string();
        assert!(
            conflict.contains("conflicting isolated receipt"),
            "{conflict}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn unverified_isolated_bundle_and_receipt_are_rejected_by_the_coordinator() {
        let root = temp_root("bogus-archive");
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        let actor = crate::auth_context::test_management_context("bogus");
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        prepare_env(&mut ctx, "site-c", ConnectivityClass::Isolated, &actor).await;
        let spec = UpgradeSpec {
            name: "fleet-bogus".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["site-c".into()],
        };
        let started = start_or_resume(&mut ctx, &spec).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let runtime = SigningKey::from_bytes(&[9; 32]);
        let bundle = export_isolated_bundle(
            "site-c",
            started.environments[0]
                .plan_id
                .as_deref()
                .unwrap_or("pending"),
            &started.release_id,
            b"immutable payload",
            &exporter,
            crate::now_millis(),
        )
        .unwrap();
        let roots = isolated_trust_roots(&exporter, Some(&runtime));
        let mut forged = bundle.clone();
        forged.signature = base64::engine::general_purpose::STANDARD.encode([0_u8; 64]);
        let forged_err = bind_isolated_bundle(&mut ctx, "fleet-bogus", "site-c", &forged, &roots)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            forged_err.contains("signature")
                || forged_err.contains("verify")
                || forged_err.contains("offline bundle"),
            "{forged_err}"
        );
        let wrong_env = export_isolated_bundle(
            "other-site",
            started.environments[0]
                .plan_id
                .as_deref()
                .unwrap_or("pending"),
            &started.release_id,
            b"immutable payload",
            &exporter,
            crate::now_millis(),
        )
        .unwrap();
        let scoped = bind_isolated_bundle(&mut ctx, "fleet-bogus", "site-c", &wrong_env, &roots)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            scoped.contains("tenant") || scoped.contains("environment") || scoped.contains("scope"),
            "{scoped}"
        );

        bind_isolated_bundle(&mut ctx, "fleet-bogus", "site-c", &bundle, &roots)
            .await
            .unwrap();
        let verified = bundle
            .verify(&roots, crate::ontology::NS, "site-c", crate::now_millis())
            .unwrap();
        let mut bad_receipt = export_isolated_receipt(
            &verified,
            &runtime,
            "runtime-1",
            "step-1",
            b"installed",
            crate::now_millis(),
        )
        .unwrap();
        bad_receipt.signature = base64::engine::general_purpose::STANDARD.encode([1_u8; 64]);
        let receipt_err = import_isolated_receipt(
            &mut ctx,
            "fleet-bogus",
            "site-c",
            &bad_receipt,
            &bundle,
            &roots,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            receipt_err.contains("signature")
                || receipt_err.contains("verify")
                || receipt_err.contains("offline receipt"),
            "{receipt_err}"
        );
        let failed = export_isolated_receipt_outcome(
            &verified,
            &runtime,
            "runtime-1",
            "step-1",
            b"failed",
            false,
            crate::now_millis(),
        )
        .unwrap();
        let failed_err =
            import_isolated_receipt(&mut ctx, "fleet-bogus", "site-c", &failed, &bundle, &roots)
                .await
                .unwrap_err()
                .to_string();
        assert!(
            failed_err.contains("not a successful completion"),
            "{failed_err}"
        );
        let exporter_signed = export_isolated_receipt(
            &verified,
            &exporter,
            "runtime-1",
            "step-1",
            b"installed",
            crate::now_millis(),
        )
        .unwrap();
        let exporter_err = import_isolated_receipt(
            &mut ctx,
            "fleet-bogus",
            "site-c",
            &exporter_signed,
            &bundle,
            &roots,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            exporter_err.contains("must not be signed by the bundle exporter"),
            "{exporter_err}"
        );
        let other_plan = export_isolated_bundle(
            "site-c",
            "other-plan",
            &started.release_id,
            b"immutable payload",
            &exporter,
            crate::now_millis(),
        )
        .unwrap();
        let plan_err = bind_isolated_bundle(&mut ctx, "fleet-bogus", "site-c", &other_plan, &roots)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            plan_err.contains("does not match upgrade plan"),
            "{plan_err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn recalled_release_and_unknown_class_fail_closed() {
        let root = temp_root("fail-closed");
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        let actor = crate::auth_context::test_management_context("deny");
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "site-a", "fixture").await.unwrap();
        let unknown = ConnectivityClass::parse("modem").unwrap_err().to_string();
        assert!(unknown.contains("unknown connectivity class"), "{unknown}");
        set_connectivity_class(&mut ctx, "site-a", ConnectivityClass::Connected)
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "site-a", "edge-app", "stable")
            .await
            .unwrap();
        crate::catalog::recall(&mut ctx, &actor, "edge-app@1.0.0")
            .await
            .unwrap();
        let spec = UpgradeSpec {
            name: "denied".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["site-a".into()],
        };
        let err = start_or_resume(&mut ctx, &spec)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("recalled"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn rollback_uses_tenkai_owned_plan() {
        let root = temp_root("rollback");
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        published_software(&mut ctx, &root, "1.1.0").await;
        let actor = crate::auth_context::test_management_context("rollback");
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "local", "fixture").await.unwrap();
        set_connectivity_class(&mut ctx, "local", ConnectivityClass::Connected)
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "local", "edge-app", "stable")
            .await
            .unwrap();
        let local_auth = ExecutionAuthorization::LocalDevelopment {
            reason: "connectivity upgrade e2e",
        };
        let baseline = plan::create(&mut ctx, "local").await.unwrap();
        apply_plan(&mut ctx, &baseline.id, local_auth)
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.1.0", "stable")
            .await
            .unwrap();
        let spec = UpgradeSpec {
            name: "rb-1".into(),
            product: "edge-app".into(),
            version: "1.1.0".into(),
            channel: "stable".into(),
            environments: vec!["local".into()],
        };
        start_or_resume(&mut ctx, &spec).await.unwrap();
        advance(&mut ctx, "rb-1", local_auth).await.unwrap();
        let rolled = rollback_upgrade(&mut ctx, "rb-1", local_auth)
            .await
            .unwrap();
        assert!(
            matches!(
                rolled.status,
                UpgradeStatus::RolledBack | UpgradeStatus::RecoveryRequired
            ),
            "{:?}",
            rolled.status
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
