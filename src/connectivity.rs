//! Connectivity-class upgrade coordinator (ADR 0020).
//!
//! One Tenkai-owned upgrade carries a signed release and approved plan across
//! connected, intermittent, and isolated environments. Class adapters never
//! become a second executor, promoter, or recovery store.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
use crate::plan::{self, Action, Plan, PlanState};

pub const UPGRADE_FORMAT_VERSION: u32 = 1;
pub const CONNECTIVITY_CLASS_PROPERTY: &str = "connectivity_class";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_digest: Option<String>,
    /// The import scanner's outcome, when `TENKAI_IMPORT_SCANNER` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<crate::import_scanner::ScanEvidence>,
    /// The accepted receipt itself, so the hub can hand it out again (#682).
    /// Absent for receipts imported before it was kept; importing the same
    /// receipt again stores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<crate::offline_bundle::ReceiptEnvelope>,
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

async fn interrupt_transfer_locked(
    ctx: &mut Ctx,
    held: &HeldEnvironments,
    name: &str,
    environment: &str,
) -> Result<UpgradeRecord> {
    let mut record = load_upgrade(ctx, name).await?;
    let base = record.clone();
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
    let record = persist(ctx, held, &base, &record).await?;
    Ok(record)
}

async fn resume_transfer_locked(
    ctx: &mut Ctx,
    held: &HeldEnvironments,
    name: &str,
    environment: &str,
) -> Result<UpgradeRecord> {
    let mut record = load_upgrade(ctx, name).await?;
    let base = record.clone();
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
        let record = persist(ctx, held, &base, &record).await?;
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
    let record = persist(ctx, held, &base, &record).await?;
    Ok(record)
}

async fn advance_locked(
    ctx: &mut Ctx,
    held: &HeldEnvironments,
    name: &str,
    target: &str,
    authorization: ExecutionAuthorization<'_>,
) -> Result<UpgradeRecord> {
    let mut record = load_upgrade(ctx, name).await?;
    let base = record.clone();
    revalidate(&record, ctx).await?;
    // The environment chosen before its lease was taken, if it still needs
    // work now that the record is read under that lease.
    let Some(index) = record.environments.iter().position(|environment| {
        environment.name == target
            && matches!(
                environment.status,
                UpgradeEnvironmentStatus::Pending | UpgradeEnvironmentStatus::Interrupted
            )
    }) else {
        record.status = summarize(&record);
        let record = persist(ctx, held, &base, &record).await?;
        return Ok(record);
    };
    record.status = UpgradeStatus::Running;
    let environment = record.environments[index].name.clone();
    let class = record.environments[index].class;
    held.ensure_held()?;
    let plan = ensure_plan(ctx, &record, &environment).await?;
    record.environments[index].plan_id = Some(plan.id.clone());
    match class {
        ConnectivityClass::Connected => {
            held.ensure_held()?;
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
                    let record = persist(ctx, held, &base, &record).await?;
                    bail!("{}", record.environments[index].detail);
                }
                Some(_) => {
                    held.ensure_held()?;
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
                held.ensure_held()?;
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
    let record = persist(ctx, held, &base, &record).await?;
    Ok(record)
}

/// The configured import scanner's verdict on a bundle whose signature
/// verifies, before anything is written. A refusal stops the import here.
fn scan_before_mutation(
    bundle: &crate::offline_bundle::BundleEnvelope,
    trust_roots: &crate::release_signing::TrustRoots,
    environment: &str,
    bundle_path: Option<&Path>,
) -> Result<
    Option<(
        crate::import_scanner::ScanEvidence,
        crate::import_scanner::ScanSnapshot,
    )>,
> {
    if crate::import_scanner::configured().is_none() {
        return Ok(None);
    }
    // Scan only media whose signature verifies against the current state.
    bundle.verify(
        trust_roots,
        crate::ontology::NS,
        environment,
        crate::now_millis(),
    )?;
    crate::import_scanner::scan_from_env(bundle, bundle_path)
}

/// The bundle digest bound to `environment` in upgrade `name`, if any.
pub async fn bound_bundle_digest(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
) -> Result<Option<String>> {
    let record = load_upgrade(ctx, name).await?;
    let index = env_index(&record, environment)?;
    Ok(record.environments[index]
        .isolated
        .as_ref()
        .map(|evidence| evidence.bundle_digest.clone()))
}

/// What binding a bundle would do, without writing anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BindPreview {
    pub bundle_digest: String,
    pub plan_id: String,
    pub release_ids: Vec<String>,
    /// True when the environment already has this bundle bound (a replay).
    pub already_bound: bool,
    /// True when the bundle carries a key revocation list to install.
    pub carries_revocations: bool,
    /// The import scanner's outcome, when one is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub scan: Option<crate::import_scanner::ScanEvidence>,
}

/// Check a bundle against an upgrade as [`bind_isolated_bundle`] does, with
/// no side effects: trust, scope and plan, every layer and weight chunk it
/// would import and the stores they need, and any revocation list it
/// carries, which is verified but not installed.
pub async fn preview_isolated_bundle(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    bundle: &crate::offline_bundle::BundleEnvelope,
    trust_roots: &crate::release_signing::TrustRoots,
    bundle_path: Option<&Path>,
) -> Result<BindPreview> {
    let verified = bundle.verify(
        trust_roots,
        crate::ontology::NS,
        environment,
        crate::now_millis(),
    )?;
    crate::offline_host_binaries::preflight(&verified)?;
    let (record, index, bundle_digest) =
        admit_isolated_bind(ctx, name, environment, &verified).await?;
    if crate::offline_bundle::stack_manifest(&verified)?.is_some() {
        crate::offline_bundle::preflight_full_stack(&verified, bundle_path)?;
    }
    // The content checks of the real bind, without storing anything.
    crate::offline_bundle::preflight_image_chunks(&verified, bundle_path)?;
    let env = crate::environment::environment(ctx, environment).await?;
    let mirrors = crate::oci_artifact::mirrors_from_properties(&env.properties);
    preflight_delta(ctx, &verified, &mirrors).await?;
    let layers: Vec<crate::oci_artifact::OciArtifactRef> =
        crate::offline_bundle::plan_artifact_layers(&verified, &mirrors)?
            .into_iter()
            .map(|(pull, _)| pull)
            .chain(crate::offline_bundle::plan_chunked_layers(
                &verified, &mirrors,
            )?)
            .collect();
    if !layers.is_empty() {
        let registry = crate::oci_artifact::selected_registry()?.ok_or_else(|| {
            anyhow::anyhow!("TENKAI_OCI_STORE is required to import offline artifact layers")
        })?;
        // A layer already stored with other bytes would refuse the real import.
        for pull in &layers {
            if let Some(stored) = registry.stored(pull)? {
                anyhow::ensure!(
                    stored,
                    "artifact digest {} is already stored with different bytes",
                    pull.digest
                );
            }
        }
    }
    crate::offline_chunk_store::preflight_weight_chunks_for_bundle(
        &verified,
        bundle_path,
        crate::offline_chunk_store::weight_cache_from_env()?.as_ref(),
        // A scanned import discards partial weights and reads every chunk.
        crate::import_scanner::configured().is_none(),
    )?;
    crate::key_revocation::preflight_bundle_revocations(bundle)?;
    let scan = crate::import_scanner::scan_from_env(bundle, bundle_path)?
        .map(|(evidence, _snapshot)| evidence);
    Ok(BindPreview {
        already_bound: record.environments[index]
            .isolated
            .as_ref()
            .is_some_and(|evidence| evidence.bundle_digest == bundle_digest),
        bundle_digest,
        plan_id: verified.statement().plan_id.clone(),
        release_ids: verified.statement().release_ids.clone(),
        carries_revocations: crate::key_revocation::bundle_carries_revocations(bundle),
        scan,
    })
}

/// The upgrade, environment index and bundle digest for a verified bundle,
/// once the environment is isolated, the plan matches, and no other bundle
/// is bound.
async fn admit_isolated_bind(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    verified: &crate::offline_bundle::VerifiedBundle,
) -> Result<(UpgradeRecord, usize, String)> {
    let bundle_digest = verified.digest().to_string();
    let record = load_upgrade(ctx, name).await?;
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
    Ok((record, index, bundle_digest))
}

/// Refuse a delta bundle (#635) unless its base release is in this site's
/// catalog and every layer and weight it relies on is held here.
async fn preflight_delta(
    ctx: &mut Ctx,
    verified: &crate::offline_bundle::VerifiedBundle,
    mirrors: &BTreeMap<String, String>,
) -> Result<()> {
    let Some((base, _)) = crate::offline_bundle::delta_base(verified)? else {
        return Ok(());
    };
    let (product, version) = crate::offline_bundle::base_release_parts(&base.base_release)?;
    if ctx.get(&release_id(product, version)).await?.is_none() {
        bail!(
            "base release {} is not in this site's catalog; import the base release first",
            base.base_release
        );
    }
    crate::offline_bundle::preflight_delta_base(
        verified,
        crate::oci_artifact::selected_registry()?.as_deref(),
        mirrors,
        crate::offline_chunk_store::weight_cache_from_env()?.as_ref(),
    )
}

#[allow(clippy::too_many_arguments)]
async fn bind_isolated_bundle_locked(
    ctx: &mut Ctx,
    held: &HeldEnvironments,
    name: &str,
    environment: &str,
    bundle: &crate::offline_bundle::BundleEnvelope,
    trust_roots: &crate::release_signing::TrustRoots,
    bundle_path: Option<&Path>,
    progress: Option<&crate::import_progress::ImportProgress>,
) -> Result<UpgradeRecord> {
    let scanned = scan_before_mutation(bundle, trust_roots, environment, bundle_path)?;
    // With a scanner, the import reads the snapshot it scanned.
    let bundle_path = match &scanned {
        Some((_, snapshot)) => Some(snapshot.archive()),
        None => bundle_path,
    };
    let scan = scanned.as_ref().map(|(evidence, _)| evidence.clone());
    // A bundle may carry key revocations; apply them before trusting it.
    held.ensure_held()?;
    crate::key_revocation::import_from_bundle(bundle)?;
    let verified = bundle.verify(
        trust_roots,
        crate::ontology::NS,
        environment,
        crate::now_millis(),
    )?;
    crate::offline_host_binaries::preflight(&verified)?;
    crate::exposure::preflight_verified_bundle(&verified, environment)?;
    let (mut record, index, bundle_digest) =
        admit_isolated_bind(ctx, name, environment, &verified).await?;
    let base = record.clone();
    if crate::offline_bundle::stack_manifest(&verified)?.is_some() {
        crate::offline_bundle::preflight_full_stack(&verified, bundle_path)?;
    }
    let env = crate::environment::environment(ctx, environment).await?;
    let mirrors = crate::oci_artifact::mirrors_from_properties(&env.properties);
    // Content collection waits until this import has stored everything.
    let _content = crate::content_inventory::ContentLock::shared_from_env().await?;
    preflight_delta(ctx, &verified, &mirrors).await?;
    held.ensure_held()?;
    crate::offline_bundle::import_artifact_layers_reporting(
        &verified,
        bundle_path,
        crate::oci_artifact::selected_registry()?.as_deref(),
        &mirrors,
        progress,
    )?;
    let weight_cache = crate::offline_chunk_store::weight_cache_from_env()?;
    if scan.is_some() {
        // Every weight must be in the scanned snapshot, even one cached.
        crate::offline_chunk_store::preflight_weight_chunks_for_bundle(
            &verified,
            bundle_path,
            weight_cache.as_ref(),
            false,
        )?;
        crate::offline_chunk_store::discard_partial_weights(&verified, weight_cache.as_ref())?;
    }
    crate::offline_chunk_store::import_weight_chunks_for_bundle_reporting(
        &verified,
        bundle_path,
        weight_cache.as_ref(),
        progress,
    )?;
    record.environments[index].isolated = Some(IsolatedEvidence {
        bundle_digest,
        receipt_digest: record.environments[index]
            .isolated
            .as_ref()
            .and_then(|evidence| evidence.receipt_digest.clone()),
        plan_digest: Some(verified.statement().plan_digest.clone()),
        approval_digest: Some(verified.statement().approval_digest.clone()),
        scan,
        receipt: record.environments[index]
            .isolated
            .as_ref()
            .and_then(|evidence| evidence.receipt.clone()),
    });
    record.environments[index].detail = "verified offline bundle bound".into();
    crate::exposure::import_from_verified_bundle(ctx, &verified, environment).await?;
    let record = persist(ctx, held, &base, &record).await?;
    crate::exposure::record_bundle_import(ctx, environment, crate::now_millis()).await?;
    Ok(record)
}

/// First-install an empty isolated environment from one signed bundle.
///
/// Completeness, the authenticated plan, and catalog payload are checked
/// before graph mutation. Artifact import happens before the upgrade record
/// is created so a failed import can be retried.
///
/// With `seed_registry` (`host[:port]`, #627), every image registry the
/// bundle names is mirrored to that one local registry: layers are stored
/// under it in `TENKAI_OCI_STORE`, which `tenkaictl registry serve` serves,
/// and later bundles bind through the same mirror.
pub async fn install_isolated_stack(
    ctx: &mut Ctx,
    spec: &UpgradeSpec,
    environment: &str,
    bundle: &crate::offline_bundle::BundleEnvelope,
    trust_roots: &crate::release_signing::TrustRoots,
    bundle_path: Option<&Path>,
    seed_registry: Option<&str>,
) -> Result<UpgradeRecord> {
    spec.validate()?;
    if spec.environments.len() != 1 || spec.environments[0] != environment {
        bail!("isolated first-install admits exactly one environment");
    }
    let scanned = scan_before_mutation(bundle, trust_roots, environment, bundle_path)?;
    // With a scanner, the import reads the snapshot it scanned.
    let bundle_path = match &scanned {
        Some((_, snapshot)) => Some(snapshot.archive()),
        None => bundle_path,
    };
    let scan = scanned.as_ref().map(|(evidence, _)| evidence.clone());
    // A bundle may carry key revocations; apply them before trusting it.
    crate::key_revocation::import_from_bundle(bundle)?;
    let verified = bundle.verify(
        trust_roots,
        crate::ontology::NS,
        environment,
        crate::now_millis(),
    )?;
    crate::offline_host_binaries::preflight(&verified)?;
    crate::exposure::preflight_verified_bundle(&verified, environment)?;
    if crate::offline_bundle::delta_base(&verified)?.is_some() {
        bail!("a first install needs a full bundle; this one is a delta against a base release");
    }
    crate::offline_bundle::preflight_full_stack(&verified, bundle_path)?;
    let expected_release = format!("{}@{}", spec.product, spec.version);
    let sanitized = expected_release.replace([':', '@'], "-");
    if !verified
        .statement()
        .release_ids
        .iter()
        .any(|id| id == &expected_release || id == &sanitized)
    {
        bail!("offline bundle does not include release {expected_release}");
    }
    let plan_path = format!("plans/{}.json", verified.statement().plan_id);
    let plan = plan::parse_authenticated(
        verified
            .entry(&plan_path)
            .with_context(|| format!("bundle is missing canonical plan entry {plan_path}"))?,
        &verified.statement().plan_id,
        environment,
    )?;
    require_first_install_plan(&plan, spec)?;
    require_connectivity_upgrade_schema(ctx).await?;
    let upgrade_id = connectivity_upgrade_id(&spec.name);
    let mirrors = bundle_layer_mirrors(&verified, seed_registry)?;
    if let Some(existing) = ctx.get(&upgrade_id).await? {
        return reinstall_isolated_stack(
            ctx,
            spec,
            environment,
            &verified,
            bundle_path,
            &mirrors,
            record_from_object(&existing)?,
        )
        .await;
    }
    if let Some(existing) = ctx.get(&env_id(environment)).await? {
        if existing.kind != crate::ontology::KIND_ENVIRONMENT {
            bail!("object {} is not an environment", existing.id);
        }
        if let Ok(class) = connectivity_class(ctx, environment).await
            && class != ConnectivityClass::Isolated
        {
            bail!(
                "isolated first-install cannot take over {environment} ({})",
                class.as_str()
            );
        }
    }
    let (_, pending_catalog) = admit_isolated_catalog(ctx, spec, &verified, &plan).await?;
    let _content = crate::content_inventory::ContentLock::shared_from_env().await?;
    let imported = (|| {
        crate::offline_bundle::import_artifact_layers(
            &verified,
            bundle_path,
            crate::oci_artifact::selected_registry()?.as_deref(),
            &mirrors,
        )?;
        let weight_cache = crate::offline_chunk_store::weight_cache_from_env()?;
        if scan.is_some() {
            // Every weight must be in the scanned snapshot, even one cached.
            crate::offline_chunk_store::preflight_weight_chunks_for_bundle(
                &verified,
                bundle_path,
                weight_cache.as_ref(),
                false,
            )?;
            crate::offline_chunk_store::discard_partial_weights(&verified, weight_cache.as_ref())?;
        }
        crate::offline_chunk_store::import_weight_chunks_for_bundle(
            &verified,
            bundle_path,
            weight_cache.as_ref(),
        )?;
        Ok::<_, anyhow::Error>(())
    })();
    if let Err(error) = imported {
        if let Some(pending) = pending_catalog {
            let _ = std::fs::remove_dir_all(&pending.root);
        }
        return Err(error);
    }
    let pin = if let Some(pending) = pending_catalog {
        commit_isolated_catalog(ctx, spec, &plan, pending, &mirrors).await?
    } else {
        crate::catalog::pin_isolated_channel(ctx, &spec.product, &spec.version, &spec.channel)
            .await?;
        let pin = resolve_release_pin(ctx, spec).await?;
        require_plan_matches_pin(&plan, spec, &pin)?;
        pin
    };
    crate::environment::env_add(ctx, environment, "isolated first install").await?;
    set_connectivity_class(ctx, environment, ConnectivityClass::Isolated).await?;
    for (registry, mirror) in &mirrors {
        crate::environment::set_artifact_mirror(ctx, environment, registry, mirror).await?;
    }
    crate::environment::subscribe(ctx, environment, &spec.product, &spec.channel).await?;
    plan::store(ctx, &plan).await?;
    let identity = identity_digest(spec, &pin)?;
    let now = crate::now_millis();
    let record = UpgradeRecord {
        format_version: UPGRADE_FORMAT_VERSION,
        id: upgrade_id,
        name: spec.name.clone(),
        identity_digest: identity,
        product: spec.product.clone(),
        version: spec.version.clone(),
        channel: spec.channel.clone(),
        release_id: pin.release_id,
        release_digest: pin.release_digest,
        artifact_digest: pin.artifact_digest,
        status: UpgradeStatus::Admitted,
        environments: vec![UpgradeEnvironmentRecord {
            name: environment.into(),
            class: ConnectivityClass::Isolated,
            status: UpgradeEnvironmentStatus::Pending,
            plan_id: Some(verified.statement().plan_id.clone()),
            detail: "verified offline bundle bound".into(),
            transfer: None,
            isolated: Some(IsolatedEvidence {
                bundle_digest: verified.digest().to_string(),
                receipt_digest: None,
                plan_digest: Some(verified.statement().plan_digest.clone()),
                approval_digest: Some(verified.statement().approval_digest.clone()),
                scan,
                receipt: None,
            }),
        }],
        created_at: now,
        updated_at: now,
    };
    crate::exposure::import_from_verified_bundle(ctx, &verified, environment).await?;
    ctx.create_once(upgrade_object(&record)?)
        .await
        .map_err(|status| anyhow::anyhow!("{status}"))?;
    crate::exposure::record_bundle_import(ctx, environment, now).await?;
    Ok(record)
}

/// A repeated first install of the same bundle (#627): nothing in the graph
/// changes, and the layers and weights are imported again, which stores
/// only what is missing, so a store lost or replaced since is refilled.
/// A different bundle, release or mirror is refused as before.
async fn reinstall_isolated_stack(
    ctx: &mut Ctx,
    spec: &UpgradeSpec,
    environment: &str,
    verified: &crate::offline_bundle::VerifiedBundle,
    bundle_path: Option<&Path>,
    mirrors: &BTreeMap<String, String>,
    record: UpgradeRecord,
) -> Result<UpgradeRecord> {
    let same_bundle = record.product == spec.product
        && record.version == spec.version
        && record.channel == spec.channel
        && matches!(
            record.environments.as_slice(),
            [only] if only.name == environment
                && only.isolated.as_ref().is_some_and(|evidence| evidence.bundle_digest == verified.digest())
        );
    if !same_bundle {
        bail!("upgrade {} already exists", spec.name);
    }
    let env = ctx
        .get(&env_id(environment))
        .await?
        .ok_or_else(|| anyhow::anyhow!("environment {environment} is not registered"))?;
    let persisted = crate::oci_artifact::mirrors_from_properties(&env.properties);
    if mirrors
        .iter()
        .any(|(registry, mirror)| persisted.get(registry) != Some(mirror))
    {
        bail!(
            "upgrade {} already exists with other artifact mirrors; change them with the environment's artifact mirror settings",
            spec.name
        );
    }
    let _content = crate::content_inventory::ContentLock::shared_from_env().await?;
    crate::offline_bundle::import_artifact_layers(
        verified,
        bundle_path,
        crate::oci_artifact::selected_registry()?.as_deref(),
        mirrors,
    )?;
    crate::offline_chunk_store::import_weight_chunks_for_bundle(
        verified,
        bundle_path,
        crate::offline_chunk_store::weight_cache_from_env()?.as_ref(),
    )?;
    crate::exposure::import_from_verified_bundle(ctx, verified, environment).await?;
    crate::exposure::record_bundle_import(ctx, environment, crate::now_millis()).await?;
    Ok(record)
}

async fn import_isolated_receipt_locked(
    ctx: &mut Ctx,
    held: &HeldEnvironments,
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
    let base = record.clone();
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
            if let Some(evidence) = record.environments[index].isolated.as_mut() {
                evidence.receipt.get_or_insert_with(|| receipt.clone());
            }
            record.environments[index].detail =
                "duplicate isolated receipt import is idempotent".into();
        }
        Some(existing) => {
            record.environments[index].status = UpgradeEnvironmentStatus::Conflicted;
            record.environments[index].detail =
                format!("conflicting isolated receipt cannot overwrite first accepted {existing}");
            record.status = UpgradeStatus::Conflicted;
            let record = persist(ctx, held, &base, &record).await?;
            bail!("{}", record.environments[index].detail);
        }
        None => {
            let previous = record.environments[index].isolated.clone();
            record.environments[index].isolated = Some(IsolatedEvidence {
                bundle_digest,
                receipt_digest: Some(receipt_digest),
                plan_digest: previous
                    .as_ref()
                    .and_then(|evidence| evidence.plan_digest.clone()),
                approval_digest: previous
                    .as_ref()
                    .and_then(|evidence| evidence.approval_digest.clone()),
                scan: previous.and_then(|evidence| evidence.scan),
                receipt: Some(receipt.clone()),
            });
            record.environments[index].detail = "isolated receipt accepted".into();
        }
    }
    let record = persist(ctx, held, &base, &record).await?;
    Ok(record)
}

async fn rollback_upgrade_locked(
    ctx: &mut Ctx,
    held: &HeldEnvironments,
    name: &str,
    locked: &[String],
    authorization: ExecutionAuthorization<'_>,
) -> Result<UpgradeRecord> {
    let mut record = load_upgrade(ctx, name).await?;
    let base = record.clone();
    for index in (0..record.environments.len()).rev() {
        if record.environments[index].status != UpgradeEnvironmentStatus::Applied
            || !locked.contains(&record.environments[index].name)
        {
            continue;
        }
        // Stop before the next environment's rollback if ownership is lost.
        held.ensure_held()?;
        let environment = record.environments[index].name.clone();
        match plan::rollback_step(ctx, &environment, &record.product).await {
            Ok(step) => {
                let rollback = plan::create_from_steps(ctx, &environment, vec![step]).await?;
                held.ensure_held()?;
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
                        let record = persist(ctx, held, &base, &record).await?;
                        return Ok(record);
                    }
                }
            }
            Err(error) => {
                record.environments[index].status = UpgradeEnvironmentStatus::RecoveryRequired;
                record.environments[index].detail =
                    format!("rollback plan unavailable; recovery-required: {error}");
                record.status = UpgradeStatus::RecoveryRequired;
                let record = persist(ctx, held, &base, &record).await?;
                return Ok(record);
            }
        }
    }
    record.status = UpgradeStatus::RolledBack;
    let record = persist(ctx, held, &base, &record).await?;
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

async fn published_release_pin(ctx: &mut Ctx, spec: &UpgradeSpec) -> Result<Option<ReleasePin>> {
    let rid = release_id(&spec.product, &spec.version);
    let Some(release) = ctx.get(&rid).await? else {
        return Ok(None);
    };
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
    Ok(Some(ReleasePin {
        release_id: rid,
        release_digest,
        artifact_digest,
    }))
}

async fn resolve_release_pin(ctx: &mut Ctx, spec: &UpgradeSpec) -> Result<ReleasePin> {
    let pin = published_release_pin(ctx, spec).await?.ok_or_else(|| {
        anyhow::anyhow!("release {}@{} is not published", spec.product, spec.version)
    })?;
    let rid = pin.release_id.clone();
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
    Ok(pin)
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
            model_runtime_executor: crate::model_runtime::selected_model_runtime_executor_factory(),
            worker_lifecycle: None,
            artifact_registry: crate::oci_artifact::selected_registry()?,
            delivery_adapter: None,
            delivery_fence: None,
        },
    )
    .await?;
    let plan = plan::load(ctx, plan_id).await?;
    if plan.state == PlanState::Failed {
        bail!(
            "plan {plan_id} failed during connectivity-class apply: {}",
            plan.status_detail
        );
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

/// Every upgrade record (#827).
pub async fn list_upgrades(ctx: &mut Ctx) -> Result<Vec<UpgradeRecord>> {
    ctx.list_kind(KIND_CONNECTIVITY_UPGRADE)
        .await?
        .iter()
        .map(record_from_object)
        .collect()
}

/// `(product, version)` of every upgrade that has not finished: its target
/// release must stay applicable here (#635).
pub async fn unfinished_upgrade_releases(ctx: &mut Ctx) -> Result<Vec<(String, String)>> {
    let mut releases = Vec::new();
    for object in ctx.list_kind(KIND_CONNECTIVITY_UPGRADE).await? {
        let record = record_from_object(&object)?;
        if !matches!(
            record.status,
            UpgradeStatus::Succeeded | UpgradeStatus::RolledBack
        ) {
            releases.push((record.product, record.version));
        }
    }
    Ok(releases)
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

fn require_first_install_plan(plan: &Plan, spec: &UpgradeSpec) -> Result<()> {
    if !matches!(plan.state, PlanState::Computed | PlanState::Blocked) {
        bail!(
            "canonical plan {} is not executable ({})",
            plan.id,
            plan.state
        );
    }
    let expected_release = release_id(&spec.product, &spec.version);
    if plan.inputs.len() != 1 || plan.steps.len() != 1 {
        bail!("canonical first-install plan must contain exactly one input and one step");
    }
    let Some(input) = plan
        .inputs
        .iter()
        .find(|input| input.product == spec.product)
    else {
        bail!("canonical plan does not name product {}", spec.product);
    };
    if input.channel != spec.channel
        || input.desired_version != spec.version
        || input.release_id != expected_release
    {
        bail!(
            "canonical plan does not target {}@{} on {}",
            spec.product,
            spec.version,
            spec.channel
        );
    }
    let Some(step) = plan.steps.iter().find(|step| step.product == spec.product) else {
        bail!("canonical plan has no step for {}", spec.product);
    };
    if step.action != Action::Install
        || step.from.is_some()
        || step.to != spec.version
        || step.release_id != expected_release
    {
        bail!(
            "canonical plan does not install {}@{}",
            spec.product,
            spec.version
        );
    }
    Ok(())
}

fn require_plan_matches_pin(plan: &Plan, spec: &UpgradeSpec, pin: &ReleasePin) -> Result<()> {
    require_first_install_plan(plan, spec)?;
    let matches_pin = |release_id: &str, release_digest: &str, artifact_digest: &str| {
        release_id == pin.release_id
            && release_digest == pin.release_digest
            && artifact_digest == pin.artifact_digest
    };
    if plan
        .inputs
        .iter()
        .filter(|input| input.product == spec.product)
        .any(|input| {
            !matches_pin(
                &input.release_id,
                &input.release_digest,
                &input.artifact_digest,
            )
        })
        || plan
            .steps
            .iter()
            .filter(|step| step.product == spec.product)
            .any(|step| {
                !matches_pin(
                    &step.release_id,
                    &step.release_digest,
                    &step.artifact_digest,
                )
            })
    {
        bail!(
            "canonical plan does not match published release {}",
            pin.release_id
        );
    }
    Ok(())
}

fn bundle_release_prefixes(spec: &UpgradeSpec) -> Vec<String> {
    let expected = format!("{}@{}", spec.product, spec.version);
    let sanitized = expected.replace([':', '@'], "-");
    vec![
        format!("releases/{expected}/"),
        format!("releases/{sanitized}/"),
    ]
}

fn bundle_release_manifest_path(
    verified: &crate::offline_bundle::VerifiedBundle,
    spec: &UpgradeSpec,
) -> Result<String> {
    for prefix in bundle_release_prefixes(spec) {
        let path = format!("{prefix}tenkai.toml");
        if verified.entry(&path).is_some() {
            return Ok(path);
        }
    }
    bail!(
        "offline bundle does not include a catalog manifest for {}@{}",
        spec.product,
        spec.version
    )
}

fn bundle_release_verification_paths(
    verified: &crate::offline_bundle::VerifiedBundle,
    spec: &UpgradeSpec,
) -> Result<(String, String)> {
    let prefix = bundle_release_manifest_path(verified, spec)?
        .rsplit_once('/')
        .map(|(dir, _)| format!("{dir}/"))
        .unwrap_or_default();
    let signature = format!("{prefix}release.sig.json");
    let trust = format!("{prefix}release-trust.toml");
    if verified.entry(&signature).is_none() || verified.entry(&trust).is_none() {
        bail!(
            "offline bundle does not include signed release verification for {}@{}",
            spec.product,
            spec.version
        );
    }
    Ok((signature, trust))
}

/// Each image registry of the bundle mapped to `seed_registry`, or to
/// itself when there is none.
fn bundle_layer_mirrors(
    verified: &crate::offline_bundle::VerifiedBundle,
    seed_registry: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    if let Some(seed) = seed_registry {
        crate::oci_artifact::validate_pull_registry("seed registry", seed)?;
    }
    let mut mirrors = BTreeMap::new();
    let Some(raw) = verified.entry(crate::offline_bundle::LAYER_INSTRUCTION_PATH) else {
        return Ok(mirrors);
    };
    let layers: crate::offline_bundle::OfflineArtifactLayerManifest = serde_json::from_slice(raw)?;
    for layer in &layers.layers {
        let mirror = seed_registry.unwrap_or(&layer.registry);
        mirrors.insert(layer.registry.clone(), mirror.to_string());
    }
    Ok(mirrors)
}

async fn require_isolated_channel_available(ctx: &mut Ctx, spec: &UpgradeSpec) -> Result<()> {
    let rid = release_id(&spec.product, &spec.version);
    let cid = channel_id(&spec.product, &spec.channel);
    let Some(existing) = ctx.get(&cid).await? else {
        return Ok(());
    };
    if existing.kind != KIND_CHANNEL {
        bail!(
            "channel {}/{} has conflicting catalog identity",
            spec.product,
            spec.channel
        );
    }
    let head = existing
        .properties
        .get("current_release")
        .cloned()
        .unwrap_or_default();
    if !head.is_empty() && head != rid {
        bail!(
            "channel {}/{} no longer points at {rid}",
            spec.product,
            spec.channel
        );
    }
    Ok(())
}

fn exclusive_private_dir() -> Result<std::path::PathBuf> {
    let parent = std::env::temp_dir();
    for _ in 0..16 {
        let root = parent.join(format!("tenkai-offline-catalog-{}", uuid::Uuid::new_v4()));
        match std::fs::create_dir(&root) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
                }
                return Ok(root);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("failed to create a private catalog staging directory")
}

fn create_private_ancestors(root: &std::path::Path, dest: &std::path::Path) -> Result<()> {
    let relative = dest
        .strip_prefix(root)
        .context("catalog staging path escaped")?;
    let mut current = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            current.push(component);
            if current.is_symlink() {
                bail!("catalog staging path {} is a symlink", current.display());
            }
            match std::fs::create_dir(&current) {
                Ok(()) => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        && current.is_dir()
                        && !current.is_symlink() => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn materialize_bundle_release(
    verified: &crate::offline_bundle::VerifiedBundle,
    spec: &UpgradeSpec,
    root: &std::path::Path,
) -> Result<()> {
    let manifest_path = bundle_release_manifest_path(verified, spec)?;
    let prefix = manifest_path
        .rsplit_once('/')
        .map(|(dir, _)| format!("{dir}/"))
        .unwrap_or_default();
    match std::fs::create_dir(root) {
        Ok(()) => {}
        Err(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists
                && root.is_dir()
                && !root.is_symlink() => {}
        Err(error) => return Err(error.into()),
    }
    for path in verified.paths() {
        let Some(relative) = path.strip_prefix(&prefix) else {
            continue;
        };
        if relative.is_empty()
            || relative.contains("..")
            || std::path::Path::new(relative).is_absolute()
        {
            bail!("offline catalog entry {path} is not a canonical relative path");
        }
        let dest = root.join(relative);
        create_private_ancestors(root, &dest)?;
        let Some(bytes) = verified.entry(path) else {
            continue;
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
            .with_context(|| format!("writing catalog staging file {}", dest.display()))?;
        use std::io::Write as _;
        file.write_all(bytes)
            .with_context(|| format!("writing catalog staging file {}", dest.display()))?;
    }
    for name in ["file-modes.json", "change-set-evidence.json"] {
        let Some(bytes) = verified.entry(name) else {
            continue;
        };
        let dest = root.join(name);
        if dest.exists() {
            let existing = std::fs::read(&dest)?;
            if existing != bytes {
                bail!("offline {name} conflicts with the catalog copy");
            }
        } else {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)
                .with_context(|| format!("writing catalog staging file {}", dest.display()))?;
            use std::io::Write as _;
            file.write_all(bytes)
                .with_context(|| format!("writing catalog staging file {}", dest.display()))?;
        }
    }
    Ok(())
}

fn apply_offline_file_modes(source: &std::path::Path) -> Result<()> {
    let path = source.join("file-modes.json");
    if !path.is_file() {
        return Ok(());
    }
    #[derive(Deserialize)]
    struct OfflineFileModes {
        schema: String,
        files: BTreeMap<String, String>,
    }
    let modes: OfflineFileModes = serde_json::from_slice(&std::fs::read(&path)?)?;
    if modes.schema != "tenkai.offline-file-modes.v1" {
        bail!("unsupported offline file-mode schema {}", modes.schema);
    }
    for (relative, encoded) in modes.files {
        if relative.is_empty()
            || relative.contains("..")
            || std::path::Path::new(&relative).is_absolute()
        {
            bail!("offline file mode path {relative} is not canonical");
        }
        let dest = source.join(&relative);
        if dest.is_symlink() || !dest.exists() {
            bail!("offline file mode path {relative} is missing or a symlink");
        }
        let mode = u32::from_str_radix(encoded.trim_start_matches("0o"), 8)
            .with_context(|| format!("offline file mode {encoded} for {relative} is not octal"))?;
        if mode & !0o7777 != 0 {
            bail!("offline file mode {encoded} for {relative} is out of range");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

fn bundle_catalog_toml(
    verified: &crate::offline_bundle::VerifiedBundle,
    spec: &UpgradeSpec,
) -> Result<String> {
    let path = bundle_release_manifest_path(verified, spec)?;
    let raw = verified
        .entry(&path)
        .with_context(|| format!("bundle is missing catalog manifest {path}"))?;
    Ok(std::str::from_utf8(raw)?.to_string())
}

fn bundle_catalog_manifest(
    verified: &crate::offline_bundle::VerifiedBundle,
    spec: &UpgradeSpec,
) -> Result<crate::manifest::Manifest> {
    crate::manifest::parse_raw(&bundle_catalog_toml(verified, spec)?)
}

fn require_catalog_artifacts_in_bundle(
    verified: &crate::offline_bundle::VerifiedBundle,
    spec: &UpgradeSpec,
) -> Result<()> {
    let manifest = bundle_catalog_manifest(verified, spec)?;
    if manifest.artifacts.is_empty() {
        return Ok(());
    }
    let stack = crate::offline_bundle::stack_manifest(verified)?.ok_or_else(|| {
        anyhow::anyhow!("first-install offline bundle requires stack/manifest.json")
    })?;
    let Some(raw) = verified.entry(crate::offline_bundle::LAYER_INSTRUCTION_PATH) else {
        bail!("bundle is missing a required image instruction list");
    };
    let layers: crate::offline_bundle::OfflineArtifactLayerManifest = serde_json::from_slice(raw)?;
    for artifact in &manifest.artifacts {
        if !stack.images.iter().any(|image| image == &artifact.digest) {
            bail!(
                "offline stack manifest does not name catalog artifact {}",
                artifact.digest
            );
        }
        let Some(layer) = layers.layers.iter().find(|layer| {
            layer.registry == artifact.registry
                && layer.repository == artifact.repository
                && layer.digest == artifact.digest
                && layer.media_type == artifact.media_type
        }) else {
            bail!(
                "offline layer instructions do not name catalog artifact {}",
                artifact.identity_key()
            );
        };
        // A layer over the entry limit is in the chunk store; its signed
        // index entry stands in for the layer entry (#684), and the stack
        // preflight has verified its chunks.
        let path = if layer.path == crate::offline_bundle::IMAGE_CHUNKS_PATH {
            crate::offline_bundle::IMAGE_CHUNKS_PATH.to_string()
        } else {
            artifact.layer_entry_path()?
        };
        if verified.entry(&path).is_none() {
            bail!(
                "offline bundle is missing catalog artifact {}",
                artifact.digest
            );
        }
    }
    Ok(())
}

fn prospective_release_pin(
    spec: &UpgradeSpec,
    manifest_path: &std::path::Path,
) -> Result<ReleasePin> {
    let loaded = crate::manifest::load(manifest_path)?;
    if loaded.manifest.product.name != spec.product
        || loaded.manifest.product.version != spec.version
    {
        bail!(
            "offline catalog manifest is {}@{}, not {}@{}",
            loaded.manifest.product.name,
            loaded.manifest.product.version,
            spec.product,
            spec.version
        );
    }
    Ok(ReleasePin {
        release_id: release_id(&spec.product, &spec.version),
        release_digest: crate::manifest::digest(&loaded.raw),
        artifact_digest: crate::manifest::identity_digest(
            &loaded.workdir,
            &loaded.manifest.immutable_inputs(),
            &loaded.manifest.artifacts,
        )?,
    })
}

struct IsolatedCatalogAdmission {
    root: std::path::PathBuf,
    source: std::path::PathBuf,
    change_set_evidence: Option<std::path::PathBuf>,
}

async fn admit_isolated_catalog(
    ctx: &mut Ctx,
    spec: &UpgradeSpec,
    verified: &crate::offline_bundle::VerifiedBundle,
    plan: &Plan,
) -> Result<(ReleasePin, Option<IsolatedCatalogAdmission>)> {
    if let Some(existing) = published_release_pin(ctx, spec).await? {
        require_plan_matches_pin(plan, spec, &existing)?;
        require_isolated_channel_available(ctx, spec).await?;
        let bundled = bundle_catalog_toml(verified, spec)?;
        if crate::manifest::digest(&bundled) != existing.release_digest {
            bail!(
                "offline catalog manifest does not match published release {}",
                existing.release_id
            );
        }
        require_catalog_artifacts_in_bundle(verified, spec)?;
        return Ok((existing, None));
    }
    bundle_release_manifest_path(verified, spec)?;
    bundle_release_verification_paths(verified, spec)?;
    require_isolated_channel_available(ctx, spec).await?;
    let root = exclusive_private_dir()?;
    let source = root.join("src");
    if let Err(error) = materialize_bundle_release(verified, spec, &source) {
        let _ = std::fs::remove_dir_all(&root);
        return Err(error);
    }
    if let Err(error) = apply_offline_file_modes(&source) {
        let _ = std::fs::remove_dir_all(&root);
        return Err(error);
    }
    let manifest = source.join("tenkai.toml");
    let signature = source.join("release.sig.json");
    let trust = source.join("release-trust.toml");
    let cleanup = |error: anyhow::Error| {
        let _ = std::fs::remove_dir_all(&root);
        Err(error)
    };
    if !signature.is_file() || !trust.is_file() {
        return cleanup(anyhow::anyhow!(
            "offline bundle does not include signed release verification for {}@{}",
            spec.product,
            spec.version
        ));
    }
    let prospective = match prospective_release_pin(spec, &manifest) {
        Ok(pin) => pin,
        Err(error) => return cleanup(error),
    };
    if let Err(error) = require_catalog_artifacts_in_bundle(verified, spec) {
        return cleanup(error);
    }
    let evidence_path = source.join("change-set-evidence.json");
    let loaded = match crate::manifest::load(&manifest) {
        Ok(loaded) => loaded,
        Err(error) => return cleanup(error),
    };
    let evidence = evidence_path
        .is_file()
        .then(|| crate::change_set_pin::ChangeSetEvidenceInput::File(evidence_path.clone()));
    if let Err(error) = crate::change_set_pin::admit_publication(
        loaded.manifest.change_set_pin.as_ref(),
        evidence.as_ref(),
    ) {
        return cleanup(error);
    }
    let envelope = match crate::release_signing::SignatureEnvelope::load(&signature) {
        Ok(envelope) => envelope,
        Err(error) => return cleanup(error),
    };
    let roots = match crate::release_signing::TrustRoots::load(&trust) {
        Ok(roots) => roots,
        Err(error) => return cleanup(error),
    };
    if let Err(error) = crate::release_signing::verify_release(
        &envelope,
        &roots,
        &prospective.release_digest,
        &prospective.artifact_digest,
    ) {
        return cleanup(error);
    }
    if let Err(error) = require_plan_matches_pin(plan, spec, &prospective) {
        return cleanup(error);
    }
    Ok((
        prospective,
        Some(IsolatedCatalogAdmission {
            root,
            source,
            change_set_evidence: evidence_path.is_file().then_some(evidence_path),
        }),
    ))
}

fn isolated_catalog_state_dir() -> Result<std::path::PathBuf> {
    if let Ok(path) = crate::host_env::var("TENKAI_STATE_DIR")
        && !path.is_empty()
    {
        return Ok(std::path::PathBuf::from(path));
    }
    let dir = std::env::current_dir()?.join(".tenkai-state");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

async fn commit_isolated_catalog(
    ctx: &mut Ctx,
    spec: &UpgradeSpec,
    plan: &Plan,
    admission: IsolatedCatalogAdmission,
    mirrors: &BTreeMap<String, String>,
) -> Result<ReleasePin> {
    require_isolated_channel_available(ctx, spec).await?;
    let published = crate::catalog::publish(
        ctx,
        &admission.source.join("tenkai.toml"),
        &crate::catalog::PublishOptions {
            signature: Some(admission.source.join("release.sig.json")),
            trust_roots: Some(admission.source.join("release-trust.toml")),
            allow_unsigned_development: false,
            // Layers were imported under their mirrors; verify them there.
            artifact_registry: crate::oci_artifact::selected_registry()?.map(|store| {
                std::sync::Arc::new(crate::oci_artifact::MirroredRegistry::new(
                    store,
                    mirrors.clone(),
                )) as std::sync::Arc<dyn crate::oci_artifact::ArtifactRegistry>
            }),
            state_dir: Some(isolated_catalog_state_dir()?),
            change_set_evidence: admission
                .change_set_evidence
                .map(crate::change_set_pin::ChangeSetEvidenceInput::File),
            ..Default::default()
        },
    )
    .await;
    if published.is_err() {
        let _ = std::fs::remove_dir_all(&admission.root);
    }
    published?;
    let _ = std::fs::remove_dir_all(&admission.root);
    // Releases are immutable, so a later channel-pin failure cannot unpublish.
    // Retry reuses published_release_pin and completes the isolated channel bind.
    crate::catalog::pin_isolated_channel(ctx, &spec.product, &spec.version, &spec.channel).await?;
    let pin = resolve_release_pin(ctx, spec).await?;
    require_plan_matches_pin(plan, spec, &pin)?;
    Ok(pin)
}

/// Operations on one environment of an upgrade run one at a time (#713):
/// each takes that environment's lease before any effect and holds it until
/// the record is written, so a second operation on the same environment is
/// refused before it acts. Operations on different environments run
/// concurrently and their record writes merge.
const UPGRADE_ENVIRONMENT_NAMESPACE: &str = "connectivity-upgrade-environment";
/// A held environment lease is renewed every third of this while its
/// operation runs, so a crashed operation frees the environment quickly.
const UPGRADE_ENVIRONMENT_TTL_MS: i64 = 120_000;

/// Environment leases one operation holds, renewed on a thread of its own
/// until released. The operation stops before its next effect, and its
/// record write is refused, once a renewal failed (`lost`) or the leases
/// may have lapsed: `valid_until_ms` is when the last renewal was asked for
/// plus the lease lifetime, so a process that was paused past it cannot act
/// before the renewal thread notices.
struct HeldEnvironments {
    leases: Vec<(String, String)>,
    lost: Arc<AtomicBool>,
    valid_until_ms: Arc<std::sync::atomic::AtomicI64>,
    stop_renewal: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Stop acting this long before a held lease could lapse.
const UPGRADE_ENVIRONMENT_MARGIN_MS: i64 = 10_000;

impl HeldEnvironments {
    fn none() -> Self {
        Self {
            leases: Vec::new(),
            lost: Arc::default(),
            valid_until_ms: Arc::new(std::sync::atomic::AtomicI64::new(i64::MAX)),
            stop_renewal: None,
        }
    }

    /// Fail when ownership of any held environment was lost or may have
    /// lapsed.
    fn ensure_held(&self) -> Result<()> {
        if self.lost.load(Ordering::SeqCst)
            || crate::now_millis().saturating_add(UPGRADE_ENVIRONMENT_MARGIN_MS)
                >= self.valid_until_ms.load(Ordering::SeqCst)
        {
            bail!("operation lease on an upgrade environment was lost; stopping");
        }
        Ok(())
    }
}

fn environment_lease_key(upgrade: &str, environment: &str) -> String {
    format!("{upgrade}/{environment}")
}

/// Lease every environment in `environments`, or none: a busy one releases
/// the leases already taken and refuses.
async fn lock_environments(
    ctx: &mut Ctx,
    upgrade: &str,
    environments: &[String],
) -> Result<HeldEnvironments> {
    let owner = format!("upgrade-op-{}", uuid::Uuid::new_v4().simple());
    // Asked for before the first lease, so no lease outlives this deadline.
    let valid_until = Arc::new(std::sync::atomic::AtomicI64::new(
        crate::now_millis().saturating_add(UPGRADE_ENVIRONMENT_TTL_MS),
    ));
    let mut held = Vec::new();
    for environment in environments {
        let key = environment_lease_key(upgrade, environment);
        match ctx
            .acquire_lease(
                UPGRADE_ENVIRONMENT_NAMESPACE,
                &key,
                &owner,
                UPGRADE_ENVIRONMENT_TTL_MS,
            )
            .await
        {
            Ok(lease) => held.push((key, lease.fencing_token)),
            Err(error) => {
                release_environment_leases(ctx, held).await;
                return match error {
                    crate::client::LeaseError::AlreadyExists => Err(anyhow::anyhow!(
                        "environment {environment} of upgrade {upgrade} has an operation in progress; retry"
                    )),
                    error => Err(error.into()),
                };
            }
        }
    }
    let lost: Arc<AtomicBool> = Arc::default();
    let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
    let mut renewing = ctx.clone();
    let leases = held.clone();
    let flag = Arc::clone(&lost);
    let deadline = Arc::clone(&valid_until);
    // A thread of its own, so an operation that blocks its runtime (a
    // synchronous bundle import) cannot starve the renewal.
    let started = std::thread::Builder::new()
        .name("upgrade-lease-renewal".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                flag.store(true, Ordering::SeqCst);
                return;
            };
            runtime.block_on(async move {
                let period =
                    std::time::Duration::from_millis((UPGRADE_ENVIRONMENT_TTL_MS / 3) as u64);
                loop {
                    tokio::select! {
                        _ = &mut stopped => return,
                        () = tokio::time::sleep(period) => {}
                    }
                    let asked = crate::now_millis();
                    for (key, token) in &leases {
                        if renewing
                            .refresh_lease(
                                UPGRADE_ENVIRONMENT_NAMESPACE,
                                key,
                                token,
                                UPGRADE_ENVIRONMENT_TTL_MS,
                            )
                            .await
                            .is_err()
                        {
                            flag.store(true, Ordering::SeqCst);
                            return;
                        }
                    }
                    deadline.store(
                        asked.saturating_add(UPGRADE_ENVIRONMENT_TTL_MS),
                        Ordering::SeqCst,
                    );
                }
            });
        });
    if started.is_err() {
        release_environment_leases(ctx, held).await;
        bail!("could not start the upgrade lease renewal");
    }
    Ok(HeldEnvironments {
        leases: held,
        lost,
        valid_until_ms: valid_until,
        stop_renewal: Some(stop),
    })
}

async fn unlock_environments(ctx: &mut Ctx, mut held: HeldEnvironments) {
    // The renewal thread exits once told; a renewal racing the release fails
    // harmlessly.
    if let Some(stop) = held.stop_renewal.take() {
        let _ = stop.send(());
    }
    release_environment_leases(ctx, held.leases).await;
}

async fn release_environment_leases(ctx: &mut Ctx, leases: Vec<(String, String)>) {
    for (key, token) in leases {
        let _ = ctx
            .release_lease(UPGRADE_ENVIRONMENT_NAMESPACE, &key, &token)
            .await;
    }
}

pub async fn interrupt_transfer(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
) -> Result<UpgradeRecord> {
    let held = lock_environments(ctx, name, &[environment.to_string()]).await?;
    let result = interrupt_transfer_locked(ctx, &held, name, environment).await;
    unlock_environments(ctx, held).await;
    result
}

pub async fn resume_transfer(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
) -> Result<UpgradeRecord> {
    let held = lock_environments(ctx, name, &[environment.to_string()]).await?;
    let result = resume_transfer_locked(ctx, &held, name, environment).await;
    unlock_environments(ctx, held).await;
    result
}

/// Advance the first environment that still needs work.
pub async fn advance(
    ctx: &mut Ctx,
    name: &str,
    authorization: ExecutionAuthorization<'_>,
) -> Result<UpgradeRecord> {
    let record = load_upgrade(ctx, name).await?;
    let target = record
        .environments
        .iter()
        .find(|environment| {
            matches!(
                environment.status,
                UpgradeEnvironmentStatus::Pending | UpgradeEnvironmentStatus::Interrupted
            )
        })
        .map(|environment| environment.name.clone())
        .unwrap_or_default();
    let held = if target.is_empty() {
        HeldEnvironments::none()
    } else {
        lock_environments(ctx, name, std::slice::from_ref(&target)).await?
    };
    let result = advance_locked(ctx, &held, name, &target, authorization).await;
    unlock_environments(ctx, held).await;
    result
}

pub async fn bind_isolated_bundle(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    bundle: &crate::offline_bundle::BundleEnvelope,
    trust_roots: &crate::release_signing::TrustRoots,
    bundle_path: Option<&Path>,
) -> Result<UpgradeRecord> {
    bind_isolated_bundle_reporting(
        ctx,
        name,
        environment,
        bundle,
        trust_roots,
        bundle_path,
        None,
    )
    .await
}

/// [`bind_isolated_bundle`], reporting each stored layer and weight to
/// `progress` (#821).
pub async fn bind_isolated_bundle_reporting(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    bundle: &crate::offline_bundle::BundleEnvelope,
    trust_roots: &crate::release_signing::TrustRoots,
    bundle_path: Option<&Path>,
    progress: Option<&crate::import_progress::ImportProgress>,
) -> Result<UpgradeRecord> {
    let held = lock_environments(ctx, name, &[environment.to_string()]).await?;
    let result = bind_isolated_bundle_locked(
        ctx,
        &held,
        name,
        environment,
        bundle,
        trust_roots,
        bundle_path,
        progress,
    )
    .await;
    unlock_environments(ctx, held).await;
    result
}

pub async fn import_isolated_receipt(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    receipt: &crate::offline_bundle::ReceiptEnvelope,
    bundle: &crate::offline_bundle::BundleEnvelope,
    trust_roots: &crate::release_signing::TrustRoots,
) -> Result<UpgradeRecord> {
    let held = lock_environments(ctx, name, &[environment.to_string()]).await?;
    let result =
        import_isolated_receipt_locked(ctx, &held, name, environment, receipt, bundle, trust_roots)
            .await;
    unlock_environments(ctx, held).await;
    result
}

/// Roll back every applied environment. All of the upgrade's environments
/// are leased before the applied ones are chosen, so none is applied
/// meanwhile and left out.
pub async fn rollback_upgrade(
    ctx: &mut Ctx,
    name: &str,
    authorization: ExecutionAuthorization<'_>,
) -> Result<UpgradeRecord> {
    let record = load_upgrade(ctx, name).await?;
    let environments: Vec<String> = record
        .environments
        .iter()
        .map(|environment| environment.name.clone())
        .collect();
    let held = lock_environments(ctx, name, &environments).await?;
    let result = rollback_upgrade_locked(ctx, &held, name, &environments, authorization).await;
    unlock_environments(ctx, held).await;
    result
}

const UPGRADE_WRITE_NAMESPACE: &str = "connectivity-upgrade-write";
/// A record write holds its lease only while it reads and writes the record.
const UPGRADE_WRITE_TTL_MS: i64 = 30_000;
const UPGRADE_WRITE_ATTEMPTS: u32 = 50;
const UPGRADE_WRITE_RETRY: std::time::Duration = std::time::Duration::from_millis(100);

/// Write `modified` back as a change to `base`, the record as this operation
/// read it (#713). Under a short lease on the upgrade, the stored record is
/// read again and only what the operation changed is applied: the
/// environment entries it changed (it holds their leases) and the status,
/// so concurrent operations on different environments both persist.
/// Returns the stored record.
async fn persist(
    ctx: &mut Ctx,
    held: &HeldEnvironments,
    base: &UpgradeRecord,
    modified: &UpgradeRecord,
) -> Result<UpgradeRecord> {
    let owner = format!("upgrade-write-{}", uuid::Uuid::new_v4().simple());
    let mut attempt = 0;
    let lease = loop {
        match ctx
            .acquire_lease(
                UPGRADE_WRITE_NAMESPACE,
                &modified.name,
                &owner,
                UPGRADE_WRITE_TTL_MS,
            )
            .await
        {
            Ok(lease) => break lease,
            Err(crate::client::LeaseError::AlreadyExists) if attempt < UPGRADE_WRITE_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(UPGRADE_WRITE_RETRY).await;
            }
            Err(crate::client::LeaseError::AlreadyExists) => bail!(
                "upgrade {} is being updated by another writer; retry",
                modified.name
            ),
            Err(error) => return Err(error.into()),
        }
    };
    let written = async {
        // The operation must still hold each environment it changes. Renewing
        // under the record lease fences an operation whose lease lapsed or
        // was taken over: it cannot record over its successor.
        held.ensure_held()?;
        for (key, token) in &held.leases {
            ctx.refresh_lease(
                UPGRADE_ENVIRONMENT_NAMESPACE,
                key,
                token,
                UPGRADE_ENVIRONMENT_TTL_MS,
            )
            .await
            .with_context(|| format!("operation lease on {key} was lost; not recording"))?;
        }
        let current = load_upgrade(ctx, &modified.name).await?;
        let merged = merge_upgrade(base, modified, current)?;
        let mut object = upgrade_object(&merged)?;
        object.updated = crate::now_millis();
        // Fenced by the lease: a writer whose lease expired while it held the
        // record is refused by storage, not applied over its successor.
        ctx.guarded_update(
            object,
            UPGRADE_WRITE_NAMESPACE,
            &modified.name,
            &lease.fencing_token,
        )
        .await?;
        Ok(merged)
    }
    .await;
    let _ = ctx
        .release_lease(
            UPGRADE_WRITE_NAMESPACE,
            &modified.name,
            &lease.fencing_token,
        )
        .await;
    written
}

/// Apply `modified`'s changes to `base` onto `current`. Environments are
/// fixed when the upgrade is created, so they merge by position.
fn merge_upgrade(
    base: &UpgradeRecord,
    modified: &UpgradeRecord,
    current: UpgradeRecord,
) -> Result<UpgradeRecord> {
    if base.environments.len() != modified.environments.len()
        || current.environments.len() != base.environments.len()
    {
        bail!("upgrade {} environments changed shape", base.name);
    }
    // Whether another writer changed any environment since `base`.
    let concurrent = current.environments != base.environments;
    let mut merged = current;
    // An operation holds the lease of each environment it changes, so its
    // entry replaces the stored one whole.
    for (index, changed) in modified.environments.iter().enumerate() {
        if *changed != base.environments[index] {
            merged.environments[index] = changed.clone();
        }
    }
    // The aggregate status follows the environments. With no concurrent
    // environment change, this operation's status stands; otherwise it is
    // derived from the merged environments, whatever order the writers
    // persisted in.
    if concurrent {
        if modified.status != base.status || merged.status != base.status {
            merged.status = summarize(&merged);
        }
    } else if modified.status != base.status {
        merged.status = modified.status;
    }
    // As before #713, `updated_at` moves only when the operation moved it,
    // so replaying the same state stores the same record.
    if modified.updated_at != base.updated_at {
        merged.updated_at = merged.updated_at.max(modified.updated_at);
    }
    Ok(merged)
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
            uuid::Uuid::new_v4()
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
                requester: None,
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
                requester: None,
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
                requester: None,
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
        bind_isolated_bundle(&mut ctx, "fleet-1", "site-c", &bundle, &roots, None)
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
                requester: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(finished.status, UpgradeStatus::Succeeded);
        // The hub keeps the accepted receipt, so it can hand it out (#682).
        assert_eq!(
            finished
                .environments
                .iter()
                .find(|environment| environment.name == "site-c")
                .and_then(|environment| environment.isolated.as_ref())
                .and_then(|evidence| evidence.receipt.as_ref()),
            Some(&receipt)
        );
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

    /// A staged bundle imported through the server path binds exactly as the
    /// CLI does; a dry run writes nothing; refusals are recorded on the job.
    #[tokio::test]
    async fn staged_bundle_import_previews_binds_and_records_refusals() {
        use crate::offline_import::{ImportRequest, ImportState};
        let root = temp_root("staged-import");
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        let actor = crate::auth_context::test_management_context("staged");
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        prepare_env(&mut ctx, "site-c", ConnectivityClass::Isolated, &actor).await;
        let spec = UpgradeSpec {
            name: "fleet-staged".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["site-c".into()],
        };
        let started = start_or_resume(&mut ctx, &spec).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let bundle = export_isolated_bundle(
            "site-c",
            started.environments[0].plan_id.as_deref().unwrap(),
            &started.release_id,
            b"immutable payload",
            &exporter,
            crate::now_millis(),
        )
        .unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let staging = root.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        bundle.save(&staging.join("site-c.json")).unwrap();
        let request = |dry_run: bool, environment: &str| ImportRequest {
            version: 1,
            operation: "import".into(),
            bundle: "site-c.json".into(),
            upgrade: "fleet-staged".into(),
            environment: environment.into(),
            dry_run,
        };

        let preview = crate::offline_import::run(
            &mut ctx,
            &staging,
            &request(true, "site-c"),
            &roots,
            "operator",
        )
        .await
        .unwrap();
        assert_eq!(
            preview.state,
            ImportState::Previewed,
            "{:?}",
            preview.refusal
        );
        assert!(!preview.preview.as_ref().unwrap().already_bound);
        assert!(
            load_upgrade(&mut ctx, "fleet-staged")
                .await
                .unwrap()
                .environments[0]
                .isolated
                .is_none()
        );

        let imported = crate::offline_import::run(
            &mut ctx,
            &staging,
            &request(false, "site-c"),
            &roots,
            "operator",
        )
        .await
        .unwrap();
        assert_eq!(
            imported.state,
            ImportState::Succeeded,
            "{:?}",
            imported.refusal
        );
        let bound = load_upgrade(&mut ctx, "fleet-staged").await.unwrap();
        assert_eq!(
            bound.environments[0]
                .isolated
                .as_ref()
                .unwrap()
                .bundle_digest,
            imported.preview.as_ref().unwrap().bundle_digest
        );
        // The CLI path on the same bundle is a replay of the same state.
        bind_isolated_bundle(&mut ctx, "fleet-staged", "site-c", &bundle, &roots, None)
            .await
            .unwrap();
        assert_eq!(load_upgrade(&mut ctx, "fleet-staged").await.unwrap(), bound);
        assert_eq!(
            crate::offline_import::job(&staging, &imported.id).unwrap(),
            imported
        );
        // #821: the list, read back from the job files as after a restart,
        // shows the dry run and the import of the same bundle as two jobs
        // with their own states, newest first.
        let listed = crate::offline_import::list_jobs(&staging).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|job| (job.id.as_str(), job.dry_run, job.state))
                .collect::<Vec<_>>(),
            [
                (imported.id.as_str(), false, ImportState::Succeeded),
                (preview.id.as_str(), true, ImportState::Previewed),
            ]
        );
        assert_ne!(imported.id, preview.id);
        // #827: the staged bundle reports the upgrade it serves, derived from
        // the upgrade records; none for an environment no upgrade plans.
        let staged = crate::offline_import::list_staged_with_upgrades(&mut ctx, &staging)
            .await
            .unwrap();
        assert_eq!(staged[0].upgrade.as_deref(), Some("fleet-staged"));
        let stray = export_isolated_bundle(
            "site-z",
            started.environments[0].plan_id.as_deref().unwrap(),
            &started.release_id,
            b"immutable payload",
            &exporter,
            crate::now_millis(),
        )
        .unwrap();
        stray.save(&staging.join("stray.json")).unwrap();
        let staged = crate::offline_import::list_staged_with_upgrades(&mut ctx, &staging)
            .await
            .unwrap();
        assert_eq!(staged[1].file, "stray.json");
        assert_eq!(staged[1].upgrade, None);
        std::fs::remove_file(staging.join("stray.json")).unwrap();
        // #830: the listing reports the staged archive's digest, and the dry
        // run and the import both record it.
        let staged_digest = |staging: &std::path::Path| {
            crate::offline_import::list_staged(staging).unwrap()[0]
                .archive_digest
                .clone()
                .unwrap()
        };
        let first_digest = staged_digest(&staging);
        assert_eq!(
            staged_digest(&staging),
            first_digest,
            "stable while unchanged"
        );
        assert_eq!(
            preview.archive_digest.as_deref(),
            Some(first_digest.as_str())
        );
        assert_eq!(
            imported.archive_digest.as_deref(),
            Some(first_digest.as_str())
        );
        // A different archive staged under the same name: a new digest that
        // no earlier job carries.
        let replacement = export_isolated_bundle(
            "site-c",
            started.environments[0].plan_id.as_deref().unwrap(),
            &started.release_id,
            b"immutable-payload",
            &exporter,
            crate::now_millis(),
        )
        .unwrap();
        replacement.save(&staging.join("site-c.json")).unwrap();
        let replaced_digest = staged_digest(&staging);
        assert_ne!(replaced_digest, first_digest);
        assert!(
            crate::offline_import::list_jobs(&staging)
                .unwrap()
                .iter()
                .all(|job| job.archive_digest.as_deref() != Some(replaced_digest.as_str()))
        );
        bundle.save(&staging.join("site-c.json")).unwrap();
        assert_eq!(staged_digest(&staging), first_digest);
        // A record of another attempt is not reported: an older binary's
        // retry rewrote the job file but left the record, or the record is
        // newer than the job file read.
        let record_path = staging.join(format!("imports/{}.archive.json", imported.id));
        let job_path = staging.join(format!("imports/{}.json", imported.id));
        let mut retried: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&job_path).unwrap()).unwrap();
        retried["started_at_ms"] = (imported.started_at_ms + 5).into();
        std::fs::write(&job_path, serde_json::to_vec(&retried).unwrap()).unwrap();
        let job_of = |id: &str| crate::offline_import::job(&staging, id).unwrap();
        assert_eq!(job_of(&imported.id).archive_digest, None);
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        record["started_at_ms"] = (imported.started_at_ms + 9).into();
        std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(job_of(&imported.id).archive_digest, None);
        record["started_at_ms"] = (imported.started_at_ms + 5).into();
        std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(
            job_of(&imported.id).archive_digest.as_deref(),
            Some(first_digest.as_str())
        );
        // A job file written before #830 carries no digest and still reads.
        std::fs::remove_file(staging.join(format!("imports/{}.archive.json", preview.id))).unwrap();
        assert_eq!(
            crate::offline_import::job(&staging, &preview.id)
                .unwrap()
                .archive_digest,
            None
        );

        let refused = crate::offline_import::run(
            &mut ctx,
            &staging,
            &request(false, "site-d"),
            &roots,
            "operator",
        )
        .await
        .unwrap();
        assert_eq!(refused.state, ImportState::Failed);
        assert!(refused.refusal.unwrap().contains("scope"));

        let inventory = crate::content_inventory::inventory(&mut ctx, Some(&staging))
            .await
            .unwrap();
        let release = inventory
            .releases
            .iter()
            .find(|release| release.product == "edge-app" && release.version == "1.0.0")
            .unwrap();
        assert!(
            release
                .referenced_by
                .contains(&"channel edge-app/stable".to_string()),
            "{:?}",
            release.referenced_by
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A configured scanner runs after the signature verifies and before any
    /// write: a refusal leaves the upgrade unbound, a pass is recorded.
    #[tokio::test(flavor = "current_thread")]
    async fn import_scanner_refuses_before_mutation_and_records_a_pass() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = temp_root("scanner");
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        let actor = crate::auth_context::test_management_context("scanner");
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        prepare_env(&mut ctx, "site-c", ConnectivityClass::Isolated, &actor).await;
        let spec = UpgradeSpec {
            name: "fleet-scan".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["site-c".into()],
        };
        let started = start_or_resume(&mut ctx, &spec).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let bundle = export_isolated_bundle(
            "site-c",
            started.environments[0].plan_id.as_deref().unwrap(),
            &started.release_id,
            b"immutable payload",
            &exporter,
            crate::now_millis(),
        )
        .unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let path = root.join("site-c.json");
        bundle.save(&path).unwrap();
        let scanner = |name: &str, body: &str| {
            let script = root.join(name);
            std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            crate::import_scanner::TEST_SCANNER.with(|slot| *slot.borrow_mut() = Some(script));
        };

        scanner("infected", "echo 'FOUND: test-signature'; exit 3");
        let refused = bind_isolated_bundle(
            &mut ctx,
            "fleet-scan",
            "site-c",
            &bundle,
            &roots,
            Some(&path),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            refused.contains("refused the bundle (exit 3): FOUND"),
            "{refused}"
        );
        assert!(
            load_upgrade(&mut ctx, "fleet-scan")
                .await
                .unwrap()
                .environments[0]
                .isolated
                .is_none()
        );

        scanner("clean", "echo clean");
        let bound = bind_isolated_bundle(
            &mut ctx,
            "fleet-scan",
            "site-c",
            &bundle,
            &roots,
            Some(&path),
        )
        .await
        .unwrap();
        let scan = bound.environments[0]
            .isolated
            .as_ref()
            .unwrap()
            .scan
            .as_ref()
            .unwrap();
        assert_eq!((scan.exit_code, scan.summary.as_str()), (0, "clean"));
        crate::import_scanner::TEST_SCANNER.with(|slot| *slot.borrow_mut() = None);
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
        let forged_err =
            bind_isolated_bundle(&mut ctx, "fleet-bogus", "site-c", &forged, &roots, None)
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
        let scoped =
            bind_isolated_bundle(&mut ctx, "fleet-bogus", "site-c", &wrong_env, &roots, None)
                .await
                .unwrap_err()
                .to_string();
        assert!(
            scoped.contains("tenant") || scoped.contains("environment") || scoped.contains("scope"),
            "{scoped}"
        );

        bind_isolated_bundle(&mut ctx, "fleet-bogus", "site-c", &bundle, &roots, None)
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
        let plan_err =
            bind_isolated_bundle(&mut ctx, "fleet-bogus", "site-c", &other_plan, &roots, None)
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

    /// An operation stops acting once its leases may have lapsed, even before
    /// the renewal thread reports a failure.
    #[test]
    fn held_environments_stop_near_their_deadline() {
        let held = HeldEnvironments::none();
        held.ensure_held().unwrap();
        held.valid_until_ms.store(
            crate::now_millis() + UPGRADE_ENVIRONMENT_MARGIN_MS / 2,
            Ordering::SeqCst,
        );
        assert!(held.ensure_held().is_err());
        held.valid_until_ms.store(i64::MAX, Ordering::SeqCst);
        held.lost.store(true, Ordering::SeqCst);
        assert!(held.ensure_held().is_err());
    }

    /// Two writers that read the same upgrade record and each bind a
    /// different environment both persist (#713); a second operation on an
    /// environment another operation holds is refused before it acts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_binds_for_different_environments_both_persist() {
        let root = temp_root("concurrent-bind");
        let db = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&db).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        let actor = crate::auth_context::test_management_context("concurrent-bind");
        for site in ["site-a", "site-b"] {
            prepare_env(&mut ctx, site, ConnectivityClass::Isolated, &actor).await;
        }
        let spec = UpgradeSpec {
            name: "bind-race".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["site-a".into(), "site-b".into()],
        };
        let base = start_or_resume(&mut ctx, &spec).await.unwrap();
        let bound = |environment: &str| {
            let mut record = base.clone();
            let index = env_index(&record, environment).unwrap();
            record.environments[index].isolated = Some(IsolatedEvidence {
                bundle_digest: format!("sha256:{environment}"),
                receipt_digest: None,
                plan_digest: None,
                approval_digest: None,
                scan: None,
                receipt: None,
            });
            record.environments[index].detail = "verified offline bundle bound".into();
            record
        };
        let (a, b) = (bound("site-a"), bound("site-b"));
        let mut ctx_a = Ctx::embedded(&db).unwrap();
        let mut ctx_b = Ctx::embedded(&db).unwrap();
        let unleased = HeldEnvironments::none();
        let (written_a, written_b) = tokio::join!(
            persist(&mut ctx_a, &unleased, &base, &a),
            persist(&mut ctx_b, &unleased, &base, &b)
        );
        written_a.unwrap();
        written_b.unwrap();
        let stored = load_upgrade(&mut ctx, "bind-race").await.unwrap();
        for environment in ["site-a", "site-b"] {
            let index = env_index(&stored, environment).unwrap();
            assert_eq!(
                stored.environments[index]
                    .isolated
                    .as_ref()
                    .map(|evidence| evidence.bundle_digest.clone()),
                Some(format!("sha256:{environment}")),
                "{stored:?}"
            );
        }

        // While one operation holds site-a, a second one on site-a is
        // refused before it acts; site-b stays free.
        let held = lock_environments(&mut ctx_a, "bind-race", &["site-a".to_string()])
            .await
            .unwrap();
        let refused = interrupt_transfer(&mut ctx_b, "bind-race", "site-a")
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("operation in progress"), "{refused}");
        let free = lock_environments(&mut ctx_b, "bind-race", &["site-b".to_string()])
            .await
            .unwrap();
        unlock_environments(&mut ctx_b, free).await;
        // The same leases, as an operation still holding them would see them.
        let stale = HeldEnvironments {
            leases: held.leases.clone(),
            lost: Arc::default(),
            valid_until_ms: Arc::new(std::sync::atomic::AtomicI64::new(i64::MAX)),
            stop_renewal: None,
        };
        unlock_environments(&mut ctx_a, held).await;

        // An operation whose lease was taken over (as after expiry) cannot
        // record over its successor.
        let successor = lock_environments(&mut ctx_b, "bind-race", &["site-a".to_string()])
            .await
            .unwrap();
        let current = load_upgrade(&mut ctx, "bind-race").await.unwrap();
        let mut late = current.clone();
        let index = env_index(&late, "site-a").unwrap();
        late.environments[index].detail = "late writer".into();
        let refused = persist(&mut ctx_a, &stale, &current, &late)
            .await
            .unwrap_err();
        assert!(format!("{refused:#}").contains("was lost"), "{refused:#}");
        unlock_environments(&mut ctx_b, successor).await;

        // Two writers move the aggregate status differently while changing
        // different environments: both persist and the status follows the
        // merged environments.
        let base = stored;
        let mut applied = base.clone();
        let index_a = env_index(&applied, "site-a").unwrap();
        applied.environments[index_a].status = UpgradeEnvironmentStatus::Applied;
        applied.status = UpgradeStatus::Running;
        let mut interrupted = base.clone();
        let index_b = env_index(&interrupted, "site-b").unwrap();
        interrupted.environments[index_b].status = UpgradeEnvironmentStatus::Interrupted;
        interrupted.status = UpgradeStatus::Interrupted;
        persist(&mut ctx, &HeldEnvironments::none(), &base, &interrupted)
            .await
            .unwrap();
        let merged = persist(&mut ctx, &HeldEnvironments::none(), &base, &applied)
            .await
            .unwrap();
        assert_eq!(
            merged.environments[index_a].status,
            UpgradeEnvironmentStatus::Applied
        );
        assert_eq!(
            merged.environments[index_b].status,
            UpgradeEnvironmentStatus::Interrupted
        );
        assert_eq!(merged.status, UpgradeStatus::Interrupted);

        // A writer that keeps the status while changing another environment
        // still makes the status follow the merged environments.
        let base = merged;
        let mut running = base.clone();
        running.environments[index_b].status = UpgradeEnvironmentStatus::Pending;
        running.status = UpgradeStatus::Running;
        let mut kept = base.clone();
        kept.environments[index_a].detail = "detail only".into();
        persist(&mut ctx, &HeldEnvironments::none(), &base, &kept)
            .await
            .unwrap();
        let merged = persist(&mut ctx, &HeldEnvironments::none(), &base, &running)
            .await
            .unwrap();
        assert_eq!(merged.status, summarize(&merged));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn incomplete_first_install_bundle_is_refused_before_mutation() {
        let root = temp_root("first-install-missing");
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        let actor = crate::auth_context::test_management_context("first-install");
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let bundle = export_isolated_bundle(
            "dark-1",
            "first-install",
            "edge-app@1.0.0",
            b"payload",
            &exporter,
            crate::now_millis(),
        )
        .unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-1".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(&mut ctx, &spec, "dark-1", &bundle, &roots, None, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("stack/manifest.json"), "{err}");
        assert!(
            crate::environment::environment(&mut ctx, "dark-1")
                .await
                .is_err()
        );
        assert!(load_upgrade(&mut ctx, "first-1").await.is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    fn sha256_digest(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    fn sample_layer(bytes: &[u8]) -> crate::oci_artifact::OciArtifactRef {
        crate::oci_artifact::OciArtifactRef {
            registry: "ghcr.io".into(),
            repository: "edge/app".into(),
            digest: sha256_digest(bytes),
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            sbom: None,
        }
    }

    fn signed_first_install_plan(
        environment: &str,
        release_digest: &str,
        artifact_digest: &str,
        workdir: &str,
    ) -> Plan {
        let mut plan = Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: String::new(),
            content_id: String::new(),
            environment: environment.into(),
            created_at: 1,
            inputs: vec![crate::plan::DesiredStateInput {
                product: "edge-app".into(),
                channel: "stable".into(),
                channel_id: channel_id("edge-app", "stable"),
                desired_version: "1.0.0".into(),
                release_id: release_id("edge-app", "1.0.0"),
                release_digest: release_digest.into(),
                artifact_digest: artifact_digest.into(),
                deployed_version: None,
            }],
            steps: vec![crate::plan::Step {
                id: String::new(),
                order: 0,
                product: "edge-app".into(),
                action: crate::plan::Action::Install,
                from: None,
                to: "1.0.0".into(),
                release_id: release_id("edge-app", "1.0.0"),
                release_digest: release_digest.into(),
                artifact_digest: artifact_digest.into(),
                workdir: workdir.into(),
                restore: None,
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        };
        plan.bind_content_identity().unwrap();
        plan
    }

    /// Point this test's artifact store, weight cache and state directory
    /// under `root`, for this test's thread only.
    fn lock_artifact_stores(root: &std::path::Path) -> crate::host_env::overlay::Scoped {
        let oci = root.join("oci");
        let weights = root.join("weights");
        let state = root.join("state");
        for dir in [&oci, &weights, &state] {
            std::fs::create_dir_all(dir).unwrap();
        }
        crate::host_env::overlay::set([
            ("TENKAI_OCI_STORE", Some(oci.as_os_str())),
            ("TENKAI_WEIGHT_CACHE", Some(weights.as_os_str())),
            ("TENKAI_STATE_DIR", Some(state.as_os_str())),
        ])
    }

    fn sign_catalog_for_layer(
        root: &std::path::Path,
        artifact: &crate::oci_artifact::OciArtifactRef,
        extra_toml: &str,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, String, String) {
        let dir = root.join("catalog-src");
        std::fs::create_dir_all(&dir).unwrap();
        let toml = format!(
            r#"
[product]
name = "edge-app"
version = "1.0.0"

[deploy]
install = "true"

[[artifacts]]
registry = "{}"
repository = "{}"
digest = "{}"
media_type = "{}"
{extra_toml}
"#,
            artifact.registry,
            artifact.repository,
            artifact.digest,
            artifact.media_type,
            extra_toml = extra_toml
        );
        let manifest = dir.join("tenkai.toml");
        std::fs::write(&manifest, &toml).unwrap();
        let signature = dir.join("release.sig.json");
        let trust = dir.join("release-trust.toml");
        crate::dev_sign::sign_release(&root.join("keys"), &manifest, &signature, &trust).unwrap();
        let loaded = crate::manifest::load(&manifest).unwrap();
        let digest = crate::manifest::digest(&std::fs::read_to_string(&manifest).unwrap());
        let artifact_digest = crate::manifest::identity_digest(
            &loaded.workdir,
            &loaded.manifest.immutable_inputs(),
            &loaded.manifest.artifacts,
        )
        .unwrap();
        (
            toml.into_bytes(),
            std::fs::read(&signature).unwrap(),
            std::fs::read(&trust).unwrap(),
            digest,
            artifact_digest,
        )
    }

    type CatalogPayload<'a> = Option<(&'a [u8], Option<&'a [u8]>, Option<&'a [u8]>)>;

    fn complete_first_install_bundle(
        environment: &str,
        plan_bytes: &[u8],
        catalog: CatalogPayload<'_>,
        archive_path: &std::path::Path,
        exporter: &SigningKey,
    ) -> crate::offline_bundle::BundleEnvelope {
        complete_first_install_bundle_with_layer(
            environment,
            plan_bytes,
            catalog,
            archive_path,
            exporter,
            &sample_layer(b"layer-a"),
            BTreeMap::new(),
        )
    }

    fn complete_first_install_bundle_with_layer(
        environment: &str,
        plan_bytes: &[u8],
        catalog: CatalogPayload<'_>,
        archive_path: &std::path::Path,
        exporter: &SigningKey,
        artifact: &crate::oci_artifact::OciArtifactRef,
        extra: BTreeMap<String, (String, Vec<u8>)>,
    ) -> crate::offline_bundle::BundleEnvelope {
        let layer_bytes = b"layer-a";
        let origin = crate::oci_artifact::MemoryArtifactRegistry::new();
        origin.put(artifact, layer_bytes.to_vec()).unwrap();
        let mut payloads = BTreeMap::new();
        let approval = br#"{"approval":"first-install"}"#.to_vec();
        payloads.insert(
            format!(
                "plans/{}.json",
                serde_json::from_slice::<Plan>(plan_bytes)
                    .map(|plan| plan.id)
                    .unwrap_or_else(|_| "first-install".into())
            ),
            ("application/json".into(), plan_bytes.to_vec()),
        );
        let plan_id = payloads
            .keys()
            .find(|path| path.starts_with("plans/"))
            .unwrap()
            .clone();
        let plan_id = plan_id
            .trim_start_matches("plans/")
            .trim_end_matches(".json")
            .to_string();
        payloads.insert(
            format!("approvals/{plan_id}.json"),
            ("application/json".into(), approval.clone()),
        );
        if let Some((toml, signature, trust)) = catalog {
            payloads.insert(
                "releases/edge-app@1.0.0/tenkai.toml".into(),
                ("application/toml".into(), toml.to_vec()),
            );
            if let Some(signature) = signature {
                payloads.insert(
                    "releases/edge-app@1.0.0/release.sig.json".into(),
                    ("application/json".into(), signature.to_vec()),
                );
            }
            if let Some(trust) = trust {
                payloads.insert(
                    "releases/edge-app@1.0.0/release-trust.toml".into(),
                    ("application/toml".into(), trust.to_vec()),
                );
            }
        } else {
            payloads.insert(
                "releases/edge-app@1.0.0/payload.bin".into(),
                ("application/octet-stream".into(), b"payload".to_vec()),
            );
        }
        payloads.insert(
            "schemas/edge.json".into(),
            ("application/json".into(), b"{}".to_vec()),
        );
        payloads.insert(
            "hub/tenkai-server".into(),
            ("application/octet-stream".into(), b"hub-bin".to_vec()),
        );
        crate::offline_bundle::insert_artifact_layers(
            &mut payloads,
            std::slice::from_ref(artifact),
            &origin,
        )
        .unwrap();
        let source = archive_path.parent().unwrap().join("weight.bin");
        std::fs::write(&source, b"weight-bytes").unwrap();
        let chunks = crate::offline_chunk_store::chunk_dir_beside(archive_path).unwrap();
        let artifact_chunks =
            crate::offline_chunk_store::export_weight_chunks(&source, &chunks, 64).unwrap();
        crate::offline_chunk_store::insert_chunk_manifest(
            &mut payloads,
            vec![artifact_chunks.clone()],
        )
        .unwrap();
        crate::offline_bundle::insert_stack_manifest(
            &mut payloads,
            crate::offline_bundle::OfflineStackManifest {
                schema: crate::offline_bundle::STACK_MANIFEST_SCHEMA.into(),
                images: vec![artifact.digest.clone()],
                weights: vec![artifact_chunks.digest],
                schemas: vec!["schemas/edge.json".into()],
                hub: vec!["hub/tenkai-server".into()],
            },
        )
        .unwrap();
        payloads.extend(extra);
        crate::offline_bundle::BundleEnvelope::create(
            crate::offline_bundle::BundleStatement {
                tenant_id: crate::ontology::NS.into(),
                environment_id: environment.into(),
                plan_id,
                plan_digest: sha256_digest(plan_bytes),
                approval_digest: sha256_digest(&approval),
                release_ids: vec!["edge-app@1.0.0".into()],
                exporter_identity: "exporter".into(),
                issued_at_unix_ms: crate::now_millis(),
                expires_at_unix_ms: crate::now_millis().saturating_add(3_600_000),
                entries: Vec::new(),
            },
            payloads,
            exporter,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn first_install_rejects_non_executable_plan_before_mutation() {
        let root = temp_root("first-install-stub-plan");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let archive = root.join("delivery.json");
        let bundle = complete_first_install_bundle(
            "dark-1",
            br#"{"plan":"first-install"}"#,
            Some((
                br#"
[product]
name = "edge-app"
version = "1.0.0"

[deploy]
install = "true"
"#,
                None,
                None,
            )),
            &archive,
            &exporter,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-stub".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("executable plan") || err.contains("canonical plan"),
            "{err}"
        );
        assert!(
            crate::environment::environment(&mut ctx, "dark-1")
                .await
                .is_err()
        );
        assert!(load_upgrade(&mut ctx, "first-stub").await.is_err());
        assert!(
            ctx.get(&release_id("edge-app", "1.0.0"))
                .await
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_rejects_non_runnable_plan_before_mutation() {
        let root = temp_root("first-install-succeeded-plan");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let mut plan = signed_first_install_plan(
            "dark-1",
            "sha256:plan-release",
            "sha256:plan-artifact",
            "/exporter/state/edge-app",
        );
        plan.state = PlanState::Succeeded;
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let (toml, signature, trust, _, _) =
            sign_catalog_for_layer(&root, &sample_layer(b"layer-a"), "");
        let bundle = complete_first_install_bundle(
            "dark-1",
            &plan_bytes,
            Some((&toml, Some(&signature), Some(&trust))),
            &archive,
            &exporter,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-succeeded".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("not executable"), "{err}");
        assert!(
            crate::environment::environment(&mut ctx, "dark-1")
                .await
                .is_err()
        );
        assert!(load_upgrade(&mut ctx, "first-succeeded").await.is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_rejects_unsigned_catalog_manifest_before_mutation() {
        let root = temp_root("first-install-unsigned");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let plan = signed_first_install_plan(
            "dark-1",
            "sha256:plan-release",
            "sha256:plan-artifact",
            "/exporter/state/edge-app",
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let unsigned = br#"
[product]
name = "edge-app"
version = "1.0.0"

[deploy]
install = "true"
"#;
        let bundle = complete_first_install_bundle(
            "dark-1",
            &plan_bytes,
            Some((unsigned, None, None)),
            &archive,
            &exporter,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-unsigned".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("signed release verification"), "{err}");
        assert!(
            crate::environment::environment(&mut ctx, "dark-1")
                .await
                .is_err()
        );
        assert!(load_upgrade(&mut ctx, "first-unsigned").await.is_err());
        assert!(
            ctx.get(&release_id("edge-app", "1.0.0"))
                .await
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_from_signed_bundle_bootstraps_catalog_and_authenticated_plan() {
        let root = temp_root("first-install-success");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let artifact = sample_layer(b"layer-a");
        let (toml, signature, trust, release_digest, artifact_digest) =
            sign_catalog_for_layer(&root, &artifact, "");
        let plan = signed_first_install_plan(
            "dark-1",
            &release_digest,
            &artifact_digest,
            "/exporter/state/edge-app",
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let bundle = complete_first_install_bundle(
            "dark-1",
            &plan_bytes,
            Some((&toml, Some(&signature), Some(&trust))),
            &archive,
            &exporter,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-ok".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let record = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap();
        assert_eq!(record.status, UpgradeStatus::Admitted);
        assert_eq!(
            record.environments[0].plan_id.as_deref(),
            Some(plan.id.as_str())
        );
        let evidence = record.environments[0].isolated.as_ref().unwrap();
        assert_eq!(
            evidence.plan_digest.as_deref(),
            Some(bundle.statement.plan_digest.as_str())
        );
        assert_eq!(
            evidence.approval_digest.as_deref(),
            Some(bundle.statement.approval_digest.as_str())
        );
        let stored = plan::load(&mut ctx, &plan.id).await.unwrap();
        assert_eq!(stored.id, plan.id);
        assert_eq!(stored.steps[0].workdir, "/exporter/state/edge-app");
        let release = ctx
            .get(&release_id("edge-app", "1.0.0"))
            .await
            .unwrap()
            .unwrap();
        let snapshot = release
            .properties
            .get("workdir")
            .cloned()
            .unwrap_or_default();
        let state = root.join("state").canonicalize().unwrap();
        assert!(
            std::path::Path::new(&snapshot).starts_with(&state),
            "host snapshot {snapshot} was not stored under TENKAI_STATE_DIR"
        );
        assert_ne!(snapshot, stored.steps[0].workdir);
        assert_eq!(
            connectivity_class(&mut ctx, "dark-1").await.unwrap(),
            ConnectivityClass::Isolated
        );
        assert!(
            ctx.get(&release_id("edge-app", "1.0.0"))
                .await
                .unwrap()
                .is_some()
        );
        let channel = ctx
            .get(&channel_id("edge-app", "stable"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            channel
                .properties
                .get("current_release")
                .map(String::as_str),
            Some(release_id("edge-app", "1.0.0").as_str())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_seeds_one_local_registry_and_a_rerun_is_a_no_op() {
        let root = temp_root("first-install-seed");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let artifact = sample_layer(b"layer-a");
        let (toml, signature, trust, release_digest, artifact_digest) =
            sign_catalog_for_layer(&root, &artifact, "");
        let plan = signed_first_install_plan(
            "dark-1",
            &release_digest,
            &artifact_digest,
            "/exporter/state/edge-app",
        );
        let archive = root.join("delivery.json");
        let bundle = complete_first_install_bundle(
            "dark-1",
            &serde_json::to_vec(&plan).unwrap(),
            Some((&toml, Some(&signature), Some(&trust))),
            &archive,
            &exporter,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-seed".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let seed = Some("seed.site:5443");
        let record = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            seed,
        )
        .await
        .unwrap();
        let env = ctx.get(&env_id("dark-1")).await.unwrap().unwrap();
        assert_eq!(
            env.properties
                .get(&format!("artifact_mirror.{}", artifact.registry))
                .map(String::as_str),
            seed
        );
        let blob = root
            .join("oci/seed.site:5443")
            .join(&artifact.repository)
            .join(artifact.digest.replace(':', "-"));
        assert!(blob.is_file(), "layer not stored under the seed registry");

        // The store is lost; the same install refills it and changes nothing else.
        std::fs::remove_file(&blob).unwrap();
        let rerun = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            seed,
        )
        .await
        .unwrap();
        assert_eq!(rerun, record);
        assert!(blob.is_file());
        let other = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            Some("other.site"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(other.contains("other artifact mirrors"), "{other}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_rejects_mismatched_layer_reference_before_mutation() {
        let root = temp_root("first-install-layer-ref");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let catalog_artifact = sample_layer(b"layer-a");
        let import_artifact = crate::oci_artifact::OciArtifactRef {
            registry: "registry.example".into(),
            repository: "other/app".into(),
            digest: catalog_artifact.digest.clone(),
            media_type: catalog_artifact.media_type.clone(),
            sbom: None,
        };
        let (toml, signature, trust, release_digest, artifact_digest) =
            sign_catalog_for_layer(&root, &catalog_artifact, "");
        let plan = signed_first_install_plan(
            "dark-1",
            &release_digest,
            &artifact_digest,
            "/exporter/state/edge-app",
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let bundle = complete_first_install_bundle_with_layer(
            "dark-1",
            &plan_bytes,
            Some((&toml, Some(&signature), Some(&trust))),
            &archive,
            &exporter,
            &import_artifact,
            BTreeMap::new(),
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-layer-ref".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("layer instructions do not name catalog artifact"),
            "{err}"
        );
        assert!(
            crate::environment::environment(&mut ctx, "dark-1")
                .await
                .is_err()
        );
        assert!(load_upgrade(&mut ctx, "first-layer-ref").await.is_err());
        assert!(
            ctx.get(&release_id("edge-app", "1.0.0"))
                .await
                .unwrap()
                .is_none()
        );
        let oci = std::path::PathBuf::from(crate::host_env::var_os("TENKAI_OCI_STORE").unwrap());
        assert!(
            !oci.join("registry.example").exists(),
            "layer import mutated the OCI store"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_rejects_recalled_release_before_mutation() {
        let root = temp_root("first-install-recalled");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let rid = release_id("edge-app", "1.0.0");
        ctx.create_once(Object {
            id: rid.clone(),
            kind: crate::ontology::KIND_RELEASE.into(),
            name: "edge-app@1.0.0".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("product".into(), "edge-app".into()),
                ("version".into(), "1.0.0".into()),
                (
                    "digest".into(),
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
                ),
                (
                    "artifact_digest".into(),
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .into(),
                ),
                ("recalled_at".into(), "1".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .await
        .unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let artifact = sample_layer(b"layer-a");
        let (toml, signature, trust, release_digest, artifact_digest) =
            sign_catalog_for_layer(&root, &artifact, "");
        let plan = signed_first_install_plan(
            "dark-1",
            &release_digest,
            &artifact_digest,
            "/exporter/state/edge-app",
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let bundle = complete_first_install_bundle(
            "dark-1",
            &plan_bytes,
            Some((&toml, Some(&signature), Some(&trust))),
            &archive,
            &exporter,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-recalled".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("recalled"), "{err}");
        assert!(
            crate::environment::environment(&mut ctx, "dark-1")
                .await
                .is_err()
        );
        assert!(load_upgrade(&mut ctx, "first-recalled").await.is_err());
        let oci = std::path::PathBuf::from(crate::host_env::var_os("TENKAI_OCI_STORE").unwrap());
        assert!(
            !oci.join("ghcr.io").exists(),
            "recalled first-install imported layers"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_completes_channel_pin_for_existing_matching_release() {
        let root = temp_root("first-install-resume-pin");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let artifact = sample_layer(b"layer-a");
        crate::oci_artifact::FilesystemArtifactRegistry::from_env()
            .unwrap()
            .put(&artifact, b"layer-a".to_vec())
            .unwrap();
        let (toml, signature, trust, release_digest, artifact_digest) =
            sign_catalog_for_layer(&root, &artifact, "");
        crate::catalog::publish(
            &mut ctx,
            &root.join("catalog-src/tenkai.toml"),
            &PublishOptions {
                signature: Some(root.join("catalog-src/release.sig.json")),
                trust_roots: Some(root.join("catalog-src/release-trust.toml")),
                allow_unsigned_development: false,
                artifact_registry: crate::oci_artifact::selected_registry().unwrap(),
                state_dir: Some(root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            ctx.get(&channel_id("edge-app", "stable"))
                .await
                .unwrap()
                .is_none()
        );
        let plan = signed_first_install_plan(
            "dark-1",
            &release_digest,
            &artifact_digest,
            "/exporter/state/edge-app",
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let bundle = complete_first_install_bundle(
            "dark-1",
            &plan_bytes,
            Some((&toml, Some(&signature), Some(&trust))),
            &archive,
            &exporter,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-resume".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let record = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap();
        assert_eq!(record.status, UpgradeStatus::Admitted);
        let channel = ctx
            .get(&channel_id("edge-app", "stable"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            channel
                .properties
                .get("current_release")
                .map(String::as_str),
            Some(release_id("edge-app", "1.0.0").as_str())
        );
        let _ = toml;
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_applies_top_level_file_modes_before_mutation() {
        let root = temp_root("first-install-file-modes");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let artifact = sample_layer(b"layer-a");
        let (toml, signature, trust, release_digest, artifact_digest) =
            sign_catalog_for_layer(&root, &artifact, "");
        let plan = signed_first_install_plan(
            "dark-1",
            &release_digest,
            &artifact_digest,
            "/exporter/state/edge-app",
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let mut extra = BTreeMap::new();
        extra.insert(
            "file-modes.json".into(),
            (
                "application/json".into(),
                br#"{"schema":"tenkai.offline-file-modes.v1","files":{"missing.sh":"0755"}}"#
                    .to_vec(),
            ),
        );
        let bundle = complete_first_install_bundle_with_layer(
            "dark-1",
            &plan_bytes,
            Some((&toml, Some(&signature), Some(&trust))),
            &archive,
            &exporter,
            &artifact,
            extra,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-modes".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("file mode path missing.sh"), "{err}");
        assert!(
            crate::environment::environment(&mut ctx, "dark-1")
                .await
                .is_err()
        );
        assert!(load_upgrade(&mut ctx, "first-modes").await.is_err());
        assert!(
            ctx.get(&release_id("edge-app", "1.0.0"))
                .await
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_rejects_existing_release_with_mismatched_bundle_layers() {
        let root = temp_root("first-install-existing-mismatch");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let catalog_artifact = sample_layer(b"layer-a");
        crate::oci_artifact::FilesystemArtifactRegistry::from_env()
            .unwrap()
            .put(&catalog_artifact, b"layer-a".to_vec())
            .unwrap();
        let (toml, signature, trust, release_digest, artifact_digest) =
            sign_catalog_for_layer(&root, &catalog_artifact, "");
        crate::catalog::publish(
            &mut ctx,
            &root.join("catalog-src/tenkai.toml"),
            &PublishOptions {
                signature: Some(root.join("catalog-src/release.sig.json")),
                trust_roots: Some(root.join("catalog-src/release-trust.toml")),
                allow_unsigned_development: false,
                artifact_registry: crate::oci_artifact::selected_registry().unwrap(),
                state_dir: Some(root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let import_artifact = crate::oci_artifact::OciArtifactRef {
            registry: "registry.example".into(),
            repository: "other/app".into(),
            digest: catalog_artifact.digest.clone(),
            media_type: catalog_artifact.media_type.clone(),
            sbom: None,
        };
        let plan = signed_first_install_plan(
            "dark-1",
            &release_digest,
            &artifact_digest,
            "/exporter/state/edge-app",
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let bundle = complete_first_install_bundle_with_layer(
            "dark-1",
            &plan_bytes,
            Some((&toml, Some(&signature), Some(&trust))),
            &archive,
            &exporter,
            &import_artifact,
            BTreeMap::new(),
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-existing-mismatch".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("layer instructions do not name catalog artifact"),
            "{err}"
        );
        assert!(
            load_upgrade(&mut ctx, "first-existing-mismatch")
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_rejects_change_set_pin_without_evidence_before_mutation() {
        let root = temp_root("first-install-changeset");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let artifact = sample_layer(b"layer-a");
        let pin = crate::manifest::ChangeSetPinSection {
            contract: crate::change_set_pin::PIN_CONTRACT.into(),
            namespace: "acme".into(),
            branch_id: "types".into(),
            proposal_id: "prop-1".into(),
            base_digest: format!("sha256:{}", "a".repeat(64)),
            closure_digest: format!("sha256:{}", "b".repeat(64)),
            receipt_digest: format!("sha256:{}", "c".repeat(64)),
            members: vec![crate::manifest::ChangeSetMemberSection {
                kind: "object_type".into(),
                id: "widget".into(),
                digest: format!("sha256:{}", "d".repeat(64)),
            }],
        };
        let extra = crate::change_set_pin::render_pin_toml(&pin);
        let (toml, signature, trust, release_digest, artifact_digest) =
            sign_catalog_for_layer(&root, &artifact, &extra);
        let plan = signed_first_install_plan(
            "dark-1",
            &release_digest,
            &artifact_digest,
            "/exporter/state/edge-app",
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let bundle = complete_first_install_bundle(
            "dark-1",
            &plan_bytes,
            Some((&toml, Some(&signature), Some(&trust))),
            &archive,
            &exporter,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-changeset".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("change-set publication evidence") || err.contains("change-set"),
            "{err}"
        );
        assert!(
            crate::environment::environment(&mut ctx, "dark-1")
                .await
                .is_err()
        );
        assert!(load_upgrade(&mut ctx, "first-changeset").await.is_err());
        assert!(
            ctx.get(&release_id("edge-app", "1.0.0"))
                .await
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn first_install_rejects_divergent_bundle_manifest_for_existing_release() {
        let root = temp_root("first-install-divergent-manifest");
        let _stores = lock_artifact_stores(&root);
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let artifact = sample_layer(b"layer-a");
        crate::oci_artifact::FilesystemArtifactRegistry::from_env()
            .unwrap()
            .put(&artifact, b"layer-a".to_vec())
            .unwrap();
        let (_toml, _signature, _trust, release_digest, artifact_digest) =
            sign_catalog_for_layer(&root, &artifact, "");
        crate::catalog::publish(
            &mut ctx,
            &root.join("catalog-src/tenkai.toml"),
            &PublishOptions {
                signature: Some(root.join("catalog-src/release.sig.json")),
                trust_roots: Some(root.join("catalog-src/release-trust.toml")),
                allow_unsigned_development: false,
                artifact_registry: crate::oci_artifact::selected_registry().unwrap(),
                state_dir: Some(root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let empty = br#"
[product]
name = "edge-app"
version = "1.0.0"

[deploy]
install = "true"
"#;
        let plan = signed_first_install_plan(
            "dark-1",
            &release_digest,
            &artifact_digest,
            "/exporter/state/edge-app",
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let archive = root.join("delivery.json");
        let bundle = complete_first_install_bundle(
            "dark-1",
            &plan_bytes,
            Some((empty, None, None)),
            &archive,
            &exporter,
        );
        bundle.save(&archive).unwrap();
        let roots = isolated_trust_roots(&exporter, None);
        let spec = UpgradeSpec {
            name: "first-divergent".into(),
            product: "edge-app".into(),
            version: "1.0.0".into(),
            channel: "stable".into(),
            environments: vec!["dark-1".into()],
        };
        let err = install_isolated_stack(
            &mut ctx,
            &spec,
            "dark-1",
            &bundle,
            &roots,
            Some(&archive),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("does not match published release")
                || err.contains("signed release verification"),
            "{err}"
        );
        assert!(load_upgrade(&mut ctx, "first-divergent").await.is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
