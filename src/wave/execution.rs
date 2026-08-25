//! Durable executable-wave admission, advancement, stop, and rollback.
//!
//! A wave coordinates existing per-environment plans. It does not apply,
//! promote, or recover outside Tenkai's plan, approval, gate, lease, health,
//! receipt, and rollback contracts (ADR 0017).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::WaveFailPolicy;
use crate::apply::{
    self, ExecutionAuthorization, ExecutionOptions, Outcome, StepOutcomeStatus,
    inspect_environment_lease,
};
use crate::client::Ctx;
use crate::ontology::{
    KIND_CHANNEL, KIND_WAVE, NS, channel_id, release_id, require_wave_schema, validate_identifier,
    wave_id,
};
use crate::pb::sekai::Object;
use crate::plan::{self, Action, Plan, PlanState};

pub const WAVE_FORMAT_VERSION: u32 = 1;
const WAVE_LEASE_NAMESPACE: &str = "tenkai/wave-execution";
const WAVE_LEASE_MS: i64 = 2 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableWaveSpec {
    pub name: String,
    pub product: String,
    pub version: String,
    pub channel: String,
    pub environments: Vec<String>,
    pub fail_policy: WaveFailPolicy,
}

impl ExecutableWaveSpec {
    pub fn new(
        name: impl Into<String>,
        product: impl Into<String>,
        version: impl Into<String>,
        channel: impl Into<String>,
        environments: impl IntoIterator<Item = String>,
        stop_on_failure: bool,
    ) -> Result<Self> {
        let spec = Self {
            name: name.into(),
            product: product.into(),
            version: version.into(),
            channel: channel.into(),
            environments: environments.into_iter().collect(),
            fail_policy: if stop_on_failure {
                WaveFailPolicy::StopOnFailure
            } else {
                WaveFailPolicy::Continue
            },
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier("wave name", &self.name)?;
        validate_identifier("product", &self.product)?;
        validate_identifier("version", &self.version)?;
        validate_identifier("channel", &self.channel)?;
        if self.environments.is_empty() {
            bail!("wave cohort must not be empty");
        }
        let mut seen = std::collections::BTreeSet::new();
        for environment in &self.environments {
            validate_identifier("environment", environment)?;
            if !seen.insert(environment) {
                bail!("wave cohort contains duplicate environment {environment}");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaveStatus {
    Admitted,
    Running,
    AwaitingApproval,
    Succeeded,
    Failed,
    Stopped,
    RollingBack,
    RolledBack,
    RecoveryRequired,
}

impl WaveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Stopped => "stopped",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::RecoveryRequired => "recovery_required",
        }
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::RolledBack | Self::RecoveryRequired
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaveEnvironmentStatus {
    Unstarted,
    Running,
    AwaitingApproval,
    Succeeded,
    Failed,
    Blocked,
    Skipped,
    RolledBack,
}

impl WaveEnvironmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unstarted => "unstarted",
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Blocked => "blocked",
            Self::Skipped => "skipped",
            Self::RolledBack => "rolled_back",
        }
    }

    fn is_complete(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Blocked | Self::Skipped | Self::RolledBack
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveEnvironmentRecord {
    pub environment: String,
    pub order: u32,
    pub status: WaveEnvironmentStatus,
    pub plan_id: Option<String>,
    pub plan_digest: Option<String>,
    pub gate_result: Option<String>,
    pub health_result: Option<String>,
    pub terminal_outcome: Option<String>,
    pub lease_generation: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveRecord {
    pub format_version: u32,
    pub name: String,
    pub id: String,
    pub identity_digest: String,
    pub product: String,
    pub version: String,
    pub channel: String,
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub fail_policy: WaveFailPolicy,
    pub status: WaveStatus,
    pub environments: Vec<WaveEnvironmentRecord>,
    pub current_order: u32,
    pub operator_decision: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy)]
pub enum WaveAuthorization<'a> {
    Signed {
        approval_dir: &'a Path,
        trust_roots: &'a Path,
    },
    LocalDevelopment {
        reason: &'a str,
    },
}

#[derive(Serialize)]
struct WaveIdentity<'a> {
    name: &'a str,
    product: &'a str,
    version: &'a str,
    channel: &'a str,
    release_id: &'a str,
    release_digest: &'a str,
    artifact_digest: &'a str,
    environments: &'a [String],
    fail_policy: WaveFailPolicy,
}

fn identity_digest(
    spec: &ExecutableWaveSpec,
    release_id: &str,
    release_digest: &str,
    artifact_digest: &str,
) -> Result<String> {
    let canonical = WaveIdentity {
        name: &spec.name,
        product: &spec.product,
        version: &spec.version,
        channel: &spec.channel,
        release_id,
        release_digest,
        artifact_digest,
        environments: &spec.environments,
        fail_policy: spec.fail_policy,
    };
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical)?)
    ))
}

fn wave_object(record: &WaveRecord) -> Result<Object> {
    let now = crate::now_millis();
    Ok(Object {
        id: record.id.clone(),
        kind: KIND_WAVE.into(),
        name: record.name.clone(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("name".into(), record.name.clone()),
            ("identity_digest".into(), record.identity_digest.clone()),
            ("product".into(), record.product.clone()),
            ("version".into(), record.version.clone()),
            ("channel".into(), record.channel.clone()),
            ("release_id".into(), record.release_id.clone()),
            ("release_digest".into(), record.release_digest.clone()),
            ("artifact_digest".into(), record.artifact_digest.clone()),
            ("status".into(), record.status.as_str().into()),
            ("record".into(), serde_json::to_string(record)?),
        ]),
        created: record.created_at,
        updated: now,
    })
}

fn record_from_object(object: &Object) -> Result<WaveRecord> {
    if object.kind != KIND_WAVE {
        bail!("object {} is not a wave record", object.id);
    }
    let raw = object
        .properties
        .get("record")
        .ok_or_else(|| anyhow::anyhow!("wave {} is missing its canonical record", object.id))?;
    let record: WaveRecord =
        serde_json::from_str(raw).with_context(|| format!("decoding wave record {}", object.id))?;
    if record.format_version != WAVE_FORMAT_VERSION {
        bail!(
            "wave {} has unsupported format version {}",
            record.id,
            record.format_version
        );
    }
    Ok(record)
}

async fn persist(ctx: &mut Ctx, record: &mut WaveRecord, lease: &WaveLease) -> Result<()> {
    ctx.refresh_lease(
        WAVE_LEASE_NAMESPACE,
        &lease.name,
        &lease.fencing_token,
        WAVE_LEASE_MS,
    )
    .await
    .context("refreshing the wave fencing lease before persisting")?;
    record.updated_at = crate::now_millis();
    ctx.guarded_update(
        wave_object(record)?,
        WAVE_LEASE_NAMESPACE,
        &lease.name,
        &lease.fencing_token,
    )
    .await
    .context("persisting the wave record under the current fencing generation")?;
    Ok(())
}

pub async fn load_wave(ctx: &mut Ctx, name: &str) -> Result<WaveRecord> {
    require_wave_schema(ctx).await?;
    validate_identifier("wave name", name)?;
    let object = ctx
        .get(&wave_id(name))
        .await?
        .ok_or_else(|| anyhow::anyhow!("wave {name} is not registered"))?;
    record_from_object(&object)
}

struct ReleasePin {
    release_id: String,
    release_digest: String,
    artifact_digest: String,
}

async fn resolve_release_pin(ctx: &mut Ctx, spec: &ExecutableWaveSpec) -> Result<ReleasePin> {
    let rid = release_id(&spec.product, &spec.version);
    let release = ctx.get(&rid).await?.ok_or_else(|| {
        anyhow::anyhow!("release {}@{} is not published", spec.product, spec.version)
    })?;
    if crate::catalog::release_is_recalled(ctx, &rid).await? {
        bail!("release {} is recalled and cannot admit a wave", rid);
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
    let channel = ctx.get(&channel_id(&spec.product, &spec.channel)).await?;
    let Some(channel) = channel else {
        bail!("channel {}/{} does not exist", spec.product, spec.channel);
    };
    if channel.kind != KIND_CHANNEL {
        bail!(
            "channel {}/{} has conflicting catalog identity",
            spec.product,
            spec.channel
        );
    }
    let current = channel
        .properties
        .get("current_release")
        .map(String::as_str)
        .unwrap_or("");
    if current != rid {
        bail!(
            "stale channel head: {}/{} currently names {current}, wave pins {rid}",
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

async fn revalidate_environment(
    ctx: &mut Ctx,
    record: &WaveRecord,
    environment: &str,
) -> Result<()> {
    crate::environment::environment(ctx, environment).await?;
    if crate::catalog::release_is_recalled(ctx, &record.release_id).await? {
        bail!(
            "release {} is recalled and cannot advance wave {}",
            record.release_id,
            record.name
        );
    }
    let release = ctx
        .get(&record.release_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("release {} disappeared", record.release_id))?;
    crate::catalog::require_deployable_trust(ctx, &release, environment).await?;
    let stored_digest = release.properties.get("digest").map(String::as_str);
    let stored_artifact = release
        .properties
        .get("artifact_digest")
        .map(String::as_str);
    if stored_digest != Some(record.release_digest.as_str())
        || stored_artifact != Some(record.artifact_digest.as_str())
    {
        bail!(
            "release {} content no longer matches the wave pin",
            record.release_id
        );
    }
    let channel = ctx
        .get(&channel_id(&record.product, &record.channel))
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("channel {}/{} disappeared", record.product, record.channel)
        })?;
    let current = channel
        .properties
        .get("current_release")
        .map(String::as_str)
        .unwrap_or("");
    if current != record.release_id {
        bail!(
            "stale channel head: {}/{} currently names {current}, wave {} pins {}",
            record.product,
            record.channel,
            record.name,
            record.release_id
        );
    }
    let inspect = plan::inspect_environment(ctx, environment).await?;
    let subscription = inspect
        .subscriptions
        .iter()
        .find(|row| row.product == record.product);
    let Some(subscription) = subscription else {
        bail!(
            "environment {environment} is not subscribed to {}/{}",
            record.product,
            record.channel
        );
    };
    if subscription.channel != record.channel {
        bail!(
            "environment {environment} subscribes {} to {}, wave pins {}",
            record.product,
            subscription.channel,
            record.channel
        );
    }
    let lease = inspect_environment_lease(ctx, environment).await?;
    if lease.held {
        bail!(
            "environment {environment} has an active apply lease owned by {}; stale controllers cannot complete wave {}",
            lease.owner.as_deref().unwrap_or("unknown"),
            record.name
        );
    }
    Ok(())
}

fn plan_pins_wave(plan: &Plan, record: &WaveRecord) -> Result<()> {
    let input = plan
        .inputs
        .iter()
        .find(|input| input.product == record.product);
    let Some(input) = input else {
        if plan.steps.iter().any(|step| step.product == record.product) {
            return Ok(());
        }
        bail!(
            "plan {} does not pin product {} required by wave {}",
            plan.id,
            record.product,
            record.name
        );
    };
    if input.release_id != record.release_id
        || input.release_digest != record.release_digest
        || input.artifact_digest != record.artifact_digest
        || input.desired_version != record.version
        || input.channel != record.channel
    {
        bail!(
            "plan {} does not pin wave {} release {}",
            plan.id,
            record.name,
            record.release_id
        );
    }
    if let Some(other) = plan
        .steps
        .iter()
        .find(|step| step.product != record.product)
    {
        bail!(
            "wave {} refuses plan {} because it also mutates product {}; converge that product separately",
            record.name,
            plan.id,
            other.product
        );
    }
    Ok(())
}

fn evidence_from_outcomes(
    plan: &Plan,
    outcomes: &[Outcome],
) -> Result<(String, String, String, WaveEnvironmentStatus, String)> {
    let mut gate = "satisfied";
    let mut health = "passed_or_not_configured";
    let mut status = WaveEnvironmentStatus::Succeeded;
    let mut detail = plan.status_detail.clone();
    for outcome in outcomes {
        match outcome.classified_status()? {
            StepOutcomeStatus::Blocked => {
                gate = if outcome.is_gate_blocked()? {
                    "blocked"
                } else {
                    gate
                };
                health = "not_run";
                status = WaveEnvironmentStatus::Blocked;
                detail = outcome.detail.clone();
            }
            StepOutcomeStatus::Failed => {
                health = "failed_or_unknown";
                status = WaveEnvironmentStatus::Failed;
                detail = outcome.detail.clone();
            }
            StepOutcomeStatus::RolledBack => {
                health = "failed_or_unknown";
                status = WaveEnvironmentStatus::Failed;
                detail = outcome.detail.clone();
            }
            StepOutcomeStatus::Succeeded => {}
        }
    }
    match plan.state {
        PlanState::Succeeded => {
            if status != WaveEnvironmentStatus::Succeeded {
                status = WaveEnvironmentStatus::Succeeded;
            }
        }
        PlanState::Blocked => {
            status = WaveEnvironmentStatus::Blocked;
            if gate == "satisfied" {
                gate = "blocked";
            }
            health = "not_run";
        }
        PlanState::Failed => {
            status = WaveEnvironmentStatus::Failed;
            if health == "passed_or_not_configured" {
                health = "failed_or_unknown";
            }
        }
        PlanState::Running | PlanState::Computed => {
            bail!(
                "plan {} is {} after apply; wave {} requires terminal evidence",
                plan.id,
                plan.state,
                plan.environment
            );
        }
    }
    Ok((
        gate.into(),
        health.into(),
        plan.state.to_string(),
        status,
        detail,
    ))
}

fn apply_fail_policy(record: &mut WaveRecord, failed_order: u32) {
    match record.fail_policy {
        WaveFailPolicy::StopOnFailure => {
            for environment in &mut record.environments {
                if environment.order > failed_order
                    && environment.status == WaveEnvironmentStatus::Unstarted
                {
                    environment.status = WaveEnvironmentStatus::Skipped;
                    environment.detail = "skipped after earlier wave failure".into();
                }
            }
            record.status = WaveStatus::Failed;
            record.operator_decision = Some("stop_on_failure".into());
        }
        WaveFailPolicy::Continue => {
            if record
                .environments
                .iter()
                .all(|environment| environment.status.is_complete())
            {
                record.status = WaveStatus::Failed;
            } else {
                record.status = WaveStatus::Running;
            }
        }
    }
}

fn refresh_wave_status(record: &mut WaveRecord) {
    if matches!(
        record.status,
        WaveStatus::Stopped | WaveStatus::RolledBack | WaveStatus::RecoveryRequired
    ) {
        return;
    }
    if record
        .environments
        .iter()
        .any(|environment| environment.status == WaveEnvironmentStatus::AwaitingApproval)
    {
        record.status = WaveStatus::AwaitingApproval;
        return;
    }
    let any_failed = record.environments.iter().any(|environment| {
        matches!(
            environment.status,
            WaveEnvironmentStatus::Failed | WaveEnvironmentStatus::Blocked
        )
    });
    if record
        .environments
        .iter()
        .all(|environment| environment.status.is_complete())
    {
        record.status = if any_failed {
            WaveStatus::Failed
        } else {
            WaveStatus::Succeeded
        };
        return;
    }
    record.status = WaveStatus::Running;
}

struct WaveLease {
    name: String,
    fencing_token: String,
}

async fn claim_wave_lease(ctx: &mut Ctx, name: &str) -> Result<WaveLease> {
    let owner = format!("wave:{name}:{}", crate::now_millis());
    let lease = ctx
        .acquire_lease(WAVE_LEASE_NAMESPACE, name, &owner, WAVE_LEASE_MS)
        .await
        .with_context(|| {
            format!(
                "wave {name} is already held by another controller; retry after that lease expires"
            )
        })?;
    Ok(WaveLease {
        name: name.into(),
        fencing_token: lease.fencing_token,
    })
}

async fn release_wave_lease(ctx: &mut Ctx, lease: &WaveLease) -> Result<()> {
    ctx.release_lease(WAVE_LEASE_NAMESPACE, &lease.name, &lease.fencing_token)
        .await
        .map(|_| ())
        .with_context(|| format!("releasing wave lease for {} failed", lease.name))
}

async fn finish_wave_lease<T>(ctx: &mut Ctx, lease: &WaveLease, result: Result<T>) -> Result<T> {
    match (result, release_wave_lease(ctx, lease).await) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(release)) => Err(error.context(release)),
    }
}

async fn admit_locked(ctx: &mut Ctx, spec: &ExecutableWaveSpec) -> Result<WaveRecord> {
    spec.validate()?;
    require_wave_schema(ctx).await?;
    let pin = resolve_release_pin(ctx, spec).await?;
    let digest = identity_digest(
        spec,
        &pin.release_id,
        &pin.release_digest,
        &pin.artifact_digest,
    )?;
    let id = wave_id(&spec.name);
    if let Some(existing) = ctx.get(&id).await? {
        let loaded = record_from_object(&existing)?;
        if loaded.identity_digest != digest {
            bail!(
                "wave {} already exists with a conflicting identity (cohort, release, channel, or policy changed)",
                spec.name
            );
        }
        return Ok(loaded);
    }
    for environment in &spec.environments {
        crate::environment::environment(ctx, environment).await?;
        let release = ctx
            .get(&pin.release_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("release {} disappeared", pin.release_id))?;
        crate::catalog::require_deployable_trust(ctx, &release, environment).await?;
        revalidate_environment(
            ctx,
            &WaveRecord {
                format_version: WAVE_FORMAT_VERSION,
                name: spec.name.clone(),
                id: wave_id(&spec.name),
                identity_digest: String::new(),
                product: spec.product.clone(),
                version: spec.version.clone(),
                channel: spec.channel.clone(),
                release_id: pin.release_id.clone(),
                release_digest: pin.release_digest.clone(),
                artifact_digest: pin.artifact_digest.clone(),
                fail_policy: spec.fail_policy,
                status: WaveStatus::Admitted,
                environments: Vec::new(),
                current_order: 0,
                operator_decision: None,
                created_at: 0,
                updated_at: 0,
            },
            environment,
        )
        .await?;
    }
    let now = crate::now_millis();
    let record = WaveRecord {
        format_version: WAVE_FORMAT_VERSION,
        name: spec.name.clone(),
        id: id.clone(),
        identity_digest: digest,
        product: spec.product.clone(),
        version: spec.version.clone(),
        channel: spec.channel.clone(),
        release_id: pin.release_id,
        release_digest: pin.release_digest,
        artifact_digest: pin.artifact_digest,
        fail_policy: spec.fail_policy,
        status: WaveStatus::Admitted,
        environments: spec
            .environments
            .iter()
            .enumerate()
            .map(|(index, environment)| WaveEnvironmentRecord {
                environment: environment.clone(),
                order: index as u32,
                status: WaveEnvironmentStatus::Unstarted,
                plan_id: None,
                plan_digest: None,
                gate_result: None,
                health_result: None,
                terminal_outcome: None,
                lease_generation: None,
                detail: String::new(),
            })
            .collect(),
        current_order: 0,
        operator_decision: None,
        created_at: now,
        updated_at: now,
    };
    match ctx.create_once(wave_object(&record)?).await {
        Ok(_) => Ok(record),
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE")) =>
        {
            let loaded = load_wave(ctx, &spec.name).await?;
            if loaded.identity_digest != record.identity_digest {
                bail!(
                    "wave {} already exists with a conflicting identity (cohort, release, channel, or policy changed)",
                    spec.name
                );
            }
            Ok(loaded)
        }
        Err(status) => Err(status.into()),
    }
}

fn signed_approval_path(approval_dir: &Path, plan_id: &str) -> Option<PathBuf> {
    let approval = approval_dir.join(format!("{plan_id}.json"));
    approval.is_file().then_some(approval)
}

async fn execute_plan(
    ctx: &mut Ctx,
    plan_id: &str,
    authorization: ExecutionAuthorization<'_>,
) -> Result<Vec<Outcome>> {
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
    .await
}

async fn capture_plan_evidence(
    ctx: &mut Ctx,
    record: &mut WaveRecord,
    index: usize,
    outcomes: &[Outcome],
) -> Result<()> {
    let plan_id = record.environments[index]
        .plan_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("wave environment is missing its plan identity"))?;
    let plan = plan::load(ctx, &plan_id).await?;
    let (gate, health, terminal, status, detail) = evidence_from_outcomes(&plan, outcomes)?;
    let digest = format!("sha256:{}", plan.executable_digest()?);
    let environment_name = record.environments[index].environment.clone();
    let order = record.environments[index].order;
    let lease = inspect_environment_lease(ctx, &environment_name).await?;
    let env = &mut record.environments[index];
    env.gate_result = Some(gate);
    env.health_result = Some(health);
    env.terminal_outcome = Some(terminal);
    env.status = status;
    env.detail = detail;
    env.plan_digest = Some(digest);
    env.lease_generation = lease.generation;
    record.current_order = order;
    if matches!(
        status,
        WaveEnvironmentStatus::Failed | WaveEnvironmentStatus::Blocked
    ) {
        apply_fail_policy(record, order);
    } else {
        refresh_wave_status(record);
    }
    Ok(())
}

async fn resume_existing_plan(
    ctx: &mut Ctx,
    record: &mut WaveRecord,
    index: usize,
    lease: &WaveLease,
) -> Result<bool> {
    let Some(plan_id) = record.environments[index].plan_id.clone() else {
        return Ok(false);
    };
    let plan = plan::load(ctx, &plan_id).await?;
    match plan.state {
        PlanState::Succeeded | PlanState::Failed | PlanState::Blocked => {
            let dummy = Vec::new();
            let (gate, health, terminal, status, detail) = evidence_from_outcomes(&plan, &dummy)
                .unwrap_or_else(|_| {
                    (
                        "unknown".into(),
                        "unknown".into(),
                        plan.state.to_string(),
                        match plan.state {
                            PlanState::Succeeded => WaveEnvironmentStatus::Succeeded,
                            PlanState::Blocked => WaveEnvironmentStatus::Blocked,
                            _ => WaveEnvironmentStatus::Failed,
                        },
                        plan.status_detail.clone(),
                    )
                });
            let order = record.environments[index].order;
            {
                let env = &mut record.environments[index];
                env.gate_result = Some(gate);
                env.health_result = Some(health);
                env.terminal_outcome = Some(terminal);
                env.status = status;
                env.detail = detail;
                env.plan_digest = Some(format!(
                    "sha256:{}",
                    plan.executable_digest().unwrap_or_default()
                ));
            }
            if matches!(
                status,
                WaveEnvironmentStatus::Failed | WaveEnvironmentStatus::Blocked
            ) {
                apply_fail_policy(record, order);
            } else {
                refresh_wave_status(record);
            }
            persist(ctx, record, lease).await?;
            Ok(true)
        }
        PlanState::Running => {
            record.status = WaveStatus::RecoveryRequired;
            record.environments[index].status = WaveEnvironmentStatus::Running;
            record.environments[index].detail =
                "plan is running after restart; reconcile the environment before resuming the wave"
                    .into();
            persist(ctx, record, lease).await?;
            Ok(true)
        }
        PlanState::Computed => Ok(false),
    }
}

async fn advance_locked(
    ctx: &mut Ctx,
    name: &str,
    authorization: WaveAuthorization<'_>,
    lease: &WaveLease,
) -> Result<WaveRecord> {
    require_wave_schema(ctx).await?;
    let mut record = load_wave(ctx, name).await?;
    if record.status == WaveStatus::Stopped {
        record.status = WaveStatus::Running;
        record.operator_decision = Some("resume".into());
        persist(ctx, &mut record, lease).await?;
    }
    if record.status.is_terminal() {
        return Ok(record);
    }
    if let Some(index) = record.environments.iter().position(|environment| {
        matches!(
            environment.status,
            WaveEnvironmentStatus::Unstarted
                | WaveEnvironmentStatus::AwaitingApproval
                | WaveEnvironmentStatus::Running
        )
    }) {
        if resume_existing_plan(ctx, &mut record, index, lease).await? {
            return Ok(record);
        }
        let environment = record.environments[index].environment.clone();
        revalidate_environment(ctx, &record, &environment).await?;
        let existing_plan_id = record.environments[index].plan_id.clone();
        let plan = if let Some(plan_id) = existing_plan_id.clone() {
            plan::load(ctx, &plan_id).await?
        } else {
            plan::create(ctx, &environment).await?
        };
        if plan
            .steps
            .iter()
            .any(|step| step.action == Action::Rollback)
        {
            bail!(
                "wave {} has a pending rollback plan {}; resume it with `tenkaictl wave rollback`",
                record.name,
                plan.id
            );
        }
        plan_pins_wave(&plan, &record)?;
        if existing_plan_id.is_none() {
            record.environments[index].plan_id = Some(plan.id.clone());
            record.environments[index].plan_digest =
                Some(format!("sha256:{}", plan.executable_digest()?));
            record.environments[index].status = WaveEnvironmentStatus::AwaitingApproval;
            persist(ctx, &mut record, lease).await?;
        }
        if !matches!(plan.state, PlanState::Computed | PlanState::Blocked) {
            bail!(
                "plan {} for wave {} is {}; only computed or blocked plans can execute",
                plan.id,
                record.name,
                plan.state
            );
        }
        let approval_path;
        let execution_authorization = match authorization {
            WaveAuthorization::LocalDevelopment { reason } => {
                if environment != "local" {
                    bail!(
                        "unapproved development execution is restricted to the built-in local environment"
                    );
                }
                ExecutionAuthorization::LocalDevelopment { reason }
            }
            WaveAuthorization::Signed {
                approval_dir,
                trust_roots,
            } => match signed_approval_path(approval_dir, &plan.id) {
                Some(path) => {
                    approval_path = path;
                    ExecutionAuthorization::Signed {
                        approval: &approval_path,
                        trust_roots,
                    }
                }
                None => {
                    record.environments[index].status = WaveEnvironmentStatus::AwaitingApproval;
                    record.environments[index].detail =
                        format!("signed approval required for plan {}", plan.id);
                    record.status = WaveStatus::AwaitingApproval;
                    persist(ctx, &mut record, lease).await?;
                    return Ok(record);
                }
            },
        };
        record.environments[index].status = WaveEnvironmentStatus::Running;
        record.status = WaveStatus::Running;
        persist(ctx, &mut record, lease).await?;
        match execute_plan(ctx, &plan.id, execution_authorization).await {
            Ok(outcomes) => {
                capture_plan_evidence(ctx, &mut record, index, &outcomes).await?;
            }
            Err(error) => {
                record_execute_error(ctx, &mut record, index, error).await?;
                persist(ctx, &mut record, lease).await?;
                return Ok(record);
            }
        }
        persist(ctx, &mut record, lease).await?;
        return Ok(record);
    }
    refresh_wave_status(&mut record);
    persist(ctx, &mut record, lease).await?;
    Ok(record)
}

/// Admit or resume a durable wave without executing the first environment.
pub async fn start_or_resume(ctx: &mut Ctx, spec: &ExecutableWaveSpec) -> Result<WaveRecord> {
    let lease = claim_wave_lease(ctx, &spec.name).await?;
    let result = admit_locked(ctx, spec).await;
    finish_wave_lease(ctx, &lease, result).await
}

/// Execute at most one pending environment of an admitted wave.
pub async fn advance(
    ctx: &mut Ctx,
    name: &str,
    authorization: WaveAuthorization<'_>,
) -> Result<WaveRecord> {
    let lease = claim_wave_lease(ctx, name).await?;
    let result = advance_locked(ctx, name, authorization, &lease).await;
    finish_wave_lease(ctx, &lease, result).await
}

/// Advance until the wave is terminal or waiting for plan approval.
pub async fn run_until_blocked(
    ctx: &mut Ctx,
    spec: &ExecutableWaveSpec,
    authorization: WaveAuthorization<'_>,
) -> Result<WaveRecord> {
    let _ = start_or_resume(ctx, spec).await?;
    loop {
        let record = advance(ctx, &spec.name, authorization).await?;
        if record.status.is_terminal() || record.status == WaveStatus::AwaitingApproval {
            return Ok(record);
        }
        if record
            .environments
            .iter()
            .all(|environment| environment.status.is_complete())
        {
            return Ok(record);
        }
    }
}

pub async fn stop_wave(ctx: &mut Ctx, name: &str) -> Result<WaveRecord> {
    let lease = claim_wave_lease(ctx, name).await?;
    let result = async {
        let mut record = load_wave(ctx, name).await?;
        if matches!(
            record.status,
            WaveStatus::RolledBack
                | WaveStatus::RecoveryRequired
                | WaveStatus::Succeeded
                | WaveStatus::Failed
        ) {
            return Ok(record);
        }
        record.status = WaveStatus::Stopped;
        record.operator_decision = Some("stop".into());
        persist(ctx, &mut record, &lease).await?;
        Ok(record)
    }
    .await;
    finish_wave_lease(ctx, &lease, result).await
}

pub async fn rollback_wave(
    ctx: &mut Ctx,
    name: &str,
    authorization: WaveAuthorization<'_>,
) -> Result<WaveRecord> {
    let lease = claim_wave_lease(ctx, name).await?;
    let result = rollback_locked(ctx, name, authorization, &lease).await;
    finish_wave_lease(ctx, &lease, result).await
}

async fn rollback_locked(
    ctx: &mut Ctx,
    name: &str,
    authorization: WaveAuthorization<'_>,
    lease: &WaveLease,
) -> Result<WaveRecord> {
    let mut record = load_wave(ctx, name).await?;
    if record.status == WaveStatus::RolledBack {
        return Ok(record);
    }
    record.status = WaveStatus::RollingBack;
    record.operator_decision = Some("rollback".into());
    persist(ctx, &mut record, lease).await?;
    let targets: Vec<(usize, String)> = record
        .environments
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, environment)| {
            environment.status == WaveEnvironmentStatus::Succeeded
                || environment.status == WaveEnvironmentStatus::AwaitingApproval
        })
        .map(|(index, environment)| (index, environment.environment.clone()))
        .collect();
    for (index, environment) in targets {
        let plan = if record.environments[index].status == WaveEnvironmentStatus::AwaitingApproval {
            let plan_id = record.environments[index]
                .plan_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("rollback is awaiting approval without a plan"))?;
            let loaded = plan::load(ctx, &plan_id).await?;
            if !loaded
                .steps
                .iter()
                .any(|step| step.action == Action::Rollback)
            {
                record.environments[index].status = WaveEnvironmentStatus::Skipped;
                record.environments[index].detail =
                    "skipped because the wave rolled back before this cohort executed".into();
                persist(ctx, &mut record, lease).await?;
                continue;
            }
            loaded
        } else if let Some(plan_id) = record.environments[index].plan_id.clone()
            && let Ok(existing) = plan::load(ctx, &plan_id).await
            && existing
                .steps
                .iter()
                .any(|step| step.action == Action::Rollback)
        {
            match existing.state {
                PlanState::Succeeded => {
                    record.environments[index].status = WaveEnvironmentStatus::RolledBack;
                    record.environments[index].terminal_outcome = Some(existing.state.to_string());
                    record.environments[index].detail = existing.status_detail.clone();
                    persist(ctx, &mut record, lease).await?;
                    continue;
                }
                PlanState::Computed | PlanState::Blocked => existing,
                PlanState::Running | PlanState::Failed => {
                    record.status = WaveStatus::RecoveryRequired;
                    record.environments[index].detail = format!(
                        "rollback plan {} is {}; reconcile before retrying wave rollback",
                        existing.id, existing.state
                    );
                    persist(ctx, &mut record, lease).await?;
                    return Ok(record);
                }
            }
        } else {
            let step = match plan::rollback_step(ctx, &environment, &record.product).await {
                Ok(step) => step,
                Err(error) => {
                    record.status = WaveStatus::RecoveryRequired;
                    record.environments[index].detail = error.to_string();
                    persist(ctx, &mut record, lease).await?;
                    return Ok(record);
                }
            };
            let created = plan::create_from_steps(ctx, &environment, vec![step]).await?;
            record.environments[index].plan_id = Some(created.id.clone());
            record.environments[index].plan_digest =
                Some(format!("sha256:{}", created.executable_digest()?));
            persist(ctx, &mut record, lease).await?;
            created
        };
        let approval_path;
        let execution_authorization = match authorization {
            WaveAuthorization::LocalDevelopment { reason } => {
                if environment != "local" {
                    bail!(
                        "unapproved development execution is restricted to the built-in local environment"
                    );
                }
                ExecutionAuthorization::LocalDevelopment { reason }
            }
            WaveAuthorization::Signed {
                approval_dir,
                trust_roots,
            } => match signed_approval_path(approval_dir, &plan.id) {
                Some(path) => {
                    approval_path = path;
                    ExecutionAuthorization::Signed {
                        approval: &approval_path,
                        trust_roots,
                    }
                }
                None => {
                    record.status = WaveStatus::AwaitingApproval;
                    record.environments[index].status = WaveEnvironmentStatus::AwaitingApproval;
                    record.environments[index].detail =
                        format!("signed approval required for rollback plan {}", plan.id);
                    persist(ctx, &mut record, lease).await?;
                    return Ok(record);
                }
            },
        };
        match execute_plan(ctx, &plan.id, execution_authorization).await {
            Ok(outcomes) => {
                let plan = plan::load(ctx, &plan.id).await?;
                let (_, _, terminal, status, detail) = evidence_from_outcomes(&plan, &outcomes)?;
                if plan.state == PlanState::Succeeded {
                    record.environments[index].status = WaveEnvironmentStatus::RolledBack;
                    record.environments[index].terminal_outcome = Some(terminal);
                    record.environments[index].detail = detail;
                    persist(ctx, &mut record, lease).await?;
                } else {
                    record.status = WaveStatus::RecoveryRequired;
                    record.environments[index].status = status;
                    record.environments[index].terminal_outcome = Some(terminal);
                    record.environments[index].detail = detail;
                    persist(ctx, &mut record, lease).await?;
                    return Ok(record);
                }
            }
            Err(error) => {
                record.status = WaveStatus::RecoveryRequired;
                record.environments[index].detail = error.to_string();
                persist(ctx, &mut record, lease).await?;
                return Err(error);
            }
        }
    }
    record.status = WaveStatus::RolledBack;
    persist(ctx, &mut record, lease).await?;
    Ok(record)
}

async fn record_execute_error(
    ctx: &mut Ctx,
    record: &mut WaveRecord,
    index: usize,
    error: anyhow::Error,
) -> Result<()> {
    let message = error.to_string();
    let plan_state = match record.environments[index].plan_id.as_deref() {
        Some(plan_id) => plan::load(ctx, plan_id).await.ok().map(|plan| plan.state),
        None => None,
    };
    record.environments[index].detail = message;
    match plan_state {
        Some(PlanState::Succeeded) | Some(PlanState::Running) => {
            record.status = WaveStatus::RecoveryRequired;
            record.environments[index].status = WaveEnvironmentStatus::Running;
        }
        Some(PlanState::Failed) => {
            record.environments[index].status = WaveEnvironmentStatus::Failed;
            let order = record.environments[index].order;
            apply_fail_policy(record, order);
        }
        Some(PlanState::Blocked) => {
            record.environments[index].status = WaveEnvironmentStatus::Blocked;
            let order = record.environments[index].order;
            apply_fail_policy(record, order);
        }
        Some(PlanState::Computed) | None => {
            record.environments[index].status = if record.environments[index].plan_id.is_some() {
                WaveEnvironmentStatus::AwaitingApproval
            } else {
                WaveEnvironmentStatus::Unstarted
            };
            record.status = if record.environments[index].plan_id.is_some() {
                WaveStatus::AwaitingApproval
            } else {
                WaveStatus::Running
            };
        }
    }
    Ok(())
}

pub fn format_wave(record: &WaveRecord) -> String {
    let mut lines = vec![format!(
        "wave name={} status={} identity={} release={} fail_policy={:?} current_order={}",
        record.name,
        record.status.as_str(),
        record.identity_digest,
        record.release_id,
        record.fail_policy,
        record.current_order
    )];
    lines.push(format!(
        "{:<6} {:<16} {:<16} plan detail",
        "order", "environment", "status"
    ));
    for environment in &record.environments {
        lines.push(format!(
            "{:<6} {:<16} {:<16} {} {}",
            environment.order,
            environment.environment,
            environment.status.as_str(),
            environment.plan_id.as_deref().unwrap_or("-"),
            environment.detail
        ));
    }
    lines.push(
        "note: executable waves do not authorize channel promotion; canary evidence remains the promotion gate (ADR 0017)"
            .into(),
    );
    lines.join("\n")
}
