//! Versioned remote management-lifecycle contract (ADR 0030).
//!
//! Admission for publish, promote, subscribe, plan, approve, apply, rollback,
//! recall, delivery holds, and failed-target retry lives here. HTTP adapters
//! call this module; they do not invent a second protocol or reuse spoke
//! runtime HTTP.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::auth_context::PrincipalKind;
use crate::plan_approval::ApprovalEnvelope;
use crate::release_signing::SignatureEnvelope;
use crate::signature_verification::{TrustRootKind, TrustRoots};

/// Wire and Rust contract version for `tenkai.management-lifecycle.v1`.
pub const MANAGEMENT_LIFECYCLE_API_VERSION: u32 = 1;

/// Total decoded deploy-input bytes a remote publish may carry.
pub const MAX_REMOTE_PUBLISH_INPUT_BYTES: u64 = 32 * 1024 * 1024;

/// HTTP body cap for `POST /v1/releases`: decoded inputs plus base64 and envelope.
pub const MAX_REMOTE_PUBLISH_HTTP_BYTES: usize =
    (MAX_REMOTE_PUBLISH_INPUT_BYTES as usize).saturating_mul(2);

/// Stable contract name recorded on the wire and in operator docs.
pub const MANAGEMENT_LIFECYCLE_CONTRACT: &str = "tenkai.management-lifecycle.v1";

/// Durable catalog snapshot directory for a remote publish.
/// Staging is deleted after admission, so this path must sit outside it.
pub fn remote_catalog_state_dir() -> Result<PathBuf> {
    let dir = if let Ok(path) = crate::host_env::var("TENKAI_STATE_DIR")
        && !path.is_empty()
    {
        PathBuf::from(path)
    } else if let Ok(path) = crate::host_env::var("STATE_DIRECTORY")
        && let Some(first) = path.split(':').map(str::trim).find(|part| !part.is_empty())
    {
        PathBuf::from(first)
    } else {
        std::env::current_dir()?.join(".tenkai-state")
    };
    prepare_catalog_state_dir(&dir)?;
    Ok(dir)
}

fn prepare_catalog_state_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    loop {
        match std::fs::symlink_metadata(dir) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    bail!(
                        "catalog state directory cannot be a symlink: {}",
                        dir.display()
                    );
                }
                if !metadata.is_dir() {
                    bail!(
                        "catalog state directory is not a directory: {}",
                        dir.display()
                    );
                }
                // SAFETY: geteuid has no preconditions and cannot fail.
                if metadata.uid() != unsafe { libc::geteuid() } {
                    bail!(
                        "catalog state directory is not owned by the server's user: {}",
                        dir.display()
                    );
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                    Ok(()) => return Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("creating catalog state directory {}", dir.display())
                        });
                    }
                }
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading catalog state directory {}", dir.display()));
            }
        }
    }
}

/// Closed lifecycle vocabulary accepted by version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementLifecycleOperation {
    Publish,
    Promote,
    Subscribe,
    Unsubscribe,
    Plan,
    Approve,
    Apply,
    Rollback,
    Recall,
    Retire,
    Hold,
    Release,
    HoldSchedule,
    HoldCancel,
    HoldThreshold,
    HoldThresholdClear,
    Retry,
    ChannelHold,
    ChannelRelease,
    ChannelRemove,
    ChannelConfigure,
    ChannelAdmit,
    ChannelPolicyPause,
    ChannelPolicyResume,
    WaiverSet,
    WaiverClear,
    ExposureGrace,
    ChannelExposureGrace,
    ReleaseLabelSet,
    ReleaseLabelClear,
    Register,
    Configure,
    Cancel,
}

impl ManagementLifecycleOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Promote => "promote",
            Self::Subscribe => "subscribe",
            Self::Unsubscribe => "unsubscribe",
            Self::Plan => "plan",
            Self::Approve => "approve",
            Self::Apply => "apply",
            Self::Rollback => "rollback",
            Self::Recall => "recall",
            Self::Retire => "retire",
            Self::Hold => "hold",
            Self::Release => "release",
            Self::HoldSchedule => "hold_schedule",
            Self::HoldCancel => "hold_cancel",
            Self::HoldThreshold => "hold_threshold",
            Self::HoldThresholdClear => "hold_threshold_clear",
            Self::Retry => "retry",
            Self::ChannelHold => "channel_hold",
            Self::ChannelRelease => "channel_release",
            Self::ChannelRemove => "channel_remove",
            Self::ChannelConfigure => "channel_configure",
            Self::ChannelAdmit => "channel_admit",
            Self::ChannelPolicyPause => "channel_policy_pause",
            Self::ChannelPolicyResume => "channel_policy_resume",
            Self::WaiverSet => "waiver_set",
            Self::WaiverClear => "waiver_clear",
            Self::ExposureGrace => "exposure_grace",
            Self::ChannelExposureGrace => "channel_exposure_grace",
            Self::ReleaseLabelSet => "release_label_set",
            Self::ReleaseLabelClear => "release_label_clear",
            Self::Register => "register",
            Self::Configure => "configure",
            Self::Cancel => "cancel",
        }
    }

    /// Catalog-wide verbs have no request environment and cannot be called
    /// with an environment-scoped management credential.
    pub fn is_catalog_wide(self) -> bool {
        matches!(
            self,
            Self::Publish
                | Self::Promote
                | Self::Recall
                | Self::ChannelHold
                | Self::ChannelRelease
                | Self::ChannelRemove
                | Self::ChannelConfigure
                | Self::ChannelAdmit
                | Self::ChannelPolicyPause
                | Self::ChannelPolicyResume
                | Self::WaiverSet
                | Self::WaiverClear
                | Self::ChannelExposureGrace
                | Self::ReleaseLabelSet
                | Self::ReleaseLabelClear
                | Self::Register
        )
    }

    /// Environment-bound verbs require `environment` on the envelope.
    pub fn requires_environment(self) -> bool {
        !self.is_catalog_wide()
    }

    /// Mutating environment-bound verbs require `expected_generation`.
    pub fn requires_expected_generation(self) -> bool {
        matches!(
            self,
            Self::Subscribe
                | Self::Unsubscribe
                | Self::Plan
                | Self::Approve
                | Self::Apply
                | Self::Rollback
                | Self::Hold
                | Self::Release
                | Self::HoldSchedule
                | Self::HoldCancel
                | Self::HoldThreshold
                | Self::HoldThresholdClear
                | Self::Retry
                | Self::Configure
                | Self::Cancel
                | Self::ExposureGrace
        )
    }
}

/// Fail-closed request header shared by lifecycle HTTP routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementLifecycleEnvelope {
    pub version: u32,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
}

/// Envelope that passed version, operation, field, and scope admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedManagementLifecycle {
    pub operation: ManagementLifecycleOperation,
    pub environment: Option<String>,
    pub expected_generation: Option<u64>,
}

pub fn require_management_lifecycle_api_version(version: u32) -> Result<()> {
    if version != MANAGEMENT_LIFECYCLE_API_VERSION {
        bail!(
            "unsupported management lifecycle API version {version}; expected {MANAGEMENT_LIFECYCLE_API_VERSION}"
        );
    }
    Ok(())
}

pub fn parse_management_lifecycle_operation(name: &str) -> Result<ManagementLifecycleOperation> {
    match name {
        "publish" => Ok(ManagementLifecycleOperation::Publish),
        "promote" => Ok(ManagementLifecycleOperation::Promote),
        "subscribe" => Ok(ManagementLifecycleOperation::Subscribe),
        "unsubscribe" => Ok(ManagementLifecycleOperation::Unsubscribe),
        "plan" => Ok(ManagementLifecycleOperation::Plan),
        "approve" => Ok(ManagementLifecycleOperation::Approve),
        "apply" => Ok(ManagementLifecycleOperation::Apply),
        "rollback" => Ok(ManagementLifecycleOperation::Rollback),
        "recall" => Ok(ManagementLifecycleOperation::Recall),
        "retire" => Ok(ManagementLifecycleOperation::Retire),
        "hold" => Ok(ManagementLifecycleOperation::Hold),
        "release" => Ok(ManagementLifecycleOperation::Release),
        "hold_schedule" => Ok(ManagementLifecycleOperation::HoldSchedule),
        "hold_cancel" => Ok(ManagementLifecycleOperation::HoldCancel),
        "hold_threshold" => Ok(ManagementLifecycleOperation::HoldThreshold),
        "hold_threshold_clear" => Ok(ManagementLifecycleOperation::HoldThresholdClear),
        "retry" => Ok(ManagementLifecycleOperation::Retry),
        "channel_hold" => Ok(ManagementLifecycleOperation::ChannelHold),
        "channel_release" => Ok(ManagementLifecycleOperation::ChannelRelease),
        "channel_remove" => Ok(ManagementLifecycleOperation::ChannelRemove),
        "channel_configure" => Ok(ManagementLifecycleOperation::ChannelConfigure),
        "channel_admit" => Ok(ManagementLifecycleOperation::ChannelAdmit),
        "channel_policy_pause" => Ok(ManagementLifecycleOperation::ChannelPolicyPause),
        "channel_policy_resume" => Ok(ManagementLifecycleOperation::ChannelPolicyResume),
        "waiver_set" => Ok(ManagementLifecycleOperation::WaiverSet),
        "waiver_clear" => Ok(ManagementLifecycleOperation::WaiverClear),
        "exposure_grace" => Ok(ManagementLifecycleOperation::ExposureGrace),
        "channel_exposure_grace" => Ok(ManagementLifecycleOperation::ChannelExposureGrace),
        "release_label_set" => Ok(ManagementLifecycleOperation::ReleaseLabelSet),
        "release_label_clear" => Ok(ManagementLifecycleOperation::ReleaseLabelClear),
        "register" => Ok(ManagementLifecycleOperation::Register),
        "configure" => Ok(ManagementLifecycleOperation::Configure),
        "cancel" => Ok(ManagementLifecycleOperation::Cancel),
        other => bail!("unknown management lifecycle operation {other:?}"),
    }
}

/// Refuse runtime principals and environment-scoped credentials that cross
/// their grant. Fleet management (no environment binding) is admitted here;
/// tenant visibility is enforced by host adapters.
pub fn authorize_management_lifecycle_scope(
    kind: PrincipalKind,
    granted_environment: Option<&str>,
    operation: ManagementLifecycleOperation,
    request_environment: Option<&str>,
) -> Result<()> {
    if kind == PrincipalKind::Runtime {
        bail!("runtime credentials cannot call management lifecycle operations");
    }
    if let Some(granted) = granted_environment {
        if operation.is_catalog_wide() {
            bail!(
                "environment-scoped credentials cannot call catalog-wide management operation {}",
                operation.as_str()
            );
        }
        match request_environment {
            Some(requested) if requested == granted => Ok(()),
            Some(_) => bail!("environment-scoped credentials cannot act on another environment"),
            None => bail!(
                "management operation {} requires environment {}",
                operation.as_str(),
                granted
            ),
        }
    } else {
        Ok(())
    }
}

pub fn admit_management_lifecycle(
    envelope: &ManagementLifecycleEnvelope,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_management_lifecycle_api_version(envelope.version)?;
    let operation = parse_management_lifecycle_operation(&envelope.operation)?;
    if operation.requires_environment() {
        match envelope.environment.as_deref() {
            Some(environment) if !environment.trim().is_empty() => {}
            _ => bail!(
                "management operation {} requires environment",
                operation.as_str()
            ),
        }
    } else if envelope.environment.is_some() {
        bail!(
            "management operation {} is catalog-wide and forbids environment",
            operation.as_str()
        );
    }
    if operation.requires_expected_generation() && envelope.expected_generation.is_none() {
        bail!(
            "management operation {} requires expected_generation",
            operation.as_str()
        );
    }
    if !operation.requires_expected_generation() && envelope.expected_generation.is_some() {
        bail!(
            "management operation {} forbids expected_generation",
            operation.as_str()
        );
    }
    authorize_management_lifecycle_scope(
        kind,
        granted_environment,
        operation,
        envelope.environment.as_deref(),
    )?;
    Ok(AdmittedManagementLifecycle {
        operation,
        environment: envelope.environment.clone(),
        expected_generation: envelope.expected_generation,
    })
}

pub fn parse_management_lifecycle_json(
    raw: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let envelope: ManagementLifecycleEnvelope = serde_json::from_str(raw)?;
    admit_management_lifecycle(&envelope, kind, granted_environment)
}

/// Versioned result shared by catalog lifecycle routes. A client ignores
/// fields it does not know, so a newer server can add one (#1172);
/// requests stay strict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ManagementLifecycleResult {
    pub version: u32,
    pub operation: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub digest: Option<String>,
    /// `<product>@<version>` the channel headed before this promotion (#1173).
    /// Omitted when the channel had no head or already named the promoted
    /// release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub replaced_head: Option<String>,
    /// One entry per step of an applied plan (#1076). Returned only to a
    /// client that asks with `?steps=true`: older clients refuse unknown
    /// fields here, so the default response stays as it was.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<ApplyStepResult>,
}

/// Longest step detail an apply response carries, in characters.
pub const STEP_DETAIL_CHARS: usize = 2_000;

/// The result of one step of a remote apply (#1076): the same facts an
/// embedded apply prints and records. Readers ignore fields they do not know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ApplyStepResult {
    pub product: String,
    pub instance: String,
    pub action: String,
    /// `succeeded`, `blocked`, `failed` or `rolled_back`.
    pub status: String,
    pub to_version: String,
    /// The step's detail, cut to [`STEP_DETAIL_CHARS`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub detail_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub cause: Option<crate::apply::DeploymentCause>,
    /// The version running after a restore: the previous version of a step
    /// rolled back on failure, or the target of a rollback step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub restored_version: Option<String>,
    /// The recorded deployment attempt (#1054), when one was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub attempt_id: Option<String>,
}

impl ApplyStepResult {
    /// The result of `outcome`, with the attempt it recorded, if any.
    pub fn from_outcome(outcome: &crate::apply::Outcome) -> Result<Self> {
        use crate::apply::StepOutcomeStatus;
        let status = outcome.classified_status()?;
        let step = &outcome.step;
        let restored_version = match status {
            StepOutcomeStatus::RolledBack => step.from.clone(),
            StepOutcomeStatus::Succeeded if step.action == crate::plan::Action::Rollback => {
                Some(step.to.clone())
            }
            _ => None,
        };
        let detail_truncated = outcome.detail.chars().count() > STEP_DETAIL_CHARS;
        Ok(Self {
            product: step.product.clone(),
            instance: step.instance_name().to_string(),
            action: step.action.to_string(),
            status: status.as_str().into(),
            to_version: step.to.clone(),
            detail: outcome.detail.chars().take(STEP_DETAIL_CHARS).collect(),
            detail_truncated,
            cause: outcome.cause.clone(),
            restored_version,
            attempt_id: outcome.attempt_id.clone(),
        })
    }

    /// The step's status, or `None` for one this release does not know.
    pub fn outcome_status(&self) -> Option<crate::apply::StepOutcomeStatus> {
        crate::apply::StepOutcomeStatus::parse(&self.status).ok()
    }
}

/// The body of a refused apply whose steps did not all succeed, when the
/// client asked for steps: the usual `error` plus every step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ApplyFailedBody {
    pub error: String,
    #[serde(default)]
    pub steps: Vec<ApplyStepResult>,
}

impl ManagementLifecycleResult {
    pub fn new(
        operation: ManagementLifecycleOperation,
        message: impl Into<String>,
        resource: Option<String>,
    ) -> Self {
        Self {
            version: MANAGEMENT_LIFECYCLE_API_VERSION,
            operation: operation.as_str().into(),
            message: message.into(),
            resource,
            digest: None,
            replaced_head: None,
            steps: Vec::new(),
        }
    }

    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }

    pub fn with_replaced_head(mut self, replaced_head: Option<String>) -> Self {
        self.replaced_head = replaced_head;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    pub version: u32,
    pub operation: String,
    pub manifest: String,
    pub signature: SignatureEnvelope,
    pub trust_roots: TrustRoots,
    /// Declared deploy inputs next to the manifest, with modes the signature binds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<PublishInputEntry>,
}

/// One file or directory from the release workdir, relative to the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishInputEntry {
    pub path: String,
    pub kind: PublishInputKind,
    /// Unix mode bits the artifact digest binds (`mode & 0o7777`).
    pub mode: u32,
    /// Standard base64 file bytes. Empty for directories.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublishInputKind {
    File,
    Dir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromoteRequest {
    pub version: u32,
    pub operation: String,
    pub spec: String,
}

// HTTP promote body with optional `expected_head` (#1158). A separate type so
// adding the field is not a Rust break on PromoteRequest; the published schema
// name stays PromoteRequest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "PromoteRequest")]
pub struct PromoteHttpRequest {
    pub version: u32,
    pub operation: String,
    pub spec: String,
    /// `<product>@<version>` the channel must head for the promotion to
    /// replace it (#1158). An empty channel, or one already heading `spec`,
    /// is promoted either way. A server that predates the field refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub expected_head: Option<String>,
}

impl PromoteHttpRequest {
    pub fn into_promote(self) -> (PromoteRequest, Option<String>) {
        (
            PromoteRequest {
                version: self.version,
                operation: self.operation,
                spec: self.spec,
            },
            self.expected_head,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecallRequest {
    pub version: u32,
    pub operation: String,
}

/// Body of `POST /v1/products/{product}/recall-range`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecallRangeRequest {
    pub version: u32,
    pub operation: String,
    pub product: String,
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub before: Option<String>,
    pub reason: String,
}

/// Body of `POST /v1/products/{product}/recall-range/close`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecallRangeCloseRequest {
    pub version: u32,
    pub operation: String,
    pub product: String,
    pub from: String,
    pub before: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubscribeRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    pub spec: String,
    /// Named instance; omitted or empty defaults to the product.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub instance: Option<String>,
}

/// `DELETE /v1/environments/{environment}/subscriptions/{product}`: remove
/// a product from the environment's desired state; the next approved plan
/// removes what is recorded for it (ADR 0049).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnsubscribeRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    pub product: String,
    /// Named instance; omitted or empty defaults to the product.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub instance: Option<String>,
    /// The version of the instance's recorded release the caller means to
    /// remove. Required while one is recorded; refused when another is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub expected_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetireEnvironmentRequest {
    pub version: u32,
    pub operation: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    pub approval: ApprovalEnvelope,
    pub trust_roots: TrustRoots,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    pub approval: ApprovalEnvelope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<ApprovalEnvelope>,
    pub trust_roots: TrustRoots,
    #[serde(default)]
    pub skip_gates: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_reason: Option<String>,
}

/// Ask for a plan that re-wraps every sealed value of the environment for
/// one more recipient key (ADR 0045 §5). The operation is `plan`: the
/// result is a plan that needs signed approval like any other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedRewrapRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    /// `sha256:<hex>` fingerprint of an unrevoked recipient key of the
    /// environment.
    pub recipient: String,
    /// Wraps for `recipient` that `secret recover` made offline with the
    /// recovery key (ADR 0045 §7), by instance. The plan's steps carry
    /// them; they take effect only once the recipient's runtime runs the
    /// approved step and opens each value with them. Omitted when empty,
    /// so a plain re-wrap request is unchanged; a server that predates the
    /// field refuses it.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub recovered: std::collections::BTreeMap<String, Vec<crate::sealed_secret::RecipientWrap>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryHoldRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Body of `POST /v1/environments/{environment}/hold/schedule` and
/// `POST /v1/environments/{environment}/hold/cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryFreezeRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Body of `POST /v1/environments/{environment}/hold/threshold` and
/// `POST /v1/environments/{environment}/hold/threshold/clear`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryFailureThresholdRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelHoldRequest {
    pub version: u32,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Body of `POST /v1/products/{product}/channels/{channel}/remove`.
/// `expected_head` (`<product>@<version>`) refuses the removal when another
/// release heads the channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelRemoveRequest {
    pub version: u32,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_head: Option<String>,
}

/// Body of `POST /v1/products/{product}/channels/{channel}/pace`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelConfigureRequest {
    pub version: u32,
    pub operation: String,
    /// Duration (`30`, `250ms`, `2m`, `3h`) or `off`. A bare number is seconds.
    pub upgrade_pace: String,
}

/// Body of `POST /v1/products/{product}/channels/{channel}/policy/pause`
/// and `.../policy/resume`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelPolicyPauseRequest {
    pub version: u32,
    pub operation: String,
}

/// Body of `POST /v1/products/{product}/channels/{channel}/admit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelAdmitRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub instance: String,
    pub reason: String,
}

/// Body of `POST /v1/exposures/waivers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExposureWaiverRequest {
    pub version: u32,
    pub operation: String,
    pub advisory_id: String,
    pub scope: String,
    pub category: String,
    pub reason: String,
    /// RFC3339 timestamp or duration (`7d`, `24h`). A bare number is seconds.
    pub expires: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
}

/// Body of `POST /v1/exposures/waivers/clear`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExposureWaiverClearRequest {
    pub version: u32,
    pub operation: String,
    pub advisory_id: String,
    pub scope: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
}

/// Body of `POST /v1/environments/{environment}/exposure-grace`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExposureGraceRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    /// Duration (`30`, `250ms`, `2m`, `24h`) or `off`. A bare number is seconds.
    pub grace: String,
}

/// Body of `POST /v1/products/{product}/channels/{channel}/exposure-grace`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelExposureGraceRequest {
    pub version: u32,
    pub operation: String,
    /// Duration (`30`, `250ms`, `2m`, `24h`) or `off`. A bare number is seconds.
    pub grace: String,
}

/// Body of `PUT`/`DELETE` `/v1/releases/{product}/{version}/labels`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseLabelRequest {
    pub version: u32,
    pub operation: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryFailedTargetRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug)]
pub struct RemotePublishFiles {
    _dir: PathBuf,
    pub manifest: PathBuf,
    pub signature: PathBuf,
    pub trust_roots: PathBuf,
}

impl RemotePublishFiles {
    pub fn materialize(
        manifest: &str,
        signature: &SignatureEnvelope,
        trust_roots: &TrustRoots,
        inputs: &[PublishInputEntry],
    ) -> Result<Self> {
        if manifest.trim().is_empty() {
            bail!("publish manifest must not be empty");
        }
        let signature_bytes = serde_json::to_vec(signature)?;
        let trust_roots_text = toml::to_string(trust_roots)?;
        let dir = std::env::temp_dir().join(format!(
            "tenkai-remote-publish-{}-{}-{}",
            std::process::id(),
            crate::now_millis(),
            uuid::Uuid::new_v4()
        ));
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .with_context(|| format!("creating publish staging directory {}", dir.display()))?;
        }
        let manifest_path = dir.join("tenkai.toml");
        let signature_path = dir.join("signature.json");
        let trust_roots_path = dir.join("trust-roots.toml");
        let cleanup = |dir: &Path| {
            let _ = std::fs::remove_dir_all(dir);
        };
        // Inputs first, then contract files, so a declared `tenkai.toml` cannot
        // replace the admitted manifest.
        write_publish_inputs(&dir, manifest, inputs).inspect_err(|_| cleanup(&dir))?;
        std::fs::write(&manifest_path, manifest)
            .with_context(|| format!("writing staged manifest {}", manifest_path.display()))
            .inspect_err(|_| cleanup(&dir))?;
        std::fs::write(&signature_path, signature_bytes)
            .with_context(|| format!("writing staged signature {}", signature_path.display()))
            .inspect_err(|_| cleanup(&dir))?;
        std::fs::write(&trust_roots_path, trust_roots_text)
            .with_context(|| format!("writing staged trust roots {}", trust_roots_path.display()))
            .inspect_err(|_| cleanup(&dir))?;
        Ok(Self {
            _dir: dir,
            manifest: manifest_path,
            signature: signature_path,
            trust_roots: trust_roots_path,
        })
    }
}

impl Drop for RemotePublishFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

#[derive(Debug)]
pub struct RemoteApprovalFiles {
    _dir: PathBuf,
    pub approval: PathBuf,
    pub trust_roots: PathBuf,
}

impl RemoteApprovalFiles {
    pub fn materialize(approval: &ApprovalEnvelope, trust_roots: &TrustRoots) -> Result<Self> {
        Self::materialize_set(approval, &[], trust_roots)
    }

    pub fn materialize_set(
        approval: &ApprovalEnvelope,
        extra: &[ApprovalEnvelope],
        trust_roots: &TrustRoots,
    ) -> Result<Self> {
        require_approval_files(approval, trust_roots)?;
        for envelope in extra {
            require_approval_files(envelope, trust_roots)?;
        }
        let dir = std::env::temp_dir().join(format!(
            "tenkai-remote-approval-{}-{}-{}",
            std::process::id(),
            crate::now_millis(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating approval staging directory {}", dir.display()))?;
        let trust_roots_path = dir.join("approval-trust-roots.toml");
        std::fs::write(&trust_roots_path, toml::to_string(trust_roots)?).with_context(|| {
            format!(
                "writing staged approval trust roots {}",
                trust_roots_path.display()
            )
        })?;
        if extra.is_empty() {
            let approval_path = dir.join("approval.json");
            std::fs::write(&approval_path, serde_json::to_vec(approval)?)
                .with_context(|| format!("writing staged approval {}", approval_path.display()))?;
            return Ok(Self {
                _dir: dir,
                approval: approval_path,
                trust_roots: trust_roots_path,
            });
        }
        let mut envelopes = Vec::with_capacity(extra.len() + 1);
        envelopes.push(approval.clone());
        envelopes.extend(extra.iter().cloned());
        for (index, envelope) in envelopes.iter().enumerate() {
            let path = dir.join(format!("{index}.json"));
            std::fs::write(&path, serde_json::to_vec(envelope)?)
                .with_context(|| format!("writing staged approval {}", path.display()))?;
        }
        Ok(Self {
            approval: dir.clone(),
            trust_roots: trust_roots_path,
            _dir: dir,
        })
    }
}

impl Drop for RemoteApprovalFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

pub fn admit_publish(
    request: &PublishRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Publish)?;
    Ok(admitted)
}

pub fn admit_promote(
    request: &PromoteRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Promote)?;
    if request.spec.trim().is_empty() {
        bail!("promote requires <product>@<version>");
    }
    Ok(admitted)
}

/// Refuses `expected_head` that is not `<product>@<version>` of the same
/// product as `spec` (#1158).
pub(crate) fn require_promote_expected_head(spec: &str, expected_head: Option<&str>) -> Result<()> {
    let Some(expected) = expected_head else {
        return Ok(());
    };
    let Some((expected_product, _)) = expected.split_once('@') else {
        bail!("expected_head must be <product>@<version>, got {expected:?}");
    };
    let spec_product = spec.split_once('@').map(|(product, _)| product);
    if spec_product != Some(expected_product) {
        bail!("expected_head {expected} names another product than {spec}");
    }
    Ok(())
}

pub fn admit_recall(
    request: &RecallRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Recall)?;
    Ok(admitted)
}

fn admit_catalog_recall(
    version: u32,
    operation: &str,
    product: &str,
    path_product: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    crate::ontology::validate_identifier("product", product)?;
    anyhow::ensure!(
        product == path_product,
        "recall range product {product} does not match path {path_product}"
    );
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version,
            operation: operation.to_string(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Recall)?;
    Ok(admitted)
}

pub fn admit_recall_range(
    request: &RecallRangeRequest,
    path_product: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    anyhow::ensure!(
        !request.reason.trim().is_empty(),
        "recall range reason must not be empty"
    );
    admit_catalog_recall(
        request.version,
        &request.operation,
        &request.product,
        path_product,
        kind,
        granted_environment,
    )
}

pub fn admit_recall_range_close(
    request: &RecallRangeCloseRequest,
    path_product: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    admit_catalog_recall(
        request.version,
        &request.operation,
        &request.product,
        path_product,
        kind,
        granted_environment,
    )
}

pub fn admit_subscribe(
    request: &SubscribeRequest,
    path_environment: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    if request.environment != path_environment {
        bail!(
            "subscribe environment {} does not match path {path_environment}",
            request.environment
        );
    }
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: Some(request.environment.clone()),
            expected_generation: Some(request.expected_generation),
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Subscribe)?;
    if request.spec.split_once('=').is_none() {
        bail!("subscribe requires <product>=<channel>");
    }
    Ok(admitted)
}

pub fn admit_unsubscribe(
    request: &UnsubscribeRequest,
    path_environment: &str,
    path_product: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    if request.environment != path_environment || request.product != path_product {
        bail!(
            "unsubscribe of {} from {} does not match path {path_product} in {path_environment}",
            request.product,
            request.environment
        );
    }
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: Some(request.environment.clone()),
            expected_generation: Some(request.expected_generation),
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(
        admitted.operation,
        ManagementLifecycleOperation::Unsubscribe,
    )?;
    Ok(admitted)
}

pub fn admit_retire_environment(
    request: &RetireEnvironmentRequest,
    environment: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<()> {
    require_management_lifecycle_api_version(request.version)?;
    let operation = parse_management_lifecycle_operation(&request.operation)?;
    require_route_operation(operation, ManagementLifecycleOperation::Retire)?;
    if environment.trim().is_empty() {
        bail!("environment retirement requires an environment");
    }
    if request.reason.trim().is_empty() {
        bail!("retirement reason must not be empty");
    }
    if request.reason.trim().len() > 1024 {
        bail!("retirement reason exceeds 1024 bytes");
    }
    authorize_management_lifecycle_scope(kind, granted_environment, operation, Some(environment))
}

pub fn admit_plan(
    request: &PlanRequest,
    path_environment: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_path_environment("plan", &request.environment, path_environment)?;
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        ManagementLifecycleOperation::Plan,
        kind,
        granted_environment,
    )
}

pub fn admit_approve(
    request: &ApproveRequest,
    path_plan_id: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_plan_id(path_plan_id)?;
    let admitted = admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        ManagementLifecycleOperation::Approve,
        kind,
        granted_environment,
    )?;
    require_approval_files(&request.approval, &request.trust_roots)?;
    Ok(admitted)
}

pub fn admit_apply(
    request: &ApplyRequest,
    path_plan_id: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_plan_id(path_plan_id)?;
    if let Some(reason) = request.emergency_reason.as_deref()
        && reason.trim().is_empty()
    {
        bail!("apply emergency_reason must not be empty when set");
    }
    let admitted = admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        ManagementLifecycleOperation::Apply,
        kind,
        granted_environment,
    )?;
    require_approval_files(&request.approval, &request.trust_roots)?;
    Ok(admitted)
}

pub fn admit_cancel_apply(
    request: &DeliveryHoldRequest,
    path_environment: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_path_environment("cancel", &request.environment, path_environment)?;
    if let Some(reason) = request.reason.as_deref()
        && reason.trim().is_empty()
    {
        bail!("cancel reason must not be empty when set");
    }
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        ManagementLifecycleOperation::Cancel,
        kind,
        granted_environment,
    )
}

pub fn admit_rollback(
    request: &RollbackRequest,
    path_environment: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_path_environment("rollback", &request.environment, path_environment)?;
    if request.product.trim().is_empty() {
        bail!("rollback requires product");
    }
    if let Some(reason) = request.recovery_reason.as_deref()
        && reason.trim().is_empty()
    {
        bail!("rollback recovery_reason must not be empty when set");
    }
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        ManagementLifecycleOperation::Rollback,
        kind,
        granted_environment,
    )
}

pub fn admit_sealed_rewrap(
    request: &SealedRewrapRequest,
    path_environment: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_path_environment("re-wrap", &request.environment, path_environment)?;
    let recipient = crate::sealing_key::normalize_fingerprint(&request.recipient)?;
    for (instance, wraps) in &request.recovered {
        crate::ontology::validate_identifier("instance", instance)?;
        for wrap in wraps {
            crate::sealed_secret::SecretRef::new(&wrap.secret, &wrap.key)?;
            crate::sealed_secret::check_wrap(&wrap.wrap)?;
            anyhow::ensure!(
                wrap.wrap.fingerprint == recipient,
                "a recovered wrap is for {}, not the re-wrap recipient {recipient}",
                wrap.wrap.fingerprint
            );
        }
    }
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        ManagementLifecycleOperation::Plan,
        kind,
        granted_environment,
    )
}

pub fn admit_delivery_hold(
    request: &DeliveryHoldRequest,
    path_environment: &str,
    expected: ManagementLifecycleOperation,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_path_environment(expected.as_str(), &request.environment, path_environment)?;
    if expected == ManagementLifecycleOperation::Hold {
        require_hold_reason(request.reason.as_deref())?;
    } else if request
        .reason
        .as_ref()
        .is_some_and(|reason| !reason.is_empty())
    {
        bail!("management operation {} forbids reason", expected.as_str());
    }
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        expected,
        kind,
        granted_environment,
    )
}

pub fn admit_delivery_freeze(
    request: &DeliveryFreezeRequest,
    path_environment: &str,
    expected: ManagementLifecycleOperation,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_path_environment(expected.as_str(), &request.environment, path_environment)?;
    crate::ontology::validate_identifier("freeze", &request.name)?;
    if expected == ManagementLifecycleOperation::HoldSchedule {
        require_hold_reason(request.reason.as_deref())?;
        let until = request
            .until
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--until is required"))?;
        let until_ms = crate::delivery_hold::parse_freeze_instant("--until", until)?;
        if let Some(from) = request.from.as_deref() {
            let from_ms = crate::delivery_hold::parse_freeze_instant("--from", from)?;
            anyhow::ensure!(until_ms > from_ms, "--until must be after --from");
        }
    } else {
        if request
            .reason
            .as_ref()
            .is_some_and(|reason| !reason.is_empty())
        {
            bail!("management operation {} forbids reason", expected.as_str());
        }
        if request.from.is_some() || request.until.is_some() {
            bail!(
                "management operation {} forbids from and until",
                expected.as_str()
            );
        }
    }
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        expected,
        kind,
        granted_environment,
    )
}

pub fn admit_delivery_failure_threshold(
    request: &DeliveryFailureThresholdRequest,
    path_environment: &str,
    expected: ManagementLifecycleOperation,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_path_environment(expected.as_str(), &request.environment, path_environment)?;
    if expected == ManagementLifecycleOperation::HoldThreshold {
        let count = request
            .count
            .ok_or_else(|| anyhow::anyhow!("--count is required"))?;
        anyhow::ensure!(count >= 1, "--count must be at least 1");
        let window = request
            .window
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--window is required"))?;
        crate::delivery_hold::parse_failure_window(window)?;
    } else if request.count.is_some() || request.window.is_some() {
        bail!(
            "management operation {} forbids count and window",
            expected.as_str()
        );
    }
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        expected,
        kind,
        granted_environment,
    )
}

pub fn admit_channel_hold(
    request: &ChannelHoldRequest,
    expected: ManagementLifecycleOperation,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    if expected == ManagementLifecycleOperation::ChannelHold {
        require_hold_reason(request.reason.as_deref())?;
    } else if request
        .reason
        .as_ref()
        .is_some_and(|reason| !reason.is_empty())
    {
        bail!("management operation {} forbids reason", expected.as_str());
    }
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, expected)?;
    Ok(admitted)
}

pub fn admit_channel_remove(
    request: &ChannelRemoveRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(
        admitted.operation,
        ManagementLifecycleOperation::ChannelRemove,
    )?;
    Ok(admitted)
}

pub fn admit_channel_configure(
    request: &ChannelConfigureRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    crate::upgrade_pace::parse_pace(&request.upgrade_pace)?;
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(
        admitted.operation,
        ManagementLifecycleOperation::ChannelConfigure,
    )?;
    Ok(admitted)
}

pub fn admit_channel_policy_pause(
    request: &ChannelPolicyPauseRequest,
    expected: ManagementLifecycleOperation,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, expected)?;
    Ok(admitted)
}

pub fn admit_channel_admit(
    request: &ChannelAdmitRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    crate::ontology::validate_identifier("environment", &request.environment)?;
    crate::ontology::validate_instance_name(&request.instance)
        .or_else(|_| crate::ontology::validate_identifier("instance", &request.instance))?;
    anyhow::ensure!(
        !request.reason.trim().is_empty(),
        "upgrade-pace admit reason must not be empty"
    );
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(
        admitted.operation,
        ManagementLifecycleOperation::ChannelAdmit,
    )?;
    Ok(admitted)
}

pub fn admit_exposure_waiver(
    request: &ExposureWaiverRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    crate::exposure::WaiverScopeKind::parse(&request.scope)?;
    crate::exposure::WaiverCategory::parse(&request.category)?;
    crate::exposure::parse_expiry(&request.expires, crate::now_millis())?;
    anyhow::ensure!(
        !request.advisory_id.trim().is_empty(),
        "waiver advisory id is required"
    );
    anyhow::ensure!(
        !request.reason.trim().is_empty(),
        "waiver reason must not be empty"
    );
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::WaiverSet)?;
    Ok(admitted)
}

pub fn admit_exposure_waiver_clear(
    request: &ExposureWaiverClearRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    crate::exposure::WaiverScopeKind::parse(&request.scope)?;
    anyhow::ensure!(
        !request.advisory_id.trim().is_empty(),
        "waiver advisory id is required"
    );
    anyhow::ensure!(
        !request.reason.trim().is_empty(),
        "waiver reason must not be empty"
    );
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(
        admitted.operation,
        ManagementLifecycleOperation::WaiverClear,
    )?;
    Ok(admitted)
}

pub fn admit_exposure_grace(
    request: &ExposureGraceRequest,
    path_environment: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    crate::exposure::parse_grace(&request.grace)?;
    require_path_environment("exposure_grace", &request.environment, path_environment)?;
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        ManagementLifecycleOperation::ExposureGrace,
        kind,
        granted_environment,
    )
}

pub fn admit_channel_exposure_grace(
    request: &ChannelExposureGraceRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    crate::exposure::parse_grace(&request.grace)?;
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(
        admitted.operation,
        ManagementLifecycleOperation::ChannelExposureGrace,
    )?;
    Ok(admitted)
}

pub fn admit_release_label(
    request: &ReleaseLabelRequest,
    expected: ManagementLifecycleOperation,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    crate::labels::validate_label_key(&request.key)?;
    if expected == ManagementLifecycleOperation::ReleaseLabelSet {
        let value = request.value.as_deref().unwrap_or("");
        crate::labels::validate_label_value(&request.key, value)?;
    }
    anyhow::ensure!(
        !request.reason.trim().is_empty(),
        "release label reason must not be empty"
    );
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, expected)?;
    Ok(admitted)
}

pub fn admit_retry_failed_target(
    request: &RetryFailedTargetRequest,
    path_environment: &str,
    path_product: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_path_environment("retry", &request.environment, path_environment)?;
    if request.product != path_product {
        bail!(
            "retry product {} does not match path {path_product}",
            request.product
        );
    }
    if request.product.trim().is_empty() {
        bail!("retry requires a product");
    }
    require_hold_reason(request.reason.as_deref())?;
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        ManagementLifecycleOperation::Retry,
        kind,
        granted_environment,
    )
}

/// Admit `POST /v1/environments`. Registration is catalog-wide: an
/// environment-scoped credential cannot create environments.
pub fn admit_register_environment(
    request: &crate::environment_config::RegisterEnvironmentRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    crate::ontology::validate_identifier("environment", &request.environment)?;
    crate::environment_config::require_reason(&request.reason)?;
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Register)?;
    Ok(admitted)
}

/// Admit one configuration route: the path environment, the route's
/// resource, method and window name, and the generation-fenced envelope.
pub fn admit_environment_config(
    request: &crate::environment_config::EnvironmentConfigRequest,
    path_environment: &str,
    route: (
        crate::environment_config::ConfigResource,
        bool,
        Option<&str>,
    ),
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_path_environment("configure", &request.environment, path_environment)?;
    let (resource, clears, window) = route;
    crate::environment_config::require_route(&request.change, resource, clears, window)?;
    crate::environment_config::require_reason(&request.reason)?;
    crate::environment_config::validate(&request.change)?;
    admit_environment_operation(
        request.version,
        &request.operation,
        &request.environment,
        request.expected_generation,
        ManagementLifecycleOperation::Configure,
        kind,
        granted_environment,
    )
}

fn require_hold_reason(reason: Option<&str>) -> Result<()> {
    let reason = reason.map(str::trim).unwrap_or("");
    if reason.is_empty() {
        bail!("delivery hold reason must not be empty");
    }
    if reason.len() > 1024 {
        bail!("delivery hold reason exceeds 1024 bytes");
    }
    Ok(())
}

fn admit_environment_operation(
    version: u32,
    operation: &str,
    environment: &str,
    expected_generation: u64,
    expected: ManagementLifecycleOperation,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version,
            operation: operation.to_string(),
            environment: Some(environment.to_string()),
            expected_generation: Some(expected_generation),
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, expected)?;
    Ok(admitted)
}

fn require_path_environment(operation: &str, request: &str, path: &str) -> Result<()> {
    if request != path {
        bail!("{operation} environment {request} does not match path {path}");
    }
    Ok(())
}

fn require_plan_id(plan_id: &str) -> Result<()> {
    if plan_id.trim().is_empty() {
        bail!("management plan routes require a plan id");
    }
    Ok(())
}

fn require_approval_files(approval: &ApprovalEnvelope, trust_roots: &TrustRoots) -> Result<()> {
    if approval.schema.trim().is_empty() || approval.signature.trim().is_empty() {
        bail!("missing approval evidence");
    }
    if trust_roots.signers.is_empty() {
        bail!("missing approval evidence");
    }
    Ok(())
}

pub fn plan_environment_from_id(plan_id: &str) -> Result<&str> {
    let identity = plan_id
        .strip_prefix("tenkai:plan:")
        .ok_or_else(|| anyhow::anyhow!("invalid plan id {plan_id}"))?;
    let mut parts = identity.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(environment), Some(created_at), Some(content_id), None)
            if !environment.is_empty()
                && created_at.parse::<i64>().is_ok()
                && !content_id.is_empty() =>
        {
            Ok(environment)
        }
        _ => bail!("invalid plan id {plan_id}"),
    }
}

fn require_route_operation(
    found: ManagementLifecycleOperation,
    expected: ManagementLifecycleOperation,
) -> Result<()> {
    if found != expected {
        bail!(
            "management operation {} is not valid on this route; expected {}",
            found.as_str(),
            expected.as_str()
        );
    }
    Ok(())
}

pub fn environment_fence_generation(lease_generation: Option<u64>) -> u64 {
    lease_generation.unwrap_or(0)
}

pub fn require_expected_generation(expected: u64, actual: u64) -> Result<()> {
    if expected != actual {
        bail!("stale fencing generation {expected} cannot complete; expected {actual}");
    }
    Ok(())
}

pub fn load_publish_request(
    manifest: &Path,
    signature: &Path,
    trust_roots: &Path,
) -> Result<PublishRequest> {
    let loaded = crate::manifest::load(manifest)?;
    Ok(PublishRequest {
        version: MANAGEMENT_LIFECYCLE_API_VERSION,
        operation: ManagementLifecycleOperation::Publish.as_str().into(),
        manifest: loaded.raw,
        signature: SignatureEnvelope::load(signature)?,
        trust_roots: TrustRoots::load(
            trust_roots,
            crate::signature_verification::TrustRootKind::Release,
        )?,
        inputs: collect_publish_inputs(&loaded.workdir, &loaded.manifest.immutable_inputs())?,
    })
}

fn require_relative_publish_path(path: &str) -> Result<()> {
    let relative = Path::new(path);
    if path.is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        bail!("deploy input must be a relative path without '..': {path}");
    }
    Ok(())
}

fn require_publish_workdir(path: &str) -> Result<()> {
    let relative = Path::new(path);
    if path.is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        bail!("deploy.workdir must be a relative path without '..': {path}");
    }
    Ok(())
}

fn collect_publish_inputs(workdir: &Path, declared: &[String]) -> Result<Vec<PublishInputEntry>> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    let mut declared = declared.to_vec();
    declared.sort();
    for input in declared {
        require_relative_publish_path(&input)?;
        collect_publish_entry(workdir, &input, &mut entries, &mut seen, &mut total)?;
    }
    Ok(entries)
}

fn collect_publish_entry(
    workdir: &Path,
    relative: &str,
    entries: &mut Vec<PublishInputEntry>,
    seen: &mut BTreeSet<String>,
    total: &mut u64,
) -> Result<()> {
    if !seen.insert(relative.to_string()) {
        return Ok(());
    }
    use std::os::unix::fs::PermissionsExt as _;
    let path = workdir.join(relative);
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("reading deploy input {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("deploy input cannot be a symlink: {relative}");
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if metadata.is_dir() {
        entries.push(PublishInputEntry {
            path: relative.to_string(),
            kind: PublishInputKind::Dir,
            mode,
            content: String::new(),
        });
        let mut children: Vec<_> = std::fs::read_dir(&path)
            .with_context(|| format!("reading deploy input {}", path.display()))?
            .collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let name = child
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("deploy input is not UTF-8: {relative}"))?;
            collect_publish_entry(workdir, &format!("{relative}/{name}"), entries, seen, total)?;
        }
        return Ok(());
    }
    if metadata.is_file() {
        let remaining = MAX_REMOTE_PUBLISH_INPUT_BYTES.saturating_sub(*total);
        if metadata.len() > remaining {
            bail!("publish inputs exceed {MAX_REMOTE_PUBLISH_INPUT_BYTES} bytes");
        }
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading deploy input {}", path.display()))?;
        *total = total.saturating_add(bytes.len() as u64);
        if *total > MAX_REMOTE_PUBLISH_INPUT_BYTES {
            bail!("publish inputs exceed {MAX_REMOTE_PUBLISH_INPUT_BYTES} bytes");
        }
        entries.push(PublishInputEntry {
            path: relative.to_string(),
            kind: PublishInputKind::File,
            mode,
            content: STANDARD.encode(bytes),
        });
        return Ok(());
    }
    bail!("deploy input is not a file or directory: {relative}")
}

fn write_publish_inputs(
    dir: &Path,
    manifest_text: &str,
    inputs: &[PublishInputEntry],
) -> Result<()> {
    let manifest: crate::manifest::Manifest =
        toml::from_str(manifest_text).context("parsing publish manifest for deploy inputs")?;
    require_publish_workdir(&manifest.deploy.workdir)?;
    let input_root = dir.join(&manifest.deploy.workdir);
    std::fs::create_dir_all(&input_root)
        .with_context(|| format!("staging deploy workdir {}", input_root.display()))?;
    let declared = manifest.immutable_inputs();
    let mut total = 0u64;
    let mut seen = BTreeSet::new();
    let mut dir_modes = Vec::new();
    for entry in inputs {
        require_relative_publish_path(&entry.path)?;
        if !seen.insert(entry.path.clone()) {
            bail!("duplicate publish input {}", entry.path);
        }
        let covered = declared
            .iter()
            .any(|input| entry.path == *input || entry.path.starts_with(&format!("{input}/")));
        if !covered {
            bail!(
                "publish input {} is not a declared deploy input",
                entry.path
            );
        }
        let dest = input_root.join(&entry.path);
        match entry.kind {
            PublishInputKind::Dir => {
                if !entry.content.is_empty() {
                    bail!(
                        "directory publish input {} must not carry content",
                        entry.path
                    );
                }
                std::fs::create_dir_all(&dest)
                    .with_context(|| format!("staging deploy input {}", dest.display()))?;
                dir_modes.push((dest, entry.mode));
            }
            PublishInputKind::File => {
                let encoded = entry.content.trim();
                let decoded_upper = (encoded.len() as u64 / 4).saturating_mul(3);
                total = total.saturating_add(decoded_upper);
                if total > MAX_REMOTE_PUBLISH_INPUT_BYTES {
                    bail!("publish inputs exceed {MAX_REMOTE_PUBLISH_INPUT_BYTES} bytes");
                }
                let bytes = STANDARD
                    .decode(encoded)
                    .with_context(|| format!("decoding publish input {}", entry.path))?;
                total = total
                    .saturating_sub(decoded_upper)
                    .saturating_add(bytes.len() as u64);
                if total > MAX_REMOTE_PUBLISH_INPUT_BYTES {
                    bail!("publish inputs exceed {MAX_REMOTE_PUBLISH_INPUT_BYTES} bytes");
                }
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("staging deploy input {}", dest.display()))?;
                }
                std::fs::write(&dest, bytes)
                    .with_context(|| format!("staging deploy input {}", dest.display()))?;
                set_publish_mode(&dest, entry.mode)?;
            }
        }
    }
    dir_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in dir_modes {
        set_publish_mode(&path, mode)?;
    }
    for input in &declared {
        if !input_root.join(input).exists() {
            bail!("publish is missing declared deploy input {input}");
        }
    }
    Ok(())
}

fn set_publish_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))
        .with_context(|| format!("setting mode on staged deploy input {}", path.display()))
}

pub fn load_approve_request(
    environment: &str,
    expected_generation: u64,
    approval: &Path,
    trust_roots: &Path,
) -> Result<ApproveRequest> {
    Ok(ApproveRequest {
        version: MANAGEMENT_LIFECYCLE_API_VERSION,
        operation: ManagementLifecycleOperation::Approve.as_str().into(),
        environment: environment.to_string(),
        expected_generation,
        approval: load_approval_envelope(approval)?,
        trust_roots: TrustRoots::load(trust_roots, TrustRootKind::PlanApproval)?,
    })
}

pub fn load_apply_request(
    environment: &str,
    expected_generation: u64,
    approval: &Path,
    trust_roots: &Path,
    skip_gates: bool,
    emergency_reason: Option<String>,
) -> Result<ApplyRequest> {
    let mut envelopes = crate::plan_approval::load_envelopes(approval)?;
    let first = envelopes
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing approval evidence"))?;
    let extra = if envelopes.len() > 1 {
        envelopes.split_off(1)
    } else {
        Vec::new()
    };
    Ok(ApplyRequest {
        version: MANAGEMENT_LIFECYCLE_API_VERSION,
        operation: ManagementLifecycleOperation::Apply.as_str().into(),
        environment: environment.to_string(),
        expected_generation,
        approval: first,
        approvals: extra,
        trust_roots: TrustRoots::load(trust_roots, TrustRootKind::PlanApproval)?,
        skip_gates,
        emergency_reason,
    })
}

fn load_approval_envelope(path: &Path) -> Result<ApprovalEnvelope> {
    let raw =
        std::fs::read(path).with_context(|| format!("reading plan approval {}", path.display()))?;
    serde_json::from_slice(&raw).context("parsing plan approval envelope")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(product: &str, action: crate::plan::Action) -> crate::plan::Step {
        crate::plan::Step {
            id: format!("step-{product}"),
            order: 0,
            product: product.into(),
            instance: String::new(),
            action,
            from: Some("1.0.0".into()),
            to: "2.0.0".into(),
            release_id: format!("tenkai:release:{product}@2.0.0"),
            release_digest: "sha256:release".into(),
            artifact_digest: "sha256:artifact".into(),
            workdir: ".".into(),
            host: None,
            sealed: Vec::new(),
            restore: None,
            rewrap: None,
            issuer: None,
            identity: None,
            restore_identity: None,
            target_changes: Vec::new(),
        }
    }

    #[test]
    fn every_step_of_an_apply_is_reported_with_its_status() {
        use crate::apply::{Outcome, StepOutcomeStatus};
        use crate::plan::Action;
        let oversized = "x".repeat(STEP_DETAIL_CHARS + 10);
        let outcomes = [
            Outcome::new(
                step("api", Action::Upgrade),
                StepOutcomeStatus::Failed,
                &oversized,
            ),
            Outcome::new(
                step("web", Action::Upgrade),
                StepOutcomeStatus::Failed,
                "Deployment web cannot become Available",
            ),
            Outcome::new(
                step("db", Action::Upgrade),
                StepOutcomeStatus::RolledBack,
                "restored 1.0.0",
            ),
        ];
        let steps: Vec<ApplyStepResult> = outcomes
            .iter()
            .map(|outcome| {
                let mut outcome = outcome.clone();
                outcome.attempt_id = Some(format!("attempt-{}", outcome.step.product));
                ApplyStepResult::from_outcome(&outcome).unwrap()
            })
            .collect();
        let statuses: Vec<_> = steps
            .iter()
            .map(|step| (step.product.as_str(), step.status.as_str()))
            .collect();
        assert_eq!(
            statuses,
            [("api", "failed"), ("web", "failed"), ("db", "rolled_back")]
        );
        // An oversized detail is cut and marked as cut.
        assert_eq!(steps[0].detail.chars().count(), STEP_DETAIL_CHARS);
        assert!(steps[0].detail_truncated);
        assert!(!steps[1].detail_truncated);
        assert!(steps[1].cause.is_some());
        assert_eq!(steps[2].restored_version.as_deref(), Some("1.0.0"));
        assert_eq!(steps[2].attempt_id.as_deref(), Some("attempt-db"));

        // A rollback step reports the version it restored.
        let rollback = ApplyStepResult::from_outcome(&Outcome::new(
            step("api", Action::Rollback),
            StepOutcomeStatus::Succeeded,
            "",
        ))
        .unwrap();
        assert_eq!(rollback.restored_version.as_deref(), Some("2.0.0"));
        // A step that recorded no attempt in this execution names none.
        assert_eq!(rollback.attempt_id, None);
    }

    #[test]
    fn a_result_without_steps_keeps_the_shape_older_clients_read() {
        let result = ManagementLifecycleResult::new(
            ManagementLifecycleOperation::Apply,
            "applied 1 step(s) for plan-1",
            Some("plan-1".into()),
        );
        let wire = serde_json::to_value(&result).unwrap();
        assert!(wire.get("steps").is_none(), "{wire}");
        // What an older client, which refuses unknown fields, would read.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct OlderResult {
            version: u32,
            operation: String,
            message: String,
            resource: Option<String>,
            digest: Option<String>,
        }
        serde_json::from_value::<OlderResult>(wire).unwrap();
    }

    fn fleet_publish() -> &'static str {
        r#"{"version":1,"operation":"publish"}"#
    }

    fn env_apply() -> &'static str {
        r#"{"version":1,"operation":"apply","environment":"stage","expected_generation":7}"#
    }

    #[test]
    fn version_and_unknown_operation_fail_closed() {
        require_management_lifecycle_api_version(MANAGEMENT_LIFECYCLE_API_VERSION).unwrap();
        let err = require_management_lifecycle_api_version(99)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unsupported management lifecycle API version 99"),
            "{err}"
        );
        let err = parse_management_lifecycle_operation("deploy")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown management lifecycle operation \"deploy\""),
            "{err}"
        );
    }

    #[test]
    fn unknown_field_and_development_bypass_fail_closed() {
        let err = parse_management_lifecycle_json(
            r#"{"version":1,"operation":"publish","allow_unapproved_development":true}"#,
            PrincipalKind::Management,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn known_version_and_operation_admit() {
        let admitted =
            parse_management_lifecycle_json(fleet_publish(), PrincipalKind::Management, None)
                .unwrap();
        assert_eq!(admitted.operation, ManagementLifecycleOperation::Publish);
        assert_eq!(admitted.environment, None);

        let admitted =
            parse_management_lifecycle_json(env_apply(), PrincipalKind::Management, None).unwrap();
        assert_eq!(admitted.operation, ManagementLifecycleOperation::Apply);
        assert_eq!(admitted.environment.as_deref(), Some("stage"));
        assert_eq!(admitted.expected_generation, Some(7));
    }

    #[test]
    fn runtime_and_crossed_environment_scope_fail_closed() {
        let err =
            parse_management_lifecycle_json(env_apply(), PrincipalKind::Runtime, Some("stage"))
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("runtime credentials cannot call management lifecycle"),
            "{err}"
        );

        let err =
            parse_management_lifecycle_json(env_apply(), PrincipalKind::Management, Some("prod"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("cannot act on another environment"), "{err}");

        let err = parse_management_lifecycle_json(
            fleet_publish(),
            PrincipalKind::Management,
            Some("stage"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("cannot call catalog-wide management operation publish"),
            "{err}"
        );
    }

    #[test]
    fn environment_scoped_apply_on_granted_environment_admits() {
        let admitted =
            parse_management_lifecycle_json(env_apply(), PrincipalKind::Management, Some("stage"))
                .unwrap();
        assert_eq!(admitted.environment.as_deref(), Some("stage"));
    }

    #[test]
    fn publish_request_rejects_development_bypass_and_wrong_operation() {
        let err = serde_json::from_str::<PublishRequest>(
            r#"{"version":1,"operation":"publish","manifest":"[product]","signature":{"schema":"tenkai.release-signature.v1","key_id":"k","statement":{"manifest_digest":"sha256:aa","artifact_digest":"sha256:bb","provenance":{"source_uri":"src","revision":"1","builder":"test","built_at_unix_ms":1,"materials":{}}},"signature":"c2ln"},"trust_roots":{"version":1,"signers":[{"key_id":"k","identity":"dev","public_key":"cA=="}]},"allow_unsigned_development":true}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown field"), "{err}");

        let err = admit_promote(
            &PromoteRequest {
                version: 1,
                operation: "publish".into(),
                spec: "api@1.0.0".into(),
            },
            PrincipalKind::Management,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not valid on this route"), "{err}");
    }

    #[test]
    fn subscribe_refuses_path_mismatch_and_stale_generation() {
        let request = SubscribeRequest {
            version: 1,
            operation: "subscribe".into(),
            environment: "stage".into(),
            expected_generation: 2,
            spec: "api=stable".into(),
            instance: None,
        };
        let err = admit_subscribe(&request, "prod", PrincipalKind::Management, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match path"), "{err}");
        let err = require_expected_generation(2, 3).unwrap_err().to_string();
        assert!(err.contains("stale fencing generation 2"), "{err}");
        assert!(err.contains("cannot complete"), "{err}");
        assert_eq!(environment_fence_generation(None), 0);
        assert_eq!(environment_fence_generation(Some(4)), 4);
    }

    #[test]
    fn hold_and_retry_admit_and_refuse_empty_reason() {
        let hold = DeliveryHoldRequest {
            version: 1,
            operation: "hold".into(),
            environment: "stage".into(),
            expected_generation: 0,
            reason: Some("freeze".into()),
        };
        admit_delivery_hold(
            &hold,
            "stage",
            ManagementLifecycleOperation::Hold,
            PrincipalKind::Management,
            Some("stage"),
        )
        .unwrap();
        let mut empty = hold.clone();
        empty.reason = Some("  ".into());
        let err = admit_delivery_hold(
            &empty,
            "stage",
            ManagementLifecycleOperation::Hold,
            PrincipalKind::Management,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("reason"), "{err}");

        let freeze = DeliveryFreezeRequest {
            version: 1,
            operation: "hold_schedule".into(),
            environment: "stage".into(),
            expected_generation: 0,
            name: "holiday".into(),
            from: Some("2026-11-24T00:00:00Z".into()),
            until: Some("2026-11-28T00:00:00Z".into()),
            reason: Some("freeze".into()),
        };
        admit_delivery_freeze(
            &freeze,
            "stage",
            ManagementLifecycleOperation::HoldSchedule,
            PrincipalKind::Management,
            Some("stage"),
        )
        .unwrap();
        let mut inverted = freeze.clone();
        inverted.from = Some("2026-11-28T00:00:00Z".into());
        inverted.until = Some("2026-11-24T00:00:00Z".into());
        let err = admit_delivery_freeze(
            &inverted,
            "stage",
            ManagementLifecycleOperation::HoldSchedule,
            PrincipalKind::Management,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--until must be after --from"), "{err}");

        let retry = RetryFailedTargetRequest {
            version: 1,
            operation: "retry".into(),
            environment: "stage".into(),
            expected_generation: 0,
            product: "api".into(),
            reason: Some("retry".into()),
        };
        admit_retry_failed_target(&retry, "stage", "api", PrincipalKind::Management, None).unwrap();
        let err =
            admit_retry_failed_target(&retry, "stage", "web", PrincipalKind::Management, None)
                .unwrap_err()
                .to_string();
        assert!(err.contains("does not match path"), "{err}");
        let runtime = admit_channel_hold(
            &ChannelHoldRequest {
                version: 1,
                operation: "channel_hold".into(),
                reason: Some("pause".into()),
            },
            ManagementLifecycleOperation::ChannelHold,
            PrincipalKind::Runtime,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(runtime.contains("runtime credentials"), "{runtime}");

        let remove = ChannelRemoveRequest {
            version: 1,
            operation: "channel_remove".into(),
            expected_head: None,
        };
        admit_channel_remove(&remove, PrincipalKind::Management, None).unwrap();
        let runtime = admit_channel_remove(&remove, PrincipalKind::Runtime, None)
            .unwrap_err()
            .to_string();
        assert!(runtime.contains("runtime credentials"), "{runtime}");
        let scoped = admit_channel_remove(&remove, PrincipalKind::Management, Some("stage"))
            .unwrap_err()
            .to_string();
        assert!(scoped.contains("cannot call catalog-wide"), "{scoped}");

        let pace = ChannelConfigureRequest {
            version: 1,
            operation: "channel_configure".into(),
            upgrade_pace: "3h".into(),
        };
        admit_channel_configure(&pace, PrincipalKind::Management, None).unwrap();
        let runtime = admit_channel_configure(&pace, PrincipalKind::Runtime, None)
            .unwrap_err()
            .to_string();
        assert!(runtime.contains("runtime credentials"), "{runtime}");
        let scoped = admit_channel_configure(&pace, PrincipalKind::Management, Some("stage"))
            .unwrap_err()
            .to_string();
        assert!(scoped.contains("cannot call catalog-wide"), "{scoped}");

        let pause = ChannelPolicyPauseRequest {
            version: 1,
            operation: "channel_policy_pause".into(),
        };
        admit_channel_policy_pause(
            &pause,
            ManagementLifecycleOperation::ChannelPolicyPause,
            PrincipalKind::Management,
            None,
        )
        .unwrap();
        let runtime = admit_channel_policy_pause(
            &pause,
            ManagementLifecycleOperation::ChannelPolicyPause,
            PrincipalKind::Runtime,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(runtime.contains("runtime credentials"), "{runtime}");
        let scoped = admit_channel_policy_pause(
            &pause,
            ManagementLifecycleOperation::ChannelPolicyPause,
            PrincipalKind::Management,
            Some("stage"),
        )
        .unwrap_err()
        .to_string();
        assert!(scoped.contains("cannot call catalog-wide"), "{scoped}");
        let resume = ChannelPolicyPauseRequest {
            version: 1,
            operation: "channel_policy_resume".into(),
        };
        admit_channel_policy_pause(
            &resume,
            ManagementLifecycleOperation::ChannelPolicyResume,
            PrincipalKind::Management,
            None,
        )
        .unwrap();

        let admit = ChannelAdmitRequest {
            version: 1,
            operation: "channel_admit".into(),
            environment: "stage".into(),
            instance: "api".into(),
            reason: "canary host".into(),
        };
        admit_channel_admit(&admit, PrincipalKind::Management, None).unwrap();
        let empty = ChannelAdmitRequest {
            reason: String::new(),
            ..admit.clone()
        };
        let err = admit_channel_admit(&empty, PrincipalKind::Management, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("reason"), "{err}");

        let waiver = ExposureWaiverRequest {
            version: 1,
            operation: "waiver_set".into(),
            advisory_id: "TENKAI-2026-1".into(),
            scope: "release".into(),
            category: "false_positive".into(),
            reason: "scanner noise".into(),
            expires: "7d".into(),
            release_id: Some("tenkai:release:api@1.0.0".into()),
            product: None,
            component: None,
        };
        admit_exposure_waiver(&waiver, PrincipalKind::Management, None).unwrap();
        let runtime = admit_exposure_waiver(&waiver, PrincipalKind::Runtime, None)
            .unwrap_err()
            .to_string();
        assert!(runtime.contains("runtime credentials"), "{runtime}");
        let scoped = admit_exposure_waiver(&waiver, PrincipalKind::Management, Some("stage"))
            .unwrap_err()
            .to_string();
        assert!(scoped.contains("cannot call catalog-wide"), "{scoped}");

        let clear = ExposureWaiverClearRequest {
            version: 1,
            operation: "waiver_clear".into(),
            advisory_id: "TENKAI-2026-1".into(),
            scope: "release".into(),
            reason: "fixed".into(),
            release_id: Some("tenkai:release:api@1.0.0".into()),
            product: None,
            component: None,
        };
        admit_exposure_waiver_clear(&clear, PrincipalKind::Management, None).unwrap();

        let env_grace = ExposureGraceRequest {
            version: 1,
            operation: "exposure_grace".into(),
            environment: "stage".into(),
            expected_generation: 0,
            grace: "24h".into(),
        };
        admit_exposure_grace(
            &env_grace,
            "stage",
            PrincipalKind::Management,
            Some("stage"),
        )
        .unwrap();
        let runtime = admit_exposure_grace(&env_grace, "stage", PrincipalKind::Runtime, None)
            .unwrap_err()
            .to_string();
        assert!(runtime.contains("runtime credentials"), "{runtime}");

        let channel_grace = ChannelExposureGraceRequest {
            version: 1,
            operation: "channel_exposure_grace".into(),
            grace: "off".into(),
        };
        admit_channel_exposure_grace(&channel_grace, PrincipalKind::Management, None).unwrap();
        let scoped =
            admit_channel_exposure_grace(&channel_grace, PrincipalKind::Management, Some("stage"))
                .unwrap_err()
                .to_string();
        assert!(scoped.contains("cannot call catalog-wide"), "{scoped}");
    }

    #[test]
    fn plan_apply_and_rollback_admit_and_refuse_bypass() {
        let plan = PlanRequest {
            version: 1,
            operation: "plan".into(),
            environment: "stage".into(),
            expected_generation: 0,
        };
        admit_plan(&plan, "stage", PrincipalKind::Management, Some("stage")).unwrap();
        let err = admit_plan(&plan, "prod", PrincipalKind::Management, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match path"), "{err}");

        let err = serde_json::from_str::<ApplyRequest>(
            r#"{"version":1,"operation":"apply","environment":"stage","expected_generation":0,"approval":{"schema":"tenkai.plan-approval.v1","key_id":"k","statement":{"plan_digest":"sha256:aa","environment":"stage","purpose":"execute_plan","skip_gates":false,"issued_at":1,"expires_at":2,"policy_provider":"builtin","policy_evidence_id":"d","policy_digest":"sha256:bb"},"signature":"c2ln"},"trust_roots":{"version":1,"signers":[{"key_id":"k","identity":"dev","public_key":"cA=="}]},"allow_unapproved_development":true}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown field"), "{err}");

        let rollback = RollbackRequest {
            version: 1,
            operation: "rollback".into(),
            environment: "stage".into(),
            expected_generation: 0,
            product: "api".into(),
            recovery_reason: None,
        };
        admit_rollback(&rollback, "stage", PrincipalKind::Management, Some("stage")).unwrap();
        assert_eq!(
            plan_environment_from_id("tenkai:plan:stage:1:abc").unwrap(),
            "stage"
        );
    }

    #[test]
    fn remote_catalog_state_dir_uses_systemd_state_directory() {
        let root = unique_temp("state-dir");
        let _guard = crate::host_env::overlay::set([
            ("TENKAI_STATE_DIR", None),
            ("STATE_DIRECTORY", Some(root.as_os_str())),
        ]);
        assert_eq!(remote_catalog_state_dir().unwrap(), root);
        let _ = std::fs::remove_dir_all(root);
    }

    fn unique_temp(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tenkai-remote-publish-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn signed_release_with_inputs(root: &Path) -> (PublishRequest, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let workdir = root.join("release");
        std::fs::create_dir_all(workdir.join("manifests")).unwrap();
        std::fs::write(
            workdir.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"deploy.sh\", \"manifests\"]\n",
        )
        .unwrap();
        let script = workdir.join("deploy.sh");
        std::fs::write(&script, b"#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(workdir.join("manifests/app.yaml"), "kind: ConfigMap\n").unwrap();
        std::fs::set_permissions(
            workdir.join("manifests"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        let keys = root.join("keys");
        let signature = root.join("signature.json");
        let trust_roots = root.join("trust-roots.toml");
        crate::dev_sign::sign_release(
            &keys,
            &workdir.join("tenkai.toml"),
            &signature,
            &trust_roots,
        )
        .unwrap();
        (
            load_publish_request(&workdir.join("tenkai.toml"), &signature, &trust_roots).unwrap(),
            workdir,
        )
    }

    #[test]
    fn remote_publish_round_trips_declared_inputs_and_modes() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = unique_temp("roundtrip");
        let (request, workdir) = signed_release_with_inputs(&root);
        assert!(
            request.inputs.iter().any(|entry| entry.path == "deploy.sh"
                && entry.kind == PublishInputKind::File
                && entry.mode & 0o111 != 0
                && !entry.content.is_empty()),
            "{:?}",
            request.inputs
        );
        assert!(
            request
                .inputs
                .iter()
                .any(|entry| { entry.path == "manifests" && entry.kind == PublishInputKind::Dir }),
            "{:?}",
            request.inputs
        );
        assert!(
            request.inputs.iter().any(|entry| {
                entry.path == "manifests/app.yaml" && entry.kind == PublishInputKind::File
            }),
            "{:?}",
            request.inputs
        );

        let files = RemotePublishFiles::materialize(
            &request.manifest,
            &request.signature,
            &request.trust_roots,
            &request.inputs,
        )
        .unwrap();
        let staged = files.manifest.parent().unwrap();
        assert_eq!(
            std::fs::metadata(staged).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let declared = ["deploy.sh".into(), "manifests".into()];
        assert_eq!(
            std::fs::metadata(staged.join("manifests"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        assert!(staged.join("manifests/app.yaml").is_file());
        assert_eq!(
            crate::manifest::artifact_digest(&workdir, &declared).unwrap(),
            crate::manifest::artifact_digest(staged, &declared).unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remote_publish_restores_inputs_under_deploy_workdir() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = unique_temp("workdir");
        let workdir = root.join("release");
        std::fs::create_dir_all(workdir.join("payload")).unwrap();
        std::fs::write(
            workdir.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\nworkdir = \"payload\"\ninputs = [\"deploy.sh\"]\n",
        )
        .unwrap();
        let script = workdir.join("payload/deploy.sh");
        std::fs::write(&script, b"#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let keys = root.join("keys");
        let signature = root.join("signature.json");
        let trust_roots = root.join("trust-roots.toml");
        crate::dev_sign::sign_release(
            &keys,
            &workdir.join("tenkai.toml"),
            &signature,
            &trust_roots,
        )
        .unwrap();
        let request =
            load_publish_request(&workdir.join("tenkai.toml"), &signature, &trust_roots).unwrap();
        assert_eq!(request.inputs.len(), 1);
        assert_eq!(request.inputs[0].path, "deploy.sh");
        let files = RemotePublishFiles::materialize(
            &request.manifest,
            &request.signature,
            &request.trust_roots,
            &request.inputs,
        )
        .unwrap();
        let staged = files.manifest.parent().unwrap();
        assert!(staged.join("payload/deploy.sh").is_file());
        let declared = ["deploy.sh".into()];
        assert_eq!(
            crate::manifest::artifact_digest(&workdir.join("payload"), &declared).unwrap(),
            crate::manifest::artifact_digest(&staged.join("payload"), &declared).unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remote_publish_keeps_admitted_manifest_when_inputs_name_tenkai_toml() {
        let root = unique_temp("overwrite");
        let (mut request, _) = signed_release_with_inputs(&root);
        request.inputs.push(PublishInputEntry {
            path: "tenkai.toml".into(),
            kind: PublishInputKind::File,
            mode: 0o644,
            content: STANDARD.encode(
                b"[product]\nname = \"other\"\nversion = \"9.9.9\"\n\n[deploy]\ninstall = \"true\"\n",
            ),
        });
        let err = RemotePublishFiles::materialize(
            &request.manifest,
            &request.signature,
            &request.trust_roots,
            &request.inputs,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a declared deploy input"), "{err}");

        let workdir = root.join("collide");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::write(
            workdir.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"3.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"tenkai.toml\"]\n",
        )
        .unwrap();
        let keys = root.join("collide-keys");
        let signature = root.join("collide-signature.json");
        let trust_roots = root.join("collide-trust.toml");
        crate::dev_sign::sign_release(
            &keys,
            &workdir.join("tenkai.toml"),
            &signature,
            &trust_roots,
        )
        .unwrap();
        let request =
            load_publish_request(&workdir.join("tenkai.toml"), &signature, &trust_roots).unwrap();
        let files = RemotePublishFiles::materialize(
            &request.manifest,
            &request.signature,
            &request.trust_roots,
            &request.inputs,
        )
        .unwrap();
        let staged = std::fs::read_to_string(&files.manifest).unwrap();
        assert!(staged.contains("name = \"api\""), "{staged}");
        assert!(!staged.contains("other"), "{staged}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remote_publish_refuses_path_escape_undeclared_and_missing_inputs() {
        let root = unique_temp("refuse");
        let (request, _) = signed_release_with_inputs(&root);

        let mut escaped = request.clone();
        escaped.inputs.push(PublishInputEntry {
            path: "../escape".into(),
            kind: PublishInputKind::File,
            mode: 0o644,
            content: STANDARD.encode(b"no"),
        });
        let err = RemotePublishFiles::materialize(
            &escaped.manifest,
            &escaped.signature,
            &escaped.trust_roots,
            &escaped.inputs,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("relative path without '..'"), "{err}");

        let mut undeclared = request.clone();
        undeclared.inputs.push(PublishInputEntry {
            path: "extra.txt".into(),
            kind: PublishInputKind::File,
            mode: 0o644,
            content: STANDARD.encode(b"no"),
        });
        let err = RemotePublishFiles::materialize(
            &undeclared.manifest,
            &undeclared.signature,
            &undeclared.trust_roots,
            &undeclared.inputs,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a declared deploy input"), "{err}");

        let mut missing = request.clone();
        missing.inputs.clear();
        let err = RemotePublishFiles::materialize(
            &missing.manifest,
            &missing.signature,
            &missing.trust_roots,
            &missing.inputs,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("missing declared deploy input"), "{err}");

        let mut duplicate = request.clone();
        duplicate.inputs.push(duplicate.inputs[0].clone());
        let err = RemotePublishFiles::materialize(
            &duplicate.manifest,
            &duplicate.signature,
            &duplicate.trust_roots,
            &duplicate.inputs,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("duplicate publish input"), "{err}");

        let link_dir = root.join("symlink");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::fs::write(
            link_dir.join("tenkai.toml"),
            "[product]\nname = \"api\"\nversion = \"2.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"link\"]\n",
        )
        .unwrap();
        std::fs::write(link_dir.join("link"), b"ok\n").unwrap();
        let keys = root.join("symlink-keys");
        let signature = root.join("symlink-signature.json");
        let trust_roots = root.join("symlink-trust.toml");
        crate::dev_sign::sign_release(
            &keys,
            &link_dir.join("tenkai.toml"),
            &signature,
            &trust_roots,
        )
        .unwrap();
        std::fs::remove_file(link_dir.join("link")).unwrap();
        std::os::unix::fs::symlink("missing", link_dir.join("link")).unwrap();
        let err = load_publish_request(&link_dir.join("tenkai.toml"), &signature, &trust_roots)
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");

        let _ = std::fs::remove_dir_all(root);
    }
}
