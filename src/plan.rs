//! Plan encoding and desired-vs-deployed computation.
//!
//! Environment identity, subscriptions, inspect, and listing live in
//! [`crate::environment`] and are re-exported here for existing call sites.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::*;
use crate::pb::sekai::Object;

mod approval_brief;
mod artifact_availability;
mod convergence;
mod lifecycle;
mod release_selection;

pub(crate) use convergence::{
    classify_change, current_peers, readable_manifest, require_host_product, require_removable,
    split_release_id, step_identity, stored_release_executor, stored_release_manifest,
};

pub(crate) use release_selection::resolve_subscription_selection;
pub use release_selection::{
    FitRefusal, dotted_version, gpu_requirements_fit, model_requirements_fit,
};

pub use crate::environment::{
    ConfigPresetView, ENVIRONMENT_FACT_KEYS, EnvironmentInspectReport, EnvironmentListEntry,
    EnvironmentPlanStepSummary, EnvironmentPlanSummary, EnvironmentProductConfig,
    EnvironmentSubscriptionView, OverlayRebase, StatusDependencyHold, StatusRow, UnmetContract,
    apply_runtime_inventory_facts, clear_artifact_mirror, clear_cluster_config_path,
    clear_docker_secret_dir, clear_environment_constraint, clear_environment_fact,
    clear_environment_overlay, clear_environment_value, clear_plan_approval_policy,
    cluster_config_path, docker_secret_dir, env_add, fleet_status, inspect_environment,
    inspect_environment_with_outcomes, list_artifact_mirrors, list_environment_constraints,
    list_environment_facts, list_environment_overlays, list_environment_presets,
    list_environment_values, list_environments, overlay_digest, plan_approval_policy,
    product_overlays, rebase_environment_overlay, reconcile_deployment, render_config_presets,
    require_environment_fact, set_artifact_mirror, set_cluster_config_path, set_docker_secret_dir,
    set_environment_constraint, set_environment_fact, set_environment_overlay,
    set_environment_preset, set_environment_value, set_plan_approval_policy, status, status_state,
    subscribe, subscribe_instance, subscription_state,
};
pub(crate) use crate::environment::{
    inspect_environment_for_policy, update_runtime_deployments_object,
};
pub use crate::spec_drift::{SpecDriftObject, SpecDriftView, TargetChange, TargetFieldChange};
pub(crate) use approval_brief::compute as compute_approval_brief;
pub use approval_brief::render as approval_brief_render;
pub use approval_brief::{
    ApprovalBrief, ApprovalBriefActor, ApprovalBriefBlast, ApprovalBriefChanges,
    ApprovalBriefPolicy, PlanProposer,
};
pub use artifact_availability::{
    ArtifactAvailability, ArtifactState, render as artifact_availability_render,
};

pub use crate::deploy_webhook::{
    clear_environment_webhooks, list_environment_webhooks, set_environment_webhook,
};

pub use crate::fleet::{
    FleetDriftSummary, FleetEnvironmentRow, FleetPostureSnapshot, FleetStatusReport,
    OpenEnvironmentExposure, compare_fleet_posture, fleet_posture_snapshot,
    fleet_status_from_inspects, fleet_status_from_rows, is_hard_drift_posture,
    load_fleet_posture_baseline, overdue_exposures, write_fleet_posture_baseline,
};
pub use crate::workshop_module::set_observed_compatibility;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Install,
    Upgrade,
    Downgrade,
    Rollback,
    Restart,
    /// Remove a product the environment no longer subscribes to: a host
    /// release as a host `uninstall` step, any other software release with
    /// its own executor (ADR 0049).
    Remove,
    /// Take a deployed instance out of service without unsubscribing (#1067).
    Stop,
    /// Return a stopped instance to serving its recorded release (#1067).
    Start,
    /// Record a live workload as deployed without mutating the target (#1082).
    Adopt,
    /// Create a declared cluster namespace (#1096). Unknown to older replicas.
    #[serde(rename = "create_cluster_namespace")]
    CreateClusterNamespace,
    /// Change a declared cluster namespace (#1096). Unknown to older replicas.
    #[serde(rename = "update_cluster_namespace")]
    UpdateClusterNamespace,
    /// Delete a declared cluster namespace (#1096). Unknown to older replicas.
    #[serde(rename = "delete_cluster_namespace")]
    DeleteClusterNamespace,
    /// Run the provision tool's plan command and seal the saved plan (ADR 0052).
    #[serde(rename = "provision_prepare")]
    ProvisionPrepare,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Action::Install => "install",
            Action::Upgrade => "upgrade",
            Action::Downgrade => "downgrade",
            Action::Rollback => "rollback",
            Action::Restart => "restart",
            Action::Remove => "remove",
            Action::Stop => "stop",
            Action::Start => "start",
            Action::Adopt => "adopt",
            Action::CreateClusterNamespace => "create_cluster_namespace",
            Action::UpdateClusterNamespace => "update_cluster_namespace",
            Action::DeleteClusterNamespace => "delete_cluster_namespace",
            Action::ProvisionPrepare => "provision_prepare",
        };
        f.write_str(s)
    }
}

pub const PLAN_FORMAT_VERSION: u32 = 1;

/// Signed record that an upgrade onto an advisory-recalled release was
/// admitted because its blocking advisory set is a proper subset of the
/// current pin (#1068).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecalledUpgradeAdmission {
    pub reason: String,
    pub product: String,
    pub current_release: String,
    pub target_release: String,
    pub current_advisories: Vec<String>,
    pub target_advisories: Vec<String>,
}

/// Operator-facing detail for a zero-step Succeeded plan. Inspect uses this
/// instead of treating empty success as applied delivery.
pub const NO_OP_STATUS_DETAIL: &str = "no-op; environment already current";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub id: String,
    pub order: u32,
    pub product: String,
    /// Instance this step applies to. Empty means the product name, omitted
    /// from the encoding so default-named plan digests stay unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub instance: String,
    pub action: Action,
    pub from: Option<String>,
    pub to: String,
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub workdir: String,
    pub restore: Option<ReleasePin>,
    /// Set only on steps the root-side host applier runs (ADR 0041). Absent
    /// on every other step and omitted from the encoding, so plan digests of
    /// steps without it are unchanged. A binary that predates the field
    /// drops it, computes a different digest, and fails approval closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostStep>,
    /// Sealed values the runtime writes before this step (ADR 0045 §4): every
    /// sealed key of the instance, in key order. Empty on every other step
    /// and omitted from the encoding, so plan digests of steps without it are
    /// unchanged. A binary that predates the field drops it, computes a
    /// different digest, and fails approval closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed: Vec<SealedStep>,
    /// Set only on a re-wrap step (ADR 0045 §5): the runtime opens the
    /// instance's sealed values, as named by `sealed`, and wraps each data
    /// key for this recipient. It deploys nothing. Omitted when absent, so
    /// plan digests of every other step are unchanged; a binary that
    /// predates it fails approval closed, as for `host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrap: Option<RewrapStep>,
    /// Set only on an environment identity issuer step (ADR 0046 §2), which
    /// names no product, instance or release. Without `rewrap` it activates
    /// the candidate key it carries; with `rewrap` it wraps the recorded
    /// issuer key for that recipient. Omitted when absent, so plan digests
    /// of every other step are unchanged; a binary that predates it fails
    /// approval closed, as for `host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<IssuerStep>,
    /// The workload certificate this step issues for its instance (ADR 0046
    /// §3), from the release's `[deploy.identity]`. The runtime issues
    /// exactly this grant or refuses the step. Omitted when absent, so plan
    /// digests of every other step are unchanged; a binary that predates it
    /// fails approval closed, as for `host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<crate::workload_identity::IdentityGrant>,
    /// The workload certificate the step's restore release issues if the
    /// step fails, from that release's `[deploy.identity]`: a restore runs
    /// with its own approved grant, never the target's. Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_identity: Option<crate::workload_identity::IdentityGrant>,
    /// Desired-versus-live target changes at plan time (#1077). Empty and
    /// omitted so plan digests of steps without it stay unchanged. A binary
    /// that predates the field drops it, computes a different digest, and
    /// fails approval closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_changes: Vec<crate::spec_drift::TargetChange>,
    /// Operator reason for a stop step (#1067). Empty and omitted on every
    /// other step so their digests stay unchanged. A binary that predates
    /// the field drops it, computes a different digest, and fails approval
    /// closed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Set only on a cluster-namespace step (#1096). Omitted on every other
    /// step so their digests stay unchanged. A binary that predates the field
    /// drops it; the action variants above still fail closed on deserialize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_namespace: Option<crate::cluster_namespace::ClusterNamespaceStep>,
    /// Set on provision prepare and apply steps (ADR 0052). Omitted on every
    /// other step so their digests stay unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provision: Option<crate::provision::ProvisionStep>,
}

/// The issuer key an identity issuer step activates or re-wraps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerStep {
    pub key: crate::identity_issuer::IssuerKey,
    /// On a re-wrap: the wire form of the recipient's sealing public key,
    /// whose fingerprint the step's `rewrap` names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// The rotation step an activation is (ADR 0046 §7). Absent on the
    /// first issuer's activation and on a re-wrap, so their plan digests
    /// are unchanged; a binary that predates it fails approval closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<crate::identity_issuer::RotationPhase>,
    /// On an issue step: the issuer it replaces. The step's
    /// approval proves it to a runtime that joins after the rotation, which
    /// keeps trusting it until it is removed (ADR 0046 §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<crate::identity_issuer::IssuerKey>,
}

/// The recipient a re-wrap step adds (ADR 0045 §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewrapStep {
    /// `sha256:<hex>` fingerprint of the recipient's sealing public key.
    pub fingerprint: String,
    /// Wraps for this recipient that the offline recovery key made
    /// (ADR 0045 §7). The recipient's own runtime opens each value with
    /// its wrap, so a wrap that does not open the approved value is never
    /// stored. Omitted when empty, so other re-wrap steps keep their
    /// digest; a binary that predates the field fails approval closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovered: Vec<crate::sealed_secret::RecipientWrap>,
}

impl Step {
    /// Instance this step applies to. Empty `instance` means the product.
    pub fn instance_name(&self) -> &str {
        if self.instance.is_empty() {
            &self.product
        } else {
            &self.instance
        }
    }

    /// Every workload certificate grant the step may issue: its target's,
    /// then its restore release's.
    pub fn identity_grants(
        &self,
    ) -> impl Iterator<Item = &crate::workload_identity::IdentityGrant> {
        self.identity.iter().chain(&self.restore_identity)
    }

    /// Whether the step delivers a dependency document, so its completion
    /// stamps what it applied. A host health step only checks what its
    /// install wrote.
    pub fn delivers_dependencies(&self) -> bool {
        !matches!(
            self.host,
            Some(HostStep {
                action: HostAction::Health,
                ..
            })
        )
    }

    /// The peers the step's certificate grant allows (ADR 0046 §5), `None`
    /// without a grant.
    pub fn granted_peers(&self) -> Option<&crate::workload_identity::Peers> {
        self.identity.as_ref().map(|grant| &grant.peers)
    }

    /// Whether the environment runtime must verify this step against a local
    /// approval policy before it runs (ADR 0045 §4).
    pub fn requires_local_approval_policy(&self) -> bool {
        !self.sealed.is_empty()
            || self.issuer.is_some()
            || self.identity_grants().next().is_some()
            || (self.provision.is_some() && self.action != Action::ProvisionPrepare)
    }

    /// Whether this step deploys its release. A re-wrap step, an identity
    /// issuer step, and a cluster-namespace step deploy nothing, so release
    /// checks (compatibility, placement, deployment records) skip them.
    pub fn deploys_release(&self) -> bool {
        self.rewrap.is_none() && self.issuer.is_none() && self.cluster_namespace.is_none()
    }

    /// Whether a successful step records a deployed pin. Prepare does not.
    pub fn records_deployment(&self) -> bool {
        self.deploys_release() && self.action != Action::ProvisionPrepare
    }

    /// Whether this step creates, changes, or deletes a cluster namespace.
    pub fn is_cluster_namespace(&self) -> bool {
        self.cluster_namespace.is_some()
            || matches!(
                self.action,
                Action::CreateClusterNamespace
                    | Action::UpdateClusterNamespace
                    | Action::DeleteClusterNamespace
            )
    }
}

impl DesiredStateInput {
    /// Instance this input applies to. Empty `instance` means the product.
    pub fn instance_name(&self) -> &str {
        if self.instance.is_empty() {
            &self.product
        } else {
            &self.instance
        }
    }
}

/// What a host step authorizes the root-side applier to do (ADR 0041).
///
/// The step's `release_id`, `release_digest`, `artifact_digest`, and `to`
/// name the release whose command runs: `deploy.install` for `install`,
/// `deploy.uninstall` for `uninstall`, `deploy.health` for `health`. `from`
/// is the release the applier's record must hold at `expected_generation`
/// (`None` for a product with nothing applied). `uninstall` and `health` act
/// on the installed release, so their `from` equals `to`.
///
/// An OS image release (`[os_image]`, ADR 0051) updates through `stage`,
/// `reboot`, `verify` and `confirm` instead of `install`, all from `from`
/// toward `to`, against the applier's one host-wide OS image record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStep {
    pub action: HostAction,
    /// Generation of the applier's per-environment, per-product record this
    /// step was planned against. The applier refuses any other.
    pub expected_generation: u64,
}

/// One sealed value a runtime writes for a step (ADR 0045 §4). The
/// ciphertext is not in the plan; only its digest is, so a rotation changes
/// the digest and needs approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedStep {
    pub secret: String,
    pub key: String,
    /// `sha256:<hex>` of the sealed ciphertext this step writes.
    pub digest: String,
}

/// The one action a host step runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostAction {
    Install,
    Uninstall,
    Health,
    /// Run `deploy.install` to stage the image and arm a one-shot boot.
    Stage,
    /// Record `awaiting_boot`, then ask the updater to reboot.
    Reboot,
    /// Settle the `reboot` from the booted image the root side reads.
    Verify,
    /// Run `deploy.confirm` to make the booted image permanent.
    Confirm,
}

impl HostAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::Health => "health",
            Self::Stage => "stage",
            Self::Reboot => "reboot",
            Self::Verify => "verify",
            Self::Confirm => "confirm",
        }
    }

    /// Whether a start of this action advances the applied-state record's
    /// generation; health and verify run at the current one.
    pub fn advances_generation(self) -> bool {
        !matches!(self, Self::Health | Self::Verify)
    }

    /// Whether only an OS image release takes this action.
    pub fn updates_os_image(self) -> bool {
        matches!(
            self,
            Self::Stage | Self::Reboot | Self::Verify | Self::Confirm
        )
    }
}

impl std::fmt::Display for HostAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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
    /// Instance this input applies to. Empty means the product name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub instance: String,
    pub channel: String,
    pub channel_id: String,
    pub desired_version: String,
    pub release_id: String,
    pub release_digest: String,
    pub artifact_digest: String,
    pub deployed_version: Option<String>,
    /// Bound provider instances for this dependent (contract → provider).
    /// Empty when unbound so existing plan hashes stay.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub providers: std::collections::BTreeMap<String, String>,
    /// Digest of the approved saved plan this apply will use (ADR 0052).
    /// Empty on every other input so existing plan hashes stay.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub saved_plan_digest: String,
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
    /// Audited reason that admits rollback onto recalled Catalog content.
    #[serde(default)]
    pub recalled_recovery_reason: Option<String>,
    /// Audited admission of an upgrade onto an advisory-recalled release
    /// whose blocking advisory set is a proper subset of the current pin
    /// (#1068). Empty on plans stored before this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recalled_upgrade: Vec<RecalledUpgradeAdmission>,
    /// A certificate that lapses before the next maintenance window opens
    /// (#778). Advisory, and outside the content address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_runway: Option<crate::trust_posture::CredentialRunway>,
    /// Bounded approval brief computed at planning (#1089). Absent on plans
    /// stored before this field; omitted so their digests stay unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_brief: Option<ApprovalBrief>,
    /// Artifact digests checked against the environment's registry at
    /// planning (#1062). Advice for the approver, outside the content
    /// address; apply keeps its own check. Empty when no step names one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_availability: Vec<ArtifactAvailability>,
    /// Where each product's config comes from when it selects a preset,
    /// and overrides that hide a changed preset value (#1095). Advice for
    /// the approver, outside the content address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_presets: Vec<crate::environment::ConfigPresetView>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    recalled_recovery_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_brief: Option<&'a ApprovalBrief>,
    #[serde(skip_serializing_if = "admissions_empty")]
    recalled_upgrade: &'a [RecalledUpgradeAdmission],
}

fn admissions_empty(admissions: &&[RecalledUpgradeAdmission]) -> bool {
    admissions.is_empty()
}

fn content_address(
    environment: &str,
    created_at: i64,
    inputs: &[DesiredStateInput],
    steps: &[Step],
    recalled_recovery_reason: Option<&str>,
    approval_brief: Option<&ApprovalBrief>,
    recalled_upgrade: &[RecalledUpgradeAdmission],
) -> Result<String> {
    let mut normalized_steps = steps.to_vec();
    for step in &mut normalized_steps {
        step.id.clear();
    }
    let recovery = recalled_recovery_reason.filter(|value| !value.is_empty());
    let bytes = if recalled_upgrade.is_empty() {
        match (recovery, approval_brief) {
            (Some(reason), Some(brief)) => serde_json::to_vec(&(
                PLAN_FORMAT_VERSION,
                environment,
                created_at,
                inputs,
                normalized_steps,
                reason,
                brief,
            ))?,
            (Some(reason), None) => serde_json::to_vec(&(
                PLAN_FORMAT_VERSION,
                environment,
                created_at,
                inputs,
                normalized_steps,
                reason,
            ))?,
            (None, Some(brief)) => serde_json::to_vec(&(
                PLAN_FORMAT_VERSION,
                environment,
                created_at,
                inputs,
                normalized_steps,
                brief,
            ))?,
            (None, None) => serde_json::to_vec(&(
                PLAN_FORMAT_VERSION,
                environment,
                created_at,
                inputs,
                normalized_steps,
            ))?,
        }
    } else {
        match (recovery, approval_brief) {
            (Some(reason), Some(brief)) => serde_json::to_vec(&(
                PLAN_FORMAT_VERSION,
                environment,
                created_at,
                inputs,
                normalized_steps,
                reason,
                brief,
                recalled_upgrade,
            ))?,
            (Some(reason), None) => serde_json::to_vec(&(
                PLAN_FORMAT_VERSION,
                environment,
                created_at,
                inputs,
                normalized_steps,
                reason,
                recalled_upgrade,
            ))?,
            (None, Some(brief)) => serde_json::to_vec(&(
                PLAN_FORMAT_VERSION,
                environment,
                created_at,
                inputs,
                normalized_steps,
                brief,
                recalled_upgrade,
            ))?,
            (None, None) => serde_json::to_vec(&(
                PLAN_FORMAT_VERSION,
                environment,
                created_at,
                inputs,
                normalized_steps,
                recalled_upgrade,
            ))?,
        }
    };
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
            recalled_recovery_reason: self.recalled_recovery_reason.as_deref(),
            approval_brief: self.approval_brief.as_ref(),
            recalled_upgrade: &self.recalled_upgrade,
        };
        let bytes = serde_json::to_vec(&content)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub(crate) fn to_object(&self) -> Result<Object> {
        lifecycle::to_object(self)
    }

    /// Bind `content_id`, `id`, and step ids to the executable contents.
    pub fn bind_content_identity(&mut self) -> Result<()> {
        self.content_id = content_address(
            &self.environment,
            self.created_at,
            &self.inputs,
            &self.steps,
            self.recalled_recovery_reason.as_deref(),
            self.approval_brief.as_ref(),
            &self.recalled_upgrade,
        )?;
        self.id = plan_id(&self.environment, self.created_at, &self.content_id);
        for (order, step) in self.steps.iter_mut().enumerate() {
            step.order = order as u32;
            step.id = format!("{}:step:{order}", self.id);
        }
        Ok(())
    }
}

/// Admit a plan whose bytes were authenticated by an offline bundle.
pub fn parse_authenticated(bytes: &[u8], expected_id: &str, environment: &str) -> Result<Plan> {
    let plan: Plan =
        serde_json::from_slice(bytes).context("canonical plan entry is not an executable plan")?;
    if plan.id != expected_id {
        bail!(
            "canonical plan id {} does not match signed plan {expected_id}",
            plan.id
        );
    }
    if plan.environment != environment {
        bail!(
            "canonical plan environment {} does not match {environment}",
            plan.environment
        );
    }
    lifecycle::from_object(&lifecycle::to_object(&plan)?)?;
    Ok(plan)
}

pub async fn store(ctx: &mut Ctx, plan: &Plan) -> Result<()> {
    lifecycle::store(ctx, plan).await
}

pub async fn load(ctx: &mut Ctx, id: &str) -> Result<Plan> {
    lifecycle::load(ctx, id).await
}

/// Load plans for one environment without scanning the full plan kind set.
///
/// Uses the store property index (`environment`, optional `status`, ordered by
/// `created_at`). Empty environment ids fail closed rather than falling back to
/// an unscoped list. When `statuses` is `Some`, only matching lifecycle states
/// are returned. Results are ordered by `created_at` ascending (oldest first),
/// matching reconcile work selection.
pub async fn list_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: Option<&[PlanState]>,
) -> Result<Vec<Plan>> {
    lifecycle::list_for_environment(ctx, environment, statuses).await
}

/// Oldest plan with steps for `environment` whose status is in `statuses`.
///
/// Zero-step plans are excluded by the `has_steps` index, not by decoding
/// every matching payload.
pub async fn oldest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Option<Plan>> {
    lifecycle::oldest_for_environment(ctx, environment, statuses).await
}

pub(crate) const EXECUTABLE_ADMISSION_BATCH: u32 = 8;

/// One window of plans with steps for `environment` whose status is in
/// `statuses`, oldest `created_at` first.
///
/// Zero-step plans are excluded by the `has_steps` index, not by decoding
/// every matching payload. Callers run
/// `require_environment_indexes_match_payloads` once per tick first.
pub(crate) async fn executable_batch_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
    limit: u32,
    offset: u32,
) -> Result<Vec<Plan>> {
    lifecycle::executable_batch_for_environment(ctx, environment, statuses, limit, offset).await
}

/// Load environment-indexed plans without repeating the catalog-wide index
/// check. Reconcile ticks call `require_environment_indexes_match_payloads`
/// once, then use this for retirement, recovery, and admission windows.
pub(crate) async fn load_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: Option<&[PlanState]>,
    descending: bool,
    limit: Option<u32>,
    offset: Option<u32>,
    has_steps: Option<bool>,
) -> Result<Vec<Plan>> {
    lifecycle::load_for_environment(
        ctx,
        environment,
        statuses,
        descending,
        limit,
        offset,
        has_steps,
    )
    .await
}

pub(crate) async fn load_oldest_for_environment(
    ctx: &mut Ctx,
    environment: &str,
    statuses: &[PlanState],
) -> Result<Option<Plan>> {
    lifecycle::load_oldest_for_environment(ctx, environment, statuses).await
}

/// Newest stored plan for `environment`, if any.
///
/// Rejects catalog-wide environment-index retarget, then peeks every matching
/// identity (`created_at`, environment, status, required `has_steps`) so a
/// depressed newest index cannot hide behind `LIMIT 1`. Full Plan decode
/// runs only for the newest validated row.
pub async fn latest_for_environment(ctx: &mut Ctx, environment: &str) -> Result<Option<Plan>> {
    lifecycle::latest_for_environment(ctx, environment).await
}

pub(crate) async fn require_environment_indexes_match_payloads(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<()> {
    lifecycle::require_environment_indexes_match_payloads(ctx, environment).await
}

pub(crate) async fn retire_empty_executable_plans(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<usize> {
    lifecycle::retire_empty_executable_plans(ctx, environment).await
}

pub(crate) use lifecycle::{Persistence, Transition};

pub(crate) async fn transition(
    ctx: &mut Ctx,
    plan: &mut Plan,
    update: Transition,
    persistence: Persistence<'_>,
) -> Result<()> {
    lifecycle::transition(ctx, plan, update, persistence).await
}

pub async fn compute(ctx: &mut Ctx, env: &str) -> Result<Vec<Step>> {
    convergence::compute(ctx, env).await
}

pub async fn create(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    create_with(
        ctx,
        env,
        &crate::software_executor::SoftwareExecutors::try_from_process()?,
    )
    .await
}

/// [`create`] that may pin an advisory-recalled channel head when `reason`
/// is set and the target's blocking advisory set is a proper subset of the
/// current pin (#1068).
pub async fn create_with_recalled_upgrade(ctx: &mut Ctx, env: &str, reason: &str) -> Result<Plan> {
    create_with_reason(
        ctx,
        env,
        &crate::software_executor::SoftwareExecutors::try_from_process()?,
        Some(reason),
    )
    .await
}

/// [`create`] with `executors` in place of this process's; host steps read
/// the root-side applier's records through its host executor.
pub async fn create_with(
    ctx: &mut Ctx,
    env: &str,
    executors: &crate::software_executor::SoftwareExecutors,
) -> Result<Plan> {
    create_with_reason(ctx, env, executors, None).await
}

async fn create_with_reason(
    ctx: &mut Ctx,
    env: &str,
    executors: &crate::software_executor::SoftwareExecutors,
    recalled_upgrade_reason: Option<&str>,
) -> Result<Plan> {
    let mut span = crate::telemetry::start_span(
        "tenkai.plan",
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Plan)
            .environment(env),
    );
    match convergence::create(ctx, env, executors, recalled_upgrade_reason).await {
        Ok(plan) => {
            span.set_plan(&plan);
            span.succeed();
            Ok(plan)
        }
        Err(error) => {
            span.fail();
            Err(error)
        }
    }
}

/// Persist a plan for an explicit failed-target retry only if it includes that release.
pub async fn create_for_held_target(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    release: &str,
) -> Result<Plan> {
    let mut span = crate::telemetry::start_span(
        "tenkai.plan",
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Plan)
            .environment(env),
    );
    match convergence::create_for_held_target(ctx, env, product, release).await {
        Ok(plan) => {
            span.set_plan(&plan);
            span.succeed();
            Ok(plan)
        }
        Err(error) => {
            span.fail();
            Err(error)
        }
    }
}

pub async fn create_from_steps(ctx: &mut Ctx, env: &str, steps: Vec<Step>) -> Result<Plan> {
    let mut span = crate::telemetry::start_span(
        "tenkai.plan",
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Plan)
            .environment(env),
    );
    match convergence::create_from_steps(ctx, env, steps).await {
        Ok(plan) => {
            span.set_plan(&plan);
            span.succeed();
            Ok(plan)
        }
        Err(error) => {
            span.fail();
            Err(error)
        }
    }
}

pub async fn create_from_steps_with_recovery(
    ctx: &mut Ctx,
    env: &str,
    steps: Vec<Step>,
    reason: String,
) -> Result<Plan> {
    let mut span = crate::telemetry::start_span(
        "tenkai.plan",
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Plan)
            .environment(env),
    );
    match convergence::create_from_steps_with_recovery(ctx, env, steps, reason).await {
        Ok(plan) => {
            span.set_plan(&plan);
            span.succeed();
            Ok(plan)
        }
        Err(error) => {
            span.fail();
            Err(error)
        }
    }
}

pub async fn rollback_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    let mut span = crate::telemetry::start_span(
        "tenkai.rollback",
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Rollback)
            .environment(env),
    );
    match convergence::rollback_step(ctx, env, product).await {
        Ok(step) => {
            span.succeed();
            Ok(step)
        }
        Err(error) => {
            span.fail();
            Err(error)
        }
    }
}

pub async fn rollback_step_with_recovery(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    recovery: Option<&str>,
) -> Result<Step> {
    let mut span = crate::telemetry::start_span(
        "tenkai.rollback",
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Rollback)
            .environment(env),
    );
    match convergence::rollback_step_with_recovery(ctx, env, product, recovery).await {
        Ok(step) => {
            span.succeed();
            Ok(step)
        }
        Err(error) => {
            span.fail();
            Err(error)
        }
    }
}

/// Re-wrap steps for `fingerprint` (ADR 0045 §5), and the instances with
/// sealed values that have nothing deployed yet.
/// Re-wrap steps for `fingerprint`, one per deployed instance with sealed
/// values, and the instances skipped because nothing is deployed.
/// `recovered` wraps (ADR 0045 §7) ride on the step of their instance,
/// only for a value still at the wrap's digest.
pub async fn rewrap_steps(
    ctx: &mut Ctx,
    env: &str,
    fingerprint: &str,
    recovered: &std::collections::BTreeMap<String, Vec<crate::sealed_secret::RecipientWrap>>,
) -> Result<(Vec<Step>, Vec<String>)> {
    convergence::rewrap_steps(ctx, env, fingerprint, recovered).await
}

pub async fn restart_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    convergence::restart_step(ctx, env, product).await
}

/// Plan a stop of the currently deployed instance, keeping its subscription.
pub async fn stop_step(ctx: &mut Ctx, env: &str, product: &str, reason: &str) -> Result<Step> {
    convergence::stop_step(ctx, env, product, reason).await
}

/// Plan a start of a stopped instance onto its recorded release.
pub async fn start_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    convergence::start_step(ctx, env, product).await
}

/// Plan recording a matching live workload as deployed without mutating it.
pub async fn adopt_step(ctx: &mut Ctx, env: &str, release: &str) -> Result<Step> {
    let executors = crate::software_executor::SoftwareExecutors::try_from_process()?;
    convergence::adopt_step(ctx, env, release, &executors).await
}

/// [`adopt_step`] with `executors` in place of this process's.
pub async fn adopt_step_with(
    ctx: &mut Ctx,
    env: &str,
    release: &str,
    executors: &crate::software_executor::SoftwareExecutors,
) -> Result<Step> {
    convergence::adopt_step(ctx, env, release, executors).await
}

pub async fn create_for_reconcile(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    let mut span = crate::telemetry::start_span(
        "tenkai.plan",
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Plan)
            .environment(env),
    );
    match convergence::create_for_reconcile(ctx, env).await {
        Ok(plan) => {
            span.set_plan(&plan);
            span.succeed();
            Ok(plan)
        }
        Err(error) => {
            span.fail();
            Err(error)
        }
    }
}

/// Persist the plan the reconciler would compute, with held failed targets
/// left held. Agent-initiated planning uses this so it cannot retry them.
pub async fn create_holding_failed_targets(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    let mut span = crate::telemetry::start_span(
        "tenkai.plan",
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Plan)
            .environment(env),
    );
    match convergence::create_holding_failed_targets(ctx, env).await {
        Ok(plan) => {
            span.set_plan(&plan);
            span.succeed();
            Ok(plan)
        }
        Err(error) => {
            span.fail();
            Err(error)
        }
    }
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

                instance: String::new(),
                channel: "stable".into(),
                channel_id: "tenkai:channel:api/stable".into(),
                desired_version: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "target-digest".into(),
                artifact_digest: "target-artifact-digest".into(),
                deployed_version: Some("1.0.0".into()),
                providers: Default::default(),
                saved_plan_digest: String::new(),
            }],
            steps: vec![Step {
                id: String::new(),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action: Action::Upgrade,
                from: Some("1.0.0".into()),
                to: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "target-digest".into(),
                artifact_digest: "target-artifact-digest".into(),
                workdir: "/srv/api".into(),
                host: None,
                sealed: Vec::new(),
                restore: Some(ReleasePin {
                    release_id: "tenkai:release:api@1.0.0".into(),
                    digest: "restore-digest".into(),
                    artifact_digest: "restore-artifact-digest".into(),
                    workdir: "/srv/api".into(),
                }),
                rewrap: None,
                issuer: None,
                identity: None,
                restore_identity: None,
                target_changes: Vec::new(),
                reason: String::new(),
                cluster_namespace: None,
                provision: None,
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            recalled_upgrade: Vec::new(),
            credential_runway: None,
            artifact_availability: Vec::new(),
            config_presets: Vec::new(),
            approval_brief: None,
        };
        plan.content_id = content_address(
            &plan.environment,
            plan.created_at,
            &plan.inputs,
            &plan.steps,
            plan.recalled_recovery_reason.as_deref(),
            plan.approval_brief.as_ref(),
            &[],
        )
        .unwrap();
        plan.id = plan_id(&plan.environment, plan.created_at, &plan.content_id);
        plan.steps[0].id = format!("{}:step:0", plan.id);
        plan
    }

    #[test]
    fn empty_providers_are_omitted_and_a_binding_changes_content_identity() {
        let unbound = example_plan();
        let mut bound = example_plan();
        bound.inputs[0]
            .providers
            .insert("database".into(), "db-a".into());
        let unbound_json = serde_json::to_value(&unbound.inputs[0]).unwrap();
        assert!(unbound_json.get("providers").is_none(), "{unbound_json}");
        let bound_json = serde_json::to_value(&bound.inputs[0]).unwrap();
        assert_eq!(
            bound_json
                .get("providers")
                .and_then(|value| value.get("database"))
                .and_then(|value| value.as_str()),
            Some("db-a")
        );
        assert_ne!(
            content_address(
                &unbound.environment,
                unbound.created_at,
                &unbound.inputs,
                &unbound.steps,
                None,
                None,
                &[],
            )
            .unwrap(),
            content_address(
                &bound.environment,
                bound.created_at,
                &bound.inputs,
                &bound.steps,
                None,
                None,
                &[],
            )
            .unwrap()
        );
    }

    #[test]
    fn empty_instance_is_omitted_from_plan_encoding() {
        let default = example_plan();
        let mut named = example_plan();
        named.steps[0].instance = "api-a".into();
        named.inputs[0].instance = "api-a".into();
        let default_json = serde_json::to_value(&default.steps[0]).unwrap();
        let named_json = serde_json::to_value(&named.steps[0]).unwrap();
        assert!(default_json.get("instance").is_none(), "{default_json}");
        assert_eq!(
            named_json.get("instance").and_then(|v| v.as_str()),
            Some("api-a")
        );
        assert_ne!(
            content_address(
                &default.environment,
                default.created_at,
                &default.inputs,
                &default.steps,
                None,
                None,
                &[],
            )
            .unwrap(),
            content_address(
                &named.environment,
                named.created_at,
                &named.inputs,
                &named.steps,
                None,
                None,
                &[],
            )
            .unwrap()
        );
    }

    #[test]
    fn recalled_recovery_reason_is_part_of_signed_plan_identity() {
        let mut left = example_plan();
        let mut right = example_plan();
        right.recalled_recovery_reason = Some("restore last known-good".into());
        left.content_id = content_address(
            &left.environment,
            left.created_at,
            &left.inputs,
            &left.steps,
            left.recalled_recovery_reason.as_deref(),
            left.approval_brief.as_ref(),
            &[],
        )
        .unwrap();
        right.content_id = content_address(
            &right.environment,
            right.created_at,
            &right.inputs,
            &right.steps,
            right.recalled_recovery_reason.as_deref(),
            right.approval_brief.as_ref(),
            &[],
        )
        .unwrap();
        assert_ne!(left.content_id, right.content_id);
        assert_ne!(
            left.executable_digest().unwrap(),
            right.executable_digest().unwrap()
        );
    }

    #[test]
    fn empty_recalled_upgrade_keeps_the_legacy_content_address() {
        let plan = example_plan();
        let mut normalized = plan.steps.clone();
        for step in &mut normalized {
            step.id.clear();
        }
        let legacy = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    PLAN_FORMAT_VERSION,
                    plan.environment.as_str(),
                    plan.created_at,
                    &plan.inputs,
                    &normalized,
                ))
                .unwrap()
            )
        );
        assert_eq!(
            content_address(
                &plan.environment,
                plan.created_at,
                &plan.inputs,
                &plan.steps,
                None,
                None,
                &[],
            )
            .unwrap(),
            legacy
        );
        let admitted = RecalledUpgradeAdmission {
            reason: "lower openssl exposure".into(),
            product: "api".into(),
            current_release: "tenkai:release:api@1.0.0".into(),
            target_release: "tenkai:release:api@1.1.0".into(),
            current_advisories: vec!["TENKAI-2026-1".into(), "TENKAI-2026-2".into()],
            target_advisories: vec!["TENKAI-2026-1".into()],
        };
        assert_ne!(
            content_address(
                &plan.environment,
                plan.created_at,
                &plan.inputs,
                &plan.steps,
                None,
                None,
                std::slice::from_ref(&admitted),
            )
            .unwrap(),
            legacy
        );
        let mut right = plan.clone();
        right.recalled_upgrade = vec![admitted];
        right.bind_content_identity().unwrap();
        let mut left = plan;
        left.bind_content_identity().unwrap();
        assert_ne!(left.content_id, right.content_id);
        assert_ne!(
            left.executable_digest().unwrap(),
            right.executable_digest().unwrap()
        );
    }

    #[test]
    fn the_approval_brief_changes_the_plan_digest() {
        let mut left = example_plan();
        let mut right = example_plan();
        right.approval_brief = Some(ApprovalBrief {
            proposer: "user-1".into(),
            actor_chain: vec![ApprovalBriefActor {
                id: "assistant-7".into(),
                kind: "agent".into(),
            }],
            blast_radius: ApprovalBriefBlast {
                environment: "prod".into(),
                instances: vec!["api".into()],
                criticality: None,
                rollback_available: true,
            },
            changes: ApprovalBriefChanges {
                counts: Default::default(),
                risky: vec!["deleted_volume:Deployment web".into()],
            },
            evidence: Vec::new(),
            policy: ApprovalBriefPolicy {
                without_human: "require_human".into(),
                reason: Some("policy mode is manual".into()),
                budget: "over".into(),
            },
        });
        left.bind_content_identity().unwrap();
        right.bind_content_identity().unwrap();
        assert_ne!(
            left.executable_digest().unwrap(),
            right.executable_digest().unwrap()
        );
        let covered = right.executable_digest().unwrap();
        right.approval_brief.as_mut().unwrap().proposer = "other".into();
        right.bind_content_identity().unwrap();
        assert_ne!(covered, right.executable_digest().unwrap());
    }

    #[test]
    fn serialized_plan_round_trips() {
        let plan = example_plan();
        let object = plan.to_object().unwrap();
        assert_eq!(lifecycle::from_object(&object).unwrap(), plan);
    }

    fn plan_for(env: &str, created_at: i64, state: PlanState) -> Plan {
        let mut plan = example_plan();
        plan.environment = env.into();
        plan.created_at = created_at;
        plan.state = state;
        plan.content_id = content_address(
            &plan.environment,
            plan.created_at,
            &plan.inputs,
            &plan.steps,
            plan.recalled_recovery_reason.as_deref(),
            plan.approval_brief.as_ref(),
            &[],
        )
        .unwrap();
        plan.id = plan_id(&plan.environment, plan.created_at, &plan.content_id);
        plan.steps[0].id = format!("{}:step:0", plan.id);
        plan
    }

    #[tokio::test]
    async fn list_for_environment_scopes_status_and_order() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-scope-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let env_a_old = plan_for("env_a", 100, PlanState::Computed);
        let env_a_new = plan_for("env_a", 200, PlanState::Running);
        let env_a_done = plan_for("env_a", 50, PlanState::Succeeded);
        let env_b = plan_for("env_b", 10, PlanState::Computed);
        for plan in [&env_a_old, &env_a_new, &env_a_done, &env_b] {
            store(&mut ctx, plan).await.unwrap();
        }

        // Noise: many other environments must not affect env_a selection.
        for i in 0..40 {
            let noise = plan_for(&format!("noise-{i}"), 1_000 + i, PlanState::Computed);
            store(&mut ctx, &noise).await.unwrap();
        }

        let executable = list_for_environment(
            &mut ctx,
            "env_a",
            Some(&[PlanState::Computed, PlanState::Running]),
        )
        .await
        .unwrap();
        assert_eq!(
            executable
                .iter()
                .map(|plan| plan.id.as_str())
                .collect::<Vec<_>>(),
            vec![env_a_old.id.as_str(), env_a_new.id.as_str()]
        );
        assert!(executable.iter().all(|plan| plan.environment == "env_a"
            && matches!(plan.state, PlanState::Computed | PlanState::Running)));

        let oldest = oldest_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed, PlanState::Running],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(oldest.id, env_a_old.id);

        let mut empty = env_a_old.clone();
        empty.created_at = 1;
        empty.steps.clear();
        empty.content_id = content_address(
            &empty.environment,
            empty.created_at,
            &empty.inputs,
            &empty.steps,
            empty.recalled_recovery_reason.as_deref(),
            empty.approval_brief.as_ref(),
            &[],
        )
        .unwrap();
        empty.id = plan_id(&empty.environment, empty.created_at, &empty.content_id);
        store(&mut ctx, &empty).await.unwrap();
        let oldest_with_work = oldest_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed, PlanState::Running],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(oldest_with_work.id, env_a_old.id);
        let latest = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.id, env_a_new.id);

        let env_b_only = list_for_environment(
            &mut ctx,
            "env_b",
            Some(&[PlanState::Computed, PlanState::Running]),
        )
        .await
        .unwrap();
        assert_eq!(env_b_only.len(), 1);
        assert_eq!(env_b_only[0].id, env_b.id);
        assert!(!env_b_only.iter().any(|plan| plan.environment == "env_a"));

        let empty = list_for_environment(&mut ctx, "env_missing", Some(&[PlanState::Computed]))
            .await
            .unwrap();
        assert!(empty.is_empty());
        assert!(
            list_for_environment(&mut ctx, "", None)
                .await
                .unwrap_err()
                .to_string()
                .contains("required")
        );

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_and_oldest_fail_closed_on_created_at_index_mismatch() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-created-at-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let older = plan_for("env_a", 100, PlanState::Computed);
        let newer = plan_for("env_a", 200, PlanState::Running);
        store(&mut ctx, &older).await.unwrap();
        store(&mut ctx, &newer).await.unwrap();

        let latest = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.id, newer.id);
        let oldest = oldest_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed, PlanState::Running],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(oldest.id, older.id);

        let mut poisoned = ctx.get(&older.id).await.unwrap().unwrap();
        poisoned
            .properties
            .insert("created_at".into(), "9999".into());
        ctx.put(poisoned).await.unwrap();

        let latest_error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            latest_error.contains("does not match payload"),
            "{latest_error}"
        );
        let oldest_error = oldest_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed, PlanState::Running],
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            oldest_error.contains("does not match payload"),
            "{oldest_error}"
        );
        let listed_error = list_for_environment(&mut ctx, "env_a", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            listed_error.contains("does not match payload"),
            "{listed_error}"
        );

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_fail_closed_on_environment_index_retarget() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-env-retarget-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let older = plan_for("env_a", 100, PlanState::Computed);
        let newer = plan_for("env_a", 200, PlanState::Running);
        store(&mut ctx, &older).await.unwrap();
        store(&mut ctx, &newer).await.unwrap();

        let mut retargeted = ctx.get(&newer.id).await.unwrap().unwrap();
        retargeted
            .properties
            .insert("environment".into(), "other".into());
        ctx.put(retargeted).await.unwrap();

        let error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("environment index other does not match payload env_a"),
            "{error}"
        );

        ctx.put(newer.to_object().unwrap()).await.unwrap();
        let foreign = plan_for("env_b", 300, PlanState::Computed);
        store(&mut ctx, &foreign).await.unwrap();
        let mut foreign_poisoned = ctx.get(&foreign.id).await.unwrap().unwrap();
        foreign_poisoned
            .properties
            .insert("status".into(), "nope".into());
        ctx.put(foreign_poisoned).await.unwrap();
        let mut foreign_malformed = ctx.get(&foreign.id).await.unwrap().unwrap();
        foreign_malformed
            .properties
            .insert("plan".into(), "not-json".into());
        ctx.put(foreign_malformed).await.unwrap();
        let latest = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.id, newer.id);

        let _ = std::fs::remove_file(&database);
    }

    // #1477: an embedded reconcile tick lists plans once. A row retargeted
    // after that snapshot still fails closed; a fresh list per call would
    // report the payload mismatch instead of the omission.
    #[tokio::test]
    async fn embedded_tick_shares_one_plan_list_and_fails_closed_on_a_later_retarget() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-tick-retarget-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let ctx = Ctx::embedded(&database).unwrap();
        let (mut tick, _guard) = ctx.with_shared_plan_retarget_tick();
        let env_a = plan_for("env_a", 100, PlanState::Computed);
        let env_b = plan_for("env_b", 200, PlanState::Computed);
        store(&mut tick, &env_a).await.unwrap();
        store(&mut tick, &env_b).await.unwrap();

        require_environment_indexes_match_payloads(&mut tick, "env_a")
            .await
            .unwrap();
        let mut retargeted = tick.get(&env_b.id).await.unwrap().unwrap();
        retargeted
            .properties
            .insert("environment".into(), "other".into());
        tick.put(retargeted).await.unwrap();

        let error = require_environment_indexes_match_payloads(&mut tick, "env_b")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("omitted from environment env_b after shared retarget snapshot"),
            "{error}"
        );

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_and_oldest_fail_closed_on_missing_has_steps_for_stepped_plan() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-missing-has-steps-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let work = plan_for("env_a", 100, PlanState::Computed);
        store(&mut ctx, &work).await.unwrap();
        let mut missing = ctx.get(&work.id).await.unwrap().unwrap();
        missing.properties.remove("has_steps");
        ctx.put(missing).await.unwrap();

        let latest_error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            latest_error.contains("no has_steps index"),
            "{latest_error}"
        );
        let oldest_error = oldest_for_environment(&mut ctx, "env_a", &[PlanState::Computed])
            .await
            .unwrap_err()
            .to_string();
        assert!(
            oldest_error.contains("no has_steps index"),
            "{oldest_error}"
        );
        let listed_error = list_for_environment(&mut ctx, "env_a", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            listed_error.contains("no has_steps index"),
            "{listed_error}"
        );

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_fail_closed_on_status_index_poison() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-status-poison-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let older = plan_for("env_a", 100, PlanState::Computed);
        let newer = plan_for("env_a", 200, PlanState::Computed);
        store(&mut ctx, &older).await.unwrap();
        store(&mut ctx, &newer).await.unwrap();

        let mut poisoned = ctx.get(&newer.id).await.unwrap().unwrap();
        poisoned
            .properties
            .insert("status".into(), "succeeded".into());
        ctx.put(poisoned).await.unwrap();

        let error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("status index succeeded does not match payload computed"),
            "{error}"
        );

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_fail_closed_when_true_newest_created_at_index_is_depressed() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-newest-depressed-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let older = plan_for("env_a", 100, PlanState::Computed);
        let newer = plan_for("env_a", 200, PlanState::Running);
        store(&mut ctx, &older).await.unwrap();
        store(&mut ctx, &newer).await.unwrap();

        let mut deflated = ctx.get(&newer.id).await.unwrap().unwrap();
        deflated.properties.insert("created_at".into(), "1".into());
        ctx.put(deflated).await.unwrap();
        let deflated_error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            deflated_error.contains("does not match payload"),
            "{deflated_error}"
        );

        ctx.put(newer.to_object().unwrap()).await.unwrap();
        let mut missing = ctx.get(&newer.id).await.unwrap().unwrap();
        missing.properties.remove("created_at");
        ctx.put(missing).await.unwrap();
        let missing_error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            missing_error.contains("no created_at index"),
            "{missing_error}"
        );

        ctx.put(newer.to_object().unwrap()).await.unwrap();
        let mut non_int = ctx.get(&newer.id).await.unwrap().unwrap();
        non_int
            .properties
            .insert("created_at".into(), "later".into());
        ctx.put(non_int).await.unwrap();
        let non_int_error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(non_int_error.contains("not an integer"), "{non_int_error}");

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn latest_selects_newest_without_requiring_full_history_plan_decode() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-latest-history-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let mut newest_id = String::new();
        for (index, created_at) in (1..=16).enumerate() {
            let state = if index + 1 == 16 {
                PlanState::Running
            } else {
                PlanState::Succeeded
            };
            let stored = plan_for("env_a", created_at * 10, state);
            if index + 1 == 16 {
                newest_id = stored.id.clone();
            }
            store(&mut ctx, &stored).await.unwrap();
        }

        let latest = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.id, newest_id);
        assert_eq!(latest.created_at, 160);
        assert_eq!(latest.state, PlanState::Running);

        let mut poisoned = ctx.get(&newest_id).await.unwrap().unwrap();
        poisoned.properties.insert("created_at".into(), "1".into());
        ctx.put(poisoned).await.unwrap();
        let error = latest_for_environment(&mut ctx, "env_a")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match payload"), "{error}");

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn executable_batch_windows_oldest_first_without_a_full_set_decode() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-exec-batch-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let mut ids = Vec::new();
        for created_at in 1..=12 {
            let stored = plan_for("env_a", created_at * 10, PlanState::Computed);
            ids.push(stored.id.clone());
            store(&mut ctx, &stored).await.unwrap();
        }

        let first = executable_batch_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed],
            EXECUTABLE_ADMISSION_BATCH,
            0,
        )
        .await
        .unwrap();
        let second = executable_batch_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed],
            EXECUTABLE_ADMISSION_BATCH,
            EXECUTABLE_ADMISSION_BATCH,
        )
        .await
        .unwrap();
        assert_eq!(first.len(), EXECUTABLE_ADMISSION_BATCH as usize);
        assert_eq!(second.len(), 4);
        assert_eq!(
            first
                .iter()
                .map(|plan| plan.id.as_str())
                .collect::<Vec<_>>(),
            ids[..8].iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(
            second
                .iter()
                .map(|plan| plan.id.as_str())
                .collect::<Vec<_>>(),
            ids[8..].iter().map(String::as_str).collect::<Vec<_>>()
        );
        let all = load_for_environment(
            &mut ctx,
            "env_a",
            Some(&[PlanState::Computed]),
            false,
            None,
            None,
            Some(true),
        )
        .await
        .unwrap();
        assert_eq!(all.len(), 12);
        assert_eq!(all[8].id, second[0].id);

        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn pending_work_and_retirement_filter_has_steps() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-plan-has-steps-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();

        let mut empty = plan_for("env_a", 10, PlanState::Computed);
        empty.steps.clear();
        empty.content_id = content_address(
            &empty.environment,
            empty.created_at,
            &empty.inputs,
            &empty.steps,
            empty.recalled_recovery_reason.as_deref(),
            empty.approval_brief.as_ref(),
            &[],
        )
        .unwrap();
        empty.id = plan_id(&empty.environment, empty.created_at, &empty.content_id);
        let work = plan_for("env_a", 20, PlanState::Computed);
        store(&mut ctx, &empty).await.unwrap();
        store(&mut ctx, &work).await.unwrap();

        let oldest = oldest_for_environment(&mut ctx, "env_a", &[PlanState::Computed])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(oldest.id, work.id);
        let executable = executable_batch_for_environment(
            &mut ctx,
            "env_a",
            &[PlanState::Computed],
            EXECUTABLE_ADMISSION_BATCH,
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            executable
                .iter()
                .map(|plan| plan.id.as_str())
                .collect::<Vec<_>>(),
            vec![work.id.as_str()]
        );

        let retired = retire_empty_executable_plans(&mut ctx, "env_a")
            .await
            .unwrap();
        assert_eq!(retired, 1);
        assert_eq!(
            load(&mut ctx, &empty.id).await.unwrap().state,
            PlanState::Succeeded
        );
        assert_eq!(
            load(&mut ctx, &work.id).await.unwrap().state,
            PlanState::Computed
        );
        let oldest = oldest_for_environment(&mut ctx, "env_a", &[PlanState::Computed])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(oldest.id, work.id);

        let _ = std::fs::remove_file(&database);
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
            lifecycle::from_object(&blocked.to_object().unwrap())
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
        let error = lifecycle::from_object(&object).unwrap_err().to_string();
        assert!(error.contains("content-addressed id"));
    }

    #[test]
    fn environment_plan_summary_is_bounded_and_omits_executable_payloads() {
        let mut plan = example_plan();
        plan.state = PlanState::Blocked;
        plan.status_detail = format!("token=do-not-return {}", "x".repeat(600));
        let release_digest = plan.steps[0].release_digest.clone();
        let artifact_digest = plan.steps[0].artifact_digest.clone();
        let workdir = plan.steps[0].workdir.clone();
        let digest = format!("sha256:{}", plan.executable_digest().unwrap());

        let summary = crate::environment::environment_plan_summary(plan).unwrap();

        assert_eq!(summary.digest.as_deref(), Some(digest.as_str()));

        assert_eq!(summary.state, "blocked");
        assert_eq!(
            summary.status_detail,
            "blocked by Tenkai approval or policy requirements"
        );
        assert!(!summary.status_detail.contains("do-not-return"));
        assert_eq!(summary.steps.len(), 1);
        assert_eq!(summary.steps[0].action, "upgrade");
        assert!(!summary.steps_truncated);
        let encoded = serde_json::to_string(&summary).unwrap();
        assert!(!encoded.contains(&release_digest));
        assert!(!encoded.contains(&artifact_digest));
        assert!(!encoded.contains(&workdir));
    }

    #[test]
    fn inspect_distinguishes_noop_succeeded_from_applied_delivery() {
        let mut noop = example_plan();
        noop.steps.clear();
        noop.state = PlanState::Succeeded;
        noop.status_detail = format!("token=do-not-return {}", "x".repeat(32));
        let summary = crate::environment::environment_plan_summary(noop).unwrap();
        assert_eq!(summary.state, "succeeded");
        assert_eq!(summary.step_count, 0);
        assert_eq!(summary.status_detail, NO_OP_STATUS_DETAIL);
        assert!(!summary.status_detail.contains("do-not-return"));
        assert!(summary.steps.is_empty());

        let mut applied = example_plan();
        applied.state = PlanState::Succeeded;
        applied.status_detail = format!("complete; token=do-not-return {}", "x".repeat(32));
        let summary = crate::environment::environment_plan_summary(applied).unwrap();
        assert_eq!(summary.state, "succeeded");
        assert_eq!(summary.step_count, 1);
        assert!(summary.status_detail.is_empty());
        assert!(!summary.status_detail.contains("do-not-return"));
    }

    /// A plan for an environment whose window is closed names the certificate
    /// that lapses before the window opens (#778); without trust sources
    /// nothing is flagged.
    #[tokio::test]
    async fn plan_flags_a_certificate_that_lapses_before_the_window_opens() {
        use chrono::Datelike as _;
        let dir = std::env::temp_dir().join(format!("tenkai-runway-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["hub.example.test".into()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::hours(1);
        let key = rcgen::KeyPair::generate().unwrap();
        let listener = dir.join("listener.pem");
        std::fs::write(&listener, params.self_signed(&key).unwrap().pem()).unwrap();
        let sources = crate::trust_posture::TrustSources {
            certificates: vec![(
                "listener".into(),
                crate::trust_posture::CertificateSource::File(listener.clone()),
            )],
            warning_days: 30,
            critical_days: 7,
            ..Default::default()
        };

        let mut ctx = Ctx::embedded(dir.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "prod", "production").await.unwrap();
        // A weekday other than today in the window's zone keeps it closed.
        let today = chrono::Utc::now()
            .with_timezone(&chrono_tz::Asia::Tokyo)
            .weekday()
            .number_from_monday();
        let window = crate::maintenance::Window::new(
            "weekly",
            "Asia/Tokyo",
            vec![today % 7 + 1],
            "02:00",
            60,
        )
        .unwrap();
        crate::maintenance::set(&mut ctx, "prod", window)
            .await
            .unwrap();

        let unflagged = create(&mut ctx, "prod").await.unwrap();
        assert_eq!(unflagged.credential_runway, None);

        let mut ctx = ctx.with_trust_sources(std::sync::Arc::new(sources));
        let flagged = create(&mut ctx, "prod")
            .await
            .unwrap()
            .credential_runway
            .expect("runway flagged");
        assert_eq!(flagged.credential, "listener (CN=rcgen self signed cert)");
        assert!(flagged.expires_at_ms < flagged.window_opens_at_ms);

        // #811: the read route lists the waiting plan as blocked by the
        // certificate, and once it outlasts the window, as not blocked.
        let runways = crate::trust_posture::plan_runways(&mut ctx).await.unwrap();
        let [listed] = runways.plans.as_slice() else {
            panic!("one waiting plan: {runways:?}");
        };
        assert_eq!(listed.environment, "prod");
        assert_eq!(listed.window_opens_at_ms, Some(flagged.window_opens_at_ms));
        assert_eq!(listed.blocked_by.as_ref(), Some(&flagged));
        params.not_after = now + time::Duration::days(30);
        std::fs::write(&listener, params.self_signed(&key).unwrap().pem()).unwrap();
        let runways = crate::trust_posture::plan_runways(&mut ctx).await.unwrap();
        assert_eq!(runways.plans.len(), 1);
        assert_eq!(runways.plans[0].blocked_by, None);
        assert_eq!(
            runways.plans[0].window_opens_at_ms,
            Some(flagged.window_opens_at_ms)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn environment_record_initializes_without_deployment_state() {
        let record =
            crate::environment::environment_record(None, "prod", "production", 20).unwrap();
        assert_eq!(record.properties.get("description").unwrap(), "production");
        assert_eq!(record.created, 20);
        assert_eq!(record.updated, 20);
    }

    #[tokio::test]
    async fn inspect_reports_maintenance_windows_and_constraints() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-env-rules-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "prod", "production").await.unwrap();

        let empty = inspect_environment(&mut ctx, "prod").await.unwrap();
        let maintenance = empty.maintenance.expect("maintenance projection");
        assert_eq!(maintenance.eligibility, "unrestricted");
        assert!(maintenance.windows.is_empty());
        assert!(empty.constraints.is_empty());

        let window = crate::maintenance::Window::new(
            "nightly",
            // No DST: a next opening that lands in a repeated or skipped
            // hour is unresolved by design, which would make this flaky.
            "Asia/Tokyo",
            vec![1, 2, 3, 4, 5, 6, 7],
            "02:00",
            60,
        )
        .unwrap();
        crate::maintenance::set(&mut ctx, "prod", window)
            .await
            .unwrap();
        crate::environment::set_environment_constraint(
            &mut ctx,
            "prod",
            "version_range",
            "api",
            "1.0.0..2.0.0",
        )
        .await
        .unwrap();
        crate::environment::set_environment_constraint(
            &mut ctx,
            "prod",
            "require_fact",
            "architecture",
            "arm64",
        )
        .await
        .unwrap();

        let report = inspect_environment(&mut ctx, "prod").await.unwrap();
        let maintenance = report.maintenance.expect("maintenance projection");
        assert!(
            maintenance.eligibility == "open" || maintenance.eligibility == "closed",
            "{maintenance:?}"
        );
        assert_eq!(maintenance.windows.len(), 1);
        let nightly = &maintenance.windows[0];
        assert_eq!(nightly.identity, "nightly");
        assert_eq!(nightly.timezone, "Asia/Tokyo");
        assert_eq!(nightly.weekdays, vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(nightly.start, "02:00");
        assert_eq!(nightly.duration_minutes, 60);
        assert!(nightly.next_opens_at_ms.unwrap() > crate::now_millis());
        assert_eq!(
            report.constraints,
            vec![
                crate::environment::EnvironmentConstraint {
                    kind: "require_fact".into(),
                    name: "architecture".into(),
                    value: "arm64".into(),
                },
                crate::environment::EnvironmentConstraint {
                    kind: "version_range".into(),
                    name: "api".into(),
                    value: "1.0.0..2.0.0".into(),
                },
            ]
        );
        let _ = std::fs::remove_file(&database);
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
    fn model_requirements_match_architecture_memory_and_accelerator() {
        let mut facts = std::collections::BTreeMap::new();
        facts.insert("architecture".into(), "arm64".into());
        facts.insert("memory_gib".into(), "32".into());
        facts.insert("accelerator".into(), "apple-metal".into());
        let requirements = crate::manifest::ModelRequirementsSection {
            architecture: vec!["arm64".into(), "x86_64".into()],
            memory_gib: 24,
            accelerator: vec!["apple-metal".into()],
            gpu: None,
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

    fn h100_facts() -> std::collections::BTreeMap<String, String> {
        [
            ("gpu_vendor", "nvidia"),
            ("gpu_family", "hopper"),
            ("gpu_model", "H100 80GB"),
            ("gpu_vram_gib", "80"),
            ("gpu_count", "2"),
            ("gpu_driver_version", "535.104.05"),
            ("gpu_runtime", "cuda"),
            ("gpu_runtime_version", "12.2"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect()
    }

    fn two_gpu_variant() -> crate::manifest::GpuRequirements {
        crate::manifest::GpuRequirements {
            vendor: vec!["nvidia".into()],
            families: vec!["hopper".into(), "ampere".into()],
            vram_gib: 80,
            count: 1,
            tensor_parallel: 2,
            driver_min: Some("535".into()),
            runtime: Some("cuda".into()),
            runtime_min: Some("12.1".into()),
        }
    }

    #[test]
    fn gpu_requirements_fit_and_refuse_with_a_reason() {
        let gpu = two_gpu_variant();
        gpu_requirements_fit(&h100_facts(), &gpu).unwrap();

        let refused = |key: &str, value: Option<&str>| {
            let mut facts = h100_facts();
            match value {
                Some(value) => facts.insert(key.into(), value.into()),
                None => facts.remove(key),
            };
            gpu_requirements_fit(&facts, &gpu).unwrap_err()
        };
        assert_eq!(
            refused("gpu_vram_gib", Some("40")),
            FitRefusal::BelowMinimum {
                fact: "gpu_vram_gib",
                actual: "40".into(),
                minimum: "80".into(),
            }
        );
        assert_eq!(
            refused("gpu_count", Some("1")),
            FitRefusal::BelowMinimum {
                fact: "gpu_count",
                actual: "1".into(),
                minimum: "2".into(),
            }
        );
        assert_eq!(
            refused("gpu_driver_version", Some("525.60.13")).code(),
            "fact_below_minimum"
        );
        assert_eq!(
            refused("gpu_runtime_version", Some("11.8")).code(),
            "fact_below_minimum"
        );
        assert_eq!(
            refused("gpu_runtime", Some("rocm")).code(),
            "fact_not_allowed"
        );
        assert_eq!(
            refused("gpu_family", Some("turing")).code(),
            "fact_not_allowed"
        );
        for unknown in [
            "gpu_vendor",
            "gpu_family",
            "gpu_vram_gib",
            "gpu_count",
            "gpu_driver_version",
            "gpu_runtime",
            "gpu_runtime_version",
        ] {
            assert_eq!(
                refused(unknown, None),
                FitRefusal::MissingFact { fact: unknown },
                "unknown {unknown} must not fit"
            );
        }
    }

    #[test]
    fn variant_with_gpu_requirements_reports_the_refusal() {
        let mut facts = h100_facts();
        facts.insert("architecture".into(), "x86_64".into());
        facts.insert("memory_gib".into(), "512".into());
        facts.insert("gpu_vram_gib".into(), "24".into());
        let requirements = crate::manifest::ModelRequirementsSection {
            architecture: vec!["x86_64".into()],
            memory_gib: 64,
            accelerator: vec![],
            gpu: Some(two_gpu_variant()),
        };
        let err = model_requirements_fit("gpu-a", "llama-70b", "1.0.0", &facts, &requirements)
            .unwrap_err()
            .to_string();
        assert!(err.contains("[fact_below_minimum]"), "{err}");
        assert!(err.contains("gpu_vram_gib"), "{err}");
    }

    #[test]
    fn dotted_versions_compare_numerically() {
        assert!(dotted_version("12.10").unwrap() > dotted_version("12.2").unwrap());
        assert_eq!(dotted_version("12.2.0"), dotted_version("12.2"));
        assert!(dotted_version("535.104.05").unwrap() > dotted_version("535").unwrap());
        assert_eq!(dotted_version("12.x"), None);
        assert_eq!(dotted_version(""), None);
    }

    fn native_inventory(components: &[(&str, &str)]) -> String {
        serde_json::json!({
            "schema": crate::exposure::INVENTORY_SCHEMA,
            "components": components
                .iter()
                .map(|(name, version)| serde_json::json!({"name": name, "version": version}))
                .collect::<Vec<_>>(),
        })
        .to_string()
    }

    async fn signed_publish(ctx: &mut Ctx, root: &std::path::Path, version: &str, inventory: &str) {
        let product = root.join(format!("product-{version}"));
        std::fs::create_dir_all(&product).unwrap();
        std::fs::write(product.join("sbom.json"), inventory).unwrap();
        std::fs::write(
            product.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "api"
version = "{version}"

[deploy]
install = "true"

[inventory]
document = "sbom.json"
"#
            ),
        )
        .unwrap();
        let keys = root.join("keys");
        let signature = root.join(format!("signature-{version}.json"));
        let trust = root.join("trust-roots.toml");
        crate::dev_sign::sign_release(&keys, &product.join("tenkai.toml"), &signature, &trust)
            .unwrap();
        crate::catalog::publish(
            ctx,
            &product.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                state_dir: Some(root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    async fn recalled_upgrade_catalog(
        label: &str,
        current_inventory: &str,
        target_inventory: &str,
    ) -> (std::path::PathBuf, Ctx) {
        let root = std::env::temp_dir().join(format!(
            "tenkai-recalled-upgrade-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(&mut ctx, &root, "1.0.0", current_inventory).await;
        signed_publish(&mut ctx, &root, "1.1.0", target_inventory).await;
        let actor = crate::auth_context::test_management_context(label);
        crate::catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        subscribe(&mut ctx, "local", "api", "stable").await.unwrap();
        (root, ctx)
    }

    async fn pin_current(ctx: &mut Ctx, version: &str) {
        let mut env = crate::environment::environment(ctx, "local").await.unwrap();
        env.properties
            .insert("deployed.api".into(), version.to_string());
        env.properties.insert(
            "deployed_release.api".into(),
            crate::ontology::release_id("api", version),
        );
        ctx.put(env).await.unwrap();
    }

    async fn set_block_severity(ctx: &mut Ctx) {
        let mut env = crate::environment::environment(ctx, "local").await.unwrap();
        env.properties.insert(
            crate::exposure::BLOCK_SEVERITY_PROPERTY.into(),
            "high".into(),
        );
        ctx.put(env).await.unwrap();
    }

    fn two_advisory_feed() -> crate::exposure::AdvisoryFeed {
        crate::exposure::AdvisoryFeed {
            schema: crate::exposure::ADVISORY_FEED_SCHEMA.into(),
            generated_at: 2_000,
            advisories: vec![
                crate::exposure::Advisory {
                    id: "TENKAI-2026-1".into(),
                    component: "openssl".into(),
                    range: ">=1.0.0,<1.2.0".into(),
                    severity: crate::exposure::Severity::High,
                    issued_at: 1,
                },
                crate::exposure::Advisory {
                    id: "TENKAI-2026-2".into(),
                    component: "libfoo".into(),
                    range: ">=1.0.0,<1.1.0".into(),
                    severity: crate::exposure::Severity::High,
                    issued_at: 1,
                },
            ],
        }
    }

    async fn import_feed(ctx: &mut Ctx) {
        crate::exposure::import_advisory_feed(ctx, two_advisory_feed(), 2)
            .await
            .unwrap();
    }

    async fn bind_notice(ctx: &mut Ctx, spec: &str) {
        let now = crate::now_millis();
        let document = serde_json::json!({
            "statement": {
                "recalled": [{"release": spec, "digest": "unused"}]
            }
        })
        .to_string();
        let digest = format!("{:x}", Sha256::digest(document.as_bytes()));
        ctx.create_once(crate::pb::sekai::Object {
            id: format!("tenkai:recall-notice:{digest}"),
            kind: crate::recall_notice::KIND_RECALL_NOTICE.into(),
            name: format!("notice {spec}"),
            namespace: crate::ontology::NS.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("document".into(), document),
                ("digest".into(), digest),
                ("imported_at".into(), now.to_string()),
                ("advisory_id".into(), "TENKAI-2026-1".into()),
                ("key_id".into(), "test-key".into()),
            ]),
            created: now,
            updated: now,
        })
        .await
        .unwrap();
    }

    async fn recall_target(ctx: &mut Ctx, label: &str) {
        let actor = crate::auth_context::test_management_context(label);
        crate::catalog::recall(ctx, &actor, "api@1.1.0")
            .await
            .unwrap();
    }

    /// #1068: a notice-bound recalled head whose blocking set is a proper
    /// subset of the current pin is admitted onto the signed plan.
    #[tokio::test]
    async fn create_admits_an_advisory_recalled_upgrade_that_lowers_exposure() {
        let current = native_inventory(&[("openssl", "1.1.1"), ("libfoo", "1.0.0")]);
        let target = native_inventory(&[("openssl", "1.1.1")]);
        let (root, mut ctx) = recalled_upgrade_catalog("happy", &current, &target).await;
        pin_current(&mut ctx, "1.0.0").await;
        set_block_severity(&mut ctx).await;
        import_feed(&mut ctx).await;
        bind_notice(&mut ctx, "api@1.1.0").await;
        recall_target(&mut ctx, "happy").await;

        let denied = create(&mut ctx, "local").await.unwrap_err().to_string();
        assert!(denied.contains("recalled"), "{denied}");

        let plan = create_with_recalled_upgrade(&mut ctx, "local", "lower libfoo exposure")
            .await
            .unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].action, Action::Upgrade);
        assert_eq!(plan.steps[0].to, "1.1.0");
        assert_eq!(plan.recalled_upgrade.len(), 1);
        let admission = &plan.recalled_upgrade[0];
        assert_eq!(admission.reason, "lower libfoo exposure");
        assert_eq!(admission.product, "api");
        assert_eq!(
            admission.current_release,
            crate::ontology::release_id("api", "1.0.0")
        );
        assert_eq!(
            admission.target_release,
            crate::ontology::release_id("api", "1.1.0")
        );
        assert_eq!(
            admission.current_advisories,
            vec!["TENKAI-2026-1".to_string(), "TENKAI-2026-2".into()]
        );
        assert_eq!(
            admission.target_advisories,
            vec!["TENKAI-2026-1".to_string()]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn create_refuses_a_recalled_upgrade_that_does_not_lower_exposure() {
        let inventory = native_inventory(&[("openssl", "1.1.1")]);
        let (root, mut ctx) = recalled_upgrade_catalog("not-lower", &inventory, &inventory).await;
        pin_current(&mut ctx, "1.0.0").await;
        set_block_severity(&mut ctx).await;
        import_feed(&mut ctx).await;
        bind_notice(&mut ctx, "api@1.1.0").await;
        recall_target(&mut ctx, "not-lower").await;

        let denied = create_with_recalled_upgrade(&mut ctx, "local", "still exposed")
            .await
            .unwrap_err()
            .to_string();
        assert!(denied.contains(crate::exposure::NOT_LOWER_GATE), "{denied}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn create_refuses_an_untyped_recalled_upgrade() {
        let current = native_inventory(&[("openssl", "1.1.1"), ("libfoo", "1.0.0")]);
        let target = native_inventory(&[("openssl", "1.1.1")]);
        let (root, mut ctx) = recalled_upgrade_catalog("unbound", &current, &target).await;
        pin_current(&mut ctx, "1.0.0").await;
        set_block_severity(&mut ctx).await;
        import_feed(&mut ctx).await;
        recall_target(&mut ctx, "unbound").await;

        let denied = create_with_recalled_upgrade(&mut ctx, "local", "operator recall")
            .await
            .unwrap_err()
            .to_string();
        assert!(denied.contains(crate::exposure::UNBOUND_GATE), "{denied}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn create_refuses_a_recalled_upgrade_when_the_feed_is_unevaluable() {
        let current = native_inventory(&[("openssl", "1.1.1"), ("libfoo", "1.0.0")]);
        let target = native_inventory(&[("openssl", "1.1.1")]);
        let (root, mut ctx) = recalled_upgrade_catalog("unevaluable", &current, &target).await;
        pin_current(&mut ctx, "1.0.0").await;
        bind_notice(&mut ctx, "api@1.1.0").await;
        recall_target(&mut ctx, "unevaluable").await;

        let denied = create_with_recalled_upgrade(&mut ctx, "local", "no feed")
            .await
            .unwrap_err()
            .to_string();
        assert!(denied.contains("recalled_upgrade_unevaluable"), "{denied}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn create_ignores_unused_recalled_upgrade_reason() {
        let inventory = native_inventory(&[("openssl", "1.1.1")]);
        let (root, mut ctx) = recalled_upgrade_catalog("unused", &inventory, &inventory).await;
        pin_current(&mut ctx, "1.0.0").await;

        let plan = create_with_recalled_upgrade(&mut ctx, "local", "unused")
            .await
            .unwrap();
        assert_eq!(plan.steps[0].action, Action::Upgrade);
        assert!(plan.recalled_upgrade.is_empty(), "{plan:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn create_refuses_a_recalled_upgrade_without_a_current_pin() {
        let current = native_inventory(&[("openssl", "1.1.1"), ("libfoo", "1.0.0")]);
        let target = native_inventory(&[("openssl", "1.1.1")]);
        let (root, mut ctx) = recalled_upgrade_catalog("not-upgrade", &current, &target).await;
        set_block_severity(&mut ctx).await;
        import_feed(&mut ctx).await;
        bind_notice(&mut ctx, "api@1.1.0").await;
        recall_target(&mut ctx, "not-upgrade").await;

        let denied = create_with_recalled_upgrade(&mut ctx, "local", "install onto recalled")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            denied.contains(crate::exposure::NOT_UPGRADE_GATE),
            "{denied}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
