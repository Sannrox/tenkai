//! Everything the root side checks about a copied request before the
//! applied-state critical section (ADR 0041 §2, steps 2 to 4).

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use super::policy::{HostApprovalPolicy, HostApprovals};
use super::request::HostApplyRequest;
use crate::plan::{Action, HostAction, PLAN_FORMAT_VERSION};
use crate::software_executor::SoftwareExecutorKind;

/// Root-owned trust the applier verifies with, loaded from its config dir.
#[derive(Debug, Clone)]
pub struct HostTrust {
    pub release_roots: crate::release_signing::TrustRoots,
    pub policy: HostApprovalPolicy,
}

/// One release as the applied-state record names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRelease {
    pub version: String,
    /// Bare sha256 hex of the signed manifest text.
    pub manifest_digest: String,
}

/// A request whose release, plan, step, and approvals all verified. Every
/// field comes from signed or approved content, never from the request's
/// own claims.
#[derive(Debug, Clone)]
pub struct VerifiedHostStep {
    pub instance: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub environment: String,
    pub product: String,
    pub step_id: String,
    /// The planner's action for the step; `rollback` selects the rollback
    /// quorum when the target is not newer than the high-water release.
    pub step_action: Action,
    pub action: HostAction,
    pub expected_generation: u64,
    /// The release the record must hold, or `None` for nothing applied.
    pub from: Option<String>,
    pub release: HostRelease,
    pub artifact_digest: String,
    /// The signed manifest's command for `action`.
    pub command: String,
    pub signer_identity: String,
    pub approvals: HostApprovals,
}

/// Verify a request that has already been copied into root-owned storage,
/// with `workdir` the copied release workdir. Refuses with the first
/// reason found; nothing here writes state.
pub fn verify_copied_request(
    request: &HostApplyRequest,
    instance: &str,
    workdir: &Path,
    trust: &HostTrust,
    now_ms: i64,
) -> Result<VerifiedHostStep> {
    super::request::validate_instance_name(instance)?;
    let plan = &request.plan;
    if plan.format_version != PLAN_FORMAT_VERSION {
        bail!(
            "host apply plan uses format version {}; this applier reads {PLAN_FORMAT_VERSION}",
            plan.format_version
        );
    }
    crate::ontology::validate_identifier("environment", &plan.environment)?;
    let plan_digest = request.plan_digest()?;
    let expected_instance = request.instance()?;
    if instance != expected_instance {
        bail!(
            "instance name {instance} does not match the request's plan digest, step, and action ({expected_instance})"
        );
    }
    let step = plan
        .steps
        .iter()
        .find(|step| step.id == request.step_id)
        .with_context(|| format!("plan {} has no step {}", plan.id, request.step_id))?;
    let Some(host) = step.host else {
        bail!("plan step {} is not a host step", step.id);
    };
    if host.action != request.action {
        bail!(
            "plan step {} authorizes {}, not {}",
            step.id,
            host.action,
            request.action
        );
    }

    let manifest = crate::manifest::parse_raw(&request.manifest)
        .context("host release manifest is not valid")?;
    if manifest.product.kind.policy().target() != crate::product_kind::ProductTarget::Software {
        bail!("host releases must be software products");
    }
    if manifest.deploy.executor != Some(SoftwareExecutorKind::Host) {
        bail!("the signed manifest does not declare deploy.executor = \"host\"");
    }
    if !manifest.artifacts.is_empty() {
        bail!("host releases cannot declare OCI artifacts; ship them as deploy inputs");
    }
    let name = &manifest.product.name;
    let version = &manifest.product.version;
    crate::ontology::validate_identifier("product", name)?;
    if step.product != *name
        || step.to != *version
        || step.release_id != crate::ontology::release_id(name, version)
    {
        bail!(
            "plan step {} names {} {}, but the signed manifest is {name} {version}",
            step.id,
            step.product,
            step.to
        );
    }
    if matches!(host.action, HostAction::Uninstall | HostAction::Health)
        && step.from.as_deref() != Some(version.as_str())
    {
        bail!(
            "a host {} step must act on the installed release: from {:?} is not {version}",
            host.action,
            step.from
        );
    }
    let command = match host.action {
        HostAction::Install => Some(manifest.deploy.install.clone()),
        HostAction::Uninstall => manifest.deploy.uninstall.clone(),
        HostAction::Health => manifest.deploy.health.clone(),
    }
    .filter(|command| !command.trim().is_empty())
    .with_context(|| {
        format!(
            "the signed manifest declares no deploy.{} command",
            host.action
        )
    })?;

    let signer = request
        .signature
        .authenticate_at(&trust.release_roots, now_ms)
        .context("host release signature")?;
    let manifest_digest = crate::manifest::digest(&request.manifest);
    if request.signature.statement.manifest_digest != manifest_digest
        || step.release_digest != manifest_digest
    {
        bail!("the release manifest does not match its signed digest or the plan step");
    }
    let artifact_digest = crate::manifest::artifact_digest(workdir, &manifest.immutable_inputs())
        .context("hashing the copied release artifacts")?;
    if request.signature.statement.artifact_digest != artifact_digest
        || step.artifact_digest != artifact_digest
    {
        bail!(
            "the copied release artifacts do not match their signed digest: signed {}, copied {artifact_digest}",
            request.signature.statement.artifact_digest
        );
    }

    let approvals = trust.policy.evaluate(plan, &request.approvals, now_ms);
    approvals.require_for_plan(plan)?;

    Ok(VerifiedHostStep {
        instance: instance.into(),
        plan_id: plan.id.clone(),
        plan_digest,
        environment: plan.environment.clone(),
        product: name.clone(),
        step_id: step.id.clone(),
        step_action: step.action,
        action: host.action,
        expected_generation: host.expected_generation,
        from: step.from.clone(),
        release: HostRelease {
            version: version.clone(),
            manifest_digest,
        },
        artifact_digest,
        command,
        signer_identity: signer.identity,
        approvals,
    })
}
