//! Everything the root side checks about a copied request before the
//! applied-state critical section (ADR 0041 §2, steps 2 to 4).

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use super::policy::{HostApprovalPolicy, HostApprovals};
use super::request::HostApplyRequest;
use crate::approval_policy::QuorumPurpose;
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
    /// Product instance this step applies to. Empty means the product.
    pub product_instance: String,
    pub step_id: String,
    /// The planner's action for the step; `rollback` selects the rollback
    /// quorum when the target is not newer than the high-water release.
    pub step_action: Action,
    pub action: HostAction,
    pub expected_generation: u64,
    /// The release the record must hold, or `None` for nothing applied.
    pub from: Option<String>,
    pub release: HostRelease,
    /// The signed artifact digest, which the step names too.
    pub artifact_digest: String,
    /// The manifest's immutable inputs, relative to the release workdir.
    pub inputs: Vec<String>,
    /// The signed manifest's command for `action`.
    pub command: String,
    pub signer_identity: String,
    pub approvals: HostApprovals,
    /// The purposes every host step of this plan needs, from the plan alone.
    pub purposes: Vec<QuorumPurpose>,
    /// The sealed values the approved step writes before its command runs
    /// (ADR 0048 §4). Empty for most steps.
    pub sealed: Vec<crate::plan::SealedStep>,
}

/// Verify a request copied into root-owned storage, and the copied release
/// workdir `workdir`. Refuses with the first reason found; nothing here
/// writes state.
pub fn verify_copied_request(
    request: &HostApplyRequest,
    instance: &str,
    workdir: &Path,
    trust: &HostTrust,
    now_ms: i64,
) -> Result<VerifiedHostStep> {
    let verified = verify_request(request, instance, trust, now_ms)?;
    verified.verify_artifacts(workdir)?;
    Ok(verified)
}

/// Verify everything about a copied request except the release workdir:
/// instance, plan and step, signed manifest, release signature, and
/// approvals. The applier runs this before it copies any artifact, so
/// unsigned or unapproved content never costs a large copy; it must then
/// call [`VerifiedHostStep::verify_artifacts`] on the copy.
pub fn verify_request(
    request: &HostApplyRequest,
    instance: &str,
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
    if request.signature.statement.artifact_digest != step.artifact_digest {
        bail!("the release signature and the plan step name different artifact digests");
    }
    let approvals = trust.policy.verify_plan(plan, &request.approvals, now_ms)?;
    let purposes = super::policy::plan_purposes(plan);

    Ok(VerifiedHostStep {
        instance: instance.into(),
        plan_id: plan.id.clone(),
        plan_digest,
        environment: plan.environment.clone(),
        product: name.clone(),
        product_instance: step.instance_name().to_string(),
        step_id: step.id.clone(),
        step_action: step.action,
        action: host.action,
        expected_generation: host.expected_generation,
        from: step.from.clone(),
        release: HostRelease {
            version: version.clone(),
            manifest_digest,
        },
        artifact_digest: step.artifact_digest.clone(),
        inputs: manifest.immutable_inputs(),
        command,
        signer_identity: signer.identity,
        approvals,
        purposes,
        sealed: step.sealed.clone(),
    })
}

impl VerifiedHostStep {
    /// Check the copied release workdir against the signed artifact digest.
    pub fn verify_artifacts(&self, workdir: &Path) -> Result<()> {
        let copied = crate::manifest::artifact_digest(workdir, &self.inputs)
            .context("hashing the copied release artifacts")?;
        if copied != self.artifact_digest {
            bail!(
                "the copied release artifacts do not match their signed digest: signed {}, copied {copied}",
                self.artifact_digest
            );
        }
        Ok(())
    }
}
