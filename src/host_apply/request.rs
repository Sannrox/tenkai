//! The request the server hands the root-side host applier, and the instance
//! key both sides derive from it.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::plan::{HostAction, Plan};
use crate::plan_approval::ApprovalEnvelope;
use crate::release_signing::SignatureEnvelope;

pub const REQUEST_SCHEMA: &str = "tenkai.host-apply-request.v1";
/// The request document inside a spooled instance directory.
pub const REQUEST_FILE: &str = "request.json";
/// The release workdir inside a spooled instance directory: the manifest's
/// deploy inputs, laid out relative to it as the release declares them.
pub const ARTIFACTS_DIR: &str = "artifacts";
/// Largest `request.json` the applier reads.
pub const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const INSTANCE_DOMAIN: &[u8] = b"TENKAI-HOST-APPLY-INSTANCE-V1\0";

/// One host step, as the server spools it under `<spool>/<instance>/`.
///
/// The applier treats every field as untrusted. It verifies `manifest` and
/// the release workdir against `signature`, `plan` against `approvals`, and
/// uses `step_id` and `action` only to find the step, which must name the
/// same action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostApplyRequest {
    pub schema: String,
    /// The executable plan in Tenkai's versioned plan encoding.
    pub plan: Plan,
    pub step_id: String,
    pub action: HostAction,
    /// The release manifest text exactly as signed.
    pub manifest: String,
    pub signature: SignatureEnvelope,
    /// Plan approval envelopes for this plan's digest (ADR 0037).
    pub approvals: Vec<ApprovalEnvelope>,
}

impl HostApplyRequest {
    /// The request for step `step_id` of `plan`: the signed release
    /// (`manifest` and its `signature`) and the plan's approval envelopes.
    /// The server's own automatic approvals never authorize a host step, so
    /// they are left out, and a request without any other is refused.
    pub fn new(
        plan: &Plan,
        step_id: &str,
        action: HostAction,
        manifest: &str,
        signature: SignatureEnvelope,
        approvals: &[ApprovalEnvelope],
    ) -> Result<Self> {
        let approvals: Vec<_> = approvals
            .iter()
            .filter(|envelope| {
                envelope.statement.policy_provider != crate::approval_policy::POLICY_PROVIDER
            })
            .cloned()
            .collect();
        if approvals.is_empty() {
            bail!(
                "host steps need human or external plan approvals; the server's own approvals never authorize them"
            );
        }
        Ok(Self {
            schema: REQUEST_SCHEMA.into(),
            plan: plan.clone(),
            step_id: step_id.into(),
            action,
            manifest: manifest.into(),
            signature,
            approvals,
        })
    }

    /// Parse a request document, refusing other schemas and unknown fields.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|error| anyhow::anyhow!("host apply request is not valid: {error}"))?;
        if request.schema != REQUEST_SCHEMA {
            bail!(
                "unsupported host apply request schema {:?}; expected {REQUEST_SCHEMA:?}",
                request.schema
            );
        }
        Ok(request)
    }

    /// `sha256:<hex>` of the plan's executable content, the digest approvals sign.
    pub fn plan_digest(&self) -> Result<String> {
        Ok(format!("sha256:{}", self.plan.executable_digest()?))
    }

    /// The instance name this request must run under.
    pub fn instance(&self) -> Result<String> {
        Ok(instance_key(
            &self.plan_digest()?,
            &self.step_id,
            self.action,
        ))
    }
}

/// Instance name of `tenkai-host-apply@<instance>.service`: 64 lowercase hex
/// characters of a digest over the plan digest, the step id, and the action.
/// The server names the unit with it; the applier recomputes it from the
/// verified request and refuses a unit started under any other name.
pub fn instance_key(plan_digest: &str, step_id: &str, action: HostAction) -> String {
    let mut bytes = INSTANCE_DOMAIN.to_vec();
    for value in [
        plan_digest.as_bytes(),
        step_id.as_bytes(),
        action.as_str().as_bytes(),
    ] {
        crate::signature_verification::push_len_prefixed(&mut bytes, value);
    }
    format!("{:x}", Sha256::digest(bytes))
}

/// Refuse anything but an instance key's shape before it touches a path.
pub fn validate_instance_name(instance: &str) -> Result<()> {
    crate::signature_verification::validate_hex_digest("host apply instance", instance)
}

/// File-name key of one environment and product, for records and locks.
pub fn product_key(environment: &str, product: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{environment}\0{product}").as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_key_binds_plan_step_and_action() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let key = instance_key(&digest, "p:step:0", HostAction::Install);
        validate_instance_name(&key).unwrap();
        assert_ne!(key, instance_key(&digest, "p:step:1", HostAction::Install));
        assert_ne!(
            key,
            instance_key(&digest, "p:step:0", HostAction::Uninstall)
        );
        assert_ne!(
            key,
            instance_key(
                &format!("sha256:{}", "b".repeat(64)),
                "p:step:0",
                HostAction::Install
            )
        );
        assert!(validate_instance_name("../etc").is_err());
        assert!(validate_instance_name(&key.to_uppercase()).is_err());
    }
}
