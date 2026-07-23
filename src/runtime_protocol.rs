//! Validation rules shared by both sides of the runtime protocol.

use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail};
use sha2::{Digest as _, Sha256};

use crate::pb::runtime_v1::{
    Capability, Lease, PlanDelivery, ProtocolVersion, RuntimeIdentity, Step, StepReceipt,
    StepResult,
};

const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

pub fn negotiate(
    supported: &[ProtocolVersion],
    capabilities: &[Capability],
    required: &[Capability],
) -> Result<ProtocolVersion> {
    let available = capability_versions(capabilities);
    for requirement in required {
        if available.get(requirement.name.as_str()).copied() < Some(requirement.version) {
            bail!(
                "required runtime capability {}@{} is unavailable",
                requirement.name,
                requirement.version
            );
        }
    }

    supported
        .iter()
        .filter(|version| {
            version.major == crate::pb::runtime_v1::PROTOCOL_MAJOR
                && crate::pb::runtime_v1::SUPPORTED_PROTOCOL_MINORS.contains(&version.minor)
        })
        .max_by_key(|version| version.minor)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no compatible runtime protocol version"))
}

pub fn validate_identity(identity: &RuntimeIdentity, expected_environment: &str) -> Result<()> {
    if identity.runtime_id.is_empty() || identity.instance_id.is_empty() {
        bail!("runtime and instance identity are required");
    }
    if identity.environment_id != expected_environment {
        bail!("runtime identity is not scoped to the requested environment");
    }
    Ok(())
}

pub fn validate_delivery(
    delivery: &PlanDelivery,
    identity: &RuntimeIdentity,
    authenticated_environment: &str,
    capabilities: &[Capability],
    supported_plan_formats: &[u32],
    now_unix_ms: i64,
) -> Result<()> {
    validate_identity(identity, authenticated_environment)?;
    if delivery.environment_id != authenticated_environment {
        bail!("plan delivery is outside the authenticated environment scope");
    }
    if delivery.delivery_id.is_empty()
        || delivery.plan_id.is_empty()
        || delivery.plan_digest.is_empty()
        || delivery.steps.is_empty()
    {
        bail!("plan delivery is missing immutable plan identity or content");
    }
    if delivery.plan_digest != delivery_plan_digest(delivery) {
        bail!("plan delivery content does not match its digest");
    }
    let lease = delivery
        .lease
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("plan delivery has no lease"))?;
    if lease.lease_id.is_empty() || lease.generation == 0 || lease.expires_at_unix_ms <= now_unix_ms
    {
        bail!("plan delivery has an invalid or expired lease generation");
    }
    if !supported_plan_formats.contains(&delivery.plan_format_version) {
        bail!(
            "plan delivery uses unsupported format version {}",
            delivery.plan_format_version
        );
    }
    let mut step_ids = HashSet::new();
    for step in &delivery.steps {
        if step.step_id.is_empty()
            || step.action.is_empty()
            || step.input_digest.is_empty()
            || !step_ids.insert(step.step_id.as_str())
        {
            bail!("plan delivery has a malformed or duplicate step attempt");
        }
        validate_step_capabilities(step, capabilities)?;
    }
    Ok(())
}

pub fn validate_receipt(
    receipt: &StepReceipt,
    delivery: &PlanDelivery,
    current_lease: &Lease,
    now_unix_ms: i64,
) -> Result<()> {
    let delivered_lease = delivery
        .lease
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("plan delivery has no lease"))?;
    if receipt.environment_id != delivery.environment_id
        || receipt.plan_id != delivery.plan_id
        || !delivery
            .steps
            .iter()
            .any(|step| step.step_id == receipt.step_id && step.attempt == receipt.attempt)
    {
        bail!("receipt does not bind to the delivered environment, plan, step, and attempt");
    }
    if receipt.lease_id != delivered_lease.lease_id
        || receipt.lease_generation != delivered_lease.generation
        || receipt.lease_id != current_lease.lease_id
        || receipt.lease_generation != current_lease.generation
        || current_lease.expires_at_unix_ms <= now_unix_ms
    {
        bail!("receipt was completed under a stale lease generation");
    }
    if receipt.completed_at_unix_ms <= 0
        || receipt.completed_at_unix_ms < now_unix_ms.saturating_sub(MAX_CLOCK_SKEW_MS)
        || receipt.completed_at_unix_ms > now_unix_ms.saturating_add(MAX_CLOCK_SKEW_MS)
        || receipt.completed_at_unix_ms > current_lease.expires_at_unix_ms
    {
        bail!("receipt completion time is outside the active lease window");
    }
    match StepResult::try_from(receipt.result) {
        Ok(StepResult::Succeeded | StepResult::Failed | StepResult::Cancelled) => {}
        Ok(StepResult::Unspecified) | Err(_) => {
            bail!("receipt has an unsupported step result")
        }
    }
    if receipt.result_digest.is_empty() {
        bail!("receipt has no result digest");
    }
    if receipt.receipt_id != receipt_id(receipt) {
        bail!("receipt id does not match its mutation identity and result");
    }
    Ok(())
}

/// A stable receipt ID is the idempotency key for one mutation attempt.
pub fn receipt_id(receipt: &StepReceipt) -> String {
    let mut digest = Sha256::new();
    for value in [
        receipt.environment_id.as_bytes(),
        receipt.plan_id.as_bytes(),
        receipt.step_id.as_bytes(),
        &receipt.attempt.to_be_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    format!("{:x}", digest.finalize())
}

/// Digest the immutable, executable plan content without transport delivery state.
pub fn delivery_plan_digest(delivery: &PlanDelivery) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest_field(&mut digest, b"tenkai-runtime-plan-v1");
    digest_field(&mut digest, delivery.environment_id.as_bytes());
    digest_field(&mut digest, delivery.plan_id.as_bytes());
    digest_field(&mut digest, &delivery.plan_format_version.to_be_bytes());
    digest_field(&mut digest, &(delivery.steps.len() as u64).to_be_bytes());
    for step in &delivery.steps {
        digest_field(&mut digest, step.step_id.as_bytes());
        digest_field(&mut digest, &step.attempt.to_be_bytes());
        digest_field(&mut digest, step.action.as_bytes());
        digest_field(&mut digest, &step.input_digest);
        let mut capabilities = step.required_capabilities.clone();
        capabilities.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then(left.version.cmp(&right.version))
        });
        digest_field(&mut digest, &(capabilities.len() as u64).to_be_bytes());
        for capability in capabilities {
            digest_field(&mut digest, capability.name.as_bytes());
            digest_field(&mut digest, &capability.version.to_be_bytes());
        }
    }
    digest.finalize().to_vec()
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn validate_step_capabilities(step: &Step, capabilities: &[Capability]) -> Result<()> {
    let available = capability_versions(capabilities);
    for requirement in &step.required_capabilities {
        if available.get(requirement.name.as_str()).copied() < Some(requirement.version) {
            bail!(
                "step {} requires unsupported capability {}@{}",
                step.step_id,
                requirement.name,
                requirement.version
            );
        }
    }
    Ok(())
}

fn capability_versions(capabilities: &[Capability]) -> HashMap<&str, u32> {
    let mut available: HashMap<&str, u32> = HashMap::new();
    for capability in capabilities {
        available
            .entry(capability.name.as_str())
            .and_modify(|version| *version = (*version).max(capability.version))
            .or_insert(capability.version);
    }
    available
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::runtime_v1::Lease;

    fn capability(name: &str, version: u32) -> Capability {
        Capability {
            name: name.into(),
            version,
        }
    }

    fn fixture() -> (RuntimeIdentity, PlanDelivery) {
        let identity = RuntimeIdentity {
            runtime_id: "runtime-prod".into(),
            environment_id: "prod".into(),
            instance_id: "boot-1".into(),
        };
        let mut delivery = PlanDelivery {
            delivery_id: "delivery-1".into(),
            environment_id: "prod".into(),
            plan_id: "plan-1".into(),
            plan_format_version: 1,
            plan_digest: vec![1],
            lease: Some(Lease {
                lease_id: "lease-1".into(),
                generation: 7,
                expires_at_unix_ms: 10,
            }),
            steps: vec![Step {
                step_id: "step-1".into(),
                attempt: 2,
                action: "install".into(),
                input_digest: vec![2],
                required_capabilities: vec![capability("shell", 1)],
            }],
        };
        delivery.plan_digest = delivery_plan_digest(&delivery);
        (identity, delivery)
    }

    #[test]
    fn negotiation_selects_the_highest_compatible_minor() {
        let selected = negotiate(
            &[
                ProtocolVersion { major: 2, minor: 0 },
                ProtocolVersion { major: 1, minor: 0 },
                ProtocolVersion { major: 1, minor: 3 },
            ],
            &[capability("shell", 2)],
            &[capability("shell", 1)],
        )
        .unwrap();
        assert_eq!(selected, ProtocolVersion { major: 1, minor: 0 });
    }

    #[test]
    fn identity_cannot_cross_environment_scope() {
        let (mut identity, delivery) = fixture();
        identity.environment_id = "staging".into();
        assert!(
            validate_delivery(
                &delivery,
                &identity,
                "prod",
                &[capability("shell", 1)],
                &[1],
                9
            )
            .is_err()
        );
    }

    #[test]
    fn unsupported_capability_blocks_before_delivery() {
        let (identity, delivery) = fixture();
        assert!(validate_delivery(&delivery, &identity, "prod", &[], &[1], 9).is_err());
    }

    #[test]
    fn receipt_is_bound_and_duplicate_safe() {
        let (_, delivery) = fixture();
        let mut receipt = StepReceipt {
            receipt_id: String::new(),
            environment_id: "prod".into(),
            plan_id: "plan-1".into(),
            step_id: "step-1".into(),
            attempt: 2,
            result: StepResult::Succeeded.into(),
            result_digest: vec![3],
            lease_id: "lease-1".into(),
            lease_generation: 7,
            completed_at_unix_ms: 9,
        };
        receipt.receipt_id = receipt_id(&receipt);
        validate_receipt(&receipt, &delivery, delivery.lease.as_ref().unwrap(), 9).unwrap();
        assert_eq!(receipt.receipt_id, receipt_id(&receipt));
        let canonical_id = receipt.receipt_id.clone();
        receipt.result = StepResult::Failed.into();
        receipt.result_digest = vec![99];
        assert_eq!(canonical_id, receipt_id(&receipt));

        receipt.attempt = 3;
        assert!(
            validate_receipt(&receipt, &delivery, delivery.lease.as_ref().unwrap(), 9).is_err()
        );
    }

    #[test]
    fn stale_lease_generation_rejects_completion() {
        let (_, delivery) = fixture();
        let mut receipt = StepReceipt {
            receipt_id: String::new(),
            environment_id: "prod".into(),
            plan_id: "plan-1".into(),
            step_id: "step-1".into(),
            attempt: 2,
            result: StepResult::Succeeded.into(),
            result_digest: vec![3],
            lease_id: "lease-1".into(),
            lease_generation: 6,
            completed_at_unix_ms: 9,
        };
        receipt.receipt_id = receipt_id(&receipt);
        assert!(
            validate_receipt(&receipt, &delivery, delivery.lease.as_ref().unwrap(), 9).is_err()
        );
    }

    #[test]
    fn unspecified_and_unknown_results_are_rejected() {
        let (_, delivery) = fixture();
        for result in [StepResult::Unspecified.into(), 99] {
            let mut receipt = StepReceipt {
                receipt_id: String::new(),
                environment_id: "prod".into(),
                plan_id: "plan-1".into(),
                step_id: "step-1".into(),
                attempt: 2,
                result,
                result_digest: vec![3],
                lease_id: "lease-1".into(),
                lease_generation: 7,
                completed_at_unix_ms: 9,
            };
            receipt.receipt_id = receipt_id(&receipt);
            assert!(
                validate_receipt(&receipt, &delivery, delivery.lease.as_ref().unwrap(), 9).is_err()
            );
        }
    }

    #[test]
    fn authoritative_lease_fences_historical_delivery() {
        let (_, delivery) = fixture();
        let mut receipt = StepReceipt {
            receipt_id: String::new(),
            environment_id: "prod".into(),
            plan_id: "plan-1".into(),
            step_id: "step-1".into(),
            attempt: 2,
            result: StepResult::Succeeded.into(),
            result_digest: vec![3],
            lease_id: "lease-1".into(),
            lease_generation: 7,
            completed_at_unix_ms: 9,
        };
        receipt.receipt_id = receipt_id(&receipt);
        let replacement = Lease {
            lease_id: "lease-2".into(),
            generation: 8,
            expires_at_unix_ms: 20,
        };
        assert!(validate_receipt(&receipt, &delivery, &replacement, 9).is_err());
        assert!(
            validate_receipt(&receipt, &delivery, delivery.lease.as_ref().unwrap(), 10).is_err()
        );
    }

    #[test]
    fn duplicate_capabilities_use_the_highest_advertised_version() {
        let selected = negotiate(
            &[ProtocolVersion { major: 1, minor: 0 }],
            &[capability("shell", 2), capability("shell", 1)],
            &[capability("shell", 2)],
        )
        .unwrap();
        assert_eq!(selected, ProtocolVersion { major: 1, minor: 0 });
    }

    #[test]
    fn expired_leases_and_unknown_plan_formats_block_delivery() {
        let (identity, mut delivery) = fixture();
        let capabilities = [capability("shell", 1)];
        assert!(validate_delivery(&delivery, &identity, "prod", &capabilities, &[1], 10).is_err());

        delivery.lease.as_mut().unwrap().expires_at_unix_ms = 20;
        delivery.plan_format_version = 2;
        assert!(validate_delivery(&delivery, &identity, "prod", &capabilities, &[1], 10).is_err());
    }

    #[test]
    fn authenticated_scope_and_step_identity_are_required() {
        let (identity, mut delivery) = fixture();
        let capabilities = [capability("shell", 1)];
        assert!(
            validate_delivery(&delivery, &identity, "staging", &capabilities, &[1], 9).is_err()
        );

        delivery.steps.push(delivery.steps[0].clone());
        assert!(validate_delivery(&delivery, &identity, "prod", &capabilities, &[1], 9).is_err());
    }
}
