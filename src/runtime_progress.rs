//! A runtime plan's durable progress across a step that loses the runtime
//! (ADR 0051 §3): an OS image `reboot`. Before it starts that step, the
//! runtime reports the receipts of the steps before it, and the server keeps
//! them on the plan's runtime claim with the time it recorded them. After
//! the reboot, a fresh runtime instance of the same enrolled runner claims
//! the plan again, gets the record back, and continues at the `verify` that
//! settles the reboot, without running any earlier step again.

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::plan::{HostAction, Plan, Step};
use crate::runtime_delivery::RuntimeStepReceipt;

/// What a runtime reports on `POST .../progress` before it starts the
/// `reboot` step `awaiting_boot` of its claimed plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProgressReport {
    pub plan_id: String,
    pub generation: u64,
    /// The step whose outcome only a later boot can tell.
    pub awaiting_boot: String,
    /// The succeeded receipts of every step before it, in plan order.
    pub receipts: Vec<RuntimeStepReceipt>,
}

/// The progress the server keeps on the claim and hands back, as
/// `progress_json`, to a claim by the runner that recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProgress {
    pub awaiting_boot: String,
    pub receipts: Vec<RuntimeStepReceipt>,
    /// The runner registry id that recorded it: only that runner may claim
    /// the plan again, since only its host can verify the boot.
    pub runner: String,
    /// When the server first durably recorded the awaited step, in
    /// milliseconds; the boot deadline counts from it.
    pub recorded_at: i64,
}

/// Whether `step` is an OS image host step, which only a runtime that names
/// the `os_image` capability is handed.
pub fn updates_os_image(step: &Step) -> bool {
    step.host.is_some_and(|host| host.action.updates_os_image())
}

/// The index of the step that awaits a boot in `plan`, when `awaiting_boot`
/// and `receipts` describe a resumable point: a host `reboot` step, a host
/// `verify` of the same product right after it, and a succeeded receipt for
/// each step before it, in order. Anything else is refused, so neither side
/// can skip a step that did not run.
pub fn awaiting_index(
    plan: &Plan,
    awaiting_boot: &str,
    receipts: &[RuntimeStepReceipt],
) -> Result<usize> {
    let Some(index) = plan.steps.iter().position(|step| step.id == awaiting_boot) else {
        bail!("plan {} has no step {awaiting_boot}", plan.id);
    };
    let step = &plan.steps[index];
    ensure!(
        step.host
            .is_some_and(|host| host.action == HostAction::Reboot),
        "step {awaiting_boot} is not a host reboot; only a reboot awaits a boot"
    );
    ensure!(
        plan.steps.get(index + 1).is_some_and(|next| {
            next.product == step.product
                && next
                    .host
                    .is_some_and(|host| host.action == HostAction::Verify)
        }),
        "step {awaiting_boot} is not followed by a host verify of {}",
        step.product
    );
    ensure!(
        receipts.len() == index,
        "{} receipts were reported for the {index} steps before {awaiting_boot}",
        receipts.len()
    );
    for (receipt, earlier) in receipts.iter().zip(&plan.steps) {
        ensure!(
            receipt.step_id == earlier.id,
            "receipt {} does not match step {} of the plan",
            receipt.step_id,
            earlier.id
        );
        ensure!(
            receipt.succeeded,
            "step {} failed, so the plan does not reach {awaiting_boot}",
            earlier.id
        );
    }
    Ok(index)
}

/// The `reboot` step's receipt, settled by the receipt of the `verify` that
/// read the booted image: it succeeds exactly when `verify` did.
pub fn settled_reboot(reboot: &Step, verify: &RuntimeStepReceipt) -> RuntimeStepReceipt {
    RuntimeStepReceipt {
        step_id: reboot.id.clone(),
        succeeded: verify.succeeded,
        detail: format!("settled by {}: {}", verify.step_id, verify.detail),
        wraps: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn step(id: &str, product: &str, host: Option<&str>) -> serde_json::Value {
        let mut step = json!({
            "id": id, "order": 0, "product": product, "action": "upgrade",
            "from": "1.0.0", "to": "2.0.0", "release_id": "r", "release_digest": "sha256:r",
            "artifact_digest": "sha256:a", "workdir": "/w", "restore": null,
        });
        if let Some(action) = host {
            step["host"] = json!({"action": action, "expected_generation": 1});
        }
        step
    }

    fn plan(steps: Vec<serde_json::Value>) -> Plan {
        serde_json::from_value(json!({
            "format_version": 1, "id": "plan-1", "content_id": "c", "environment": "prod",
            "created_at": 0, "inputs": [], "steps": steps, "state": "computed",
            "gates_skipped": null, "status_detail": "",
        }))
        .unwrap()
    }

    fn receipt(step_id: &str, succeeded: bool) -> RuntimeStepReceipt {
        RuntimeStepReceipt {
            step_id: step_id.into(),
            succeeded,
            detail: String::new(),
            wraps: Vec::new(),
        }
    }

    fn image_plan() -> Plan {
        plan(vec![
            step("s0", "os", Some("stage")),
            step("s1", "os", Some("reboot")),
            step("s2", "os", Some("verify")),
            step("s3", "os", Some("confirm")),
        ])
    }

    #[test]
    fn a_reboot_after_succeeded_steps_is_the_resume_point() {
        assert_eq!(
            awaiting_index(&image_plan(), "s1", &[receipt("s0", true)]).unwrap(),
            1
        );
    }

    #[test]
    fn a_report_that_would_skip_a_step_is_refused() {
        let plan = image_plan();
        for (awaiting, receipts, refusal) in [
            ("s9", vec![receipt("s0", true)], "has no step"),
            ("s0", vec![], "is not a host reboot"),
            ("s1", vec![], "0 receipts"),
            ("s1", vec![receipt("s9", true)], "does not match"),
            ("s1", vec![receipt("s0", false)], "failed"),
        ] {
            let error = awaiting_index(&plan, awaiting, &receipts).unwrap_err();
            assert!(error.to_string().contains(refusal), "{error}");
        }
        let no_verify = plan_without_verify();
        let error = awaiting_index(&no_verify, "s1", &[receipt("s0", true)]).unwrap_err();
        assert!(error.to_string().contains("not followed by a host verify"));
    }

    fn plan_without_verify() -> Plan {
        plan(vec![
            step("s0", "os", Some("stage")),
            step("s1", "os", Some("reboot")),
            step("s2", "api", None),
        ])
    }

    #[test]
    fn the_reboot_settles_with_its_verify() {
        let plan = image_plan();
        let settled = settled_reboot(&plan.steps[1], &receipt("s2", false));
        assert_eq!((settled.step_id.as_str(), settled.succeeded), ("s1", false));
        assert!(settled.detail.starts_with("settled by s2"));
    }
}
