//! Feedback observations (#802, layer 1 of #782).
//!
//! One versioned, bounded record per committed deployment outcome: which
//! operation and stage, a typed reason, how long the step took, the
//! controller version, and the lease generation it ran under. It is written
//! in the same transaction as the outcome, never changes afterwards, and is
//! never sent anywhere by this layer. `tenkai.terminal_outcome.v1` is
//! unchanged.
//!
//! An observation carries no detail text: no command output, credentials,
//! signing material, environment facts or content. The reason is classified
//! from Tenkai's own outcome vocabulary, and every identifier is bounded.

use serde::{Deserialize, Serialize};

use crate::plan::Action;

pub const FEEDBACK_OBSERVATION_SCHEMA: &str = "tenkai.feedback_observation.v1";
/// The longest identifier an observation stores; longer ones are cut.
const MAX_FIELD_BYTES: usize = 256;

/// Where the outcome was committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// An apply or rollback step run by the controller.
    ApplyStep,
    /// A step a runtime agent completed.
    RuntimeCompletion,
    /// An operator resolved an unknown deployment state.
    UnknownReconciliation,
    /// A plan was held before or between steps: maintenance or a gate (#803).
    PlanBlocked,
    /// A plan failed outside any step outcome (#803).
    PlanFailed,
    /// A plan left running by a controller that stopped was recovered
    /// after a restart (#803).
    OrphanRecovery,
}

/// Why the outcome is what it is. Closed: a new reason is a schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The step succeeded.
    None,
    /// The deployed product's command or health failed.
    ProductFailed,
    /// The product failed and the previous release was restored.
    ProductFailedRestored,
    /// Tenkai itself failed: executor, cleanup or bookkeeping.
    TenkaiFailed,
    /// Tenkai failed and the previous release was restored.
    TenkaiFailedRestored,
    /// The deployment command was interrupted or terminated.
    Cancelled,
    /// A policy, gate or drain held the step.
    Blocked,
    /// The step ended with the deployed state unknown.
    StateUnknown,
    /// An operator recorded what is deployed after an unknown state.
    Reconciled,
    /// The observation could not be built from the outcome; only its
    /// identity is kept.
    Degraded,
    /// A maintenance window held the plan.
    MaintenanceBlocked,
    /// A release gate (such as an evaluation suite) held the plan.
    GateBlocked,
    /// The plan failed before or around its steps.
    PlanFailed,
    /// The controller running the plan stopped; it was failed on recovery.
    Abandoned,
}

/// Retry and recovery facts an outcome is attributable to (#803). All
/// optional, so records without them are unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryContext {
    /// The environment lease was taken over from an expired holder.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub takeover: bool,
    /// The runtime claim generation that completed the steps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_claim_generation: Option<u64>,
    /// The step retried a release the environment held as a failed target.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub failed_target_retry: bool,
    /// The audited reason that admitted rollback onto recalled content,
    /// bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_reason: Option<String>,
}

impl RetryContext {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// One immutable observation. `id` is the committed outcome's identity, so
/// an identical replay of the same outcome is idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackObservation {
    pub schema: String,
    pub id: String,
    pub operation: Operation,
    pub environment: String,
    pub product: String,
    pub plan_id: String,
    pub step_id: String,
    pub action: String,
    pub release_id: String,
    pub status: String,
    pub reason: Reason,
    /// From execution entry to the committed outcome; absent when the start
    /// was not observed by this process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    pub controller_version: String,
    /// The environment lease generation the outcome committed under, so
    /// retries and takeovers of one step are told apart.
    pub lease_generation: u64,
    pub observed_at_ms: i64,
    #[serde(default, skip_serializing_if = "RetryContext::is_empty")]
    pub context: RetryContext,
}

/// The facts an observation is built from.
pub struct Capture<'a> {
    pub id: &'a str,
    pub operation: Operation,
    pub environment: &'a str,
    pub product: &'a str,
    pub plan_id: &'a str,
    pub step_id: &'a str,
    /// `None` for a plan-level operation that names no step; for a step
    /// operation, `None` means the step could not be read and degrades the
    /// observation.
    pub action: Option<Action>,
    pub release_id: &'a str,
    pub status: &'a str,
    pub reason: Reason,
    pub started_at_ms: Option<i64>,
    pub lease_generation: u64,
    pub observed_at_ms: i64,
    pub context: RetryContext,
}

impl FeedbackObservation {
    /// Build an observation. A field that cannot be stored as given yields a
    /// degraded observation that keeps only the outcome's identity, so a
    /// build failure never interrupts the operation.
    pub fn capture(capture: Capture<'_>) -> Self {
        let observation = Self {
            schema: FEEDBACK_OBSERVATION_SCHEMA.into(),
            id: capture.id.into(),
            operation: capture.operation,
            environment: capture.environment.into(),
            product: capture.product.into(),
            plan_id: capture.plan_id.into(),
            step_id: capture.step_id.into(),
            action: capture
                .action
                .map(|action| action.to_string())
                .unwrap_or_default(),
            release_id: capture.release_id.into(),
            status: capture.status.into(),
            reason: capture.reason,
            duration_ms: capture.started_at_ms.and_then(|started| {
                u64::try_from(capture.observed_at_ms.checked_sub(started)?).ok()
            }),
            controller_version: crate::version_skew::SERVER_VERSION.into(),
            lease_generation: capture.lease_generation,
            observed_at_ms: capture.observed_at_ms,
            context: RetryContext {
                recovery_reason: capture.context.recovery_reason.as_deref().map(bounded),
                ..capture.context
            },
        };
        // Step operations need their step; plan-level ones may have none.
        let step_known = capture.action.is_some()
            || matches!(
                capture.operation,
                Operation::PlanBlocked | Operation::PlanFailed | Operation::OrphanRecovery
            );
        if step_known && observation.within_bounds() {
            return observation;
        }
        Self {
            id: bounded_identity(&observation.id),
            environment: bounded(&observation.environment),
            product: bounded(&observation.product),
            plan_id: bounded(&observation.plan_id),
            step_id: bounded(&observation.step_id),
            release_id: bounded(&observation.release_id),
            status: bounded(&observation.status),
            reason: Reason::Degraded,
            duration_ms: None,
            ..observation
        }
    }

    fn within_bounds(&self) -> bool {
        [
            &self.id,
            &self.environment,
            &self.product,
            &self.plan_id,
            &self.step_id,
            &self.release_id,
            &self.status,
        ]
        .iter()
        .all(|field| field.len() <= MAX_FIELD_BYTES && !field.chars().any(char::is_control))
    }
}

/// `value` without control characters and cut to [`MAX_FIELD_BYTES`] at a
/// character boundary.
fn bounded(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_FIELD_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

/// `id` when it is storable as given, else a digest of the whole of it, so
/// two long identities never collapse into one record.
fn bounded_identity(id: &str) -> String {
    if id.len() <= MAX_FIELD_BYTES && !id.chars().any(char::is_control) {
        return id.into();
    }
    use sha2::{Digest as _, Sha256};
    format!("sha256:{:x}", Sha256::digest(id.as_bytes()))
}

/// The reason of a controller step outcome, from its status, the deployed
/// state it left, and the prefixes Tenkai itself writes into the detail.
/// The detail is read, never stored.
pub(crate) fn controller_reason(status: &str, detail: &str, state_unknown: bool) -> Reason {
    let tenkai_failed = TENKAI_FAILURE_MARKERS
        .iter()
        .any(|marker| detail.contains(marker));
    match status {
        "succeeded" => Reason::None,
        "blocked" => Reason::Blocked,
        "rolled_back" if tenkai_failed => Reason::TenkaiFailedRestored,
        "rolled_back" => Reason::ProductFailedRestored,
        _ if crate::terminal_outcome::is_cancellation(detail) => Reason::Cancelled,
        _ if state_unknown => Reason::StateUnknown,
        _ if tenkai_failed => Reason::TenkaiFailed,
        _ => Reason::ProductFailed,
    }
}

/// Detail text Tenkai writes when it, not the deployed product, failed.
const TENKAI_FAILURE_MARKERS: [&str; 3] = [
    "deployment executor failed",
    "cleanup executor failed",
    "deployment bookkeeping failed",
];

/// The reason of a step a runtime agent completed.
pub(crate) fn runtime_reason(succeeded: bool) -> Reason {
    if succeeded {
        Reason::None
    } else {
        Reason::ProductFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(status: &str, reason: Reason) -> Capture<'_> {
        Capture {
            id: "deployment:prod:api:2000",
            operation: Operation::ApplyStep,
            environment: "prod",
            product: "api",
            plan_id: "plan:1",
            step_id: "step-1",
            action: Some(Action::Upgrade),
            release_id: "release:api:1.1.0",
            status,
            reason,
            started_at_ms: Some(1_500),
            lease_generation: 3,
            observed_at_ms: 2_000,
            context: RetryContext::default(),
        }
    }

    /// Reasons come from Tenkai's own outcome vocabulary.
    #[test]
    fn controller_outcomes_classify_into_a_typed_reason() {
        for (status, detail, unknown, reason) in [
            ("succeeded", "", false, Reason::None),
            (
                "blocked",
                "waiting for bounded drain",
                false,
                Reason::Blocked,
            ),
            (
                "rolled_back",
                "health failed; restored 1.0.0",
                false,
                Reason::ProductFailedRestored,
            ),
            (
                "rolled_back",
                "deployment executor failed: spawn; restored 1.0.0",
                false,
                Reason::TenkaiFailedRestored,
            ),
            (
                "failed",
                "deployment command interrupted by signal",
                false,
                Reason::Cancelled,
            ),
            (
                "failed",
                "exit 3; re-apply of the current pin also failed",
                true,
                Reason::StateUnknown,
            ),
            (
                "failed",
                "deployment executor failed: spawn",
                false,
                Reason::TenkaiFailed,
            ),
            (
                "failed",
                "exit 3; current pin remains deployed",
                false,
                Reason::ProductFailed,
            ),
        ] {
            assert_eq!(
                controller_reason(status, detail, unknown),
                reason,
                "{status} {detail}"
            );
        }
        assert_eq!(runtime_reason(false), Reason::ProductFailed);
    }

    #[test]
    fn an_observation_records_duration_and_version_but_no_detail() {
        let observation = FeedbackObservation::capture(capture("failed", Reason::ProductFailed));
        assert_eq!(observation.duration_ms, Some(500));
        assert_eq!(
            observation.controller_version,
            crate::version_skew::SERVER_VERSION
        );
        assert_eq!(observation.schema, FEEDBACK_OBSERVATION_SCHEMA);
        let encoded = serde_json::to_string(&observation).unwrap();
        assert!(!encoded.contains("detail"), "{encoded}");
        // A clock that moved back gives no duration rather than a wrong one.
        let mut backwards = capture("succeeded", Reason::None);
        backwards.started_at_ms = Some(3_000);
        assert_eq!(FeedbackObservation::capture(backwards).duration_ms, None);
    }

    /// A field that cannot be stored as given degrades the observation to
    /// its bounded identity instead of failing the operation.
    #[test]
    fn an_unbounded_field_yields_a_degraded_observation() {
        let long = "x".repeat(1_000);
        let mut oversized = capture("failed", Reason::ProductFailed);
        oversized.release_id = &long;
        let observation = FeedbackObservation::capture(oversized);
        assert_eq!(observation.reason, Reason::Degraded);
        assert_eq!(observation.release_id.len(), MAX_FIELD_BYTES);
        assert_eq!(observation.duration_ms, None);
        assert_eq!(observation.id, "deployment:prod:api:2000");

        // Long identities stay distinct, as digests of the whole identity.
        let long_id = |suffix: &str| format!("deployment:{}:{suffix}", "e".repeat(300));
        let (first_id, second_id) = (long_id("1000"), long_id("2000"));
        let ids = [&first_id, &second_id].map(|id| {
            let mut long = capture("succeeded", Reason::None);
            long.id = id;
            FeedbackObservation::capture(long).id
        });
        assert_ne!(ids[0], ids[1]);
        assert!(ids.iter().all(|id| id.starts_with("sha256:")));

        // A step that could not be read degrades the observation.
        let mut unread = capture("reconciled", Reason::Reconciled);
        unread.action = None;
        assert_eq!(
            FeedbackObservation::capture(unread).reason,
            Reason::Degraded
        );
    }
}
