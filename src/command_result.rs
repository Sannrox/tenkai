//! Versioned, bounded machine-readable results for typed CLI adapters, in
//! embedded and remote mode alike.
//!
//! These envelopes are correlation metadata, not execution receipts or
//! recovery state. A client that does not receive one complete envelope must
//! treat the command outcome as unknown and reconcile with Tenkai.

use serde::{Deserialize, Deserializer, Serialize};

pub const COMMAND_RESULT_SCHEMA_V1: &str = "tenkai.command-result/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandName {
    Invocation,
    Publish,
    Promote,
    Plan,
    Apply,
    ApplyCancel,
    Status,
    Explain,
    InspectEnvironment,
    HistoryEnvironment,
    Rollback,
    Restart,
    Recall,
    Approve,
    Subscribe,
    ListEnvironments,
    FleetStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutcome {
    Succeeded,
    Failed,
    AwaitingApproval,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryGuidance {
    NotNeeded,
    CorrectRequest,
    ReconcileBeforeRetry,
    NotSafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceReference {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandCounts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<u64>,
}

/// Bounded gate that refused a command. `code` reuses instance-explain checks
/// plus the closed refusal list; `next` names the action and its actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandRefusalReason {
    pub code: String,
    pub next: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandFailure {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<CommandRefusalReason>,
}

/// Named gate refusal that adapters attach to `tenkai.command-result/v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRefusal {
    pub code: String,
    pub next: String,
    message: String,
}

pub const REFUSAL_APPROVAL: &str = "approval";
pub const REFUSAL_QUORUM: &str = "quorum";
pub const REFUSAL_AGENT_BUDGET: &str = "agent_budget";
pub const REFUSAL_DELIVERY_HOLD: &str = "delivery_hold";
pub const REFUSAL_FAILED_TARGET: &str = "failed_target";
pub const REFUSAL_MAINTENANCE: &str = "maintenance";
pub const REFUSAL_DEPENDENCY_HOLD: &str = "dependency_hold";
pub const REFUSAL_RECALL: &str = "recall";
pub const REFUSAL_STALE_GENERATION: &str = "stale_generation";
pub const REFUSAL_LEASE: &str = "apply_lease";
pub const REFUSAL_INVALID_SELECTOR: &str = "invalid_selector";

const KNOWN_REFUSAL_CODES: &[&str] = &[
    REFUSAL_APPROVAL,
    REFUSAL_QUORUM,
    REFUSAL_AGENT_BUDGET,
    REFUSAL_DELIVERY_HOLD,
    REFUSAL_FAILED_TARGET,
    REFUSAL_MAINTENANCE,
    REFUSAL_DEPENDENCY_HOLD,
    REFUSAL_RECALL,
    REFUSAL_STALE_GENERATION,
    REFUSAL_LEASE,
    REFUSAL_INVALID_SELECTOR,
];

const MAX_RESOURCES: usize = 8;
const MAX_RESOURCE_KIND_BYTES: usize = 64;
const MAX_RESOURCE_ID_BYTES: usize = 512;
const MAX_ERROR_CODE_BYTES: usize = 64;
const MAX_ERROR_MESSAGE_BYTES: usize = 256;
const MAX_NEXT_BYTES: usize = 256;

/// Map a reason code the receiver does not know to `domain_denied`.
pub fn map_unknown_refusal_code(code: &str) -> &str {
    if KNOWN_REFUSAL_CODES.contains(&code) {
        code
    } else {
        "domain_denied"
    }
}

fn bound_bytes(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

impl CommandRefusalReason {
    pub fn sanitized(self) -> Self {
        Self {
            code: map_unknown_refusal_code(&self.code).to_string(),
            next: bound_bytes(&self.next, MAX_NEXT_BYTES),
        }
    }
}

impl CommandRefusal {
    pub fn delivery_hold(
        plan_id: &str,
        scope: &str,
        actor: &str,
        hold_reason: &str,
        next: impl Into<String>,
    ) -> Self {
        Self {
            code: REFUSAL_DELIVERY_HOLD.into(),
            next: bound_bytes(&next.into(), MAX_NEXT_BYTES),
            message: format!(
                "plan {plan_id} is paused by delivery hold {scope} set by {actor}: {hold_reason}; clear the hold to execute"
            ),
        }
    }

    pub fn agent_budget(rule: &str) -> Self {
        let prefix = "human principal must approve and apply: ";
        let rule = bound_bytes(rule, MAX_NEXT_BYTES.saturating_sub(prefix.len()));
        Self {
            code: REFUSAL_AGENT_BUDGET.into(),
            next: format!("{prefix}{rule}"),
            message: "agent plan exceeds the approval budget".into(),
        }
    }

    pub fn reason(&self) -> CommandRefusalReason {
        CommandRefusalReason {
            code: self.code.clone(),
            next: self.next.clone(),
        }
        .sanitized()
    }
}

impl std::fmt::Display for CommandRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CommandRefusal {}

pub fn validate_resource_reference(kind: &str, id: &str) -> Result<(), &'static str> {
    if kind.is_empty() || kind.len() > MAX_RESOURCE_KIND_BYTES {
        return Err("command-result resource kind is outside bounds");
    }
    if id.is_empty() || id.len() > MAX_RESOURCE_ID_BYTES {
        return Err("command-result resource id is outside bounds");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandResultV1 {
    pub schema: String,
    pub command: CommandName,
    pub outcome: CommandOutcome,
    pub retry: RetryGuidance,
    pub resources: Vec<ResourceReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<CommandCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CommandFailure>,
}

impl CommandResultV1 {
    pub fn succeeded(command: CommandName) -> Self {
        Self {
            schema: COMMAND_RESULT_SCHEMA_V1.into(),
            command,
            outcome: CommandOutcome::Succeeded,
            retry: RetryGuidance::NotNeeded,
            resources: Vec::new(),
            counts: None,
            error: None,
        }
    }

    pub fn failed(
        command: CommandName,
        code: &'static str,
        message: &'static str,
        retry: RetryGuidance,
    ) -> Self {
        Self {
            schema: COMMAND_RESULT_SCHEMA_V1.into(),
            command,
            outcome: CommandOutcome::Failed,
            retry,
            resources: Vec::new(),
            counts: None,
            error: Some(CommandFailure {
                code: code.into(),
                message: message.into(),
                reason: None,
            }),
        }
    }

    pub fn refused(command: CommandName, refusal: &CommandRefusal) -> Self {
        Self::failed(
            command,
            "domain_denied",
            "Tenkai refused the command",
            RetryGuidance::CorrectRequest,
        )
        .with_reason(refusal.reason())
    }

    pub fn with_reason(mut self, reason: CommandRefusalReason) -> Self {
        let reason = CommandRefusalReason {
            code: bound_bytes(&reason.code, MAX_ERROR_CODE_BYTES),
            next: bound_bytes(&reason.next, MAX_NEXT_BYTES),
        };
        if reason.code.is_empty() || reason.next.is_empty() {
            return self;
        }
        if let Some(error) = &mut self.error {
            error.reason = Some(reason);
        }
        self
    }

    pub fn resource(mut self, kind: &'static str, id: impl Into<String>) -> Self {
        self.resources.push(ResourceReference {
            kind: kind.into(),
            id: id.into(),
        });
        self
    }

    pub fn counts(mut self, steps: Option<usize>, items: Option<usize>) -> Self {
        self.counts = Some(CommandCounts {
            steps: steps.map(|value| value as u64),
            items: items.map(|value| value as u64),
        });
        self
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != COMMAND_RESULT_SCHEMA_V1 {
            return Err("unsupported command-result schema");
        }
        if self.resources.len() > MAX_RESOURCES {
            return Err("too many command-result resources");
        }
        for resource in &self.resources {
            validate_resource_reference(&resource.kind, &resource.id)?;
        }
        if let Some(error) = &self.error {
            if error.code.is_empty()
                || error.code.len() > MAX_ERROR_CODE_BYTES
                || error.message.is_empty()
                || error.message.len() > MAX_ERROR_MESSAGE_BYTES
            {
                return Err("command-result error metadata is outside bounds");
            }
            if let Some(reason) = &error.reason
                && (reason.code.is_empty()
                    || reason.code.len() > MAX_ERROR_CODE_BYTES
                    || reason.next.is_empty()
                    || reason.next.len() > MAX_NEXT_BYTES)
            {
                return Err("command-result refusal reason is outside bounds");
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CommandResultV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireResult {
            schema: String,
            command: CommandName,
            outcome: CommandOutcome,
            retry: RetryGuidance,
            resources: Vec<ResourceReference>,
            counts: Option<CommandCounts>,
            error: Option<CommandFailure>,
        }

        let wire = WireResult::deserialize(deserializer)?;
        let mut error = wire.error;
        if let Some(failure) = &mut error
            && let Some(reason) = failure.reason.take()
        {
            failure.reason = Some(reason.sanitized());
        }
        let result = Self {
            schema: wire.schema,
            command: wire.command,
            outcome: wire.outcome,
            retry: wire.retry,
            resources: wire.resources,
            counts: wire.counts,
            error,
        };
        result.validate().map_err(serde::de::Error::custom)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_envelope_is_stable_and_roundtrips() {
        let result = CommandResultV1::succeeded(CommandName::Plan)
            .resource("plan", "tenkai:plan:local:1:digest")
            .counts(Some(2), None);
        let encoded = serde_json::to_string(&result).unwrap();
        assert_eq!(
            encoded,
            r#"{"schema":"tenkai.command-result/v1","command":"plan","outcome":"succeeded","retry":"not_needed","resources":[{"kind":"plan","id":"tenkai:plan:local:1:digest"}],"counts":{"steps":2}}"#
        );
        assert_eq!(
            serde_json::from_str::<CommandResultV1>(&encoded).unwrap(),
            result
        );
    }

    #[test]
    fn failure_envelope_is_sanitized_and_strict() {
        let result = CommandResultV1::failed(
            CommandName::Publish,
            "operation_failed",
            "Tenkai rejected the operation",
            RetryGuidance::ReconcileBeforeRetry,
        );
        let encoded = serde_json::to_string(&result).unwrap();
        for forbidden in [
            "password",
            "token",
            "private_key",
            "database",
            "/Users/",
            "manifest",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        let with_unknown = encoded.replacen(
            r#""command":"publish""#,
            r#""unexpected":true,"command":"publish""#,
            1,
        );
        assert!(serde_json::from_str::<CommandResultV1>(&with_unknown).is_err());
        let wrong_schema = encoded.replace(COMMAND_RESULT_SCHEMA_V1, "tenkai.command-result/v2");
        assert!(serde_json::from_str::<CommandResultV1>(&wrong_schema).is_err());
    }

    #[test]
    fn resource_identifiers_are_bounded_on_decode() {
        let result = CommandResultV1::succeeded(CommandName::Status)
            .resource("environment", "x".repeat(MAX_RESOURCE_ID_BYTES + 1));
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(serde_json::from_str::<CommandResultV1>(&encoded).is_err());
    }

    #[test]
    fn unknown_outcome_is_available_for_adapter_reconciliation() {
        let result = CommandResultV1 {
            schema: COMMAND_RESULT_SCHEMA_V1.into(),
            command: CommandName::Apply,
            outcome: CommandOutcome::Unknown,
            retry: RetryGuidance::ReconcileBeforeRetry,
            resources: vec![ResourceReference {
                kind: "plan".into(),
                id: "plan-1".into(),
            }],
            counts: None,
            error: None,
        };
        assert!(
            serde_json::to_string(&result)
                .unwrap()
                .contains(r#""outcome":"unknown""#)
        );
    }

    #[test]
    fn refusal_reason_is_omitted_when_absent_and_bounded_when_present() {
        let without = CommandResultV1::failed(
            CommandName::Apply,
            "domain_denied",
            "Tenkai refused the command",
            RetryGuidance::CorrectRequest,
        );
        let encoded = serde_json::to_string(&without).unwrap();
        assert!(!encoded.contains("reason"));
        let with = CommandResultV1::refused(
            CommandName::Apply,
            &CommandRefusal::delivery_hold(
                "plan-1",
                "environment:lab",
                "alice",
                "pause",
                "tenkaictl env hold lab clear",
            ),
        );
        let encoded = serde_json::to_string(&with).unwrap();
        assert!(encoded.contains(r#""code":"delivery_hold""#));
        assert!(encoded.contains(r#""next":"tenkaictl env hold lab clear""#));
        assert_eq!(
            serde_json::from_str::<CommandResultV1>(&encoded).unwrap(),
            with
        );
    }

    #[test]
    fn older_client_maps_unknown_reason_code_to_domain_denied() {
        #[derive(Deserialize)]
        struct LegacyFailure {
            code: String,
            #[serde(default)]
            reason: Option<LegacyReason>,
        }
        #[derive(Deserialize)]
        struct LegacyReason {
            code: String,
        }
        #[derive(Deserialize)]
        struct LegacyResult {
            error: LegacyFailure,
        }

        let encoded = r#"{"schema":"tenkai.command-result/v1","command":"plan","outcome":"failed","retry":"correct_request","resources":[],"error":{"code":"domain_denied","message":"Tenkai refused the command","reason":{"code":"future_gate","next":"wait"}}}"#;
        let legacy: LegacyResult = serde_json::from_str(encoded).unwrap();
        assert_eq!(legacy.error.code, "domain_denied");
        let reason = legacy.error.reason.expect("reason present");
        assert_eq!(map_unknown_refusal_code(&reason.code), "domain_denied");
        let current = serde_json::from_str::<CommandResultV1>(encoded).unwrap();
        assert_eq!(
            current
                .error
                .as_ref()
                .unwrap()
                .reason
                .as_ref()
                .unwrap()
                .code,
            "domain_denied"
        );
    }

    #[test]
    fn agent_budget_refusal_names_the_rule() {
        let refusal = CommandRefusal::agent_budget("policy mode is manual");
        assert_eq!(refusal.code, REFUSAL_AGENT_BUDGET);
        assert_eq!(
            refusal.next,
            "human principal must approve and apply: policy mode is manual"
        );
        let result = CommandResultV1::refused(CommandName::Plan, &refusal);
        let reason = result.error.as_ref().unwrap().reason.as_ref().unwrap();
        assert_eq!(reason.code, REFUSAL_AGENT_BUDGET);
        assert_eq!(
            reason.next,
            "human principal must approve and apply: policy mode is manual"
        );
    }
}
