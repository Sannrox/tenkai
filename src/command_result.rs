//! Versioned, bounded machine-readable results for typed local CLI adapters.
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
    Status,
    InspectEnvironment,
    Rollback,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandFailure {
    pub code: String,
    pub message: String,
}

const MAX_RESOURCES: usize = 8;
const MAX_RESOURCE_KIND_BYTES: usize = 64;
const MAX_RESOURCE_ID_BYTES: usize = 512;
const MAX_ERROR_CODE_BYTES: usize = 64;
const MAX_ERROR_MESSAGE_BYTES: usize = 256;

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
            }),
        }
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
        if let Some(error) = &self.error
            && (error.code.is_empty()
                || error.code.len() > MAX_ERROR_CODE_BYTES
                || error.message.is_empty()
                || error.message.len() > MAX_ERROR_MESSAGE_BYTES)
        {
            return Err("command-result error metadata is outside bounds");
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
        let result = Self {
            schema: wire.schema,
            command: wire.command,
            outcome: wire.outcome,
            retry: wire.retry,
            resources: wire.resources,
            counts: wire.counts,
            error: wire.error,
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
}
