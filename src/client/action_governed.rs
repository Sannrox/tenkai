//! Governed action type and parameter encoding helpers.

use anyhow::{Context as _, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::action_lifecycle::{
    GOVERNED_ACTION_NAMESPACE, GOVERNED_ACTION_VERSION, RemoteActionDefs,
};
use crate::pb::graph_action::ActionTypeDef;
use crate::pb::sekai::GovernedActionType;

pub(super) fn resolve_remote_action_def(
    action_defs: &RemoteActionDefs,
    action: &str,
) -> Option<ActionTypeDef> {
    action_defs
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(action)
        .cloned()
        .or_else(|| crate::ontology::known_action(action))
}

pub(super) fn governed_action_type(
    action: &ActionTypeDef,
) -> std::result::Result<GovernedActionType, tonic::Status> {
    let schema = parameter_schema_json(action).map_err(tonic::Status::invalid_argument)?;
    Ok(GovernedActionType {
        namespace: GOVERNED_ACTION_NAMESPACE.into(),
        type_id: action.name.clone(),
        version: GOVERNED_ACTION_VERSION.into(),
        description: action.description.clone(),
        parameter_schema_json: schema,
        // Mutations remain Tenkai-applied graph RPCs after admission.
        allowed_effect_kinds: vec!["external_mutate".into()],
        policy_scope: String::new(),
        budget_scope: String::new(),
        enabled: true,
        created_by: String::new(),
        created_at_ms: 0,
        updated_at_ms: 0,
        disabled_at_ms: 0,
    })
}

pub(super) fn parameter_schema_json(action: &ActionTypeDef) -> Result<String, String> {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    properties.insert(
        "id".into(),
        serde_json::json!({"type": "string", "minLength": 1}),
    );
    required.push("id".into());
    for param in &action.params {
        let mut property = serde_json::Map::new();
        let ty = match param.r#type.as_str() {
            "number" => "number",
            "integer" => "integer",
            "boolean" => "boolean",
            _ => "string",
        };
        property.insert("type".into(), serde_json::Value::String(ty.into()));
        if ty == "string" {
            property.insert("minLength".into(), serde_json::json!(1));
        }
        if !param.enum_values.is_empty() {
            property.insert(
                "enum".into(),
                serde_json::Value::Array(
                    param
                        .enum_values
                        .iter()
                        .map(|value| serde_json::Value::String(value.clone()))
                        .collect(),
                ),
            );
        }
        properties.insert(param.name.clone(), serde_json::Value::Object(property));
        if param.required {
            required.push(param.name.clone());
        }
    }
    serde_json::to_string(&serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    }))
    .map_err(|error| error.to_string())
}

pub(super) fn parameters_json(params: &HashMap<String, String>) -> Result<String> {
    let mut object = serde_json::Map::new();
    let mut keys = params.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        let value = params
            .get(&key)
            .with_context(|| format!("missing parameter {key}"))?;
        object.insert(key, serde_json::Value::String(value.clone()));
    }
    Ok(serde_json::Value::Object(object).to_string())
}

pub(super) fn idempotency_key(action: &str, params: &HashMap<String, String>) -> String {
    if let Some(correlation) = params.get("correlation") {
        return format!("{action}:{correlation}");
    }
    let mut digest = Sha256::new();
    digest.update(action.as_bytes());
    let mut keys = params.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        digest.update(key.as_bytes());
        digest.update([0]);
        if let Some(value) = params.get(&key) {
            digest.update(value.as_bytes());
        }
        digest.update([0]);
    }
    let digest = digest.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("{action}:sha256:{hex}")
}

pub(super) fn map_instance_decision(instance: &crate::pb::sekai::ActionInstance) -> String {
    if instance.status == "admitted" {
        return "allow".into();
    }
    if instance.policy_decision == "require_approval" {
        return "require_approval".into();
    }
    "deny".into()
}
