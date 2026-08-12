//! Governed action lifecycle semantics across embedded and remote adapters.
//!
//! Embedded Tenkai keeps a local graph-action definition store and applies the
//! Tenkai-owned mutation DSL in-process. Remote Tenkai registers
//! `GovernedActionType` records and admits work through `SubmitActionInstance`,
//! then applies the same mutation plan through ordinary graph RPCs after
//! admission. Missing, disabled, denied, or unauthorized definitions fail closed.

use anyhow::{Context as _, Result, bail};
use prost::Message;
use sekai_client::CallOptions;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::{RemoteClient, sdk_error_status};
use crate::pb::graph_action::{ActionResult, ActionTypeDef};
use crate::pb::sekai::{
    CreateLinkRequest, CreateLinkResponse, Decision, DeleteLinkRequest, DeleteLinkResponse,
    GetGovernedActionTypeRequest, GetGovernedActionTypeResponse, GetObjectRequest,
    GetObjectResponse, GovernedActionType, Link, ListActionPoliciesRequest,
    ListActionPoliciesResponse, ListDecisionsRequest, ListDecisionsResponse, Object,
    PutGovernedActionTypeRequest, PutGovernedActionTypeResponse, RecordDecisionRequest,
    RecordDecisionResponse, SubmitActionInstanceRequest, SubmitActionInstanceResponse,
    UpdateObjectRequest, UpdateObjectResponse,
};

pub(super) const GOVERNED_ACTION_NAMESPACE: &str = "tenkai";
pub(super) const GOVERNED_ACTION_VERSION: &str = "1";

pub(super) type RemoteActionDefs = Arc<Mutex<HashMap<String, ActionTypeDef>>>;

pub(super) enum ActionLifecycle<'a> {
    Remote {
        client: &'a RemoteClient,
        action_defs: &'a RemoteActionDefs,
    },
    Embedded(&'a crate::embedded::EmbeddedStore),
}

impl ActionLifecycle<'_> {
    pub(super) async fn register(
        &self,
        action: ActionTypeDef,
    ) -> std::result::Result<(), tonic::Status> {
        match self {
            Self::Embedded(store) => store.register_action(action),
            Self::Remote {
                client,
                action_defs,
            } => {
                let action_name = action.name.clone();
                let governed = governed_action_type(&action)?;
                let response: std::result::Result<PutGovernedActionTypeResponse, tonic::Status> =
                    remote_unary(
                        client,
                        "/sekai.SekaiService/PutGovernedActionType",
                        PutGovernedActionTypeRequest {
                            r#type: Some(governed),
                            request_id: uuid::Uuid::new_v4().to_string(),
                        },
                    )
                    .await;
                match response {
                    Ok(response) => {
                        if response.r#type.is_none() {
                            return Err(tonic::Status::internal(
                                "Sekai PutGovernedActionType returned no type",
                            ));
                        }
                    }
                    Err(status) if status.code() == tonic::Code::AlreadyExists => {}
                    Err(status)
                        if status.code() == tonic::Code::Internal
                            && remote_governed_action_exists(client, &action_name).await =>
                    {
                        // Idempotent bootstrap against hosts that surface conflicts as Internal.
                    }
                    Err(status) => return Err(status),
                }
                action_defs
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .insert(action_name, action);
                Ok(())
            }
        }
    }

    pub(super) async fn execute(
        &self,
        action: &str,
        params: HashMap<String, String>,
        dry_run: bool,
    ) -> Result<ActionResult> {
        match self {
            Self::Embedded(store) => store.execute_action(action, params, dry_run),
            Self::Remote {
                client,
                action_defs,
            } => {
                let definition = resolve_remote_action_def(action_defs, action).with_context(|| {
                    format!(
                        "remote action {action} is not registered in this Tenkai process; run `tenkaictl init`"
                    )
                })?;
                ensure_remote_type_enabled(client, action).await?;
                let planned_ops = definition
                    .ops
                    .iter()
                    .map(|op| op.op.clone())
                    .collect::<Vec<_>>();
                if dry_run {
                    let decision = preview_remote_decision(client, action).await?;
                    return Ok(ActionResult {
                        action: action.into(),
                        message: format!("remote governed preview decision: {decision}"),
                        dry_run: true,
                        planned_ops,
                        decision,
                        approval_id: String::new(),
                    });
                }

                let parameters_json = parameters_json(&params)?;
                let response: SubmitActionInstanceResponse = remote_unary(
                    client,
                    "/sekai.SekaiService/SubmitActionInstance",
                    SubmitActionInstanceRequest {
                        namespace: GOVERNED_ACTION_NAMESPACE.into(),
                        type_id: action.into(),
                        version: GOVERNED_ACTION_VERSION.into(),
                        parameters_json,
                        idempotency_key: idempotency_key(action, &params),
                        evidence_submission_ids: Vec::new(),
                        request_id: uuid::Uuid::new_v4().to_string(),
                    },
                )
                .await?;
                let instance = response
                    .instance
                    .context("Sekai SubmitActionInstance returned no instance")?;
                let decision = map_instance_decision(&instance);
                if decision != "allow" {
                    return Ok(ActionResult {
                        action: action.into(),
                        message: if instance.deny_reason.is_empty() {
                            format!("governed action admission status {}", instance.status)
                        } else {
                            instance.deny_reason.clone()
                        },
                        dry_run: false,
                        planned_ops,
                        decision,
                        approval_id: instance.instance_id,
                    });
                }

                apply_remote_ops(client, action, &definition, &params).await?;
                record_remote_execution_decision(client, action, &params).await?;
                Ok(ActionResult {
                    action: action.into(),
                    message: "allowed by governed action admission".into(),
                    dry_run: false,
                    planned_ops,
                    decision: "allow".into(),
                    approval_id: instance.instance_id,
                })
            }
        }
    }

    pub(super) async fn deny(&self, approval_id: &str, reason: &str) -> Result<()> {
        match self {
            Self::Embedded(_) => anyhow::bail!(
                "embedded mode has no deferred approvals; action {approval_id} cannot be denied"
            ),
            Self::Remote { .. } => {
                // Governed require_approval admissions are denied at submit time;
                // there is no deferred approval queue to cancel.
                let _ = reason;
                Ok(())
            }
        }
    }

    pub(super) async fn decisions(
        &self,
        actor: &str,
        action: &str,
        after: i64,
    ) -> Result<Vec<Decision>> {
        match self {
            Self::Embedded(store) => store.decisions(actor, action, after),
            Self::Remote { client, .. } => {
                let response: ListDecisionsResponse = remote_unary(
                    client,
                    "/sekai.SekaiService/ListDecisions",
                    ListDecisionsRequest {
                        actor: actor.into(),
                        action: action.into(),
                        after,
                        limit: i32::MAX,
                        target_id: String::new(),
                    },
                )
                .await?;
                Ok(response.decisions)
            }
        }
    }
}

fn resolve_remote_action_def(
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

fn governed_action_type(
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

fn parameter_schema_json(action: &ActionTypeDef) -> Result<String, String> {
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

fn parameters_json(params: &HashMap<String, String>) -> Result<String> {
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

fn idempotency_key(action: &str, params: &HashMap<String, String>) -> String {
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

fn map_instance_decision(instance: &crate::pb::sekai::ActionInstance) -> String {
    if instance.status == "admitted" {
        return "allow".into();
    }
    if instance.policy_decision == "require_approval" {
        return "require_approval".into();
    }
    "deny".into()
}

async fn ensure_remote_type_enabled(client: &RemoteClient, action: &str) -> Result<()> {
    let response: GetGovernedActionTypeResponse = remote_unary(
        client,
        "/sekai.SekaiService/GetGovernedActionType",
        GetGovernedActionTypeRequest {
            namespace: GOVERNED_ACTION_NAMESPACE.into(),
            type_id: action.into(),
            version: GOVERNED_ACTION_VERSION.into(),
        },
    )
    .await
    .with_context(|| format!("governed action type {action}@{GOVERNED_ACTION_VERSION}"))?;
    let Some(type_def) = response.r#type else {
        bail!("governed action type {action}@{GOVERNED_ACTION_VERSION} is missing");
    };
    if !type_def.enabled {
        bail!("governed action type {action}@{GOVERNED_ACTION_VERSION} is disabled");
    }
    Ok(())
}

async fn preview_remote_decision(client: &RemoteClient, action: &str) -> Result<String> {
    let response: std::result::Result<ListActionPoliciesResponse, tonic::Status> = remote_unary(
        client,
        "/sekai.SekaiService/ListActionPolicies",
        ListActionPoliciesRequest {},
    )
    .await;
    let Ok(response) = response else {
        // No policy listing permission or empty surface: default matches Sekai
        // admit-time implicit allow when no ActionPolicy is configured.
        return Ok("allow".into());
    };
    let mut decision = "allow".to_string();
    for policy in response.policies {
        if let Some(override_decision) = policy.action_overrides.get("submit_action_instance") {
            decision = override_decision.clone();
            continue;
        }
        if let Some(override_decision) = policy.risk_overrides.get("write") {
            decision = override_decision.clone();
            continue;
        }
        if !policy.default_decision.is_empty() {
            decision = policy.default_decision;
        }
        let _ = action;
    }
    Ok(decision)
}

async fn apply_remote_ops(
    client: &RemoteClient,
    action_name: &str,
    action: &ActionTypeDef,
    params: &HashMap<String, String>,
) -> Result<()> {
    let target_id = params
        .get("id")
        .with_context(|| format!("remote action {action_name} requires target parameter id"))?;
    let mut target = remote_get_object(client, target_id)
        .await?
        .with_context(|| format!("remote action target {target_id} does not exist"))?;
    for op in &action.ops {
        match op.op.as_str() {
            "set_property" => {
                let value = params.get(&op.value_from).with_context(|| {
                    format!("remote action {action_name} requires {}", op.value_from)
                })?;
                target.properties.insert(op.property.clone(), value.clone());
            }
            "create_link" => {
                let to_id = params.get(&op.property).with_context(|| {
                    format!("remote action {action_name} requires {}", op.property)
                })?;
                let link = Link {
                    id: format!("{target_id}--{}--{to_id}", op.relation),
                    from_id: target_id.clone(),
                    to_id: to_id.clone(),
                    relation: op.relation.clone(),
                    created: crate::now_millis(),
                };
                let response: std::result::Result<CreateLinkResponse, tonic::Status> =
                    remote_unary(
                        client,
                        "/sekai.SekaiService/CreateLink",
                        CreateLinkRequest {
                            link: Some(link),
                            fail_if_exists: true,
                        },
                    )
                    .await;
                match response {
                    Ok(_) => {}
                    Err(status) if status.code() == tonic::Code::AlreadyExists => {}
                    Err(status) => return Err(status.into()),
                }
            }
            "delete_link" => {
                let link_id = params.get(&op.value_from).with_context(|| {
                    format!("remote action {action_name} requires {}", op.value_from)
                })?;
                let response: std::result::Result<DeleteLinkResponse, tonic::Status> =
                    remote_unary(
                        client,
                        "/sekai.SekaiService/DeleteLink",
                        DeleteLinkRequest {
                            id: link_id.clone(),
                        },
                    )
                    .await;
                match response {
                    Ok(_) => {}
                    Err(status) if status.code() == tonic::Code::NotFound => {}
                    Err(status) => return Err(status.into()),
                }
            }
            other => bail!("unsupported remote action operation {other:?}"),
        }
    }
    target.updated = crate::now_millis();
    let _: UpdateObjectResponse = remote_unary(
        client,
        "/sekai.SekaiService/UpdateObject",
        UpdateObjectRequest {
            object: Some(target),
            lease_precondition: None,
        },
    )
    .await?;
    Ok(())
}

async fn record_remote_execution_decision(
    client: &RemoteClient,
    action: &str,
    params: &HashMap<String, String>,
) -> Result<()> {
    let target_id = params
        .get("id")
        .with_context(|| format!("remote action {action} requires target parameter id"))?;
    let mut evidence = params.clone();
    evidence.insert("decision".into(), "allow".into());
    let _: RecordDecisionResponse = remote_unary(
        client,
        "/sekai.SekaiService/RecordDecision",
        RecordDecisionRequest {
            decision: Some(Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: crate::now_millis(),
                actor: client.config().principal.clone(),
                action: action.into(),
                reason: "execute_action".into(),
                evidence,
                target_id: target_id.clone(),
                outcome: "allow".into(),
            }),
        },
    )
    .await
    .context("recording governed action execution evidence")?;
    Ok(())
}

async fn remote_get_object(client: &RemoteClient, id: &str) -> Result<Option<Object>> {
    let response: std::result::Result<GetObjectResponse, tonic::Status> = remote_unary(
        client,
        "/sekai.SekaiService/GetObject",
        GetObjectRequest { id: id.into() },
    )
    .await;
    match response {
        Ok(response) => Ok(response.object),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(status.into()),
    }
}

async fn remote_governed_action_exists(client: &RemoteClient, name: &str) -> bool {
    let response: std::result::Result<GetGovernedActionTypeResponse, tonic::Status> = remote_unary(
        client,
        "/sekai.SekaiService/GetGovernedActionType",
        GetGovernedActionTypeRequest {
            namespace: GOVERNED_ACTION_NAMESPACE.into(),
            type_id: name.into(),
            version: GOVERNED_ACTION_VERSION.into(),
        },
    )
    .await;
    response.is_ok_and(|response| response.r#type.is_some())
}

async fn remote_unary<Req, Resp>(
    client: &RemoteClient,
    path: &str,
    request: Req,
) -> std::result::Result<Resp, tonic::Status>
where
    Req: Message + Default + Clone + Send + 'static,
    Resp: Message + Default + Send + 'static,
{
    client
        .raw()
        .unary(path, request, CallOptions::default())
        .await
        .map_err(sdk_error_status)
}
