//! Remote governed-action admission and mutation helpers.

use anyhow::{Context as _, Result, bail};
use std::collections::HashMap;

use super::action_lifecycle::{GOVERNED_ACTION_NAMESPACE, GOVERNED_ACTION_VERSION};
use super::{RemoteClient, remote_unary};
use crate::pb::graph_action::ActionTypeDef;
use crate::pb::sekai::{
    CreateLinkRequest, CreateLinkResponse, Decision, DeleteLinkRequest, DeleteLinkResponse,
    GetGovernedActionTypeRequest, GetGovernedActionTypeResponse, GetObjectRequest,
    GetObjectResponse, Link, ListActionPoliciesRequest, ListActionPoliciesResponse, Object,
    RecordDecisionRequest, RecordDecisionResponse, UpdateObjectRequest, UpdateObjectResponse,
};

pub(super) async fn ensure_remote_type_enabled(client: &RemoteClient, action: &str) -> Result<()> {
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

pub(super) async fn preview_remote_decision(client: &RemoteClient, action: &str) -> Result<String> {
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

pub(super) async fn apply_remote_ops(
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

pub(super) async fn record_remote_execution_decision(
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

pub(super) async fn remote_get_object(client: &RemoteClient, id: &str) -> Result<Option<Object>> {
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

pub(super) async fn remote_governed_action_exists(client: &RemoteClient, name: &str) -> bool {
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
