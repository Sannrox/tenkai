//! Remote governed-action admission and mutation helpers.

use anyhow::{Context as _, Result, bail};
use std::collections::HashMap;

use super::action_lifecycle::{GOVERNED_ACTION_NAMESPACE, GOVERNED_ACTION_VERSION};
use super::{RemoteClient, remote_unary};
use crate::pb::graph_action::ActionTypeDef;
use crate::pb::sekai::{
    CreateLinkRequest, CreateLinkResponse, Decision, DeleteLinkRequest, DeleteLinkResponse,
    GetGovernedActionTypeRequest, GetGovernedActionTypeResponse, GetObjectRequest,
    GetObjectResponse, ListActionPoliciesRequest, ListActionPoliciesResponse, Object,
    RecordDecisionRequest, RecordDecisionResponse, UpdateObjectRequest, UpdateObjectResponse,
};
use crate::storage::ActionWrite;

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
    preview_decision(response, action)
}

/// The dry-run decision for `action` from the provider's policy listing.
///
/// Only a provider without a policy surface (unimplemented or absent) previews
/// as "allow", matching admit-time implicit allow; any other listing error is
/// returned. Each policy decides by its override for `action`, then its
/// `submit_action_instance` override, then its `write` risk override, then
/// its default. Which policy scope applies is decided at admission, so the
/// preview reports the most restrictive decision: deny, then
/// require_approval, then allow. Real admission is enforced by the provider.
fn preview_decision(
    response: std::result::Result<ListActionPoliciesResponse, tonic::Status>,
    action: &str,
) -> Result<String> {
    let response = match response {
        Ok(response) => response,
        Err(status)
            if matches!(
                status.code(),
                tonic::Code::Unimplemented | tonic::Code::NotFound
            ) =>
        {
            return Ok("allow".into());
        }
        Err(status) => {
            return Err(anyhow::Error::new(status))
                .with_context(|| format!("previewing the policy decision for {action}"));
        }
    };
    let restrictiveness = |decision: &str| match decision {
        "deny" => 2,
        "require_approval" => 1,
        _ => 0,
    };
    let decision = response
        .policies
        .iter()
        .filter_map(|policy| {
            policy
                .action_overrides
                .get(action)
                .or_else(|| policy.action_overrides.get("submit_action_instance"))
                .or_else(|| policy.risk_overrides.get("write"))
                .or((!policy.default_decision.is_empty()).then_some(&policy.default_decision))
        })
        .max_by_key(|decision| restrictiveness(decision))
        .map_or("allow", String::as_str);
    Ok(decision.to_string())
}

pub(super) async fn apply_remote_ops(
    client: &RemoteClient,
    action_name: &str,
    action: &ActionTypeDef,
    params: &HashMap<String, String>,
) -> Result<()> {
    let writes = crate::storage::ActionWrites::plan("remote", action_name, action, params)?;
    let target_id = &writes.target_id;
    let mut target = remote_get_object(client, target_id)
        .await?
        .with_context(|| format!("remote action target {target_id} does not exist"))?;
    for write in &writes.writes {
        match write {
            ActionWrite::SetProperty { .. } => {}
            ActionWrite::CreateLink(link) => {
                let response: std::result::Result<CreateLinkResponse, tonic::Status> =
                    remote_unary(
                        client,
                        "/sekai.SekaiService/CreateLink",
                        CreateLinkRequest {
                            link: Some(link.clone()),
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
            ActionWrite::DeleteLink(link_id) => {
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
        }
    }
    writes.apply_properties(&mut target);
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

/// The governed action type registered remotely under `name`, or `None` when
/// it is absent or cannot be read.
pub(super) async fn remote_governed_action(
    client: &RemoteClient,
    name: &str,
) -> Option<crate::pb::sekai::GovernedActionType> {
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
    response.ok().and_then(|response| response.r#type)
}

/// Refuse a remote type that differs from the definition this release
/// registers. The remote version is pinned, so a changed definition can
/// never reach it; accepting it would let local and remote schemas diverge.
pub(super) fn refuse_divergent_type(
    local: &crate::pb::sekai::GovernedActionType,
    remote: &crate::pb::sekai::GovernedActionType,
) -> Result<()> {
    let differs: Vec<&str> = [
        ("description", local.description != remote.description),
        (
            "parameter schema",
            local.parameter_schema_json != remote.parameter_schema_json,
        ),
        (
            "allowed effects",
            local.allowed_effect_kinds != remote.allowed_effect_kinds,
        ),
    ]
    .into_iter()
    .filter_map(|(field, differs)| differs.then_some(field))
    .collect();
    if !differs.is_empty() {
        bail!(
            "remote action type {}/{} version {} already exists with a different {}; \
             this release cannot change it in place. Remove or disable the remote type, \
             or run the Tenkai release that registered it",
            local.namespace,
            local.type_id,
            local.version,
            differs.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod preview_tests {
    use super::*;
    use crate::pb::sekai::ActionPolicy;

    fn policies(
        policies: Vec<ActionPolicy>,
    ) -> std::result::Result<ListActionPoliciesResponse, tonic::Status> {
        Ok(ListActionPoliciesResponse { policies })
    }

    #[test]
    fn a_missing_policy_surface_allows_and_other_errors_surface() {
        for code in [tonic::Code::Unimplemented, tonic::Code::NotFound] {
            let decision = preview_decision(Err(tonic::Status::new(code, "none")), "act").unwrap();
            assert_eq!(decision, "allow");
        }
        let error = preview_decision(Err(tonic::Status::unavailable("down")), "act").unwrap_err();
        assert!(format!("{error:#}").contains("down"), "{error:#}");
        assert!(preview_decision(Err(tonic::Status::permission_denied("no")), "act").is_err());
    }

    #[test]
    fn the_named_action_and_the_most_restrictive_policy_decide() {
        let named = ActionPolicy {
            default_decision: "allow".into(),
            action_overrides: [("act".to_string(), "require_approval".to_string())].into(),
            ..ActionPolicy::default()
        };
        let other_action = ActionPolicy {
            default_decision: "allow".into(),
            action_overrides: [("other".to_string(), "deny".to_string())].into(),
            ..ActionPolicy::default()
        };
        assert_eq!(
            preview_decision(policies(vec![named.clone(), other_action.clone()]), "act").unwrap(),
            "require_approval"
        );
        // Order does not matter: a later permissive policy does not win.
        let permissive = ActionPolicy {
            default_decision: "allow".into(),
            ..ActionPolicy::default()
        };
        assert_eq!(
            preview_decision(policies(vec![named, permissive]), "act").unwrap(),
            "require_approval"
        );
        assert_eq!(
            preview_decision(policies(vec![other_action]), "act").unwrap(),
            "allow"
        );
        assert_eq!(
            preview_decision(policies(Vec::new()), "act").unwrap(),
            "allow"
        );
    }
}
