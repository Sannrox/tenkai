//! Governed action lifecycle semantics across embedded and remote adapters.

use anyhow::{Context as _, Result};
use prost::Message;
use sekai_client::CallOptions;

use super::{RemoteClient, sdk_error_status};
use crate::pb::sekai::{
    ActionRequest, ActionResult, ActionTypeDef, CreateActionTypeRequest, CreateActionTypeResponse,
    Decision, DenyActionRequest, DenyActionResponse, ExecuteActionRequest, ExecuteActionResponse,
    ListActionTypesRequest, ListActionTypesResponse, ListDecisionsRequest, ListDecisionsResponse,
};

pub(super) enum ActionLifecycle<'a> {
    Remote(&'a RemoteClient),
    Embedded(&'a crate::embedded::EmbeddedStore),
}

impl ActionLifecycle<'_> {
    pub(super) async fn register(
        &self,
        action: ActionTypeDef,
    ) -> std::result::Result<(), tonic::Status> {
        match self {
            Self::Embedded(store) => store.register_action(action),
            Self::Remote(client) => {
                let action_name = action.name.clone();
                let response: std::result::Result<CreateActionTypeResponse, tonic::Status> =
                    remote_unary(
                        client,
                        "/sekai.SekaiService/CreateActionType",
                        CreateActionTypeRequest {
                            action_type: Some(action),
                        },
                    )
                    .await;
                let response = match response {
                    Ok(response) => response,
                    Err(status)
                        if status.code() == tonic::Code::Internal
                            && remote_action_exists(client, &action_name).await =>
                    {
                        return Err(tonic::Status::already_exists("action type already exists"));
                    }
                    Err(status) => return Err(status),
                };
                if response.action_type.is_none() {
                    return Err(tonic::Status::internal(
                        "Sekai CreateActionType returned no action_type",
                    ));
                }
                Ok(())
            }
        }
    }

    pub(super) async fn execute(
        &self,
        action: &str,
        params: std::collections::HashMap<String, String>,
        dry_run: bool,
    ) -> Result<ActionResult> {
        match self {
            Self::Embedded(store) => store.execute_action(action, params, dry_run),
            Self::Remote(client) => {
                let response: ExecuteActionResponse = remote_unary(
                    client,
                    "/sekai.SekaiService/ExecuteAction",
                    ExecuteActionRequest {
                        request: Some(ActionRequest {
                            action: action.into(),
                            params,
                            actor: String::new(),
                        }),
                        dry_run,
                    },
                )
                .await?;
                response
                    .result
                    .context("governed action returned no result")
            }
        }
    }

    pub(super) async fn deny(&self, approval_id: &str, reason: &str) -> Result<()> {
        match self {
            Self::Embedded(_) => anyhow::bail!(
                "embedded mode has no deferred approvals; action {approval_id} cannot be denied"
            ),
            Self::Remote(client) => {
                let _: DenyActionResponse = remote_unary(
                    client,
                    "/sekai.SekaiService/DenyAction",
                    DenyActionRequest {
                        approval_id: approval_id.into(),
                        reason: reason.into(),
                    },
                )
                .await?;
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
            Self::Remote(client) => {
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

async fn remote_action_exists(client: &RemoteClient, name: &str) -> bool {
    let response: std::result::Result<ListActionTypesResponse, tonic::Status> = remote_unary(
        client,
        "/sekai.SekaiService/ListActionTypes",
        ListActionTypesRequest {},
    )
    .await;
    response.is_ok_and(|response| {
        response
            .action_types
            .iter()
            .any(|action| action.name == name)
    })
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
