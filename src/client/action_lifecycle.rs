//! Governed action lifecycle semantics across embedded and remote adapters.
//!
//! Embedded Tenkai keeps a local graph-action definition store and applies the
//! Tenkai-owned mutation DSL in-process. Remote Tenkai registers
//! `GovernedActionType` records and admits work through `SubmitActionInstance`,
//! then applies the same mutation plan through ordinary graph RPCs after
//! admission. Missing, disabled, denied, or unauthorized definitions fail closed.

use anyhow::{Context as _, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::action_governed::{
    governed_action_type, idempotency_key, map_instance_decision, parameters_json,
    resolve_remote_action_def,
};
use super::action_remote::{
    apply_remote_ops, ensure_remote_type_enabled, preview_remote_decision,
    record_remote_execution_decision, remote_governed_action_exists,
};
use super::{RemoteClient, remote_unary};
use crate::pb::graph_action::{ActionResult, ActionTypeDef};
use crate::pb::sekai::{
    Decision, ListDecisionsRequest, ListDecisionsResponse, PutGovernedActionTypeRequest,
    PutGovernedActionTypeResponse, SubmitActionInstanceRequest, SubmitActionInstanceResponse,
};

pub(super) const GOVERNED_ACTION_NAMESPACE: &str = "tenkai";
pub(super) const GOVERNED_ACTION_VERSION: &str = "1";

pub(super) type RemoteActionDefs = Arc<Mutex<HashMap<String, ActionTypeDef>>>;

pub(super) enum ActionLifecycle<'a> {
    Remote {
        client: &'a RemoteClient,
        action_defs: &'a RemoteActionDefs,
    },
    Embedded(Arc<crate::storage::SqliteStore>),
}

impl ActionLifecycle<'_> {
    pub(super) async fn register(
        &self,
        action: ActionTypeDef,
    ) -> std::result::Result<(), tonic::Status> {
        match self {
            Self::Embedded(store) => {
                let store = Arc::clone(store);
                super::block_embedded_status(store, move |store| store.register_action(action))
                    .await
            }
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
            Self::Embedded(store) => {
                let store = Arc::clone(store);
                let action = action.to_string();
                super::block_embedded(store, move |store| {
                    store.execute_action(&action, params, dry_run)
                })
                .await
            }
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
            Self::Embedded(store) => {
                let store = Arc::clone(store);
                let actor = actor.to_string();
                let action = action.to_string();
                super::block_embedded(store, move |store| store.decisions(&actor, &action, after))
                    .await
            }
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
