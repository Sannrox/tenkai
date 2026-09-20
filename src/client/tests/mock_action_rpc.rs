use std::future::Future;
use std::pin::Pin;

use super::mock_state::{MockSekaiState, mock_now_ms};
use crate::pb::sekai::{
    ActionInstance, GetGovernedActionTypeRequest, GetGovernedActionTypeResponse,
    ListActionPoliciesRequest, ListActionPoliciesResponse, ListDecisionsRequest,
    ListDecisionsResponse, PutGovernedActionTypeRequest, PutGovernedActionTypeResponse,
    RecordDecisionRequest, RecordDecisionResponse, SubmitActionInstanceRequest,
    SubmitActionInstanceResponse,
};

pub(super) struct PutGovernedActionTypeRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<PutGovernedActionTypeRequest> for PutGovernedActionTypeRpc {
    type Response = PutGovernedActionTypeResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<PutGovernedActionTypeRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let principal = request
                .metadata()
                .get("x-principal")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let authorization = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            state
                .metadata
                .lock()
                .unwrap()
                .push((principal, authorization));
            let mut action = request.into_inner().r#type.unwrap_or_default();
            if action.created_at_ms == 0 {
                action.created_at_ms = mock_now_ms();
            }
            action.enabled = true;
            state.governed_actions.lock().unwrap().push(action.clone());
            Ok(tonic::Response::new(PutGovernedActionTypeResponse {
                r#type: Some(action),
            }))
        })
    }
}

pub(super) struct GetGovernedActionTypeRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<GetGovernedActionTypeRequest> for GetGovernedActionTypeRpc {
    type Response = GetGovernedActionTypeResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<GetGovernedActionTypeRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let request = request.into_inner();
            let action = state
                .governed_actions
                .lock()
                .unwrap()
                .iter()
                .find(|candidate| {
                    candidate.namespace == request.namespace
                        && candidate.type_id == request.type_id
                        && candidate.version == request.version
                })
                .cloned()
                .ok_or_else(|| tonic::Status::not_found("governed action type not found"))?;
            Ok(tonic::Response::new(GetGovernedActionTypeResponse {
                r#type: Some(action),
            }))
        })
    }
}

pub(super) struct ListActionPoliciesRpc;

impl tonic::server::UnaryService<ListActionPoliciesRequest> for ListActionPoliciesRpc {
    type Response = ListActionPoliciesResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<ListActionPoliciesRequest>) -> Self::Future {
        Box::pin(async move {
            let _ = request;
            Ok(tonic::Response::new(ListActionPoliciesResponse {
                policies: Vec::new(),
            }))
        })
    }
}

pub(super) struct SubmitActionInstanceRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<SubmitActionInstanceRequest> for SubmitActionInstanceRpc {
    type Response = SubmitActionInstanceResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<SubmitActionInstanceRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let request = request.into_inner();
            let exists = state.governed_actions.lock().unwrap().iter().any(|action| {
                action.namespace == request.namespace
                    && action.type_id == request.type_id
                    && action.version == request.version
                    && action.enabled
            });
            if !exists {
                return Err(tonic::Status::failed_precondition(
                    "governed action type missing or disabled",
                ));
            }
            let now = mock_now_ms();
            Ok(tonic::Response::new(SubmitActionInstanceResponse {
                instance: Some(ActionInstance {
                    instance_id: uuid::Uuid::new_v4().to_string(),
                    namespace: request.namespace,
                    type_id: request.type_id,
                    version: request.version,
                    principal: "remote-mock".into(),
                    parameters_json: request.parameters_json,
                    request_digest: "sha256:mock".into(),
                    idempotency_key: request.idempotency_key,
                    operation_id: uuid::Uuid::new_v4().to_string(),
                    status: "admitted".into(),
                    deny_reason: String::new(),
                    evidence_submission_ids: request.evidence_submission_ids,
                    policy_decision: "allow".into(),
                    budget_decision: "not_configured".into(),
                    created_at_ms: now,
                    decided_at_ms: now,
                }),
                replay: false,
            }))
        })
    }
}

pub(super) struct RecordDecisionRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<RecordDecisionRequest> for RecordDecisionRpc {
    type Response = RecordDecisionResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<RecordDecisionRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let principal = request
                .metadata()
                .get("x-principal")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("remote-mock")
                .to_owned();
            let mut decision = request
                .into_inner()
                .decision
                .ok_or_else(|| tonic::Status::invalid_argument("decision required"))?;
            decision.actor = principal;
            if decision.timestamp <= 0 {
                decision.timestamp = mock_now_ms();
            }
            state.decisions.lock().unwrap().push(decision.clone());
            Ok(tonic::Response::new(RecordDecisionResponse {
                decision: Some(decision),
            }))
        })
    }
}

pub(super) struct ListDecisionsRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<ListDecisionsRequest> for ListDecisionsRpc {
    type Response = ListDecisionsResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<ListDecisionsRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let request = request.into_inner();
            let decisions = state
                .decisions
                .lock()
                .unwrap()
                .iter()
                .filter(|decision| {
                    (request.actor.is_empty() || decision.actor == request.actor)
                        && (request.action.is_empty() || decision.action == request.action)
                        && decision.timestamp > request.after
                })
                .cloned()
                .collect();
            Ok(tonic::Response::new(ListDecisionsResponse { decisions }))
        })
    }
}
