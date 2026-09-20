use std::future::Future;
use std::pin::Pin;

use super::mock_state::{MockSekaiState, mock_lease_key, mock_now_ms};
use crate::pb::sekai::{
    AcquireLeaseRequest, AcquireLeaseResponse, GetLeaseRequest, GetLeaseResponse, Lease,
    RefreshLeaseRequest, RefreshLeaseResponse, ReleaseLeaseRequest, ReleaseLeaseResponse,
    TakeoverExpiredLeaseRequest, TakeoverExpiredLeaseResponse,
};

pub(super) struct AcquireLeaseRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<AcquireLeaseRequest> for AcquireLeaseRpc {
    type Response = AcquireLeaseResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<AcquireLeaseRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let request = request.into_inner();
            if request.ttl_ms <= 0 {
                return Err(tonic::Status::invalid_argument("ttl_ms must be positive"));
            }
            let now = mock_now_ms();
            let key = mock_lease_key(&request.namespace, &request.key);
            let mut leases = state.leases.lock().unwrap();
            if let Some(current) = leases.get(&key)
                && current.status == "active"
                && current.expires_at_ms > now
            {
                return Err(tonic::Status::already_exists(format!(
                    "lease {}/{} is held by {}",
                    request.namespace, request.key, current.owner
                )));
            }
            let generation = leases
                .get(&key)
                .map_or(1, |lease| lease.generation.saturating_add(1));
            let lease = Lease {
                namespace: request.namespace,
                key: request.key,
                generation,
                fencing_token: uuid::Uuid::new_v4().to_string(),
                owner: request.owner,
                status: "active".into(),
                acquired_at_ms: now,
                refreshed_at_ms: now,
                expires_at_ms: now.saturating_add(request.ttl_ms),
                released_at_ms: 0,
                site_id: String::new(),
            };
            leases.insert(key, lease.clone());
            Ok(tonic::Response::new(AcquireLeaseResponse {
                lease: Some(lease),
            }))
        })
    }
}

pub(super) struct GetLeaseRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<GetLeaseRequest> for GetLeaseRpc {
    type Response = GetLeaseResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<GetLeaseRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let request = request.into_inner();
            let key = mock_lease_key(&request.namespace, &request.key);
            match state.leases.lock().unwrap().get(&key).cloned() {
                Some(lease) => Ok(tonic::Response::new(GetLeaseResponse {
                    lease: Some(lease),
                })),
                None => Err(tonic::Status::not_found("lease not found")),
            }
        })
    }
}

pub(super) struct RefreshLeaseRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<RefreshLeaseRequest> for RefreshLeaseRpc {
    type Response = RefreshLeaseResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<RefreshLeaseRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let request = request.into_inner();
            let key = mock_lease_key(&request.namespace, &request.key);
            let mut leases = state.leases.lock().unwrap();
            let Some(lease) = leases.get_mut(&key) else {
                return Err(tonic::Status::not_found("lease not found"));
            };
            if lease.status != "active" || lease.fencing_token != request.fencing_token {
                return Err(tonic::Status::failed_precondition("lease refresh rejected"));
            }
            let now = mock_now_ms();
            lease.refreshed_at_ms = now;
            lease.expires_at_ms = now.saturating_add(request.ttl_ms);
            Ok(tonic::Response::new(RefreshLeaseResponse {
                lease: Some(lease.clone()),
            }))
        })
    }
}

pub(super) struct ReleaseLeaseRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<ReleaseLeaseRequest> for ReleaseLeaseRpc {
    type Response = ReleaseLeaseResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<ReleaseLeaseRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let request = request.into_inner();
            let key = mock_lease_key(&request.namespace, &request.key);
            let mut leases = state.leases.lock().unwrap();
            let Some(lease) = leases.get_mut(&key) else {
                return Err(tonic::Status::not_found("lease not found"));
            };
            if lease.status != "active" || lease.fencing_token != request.fencing_token {
                return Err(tonic::Status::failed_precondition("lease release rejected"));
            }
            lease.status = "released".into();
            lease.released_at_ms = mock_now_ms();
            Ok(tonic::Response::new(ReleaseLeaseResponse {
                lease: Some(lease.clone()),
            }))
        })
    }
}

pub(super) struct TakeoverExpiredLeaseRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<TakeoverExpiredLeaseRequest> for TakeoverExpiredLeaseRpc {
    type Response = TakeoverExpiredLeaseResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<TakeoverExpiredLeaseRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let request = request.into_inner();
            if request.ttl_ms <= 0 {
                return Err(tonic::Status::invalid_argument("ttl_ms must be positive"));
            }
            let key = mock_lease_key(&request.namespace, &request.key);
            let mut leases = state.leases.lock().unwrap();
            let Some(current) = leases.get(&key).cloned() else {
                return Err(tonic::Status::not_found("lease not found"));
            };
            let now = mock_now_ms();
            if current.fencing_token != request.expected_fencing_token
                || current.expires_at_ms != request.expected_expires_at_ms
                || current.expires_at_ms > now
            {
                return Err(tonic::Status::failed_precondition(
                    "lease takeover precondition failed",
                ));
            }
            let lease = Lease {
                namespace: request.namespace,
                key: request.key,
                generation: current.generation.saturating_add(1),
                fencing_token: uuid::Uuid::new_v4().to_string(),
                owner: request.owner,
                status: "active".into(),
                acquired_at_ms: now,
                refreshed_at_ms: now,
                expires_at_ms: now.saturating_add(request.ttl_ms),
                released_at_ms: 0,
                site_id: String::new(),
            };
            leases.insert(key, lease.clone());
            Ok(tonic::Response::new(TakeoverExpiredLeaseResponse {
                lease: Some(lease),
            }))
        })
    }
}
