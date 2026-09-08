//! Lease lifecycle semantics across embedded and remote adapters.

use anyhow::{Context as _, Result};
use prost::Message;
use sekai_client::CallOptions;
use std::sync::Arc;

use super::{RemoteClient, sdk_error_status};
use crate::pb::sekai::{
    AcquireLeaseRequest, AcquireLeaseResponse, GetLeaseRequest, GetLeaseResponse, Lease,
    RefreshLeaseRequest, RefreshLeaseResponse, ReleaseLeaseRequest, ReleaseLeaseResponse,
    TakeoverExpiredLeaseRequest, TakeoverExpiredLeaseResponse,
};

pub(super) enum LeaseLifecycle<'a> {
    Remote(&'a RemoteClient),
    Embedded(Arc<crate::embedded::EmbeddedStore>),
}

impl LeaseLifecycle<'_> {
    pub(super) async fn acquire(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        match self {
            Self::Embedded(store) => {
                let store = Arc::clone(store);
                let namespace = namespace.to_string();
                let key = key.to_string();
                let owner = owner.to_string();
                super::block_embedded(store, move |store| {
                    store.acquire_lease(&namespace, &key, &owner, ttl_ms)
                })
                .await
            }
            Self::Remote(client) => {
                let request_id = uuid::Uuid::new_v4().to_string();
                let response: AcquireLeaseResponse = remote_unary_with_options(
                    client,
                    "/sekai.SekaiService/AcquireLease",
                    AcquireLeaseRequest {
                        namespace: namespace.into(),
                        key: key.into(),
                        owner: owner.into(),
                        ttl_ms,
                        request_id: request_id.clone(),
                    },
                    CallOptions::default().with_request_id(request_id),
                )
                .await?;
                response.lease.context("provider returned an empty lease")
            }
        }
    }

    pub(super) async fn get(&self, namespace: &str, key: &str) -> Result<Option<Lease>> {
        match self {
            Self::Embedded(store) => {
                let store = Arc::clone(store);
                let namespace = namespace.to_string();
                let key = key.to_string();
                super::block_embedded(store, move |store| store.get_lease(&namespace, &key)).await
            }
            Self::Remote(client) => {
                let response: std::result::Result<GetLeaseResponse, tonic::Status> = remote_unary(
                    client,
                    "/sekai.SekaiService/GetLease",
                    GetLeaseRequest {
                        namespace: namespace.into(),
                        key: key.into(),
                    },
                )
                .await;
                match response {
                    Ok(response) => Ok(response.lease),
                    Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
                    Err(status) => Err(status.into()),
                }
            }
        }
    }

    pub(super) async fn refresh(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        match self {
            Self::Embedded(store) => {
                let store = Arc::clone(store);
                let namespace = namespace.to_string();
                let key = key.to_string();
                let fencing_token = fencing_token.to_string();
                super::block_embedded(store, move |store| {
                    store.refresh_lease(&namespace, &key, &fencing_token, ttl_ms)
                })
                .await
            }
            Self::Remote(client) => {
                let request_id = uuid::Uuid::new_v4().to_string();
                let response: RefreshLeaseResponse = remote_unary_with_options(
                    client,
                    "/sekai.SekaiService/RefreshLease",
                    RefreshLeaseRequest {
                        namespace: namespace.into(),
                        key: key.into(),
                        fencing_token: fencing_token.into(),
                        ttl_ms,
                        request_id: request_id.clone(),
                    },
                    CallOptions::default().with_request_id(request_id),
                )
                .await?;
                response
                    .lease
                    .context("provider returned an empty refreshed lease")
            }
        }
    }

    pub(super) async fn release(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> Result<Lease> {
        match self {
            Self::Embedded(store) => {
                let store = Arc::clone(store);
                let namespace = namespace.to_string();
                let key = key.to_string();
                let fencing_token = fencing_token.to_string();
                super::block_embedded(store, move |store| {
                    store.release_lease(&namespace, &key, &fencing_token)
                })
                .await
            }
            Self::Remote(client) => {
                let request_id = uuid::Uuid::new_v4().to_string();
                let response: ReleaseLeaseResponse = remote_unary_with_options(
                    client,
                    "/sekai.SekaiService/ReleaseLease",
                    ReleaseLeaseRequest {
                        namespace: namespace.into(),
                        key: key.into(),
                        fencing_token: fencing_token.into(),
                        request_id: request_id.clone(),
                    },
                    CallOptions::default().with_request_id(request_id),
                )
                .await?;
                response
                    .lease
                    .context("provider returned an empty released lease")
            }
        }
    }

    pub(super) async fn takeover(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_fencing_token: &str,
        expected_expires_at_ms: i64,
        ttl_ms: i64,
    ) -> Result<Lease> {
        match self {
            Self::Embedded(store) => {
                let store = Arc::clone(store);
                let namespace = namespace.to_string();
                let key = key.to_string();
                let owner = owner.to_string();
                let expected_fencing_token = expected_fencing_token.to_string();
                super::block_embedded(store, move |store| {
                    store.takeover_lease(
                        &namespace,
                        &key,
                        &owner,
                        &expected_fencing_token,
                        expected_expires_at_ms,
                        ttl_ms,
                    )
                })
                .await
            }
            Self::Remote(client) => {
                let request_id = uuid::Uuid::new_v4().to_string();
                let response: TakeoverExpiredLeaseResponse = remote_unary_with_options(
                    client,
                    "/sekai.SekaiService/TakeoverExpiredLease",
                    TakeoverExpiredLeaseRequest {
                        namespace: namespace.into(),
                        key: key.into(),
                        owner: owner.into(),
                        expected_fencing_token: expected_fencing_token.into(),
                        expected_expires_at_ms,
                        ttl_ms,
                        request_id: request_id.clone(),
                    },
                    CallOptions::default().with_request_id(request_id),
                )
                .await?;
                response
                    .lease
                    .context("provider returned an empty takeover lease")
            }
        }
    }
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
    remote_unary_with_options(client, path, request, CallOptions::default()).await
}

async fn remote_unary_with_options<Req, Resp>(
    client: &RemoteClient,
    path: &str,
    request: Req,
    options: CallOptions,
) -> std::result::Result<Resp, tonic::Status>
where
    Req: Message + Default + Clone + Send + 'static,
    Resp: Message + Default + Send + 'static,
{
    client
        .raw()
        .unary(path, request, options)
        .await
        .map_err(sdk_error_status)
}
