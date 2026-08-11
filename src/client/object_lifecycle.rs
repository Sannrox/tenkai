//! Object lifecycle semantics across embedded and remote adapters.

use anyhow::Result;
use prost::Message;
use sekai_client::CallOptions;

use super::{RemoteClient, canonical_create_request, canonical_update_request, sdk_error_status};
use crate::pb::sekai::{
    CreateObjectResponse, DeleteObjectRequest, DeleteObjectResponse, GetObjectRequest,
    GetObjectResponse, ListObjectChangesRequest, ListObjectChangesResponse, Object,
    UpdateObjectResponse,
};

pub(super) enum ObjectLifecycle<'a> {
    Remote(&'a RemoteClient),
    Embedded(&'a crate::embedded::EmbeddedStore),
}

impl ObjectLifecycle<'_> {
    pub(super) async fn get(&self, id: &str) -> Result<Option<Object>> {
        match self {
            Self::Embedded(store) => store.get(id),
            Self::Remote(client) => {
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
        }
    }

    pub(super) async fn create_once(
        &self,
        object: Object,
    ) -> std::result::Result<Object, tonic::Status> {
        match self {
            Self::Embedded(store) => store.create(object),
            Self::Remote(client) => {
                let object_id = object.id.clone();
                let response: std::result::Result<CreateObjectResponse, tonic::Status> =
                    remote_unary_with_options(
                        client,
                        "/sekai.SekaiService/CreateObject",
                        canonical_create_request(object, None),
                        CallOptions::default(),
                    )
                    .await;
                let response = match response {
                    Ok(response) => response,
                    Err(status)
                        if status.code() == tonic::Code::Internal
                            && remote_object_conflict(client, &object_id).await =>
                    {
                        return Err(tonic::Status::already_exists("object already exists"));
                    }
                    Err(status) => return Err(status),
                };
                Ok(response.object.unwrap_or_default())
            }
        }
    }

    pub(super) async fn delete(&self, id: &str) -> Result<()> {
        match self {
            Self::Embedded(store) => store.delete(id),
            Self::Remote(client) => {
                let _: DeleteObjectResponse = remote_unary(
                    client,
                    "/sekai.SekaiService/DeleteObject",
                    DeleteObjectRequest {
                        id: id.into(),
                        lease_precondition: None,
                    },
                )
                .await?;
                Ok(())
            }
        }
    }

    pub(super) async fn put(&self, object: Object) -> Result<Object> {
        match self {
            Self::Embedded(store) => store.put(object),
            Self::Remote(client) => {
                let existing: std::result::Result<GetObjectResponse, tonic::Status> = remote_unary(
                    client,
                    "/sekai.SekaiService/GetObject",
                    GetObjectRequest {
                        id: object.id.clone(),
                    },
                )
                .await;
                let exists = match existing {
                    Ok(response) => response.object.is_some(),
                    Err(status) if status.code() == tonic::Code::NotFound => false,
                    Err(status) => return Err(status.into()),
                };
                if exists {
                    let response: UpdateObjectResponse = remote_unary(
                        client,
                        "/sekai.SekaiService/UpdateObject",
                        canonical_update_request(object, None),
                    )
                    .await?;
                    Ok(response.object.unwrap_or_default())
                } else {
                    let response: CreateObjectResponse = remote_unary(
                        client,
                        "/sekai.SekaiService/CreateObject",
                        canonical_create_request(object, None),
                    )
                    .await?;
                    Ok(response.object.unwrap_or_default())
                }
            }
        }
    }
}

async fn remote_object_conflict(client: &RemoteClient, id: &str) -> bool {
    let object: std::result::Result<GetObjectResponse, tonic::Status> = remote_unary(
        client,
        "/sekai.SekaiService/GetObject",
        GetObjectRequest { id: id.into() },
    )
    .await;
    match object {
        Ok(response) => response.object.is_some(),
        Err(status) if status.code() == tonic::Code::NotFound => {
            let changes: std::result::Result<ListObjectChangesResponse, tonic::Status> =
                remote_unary(
                    client,
                    "/sekai.SekaiService/ListObjectChanges",
                    ListObjectChangesRequest {
                        object_id: id.into(),
                        limit: 1,
                        offset: 0,
                    },
                )
                .await;
            changes.is_ok_and(|response| !response.changes.is_empty())
        }
        Err(_) => false,
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
