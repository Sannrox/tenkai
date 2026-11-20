//! Object lifecycle semantics across embedded and remote adapters.

use anyhow::Result;
use sekai_client::CallOptions;
use std::sync::Arc;

use super::{
    RemoteClient, canonical_create_request, canonical_update_request, remote_unary,
    remote_unary_with_options,
};
use crate::pb::sekai::{
    CreateObjectResponse, DeleteObjectRequest, DeleteObjectResponse, GetObjectRequest,
    GetObjectResponse, ListObjectChangesRequest, ListObjectChangesResponse, Object,
    UpdateObjectResponse,
};

pub(super) enum ObjectLifecycle<'a> {
    Remote(&'a RemoteClient),
    Catalog {
        catalog: Arc<dyn crate::storage::CatalogGraph>,
        tenant: Option<String>,
    },
    /// A tenant hub without a usable catalog binding. `tenant_unbound` is a
    /// hub that has a catalog but no tenant yet: its reads fail with
    /// [`super::TENANT_NOT_BOUND`] instead of looking like an empty catalog.
    Unavailable {
        tenant_unbound: bool,
    },
}

impl ObjectLifecycle<'_> {
    pub(super) async fn get(&self, id: &str) -> Result<Option<Object>> {
        match self {
            Self::Unavailable {
                tenant_unbound: true,
            } => anyhow::bail!(super::TENANT_NOT_BOUND),
            Self::Unavailable { .. } => Ok(None),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let id = id.to_string();
                super::block_catalog(catalog, move |catalog| catalog.get(tenant.as_deref(), &id))
                    .await
            }
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
    ) -> std::result::Result<Object, super::ClientError> {
        match self {
            Self::Unavailable { .. } => Err(super::ClientError::Failed(anyhow::anyhow!(
                super::TENANT_HUB_UNAVAILABLE
            ))),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                super::block_catalog_status(catalog, move |catalog| {
                    catalog.create(tenant.as_deref(), object)
                })
                .await
            }
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
                        return Err(super::ClientError::UniqueConflict);
                    }
                    Err(status) => return Err(status.into()),
                };
                Ok(response.object.unwrap_or_default())
            }
        }
    }

    pub(super) async fn delete(&self, id: &str) -> Result<()> {
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let id = id.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.delete(tenant.as_deref(), &id)
                })
                .await
            }
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
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                super::block_catalog(catalog, move |catalog| {
                    catalog.put(tenant.as_deref(), object)
                })
                .await
            }
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
