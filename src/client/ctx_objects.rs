//! Object create, update, delete, and fenced write methods on `Ctx`.

use anyhow::{Context as _, Result};

use sekai_client::CallOptions;

use super::{
    Ctx, block_embedded, canonical_create_request, canonical_update_request, lease_precondition,
};
use crate::pb::sekai::{CreateObjectResponse, Object, UpdateObjectResponse};

impl Ctx {
    /// Get an object by id; `None` on not-found.
    pub async fn get(&mut self, id: &str) -> Result<Option<Object>> {
        self.backend.object_lifecycle().get(id).await
    }

    /// Create an object without falling back to update when its id exists.
    pub async fn create_once(
        &mut self,
        object: Object,
    ) -> std::result::Result<Object, tonic::Status> {
        self.backend.object_lifecycle().create_once(object).await
    }

    pub async fn delete(&mut self, id: &str) -> Result<()> {
        self.backend.object_lifecycle().delete(id).await
    }

    /// Create the object, or update it if the id already exists.
    pub async fn put(&mut self, object: Object) -> Result<Object> {
        self.backend.object_lifecycle().put(object).await
    }

    pub(crate) async fn put_with_provider_events(
        &mut self,
        object: Object,
        events: &[crate::storage::ProviderEventRecord],
    ) -> Result<Object> {
        if events.is_empty() {
            return self.put(object).await;
        }
        let Some(store) = self.embedded_arc() else {
            anyhow::bail!(
                "remote application state cannot atomically enqueue Tenkai provider events"
            );
        };
        let events = events.to_vec();
        block_embedded(store, move |store| {
            store.put_with_provider_events(object, &events)
        })
        .await
    }

    pub(crate) async fn put_objects_with_provider_events(
        &mut self,
        objects: &[Object],
        events: &[crate::storage::ProviderEventRecord],
    ) -> Result<()> {
        let Some(store) = self.embedded_arc() else {
            anyhow::bail!(
                "remote application state cannot atomically update objects and enqueue Tenkai provider events"
            );
        };
        let objects = objects.to_vec();
        let events = events.to_vec();
        block_embedded(store, move |store| {
            store.put_objects_with_provider_events(&objects, &events)
        })
        .await
    }

    pub(crate) async fn guarded_create(
        &mut self,
        object: Object,
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
    ) -> Result<Object> {
        if let Some(store) = self.embedded_arc() {
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return block_embedded(store, move |store| {
                store.guarded_put(object, &lease_namespace, &lease_key, &fencing_token, true)
            })
            .await;
        }
        let request = canonical_create_request(
            object,
            Some(lease_precondition(
                lease_namespace,
                lease_key,
                fencing_token,
            )),
        );
        let request_id = request
            .lease_precondition
            .as_ref()
            .map(|precondition| precondition.request_id.clone());
        let mut options = CallOptions::default().retryable(true);
        if let Some(request_id) = request_id {
            options = options.with_request_id(request_id);
        }
        let response: CreateObjectResponse = self
            .remote_unary("/sekai.SekaiService/CreateObject", request, options)
            .await?;
        response
            .object
            .context("Sekai returned an empty canonical create result")
    }

    pub(crate) async fn guarded_update(
        &mut self,
        object: Object,
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
    ) -> Result<Object> {
        if let Some(store) = self.embedded_arc() {
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return block_embedded(store, move |store| {
                store.guarded_put(object, &lease_namespace, &lease_key, &fencing_token, false)
            })
            .await;
        }
        let request = canonical_update_request(
            object,
            Some(lease_precondition(
                lease_namespace,
                lease_key,
                fencing_token,
            )),
        );
        let request_id = request
            .lease_precondition
            .as_ref()
            .map(|precondition| precondition.request_id.clone());
        let mut options = CallOptions::default().retryable(true);
        if let Some(request_id) = request_id {
            options = options.with_request_id(request_id);
        }
        let response: UpdateObjectResponse = self
            .remote_unary("/sekai.SekaiService/UpdateObject", request, options)
            .await?;
        response
            .object
            .context("Sekai returned an empty canonical update result")
    }

    pub(crate) async fn guarded_update_objects_with_provider_events(
        &mut self,
        objects: &[Object],
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
        events: &[crate::storage::ProviderEventRecord],
    ) -> Result<()> {
        let Some(store) = self.embedded_arc() else {
            anyhow::bail!(
                "remote application state cannot atomically update objects and enqueue Tenkai provider events"
            );
        };
        let objects = objects.to_vec();
        let lease_namespace = lease_namespace.to_string();
        let lease_key = lease_key.to_string();
        let fencing_token = fencing_token.to_string();
        let events = events.to_vec();
        block_embedded(store, move |store| {
            store.guarded_put_objects_with_provider_events(
                &objects,
                &lease_namespace,
                &lease_key,
                &fencing_token,
                &events,
            )
        })
        .await
    }
}
