//! Object create, update, delete, and fenced write methods on `Ctx`.

use std::collections::HashMap;

use anyhow::{Context as _, Result, ensure};

use sekai_client::CallOptions;

use super::{
    Ctx, block_embedded, canonical_create_request, canonical_update_request, lease_precondition,
};
use crate::pb::sekai::{CreateObjectResponse, Lease, Object, UpdateObjectResponse};
use crate::storage::LeaseRefresh;

impl Ctx {
    fn with_feedback_export_events(
        &self,
        events: &[crate::storage::ProviderEventRecord],
        observations: &[crate::feedback_observation::FeedbackObservation],
    ) -> Vec<crate::storage::ProviderEventRecord> {
        if !self.feedback_export_enabled()
            || observations.is_empty()
            || (self.embedded_arc().is_none() && !self.has_catalog())
        {
            return events.to_vec();
        }
        let mut events = events.to_vec();
        events.extend(crate::feedback_export::records_for_observations(
            observations,
        ));
        events
    }

    /// Sekai export when enabled, plus opt-in `feedback.observation` webhooks.
    /// Lookup failures skip the webhook; they never fail the capture write.
    async fn with_observation_delivery_events(
        &mut self,
        events: &[crate::storage::ProviderEventRecord],
        observations: &[crate::feedback_observation::FeedbackObservation],
    ) -> Vec<crate::storage::ProviderEventRecord> {
        let mut events = self.with_feedback_export_events(events, observations);
        events.extend(self.feedback_webhook_records(observations).await);
        events
    }

    async fn feedback_webhook_records(
        &mut self,
        observations: &[crate::feedback_observation::FeedbackObservation],
    ) -> Vec<crate::storage::ProviderEventRecord> {
        if observations.is_empty() || (self.embedded_arc().is_none() && !self.has_catalog()) {
            return Vec::new();
        }
        let mut endpoints_by_env: HashMap<String, Vec<crate::deploy_webhook::WebhookEndpoint>> =
            HashMap::new();
        let mut records = Vec::new();
        for observation in observations {
            let environment = observation.environment.as_str();
            if environment.is_empty() {
                continue;
            }
            if !endpoints_by_env.contains_key(environment) {
                let endpoints = match self.get(&crate::ontology::env_id(environment)).await {
                    Ok(Some(object)) => crate::deploy_webhook::configured_endpoints(&object),
                    _ => Vec::new(),
                };
                endpoints_by_env.insert(environment.to_owned(), endpoints);
            }
            let Some(endpoints) = endpoints_by_env.get(environment) else {
                continue;
            };
            records.extend(crate::feedback_webhook::records_for_observation(
                endpoints,
                observation,
            ));
        }
        records
    }

    /// Get an object by id; `None` on not-found.
    pub async fn get(&mut self, id: &str) -> Result<Option<Object>> {
        self.backend.object_lifecycle().get(id).await
    }

    /// Create an object without falling back to update when its id exists.
    pub async fn create_once(
        &mut self,
        object: Object,
    ) -> std::result::Result<Object, super::ClientError> {
        self.backend.object_lifecycle().create_once(object).await
    }

    pub async fn delete(&mut self, id: &str) -> Result<()> {
        self.backend.object_lifecycle().delete(id).await
    }

    /// Create the object, or update it if the id already exists.
    pub async fn put(&mut self, object: Object) -> Result<Object> {
        self.backend.object_lifecycle().put(object).await
    }

    /// Write `object` with `events` and feedback `observations` atomically,
    /// on the embedded store or the tenant's catalog partition (#868).
    /// Remote application state has no observation store: there the
    /// observations are dropped and the write goes ahead (#802).
    pub(crate) async fn put_with_provider_events(
        &mut self,
        object: Object,
        events: &[crate::storage::ProviderEventRecord],
        observations: &[crate::feedback_observation::FeedbackObservation],
    ) -> Result<Object> {
        let events = self
            .with_observation_delivery_events(events, observations)
            .await;
        if let Some((catalog, Some(tenant))) = self.catalog_binding() {
            if events.is_empty() && observations.is_empty() {
                return self.put(object).await;
            }
            let observations = observations.to_vec();
            return super::block_catalog(catalog, move |catalog| {
                catalog.put_with_provider_events(Some(&tenant), object, &events, &observations)
            })
            .await;
        }
        let Some(store) = self.embedded_arc() else {
            if events.is_empty() {
                return self.put(object).await;
            }
            anyhow::bail!(
                "remote application state cannot atomically enqueue Tenkai provider events"
            );
        };
        if events.is_empty() && observations.is_empty() {
            return self.put(object).await;
        }
        let observations = observations.to_vec();
        block_embedded(store, move |store| {
            store.put_with_provider_events(object, &events, &observations)
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
        if let Some((catalog, Some(tenant))) = self.catalog_binding() {
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return super::block_catalog(catalog, move |catalog| {
                catalog.guarded_put(
                    Some(&tenant),
                    object,
                    &lease_namespace,
                    &lease_key,
                    &fencing_token,
                    true,
                )
            })
            .await;
        }
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

    /// Refresh every lease in `refreshes` in one store transaction where
    /// the backend has one. A lease with `extend` is renewed; the rest must
    /// still be held.
    pub(crate) async fn refresh_leases(
        &mut self,
        refreshes: Vec<LeaseRefresh>,
    ) -> Result<Vec<Lease>> {
        if let Some((catalog, Some(tenant))) = self.catalog_binding() {
            return super::block_catalog(catalog, move |catalog| {
                catalog.refresh_leases(Some(&tenant), &refreshes)
            })
            .await;
        }
        if let Some(store) = self.embedded_arc() {
            return block_embedded(store, move |store| store.refresh_leases(&refreshes)).await;
        }
        let mut leases = Vec::with_capacity(refreshes.len());
        for refresh in &refreshes {
            if refresh.extend {
                leases.push(
                    self.refresh_lease(
                        &refresh.namespace,
                        &refresh.key,
                        &refresh.fencing_token,
                        refresh.ttl_ms,
                    )
                    .await?,
                );
            } else {
                let lease = self
                    .get_lease(&refresh.namespace, &refresh.key)
                    .await?
                    .with_context(|| {
                        format!("lease {}/{} does not exist", refresh.namespace, refresh.key)
                    })?;
                ensure!(
                    lease.status == "active"
                        && lease.fencing_token == refresh.fencing_token
                        && lease.expires_at_ms > crate::now_millis(),
                    "lease {}/{} is not the active fenced holder",
                    refresh.namespace,
                    refresh.key
                );
                leases.push(lease);
            }
        }
        Ok(leases)
    }

    pub(crate) async fn refresh_leases_and_guarded_put(
        &mut self,
        refreshes: Vec<LeaseRefresh>,
        object: Object,
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
    ) -> Result<(Vec<Lease>, Object)> {
        Box::pin(self.refresh_leases_and_guarded_put_inner(
            refreshes,
            object,
            lease_namespace,
            lease_key,
            fencing_token,
        ))
        .await
    }

    async fn refresh_leases_and_guarded_put_inner(
        &mut self,
        refreshes: Vec<LeaseRefresh>,
        object: Object,
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
    ) -> Result<(Vec<Lease>, Object)> {
        if let Some((catalog, Some(tenant))) = self.catalog_binding() {
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return super::block_catalog(catalog, move |catalog| {
                catalog.refresh_leases_and_guarded_put(
                    Some(&tenant),
                    &refreshes,
                    object,
                    &lease_namespace,
                    &lease_key,
                    &fencing_token,
                )
            })
            .await;
        }
        if let Some(store) = self.embedded_arc() {
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return block_embedded(store, move |store| {
                store.refresh_leases_and_guarded_put(
                    &refreshes,
                    object,
                    &lease_namespace,
                    &lease_key,
                    &fencing_token,
                )
            })
            .await;
        }
        let leases = self.refresh_leases(refreshes).await?;
        let mut object = object;
        crate::storage::stamp_claim_expiry(&mut object, &leases, lease_namespace, lease_key);
        let object = self
            .guarded_update(object, lease_namespace, lease_key, fencing_token)
            .await?;
        Ok((leases, object))
    }

    pub(crate) async fn guarded_update(
        &mut self,
        object: Object,
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
    ) -> Result<Object> {
        if let Some((catalog, Some(tenant))) = self.catalog_binding() {
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return super::block_catalog(catalog, move |catalog| {
                catalog.guarded_put(
                    Some(&tenant),
                    object,
                    &lease_namespace,
                    &lease_key,
                    &fencing_token,
                    false,
                )
            })
            .await;
        }
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
        observations: &[crate::feedback_observation::FeedbackObservation],
    ) -> Result<()> {
        let events = self
            .with_observation_delivery_events(events, observations)
            .await;
        if let Some((catalog, Some(tenant))) = self.catalog_binding() {
            // Observations land in the tenant partition with the objects
            // (#868); export events enqueue on its outbox when enabled (#783).
            let objects = objects.to_vec();
            let observations = observations.to_vec();
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return super::block_catalog(catalog, move |catalog| {
                catalog.guarded_put_objects_with_provider_events(
                    Some(&tenant),
                    objects,
                    &lease_namespace,
                    &lease_key,
                    &fencing_token,
                    &events,
                    &observations,
                )
            })
            .await;
        }
        let Some(store) = self.embedded_arc() else {
            anyhow::bail!(
                "remote application state cannot atomically update objects and enqueue Tenkai provider events"
            );
        };
        let objects = objects.to_vec();
        let lease_namespace = lease_namespace.to_string();
        let lease_key = lease_key.to_string();
        let fencing_token = fencing_token.to_string();
        let observations = observations.to_vec();
        block_embedded(store, move |store| {
            store.guarded_put_objects_with_provider_events(
                &objects,
                &lease_namespace,
                &lease_key,
                &fencing_token,
                &events,
                &observations,
            )
        })
        .await
    }
}
