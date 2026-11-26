//! Object create, update, delete, and fenced write methods on `Ctx`.

use std::collections::HashMap;

use anyhow::{Context as _, Result, ensure};

use super::Ctx;
use crate::pb::record::{Lease, Object};
use crate::storage::LeaseRefresh;

impl Ctx {
    /// Opt-in `feedback.observation` webhooks for the captured observations.
    /// Lookup failures skip the webhook; they never fail the capture write.
    async fn with_observation_delivery_events(
        &mut self,
        events: &[crate::storage::ProviderEventRecord],
        observations: &[crate::feedback_observation::FeedbackObservation],
    ) -> Vec<crate::storage::ProviderEventRecord> {
        let mut events = events.to_vec();
        events.extend(self.feedback_webhook_records(observations).await);
        events
    }

    async fn feedback_webhook_records(
        &mut self,
        observations: &[crate::feedback_observation::FeedbackObservation],
    ) -> Vec<crate::storage::ProviderEventRecord> {
        if observations.is_empty() || (!self.is_embedded() && !self.has_catalog()) {
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
        let Some(reads) = self.release_reads_for(id) else {
            return self.backend.object_lifecycle().get(id).await;
        };
        if let Some(object) = reads.lock().get(id) {
            return Ok(object.clone());
        }
        let object = self.backend.object_lifecycle().get(id).await?;
        reads.lock().insert(id.to_string(), object.clone());
        Ok(object)
    }

    /// Create an object without falling back to update when its id exists.
    pub async fn create_once(
        &mut self,
        object: Object,
    ) -> std::result::Result<Object, super::ClientError> {
        self.forget_release_read(&object.id);
        self.backend.object_lifecycle().create_once(object).await
    }

    pub async fn delete(&mut self, id: &str) -> Result<()> {
        self.forget_release_read(id);
        self.backend.object_lifecycle().delete(id).await
    }

    /// Write `object`, copying `key` from the stored row when it is already set.
    ///
    /// Embedded SQLite reads and upserts in one immediate transaction.
    pub(crate) async fn put_keeping_property(
        &mut self,
        object: Object,
        key: &str,
    ) -> Result<Object> {
        let Some((catalog, None)) = self.catalog_port() else {
            anyhow::bail!("put_keeping_property requires the embedded store");
        };
        let key = key.to_string();
        super::block_catalog(catalog, move |catalog| {
            catalog.put_keeping_property(None, object, &key)
        })
        .await
    }

    /// Delete `id` only while property `key` still equals `value`.
    ///
    /// Embedded SQLite checks and deletes in one immediate transaction.
    pub(crate) async fn delete_if_property(
        &mut self,
        id: &str,
        key: &str,
        value: &str,
    ) -> Result<bool> {
        let Some((catalog, None)) = self.catalog_port() else {
            anyhow::bail!("delete_if_property requires the embedded store");
        };
        let id = id.to_string();
        let key = key.to_string();
        let value = value.to_string();
        super::block_catalog(catalog, move |catalog| {
            catalog.delete_if_property(None, &id, &key, &value)
        })
        .await
    }

    /// Create the object, or update it if the id already exists.
    pub async fn put(&mut self, object: Object) -> Result<Object> {
        self.forget_release_read(&object.id);
        self.backend.object_lifecycle().put(object).await
    }

    /// Write `object` with `events` and feedback `observations` atomically,
    /// on the embedded store or the tenant's catalog partition (#868).
    pub(crate) async fn put_with_provider_events(
        &mut self,
        object: Object,
        events: &[crate::storage::ProviderEventRecord],
        observations: &[crate::feedback_observation::FeedbackObservation],
    ) -> Result<Object> {
        let events = self
            .with_observation_delivery_events(events, observations)
            .await;
        if let Some((catalog, tenant)) = self.catalog_port() {
            if events.is_empty() && observations.is_empty() {
                return self.put(object).await;
            }
            let observations = observations.to_vec();
            return super::block_catalog(catalog, move |catalog| {
                catalog.put_with_provider_events(tenant.as_deref(), object, &events, &observations)
            })
            .await;
        }
        anyhow::bail!(super::TENANT_HUB_UNAVAILABLE)
    }

    /// Whether this context commits objects and provider events in one
    /// transaction: embedded state and a bound tenant hub do.
    pub(crate) fn commits_provider_events_atomically(&self) -> bool {
        self.catalog_port().is_some()
    }

    /// [`Self::put_with_provider_events`] for an existing object, committed
    /// only while the lease `fencing_token` names is still held (#1294).
    pub(crate) async fn guarded_put_with_provider_events(
        &mut self,
        object: Object,
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
        events: &[crate::storage::ProviderEventRecord],
        observations: &[crate::feedback_observation::FeedbackObservation],
    ) -> Result<()> {
        if self.commits_provider_events_atomically() {
            return self
                .guarded_update_objects_with_provider_events(
                    &[object],
                    lease_namespace,
                    lease_key,
                    fencing_token,
                    events,
                    observations,
                )
                .await;
        }
        anyhow::bail!(super::TENANT_HUB_UNAVAILABLE)
    }

    pub(crate) async fn guarded_create(
        &mut self,
        object: Object,
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
    ) -> Result<Object> {
        if let Some((catalog, tenant)) = self.catalog_port() {
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return super::block_catalog(catalog, move |catalog| {
                catalog.guarded_put(
                    tenant.as_deref(),
                    object,
                    &lease_namespace,
                    &lease_key,
                    &fencing_token,
                    true,
                )
            })
            .await;
        }
        anyhow::bail!(super::TENANT_HUB_UNAVAILABLE)
    }

    /// Refresh every lease in `refreshes` in one store transaction where
    /// the backend has one. A lease with `extend` is renewed; the rest must
    /// still be held.
    pub(crate) async fn refresh_leases(
        &mut self,
        refreshes: Vec<LeaseRefresh>,
    ) -> Result<Vec<Lease>> {
        if let Some((catalog, tenant)) = self.catalog_port() {
            return super::block_catalog(catalog, move |catalog| {
                catalog.refresh_leases(tenant.as_deref(), &refreshes)
            })
            .await;
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
        if let Some((catalog, tenant)) = self.catalog_port() {
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return super::block_catalog(catalog, move |catalog| {
                catalog.refresh_leases_and_guarded_put(
                    tenant.as_deref(),
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
        if let Some((catalog, tenant)) = self.catalog_port() {
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return super::block_catalog(catalog, move |catalog| {
                catalog.guarded_put(
                    tenant.as_deref(),
                    object,
                    &lease_namespace,
                    &lease_key,
                    &fencing_token,
                    false,
                )
            })
            .await;
        }
        anyhow::bail!(super::TENANT_HUB_UNAVAILABLE)
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
        if let Some((catalog, tenant)) = self.catalog_port() {
            // Observations land in the tenant partition with the objects
            // (#868); export events enqueue on its outbox when enabled (#783).
            let objects = objects.to_vec();
            let observations = observations.to_vec();
            let lease_namespace = lease_namespace.to_string();
            let lease_key = lease_key.to_string();
            let fencing_token = fencing_token.to_string();
            return super::block_catalog(catalog, move |catalog| {
                catalog.guarded_put_objects_with_provider_events(
                    tenant.as_deref(),
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
        anyhow::bail!(super::TENANT_HUB_UNAVAILABLE)
    }
}
