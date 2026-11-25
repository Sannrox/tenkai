//! Tenant-partitioned catalog object graph shared by SQLite and PostgreSQL.
//!
//! Community SQLite ignores `tenant`. A hub catalog write without a tenant
//! fails closed (ADR 0038).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result as AnyResult, bail};

use crate::feedback_observation::FeedbackObservation;
use crate::ontology::{
    CHANNEL_REVISION_FLOOR, KIND_CHANNEL, KIND_ENVIRONMENT, KIND_ENVIRONMENT_EXECUTION, KIND_PLAN,
    KIND_RELEASE, NS, env_id, release_id,
};
use crate::pb::graph_action::{ActionResult, ActionTypeDef};
use crate::pb::sekai::{Decision, Lease, Link, Object, ObjectChange, ObjectType};
use crate::plan::Plan;
use crate::storage::{
    CATALOG_HISTORY_RETENTION_MS, ChannelRecord, EnvironmentRecord, PlanRecord, PlanStatus,
    ProviderEventRecord, ReleaseRecord, Result, StoreError, channel_record_to_object,
    encode_object, environment_record_to_object, plan_record_to_object, release_record_to_object,
};

/// One namespaced lease to refresh inside [`CatalogGraph::refresh_leases_and_guarded_put`].
#[derive(Clone, Debug)]
pub struct LeaseRefresh {
    pub namespace: String,
    pub key: String,
    pub fencing_token: String,
    pub ttl_ms: i64,
    /// When false, require the active holder without extending TTL (#874).
    pub extend: bool,
}

/// True when `next` is an environment execution claim whose only property
/// diff is `expires_at` (a lease heartbeat). Those diffs are not catalog
/// history (#874).
pub fn skip_execution_claim_heartbeat(previous: &Object, next: &Object) -> bool {
    next.kind == KIND_ENVIRONMENT_EXECUTION
        && previous
            .properties
            .keys()
            .chain(next.properties.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .all(|key| {
                key.as_str() == "expires_at"
                    || previous.properties.get(key) == next.properties.get(key)
            })
}

/// Catalog object, link, lease, schema, and action contract.
pub trait CatalogGraph: Send + Sync {
    fn get(&self, tenant: Option<&str>, id: &str) -> AnyResult<Option<Object>>;
    fn create(&self, tenant: Option<&str>, object: Object) -> Result<Object>;
    fn put(&self, tenant: Option<&str>, object: Object) -> AnyResult<Object>;
    fn delete(&self, tenant: Option<&str>, id: &str) -> AnyResult<()>;
    fn list_kind(&self, tenant: Option<&str>, kind: &str) -> AnyResult<Vec<Object>>;
    fn list_kind_ids(&self, tenant: Option<&str>, kind: &str) -> AnyResult<Vec<String>>;
    fn find_by_property(
        &self,
        tenant: Option<&str>,
        kind: &str,
        key: &str,
        value: &str,
    ) -> AnyResult<Vec<Object>>;
    /// Property-index lookup with optional value filter, order, and page.
    ///
    /// The default loads by `kind`/`key`/`value`. SQLite applies the rest in
    /// SQL, including the plan-row join so pages stay full.
    fn find_by_property_matching(
        &self,
        tenant: Option<&str>,
        query: crate::embedded::PropertyIndexQuery<'_>,
    ) -> AnyResult<Vec<Object>> {
        self.find_by_property(tenant, query.kind, query.key, query.value)
    }
    fn create_link(&self, tenant: Option<&str>, link: Link, fail_if_exists: bool) -> Result<()>;
    fn unlink(&self, tenant: Option<&str>, id: &str) -> AnyResult<()>;
    fn links(
        &self,
        tenant: Option<&str>,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> AnyResult<Vec<Link>>;
    fn linked(
        &self,
        tenant: Option<&str>,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> AnyResult<Vec<Object>>;
    fn acquire_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease>;
    fn get_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
    ) -> AnyResult<Option<Lease>>;
    fn refresh_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease>;
    /// Refresh every lease in `refreshes` in one catalog transaction: a
    /// lease with `extend` is renewed, the rest must still be held.
    fn refresh_leases(
        &self,
        tenant: Option<&str>,
        refreshes: &[LeaseRefresh],
    ) -> AnyResult<Vec<Lease>> {
        let mut leases = Vec::with_capacity(refreshes.len());
        for refresh in refreshes {
            if refresh.extend {
                leases.push(self.refresh_lease(
                    tenant,
                    &refresh.namespace,
                    &refresh.key,
                    &refresh.fencing_token,
                    refresh.ttl_ms,
                )?);
            } else {
                let lease = self
                    .get_lease(tenant, &refresh.namespace, &refresh.key)?
                    .with_context(|| {
                        format!(
                            "embedded lease {}/{} does not exist",
                            refresh.namespace, refresh.key
                        )
                    })?;
                anyhow::ensure!(
                    lease.status == "active"
                        && lease.fencing_token == refresh.fencing_token
                        && lease.expires_at_ms > crate::now_millis(),
                    "embedded lease {}/{} is not the active fenced holder",
                    refresh.namespace,
                    refresh.key
                );
                leases.push(lease);
            }
        }
        Ok(leases)
    }
    /// Refresh `refreshes` and guarded-put `object` in one catalog transaction.
    ///
    /// When a refreshed lease matches `object_namespace`/`object_key`, the
    /// object's `expires_at` is taken from that lease so a heartbeat does not
    /// take a second round trip (#874).
    fn refresh_leases_and_guarded_put(
        &self,
        tenant: Option<&str>,
        refreshes: &[LeaseRefresh],
        mut object: Object,
        object_namespace: &str,
        object_key: &str,
        object_fencing_token: &str,
    ) -> AnyResult<(Vec<Lease>, Object)> {
        let leases = self.refresh_leases(tenant, refreshes)?;
        stamp_claim_expiry(&mut object, &leases, object_namespace, object_key);
        let object = self.guarded_put(
            tenant,
            object,
            object_namespace,
            object_key,
            object_fencing_token,
            false,
        )?;
        Ok((leases, object))
    }
    fn release_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> AnyResult<Lease>;
    #[allow(clippy::too_many_arguments)]
    fn takeover_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at: i64,
        ttl_ms: i64,
    ) -> AnyResult<Lease>;
    fn guarded_put(
        &self,
        tenant: Option<&str>,
        object: Object,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        create: bool,
    ) -> AnyResult<Object>;
    fn guarded_put_many(
        &self,
        tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> AnyResult<()> {
        for object in objects {
            self.guarded_put(tenant, object, namespace, key, fencing_token, false)?;
        }
        Ok(())
    }
    /// Write `object`, enqueue `events`, and capture feedback `observations`
    /// in one catalog transaction. A refused observation is logged and the
    /// write still commits (#802, #868).
    fn put_with_provider_events(
        &self,
        tenant: Option<&str>,
        object: Object,
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<Object>;
    fn put_objects_with_provider_events(
        &self,
        tenant: Option<&str>,
        objects: &[Object],
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<()>;
    #[allow(clippy::too_many_arguments)]
    fn guarded_put_objects_with_provider_events(
        &self,
        tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<()>;
    /// Feedback observations of `environment` in `tenant`, oldest first.
    fn feedback_observations(
        &self,
        tenant: Option<&str>,
        environment: &str,
    ) -> AnyResult<Vec<FeedbackObservation>>;
    fn register_schema(&self, tenant: Option<&str>, schema: ObjectType) -> Result<()>;
    fn schemas(&self, tenant: Option<&str>) -> AnyResult<Vec<ObjectType>>;
    fn register_action(&self, tenant: Option<&str>, action: ActionTypeDef) -> Result<()>;
    /// Run a registered action on target parameter `id`. Every parameter is
    /// checked before any write; links, properties and the decision then
    /// commit together or not at all (#1304).
    fn execute_action(
        &self,
        tenant: Option<&str>,
        action: &str,
        params: HashMap<String, String>,
        dry_run: bool,
    ) -> AnyResult<ActionResult>;
    fn decisions(
        &self,
        tenant: Option<&str>,
        actor: &str,
        action: &str,
        after: i64,
    ) -> AnyResult<Vec<Decision>>;
    fn changes(&self, tenant: Option<&str>, object_id: &str) -> AnyResult<Vec<ObjectChange>>;
    /// Write `object`, copying `key` from the stored row when it is already set.
    fn put_keeping_property(
        &self,
        tenant: Option<&str>,
        mut object: Object,
        key: &str,
    ) -> AnyResult<Object> {
        if let Some(existing) = self.get(tenant, &object.id)?
            && let Some(value) = existing.properties.get(key)
        {
            object.properties.insert(key.to_string(), value.clone());
        }
        self.put(tenant, object)
    }
    /// Delete `id` only while property `key` still equals `value`.
    fn delete_if_property(
        &self,
        tenant: Option<&str>,
        id: &str,
        key: &str,
        value: &str,
    ) -> AnyResult<bool> {
        match self.get(tenant, id)? {
            Some(object) if object.properties.get(key).map(String::as_str) == Some(value) => {
                self.delete(tenant, id)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// In-memory catalog and operational store for unit tests and tenant-mode
/// hosts without Postgres. One value implements both [`CatalogGraph`] and
/// [`super::OperationalStore`] so community tests share catalog outbox and
/// operational events the way `tenkai-sqlite::SqliteStore` does.
#[derive(Clone, Default)]
pub struct MemoryCatalogGraph {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    principal: String,
}

#[derive(Clone, Default)]
struct Partition {
    objects: BTreeMap<String, Object>,
    links: BTreeMap<String, Link>,
    leases: BTreeMap<(String, String), Lease>,
    schemas: BTreeMap<String, ObjectType>,
    actions: BTreeMap<String, ActionTypeDef>,
    decisions: Vec<Decision>,
    changes: BTreeMap<String, Vec<ObjectChange>>,
    events: BTreeMap<(String, String), ProviderEventRecord>,
    observations: BTreeMap<String, FeedbackObservation>,
    releases: BTreeMap<String, super::ReleaseRecord>,
    channels: BTreeMap<String, super::ChannelRecord>,
    environments: BTreeMap<String, super::EnvironmentRecord>,
    plans: BTreeMap<String, super::PlanRecord>,
    apply_leases: BTreeMap<String, super::LeaseRecord>,
    lease_takeovers: BTreeMap<(String, u64), (String, String)>,
    receipts: BTreeMap<String, super::ReceiptRecord>,
    offline_imports: BTreeMap<String, super::OfflineImportRecord>,
    offline_steps: Vec<super::OfflineStepImportRecord>,
    rollbacks: BTreeMap<String, super::RollbackRecord>,
    audit: Vec<super::AuditRecord>,
    change_events: Vec<crate::change_stream::ChangeEvent>,
    change_seq: i64,
    producer_sequences: BTreeMap<String, i64>,
    runtime_claims: BTreeMap<String, super::RuntimeClaim>,
    enrollments: BTreeMap<String, super::RuntimeEnrollmentRecord>,
    credentials: BTreeMap<String, super::RuntimeCredentialRecord>,
    credential_revocations: BTreeMap<String, super::RuntimeRevocation>,
    activity: BTreeMap<(String, String), super::RuntimeActivityRecord>,
    certificates: BTreeMap<String, (String, i64)>,
    attestations: BTreeMap<String, super::RuntimeAttestationRecord>,
    sealing_keys: BTreeMap<String, super::RuntimeSealingKeyRecord>,
    fixture_objects: BTreeMap<(String, String), (String, String, i64)>,
    grant_rules: BTreeMap<String, String>,
    grant_rule_generation: i64,
}

impl MemoryCatalogGraph {
    pub fn new() -> Self {
        Self {
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
            principal: "tenkai".into(),
        }
    }

    fn lock(&self) -> AnyResult<std::sync::MutexGuard<'_, BTreeMap<String, Partition>>> {
        self.partitions
            .lock()
            .map_err(|_| anyhow::anyhow!("{}", StoreError::Poisoned))
    }

    fn key(tenant: Option<&str>) -> String {
        tenant.unwrap_or("").to_owned()
    }
}

impl CatalogGraph for MemoryCatalogGraph {
    fn get(&self, tenant: Option<&str>, id: &str) -> AnyResult<Option<Object>> {
        let partitions = self.lock()?;
        Ok(partitions
            .get(&Self::key(tenant))
            .and_then(|partition| partition.objects.get(id))
            .cloned())
    }

    fn create(&self, tenant: Option<&str>, object: Object) -> Result<Object> {
        let mut partitions = self
            .lock()
            .map_err(|error| StoreError::Database(error.to_string()))?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        if partition.objects.contains_key(&object.id) {
            return Err(StoreError::already_exists("object", object.id));
        }
        persist_memory_object(partition, object, &self.principal, None).map_err(|error| {
            match error.downcast::<StoreError>() {
                Ok(store) => store,
                Err(error) => StoreError::Database(error.to_string()),
            }
        })
    }

    fn put(&self, tenant: Option<&str>, object: Object) -> AnyResult<Object> {
        // Read the previous object under the same guard that records the
        // change and writes, so concurrent puts diff against what they replace.
        let mut partitions = self.lock()?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        let previous = partition.objects.get(&object.id).cloned();
        persist_memory_object(partition, object, &self.principal, previous.as_ref())
    }

    fn delete(&self, tenant: Option<&str>, id: &str) -> AnyResult<()> {
        let mut partitions = self.lock()?;
        let Some(partition) = partitions.get_mut(&Self::key(tenant)) else {
            return Ok(());
        };
        partition.objects.remove(id);
        partition.environments.remove(id);
        partition.releases.remove(id);
        partition.channels.remove(id);
        partition.plans.remove(id);
        partition
            .links
            .retain(|_, link| link.from_id != id && link.to_id != id);
        partition.changes.remove(id);
        Ok(())
    }

    fn list_kind(&self, tenant: Option<&str>, kind: &str) -> AnyResult<Vec<Object>> {
        let partitions = self.lock()?;
        let Some(partition) = partitions.get(&Self::key(tenant)) else {
            return Ok(Vec::new());
        };
        match kind {
            KIND_ENVIRONMENT => list_memory_environments(partition),
            KIND_PLAN => list_memory_plans(partition),
            KIND_RELEASE => list_memory_releases(partition),
            KIND_CHANNEL => list_memory_channels(partition),
            _ => {
                let mut objects: Vec<Object> = partition
                    .objects
                    .values()
                    .filter(|object| object.kind == kind)
                    .cloned()
                    .collect();
                objects.sort_by(|left, right| left.id.cmp(&right.id));
                Ok(objects)
            }
        }
    }

    fn list_kind_ids(&self, tenant: Option<&str>, kind: &str) -> AnyResult<Vec<String>> {
        if kind == KIND_ENVIRONMENT {
            let partitions = self.lock()?;
            return Ok(partitions
                .get(&Self::key(tenant))
                .map(list_active_catalog_environment_ids)
                .unwrap_or_default());
        }
        Ok(self
            .list_kind(tenant, kind)?
            .into_iter()
            .map(|object| object.id)
            .collect())
    }

    fn find_by_property(
        &self,
        tenant: Option<&str>,
        kind: &str,
        key: &str,
        value: &str,
    ) -> AnyResult<Vec<Object>> {
        anyhow::ensure!(
            !kind.trim().is_empty() && !key.trim().is_empty(),
            "find_by_property requires non-empty kind and key"
        );
        Ok(self
            .list_kind(tenant, kind)?
            .into_iter()
            .filter(|object| {
                object
                    .properties
                    .get(key)
                    .is_some_and(|stored| stored == value)
            })
            .collect())
    }

    fn find_by_property_matching(
        &self,
        tenant: Option<&str>,
        query: crate::embedded::PropertyIndexQuery<'_>,
    ) -> AnyResult<Vec<Object>> {
        anyhow::ensure!(
            !query.kind.trim().is_empty() && !query.key.trim().is_empty(),
            "find_by_property requires non-empty kind and key"
        );
        if let Some(filter_key) = query.matching_key {
            anyhow::ensure!(
                !filter_key.trim().is_empty(),
                "find_by_property matching key must be non-empty"
            );
            if query.matching_values.is_empty() {
                return Ok(Vec::new());
            }
        }
        if let Some(equals_key) = query.equals_key {
            anyhow::ensure!(
                !equals_key.trim().is_empty(),
                "find_by_property equals key must be non-empty"
            );
            anyhow::ensure!(
                query
                    .equals_value
                    .is_some_and(|value| !value.trim().is_empty()),
                "find_by_property equals value must be non-empty"
            );
        }
        if let Some(order_key) = query.order_key {
            anyhow::ensure!(
                !order_key.trim().is_empty(),
                "find_by_property order key must be non-empty"
            );
        }
        let partitions = self.lock()?;
        let Some(partition) = partitions.get(&Self::key(tenant)) else {
            return Ok(Vec::new());
        };
        let mut objects: Vec<Object> = partition
            .objects
            .values()
            .filter(|object| {
                object.kind == query.kind
                    && object
                        .properties
                        .get(query.key)
                        .is_some_and(|stored| stored == query.value)
            })
            .cloned()
            .collect();
        if query.kind == KIND_PLAN {
            objects.retain(|object| partition.plans.contains_key(&object.id));
        }
        if let Some(filter_key) = query.matching_key {
            objects.retain(|object| {
                object
                    .properties
                    .get(filter_key)
                    .is_some_and(|stored| query.matching_values.contains(&stored.as_str()))
            });
        }
        if let (Some(equals_key), Some(equals_value)) = (query.equals_key, query.equals_value) {
            objects.retain(|object| {
                object
                    .properties
                    .get(equals_key)
                    .is_some_and(|stored| stored == equals_value)
            });
        }
        if let Some(order_key) = query.order_key {
            objects.sort_by(|left, right| {
                let order =
                    integer_property(left, order_key).cmp(&integer_property(right, order_key));
                let order = order.then_with(|| left.id.cmp(&right.id));
                if query.descending {
                    order.reverse()
                } else {
                    order
                }
            });
        } else {
            objects.sort_by(|left, right| left.id.cmp(&right.id));
        }
        if let Some(offset) = query.offset {
            anyhow::ensure!(
                query.limit.is_some(),
                "find_by_property offset requires a limit"
            );
            let offset = usize::try_from(offset).unwrap_or(usize::MAX);
            if offset >= objects.len() {
                objects.clear();
            } else {
                objects.drain(..offset);
            }
        }
        if let Some(limit) = query.limit {
            objects.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        Ok(objects)
    }

    fn create_link(&self, tenant: Option<&str>, link: Link, fail_if_exists: bool) -> Result<()> {
        let mut partitions = self
            .lock()
            .map_err(|error| StoreError::Database(error.to_string()))?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        if partition.links.contains_key(&link.id) {
            if fail_if_exists {
                return Err(StoreError::already_exists("link", link.id));
            }
            return Ok(());
        }
        partition.links.insert(link.id.clone(), link);
        Ok(())
    }

    fn unlink(&self, tenant: Option<&str>, id: &str) -> AnyResult<()> {
        let mut partitions = self.lock()?;
        if let Some(partition) = partitions.get_mut(&Self::key(tenant)) {
            partition.links.remove(id);
        }
        Ok(())
    }

    fn links(
        &self,
        tenant: Option<&str>,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> AnyResult<Vec<Link>> {
        let partitions = self.lock()?;
        let Some(partition) = partitions.get(&Self::key(tenant)) else {
            return Ok(Vec::new());
        };
        let mut links: Vec<Link> = partition
            .links
            .values()
            .filter(|link| {
                link.relation == relation
                    && match direction {
                        "out" => link.from_id == object_id,
                        "in" => link.to_id == object_id,
                        _ => false,
                    }
            })
            .cloned()
            .collect();
        if !matches!(direction, "out" | "in") {
            bail!("unsupported embedded link direction {direction:?}");
        }
        links.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(links)
    }

    fn linked(
        &self,
        tenant: Option<&str>,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> AnyResult<Vec<Object>> {
        let links = self.links(tenant, object_id, relation, direction)?;
        links
            .into_iter()
            .map(|link| {
                let id = if direction == "in" {
                    link.from_id
                } else {
                    link.to_id
                };
                self.get(tenant, &id)?
                    .with_context(|| format!("linked object {id} is missing"))
            })
            .collect()
    }

    fn acquire_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let now = crate::now_millis();
        let mut partitions = self.lock()?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        let lease_key = (namespace.to_owned(), key.to_owned());
        if partition
            .leases
            .get(&lease_key)
            .is_some_and(|lease| lease.status == "active" && lease.expires_at_ms > now)
        {
            return Err(StoreError::already_exists("lease", format!("{namespace}/{key}")).into());
        }
        let generation = partition
            .leases
            .get(&lease_key)
            .map(|lease| lease.generation.saturating_add(1))
            .unwrap_or(1);
        let lease = Lease {
            namespace: namespace.into(),
            key: key.into(),
            generation,
            fencing_token: uuid::Uuid::new_v4().to_string(),
            owner: owner.into(),
            status: "active".into(),
            acquired_at_ms: now,
            refreshed_at_ms: now,
            expires_at_ms: now.saturating_add(ttl_ms),
            released_at_ms: 0,
            site_id: String::new(),
        };
        partition.leases.insert(lease_key, lease.clone());
        Ok(lease)
    }

    fn get_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
    ) -> AnyResult<Option<Lease>> {
        let partitions = self.lock()?;
        Ok(partitions
            .get(&Self::key(tenant))
            .and_then(|partition| {
                partition
                    .leases
                    .get(&(namespace.to_owned(), key.to_owned()))
            })
            .cloned())
    }

    fn refresh_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let mut partitions = self.lock()?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        let mut lease = require_memory_lease(partition, namespace, key, fencing_token)?;
        let now = crate::now_millis();
        lease.refreshed_at_ms = now;
        lease.expires_at_ms = now.saturating_add(ttl_ms);
        partition
            .leases
            .insert((namespace.to_owned(), key.to_owned()), lease.clone());
        Ok(lease)
    }

    fn release_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> AnyResult<Lease> {
        let mut partitions = self.lock()?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        let mut lease = require_memory_lease(partition, namespace, key, fencing_token)?;
        lease.status = "released".into();
        lease.released_at_ms = crate::now_millis();
        partition
            .leases
            .insert((namespace.to_owned(), key.to_owned()), lease.clone());
        Ok(lease)
    }

    #[allow(clippy::too_many_arguments)]
    fn takeover_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at: i64,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let mut partitions = self.lock()?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        let current = partition
            .leases
            .get(&(namespace.to_owned(), key.to_owned()))
            .cloned()
            .with_context(|| format!("embedded lease {namespace}/{key} does not exist"))?;
        anyhow::ensure!(
            current.fencing_token == expected_token
                && current.expires_at_ms == expected_expires_at
                && current.expires_at_ms <= crate::now_millis(),
            "embedded lease takeover precondition failed"
        );
        let now = crate::now_millis();
        let lease = Lease {
            namespace: namespace.into(),
            key: key.into(),
            generation: current.generation.saturating_add(1),
            fencing_token: uuid::Uuid::new_v4().to_string(),
            owner: owner.into(),
            status: "active".into(),
            acquired_at_ms: now,
            refreshed_at_ms: now,
            expires_at_ms: now.saturating_add(ttl_ms),
            released_at_ms: 0,
            site_id: String::new(),
        };
        partition
            .leases
            .insert((namespace.to_owned(), key.to_owned()), lease.clone());
        Ok(lease)
    }

    fn guarded_put(
        &self,
        tenant: Option<&str>,
        object: Object,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        create: bool,
    ) -> AnyResult<Object> {
        let mut partitions = self.lock()?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        require_memory_lease(partition, namespace, key, fencing_token)?;
        let previous = partition.objects.get(&object.id).cloned();
        if create && previous.is_some() {
            return Err(StoreError::already_exists("object", object.id.clone()).into());
        }
        if !create {
            anyhow::ensure!(
                previous.is_some(),
                "embedded object {} does not exist",
                object.id
            );
        }
        persist_memory_object(partition, object, &self.principal, previous.as_ref())
    }

    fn guarded_put_many(
        &self,
        tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> AnyResult<()> {
        self.guarded_put_objects_with_provider_events(
            tenant,
            objects,
            namespace,
            key,
            fencing_token,
            &[],
            &[],
        )
    }

    fn put_with_provider_events(
        &self,
        tenant: Option<&str>,
        object: Object,
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<Object> {
        self.put_objects_with_provider_events(
            tenant,
            std::slice::from_ref(&object),
            events,
            observations,
        )?;
        Ok(object)
    }

    fn put_objects_with_provider_events(
        &self,
        tenant: Option<&str>,
        objects: &[Object],
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<()> {
        self.apply_objects_with_provider_events(tenant, objects, events, observations, None)
    }

    fn guarded_put_objects_with_provider_events(
        &self,
        tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<()> {
        self.apply_objects_with_provider_events(
            tenant,
            &objects,
            events,
            observations,
            Some((namespace, key, fencing_token)),
        )
    }

    fn feedback_observations(
        &self,
        tenant: Option<&str>,
        environment: &str,
    ) -> AnyResult<Vec<FeedbackObservation>> {
        let partitions = self.lock()?;
        let mut observations: Vec<FeedbackObservation> = partitions
            .get(&Self::key(tenant))
            .map(|partition| {
                partition
                    .observations
                    .values()
                    .filter(|observation| observation.environment == environment)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        observations.sort_by(|left, right| {
            (left.observed_at_ms, &left.id).cmp(&(right.observed_at_ms, &right.id))
        });
        Ok(observations)
    }

    fn register_schema(&self, tenant: Option<&str>, schema: ObjectType) -> Result<()> {
        let mut partitions = self
            .lock()
            .map_err(|error| StoreError::Database(error.to_string()))?;
        partitions
            .entry(Self::key(tenant))
            .or_default()
            .schemas
            .insert(schema.kind.clone(), schema);
        Ok(())
    }

    fn schemas(&self, tenant: Option<&str>) -> AnyResult<Vec<ObjectType>> {
        let partitions = self.lock()?;
        Ok(partitions
            .get(&Self::key(tenant))
            .map(|partition| partition.schemas.values().cloned().collect())
            .unwrap_or_default())
    }

    fn register_action(&self, tenant: Option<&str>, action: ActionTypeDef) -> Result<()> {
        let mut partitions = self
            .lock()
            .map_err(|error| StoreError::Database(error.to_string()))?;
        partitions
            .entry(Self::key(tenant))
            .or_default()
            .actions
            .insert(action.name.clone(), action);
        Ok(())
    }

    fn execute_action(
        &self,
        tenant: Option<&str>,
        action_name: &str,
        params: HashMap<String, String>,
        dry_run: bool,
    ) -> AnyResult<ActionResult> {
        let action = {
            let partitions = self.lock()?;
            partitions
                .get(&Self::key(tenant))
                .and_then(|partition| partition.actions.get(action_name))
                .cloned()
                .with_context(|| {
                    format!("embedded action {action_name} is not registered; run `tenkaictl init`")
                })?
        };
        let writes = super::ActionWrites::plan("embedded", action_name, &action, &params)?;
        let target_id = &writes.target_id;
        let planned_ops = action
            .ops
            .iter()
            .map(|op| op.op.clone())
            .collect::<Vec<_>>();
        // One guard covers the read and every write, so the action is atomic.
        let mut partitions = self.lock()?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        let previous = partition
            .objects
            .get(target_id)
            .cloned()
            .with_context(|| format!("embedded action target {target_id} does not exist"))?;
        if !dry_run {
            let mut target = previous.clone();
            writes.apply_properties(&mut target);
            // The only fallible write goes first; the map updates below cannot fail.
            persist_memory_object(partition, target, &self.principal, Some(&previous))?;
            for write in &writes.writes {
                match write {
                    super::ActionWrite::SetProperty { .. } => {}
                    super::ActionWrite::CreateLink(link) => {
                        partition
                            .links
                            .entry(link.id.clone())
                            .or_insert_with(|| link.clone());
                    }
                    super::ActionWrite::DeleteLink(id) => {
                        partition.links.remove(id);
                    }
                }
            }
            partition.decisions.push(action_decision(
                &self.principal,
                action_name,
                target_id,
                &params,
            ));
        }
        Ok(ActionResult {
            action: action_name.into(),
            message: "allowed by embedded host policy".into(),
            dry_run,
            planned_ops,
            decision: "allow".into(),
            approval_id: String::new(),
        })
    }

    fn decisions(
        &self,
        tenant: Option<&str>,
        actor: &str,
        action: &str,
        after: i64,
    ) -> AnyResult<Vec<Decision>> {
        let partitions = self.lock()?;
        Ok(partitions
            .get(&Self::key(tenant))
            .map(|partition| {
                partition
                    .decisions
                    .iter()
                    .filter(|decision| {
                        (actor.is_empty() || decision.actor == actor)
                            && (action.is_empty() || decision.action == action)
                            && decision.timestamp > after
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    fn changes(&self, tenant: Option<&str>, object_id: &str) -> AnyResult<Vec<ObjectChange>> {
        let partitions = self.lock()?;
        Ok(partitions
            .get(&Self::key(tenant))
            .and_then(|partition| partition.changes.get(object_id))
            .cloned()
            .unwrap_or_default())
    }
}

impl MemoryCatalogGraph {
    fn apply_objects_with_provider_events(
        &self,
        tenant: Option<&str>,
        objects: &[Object],
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
        lease: Option<(&str, &str, &str)>,
    ) -> AnyResult<()> {
        anyhow::ensure!(!objects.is_empty(), "embedded object update is empty");
        let unique = objects
            .iter()
            .map(|object| object.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            unique.len() == objects.len(),
            "embedded object update contains duplicate identities"
        );
        let events = crate::providers::bind_tenant_to_provider_events(tenant, events)?;
        let mut partitions = self.lock()?;
        let key = Self::key(tenant);
        let mut partition = partitions.get(&key).cloned().unwrap_or_default();
        if let Some((namespace, lease_key, token)) = lease {
            require_memory_lease(&partition, namespace, lease_key, token)?;
        }
        let previous: Vec<Object> =
            objects
                .iter()
                .map(|object| {
                    partition.objects.get(&object.id).cloned().ok_or_else(|| {
                        anyhow::anyhow!("embedded object {} does not exist", object.id)
                    })
                })
                .collect::<AnyResult<_>>()?;
        for (object, previous) in objects.iter().zip(previous) {
            persist_memory_object(
                &mut partition,
                object.clone(),
                &self.principal,
                Some(&previous),
            )?;
        }
        for event in &events {
            enqueue_memory_provider_event(&mut partition, event)?;
        }
        // First write wins, like the durable stores' immutable table.
        for observation in observations {
            partition
                .observations
                .entry(observation.id.clone())
                .or_insert_with(|| observation.clone());
        }
        partitions.insert(key, partition);
        Ok(())
    }

    #[cfg(test)]
    fn listed_provider_events(
        &self,
        tenant: Option<&str>,
        provider_kind: &str,
        environment_id: &str,
    ) -> AnyResult<Vec<ProviderEventRecord>> {
        let partitions = self.lock()?;
        Ok(partitions
            .get(&Self::key(tenant))
            .map(|partition| {
                partition
                    .events
                    .values()
                    .filter(|event| {
                        event.provider_kind == provider_kind
                            && crate::storage::provider_event_environment_id(&event.payload_json)
                                .as_deref()
                                == Some(environment_id)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// The allow decision an executed embedded action records.
fn action_decision(
    principal: &str,
    action: &str,
    target_id: &str,
    params: &HashMap<String, String>,
) -> Decision {
    let mut evidence = params.clone();
    evidence.insert("decision".into(), "allow".into());
    Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: crate::now_millis(),
        actor: principal.into(),
        action: action.into(),
        reason: "execute_action".into(),
        evidence,
        target_id: target_id.into(),
        outcome: "allow".into(),
    }
}

fn environment_is_retired(environment: &EnvironmentRecord) -> bool {
    crate::environment::retirement_from_configuration_json(&environment.configuration_json)
        .is_some()
}

fn list_active_catalog_environment_ids(partition: &Partition) -> Vec<String> {
    let mut ids: Vec<String> = partition
        .environments
        .values()
        .filter(|environment| !environment_is_retired(environment))
        .filter(|environment| {
            environment.id.starts_with("tenkai:env:") || {
                let catalog_id = env_id(&environment.id);
                !partition
                    .environments
                    .get(&catalog_id)
                    .is_some_and(environment_is_retired)
            }
        })
        .map(|environment| environment.id.clone())
        .collect();
    ids.sort();
    ids
}

fn list_memory_environments(partition: &Partition) -> AnyResult<Vec<Object>> {
    list_active_catalog_environment_ids(partition)
        .into_iter()
        .filter_map(|id| partition.environments.get(&id).cloned())
        .map(|record| environment_record_to_object(&record))
        .collect()
}

fn list_memory_plans(partition: &Partition) -> AnyResult<Vec<Object>> {
    let mut objects = Vec::new();
    for record in partition.plans.values() {
        if let Some(stored) = partition.objects.get(&record.id) {
            objects.push(stored.clone());
        } else {
            objects.push(plan_record_to_object(record)?);
        }
    }
    objects.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(objects)
}

fn list_memory_releases(partition: &Partition) -> AnyResult<Vec<Object>> {
    partition
        .releases
        .values()
        .map(release_record_to_object)
        .collect::<AnyResult<Vec<_>>>()
        .map(|mut objects| {
            objects.sort_by(|left, right| left.id.cmp(&right.id));
            objects
        })
}

fn list_memory_channels(partition: &Partition) -> AnyResult<Vec<Object>> {
    let mut objects: Vec<Object> = partition
        .channels
        .values()
        .map(|record| {
            partition
                .objects
                .get(&record.id)
                .cloned()
                .unwrap_or_else(|| channel_record_to_object(record))
        })
        .collect();
    let mut seen: std::collections::BTreeSet<String> =
        objects.iter().map(|object| object.id.clone()).collect();
    for object in partition.objects.values() {
        if object.kind == KIND_CHANNEL && seen.insert(object.id.clone()) {
            objects.push(object.clone());
        }
    }
    objects.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(objects)
}

fn integer_property(object: &Object, key: &str) -> i64 {
    object
        .properties
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn persist_memory_object(
    partition: &mut Partition,
    object: Object,
    principal: &str,
    previous: Option<&Object>,
) -> AnyResult<Object> {
    let object = upsert_memory_typed(partition, object)?;
    if let Some(previous) = previous {
        record_memory_changes(partition, previous, &object, principal);
    }
    partition.objects.insert(object.id.clone(), object.clone());
    Ok(object)
}

fn upsert_memory_typed(partition: &mut Partition, object: Object) -> AnyResult<Object> {
    match object.kind.as_str() {
        KIND_ENVIRONMENT => {
            upsert_memory_environment(partition, &object)?;
            Ok(object)
        }
        KIND_RELEASE => {
            upsert_memory_release(partition, &object)?;
            Ok(object)
        }
        KIND_CHANNEL => upsert_memory_channel(partition, object),
        KIND_PLAN => {
            upsert_memory_plan(partition, &object)?;
            Ok(object)
        }
        _ => Ok(object),
    }
}

fn upsert_memory_environment(partition: &mut Partition, object: &Object) -> AnyResult<()> {
    let existing = partition.environments.get(&object.id);
    let was_retired = existing
        .and_then(|environment| {
            crate::environment::retirement_from_configuration_json(&environment.configuration_json)
        })
        .is_some();
    if was_retired {
        return Err(StoreError::InvalidData {
            kind: "environment",
            detail: format!(
                "environment {} is retired and cannot be updated",
                object.name
            ),
        }
        .into());
    }
    if crate::environment::is_retired_object(object) {
        let now = crate::now_millis();
        let active_claim = partition.runtime_claims.values().any(|claim| {
            (claim.environment_id == object.name || claim.environment_id == object.id)
                && claim.expires_at > now
                && claim.completion_json.is_none()
        });
        let catalog_lease = partition
            .leases
            .get(&(
                crate::apply::ENVIRONMENT_LEASE_NAMESPACE.to_string(),
                object.name.clone(),
            ))
            .is_some_and(|lease| lease.status == "active" && lease.expires_at_ms > now);
        let typed_lease = partition
            .apply_leases
            .get(&object.id)
            .or_else(|| partition.apply_leases.get(&object.name))
            .is_some_and(|lease| lease.expires_at > now);
        if active_claim || catalog_lease || typed_lease {
            return Err(StoreError::InvalidData {
                kind: "environment",
                detail: format!("environment {} has active delivery work", object.name),
            }
            .into());
        }
    }
    let next = existing
        .map(|environment| environment.revision + 1)
        .unwrap_or(1);
    partition.environments.insert(
        object.id.clone(),
        EnvironmentRecord {
            id: object.id.clone(),
            revision: next,
            configuration_json: encode_object(object),
        },
    );
    Ok(())
}

fn upsert_memory_release(partition: &mut Partition, object: &Object) -> AnyResult<()> {
    let product = object
        .properties
        .get("product")
        .cloned()
        .unwrap_or_default();
    let version = object
        .properties
        .get("version")
        .cloned()
        .unwrap_or_default();
    let digest = object
        .properties
        .get("digest")
        .cloned()
        .or_else(|| object.properties.get("content_digest").cloned())
        .unwrap_or_default();
    let id = if object.id.is_empty() {
        release_id(&product, &version)
    } else {
        object.id.clone()
    };
    if let Some(existing) = partition.releases.get_mut(&id) {
        if existing.content_digest != digest {
            return Err(StoreError::ImmutableConflict {
                kind: "release",
                id,
            }
            .into());
        }
        existing.descriptor_json = encode_object(object);
        return Ok(());
    }
    partition.releases.insert(
        id.clone(),
        ReleaseRecord {
            id,
            product,
            version,
            content_digest: digest,
            descriptor_json: encode_object(object),
        },
    );
    Ok(())
}

fn upsert_memory_channel(partition: &mut Partition, mut object: Object) -> AnyResult<Object> {
    let product = object
        .properties
        .get("product")
        .cloned()
        .unwrap_or_default();
    let name = object
        .properties
        .get("name")
        .cloned()
        .or_else(|| object.properties.get("channel").cloned())
        .unwrap_or_else(|| object.name.clone());
    let release = object
        .properties
        .get("current_release")
        .cloned()
        .unwrap_or_default();
    let floor = partition
        .channels
        .get(&object.id)
        .map(|channel| channel.revision)
        .or_else(|| {
            object
                .properties
                .get(CHANNEL_REVISION_FLOOR)
                .and_then(|value| value.parse().ok())
        });
    let release_exists = !release.is_empty() && partition.releases.contains_key(&release);
    if !release_exists {
        partition.channels.remove(&object.id);
        if let Some(floor) = floor {
            object
                .properties
                .insert(CHANNEL_REVISION_FLOOR.into(), floor.to_string());
        }
        return Ok(object);
    }
    let next = floor.map(|value| value + 1).unwrap_or(1);
    partition.channels.insert(
        object.id.clone(),
        ChannelRecord {
            id: object.id.clone(),
            product,
            name,
            release_id: release,
            revision: next,
        },
    );
    Ok(object)
}

fn upsert_memory_plan(partition: &mut Partition, object: &Object) -> AnyResult<()> {
    let Some(raw) = object.properties.get("plan") else {
        return Ok(());
    };
    let Ok(plan) = serde_json::from_str::<Plan>(raw) else {
        return Ok(());
    };
    let environment_id = env_id(&plan.environment);
    if !partition.plans.contains_key(&object.id)
        && partition
            .environments
            .get(&environment_id)
            .or_else(|| partition.environments.get(&plan.environment))
            .and_then(|environment| {
                crate::environment::retirement_from_configuration_json(
                    &environment.configuration_json,
                )
            })
            .is_some()
    {
        return Err(StoreError::InvalidData {
            kind: "environment",
            detail: format!(
                "retired environment {} cannot accept new plans",
                plan.environment
            ),
        }
        .into());
    }
    if !partition.environments.contains_key(&environment_id) {
        partition.environments.insert(
            environment_id.clone(),
            EnvironmentRecord {
                id: environment_id.clone(),
                revision: 1,
                configuration_json: encode_object(&Object {
                    id: environment_id.clone(),
                    kind: KIND_ENVIRONMENT.into(),
                    name: plan.environment.clone(),
                    namespace: NS.into(),
                    created: plan.created_at,
                    updated: plan.created_at,
                    ..Object::default()
                }),
            },
        );
    }
    let digest = object
        .properties
        .get("content_digest")
        .cloned()
        .unwrap_or_default();
    let status = object
        .properties
        .get("status")
        .and_then(|value| PlanStatus::parse(value).ok())
        .unwrap_or(PlanStatus::Computed);
    partition.plans.insert(
        object.id.clone(),
        PlanRecord {
            id: object.id.clone(),
            environment_id,
            format_version: plan.format_version,
            content_digest: digest,
            plan_json: raw.clone(),
            status,
            status_detail: plan.status_detail,
        },
    );
    Ok(())
}

fn keep_first_optional_webhook(event: &ProviderEventRecord) -> bool {
    event.provider_kind == "feedback_webhook" || event.provider_kind == "deploy_webhook"
}

fn enqueue_memory_provider_event(
    partition: &mut Partition,
    event: &ProviderEventRecord,
) -> AnyResult<()> {
    super::validate_new_provider_event(event).map_err(anyhow::Error::from)?;
    let key = (event.provider_kind.clone(), event.id.clone());
    if let Some(existing) = partition.events.get(&key) {
        if existing.provider_kind != event.provider_kind
            || existing.binding_digest != event.binding_digest
            || !super::provider_event_payloads_match(&existing.payload_json, &event.payload_json)
        {
            if keep_first_optional_webhook(event) {
                return Ok(());
            }
            return Err(StoreError::ImmutableConflict {
                kind: "provider event",
                id: event.id.clone(),
            }
            .into());
        }
        return Ok(());
    }
    partition.events.insert(key, event.clone());
    Ok(())
}

fn require_memory_lease(
    partition: &Partition,
    namespace: &str,
    key: &str,
    fencing_token: &str,
) -> AnyResult<Lease> {
    let lease = partition
        .leases
        .get(&(namespace.to_owned(), key.to_owned()))
        .cloned()
        .with_context(|| format!("embedded lease {namespace}/{key} does not exist"))?;
    anyhow::ensure!(
        lease.status == "active"
            && lease.fencing_token == fencing_token
            && lease.expires_at_ms > crate::now_millis(),
        "embedded lease {namespace}/{key} is not the active fenced holder"
    );
    Ok(lease)
}

fn prune_memory_execution_claim_history(partition: &mut Partition, now: i64) {
    let cutoff = now.saturating_sub(CATALOG_HISTORY_RETENTION_MS);
    let claim_ids: Vec<String> = partition
        .objects
        .values()
        .filter(|object| object.kind == KIND_ENVIRONMENT_EXECUTION)
        .map(|object| object.id.clone())
        .collect();
    for id in claim_ids {
        if let Some(changes) = partition.changes.get_mut(&id) {
            changes.retain(|change| change.timestamp >= cutoff);
            if changes.is_empty() {
                partition.changes.remove(&id);
            }
        }
    }
}

pub fn stamp_claim_expiry(object: &mut Object, leases: &[Lease], namespace: &str, key: &str) {
    if let Some(lease) = leases
        .iter()
        .find(|lease| lease.namespace == namespace && lease.key == key)
    {
        object
            .properties
            .insert("expires_at".into(), lease.expires_at_ms.to_string());
        object.updated = lease.refreshed_at_ms;
    }
}

fn record_memory_changes(
    partition: &mut Partition,
    previous: &Object,
    next: &Object,
    principal: &str,
) {
    let timestamp = crate::now_millis();
    prune_memory_execution_claim_history(partition, timestamp);
    if skip_execution_claim_heartbeat(previous, next) {
        return;
    }
    for key in previous
        .properties
        .keys()
        .chain(next.properties.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let old = previous.properties.get(key).cloned().unwrap_or_default();
        let new = next.properties.get(key).cloned().unwrap_or_default();
        if old == new {
            continue;
        }
        partition
            .changes
            .entry(next.id.clone())
            .or_default()
            .push(ObjectChange {
                id: uuid::Uuid::new_v4().to_string(),
                object_id: next.id.clone(),
                field: format!("properties.{key}"),
                old_value: old,
                new_value: new,
                changed_by: principal.into(),
                timestamp,
            });
    }
}

mod memory_operational;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, kind: &str, name: &str) -> Object {
        Object {
            id: id.into(),
            kind: kind.into(),
            name: name.into(),
            properties: [("environment".into(), "lab".into())].into_iter().collect(),
            ..Object::default()
        }
    }

    fn assert_graph(graph: &dyn CatalogGraph, tenant: Option<&str>) {
        let id = "tenkai:conformance:object";
        assert_eq!(graph.get(tenant, id).unwrap(), None);
        let original = sample(id, "tenkai.conformance", "original");
        assert_eq!(graph.create(tenant, original.clone()).unwrap(), original);
        assert_eq!(graph.get(tenant, id).unwrap(), Some(original.clone()));
        let mut conflicting = original.clone();
        conflicting.name = "must-not-replace".into();
        assert!(
            graph
                .create(tenant, conflicting)
                .unwrap_err()
                .is_already_exists()
        );
        let mut updated = original.clone();
        updated.name = "updated".into();
        updated.properties.insert("status".into(), "ready".into());
        assert_eq!(graph.put(tenant, updated.clone()).unwrap(), updated);
        assert_eq!(
            graph
                .find_by_property(tenant, "tenkai.conformance", "status", "ready")
                .unwrap()
                .iter()
                .map(|object| object.id.as_str())
                .collect::<Vec<_>>(),
            [id]
        );
        let link = Link {
            id: format!("{id}--uses--tenkai:conformance:other"),
            from_id: id.into(),
            to_id: "tenkai:conformance:other".into(),
            relation: "uses".into(),
            created: 1,
        };
        graph.create_link(tenant, link.clone(), true).unwrap();
        assert!(
            graph
                .create_link(tenant, link.clone(), true)
                .unwrap_err()
                .is_already_exists()
        );
        graph.create_link(tenant, link.clone(), false).unwrap();
        assert_eq!(graph.links(tenant, id, "uses", "out").unwrap().len(), 1);
        let lease = graph
            .acquire_lease(tenant, "tenkai/test", "lock", "owner", 60_000)
            .unwrap();
        assert!(
            graph
                .acquire_lease(tenant, "tenkai/test", "lock", "other", 60_000)
                .unwrap_err()
                .downcast_ref::<StoreError>()
                .is_some_and(StoreError::is_already_exists)
        );
        graph
            .refresh_lease(tenant, "tenkai/test", "lock", &lease.fencing_token, 60_000)
            .unwrap();
        graph
            .guarded_put(
                tenant,
                updated.clone(),
                "tenkai/test",
                "lock",
                &lease.fencing_token,
                false,
            )
            .unwrap();
        graph
            .release_lease(tenant, "tenkai/test", "lock", &lease.fencing_token)
            .unwrap();
        graph.delete(tenant, id).unwrap();
        assert_eq!(graph.get(tenant, id).unwrap(), None);
    }

    #[test]
    fn memory_catalog_matches_sqlite_contract() {
        assert_graph(&MemoryCatalogGraph::new(), Some("tenant-a"));
    }

    #[test]
    fn memory_catalog_isolates_tenants() {
        let graph = MemoryCatalogGraph::new();
        graph
            .create(Some("a"), sample("tenkai:obj", "tenkai.conformance", "a"))
            .unwrap();
        assert!(graph.get(Some("b"), "tenkai:obj").unwrap().is_none());
        assert_eq!(
            graph
                .list_kind(Some("a"), "tenkai.conformance")
                .unwrap()
                .len(),
            1
        );
        assert!(
            graph
                .list_kind(Some("b"), "tenkai.conformance")
                .unwrap()
                .is_empty()
        );
    }

    fn set_status_action() -> ActionTypeDef {
        use crate::pb::graph_action::{ActionOp, ActionParamDef};
        ActionTypeDef {
            name: "tenkai.conformance.set_status".into(),
            description: "conformance".into(),
            params: vec![ActionParamDef {
                name: "value".into(),
                r#type: "string".into(),
                required: true,
                enum_values: vec![],
            }],
            ops: vec![ActionOp {
                op: "set_property".into(),
                property: "status".into(),
                value_from: "value".into(),
                relation: String::new(),
            }],
            target_kind: "tenkai.conformance".into(),
            created: 1,
            required_purpose: String::new(),
        }
    }

    fn assert_execute_action_records_decision(graph: &dyn CatalogGraph, tenant: Option<&str>) {
        let id = "tenkai:conformance:action-target";
        let _ = graph.delete(tenant, id);
        graph.register_action(tenant, set_status_action()).unwrap();
        graph
            .create(tenant, sample(id, "tenkai.conformance", "target"))
            .unwrap();
        graph
            .execute_action(
                tenant,
                "tenkai.conformance.set_status",
                HashMap::from([("id".into(), id.into()), ("value".into(), "ready".into())]),
                false,
            )
            .unwrap();
        let decisions = graph
            .decisions(tenant, "", "tenkai.conformance.set_status", 0)
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].outcome, "allow");
        assert_eq!(decisions[0].target_id, id);
        assert_eq!(
            graph
                .get(tenant, id)
                .unwrap()
                .unwrap()
                .properties
                .get("status")
                .map(String::as_str),
            Some("ready")
        );
        let _ = graph.delete(tenant, id);
    }

    fn assert_environment_retire_refuses_active_apply_lease(
        graph: &dyn CatalogGraph,
        tenant: Option<&str>,
    ) {
        let name = "lab";
        let id = crate::ontology::env_id(name);
        let _ = graph.delete(tenant, &id);
        let environment = Object {
            id: id.clone(),
            kind: crate::ontology::KIND_ENVIRONMENT.into(),
            name: name.into(),
            namespace: crate::ontology::NS.into(),
            ..Object::default()
        };
        graph.create(tenant, environment.clone()).unwrap();
        graph
            .acquire_lease(
                tenant,
                crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
                name,
                "owner",
                60_000,
            )
            .unwrap();
        let mut retired = environment;
        retired
            .properties
            .insert("tenkai.retirement.reason".into(), "done".into());
        retired
            .properties
            .insert("tenkai.retirement.actor".into(), "tester".into());
        retired.properties.insert(
            "tenkai.retirement.at".into(),
            crate::now_millis().to_string(),
        );
        let error = graph.put(tenant, retired).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("active delivery work"), "{message}");
        let _ = graph.release_lease(
            tenant,
            crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
            name,
            graph
                .get_lease(tenant, crate::apply::ENVIRONMENT_LEASE_NAMESPACE, name)
                .unwrap()
                .unwrap()
                .fencing_token
                .as_str(),
        );
        let _ = graph.delete(tenant, &id);
    }

    #[test]
    fn memory_catalog_execute_action_records_decision() {
        assert_execute_action_records_decision(&MemoryCatalogGraph::new(), Some("tenant-a"));
    }

    #[test]
    fn memory_catalog_retire_refuses_active_apply_lease() {
        assert_environment_retire_refuses_active_apply_lease(
            &MemoryCatalogGraph::new(),
            Some("tenant-a"),
        );
    }

    fn sample_event(id: &str, environment: &str) -> ProviderEventRecord {
        ProviderEventRecord {
            id: id.into(),
            provider_kind: "outcome".into(),
            binding_digest: "digest".into(),
            payload_json: format!(
                r#"{{"binding":{{"environment_id":"{environment}"}},"payload_json":"{{}}" }}"#
            ),
            attempts: 0,
            next_attempt_at: 1,
            delivered_at: None,
            last_error: String::new(),
            claim_token: None,
            claim_until: None,
        }
    }

    fn sample_observation(id: &str, status: &str) -> FeedbackObservation {
        FeedbackObservation::capture(crate::feedback_observation::Capture {
            id,
            operation: crate::feedback_observation::Operation::ApplyStep,
            environment: "prod",
            product: "api",
            plan_id: "plan-1",
            step_id: "step-1",
            action: Some(crate::plan::Action::Upgrade),
            release_id: "release:api:1.1.0",
            status,
            reason: crate::feedback_observation::Reason::None,
            started_at_ms: Some(1_000),
            lease_generation: 1,
            observed_at_ms: 2_000,
            context: Default::default(),
        })
    }

    /// Events and feedback observations commit with the object, replay
    /// idempotently, and roll back with it (#765, #868).
    fn assert_atomic_outbox(
        graph: &dyn CatalogGraph,
        tenant: Option<&str>,
        list: impl Fn() -> Vec<ProviderEventRecord>,
    ) {
        let id = "tenkai:conformance:outbox";
        let _ = graph.delete(tenant, id);
        let original = sample(id, "tenkai.conformance", "original");
        graph.create(tenant, original.clone()).unwrap();
        let mut updated = original.clone();
        updated.name = "terminal".into();
        let event = sample_event("event-1", "prod");
        let observation = sample_observation("deployment:prod:api:2000", "succeeded");
        graph
            .put_with_provider_events(
                tenant,
                updated.clone(),
                std::slice::from_ref(&event),
                std::slice::from_ref(&observation),
            )
            .unwrap();
        assert_eq!(graph.get(tenant, id).unwrap().unwrap().name, "terminal");
        assert_eq!(list().len(), 1);
        assert_eq!(
            graph.feedback_observations(tenant, "prod").unwrap(),
            std::slice::from_ref(&observation)
        );
        let conflicting_observation = sample_observation(&observation.id, "failed");
        graph
            .put_with_provider_events(
                tenant,
                updated.clone(),
                std::slice::from_ref(&event),
                &[conflicting_observation],
            )
            .unwrap();
        assert_eq!(list().len(), 1);
        assert_eq!(
            graph.feedback_observations(tenant, "prod").unwrap(),
            std::slice::from_ref(&observation)
        );

        let mut conflicting = event.clone();
        conflicting.payload_json =
            r#"{"binding":{"environment_id":"prod"},"payload_json":"{\"different\":true}"}"#.into();
        let mut rolled = updated.clone();
        rolled.name = "must-roll-back".into();
        let rolled_observation = sample_observation("deployment:prod:api:rolled", "failed");
        assert!(
            graph
                .put_with_provider_events(
                    tenant,
                    rolled.clone(),
                    &[conflicting],
                    std::slice::from_ref(&rolled_observation),
                )
                .is_err()
        );
        assert_eq!(graph.get(tenant, id).unwrap().unwrap().name, "terminal");
        assert_eq!(list().len(), 1);
        assert_eq!(
            graph.feedback_observations(tenant, "prod").unwrap(),
            [observation]
        );

        let mut invalid = event;
        invalid.id.clear();
        rolled.name = "invalid-must-roll-back".into();
        assert!(
            graph
                .put_with_provider_events(tenant, rolled, &[invalid], &[])
                .is_err()
        );
        assert_eq!(graph.get(tenant, id).unwrap().unwrap().name, "terminal");
        let _ = graph.delete(tenant, id);
    }

    #[test]
    fn memory_catalog_enqueues_provider_events_atomically() {
        let graph = MemoryCatalogGraph::new();
        assert_atomic_outbox(&graph, Some("tenant-a"), || {
            graph
                .listed_provider_events(Some("tenant-a"), "outcome", "prod")
                .unwrap()
        });
        let other = graph
            .listed_provider_events(Some("tenant-b"), "outcome", "prod")
            .unwrap();
        assert!(other.is_empty());
        assert!(
            graph
                .feedback_observations(Some("tenant-b"), "prod")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn memory_catalog_stamps_tenant_on_terminal_outcomes() {
        let graph = MemoryCatalogGraph::new();
        let id = "tenkai:conformance:outbox-tenant";
        let original = sample(id, "tenkai.conformance", "original");
        graph.create(Some("tenant-a"), original.clone()).unwrap();
        graph.create(Some("tenant-b"), original.clone()).unwrap();
        let event = crate::providers::terminal_outcome_event(
            "tenkai:deployment:prod:api:1",
            "tenkai:plan:prod:1",
            "sha256:plan",
            "tenkai:release:api@2.0.0",
            "sha256:release",
            "api",
            "prod",
            "tenkai:environment:prod",
            "sha256:config",
            crate::providers::TerminalOutcomeState::DeploymentSucceeded,
            100,
        )
        .unwrap();
        let record = crate::providers::provider_event_record("outcome", &event, 100).unwrap();
        let mut updated = original;
        updated.name = "terminal".into();
        graph
            .put_with_provider_events(
                Some("tenant-a"),
                updated.clone(),
                std::slice::from_ref(&record),
                &[],
            )
            .unwrap();
        graph
            .put_with_provider_events(
                Some("tenant-b"),
                updated,
                std::slice::from_ref(&record),
                &[],
            )
            .unwrap();
        let listed_a = graph
            .listed_provider_events(Some("tenant-a"), "outcome", "prod")
            .unwrap();
        let listed_b = graph
            .listed_provider_events(Some("tenant-b"), "outcome", "prod")
            .unwrap();
        assert_eq!(listed_a.len(), 1);
        assert_eq!(listed_b.len(), 1);
        assert_ne!(listed_a[0].id, listed_b[0].id);
        let payload_a: crate::providers::TerminalOutcomePayload = {
            let event: crate::providers::ProviderEvent =
                serde_json::from_str(&listed_a[0].payload_json).unwrap();
            serde_json::from_str(&event.payload_json).unwrap()
        };
        assert_eq!(payload_a.tenant_id, "tenant-a");
    }

    #[test]
    fn runtime_progress_outlives_a_later_claim() {
        use crate::storage::OperationalStore as _;
        let store = MemoryCatalogGraph::new();
        let expiry = crate::now_millis() + 10_000;
        let claim = store
            .claim_runtime_plan("prod", "plan-1", "runtime-a", expiry)
            .unwrap()
            .unwrap();
        assert!(
            store
                .record_runtime_progress("plan-1", "runtime-a", claim.generation, "{\"a\":1}")
                .unwrap()
        );
        store.lapse_runtime_claims(1).unwrap();
        let next = store
            .claim_runtime_plan("prod", "plan-1", "runtime-a", expiry)
            .unwrap()
            .unwrap();
        assert_eq!(next.generation, claim.generation + 1);
        assert_eq!(
            store.runtime_progress("plan-1").unwrap().as_deref(),
            Some("{\"a\":1}")
        );
    }

    #[test]
    fn memory_catalog_path_keyed_enqueues_provider_events_atomically() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-765-memory-outbox-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&path);
        let store = MemoryCatalogGraph::open(&path).unwrap();
        assert_atomic_outbox(&store, None, || {
            crate::storage::OperationalStore::list_provider_events(&store, "outcome", "prod", 8)
                .unwrap()
        });
        let _ = std::fs::remove_file(path);
    }
}
