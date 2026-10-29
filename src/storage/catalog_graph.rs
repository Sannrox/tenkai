//! Tenant-partitioned catalog object graph shared by SQLite and PostgreSQL.
//!
//! Community SQLite ignores `tenant`. A hub catalog write without a tenant
//! fails closed (ADR 0038).

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use anyhow::{Context as _, Result as AnyResult, bail};

use crate::pb::graph_action::{ActionResult, ActionTypeDef};
use crate::pb::sekai::{Decision, Lease, Link, Object, ObjectChange, ObjectType};
use crate::storage::{ProviderEventRecord, Result, SqliteStore, StoreError};

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
    /// Write `object` and enqueue `events` in one catalog transaction.
    fn put_with_provider_events(
        &self,
        tenant: Option<&str>,
        object: Object,
        events: &[ProviderEventRecord],
    ) -> AnyResult<Object> {
        if events.is_empty() {
            return self.put(tenant, object);
        }
        anyhow::bail!("catalog cannot atomically enqueue Tenkai provider events")
    }
    fn put_objects_with_provider_events(
        &self,
        tenant: Option<&str>,
        objects: &[Object],
        events: &[ProviderEventRecord],
    ) -> AnyResult<()> {
        if events.is_empty() {
            for object in objects {
                self.put(tenant, object.clone())?;
            }
            return Ok(());
        }
        anyhow::bail!("catalog cannot atomically enqueue Tenkai provider events")
    }
    fn guarded_put_objects_with_provider_events(
        &self,
        tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        events: &[ProviderEventRecord],
    ) -> AnyResult<()> {
        if events.is_empty() {
            return self.guarded_put_many(tenant, objects, namespace, key, fencing_token);
        }
        anyhow::bail!("catalog cannot atomically enqueue Tenkai provider events")
    }
    fn register_schema(&self, tenant: Option<&str>, schema: ObjectType) -> Result<()>;
    fn schemas(&self, tenant: Option<&str>) -> AnyResult<Vec<ObjectType>>;
    fn register_action(&self, tenant: Option<&str>, action: ActionTypeDef) -> Result<()>;
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
}

/// In-memory catalog used by unit tests and tenant-mode hosts without Postgres.
#[derive(Default)]
pub struct MemoryCatalogGraph {
    partitions: Mutex<BTreeMap<String, Partition>>,
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
}

impl MemoryCatalogGraph {
    pub fn new() -> Self {
        Self {
            partitions: Mutex::new(BTreeMap::new()),
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
        partition.objects.insert(object.id.clone(), object.clone());
        Ok(object)
    }

    fn put(&self, tenant: Option<&str>, object: Object) -> AnyResult<Object> {
        let previous = self.get(tenant, &object.id)?;
        let mut partitions = self.lock()?;
        let partition = partitions.entry(Self::key(tenant)).or_default();
        if let Some(previous) = previous {
            record_memory_changes(partition, &previous, &object, &self.principal);
        }
        partition.objects.insert(object.id.clone(), object.clone());
        Ok(object)
    }

    fn delete(&self, tenant: Option<&str>, id: &str) -> AnyResult<()> {
        let mut partitions = self.lock()?;
        let Some(partition) = partitions.get_mut(&Self::key(tenant)) else {
            return Ok(());
        };
        partition.objects.remove(id);
        partition
            .links
            .retain(|_, link| link.from_id != id && link.to_id != id);
        partition.changes.remove(id);
        Ok(())
    }

    fn list_kind(&self, tenant: Option<&str>, kind: &str) -> AnyResult<Vec<Object>> {
        let partitions = self.lock()?;
        let mut objects = partitions
            .get(&Self::key(tenant))
            .map(|partition| {
                partition
                    .objects
                    .values()
                    .filter(|object| object.kind == kind)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        objects.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(objects)
    }

    fn list_kind_ids(&self, tenant: Option<&str>, kind: &str) -> AnyResult<Vec<String>> {
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
        if let Some(previous) = previous {
            record_memory_changes(partition, &previous, &object, &self.principal);
        }
        partition.objects.insert(object.id.clone(), object.clone());
        Ok(object)
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
        )
    }

    fn put_with_provider_events(
        &self,
        tenant: Option<&str>,
        object: Object,
        events: &[ProviderEventRecord],
    ) -> AnyResult<Object> {
        self.put_objects_with_provider_events(tenant, std::slice::from_ref(&object), events)?;
        Ok(object)
    }

    fn put_objects_with_provider_events(
        &self,
        tenant: Option<&str>,
        objects: &[Object],
        events: &[ProviderEventRecord],
    ) -> AnyResult<()> {
        self.apply_objects_with_provider_events(tenant, objects, events, None)
    }

    fn guarded_put_objects_with_provider_events(
        &self,
        tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        events: &[ProviderEventRecord],
    ) -> AnyResult<()> {
        self.apply_objects_with_provider_events(
            tenant,
            &objects,
            events,
            Some((namespace, key, fencing_token)),
        )
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
        let target_id = params.get("id").with_context(|| {
            format!("embedded action {action_name} requires target parameter id")
        })?;
        let mut target = self
            .get(tenant, target_id)?
            .with_context(|| format!("embedded action target {target_id} does not exist"))?;
        let planned_ops = action
            .ops
            .iter()
            .map(|op| op.op.clone())
            .collect::<Vec<_>>();
        if !dry_run {
            for op in &action.ops {
                match op.op.as_str() {
                    "set_property" => {
                        let value = params.get(&op.value_from).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.value_from)
                        })?;
                        target.properties.insert(op.property.clone(), value.clone());
                    }
                    "create_link" => {
                        let to_id = params.get(&op.property).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.property)
                        })?;
                        self.create_link(
                            tenant,
                            Link {
                                id: format!("{target_id}--{}--{to_id}", op.relation),
                                from_id: target_id.clone(),
                                to_id: to_id.clone(),
                                relation: op.relation.clone(),
                                created: crate::now_millis(),
                            },
                            false,
                        )
                        .map_err(anyhow::Error::from)?;
                    }
                    "delete_link" => {
                        let link_id = params.get(&op.value_from).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.value_from)
                        })?;
                        self.unlink(tenant, link_id)?;
                    }
                    other => bail!("unsupported embedded action operation {other:?}"),
                }
            }
            target.updated = crate::now_millis();
            self.put(tenant, target)?;
            self.record_decision(tenant, action_name, target_id, "allow", &params)?;
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
            record_memory_changes(&mut partition, &previous, object, &self.principal);
            partition.objects.insert(object.id.clone(), object.clone());
        }
        for event in &events {
            enqueue_memory_provider_event(&mut partition, event)?;
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

    fn record_decision(
        &self,
        tenant: Option<&str>,
        action: &str,
        target_id: &str,
        outcome: &str,
        params: &HashMap<String, String>,
    ) -> AnyResult<()> {
        let timestamp = crate::now_millis();
        let mut evidence = params.clone();
        evidence.insert("decision".into(), outcome.into());
        let decision = Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            actor: self.principal.clone(),
            action: action.into(),
            reason: "execute_action".into(),
            evidence,
            target_id: target_id.into(),
            outcome: outcome.into(),
        };
        let mut partitions = self.lock()?;
        partitions
            .entry(Self::key(tenant))
            .or_default()
            .decisions
            .push(decision);
        Ok(())
    }
}

fn enqueue_memory_provider_event(
    partition: &mut Partition,
    event: &ProviderEventRecord,
) -> AnyResult<()> {
    super::provider_claims::validate_new_provider_event(event).map_err(anyhow::Error::from)?;
    let key = (event.provider_kind.clone(), event.id.clone());
    if let Some(existing) = partition.events.get(&key) {
        if existing.provider_kind != event.provider_kind
            || existing.binding_digest != event.binding_digest
            || !super::provider_event_payloads_match(&existing.payload_json, &event.payload_json)
        {
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

fn record_memory_changes(
    partition: &mut Partition,
    previous: &Object,
    next: &Object,
    principal: &str,
) {
    let timestamp = crate::now_millis();
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

impl CatalogGraph for SqliteStore {
    fn get(&self, _tenant: Option<&str>, id: &str) -> AnyResult<Option<Object>> {
        SqliteStore::get(self, id)
    }

    fn create(&self, _tenant: Option<&str>, object: Object) -> Result<Object> {
        SqliteStore::create(self, object)
    }

    fn put(&self, _tenant: Option<&str>, object: Object) -> AnyResult<Object> {
        SqliteStore::put(self, object)
    }

    fn delete(&self, _tenant: Option<&str>, id: &str) -> AnyResult<()> {
        SqliteStore::delete(self, id)
    }

    fn list_kind(&self, _tenant: Option<&str>, kind: &str) -> AnyResult<Vec<Object>> {
        SqliteStore::list_kind(self, kind)
    }

    fn list_kind_ids(&self, _tenant: Option<&str>, kind: &str) -> AnyResult<Vec<String>> {
        SqliteStore::list_kind_ids(self, kind)
    }

    fn find_by_property(
        &self,
        _tenant: Option<&str>,
        kind: &str,
        key: &str,
        value: &str,
    ) -> AnyResult<Vec<Object>> {
        SqliteStore::find_by_property(self, kind, key, value)
    }

    fn create_link(&self, _tenant: Option<&str>, link: Link, fail_if_exists: bool) -> Result<()> {
        SqliteStore::create_link(self, link, fail_if_exists)
    }

    fn unlink(&self, _tenant: Option<&str>, id: &str) -> AnyResult<()> {
        SqliteStore::unlink(self, id)
    }

    fn links(
        &self,
        _tenant: Option<&str>,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> AnyResult<Vec<Link>> {
        SqliteStore::links(self, object_id, relation, direction)
    }

    fn linked(
        &self,
        _tenant: Option<&str>,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> AnyResult<Vec<Object>> {
        SqliteStore::linked(self, object_id, relation, direction)
    }

    fn acquire_lease(
        &self,
        _tenant: Option<&str>,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        self.acquire_namespaced_lease(namespace, key, owner, ttl_ms)
    }

    fn get_lease(
        &self,
        _tenant: Option<&str>,
        namespace: &str,
        key: &str,
    ) -> AnyResult<Option<Lease>> {
        self.get_namespaced_lease(namespace, key)
    }

    fn refresh_lease(
        &self,
        _tenant: Option<&str>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        self.refresh_namespaced_lease(namespace, key, fencing_token, ttl_ms)
    }

    fn release_lease(
        &self,
        _tenant: Option<&str>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> AnyResult<Lease> {
        self.release_namespaced_lease(namespace, key, fencing_token)
    }

    #[allow(clippy::too_many_arguments)]
    fn takeover_lease(
        &self,
        _tenant: Option<&str>,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at: i64,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        self.takeover_namespaced_lease(
            namespace,
            key,
            owner,
            expected_token,
            expected_expires_at,
            ttl_ms,
        )
    }

    fn guarded_put(
        &self,
        _tenant: Option<&str>,
        object: Object,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        create: bool,
    ) -> AnyResult<Object> {
        SqliteStore::guarded_put(self, object, namespace, key, fencing_token, create)
    }

    fn guarded_put_many(
        &self,
        _tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> AnyResult<()> {
        SqliteStore::guarded_put_objects_with_provider_events(
            self,
            &objects,
            namespace,
            key,
            fencing_token,
            &[],
            &[],
        )
    }

    fn put_with_provider_events(
        &self,
        _tenant: Option<&str>,
        object: Object,
        events: &[ProviderEventRecord],
    ) -> AnyResult<Object> {
        SqliteStore::put_with_provider_events(self, object, events, &[])
    }

    fn put_objects_with_provider_events(
        &self,
        _tenant: Option<&str>,
        objects: &[Object],
        events: &[ProviderEventRecord],
    ) -> AnyResult<()> {
        SqliteStore::put_objects_with_provider_events(self, objects, events, &[])
    }

    fn guarded_put_objects_with_provider_events(
        &self,
        _tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        events: &[ProviderEventRecord],
    ) -> AnyResult<()> {
        SqliteStore::guarded_put_objects_with_provider_events(
            self,
            &objects,
            namespace,
            key,
            fencing_token,
            events,
            &[],
        )
    }

    fn register_schema(&self, _tenant: Option<&str>, schema: ObjectType) -> Result<()> {
        SqliteStore::register_schema(self, schema)
    }

    fn schemas(&self, _tenant: Option<&str>) -> AnyResult<Vec<ObjectType>> {
        SqliteStore::schemas(self)
    }

    fn register_action(&self, _tenant: Option<&str>, action: ActionTypeDef) -> Result<()> {
        SqliteStore::register_action(self, action)
    }

    fn execute_action(
        &self,
        _tenant: Option<&str>,
        action: &str,
        params: HashMap<String, String>,
        dry_run: bool,
    ) -> AnyResult<ActionResult> {
        SqliteStore::execute_action(self, action, params, dry_run)
    }

    fn decisions(
        &self,
        _tenant: Option<&str>,
        actor: &str,
        action: &str,
        after: i64,
    ) -> AnyResult<Vec<Decision>> {
        SqliteStore::decisions(self, actor, action, after)
    }

    fn changes(&self, _tenant: Option<&str>, object_id: &str) -> AnyResult<Vec<ObjectChange>> {
        SqliteStore::changes(self, object_id)
    }
}

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
        let path = std::env::temp_dir().join(format!(
            "tenkai-764-sqlite-catalog-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&path);
        let store = SqliteStore::open(&path).unwrap();
        assert_graph(&store, None);
        let _ = std::fs::remove_file(path);
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
    fn memory_and_sqlite_execute_action_records_decision() {
        assert_execute_action_records_decision(&MemoryCatalogGraph::new(), Some("tenant-a"));
        let path = std::env::temp_dir().join(format!(
            "tenkai-764-sqlite-action-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&path);
        let store = SqliteStore::open(&path).unwrap();
        assert_execute_action_records_decision(&store, None);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sqlite_environment_retire_refuses_active_apply_lease() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-764-sqlite-retire-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&path);
        let store = SqliteStore::open(&path).unwrap();
        assert_environment_retire_refuses_active_apply_lease(&store, None);
        let _ = std::fs::remove_file(path);
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
        graph
            .put_with_provider_events(tenant, updated.clone(), std::slice::from_ref(&event))
            .unwrap();
        assert_eq!(graph.get(tenant, id).unwrap().unwrap().name, "terminal");
        assert_eq!(list().len(), 1);
        graph
            .put_with_provider_events(tenant, updated.clone(), std::slice::from_ref(&event))
            .unwrap();
        assert_eq!(list().len(), 1);

        let mut conflicting = event.clone();
        conflicting.payload_json =
            r#"{"binding":{"environment_id":"prod"},"payload_json":"{\"different\":true}"}"#.into();
        let mut rolled = updated.clone();
        rolled.name = "must-roll-back".into();
        assert!(
            graph
                .put_with_provider_events(tenant, rolled.clone(), &[conflicting])
                .is_err()
        );
        assert_eq!(graph.get(tenant, id).unwrap().unwrap().name, "terminal");
        assert_eq!(list().len(), 1);

        let mut invalid = event;
        invalid.id.clear();
        rolled.name = "invalid-must-roll-back".into();
        assert!(
            graph
                .put_with_provider_events(tenant, rolled, &[invalid])
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
            )
            .unwrap();
        graph
            .put_with_provider_events(Some("tenant-b"), updated, std::slice::from_ref(&record))
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
    fn sqlite_catalog_enqueues_provider_events_atomically() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-765-sqlite-outbox-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&path);
        let store = SqliteStore::open(&path).unwrap();
        assert_atomic_outbox(&store, None, || {
            crate::storage::OperationalStore::list_provider_events(&store, "outcome", "prod", 8)
                .unwrap()
        });
        let _ = std::fs::remove_file(path);
    }
}
