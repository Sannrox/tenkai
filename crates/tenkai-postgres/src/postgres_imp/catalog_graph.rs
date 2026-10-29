use postgres::Transaction;
use prost::Message;
use tenkai::ontology::{KIND_CHANNEL, KIND_ENVIRONMENT, KIND_PLAN, KIND_RELEASE, NS, env_id};
use tenkai::pb::graph_action::{ActionResult, ActionTypeDef};
use tenkai::pb::sekai::{Decision, Lease, Link, Object, ObjectChange, ObjectType};
use tenkai::plan::Plan;
use tenkai::storage::{
    ChannelRecord, PlanStatus, encode_object, environment_record_to_object, plan_record_to_object,
    release_record_to_object,
};

use super::provider_queue::enqueue_provider_event_in;
use super::*;
use super::{Inner, ensure_environment_active, pg};

const STRICT_AUTHORITY_KINDS: &[&str] = &[KIND_PLAN, KIND_ENVIRONMENT, KIND_RELEASE];
const ENVIRONMENT_LEASE_NAMESPACE: &str = "tenkai/environment-execution";

impl Inner {
    pub fn catalog_get(&self, schema: &str, id: &str) -> Result<Option<Object>> {
        let id = id.to_owned();
        self.with_schema(schema, move |tx| catalog_get_in(tx, &id))
    }

    pub fn catalog_create(&self, schema: &str, object: &Object) -> Result<Object> {
        let object = object.clone();
        self.with_writer_schema(schema, move |tx| {
            lock_environment_writes(tx, &object)?;
            lock_catalog_object(tx, &object.id)?;
            if catalog_get_in(tx, &object.id)?.is_some() {
                return Err(StoreError::already_exists("object", object.id.clone()));
            }
            catalog_put_in(tx, &object)?;
            Ok(object)
        })
    }

    pub fn catalog_put(&self, schema: &str, object: &Object) -> Result<Object> {
        let object = object.clone();
        self.with_writer_schema(schema, move |tx| {
            lock_environment_writes(tx, &object)?;
            lock_catalog_object(tx, &object.id)?;
            let previous = catalog_get_in(tx, &object.id)?;
            catalog_put_in(tx, &object)?;
            if let Some(previous) = previous {
                record_changes_in(tx, &previous, &object)?;
            }
            Ok(object)
        })
    }

    pub fn catalog_delete(&self, schema: &str, id: &str) -> Result<()> {
        let id = id.to_owned();
        self.with_writer_schema(schema, move |tx| {
            if let Some(record) = load_environment(tx, &id)? {
                lock_lease(tx, &record.id)?;
                lock_catalog_apply_leases(tx, &record.id)?;
            }
            lock_catalog_object(tx, &id)?;
            tx.execute("DELETE FROM plans WHERE id=$1", &[&id])
                .map_err(pg)?;
            let environment_id = load_environment(tx, &id)?
                .map(|record| record.id)
                .unwrap_or_else(|| id.clone());
            tx.execute("DELETE FROM environments WHERE id=$1", &[&environment_id])
                .map_err(pg)?;
            tx.execute("DELETE FROM releases WHERE id=$1", &[&id])
                .map_err(pg)?;
            tx.execute("DELETE FROM channels WHERE id=$1", &[&id])
                .map_err(pg)?;
            tx.execute(
                "DELETE FROM catalog_links WHERE from_id=$1 OR to_id=$1",
                &[&id],
            )
            .map_err(pg)?;
            tx.execute(
                "DELETE FROM catalog_object_properties WHERE object_id=$1",
                &[&id],
            )
            .map_err(pg)?;
            tx.execute("DELETE FROM catalog_objects WHERE id=$1", &[&id])
                .map_err(pg)?;
            Ok(())
        })
    }

    pub fn catalog_list_kind(&self, schema: &str, kind: &str) -> Result<Vec<Object>> {
        let kind = kind.to_owned();
        self.with_schema(schema, move |tx| catalog_list_kind_in(tx, &kind))
    }

    pub fn catalog_find_by_property(
        &self,
        schema: &str,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>> {
        if kind.trim().is_empty() || key.trim().is_empty() {
            return Err(StoreError::InvalidData {
                kind: "catalog",
                detail: "find_by_property requires non-empty kind and key".into(),
            });
        }
        let kind = kind.to_owned();
        let key = key.to_owned();
        let value = value.to_owned();
        self.with_schema(schema, move |tx| {
            let rows = tx
                .query(
                    "SELECT o.payload FROM catalog_objects o
                     INNER JOIN catalog_object_properties p
                       ON p.object_id = o.id AND p.kind = $1 AND p.key = $2 AND p.value = $3
                     ORDER BY o.id",
                    &[&kind, &key, &value],
                )
                .map_err(pg)?;
            let mut objects = decode_objects(rows)?;
            // KIND_PLAN overlays plans.status and unions typed-only rows so
            // tenant recovery and plan selection survive upgrade. Other kinds
            // stay sidecar-indexed; HTTP lists use list_kind.
            if kind == KIND_PLAN {
                for object in &mut objects {
                    if let Some(record) = load_plan(tx, &object.id)? {
                        overlay_plan_lifecycle(object, &record)?;
                    }
                }
                objects.retain(|object| {
                    load_plan(tx, &object.id).ok().flatten().is_some()
                        && object_matches_property(object, &key, &value)
                });
                for object in typed_plan_objects_matching(tx, &key, &value)? {
                    if !objects.iter().any(|existing| existing.id == object.id) {
                        objects.push(object);
                    }
                }
                objects.sort_by(|left, right| left.id.cmp(&right.id));
            }
            Ok(objects)
        })
    }

    pub fn catalog_create_link(
        &self,
        schema: &str,
        link: &Link,
        fail_if_exists: bool,
    ) -> Result<()> {
        let link = link.clone();
        self.with_writer_schema(schema, move |tx| {
            let payload = link.encode_to_vec();
            let changed = tx
                .execute(
                    "INSERT INTO catalog_links(id,from_id,to_id,relation,payload)
                     VALUES($1,$2,$3,$4,$5)
                     ON CONFLICT(id) DO NOTHING",
                    &[
                        &link.id,
                        &link.from_id,
                        &link.to_id,
                        &link.relation,
                        &payload,
                    ],
                )
                .map_err(pg)?;
            if fail_if_exists && changed == 0 {
                return Err(StoreError::already_exists("link", link.id.clone()));
            }
            Ok(())
        })
    }

    pub fn catalog_unlink(&self, schema: &str, id: &str) -> Result<()> {
        let id = id.to_owned();
        self.with_writer_schema(schema, move |tx| {
            tx.execute("DELETE FROM catalog_links WHERE id=$1", &[&id])
                .map_err(pg)?;
            Ok(())
        })
    }

    pub fn catalog_links(
        &self,
        schema: &str,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> Result<Vec<Link>> {
        let sql = match direction {
            "out" => {
                "SELECT payload FROM catalog_links WHERE from_id=$1 AND relation=$2 ORDER BY id"
            }
            "in" => "SELECT payload FROM catalog_links WHERE to_id=$1 AND relation=$2 ORDER BY id",
            other => {
                return Err(StoreError::InvalidData {
                    kind: "link",
                    detail: format!("unsupported embedded link direction {other:?}"),
                });
            }
        };
        let object_id = object_id.to_owned();
        let relation = relation.to_owned();
        self.with_schema(schema, move |tx| {
            let rows = tx.query(sql, &[&object_id, &relation]).map_err(pg)?;
            rows.into_iter()
                .map(|row| {
                    let payload: Vec<u8> = row.get(0);
                    Link::decode(payload.as_slice()).map_err(|error| StoreError::InvalidData {
                        kind: "link",
                        detail: error.to_string(),
                    })
                })
                .collect()
        })
    }

    pub fn catalog_acquire_lease(
        &self,
        schema: &str,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        if ttl_ms <= 0 {
            return Err(StoreError::InvalidData {
                kind: "lease",
                detail: "embedded lease TTL must be positive".into(),
            });
        }
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        let owner = owner.to_owned();
        self.with_writer_schema(schema, move |tx| {
            let now = tenkai::now_millis();
            if namespace == ENVIRONMENT_LEASE_NAMESPACE {
                lock_typed_environment_if_present(tx, &key)?;
                lock_catalog_apply_leases(tx, &key)?;
                ensure_environment_active(tx, &key, "new apply leases")?;
                refuse_fixture_environment(tx, &key, "fixture environments are non-executable")?;
            } else {
                lock_catalog_lease(tx, &namespace, &key)?;
            }
            if namespace == ENVIRONMENT_LEASE_NAMESPACE
                && (typed_apply_lease_is_active(tx, &key)?
                    || catalog_apply_lease(tx, &key)?.is_some())
            {
                return Err(StoreError::already_exists(
                    "lease",
                    format!("{namespace}/{key}"),
                ));
            }
            let current = load_lease_in(tx, &namespace, &key)?;
            if namespace != ENVIRONMENT_LEASE_NAMESPACE
                && current
                    .as_ref()
                    .is_some_and(|lease| lease.status == "active" && lease.expires_at_ms > now)
            {
                return Err(StoreError::already_exists(
                    "lease",
                    format!("{namespace}/{key}"),
                ));
            }
            let generation = current
                .as_ref()
                .map(|lease| lease.generation.saturating_add(1))
                .unwrap_or(1);
            let lease = Lease {
                namespace: namespace.clone(),
                key: key.clone(),
                generation,
                fencing_token: uuid::Uuid::new_v4().to_string(),
                owner,
                status: "active".into(),
                acquired_at_ms: now,
                refreshed_at_ms: now,
                expires_at_ms: now.saturating_add(ttl_ms),
                released_at_ms: 0,
                site_id: String::new(),
            };
            save_lease_in(tx, &lease)?;
            Ok(lease)
        })
    }

    pub fn catalog_get_lease(
        &self,
        schema: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<Lease>> {
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        self.with_schema(schema, move |tx| load_lease_in(tx, &namespace, &key))
    }

    pub fn catalog_refresh_lease(
        &self,
        schema: &str,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        if ttl_ms <= 0 {
            return Err(StoreError::InvalidData {
                kind: "lease",
                detail: "embedded lease TTL must be positive".into(),
            });
        }
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        let fencing_token = fencing_token.to_owned();
        self.with_writer_schema(schema, move |tx| {
            lock_catalog_lease(tx, &namespace, &key)?;
            let mut lease = require_active_lease_in(tx, &namespace, &key, &fencing_token)?;
            let now = tenkai::now_millis();
            lease.refreshed_at_ms = now;
            lease.expires_at_ms = now.saturating_add(ttl_ms);
            save_lease_in(tx, &lease)?;
            Ok(lease)
        })
    }

    pub fn catalog_release_lease(
        &self,
        schema: &str,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> Result<Lease> {
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        let fencing_token = fencing_token.to_owned();
        self.with_writer_schema(schema, move |tx| {
            lock_catalog_lease(tx, &namespace, &key)?;
            let mut lease = require_active_lease_in(tx, &namespace, &key, &fencing_token)?;
            lease.status = "released".into();
            lease.released_at_ms = tenkai::now_millis();
            save_lease_in(tx, &lease)?;
            Ok(lease)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn catalog_takeover_lease(
        &self,
        schema: &str,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at: i64,
        ttl_ms: i64,
    ) -> Result<Lease> {
        if ttl_ms <= 0 {
            return Err(StoreError::InvalidData {
                kind: "lease",
                detail: "embedded lease TTL must be positive".into(),
            });
        }
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        let owner = owner.to_owned();
        let expected_token = expected_token.to_owned();
        self.with_writer_schema(schema, move |tx| {
            if namespace == ENVIRONMENT_LEASE_NAMESPACE {
                lock_typed_environment_if_present(tx, &key)?;
                lock_catalog_apply_leases(tx, &key)?;
                ensure_environment_active(tx, &key, "apply lease takeover")?;
                refuse_fixture_environment(tx, &key, "fixture environments are non-executable")?;
                if typed_apply_lease_is_active(tx, &key)?
                    || catalog_apply_lease(tx, &key)?.is_some()
                {
                    return Err(StoreError::InvalidData {
                        kind: "lease",
                        detail: "embedded lease takeover precondition failed".into(),
                    });
                }
            } else {
                lock_catalog_lease(tx, &namespace, &key)?;
            }
            let current =
                load_lease_in(tx, &namespace, &key)?.ok_or_else(|| StoreError::NotFound {
                    kind: "lease",
                    id: format!("{namespace}/{key}"),
                })?;
            if current.fencing_token != expected_token
                || current.expires_at_ms != expected_expires_at
                || current.expires_at_ms > tenkai::now_millis()
            {
                return Err(StoreError::InvalidData {
                    kind: "lease",
                    detail: "embedded lease takeover precondition failed".into(),
                });
            }
            let now = tenkai::now_millis();
            let lease = Lease {
                namespace: namespace.clone(),
                key: key.clone(),
                generation: current.generation.saturating_add(1),
                fencing_token: uuid::Uuid::new_v4().to_string(),
                owner,
                status: "active".into(),
                acquired_at_ms: now,
                refreshed_at_ms: now,
                expires_at_ms: now.saturating_add(ttl_ms),
                released_at_ms: 0,
                site_id: String::new(),
            };
            save_lease_in(tx, &lease)?;
            Ok(lease)
        })
    }

    pub fn catalog_guarded_put(
        &self,
        schema: &str,
        object: &Object,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        create: bool,
    ) -> Result<Object> {
        let object = object.clone();
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        let fencing_token = fencing_token.to_owned();
        self.with_writer_schema(schema, move |tx| {
            if namespace == ENVIRONMENT_LEASE_NAMESPACE {
                lock_typed_environment_if_present(tx, &key)?;
                lock_catalog_apply_leases(tx, &key)?;
            } else {
                lock_catalog_lease(tx, &namespace, &key)?;
            }
            lock_catalog_object(tx, &object.id)?;
            require_active_lease_in(tx, &namespace, &key, &fencing_token)?;
            let previous = catalog_get_in(tx, &object.id)?;
            if create && previous.is_some() {
                return Err(StoreError::already_exists("object", object.id.clone()));
            }
            if !create && previous.is_none() {
                return Err(StoreError::NotFound {
                    kind: "object",
                    id: object.id.clone(),
                });
            }
            catalog_put_in(tx, &object)?;
            if let Some(previous) = previous {
                record_changes_in(tx, &previous, &object)?;
            }
            Ok(object)
        })
    }

    pub fn catalog_guarded_put_many(
        &self,
        schema: &str,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> Result<()> {
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        let fencing_token = fencing_token.to_owned();
        self.with_writer_schema(schema, move |tx| {
            if namespace == ENVIRONMENT_LEASE_NAMESPACE {
                lock_typed_environment_if_present(tx, &key)?;
                lock_catalog_apply_leases(tx, &key)?;
            } else {
                lock_catalog_lease(tx, &namespace, &key)?;
            }
            require_active_lease_in(tx, &namespace, &key, &fencing_token)?;
            for object in objects {
                lock_environment_writes(tx, &object)?;
                lock_catalog_object(tx, &object.id)?;
                let previous = catalog_get_in(tx, &object.id)?;
                if previous.is_none() {
                    return Err(StoreError::NotFound {
                        kind: "object",
                        id: object.id.clone(),
                    });
                }
                catalog_put_in(tx, &object)?;
                if let Some(previous) = previous {
                    record_changes_in(tx, &previous, &object)?;
                }
            }
            Ok(())
        })
    }

    pub fn catalog_put_objects_with_provider_events(
        &self,
        schema: &str,
        objects: &[Object],
        events: &[ProviderEventRecord],
    ) -> Result<()> {
        if objects.is_empty() {
            return Err(StoreError::InvalidData {
                kind: "catalog",
                detail: "object update is empty".into(),
            });
        }
        let objects = objects.to_vec();
        let events = events.to_vec();
        self.with_writer_schema(schema, move |tx| {
            catalog_put_objects_with_provider_events_in(tx, &objects, &events, None)
        })
    }

    pub fn catalog_guarded_put_objects_with_provider_events(
        &self,
        schema: &str,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        events: &[ProviderEventRecord],
    ) -> Result<()> {
        if objects.is_empty() {
            return Err(StoreError::InvalidData {
                kind: "catalog",
                detail: "object update is empty".into(),
            });
        }
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        let fencing_token = fencing_token.to_owned();
        let events = events.to_vec();
        self.with_writer_schema(schema, move |tx| {
            catalog_put_objects_with_provider_events_in(
                tx,
                &objects,
                &events,
                Some((namespace.as_str(), key.as_str(), fencing_token.as_str())),
            )
        })
    }

    pub fn catalog_register_schema(&self, schema: &str, object_type: &ObjectType) -> Result<()> {
        let object_type = object_type.clone();
        self.with_writer_schema(schema, move |tx| {
            let payload = object_type.encode_to_vec();
            tx.execute(
                "INSERT INTO catalog_schema_types(name,payload) VALUES($1,$2)
                 ON CONFLICT(name) DO UPDATE SET payload=EXCLUDED.payload",
                &[&object_type.kind, &payload],
            )
            .map_err(pg)?;
            Ok(())
        })
    }

    pub fn catalog_schemas(&self, schema: &str) -> Result<Vec<ObjectType>> {
        self.with_schema(schema, move |tx| {
            let rows = tx
                .query("SELECT payload FROM catalog_schema_types", &[])
                .map_err(pg)?;
            rows.into_iter()
                .map(|row| {
                    let payload: Vec<u8> = row.get(0);
                    ObjectType::decode(payload.as_slice()).map_err(|error| {
                        StoreError::InvalidData {
                            kind: "schema",
                            detail: error.to_string(),
                        }
                    })
                })
                .collect()
        })
    }

    pub fn catalog_register_action(&self, schema: &str, action: &ActionTypeDef) -> Result<()> {
        let action = action.clone();
        self.with_writer_schema(schema, move |tx| {
            let payload = action.encode_to_vec();
            tx.execute(
                "INSERT INTO catalog_action_types(name,payload) VALUES($1,$2)
                 ON CONFLICT(name) DO UPDATE SET payload=EXCLUDED.payload",
                &[&action.name, &payload],
            )
            .map_err(pg)?;
            Ok(())
        })
    }

    pub fn catalog_execute_action(
        &self,
        schema: &str,
        action_name: &str,
        params: &std::collections::HashMap<String, String>,
        dry_run: bool,
    ) -> Result<ActionResult> {
        let action_name = action_name.to_owned();
        let params = params.clone();
        self.with_writer_schema(schema, move |tx| {
            let payload = tx
                .query_opt(
                    "SELECT payload FROM catalog_action_types WHERE name=$1",
                    &[&action_name],
                )
                .map_err(pg)?
                .map(|row| row.get::<_, Vec<u8>>(0))
                .ok_or_else(|| StoreError::NotFound {
                    kind: "action",
                    id: action_name.clone(),
                })?;
            let action = ActionTypeDef::decode(payload.as_slice()).map_err(|error| {
                StoreError::InvalidData {
                    kind: "action",
                    detail: error.to_string(),
                }
            })?;
            let target_id = params.get("id").ok_or_else(|| StoreError::InvalidData {
                kind: "action",
                detail: format!("embedded action {action_name} requires target parameter id"),
            })?;
            if let Some(record) = load_environment(tx, target_id)? {
                lock_lease(tx, &record.id)?;
                lock_catalog_apply_leases(tx, &record.id)?;
            } else if let Some(plan) = load_plan(tx, target_id)? {
                lock_typed_environment_if_present(tx, &plan.environment_id)?;
                lock_catalog_apply_leases(tx, &plan.environment_id)?;
            }
            lock_catalog_object(tx, target_id)?;
            let mut target =
                catalog_get_in(tx, target_id)?.ok_or_else(|| StoreError::NotFound {
                    kind: "object",
                    id: target_id.clone(),
                })?;
            let previous = target.clone();
            let planned_ops = action
                .ops
                .iter()
                .map(|op| op.op.clone())
                .collect::<Vec<_>>();
            if !dry_run {
                for op in &action.ops {
                    match op.op.as_str() {
                        "set_property" => {
                            let value = params.get(&op.value_from).ok_or_else(|| {
                                StoreError::InvalidData {
                                    kind: "action",
                                    detail: format!(
                                        "embedded action {action_name} requires {}",
                                        op.value_from
                                    ),
                                }
                            })?;
                            target.properties.insert(op.property.clone(), value.clone());
                        }
                        "create_link" => {
                            let to_id = params.get(&op.property).ok_or_else(|| {
                                StoreError::InvalidData {
                                    kind: "action",
                                    detail: format!(
                                        "embedded action {action_name} requires {}",
                                        op.property
                                    ),
                                }
                            })?;
                            let link = Link {
                                id: format!("{target_id}--{}--{to_id}", op.relation),
                                from_id: target_id.clone(),
                                to_id: to_id.clone(),
                                relation: op.relation.clone(),
                                created: tenkai::now_millis(),
                            };
                            let payload = link.encode_to_vec();
                            tx.execute(
                                "INSERT INTO catalog_links(id,from_id,to_id,relation,payload)
                                 VALUES($1,$2,$3,$4,$5)
                                 ON CONFLICT(id) DO NOTHING",
                                &[
                                    &link.id,
                                    &link.from_id,
                                    &link.to_id,
                                    &link.relation,
                                    &payload,
                                ],
                            )
                            .map_err(pg)?;
                        }
                        "delete_link" => {
                            let link_id = params.get(&op.value_from).ok_or_else(|| {
                                StoreError::InvalidData {
                                    kind: "action",
                                    detail: format!(
                                        "embedded action {action_name} requires {}",
                                        op.value_from
                                    ),
                                }
                            })?;
                            tx.execute("DELETE FROM catalog_links WHERE id=$1", &[link_id])
                                .map_err(pg)?;
                        }
                        other => {
                            return Err(StoreError::InvalidData {
                                kind: "action",
                                detail: format!("unsupported embedded action operation {other:?}"),
                            });
                        }
                    }
                }
                target.updated = tenkai::now_millis();
                catalog_put_in(tx, &target)?;
                record_changes_in(tx, &previous, &target)?;
                record_decision_in(tx, &action_name, target_id, "allow", &params)?;
            }
            Ok(ActionResult {
                action: action_name,
                message: "allowed by embedded host policy".into(),
                dry_run,
                planned_ops,
                decision: "allow".into(),
                approval_id: String::new(),
            })
        })
    }

    pub fn catalog_decisions(
        &self,
        schema: &str,
        actor: &str,
        action: &str,
        after: i64,
    ) -> Result<Vec<Decision>> {
        let actor = actor.to_owned();
        let action = action.to_owned();
        self.with_schema(schema, move |tx| {
            let rows = tx
                .query(
                    "SELECT payload FROM catalog_decisions
                     WHERE ($1='' OR actor=$1) AND ($2='' OR action=$2) AND timestamp>$3
                     ORDER BY timestamp,id",
                    &[&actor, &action, &after],
                )
                .map_err(pg)?;
            rows.into_iter()
                .map(|row| {
                    let payload: Vec<u8> = row.get(0);
                    Decision::decode(payload.as_slice()).map_err(|error| StoreError::InvalidData {
                        kind: "decision",
                        detail: error.to_string(),
                    })
                })
                .collect()
        })
    }

    pub fn catalog_changes(&self, schema: &str, object_id: &str) -> Result<Vec<ObjectChange>> {
        let object_id = object_id.to_owned();
        self.with_schema(schema, move |tx| {
            let rows = tx
                .query(
                    "SELECT payload FROM catalog_changes WHERE object_id=$1 ORDER BY timestamp,id",
                    &[&object_id],
                )
                .map_err(pg)?;
            rows.into_iter()
                .map(|row| {
                    let payload: Vec<u8> = row.get(0);
                    ObjectChange::decode(payload.as_slice()).map_err(|error| {
                        StoreError::InvalidData {
                            kind: "object change",
                            detail: error.to_string(),
                        }
                    })
                })
                .collect()
        })
    }
}

fn catalog_get_in(tx: &mut Transaction<'_>, id: &str) -> Result<Option<Object>> {
    if let Some(record) = load_plan(tx, id)? {
        if let Some(mut stored) = load_catalog_object(tx, id)? {
            overlay_plan_lifecycle(&mut stored, &record)?;
            return Ok(Some(stored));
        }
        return plan_record_to_object(&record)
            .map(Some)
            .map_err(|error| StoreError::InvalidData {
                kind: "plan",
                detail: error.to_string(),
            });
    }
    if let Some(record) = load_environment(tx, id)? {
        let mut object =
            environment_record_to_object(&record).map_err(|error| StoreError::InvalidData {
                kind: "environment",
                detail: error.to_string(),
            })?;
        object.id = env_id(&object.name);
        return Ok(Some(object));
    }
    if let Some(record) = load_release(tx, id)? {
        return release_record_to_object(&record)
            .map(Some)
            .map_err(|error| StoreError::InvalidData {
                kind: "release",
                detail: error.to_string(),
            });
    }
    if let Some(record) = load_channel(tx, id)? {
        let mut object = load_catalog_object(tx, id)?
            .unwrap_or_else(|| tenkai::storage::channel_record_to_object(&record));
        overlay_channel_head(tx, &mut object, &record)?;
        return Ok(Some(object));
    }
    Ok(load_catalog_object(tx, id)?
        .filter(|object| !STRICT_AUTHORITY_KINDS.contains(&object.kind.as_str())))
}

fn catalog_list_kind_in(tx: &mut Transaction<'_>, kind: &str) -> Result<Vec<Object>> {
    let ids: Vec<String> = match kind {
        KIND_ENVIRONMENT => tx
            .query(
                "SELECT id FROM environments WHERE retired_at IS NULL ORDER BY id ASC",
                &[],
            )
            .map_err(pg)?
            .into_iter()
            .map(|row| row.get(0))
            .collect(),
        KIND_RELEASE => tx
            .query("SELECT id FROM releases ORDER BY id", &[])
            .map_err(pg)?
            .into_iter()
            .map(|row| row.get(0))
            .collect(),
        KIND_PLAN => tx
            .query("SELECT id FROM plans ORDER BY id", &[])
            .map_err(pg)?
            .into_iter()
            .map(|row| row.get(0))
            .collect(),
        KIND_CHANNEL => {
            let mut ids: Vec<String> = tx
                .query("SELECT id FROM channels ORDER BY id", &[])
                .map_err(pg)?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            let catalog = tx
                .query(
                    "SELECT id FROM catalog_objects WHERE kind=$1 ORDER BY id",
                    &[&kind],
                )
                .map_err(pg)?;
            for row in catalog {
                let id: String = row.get(0);
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            ids.sort();
            ids
        }
        _ => {
            return decode_objects(
                tx.query(
                    "SELECT payload FROM catalog_objects WHERE kind=$1 ORDER BY id",
                    &[&kind],
                )
                .map_err(pg)?,
            );
        }
    };
    ids.into_iter()
        .map(|id| catalog_get_in(tx, &id)?.ok_or(StoreError::NotFound { kind: "object", id }))
        .collect()
}

fn catalog_put_objects_with_provider_events_in(
    tx: &mut Transaction<'_>,
    objects: &[Object],
    events: &[ProviderEventRecord],
    lease: Option<(&str, &str, &str)>,
) -> Result<()> {
    let unique = objects
        .iter()
        .map(|object| object.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if unique.len() != objects.len() {
        return Err(StoreError::InvalidData {
            kind: "catalog",
            detail: "object update contains duplicate identities".into(),
        });
    }
    if let Some((namespace, key, fencing_token)) = lease {
        if namespace == ENVIRONMENT_LEASE_NAMESPACE {
            lock_typed_environment_if_present(tx, key)?;
            lock_catalog_apply_leases(tx, key)?;
        } else {
            lock_catalog_lease(tx, namespace, key)?;
        }
        require_active_lease_in(tx, namespace, key, fencing_token)?;
    }
    for object in objects {
        lock_environment_writes(tx, object)?;
        lock_catalog_object(tx, &object.id)?;
        let previous = catalog_get_in(tx, &object.id)?;
        if previous.is_none() {
            return Err(StoreError::NotFound {
                kind: "object",
                id: object.id.clone(),
            });
        }
        catalog_put_in(tx, object)?;
        if let Some(previous) = previous {
            record_changes_in(tx, &previous, object)?;
        }
    }
    for event in events {
        enqueue_provider_event_in(tx, event)?;
    }
    Ok(())
}

fn catalog_put_in(tx: &mut Transaction<'_>, object: &Object) -> Result<()> {
    match object.kind.as_str() {
        KIND_ENVIRONMENT => upsert_environment(tx, object)?,
        KIND_RELEASE => upsert_release(tx, object)?,
        KIND_CHANNEL => upsert_channel(tx, object)?,
        KIND_PLAN => upsert_plan(tx, object)?,
        _ => {}
    }
    upsert_catalog_sidecar(tx, object)
}

fn upsert_catalog_sidecar(tx: &mut Transaction<'_>, object: &Object) -> Result<()> {
    let payload = object.encode_to_vec();
    tx.execute(
        "INSERT INTO catalog_objects(id,kind,payload) VALUES($1,$2,$3)
         ON CONFLICT(id) DO UPDATE SET kind=EXCLUDED.kind, payload=EXCLUDED.payload",
        &[&object.id, &object.kind, &payload],
    )
    .map_err(pg)?;
    tx.execute(
        "DELETE FROM catalog_object_properties WHERE object_id=$1",
        &[&object.id],
    )
    .map_err(pg)?;
    for (key, value) in &object.properties {
        tx.execute(
            "INSERT INTO catalog_object_properties(object_id,kind,key,value)
             VALUES($1,$2,$3,$4)",
            &[&object.id, &object.kind, key, value],
        )
        .map_err(pg)?;
    }
    Ok(())
}

fn upsert_environment(tx: &mut Transaction<'_>, object: &Object) -> Result<()> {
    let row_id = environment_row_id(tx, object)?;
    refuse_fixture_environment(tx, &row_id, "fixture environments are immutable")?;
    lock_typed_environment_if_present(tx, &row_id)?;
    lock_catalog_apply_leases(tx, &row_id)?;
    let existing = tx
        .query_opt(
            "SELECT revision,configuration_json FROM environments WHERE id=$1",
            &[&row_id],
        )
        .map_err(pg)?;
    let was_retired = existing.as_ref().is_some_and(|row| {
        tenkai::environment::retirement_from_configuration_json(&row.get::<_, String>(1)).is_some()
    });
    if was_retired {
        return Err(StoreError::InvalidData {
            kind: "environment",
            detail: format!(
                "environment {} is retired and cannot be updated",
                object.name
            ),
        });
    }
    let configuration = encode_object(object);
    if tenkai::environment::retirement_from_configuration_json(&configuration).is_some() {
        refuse_retire_while_active(tx, &row_id, &object.name)?;
    }
    let next = existing
        .as_ref()
        .map(|row| row.get::<_, i64>(0) + 1)
        .unwrap_or(1);
    let retired_at = tenkai::environment::retirement_from_configuration_json(&configuration)
        .map(|retirement| retirement.retired_at);
    tx.execute(
        "INSERT INTO environments(id,revision,configuration_json,retired_at)
         VALUES($1,$2,$3,$4)
         ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,
           configuration_json=EXCLUDED.configuration_json, retired_at=EXCLUDED.retired_at",
        &[&row_id, &next, &configuration, &retired_at],
    )
    .map_err(pg)?;
    Ok(())
}

fn refuse_retire_while_active(
    tx: &mut Transaction<'_>,
    environment: &str,
    display_name: &str,
) -> Result<()> {
    let now = tenkai::now_millis();
    let keys = apply_lease_keys(environment);
    let key0 = keys[0].as_str();
    let key1 = keys.get(1).map(String::as_str).unwrap_or(key0);
    let active_runtime_claim: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM runtime_claims
             WHERE (environment_id=$1 OR environment_id=$2)
               AND expires_at>$3 AND completion_json IS NULL)",
            &[&key0, &key1, &now],
        )
        .map_err(pg)?
        .get(0);
    if active_runtime_claim
        || typed_apply_lease_is_active(tx, environment)?
        || catalog_apply_lease(tx, environment)?.is_some()
    {
        return Err(StoreError::InvalidData {
            kind: "environment",
            detail: format!("environment {display_name} has active delivery work"),
        });
    }
    Ok(())
}

fn upsert_release(tx: &mut Transaction<'_>, object: &Object) -> Result<()> {
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
    let descriptor = encode_object(object);
    if let Some(existing) = tx
        .query_opt(
            "SELECT content_digest FROM releases WHERE id=$1",
            &[&object.id],
        )
        .map_err(pg)?
    {
        let stored: String = existing.get(0);
        if stored != digest {
            return Err(StoreError::ImmutableConflict {
                kind: "release",
                id: object.id.clone(),
            });
        }
        tx.execute(
            "UPDATE releases SET descriptor_json=$2 WHERE id=$1",
            &[&object.id, &descriptor],
        )
        .map_err(pg)?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO releases(id,product,version,content_digest,descriptor_json)
         VALUES($1,$2,$3,$4,$5)",
        &[&object.id, &product, &version, &digest, &descriptor],
    )
    .map_err(pg)?;
    Ok(())
}

fn upsert_channel(tx: &mut Transaction<'_>, object: &Object) -> Result<()> {
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
    let release_exists = !release.is_empty()
        && tx
            .query_opt("SELECT 1 FROM releases WHERE id=$1", &[&release])
            .map_err(pg)?
            .is_some();
    if !release_exists {
        return Ok(());
    }
    let revision = tx
        .query_opt("SELECT revision FROM channels WHERE id=$1", &[&object.id])
        .map_err(pg)?
        .map(|row| row.get::<_, i64>(0) + 1)
        .unwrap_or(1);
    tx.execute(
        "INSERT INTO channels(id,product,name,release_id,revision) VALUES($1,$2,$3,$4,$5)
         ON CONFLICT(id) DO UPDATE SET release_id=EXCLUDED.release_id, revision=EXCLUDED.revision",
        &[&object.id, &product, &name, &release, &revision],
    )
    .map_err(pg)?;
    Ok(())
}

fn upsert_plan(tx: &mut Transaction<'_>, object: &Object) -> Result<()> {
    let Some(raw) = object.properties.get("plan") else {
        return Ok(());
    };
    let Ok(plan) = serde_json::from_str::<Plan>(raw) else {
        return Ok(());
    };
    lock_typed_environment_if_present(tx, &plan.environment)?;
    lock_catalog_apply_leases(tx, &plan.environment)?;
    let plan_exists: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM plans WHERE id=$1)",
            &[&object.id],
        )
        .map_err(pg)?
        .get(0);
    if !plan_exists {
        ensure_environment_active(tx, &plan.environment, "new plans")?;
    }
    let environment_id = match load_environment(tx, &plan.environment)? {
        Some(record) => record.id,
        None => {
            let environment_id = plan.environment.clone();
            let configuration = encode_object(&Object {
                id: env_id(&plan.environment),
                kind: KIND_ENVIRONMENT.into(),
                name: plan.environment.clone(),
                namespace: NS.into(),
                ..Object::default()
            });
            tx.execute(
                "INSERT INTO environments(id,revision,configuration_json) VALUES($1,1,$2)",
                &[&environment_id, &configuration],
            )
            .map_err(pg)?;
            environment_id
        }
    };
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
    let format = plan.format_version as i32;
    tx.execute(
        "INSERT INTO plans(id,environment_id,format_version,content_digest,plan_json,status,status_detail)
         VALUES($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT(id) DO UPDATE SET
            status=EXCLUDED.status,
            status_detail=EXCLUDED.status_detail,
            plan_json=EXCLUDED.plan_json",
        &[
            &object.id,
            &environment_id,
            &format,
            &digest,
            raw,
            &status.as_str(),
            &plan.status_detail,
        ],
    )
    .map_err(pg)?;
    Ok(())
}

fn load_catalog_object(tx: &mut Transaction<'_>, id: &str) -> Result<Option<Object>> {
    tx.query_opt("SELECT payload FROM catalog_objects WHERE id=$1", &[&id])
        .map_err(pg)?
        .map(|row| {
            let payload: Vec<u8> = row.get(0);
            Object::decode(payload.as_slice()).map_err(|error| StoreError::InvalidData {
                kind: "object",
                detail: error.to_string(),
            })
        })
        .transpose()
}

fn load_environment_exact(
    tx: &mut Transaction<'_>,
    id: &str,
) -> Result<Option<tenkai::storage::EnvironmentRecord>> {
    Ok(tx
        .query_opt(
            "SELECT id, revision, configuration_json FROM environments WHERE id=$1",
            &[&id],
        )
        .map_err(pg)?
        .map(|row| tenkai::storage::EnvironmentRecord {
            id: row.get(0),
            revision: row.get::<_, i64>(1) as u64,
            configuration_json: row.get(2),
        }))
}

fn load_environment(
    tx: &mut Transaction<'_>,
    id: &str,
) -> Result<Option<tenkai::storage::EnvironmentRecord>> {
    if let Some(record) = load_environment_exact(tx, id)? {
        return Ok(Some(record));
    }
    if let Some(name) = id.strip_prefix("tenkai:env:")
        && let Some(record) = load_environment_exact(tx, name)?
    {
        return Ok(Some(record));
    }
    if !id.starts_with("tenkai:env:") {
        return load_environment_exact(tx, &env_id(id));
    }
    Ok(None)
}

fn environment_row_id(tx: &mut Transaction<'_>, object: &Object) -> Result<String> {
    if load_environment_exact(tx, &object.id)?.is_some() {
        return Ok(object.id.clone());
    }
    if !object.name.is_empty() && load_environment_exact(tx, &object.name)?.is_some() {
        return Ok(object.name.clone());
    }
    if !object.name.is_empty() && object.id == env_id(&object.name) {
        return Ok(object.name.clone());
    }
    Ok(object.id.clone())
}

fn lock_environment_writes(tx: &mut Transaction<'_>, object: &Object) -> Result<()> {
    let key = match object.kind.as_str() {
        KIND_ENVIRONMENT if !object.name.is_empty() => object.name.as_str(),
        KIND_ENVIRONMENT => object.id.as_str(),
        KIND_PLAN => object
            .properties
            .get("environment")
            .map(String::as_str)
            .unwrap_or(""),
        _ => return Ok(()),
    };
    if key.is_empty() {
        return Ok(());
    }
    lock_typed_environment_if_present(tx, key)?;
    lock_catalog_apply_leases(tx, key)
}

fn object_matches_property(object: &Object, key: &str, value: &str) -> bool {
    object.properties.get(key) == Some(&value.to_string())
        || (key == "environment"
            && apply_lease_keys(value)
                .iter()
                .any(|alias| object.properties.get("environment") == Some(alias)))
}

fn lock_catalog_object(tx: &mut Transaction<'_>, id: &str) -> Result<()> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(
            hashtextextended(current_schema() || ':catalog_object:' || $1, 0)
         )",
        &[&id],
    )
    .map_err(pg)?;
    Ok(())
}

fn lock_catalog_lease(tx: &mut Transaction<'_>, namespace: &str, key: &str) -> Result<()> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(
            hashtextextended(current_schema() || ':catalog_lease:' || $1 || '/' || $2, 0)
         )",
        &[&namespace, &key],
    )
    .map_err(pg)?;
    Ok(())
}

fn apply_lease_keys(environment: &str) -> Vec<String> {
    let name = environment
        .strip_prefix("tenkai:env:")
        .unwrap_or(environment);
    let mut keys = vec![name.to_string(), env_id(name)];
    keys.sort();
    keys.dedup();
    keys
}

/// Catalog apply keys for `name` and `tenkai:env:<name>`, locked in sorted order.
pub(crate) fn lock_catalog_apply_leases(tx: &mut Transaction<'_>, environment: &str) -> Result<()> {
    for key in apply_lease_keys(environment) {
        lock_catalog_lease(tx, ENVIRONMENT_LEASE_NAMESPACE, &key)?;
    }
    Ok(())
}

pub(crate) fn catalog_apply_lease(
    tx: &mut Transaction<'_>,
    environment: &str,
) -> Result<Option<Lease>> {
    let now = tenkai::now_millis();
    for key in apply_lease_keys(environment) {
        if let Some(lease) = load_lease_in(tx, ENVIRONMENT_LEASE_NAMESPACE, &key)?
            && lease.status == "active"
            && lease.expires_at_ms > now
        {
            return Ok(Some(lease));
        }
    }
    Ok(None)
}

fn typed_apply_lease_is_active(tx: &mut Transaction<'_>, key: &str) -> Result<bool> {
    let now = tenkai::now_millis();
    let mut ids = apply_lease_keys(key);
    if let Some(record) = load_environment(tx, key)? {
        ids.push(record.id);
        ids.sort();
        ids.dedup();
    }
    for id in ids {
        if super::leases::lease_in(tx, &id)?.is_some_and(|lease| lease.expires_at > now) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn refuse_fixture_environment(
    tx: &mut Transaction<'_>,
    environment: &str,
    detail: &str,
) -> Result<()> {
    let env_id = env_id(environment);
    let fixture: bool = tx
        .query_one(
            "SELECT EXISTS(
                SELECT 1 FROM development_fixture_objects
                WHERE object_kind='environment' AND (object_id=$1 OR object_id=$2)
             )",
            &[&environment, &env_id],
        )
        .map_err(pg)?
        .get(0);
    if fixture {
        return Err(StoreError::InvalidData {
            kind: "development_fixture",
            detail: detail.into(),
        });
    }
    Ok(())
}

fn lock_typed_environment_if_present(tx: &mut Transaction<'_>, key: &str) -> Result<()> {
    if let Some(record) = load_environment(tx, key)? {
        lock_lease(tx, &record.id)?;
    }
    Ok(())
}

pub(crate) fn catalog_apply_lease_is_active(
    tx: &mut Transaction<'_>,
    environment: &str,
) -> Result<bool> {
    Ok(catalog_apply_lease(tx, environment)?.is_some())
}

fn load_release(
    tx: &mut Transaction<'_>,
    id: &str,
) -> Result<Option<tenkai::storage::ReleaseRecord>> {
    Ok(tx
        .query_opt(
            "SELECT id,product,version,content_digest,descriptor_json FROM releases WHERE id=$1",
            &[&id],
        )
        .map_err(pg)?
        .map(|row| tenkai::storage::ReleaseRecord {
            id: row.get(0),
            product: row.get(1),
            version: row.get(2),
            content_digest: row.get(3),
            descriptor_json: row.get(4),
        }))
}

fn load_channel(tx: &mut Transaction<'_>, id: &str) -> Result<Option<ChannelRecord>> {
    Ok(tx
        .query_opt(
            "SELECT id,product,name,release_id,revision FROM channels WHERE id=$1",
            &[&id],
        )
        .map_err(pg)?
        .map(|row| ChannelRecord {
            id: row.get(0),
            product: row.get(1),
            name: row.get(2),
            release_id: row.get(3),
            revision: row.get::<_, i64>(4) as u64,
        }))
}

// Typed channels.current_release is the head. Planning and apply admission
// require current_version and channel as well; a sidecar-only overlay would
// skip typed-only heads after upgrade and keep a stale version after promote.
fn overlay_channel_head(
    tx: &mut Transaction<'_>,
    object: &mut Object,
    record: &ChannelRecord,
) -> Result<()> {
    object
        .properties
        .insert("product".into(), record.product.clone());
    object.properties.insert("name".into(), record.name.clone());
    object
        .properties
        .insert("channel".into(), record.name.clone());
    object
        .properties
        .insert("current_release".into(), record.release_id.clone());
    if let Some(release) = load_release(tx, &record.release_id)? {
        object
            .properties
            .insert("current_version".into(), release.version);
    }
    Ok(())
}

fn overlay_plan_lifecycle(object: &mut Object, record: &tenkai::storage::PlanRecord) -> Result<()> {
    let authoritative = plan_record_to_object(record).map_err(|error| StoreError::InvalidData {
        kind: "plan",
        detail: error.to_string(),
    })?;
    for key in ["status", "plan"] {
        if let Some(value) = authoritative.properties.get(key) {
            object.properties.insert(key.to_string(), value.clone());
        }
    }
    Ok(())
}

fn typed_plan_objects_matching(
    tx: &mut Transaction<'_>,
    key: &str,
    value: &str,
) -> Result<Vec<Object>> {
    let aliases = apply_lease_keys(value);
    let key0 = aliases[0].as_str();
    let key1 = aliases.get(1).map(String::as_str).unwrap_or(key0);
    let rows = match key {
        "environment" => tx
            .query(
                "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail
                 FROM plans WHERE environment_id=$1 OR environment_id=$2",
                &[&key0, &key1],
            )
            .map_err(pg)?,
        "status" => tx
            .query(
                "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail
                 FROM plans WHERE status=$1",
                &[&value],
            )
            .map_err(pg)?,
        _ => tx
            .query(
                "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail
                 FROM plans",
                &[],
            )
            .map_err(pg)?,
    };
    let mut objects = Vec::new();
    for row in rows {
        let status: String = row.get(5);
        let record = tenkai::storage::PlanRecord {
            id: row.get(0),
            environment_id: row.get(1),
            format_version: row.get::<_, i32>(2) as u32,
            content_digest: row.get(3),
            plan_json: row.get(4),
            status: PlanStatus::parse(&status)?,
            status_detail: row.get(6),
        };
        let object = plan_record_to_object(&record).map_err(|error| StoreError::InvalidData {
            kind: "plan",
            detail: error.to_string(),
        })?;
        let matches = object.properties.get(key) == Some(&value.to_string())
            || (key == "environment"
                && aliases.iter().any(|alias| {
                    object.properties.get("environment") == Some(alias)
                        || record.environment_id == *alias
                }));
        if matches {
            objects.push(object);
        }
    }
    Ok(objects)
}

fn load_plan(tx: &mut Transaction<'_>, id: &str) -> Result<Option<tenkai::storage::PlanRecord>> {
    tx.query_opt(
        "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail
         FROM plans WHERE id=$1",
        &[&id],
    )
    .map_err(pg)?
    .map(|row| {
        let status: String = row.get(5);
        Ok(tenkai::storage::PlanRecord {
            id: row.get(0),
            environment_id: row.get(1),
            format_version: row.get::<_, i32>(2) as u32,
            content_digest: row.get(3),
            plan_json: row.get(4),
            status: PlanStatus::parse(&status)?,
            status_detail: row.get(6),
        })
    })
    .transpose()
}

fn load_lease_in(tx: &mut Transaction<'_>, namespace: &str, key: &str) -> Result<Option<Lease>> {
    tx.query_opt(
        "SELECT payload FROM catalog_leases WHERE namespace=$1 AND lease_key=$2",
        &[&namespace, &key],
    )
    .map_err(pg)?
    .map(|row| {
        let payload: Vec<u8> = row.get(0);
        Lease::decode(payload.as_slice()).map_err(|error| StoreError::InvalidData {
            kind: "lease",
            detail: error.to_string(),
        })
    })
    .transpose()
}

fn require_active_lease_in(
    tx: &mut Transaction<'_>,
    namespace: &str,
    key: &str,
    fencing_token: &str,
) -> Result<Lease> {
    let lease = load_lease_in(tx, namespace, key)?.ok_or_else(|| StoreError::NotFound {
        kind: "lease",
        id: format!("{namespace}/{key}"),
    })?;
    if lease.status != "active"
        || lease.fencing_token != fencing_token
        || lease.expires_at_ms <= tenkai::now_millis()
    {
        return Err(StoreError::InvalidData {
            kind: "lease",
            detail: format!("embedded lease {namespace}/{key} is not the active fenced holder"),
        });
    }
    Ok(lease)
}

fn save_lease_in(tx: &mut Transaction<'_>, lease: &Lease) -> Result<()> {
    let payload = lease.encode_to_vec();
    tx.execute(
        "INSERT INTO catalog_leases(namespace,lease_key,payload) VALUES($1,$2,$3)
         ON CONFLICT(namespace,lease_key) DO UPDATE SET payload=EXCLUDED.payload",
        &[&lease.namespace, &lease.key, &payload],
    )
    .map_err(pg)?;
    Ok(())
}

fn record_decision_in(
    tx: &mut Transaction<'_>,
    action: &str,
    target_id: &str,
    outcome: &str,
    params: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let timestamp = tenkai::now_millis();
    let mut evidence = params.clone();
    evidence.insert("decision".into(), outcome.into());
    let decision = Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp,
        actor: "tenkai".into(),
        action: action.into(),
        reason: "execute_action".into(),
        evidence,
        target_id: target_id.into(),
        outcome: outcome.into(),
    };
    let payload = decision.encode_to_vec();
    tx.execute(
        "INSERT INTO catalog_decisions(id,timestamp,actor,action,payload)
         VALUES($1,$2,$3,$4,$5)",
        &[
            &decision.id,
            &decision.timestamp,
            &decision.actor,
            &decision.action,
            &payload,
        ],
    )
    .map_err(pg)?;
    Ok(())
}

fn record_changes_in(tx: &mut Transaction<'_>, previous: &Object, next: &Object) -> Result<()> {
    let timestamp = tenkai::now_millis();
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
        let change = ObjectChange {
            id: uuid::Uuid::new_v4().to_string(),
            object_id: next.id.clone(),
            field: format!("properties.{key}"),
            old_value: old,
            new_value: new,
            changed_by: "tenkai".into(),
            timestamp,
        };
        let payload = change.encode_to_vec();
        tx.execute(
            "INSERT INTO catalog_changes(id,object_id,timestamp,payload) VALUES($1,$2,$3,$4)",
            &[&change.id, &change.object_id, &change.timestamp, &payload],
        )
        .map_err(pg)?;
    }
    Ok(())
}

fn decode_objects(rows: Vec<postgres::Row>) -> Result<Vec<Object>> {
    rows.into_iter()
        .map(|row| {
            let payload: Vec<u8> = row.get(0);
            Object::decode(payload.as_slice()).map_err(|error| StoreError::InvalidData {
                kind: "object",
                detail: error.to_string(),
            })
        })
        .collect()
}
