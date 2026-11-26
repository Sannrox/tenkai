use super::*;
use anyhow::Result as AnyResult;
use std::collections::HashMap;
use tenkai::feedback_observation::FeedbackObservation;
use tenkai::pb::graph_action::{ActionResult, ActionTypeDef};
use tenkai::pb::record::{Decision, Lease, Link, Object, ObjectChange, ObjectType};

impl CatalogGraph for SqliteStore {
    fn writes_after(
        &self,
        _tenant: Option<&str>,
        after: i64,
        limit: usize,
    ) -> AnyResult<Vec<tenkai::storage::CatalogWrite>> {
        SqliteStore::writes_after(self, after, limit)
    }

    fn latest_write(&self, _tenant: Option<&str>) -> AnyResult<i64> {
        SqliteStore::latest_write(self)
    }

    fn prune_writes(&self, _tenant: Option<&str>, before_ms: i64) -> AnyResult<()> {
        SqliteStore::prune_writes(self, before_ms)
    }

    fn get(&self, _tenant: Option<&str>, id: &str) -> AnyResult<Option<Object>> {
        SqliteStore::get(self, id)
    }

    fn create(&self, _tenant: Option<&str>, object: Object) -> tenkai::storage::Result<Object> {
        SqliteStore::create(self, object).map_err(Into::into)
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

    fn find_by_property_matching(
        &self,
        _tenant: Option<&str>,
        query: tenkai::embedded::PropertyIndexQuery<'_>,
    ) -> AnyResult<Vec<Object>> {
        SqliteStore::find_by_property_matching(self, query)
    }

    fn create_link(
        &self,
        _tenant: Option<&str>,
        link: Link,
        fail_if_exists: bool,
    ) -> tenkai::storage::Result<()> {
        SqliteStore::create_link(self, link, fail_if_exists).map_err(Into::into)
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

    fn refresh_leases(
        &self,
        _tenant: Option<&str>,
        refreshes: &[LeaseRefresh],
    ) -> AnyResult<Vec<Lease>> {
        SqliteStore::refresh_leases(self, refreshes)
    }

    fn refresh_leases_and_guarded_put(
        &self,
        _tenant: Option<&str>,
        refreshes: &[LeaseRefresh],
        object: Object,
        object_namespace: &str,
        object_key: &str,
        object_fencing_token: &str,
    ) -> AnyResult<(Vec<Lease>, Object)> {
        SqliteStore::refresh_leases_and_guarded_put(
            self,
            refreshes,
            object,
            object_namespace,
            object_key,
            object_fencing_token,
        )
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
        observations: &[FeedbackObservation],
    ) -> AnyResult<Object> {
        SqliteStore::put_with_provider_events(self, object, events, observations)
    }

    fn put_objects_with_provider_events(
        &self,
        _tenant: Option<&str>,
        objects: &[Object],
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<()> {
        SqliteStore::put_objects_with_provider_events(self, objects, events, observations)
    }

    fn guarded_put_objects_with_provider_events(
        &self,
        _tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<()> {
        SqliteStore::guarded_put_objects_with_provider_events(
            self,
            &objects,
            namespace,
            key,
            fencing_token,
            events,
            observations,
        )
    }

    fn feedback_observations(
        &self,
        _tenant: Option<&str>,
        environment: &str,
    ) -> AnyResult<Vec<FeedbackObservation>> {
        SqliteStore::feedback_observations(self, environment)
    }

    fn register_schema(
        &self,
        _tenant: Option<&str>,
        schema: ObjectType,
    ) -> tenkai::storage::Result<()> {
        SqliteStore::register_schema(self, schema).map_err(Into::into)
    }

    fn schemas(&self, _tenant: Option<&str>) -> AnyResult<Vec<ObjectType>> {
        SqliteStore::schemas(self)
    }

    fn register_action(
        &self,
        _tenant: Option<&str>,
        action: ActionTypeDef,
    ) -> tenkai::storage::Result<()> {
        SqliteStore::register_action(self, action).map_err(Into::into)
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

    fn put_keeping_property(
        &self,
        _tenant: Option<&str>,
        object: Object,
        key: &str,
    ) -> AnyResult<Object> {
        SqliteStore::put_keeping_property(self, object, key)
    }

    fn delete_if_property(
        &self,
        _tenant: Option<&str>,
        id: &str,
        key: &str,
        value: &str,
    ) -> AnyResult<bool> {
        SqliteStore::delete_if_property(self, id, key, value)
    }
}
