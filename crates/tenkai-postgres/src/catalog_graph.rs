use anyhow::Context as _;
use tenkai::pb::graph_action::{ActionResult, ActionTypeDef};
use tenkai::pb::sekai::{Decision, Lease, Link, Object, ObjectChange, ObjectType};
use tenkai::storage::{CatalogGraph, Result, StoreError};

use super::PostgresTenantOperationalStore;
use super::tenant_schema_name;

fn missing_tenant() -> StoreError {
    StoreError::AdapterUnavailable("missing tenant on hub catalog write".into())
}

#[cfg(not(feature = "postgres"))]
fn postgres_disabled() -> StoreError {
    StoreError::AdapterUnavailable(
        "rebuild tenkai with --features postgres to use the PostgreSQL hub catalog".into(),
    )
}

impl PostgresTenantOperationalStore {
    fn catalog_schema(&self, tenant: Option<&str>) -> Result<String> {
        let tenant = tenant.ok_or_else(missing_tenant)?;
        let schema = tenant_schema_name(tenant)?;
        #[cfg(feature = "postgres")]
        {
            self.inner.ensure_tenant_schema(&schema)?;
            Ok(schema)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = schema;
            Err(postgres_disabled())
        }
    }
}

impl CatalogGraph for PostgresTenantOperationalStore {
    fn get(&self, tenant: Option<&str>, id: &str) -> anyhow::Result<Option<Object>> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_get(&schema, id)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, id);
            Err(postgres_disabled().into())
        }
    }

    fn create(&self, tenant: Option<&str>, object: Object) -> Result<Object> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            self.inner.catalog_create(&schema, &object)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, object);
            Err(postgres_disabled())
        }
    }

    fn put(&self, tenant: Option<&str>, object: Object) -> anyhow::Result<Object> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_put(&schema, &object)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, object);
            Err(postgres_disabled().into())
        }
    }

    fn delete(&self, tenant: Option<&str>, id: &str) -> anyhow::Result<()> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_delete(&schema, id)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, id);
            Err(postgres_disabled().into())
        }
    }

    fn list_kind(&self, tenant: Option<&str>, kind: &str) -> anyhow::Result<Vec<Object>> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_list_kind(&schema, kind)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, kind);
            Err(postgres_disabled().into())
        }
    }

    fn list_kind_ids(&self, tenant: Option<&str>, kind: &str) -> anyhow::Result<Vec<String>> {
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
    ) -> anyhow::Result<Vec<Object>> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self
                .inner
                .catalog_find_by_property(&schema, kind, key, value)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, kind, key, value);
            Err(postgres_disabled().into())
        }
    }

    fn create_link(&self, tenant: Option<&str>, link: Link, fail_if_exists: bool) -> Result<()> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            self.inner
                .catalog_create_link(&schema, &link, fail_if_exists)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, link, fail_if_exists);
            Err(postgres_disabled())
        }
    }

    fn unlink(&self, tenant: Option<&str>, id: &str) -> anyhow::Result<()> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_unlink(&schema, id)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, id);
            Err(postgres_disabled().into())
        }
    }

    fn links(
        &self,
        tenant: Option<&str>,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> anyhow::Result<Vec<Link>> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self
                .inner
                .catalog_links(&schema, object_id, relation, direction)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, object_id, relation, direction);
            Err(postgres_disabled().into())
        }
    }

    fn linked(
        &self,
        tenant: Option<&str>,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> anyhow::Result<Vec<Object>> {
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
    ) -> anyhow::Result<Lease> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self
                .inner
                .catalog_acquire_lease(&schema, namespace, key, owner, ttl_ms)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, namespace, key, owner, ttl_ms);
            Err(postgres_disabled().into())
        }
    }

    fn get_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
    ) -> anyhow::Result<Option<Lease>> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_get_lease(&schema, namespace, key)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, namespace, key);
            Err(postgres_disabled().into())
        }
    }

    fn refresh_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> anyhow::Result<Lease> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self
                .inner
                .catalog_refresh_lease(&schema, namespace, key, fencing_token, ttl_ms)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, namespace, key, fencing_token, ttl_ms);
            Err(postgres_disabled().into())
        }
    }

    fn release_lease(
        &self,
        tenant: Option<&str>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> anyhow::Result<Lease> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self
                .inner
                .catalog_release_lease(&schema, namespace, key, fencing_token)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, namespace, key, fencing_token);
            Err(postgres_disabled().into())
        }
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
    ) -> anyhow::Result<Lease> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_takeover_lease(
                &schema,
                namespace,
                key,
                owner,
                expected_token,
                expected_expires_at,
                ttl_ms,
            )?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (
                schema,
                namespace,
                key,
                owner,
                expected_token,
                expected_expires_at,
                ttl_ms,
            );
            Err(postgres_disabled().into())
        }
    }

    fn guarded_put(
        &self,
        tenant: Option<&str>,
        object: Object,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        create: bool,
    ) -> anyhow::Result<Object> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_guarded_put(
                &schema,
                &object,
                namespace,
                key,
                fencing_token,
                create,
            )?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, object, namespace, key, fencing_token, create);
            Err(postgres_disabled().into())
        }
    }

    fn guarded_put_many(
        &self,
        tenant: Option<&str>,
        objects: Vec<Object>,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> anyhow::Result<()> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_guarded_put_many(
                &schema,
                objects,
                namespace,
                key,
                fencing_token,
            )?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, objects, namespace, key, fencing_token);
            Err(postgres_disabled().into())
        }
    }

    fn register_schema(&self, tenant: Option<&str>, schema_type: ObjectType) -> Result<()> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            self.inner.catalog_register_schema(&schema, &schema_type)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, schema_type);
            Err(postgres_disabled())
        }
    }

    fn schemas(&self, tenant: Option<&str>) -> anyhow::Result<Vec<ObjectType>> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_schemas(&schema)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = schema;
            Err(postgres_disabled().into())
        }
    }

    fn register_action(&self, tenant: Option<&str>, action: ActionTypeDef) -> Result<()> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            self.inner.catalog_register_action(&schema, &action)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, action);
            Err(postgres_disabled())
        }
    }

    fn execute_action(
        &self,
        tenant: Option<&str>,
        action: &str,
        params: std::collections::HashMap<String, String>,
        dry_run: bool,
    ) -> anyhow::Result<ActionResult> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self
                .inner
                .catalog_execute_action(&schema, action, &params, dry_run)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, action, params, dry_run);
            Err(postgres_disabled().into())
        }
    }

    fn decisions(
        &self,
        tenant: Option<&str>,
        actor: &str,
        action: &str,
        after: i64,
    ) -> anyhow::Result<Vec<Decision>> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self
                .inner
                .catalog_decisions(&schema, actor, action, after)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, actor, action, after);
            Err(postgres_disabled().into())
        }
    }

    fn changes(&self, tenant: Option<&str>, object_id: &str) -> anyhow::Result<Vec<ObjectChange>> {
        let schema = self.catalog_schema(tenant)?;
        #[cfg(feature = "postgres")]
        {
            Ok(self.inner.catalog_changes(&schema, object_id)?)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (schema, object_id);
            Err(postgres_disabled().into())
        }
    }
}
