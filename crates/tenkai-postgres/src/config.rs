use std::sync::Arc;

use tenkai::storage::{OperationalStore, Result, StoreError};
use tenkai::tenant_store::TenantOperationalStore;

use super::PostgresTenantOperationalStore;
use super::postgres_feature_enabled;

/// Hub-wide PostgreSQL schema for host-scoped operational records (audit,
/// runtime claims, and the shared outcome producer sequence). Distinct from
/// per-tenant `tenkai_t_*`, which own the catalog object graph and the
/// terminal-outcome outbox.
pub const HUB_SCHEMA: &str = "tenkai_hub";

/// Enterprise hub composition: tenant partitions plus the hub operational store.
pub struct EnterpriseHub {
    pub tenant: Arc<dyn TenantOperationalStore>,
    pub operational: Arc<dyn OperationalStore>,
    /// Tenant-schema catalog object graph (ADR 0038).
    pub catalog: Arc<dyn tenkai::storage::CatalogGraph>,
    /// Stored OIDC grant rules (#836), hub-wide.
    pub grant_rules: Arc<dyn tenkai::grant_rules::GrantRuleStore>,
}

/// ADR 0010: a process selects exactly one authoritative operational backend.
pub fn refuse_mixed_store_configuration(
    sqlite_configured: bool,
    postgres_configured: bool,
) -> Result<()> {
    if sqlite_configured && postgres_configured {
        return Err(StoreError::AdapterUnavailable(
            "SQLite and PostgreSQL runtime configuration cannot be supplied together; a process selects exactly one authoritative operational backend (ADR 0010)".into(),
        ));
    }
    Ok(())
}

/// Hub connection configuration (no secrets in process arguments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresTenantConfig {
    /// `postgres://` URL (user/password from env-backed URL only).
    pub url: String,
}

impl PostgresTenantConfig {
    /// Load from `TENKAI_POSTGRES_URL`. Missing/empty → configuration error.
    pub fn from_env() -> Result<Self> {
        let url = tenkai::secret_source::read("TENKAI_POSTGRES_URL")
            .map_err(|error| StoreError::AdapterUnavailable(format!("{error:#}")))?
            .ok_or_else(|| {
                StoreError::AdapterUnavailable(
                    "TENKAI_POSTGRES_URL is not set (postgres://user:pass@host/db, or TENKAI_POSTGRES_URL_FILE)".into(),
                )
            })?;
        Self::new(url)
    }

    pub fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        if url.trim().is_empty() {
            return Err(StoreError::AdapterUnavailable(
                "postgres URL must not be empty".into(),
            ));
        }
        if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
            return Err(StoreError::AdapterUnavailable(
                "postgres URL must use postgres:// or postgresql://".into(),
            ));
        }
        Ok(Self { url })
    }

    /// Open the multi-tenant factory. Requires `--features postgres`.
    pub fn open(&self) -> Result<PostgresTenantOperationalStore> {
        #[cfg(feature = "postgres")]
        {
            PostgresTenantOperationalStore::connect(self)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = self;
            Err(StoreError::AdapterUnavailable(
                "rebuild tenkai with --features postgres to use the PostgreSQL tenant store".into(),
            ))
        }
    }
}

/// A `tenkai-server` compiled with `postgres` is a hub host.
///
/// It must not start as the community SQLite host when `--tenant-mode` is
/// unset. Community GitHub assets are built without this feature.
pub fn require_hub_tenant_mode(tenant_mode: bool) -> Result<()> {
    if postgres_feature_enabled() && !tenant_mode {
        return Err(StoreError::AdapterUnavailable(
            "this hub host requires --tenant-mode and TENKAI_POSTGRES_URL; use the community tenkai-server-<platform> asset for SQLite".into(),
        ));
    }
    Ok(())
}

/// Resolve the durable hub tenant store for `tenkai-server` startup (#127).
///
/// - `tenant_mode == false` → `Ok(None)` (community path).
/// - `tenant_mode == true` → requires `TENKAI_POSTGRES_URL` and feature `postgres`,
///   then returns a wired [`PostgresTenantOperationalStore`].
pub fn resolve_server_tenant_store(
    tenant_mode: bool,
) -> Result<Option<std::sync::Arc<dyn TenantOperationalStore>>> {
    if !tenant_mode {
        return Ok(None);
    }
    if !postgres_feature_enabled() {
        return Err(StoreError::AdapterUnavailable(
            "tenant mode requires a binary built with --features postgres and TENKAI_POSTGRES_URL"
                .into(),
        ));
    }
    let config = PostgresTenantConfig::from_env()?;
    let store = config.open()?;
    Ok(Some(Arc::new(store)))
}

/// Open the enterprise hub with PostgreSQL as the sole authoritative store.
///
/// Tenant partitions and the hub schema live in one database. SQLite is not
/// opened. Callers must already have refused a mixed SQLite configuration.
pub fn resolve_enterprise_hub() -> Result<EnterpriseHub> {
    resolve_fenced_enterprise_hub(None)
}

/// [`resolve_enterprise_hub`] whose authoritative writes need the hub
/// writer lease when `fence` is set (#748, multi-replica hubs).
pub fn resolve_fenced_enterprise_hub(
    fence: Option<std::sync::Arc<tenkai::writer_fence::WriterFence>>,
) -> Result<EnterpriseHub> {
    #[cfg(feature = "postgres")]
    {
        let store = PostgresTenantConfig::from_env()?.open()?;
        if let Some(fence) = fence {
            store.fence_writes(fence)?;
        }
        let hub = store.hub_partition()?;
        Ok(EnterpriseHub {
            grant_rules: Arc::new(store.clone()),
            tenant: Arc::new(store.clone()),
            catalog: Arc::new(store),
            operational: Arc::new(hub),
        })
    }
    #[cfg(not(feature = "postgres"))]
    {
        let _ = fence;
        Err(StoreError::AdapterUnavailable(
            "tenant mode requires a binary built with --features postgres and TENKAI_POSTGRES_URL"
                .into(),
        ))
    }
}

/// Sanitize tenant id into a safe Postgres schema name (`tenkai_t_*`).
pub fn tenant_schema_name(tenant_id: &str) -> Result<String> {
    if tenant_id.trim().is_empty() || tenant_id.len() > 64 {
        return Err(StoreError::InvalidData {
            kind: "tenant",
            detail: "tenant id must be 1..=64 characters".into(),
        });
    }
    let mut out = String::from("tenkai_t_");
    for ch in tenant_id.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' {
            out.push('_');
        } else {
            return Err(StoreError::InvalidData {
                kind: "tenant",
                detail: format!("tenant id contains unsupported character {ch:?}"),
            });
        }
    }
    if out == "tenkai_t_" {
        return Err(StoreError::InvalidData {
            kind: "tenant",
            detail: "tenant id produced an empty schema suffix".into(),
        });
    }
    Ok(out)
}
