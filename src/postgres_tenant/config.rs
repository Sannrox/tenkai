use crate::storage::{Result, StoreError};
use crate::tenant_store::TenantOperationalStore;

use super::PostgresTenantOperationalStore;
use super::postgres_feature_enabled;

/// Hub connection configuration (no secrets in process arguments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresTenantConfig {
    /// `postgres://` URL (user/password from env-backed URL only).
    pub url: String,
}

impl PostgresTenantConfig {
    /// Load from `TENKAI_POSTGRES_URL`. Missing/empty → configuration error.
    pub fn from_env() -> Result<Self> {
        let url = std::env::var("TENKAI_POSTGRES_URL").map_err(|_| {
            StoreError::AdapterUnavailable(
                "TENKAI_POSTGRES_URL is not set (postgres://user:pass@host/db)".into(),
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
    Ok(Some(std::sync::Arc::new(store)))
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
