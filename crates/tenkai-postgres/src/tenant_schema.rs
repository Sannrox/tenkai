//! Per-tenant Postgres schema version stamp (#870).
//!
//! Tenant DDL runs once per schema per stamp, not on the request path. Bump
//! [`TENANT_SCHEMA_VERSION`] when `migrate_tenant_schema` changes shape.
//! SQLite [`tenkai::storage::SCHEMA_VERSION`] is independent.

use std::collections::HashSet;
use std::sync::RwLock;

/// Stamp written to `tenkai_tenant_schema_versions` after a successful migrate.
/// A stored value greater than this is left in place so a rolling older
/// replica does not downgrade or re-run `CREATE INDEX`.
pub(crate) const TENANT_SCHEMA_VERSION: u32 = 3;

/// True when `stored` is this binary's stamp or newer.
pub(crate) fn tenant_schema_is_current(stored: Option<i32>, current: u32) -> bool {
    stored.is_some_and(|stored| u32::try_from(stored).is_ok_and(|stored| stored >= current))
}

/// Process-local set of schemas already confirmed at this binary's stamp.
pub(crate) struct EnsuredTenantSchemas {
    inner: RwLock<HashSet<String>>,
}

impl EnsuredTenantSchemas {
    pub(crate) fn new() -> Self {
        Self {
            inner: RwLock::new(HashSet::new()),
        }
    }

    pub(crate) fn contains(&self, schema: &str) -> bool {
        self.inner
            .read()
            .map(|guard| guard.contains(schema))
            .unwrap_or(false)
    }

    pub(crate) fn insert(&self, schema: String) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(schema);
        }
    }

    pub(crate) fn remove(&self, schema: &str) {
        if let Ok(mut guard) = self.inner.write() {
            guard.remove(schema);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_or_newer_skips_migrate() {
        let stamp = i32::try_from(TENANT_SCHEMA_VERSION).unwrap();
        assert!(tenant_schema_is_current(Some(stamp), TENANT_SCHEMA_VERSION));
        assert!(tenant_schema_is_current(Some(2), 1));
        assert!(!tenant_schema_is_current(Some(0), 1));
        assert!(!tenant_schema_is_current(None, 1));
        assert!(!tenant_schema_is_current(Some(-1), 1));
    }

    #[test]
    fn memo_remembers_until_forgotten() {
        let memo = EnsuredTenantSchemas::new();
        assert!(!memo.contains("tenkai_t_a"));
        memo.insert("tenkai_t_a".into());
        assert!(memo.contains("tenkai_t_a"));
        assert!(!memo.contains("tenkai_t_b"));
        memo.remove("tenkai_t_a");
        assert!(!memo.contains("tenkai_t_a"));
    }
}
