use super::*;

pub struct SqliteStore {
    pub(super) connection: Mutex<Connection>,
    pub(super) principal: String,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            principal: "tenkai".into(),
        })
    }

    /// Open the solo operator store and refuse `TENKAI_POSTGRES_URL` on this process.
    pub fn open_embedded(path: impl AsRef<Path>, principal: impl Into<String>) -> Result<Self> {
        refuse_postgres_on_embedded()?;
        Self::open_control_plane(path, principal)
    }

    /// Open SQLite control-plane state for a tenant-mode hub.
    ///
    /// Hub processes also set `TENKAI_POSTGRES_URL` for the tenant store. That
    /// URL is not the control-plane database; refusing it here made
    /// `tenkai-server --tenant-mode` unstartable.
    pub fn open_control_plane(
        path: impl AsRef<Path>,
        principal: impl Into<String>,
    ) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                StoreError::AdapterUnavailable(format!(
                    "creating embedded state directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            principal: principal.into(),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            principal: "tenkai".into(),
        })
    }

    pub fn schema_version(&self) -> Result<u32> {
        let connection = self.connection()?;
        Ok(connection.query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    pub(super) fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StoreError::Poisoned)
    }

    /// Load one environment by id (used by tenant-scoped adapters and inspect paths).
    pub fn get_environment(&self, id: &str) -> Result<Option<EnvironmentRecord>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT id, revision, configuration_json FROM environments WHERE id=?1")?;
        let mut rows = statement.query(rusqlite::params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(EnvironmentRecord {
                id: row.get(0)?,
                revision: row.get(1)?,
                configuration_json: row.get(2)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// List environment ids in stable order (no configuration payloads).
    pub fn list_environment_ids(&self) -> Result<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT id FROM environments ORDER BY id ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        Ok(ids)
    }

    /// Non-retired environment ids in stable order, served by `environments_active`.
    pub fn list_active_environment_ids(&self) -> Result<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT id FROM environments WHERE retired_at IS NULL ORDER BY id ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Active catalog environment ids. A legacy name-keyed row is also hidden
    /// when its `tenkai:env:<name>` catalog row is retired.
    pub(crate) fn list_active_catalog_environment_ids(&self) -> Result<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT e.id FROM environments e
             WHERE e.retired_at IS NULL
               AND (e.id GLOB 'tenkai:env:*' OR NOT EXISTS (
                    SELECT 1 FROM environments r
                    WHERE r.id = 'tenkai:env:' || e.id AND r.retired_at IS NOT NULL))
             ORDER BY e.id ASC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

pub fn refuse_postgres_on_embedded() -> Result<()> {
    match std::env::var("TENKAI_POSTGRES_URL") {
        Ok(value) if !value.trim().is_empty() => Err(StoreError::AdapterUnavailable(
            "TENKAI_POSTGRES_URL is not valid on embedded or spoke hosts; SQLite is the sole operational store (ADR 0029)".into(),
        )),
        _ => Ok(()),
    }
}
