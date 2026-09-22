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
}

pub fn refuse_postgres_on_embedded() -> Result<()> {
    match std::env::var("TENKAI_POSTGRES_URL") {
        Ok(value) if !value.trim().is_empty() => Err(StoreError::AdapterUnavailable(
            "TENKAI_POSTGRES_URL is not valid on embedded or spoke hosts; SQLite is the sole operational store (ADR 0029)".into(),
        )),
        _ => Ok(()),
    }
}
