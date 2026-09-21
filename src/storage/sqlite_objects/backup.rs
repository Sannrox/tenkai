use super::*;

impl SqliteStore {
    pub fn backup(&self, destination: impl AsRef<Path>) -> AnyResult<()> {
        let destination = destination.as_ref();
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating backup directory {}", parent.display()))?;
        }
        self.connection()?
            .backup(DatabaseName::Main, destination, None)
            .with_context(|| format!("backing up operational state to {}", destination.display()))
    }

    pub fn restore(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> AnyResult<()> {
        let source = source.as_ref();
        let destination = destination.as_ref();
        anyhow::ensure!(
            source.is_file(),
            "backup {} does not exist",
            source.display()
        );
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating state directory {}", parent.display()))?;
        }
        let source_connection =
            Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .with_context(|| format!("opening backup {}", source.display()))?;
        let check: String = source_connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .context("checking backup integrity")?;
        anyhow::ensure!(check == "ok", "backup integrity check failed: {check}");
        source_connection
            .backup(DatabaseName::Main, destination, None)
            .with_context(|| {
                format!(
                    "restoring backup {} to {}",
                    source.display(),
                    destination.display()
                )
            })
    }

    pub fn leftover_graph_tables(&self) -> AnyResult<bool> {
        let connection = self.connection()?;
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_objects')",
            [],
            |row| row.get(0),
        )?;
        Ok(present)
    }
}
