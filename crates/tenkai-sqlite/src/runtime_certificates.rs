//! Which runners the runner CA issued a certificate to (#809), in SQLite.
//! The table is additive, so an older binary on the same database ignores
//! it; a certificate it issues meanwhile is recorded at the next renewal.

use super::*;

pub(super) fn ensure_runtime_certificate_table(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS runtime_certificates (
             runner_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
             issued_at INTEGER NOT NULL
         );",
    )?;
    Ok(())
}

impl SqliteStore {
    pub(super) fn record_runtime_certificate_sqlite(
        &self,
        runner_id: &str,
        environment_id: &str,
        issued_at: i64,
    ) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO runtime_certificates(runner_id, environment_id, issued_at)
             VALUES(?1, ?2, ?3)
             ON CONFLICT(runner_id) DO UPDATE SET issued_at = max(issued_at, excluded.issued_at)",
            params![runner_id, environment_id, issued_at],
        )?;
        Ok(())
    }

    pub(super) fn certified_runtime_runners_sqlite(&self) -> Result<Vec<String>> {
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT runner_id FROM runtime_certificates ORDER BY runner_id")?;
        let ids = statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(ids)
    }
}
