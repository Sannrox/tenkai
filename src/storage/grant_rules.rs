//! Stored OIDC grant rules (#836) in SQLite. The tables are additive, so an
//! older binary on the same database ignores them.

use super::*;
use crate::grant_rules::{
    GrantRuleStore, GrantRuleWrite, MAX_STORED_RULES, StoredGrantRule, decode, encode,
};

pub(super) fn ensure_grant_rule_tables(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS grant_rules (
            value TEXT PRIMARY KEY, rule_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS grant_rule_generation (
            id INTEGER PRIMARY KEY CHECK (id = 1), generation INTEGER NOT NULL
         );",
    )?;
    Ok(())
}

fn generation(connection: &Connection) -> Result<i64> {
    Ok(connection
        .query_row(
            "SELECT generation FROM grant_rule_generation WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

/// The next generation, inside the caller's transaction.
fn bump(connection: &Connection) -> Result<i64> {
    Ok(connection.query_row(
        "INSERT INTO grant_rule_generation(id, generation) VALUES(1, 1)
         ON CONFLICT(id) DO UPDATE SET generation = generation + 1
         RETURNING generation",
        [],
        |row| row.get(0),
    )?)
}

impl GrantRuleStore for SqliteStore {
    fn grant_rule_generation(&self) -> Result<i64> {
        generation(&*self.connection()?)
    }

    fn grant_rules(&self) -> Result<(i64, Vec<StoredGrantRule>)> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let current = generation(&tx)?;
        let raw = {
            let mut statement = tx.prepare("SELECT rule_json FROM grant_rules ORDER BY value")?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.commit()?;
        let rules = raw.iter().map(|raw| decode(raw)).collect::<Result<_>>()?;
        Ok((current, rules))
    }

    fn insert_grant_rule(
        &self,
        rule: &StoredGrantRule,
        expected: Option<i64>,
    ) -> Result<GrantRuleWrite> {
        let json = encode(rule)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(stale) = GrantRuleWrite::check_expected(expected, generation(&tx)?) {
            return Ok(stale);
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM grant_rules", [], |row| row.get(0))?;
        if count >= MAX_STORED_RULES as i64 {
            return Ok(GrantRuleWrite::Refused);
        }
        let inserted = tx.execute(
            "INSERT INTO grant_rules(value, rule_json) VALUES(?1, ?2) ON CONFLICT(value) DO NOTHING",
            params![rule.rule.value, json],
        )?;
        if inserted == 0 {
            return Ok(GrantRuleWrite::Refused);
        }
        let next = bump(&tx)?;
        tx.commit()?;
        Ok(GrantRuleWrite::Applied(next))
    }

    fn delete_grant_rule(&self, value: &str, expected: Option<i64>) -> Result<GrantRuleWrite> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(stale) = GrantRuleWrite::check_expected(expected, generation(&tx)?) {
            return Ok(stale);
        }
        if tx.execute("DELETE FROM grant_rules WHERE value = ?1", params![value])? == 0 {
            return Ok(GrantRuleWrite::Refused);
        }
        let next = bump(&tx)?;
        tx.commit()?;
        Ok(GrantRuleWrite::Applied(next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_grant_rules_follow_the_contract() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-grant-rules-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = std::sync::Arc::new(SqliteStore::open(dir.join("tenkai.db")).unwrap());
        let other = std::sync::Arc::new(SqliteStore::open(dir.join("tenkai.db")).unwrap());
        crate::grant_rules::assert_grant_rule_store_contract(store, other, "sqlite");
        let _ = std::fs::remove_dir_all(dir);
    }
}
