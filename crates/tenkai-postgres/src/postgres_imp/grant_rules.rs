//! Stored OIDC grant rules (#836) in the hub-wide PostgreSQL tables.

use postgres::Transaction;
use tenkai::grant_rules::{GrantRuleWrite, MAX_STORED_RULES, StoredGrantRule, decode, encode};

use super::{Inner, Result, pg};

fn generation(tx: &mut Transaction<'_>) -> Result<i64> {
    Ok(tx
        .query_opt(
            "SELECT generation FROM tenkai_grant_rule_generation WHERE id = 1",
            &[],
        )
        .map_err(pg)?
        .map_or(0, |row| row.get(0)))
}

/// The next generation, inside the caller's transaction.
fn bump(tx: &mut Transaction<'_>) -> Result<i64> {
    Ok(tx
        .query_one(
            "INSERT INTO tenkai_grant_rule_generation(id, generation) VALUES (1, 1)
             ON CONFLICT (id) DO UPDATE
             SET generation = tenkai_grant_rule_generation.generation + 1
             RETURNING generation",
            &[],
        )
        .map_err(pg)?
        .get(0))
}

impl Inner {
    pub(crate) fn grant_rule_generation(&self) -> Result<i64> {
        self.with_schema("public", generation)
    }

    pub(crate) fn grant_rules(&self) -> Result<(i64, Vec<StoredGrantRule>)> {
        self.with_schema("public", |tx| {
            // One statement, so the generation and the rules are one snapshot.
            let rows = tx
                .query(
                    "SELECT g.generation, r.rule_json
                     FROM (SELECT coalesce(
                             (SELECT generation FROM tenkai_grant_rule_generation WHERE id = 1),
                             0) AS generation) g
                     LEFT JOIN tenkai_grant_rules r ON true
                     ORDER BY r.value",
                    &[],
                )
                .map_err(pg)?;
            let current = rows.first().map_or(0, |row| row.get(0));
            let rules = rows
                .iter()
                .filter_map(|row| row.get::<_, Option<String>>(1))
                .map(|raw| decode(&raw))
                .collect::<Result<_>>()?;
            Ok((current, rules))
        })
    }

    pub(crate) fn insert_grant_rule(
        &self,
        rule: &StoredGrantRule,
        expected: Option<i64>,
    ) -> Result<GrantRuleWrite> {
        let json = encode(rule)?;
        let value = rule.rule.value.clone();
        self.with_writer_schema("public", move |tx| {
            serialize_changes(tx)?;
            if let Some(stale) = GrantRuleWrite::check_expected(expected, generation(tx)?) {
                return Ok(stale);
            }
            let count: i64 = tx
                .query_one("SELECT count(*) FROM tenkai_grant_rules", &[])
                .map_err(pg)?
                .get(0);
            if count >= MAX_STORED_RULES as i64 {
                return Ok(GrantRuleWrite::Refused);
            }
            let inserted = tx
                .execute(
                    "INSERT INTO tenkai_grant_rules(value, rule_json) VALUES ($1, $2)
                     ON CONFLICT (value) DO NOTHING",
                    &[&value, &json],
                )
                .map_err(pg)?;
            if inserted == 0 {
                return Ok(GrantRuleWrite::Refused);
            }
            bump(tx).map(GrantRuleWrite::Applied)
        })
    }

    pub(crate) fn delete_grant_rule(
        &self,
        value: &str,
        expected: Option<i64>,
    ) -> Result<GrantRuleWrite> {
        let value = value.to_owned();
        self.with_writer_schema("public", move |tx| {
            serialize_changes(tx)?;
            if let Some(stale) = GrantRuleWrite::check_expected(expected, generation(tx)?) {
                return Ok(stale);
            }
            let deleted = tx
                .execute("DELETE FROM tenkai_grant_rules WHERE value = $1", &[&value])
                .map_err(pg)?;
            if deleted == 0 {
                return Ok(GrantRuleWrite::Refused);
            }
            bump(tx).map(GrantRuleWrite::Applied)
        })
    }
}

/// Changes to the rules run one at a time, so the size bound holds and each
/// takes the next generation.
fn serialize_changes(tx: &mut Transaction<'_>) -> Result<()> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended('tenkai_grant_rules', 0))",
        &[],
    )
    .map_err(pg)?;
    Ok(())
}
