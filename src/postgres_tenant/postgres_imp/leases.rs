use super::*;
use super::{Inner, pg};
use postgres::Transaction;

impl Inner {
    pub fn acquire_lease(
        &self,
        schema: &str,
        environment: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<LeaseRecord> {
        let now = crate::now_millis();
        if expires_at <= now {
            return Err(StoreError::LeaseExpired {
                environment: environment.into(),
                generation: 0,
            });
        }
        self.with_schema(schema, |tx| {
            lock_lease(tx, environment)?;
            if tx
                .query_one(
                    "SELECT EXISTS(
                        SELECT 1 FROM development_fixture_objects
                        WHERE object_kind='environment' AND object_id=$1
                     )",
                    &[&environment],
                )
                .map_err(pg)?
                .get::<_, bool>(0)
            {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture environments are non-executable".into(),
                });
            }
            let current = lease_in(tx, environment)?;
            let generation = match current {
                Some(current) if current.expires_at > now && current.owner != owner => {
                    return Err(StoreError::LeaseHeld {
                        environment: environment.into(),
                        owner: current.owner,
                        expires_at: current.expires_at,
                    });
                }
                Some(current) if current.expires_at > now => current.generation,
                Some(current) => current.generation + 1,
                None => 1,
            };
            let gen_i = generation as i64;
            tx.execute(
                "INSERT INTO leases(environment_id,owner,generation,expires_at)
                 VALUES($1,$2,$3,$4)
                 ON CONFLICT(environment_id) DO UPDATE SET owner=EXCLUDED.owner,
                   generation=EXCLUDED.generation,expires_at=EXCLUDED.expires_at",
                &[&environment, &owner, &gen_i, &expires_at],
            )
            .map_err(pg)?;
            Ok(LeaseRecord {
                environment_id: environment.into(),
                owner: owner.into(),
                generation,
                expires_at,
            })
        })
    }

    pub fn current_lease(&self, schema: &str, environment: &str) -> Result<Option<LeaseRecord>> {
        self.with_schema(schema, |tx| lease_in(tx, environment))
    }

    pub(crate) fn expire_lease_for_conformance(
        &self,
        schema: &str,
        environment: &str,
    ) -> Result<()> {
        self.with_schema(schema, |tx| {
            tx.execute(
                "UPDATE leases SET expires_at = 0 WHERE environment_id = $1",
                &[&environment],
            )
            .map_err(pg)?;
            Ok(())
        })
    }

    pub(crate) fn cleanup_conformance_schema(&self, schema: &str) -> Result<()> {
        if !schema.starts_with("tenkai_t_delivery_test_")
            || !schema
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return Err(StoreError::InvalidData {
                kind: "delivery conformance",
                detail: "refusing to clean a non-conformance tenant schema".into(),
            });
        }
        self.client
            .lock()
            .map_err(|_| StoreError::AdapterUnavailable("postgres lock poisoned".into()))?
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .map_err(pg)
    }

    #[cfg(test)]
    pub(crate) fn expire_lease_for_test(&self, schema: &str, environment: &str) -> Result<()> {
        self.expire_lease_for_conformance(schema, environment)
    }

    #[cfg(test)]
    pub(crate) fn delivery_effect_counts_for_test(
        &self,
        schema: &str,
    ) -> Result<(i64, i64, i64, i64)> {
        self.with_schema(schema, |tx| {
            let row = tx
                .query_one(
                    "SELECT
                       (SELECT count(*) FROM channels),
                       (SELECT count(*) FROM plans),
                       (SELECT count(*) FROM receipts),
                       (SELECT count(*) FROM rollbacks)",
                    &[],
                )
                .map_err(pg)?;
            Ok((row.get(0), row.get(1), row.get(2), row.get(3)))
        })
    }
}

pub(crate) fn lease_in(tx: &mut Transaction<'_>, environment: &str) -> Result<Option<LeaseRecord>> {
    let row = tx
        .query_opt(
            "SELECT environment_id,owner,generation,expires_at FROM leases WHERE environment_id = $1",
            &[&environment],
        )
        .map_err(pg)?;
    Ok(row.map(|row| LeaseRecord {
        environment_id: row.get(0),
        owner: row.get(1),
        generation: row.get::<_, i64>(2) as u64,
        expires_at: row.get(3),
    }))
}

pub(crate) fn require_lease(
    tx: &mut Transaction<'_>,
    environment: &str,
    owner: &str,
    generation: u64,
    now: i64,
) -> Result<()> {
    lock_lease(tx, environment)?;
    let lease = lease_in(tx, environment)?.ok_or_else(|| StoreError::LeaseExpired {
        environment: environment.into(),
        generation,
    })?;
    if lease.generation != generation {
        return Err(StoreError::StaleLease {
            environment: environment.into(),
            expected: lease.generation,
            actual: generation,
        });
    }
    if lease.owner != owner {
        return Err(StoreError::LeaseOwnerMismatch {
            environment: environment.into(),
            expected: lease.owner,
            actual: owner.into(),
        });
    }
    if lease.expires_at <= now {
        return Err(StoreError::LeaseExpired {
            environment: environment.into(),
            generation,
        });
    }
    Ok(())
}

pub(crate) fn lock_lease(tx: &mut Transaction<'_>, environment: &str) -> Result<()> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(
            hashtextextended(current_schema() || ':lease:' || $1, 0)
         )",
        &[&environment],
    )
    .map_err(pg)?;
    Ok(())
}

pub(crate) fn require_plan_environment(
    tx: &mut Transaction<'_>,
    plan_id: &str,
    environment: &str,
) -> Result<()> {
    let stored: String = tx
        .query_opt(
            "SELECT environment_id FROM plans WHERE id = $1",
            &[&plan_id],
        )
        .map_err(pg)?
        .map(|row| row.get(0))
        .ok_or_else(|| StoreError::NotFound {
            kind: "plan",
            id: plan_id.into(),
        })?;
    if stored != environment {
        return Err(StoreError::EnvironmentMismatch {
            kind: "plan",
            id: plan_id.into(),
            expected: stored,
            actual: environment.into(),
        });
    }
    Ok(())
}
