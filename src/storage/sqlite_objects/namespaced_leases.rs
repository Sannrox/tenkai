use super::*;

// Lease writes read the row and then write it, so each runs in an immediate
// transaction: a concurrent writer waits on the busy timeout instead of
// failing when its read lock cannot be upgraded (#713).
impl SqliteStore {
    pub fn acquire_namespaced_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let now = crate::now_millis();
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if namespace == crate::apply::ENVIRONMENT_LEASE_NAMESPACE {
            crate::storage::ensure_environment_active_in(&tx, key, "new apply leases")?;
        }
        let current: Option<Lease> = decode_lease(
            tx.query_row(
                "SELECT payload FROM catalog_leases WHERE namespace=?1 AND lease_key=?2",
                params![namespace, key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?,
        )?;
        if current
            .as_ref()
            .is_some_and(|lease| lease.status == "active" && lease.expires_at_ms > now)
        {
            return Err(StoreError::already_exists("lease", format!("{namespace}/{key}")).into());
        }
        let generation = current
            .as_ref()
            .map(|lease| lease.generation.saturating_add(1))
            .unwrap_or(1);
        let lease = Lease {
            namespace: namespace.into(),
            key: key.into(),
            generation,
            fencing_token: uuid::Uuid::new_v4().to_string(),
            owner: owner.into(),
            status: "active".into(),
            acquired_at_ms: now,
            refreshed_at_ms: now,
            expires_at_ms: now.saturating_add(ttl_ms),
            released_at_ms: 0,
            site_id: String::new(),
        };
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }

    pub fn get_namespaced_lease(&self, namespace: &str, key: &str) -> AnyResult<Option<Lease>> {
        let connection = self.connection()?;
        decode_lease(
            connection
                .query_row(
                    "SELECT payload FROM catalog_leases WHERE namespace=?1 AND lease_key=?2",
                    params![namespace, key],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
        )
    }

    pub fn refresh_namespaced_lease(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let lease = refresh_lease_in(&tx, namespace, key, fencing_token, ttl_ms)?;
        tx.commit()?;
        Ok(lease)
    }

    pub fn refresh_leases_and_guarded_put(
        &self,
        refreshes: &[crate::storage::LeaseRefresh],
        mut object: Object,
        object_namespace: &str,
        object_key: &str,
        object_fencing_token: &str,
    ) -> AnyResult<(Vec<Lease>, Object)> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut leases = Vec::with_capacity(refreshes.len());
        for refresh in refreshes {
            anyhow::ensure!(refresh.ttl_ms > 0, "embedded lease TTL must be positive");
            if refresh.extend {
                leases.push(refresh_lease_in(
                    &tx,
                    &refresh.namespace,
                    &refresh.key,
                    &refresh.fencing_token,
                    refresh.ttl_ms,
                )?);
            } else {
                leases.push(require_active_lease_in(
                    &tx,
                    &refresh.namespace,
                    &refresh.key,
                    &refresh.fencing_token,
                )?);
            }
        }
        crate::storage::stamp_claim_expiry(&mut object, &leases, object_namespace, object_key);
        require_active_lease_in(&tx, object_namespace, object_key, object_fencing_token)?;
        let previous = decode_optional(
            tx.query_row(
                "SELECT payload FROM catalog_objects WHERE id=?1",
                [&object.id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?,
            "object",
        )?;
        anyhow::ensure!(
            previous.is_some(),
            "embedded object {} does not exist",
            object.id
        );
        upsert_object_in(&tx, &object, &self.principal).map_err(anyhow::Error::from)?;
        if let Some(previous) = previous {
            record_changes(&tx, &previous, &object, &self.principal)?;
        }
        tx.commit()?;
        Ok((leases, object))
    }

    pub fn release_namespaced_lease(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> AnyResult<Lease> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut lease = require_active_lease_in(&tx, namespace, key, fencing_token)?;
        lease.status = "released".into();
        lease.released_at_ms = crate::now_millis();
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }

    pub fn takeover_namespaced_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at: i64,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current = decode_lease(
            tx.query_row(
                "SELECT payload FROM catalog_leases WHERE namespace=?1 AND lease_key=?2",
                params![namespace, key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?,
        )?
        .with_context(|| format!("embedded lease {namespace}/{key} does not exist"))?;
        anyhow::ensure!(
            current.fencing_token == expected_token
                && current.expires_at_ms == expected_expires_at
                && current.expires_at_ms <= crate::now_millis(),
            "embedded lease takeover precondition failed"
        );
        let now = crate::now_millis();
        let lease = Lease {
            namespace: namespace.into(),
            key: key.into(),
            generation: current.generation.saturating_add(1),
            fencing_token: uuid::Uuid::new_v4().to_string(),
            owner: owner.into(),
            status: "active".into(),
            acquired_at_ms: now,
            refreshed_at_ms: now,
            expires_at_ms: now.saturating_add(ttl_ms),
            released_at_ms: 0,
            site_id: String::new(),
        };
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }
}

fn refresh_lease_in(
    tx: &Transaction<'_>,
    namespace: &str,
    key: &str,
    fencing_token: &str,
    ttl_ms: i64,
) -> AnyResult<Lease> {
    let mut lease = require_active_lease_in(tx, namespace, key, fencing_token)?;
    let now = crate::now_millis();
    lease.refreshed_at_ms = now;
    lease.expires_at_ms = now.saturating_add(ttl_ms);
    save_lease_in(tx, &lease)?;
    Ok(lease)
}

pub(super) fn require_active_lease_in(
    tx: &Transaction<'_>,
    namespace: &str,
    key: &str,
    fencing_token: &str,
) -> AnyResult<Lease> {
    let lease = decode_lease(
        tx.query_row(
            "SELECT payload FROM catalog_leases WHERE namespace=?1 AND lease_key=?2",
            params![namespace, key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?,
    )?
    .with_context(|| format!("embedded lease {namespace}/{key} does not exist"))?;
    anyhow::ensure!(
        lease.status == "active"
            && lease.fencing_token == fencing_token
            && lease.expires_at_ms > crate::now_millis(),
        "embedded lease {namespace}/{key} is not the active fenced holder"
    );
    Ok(lease)
}

pub(super) fn save_lease_in(tx: &Transaction<'_>, lease: &Lease) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO catalog_leases(namespace,lease_key,payload) VALUES(?1,?2,?3)
         ON CONFLICT(namespace,lease_key) DO UPDATE SET payload=excluded.payload",
        params![lease.namespace, lease.key, lease.encode_to_vec()],
    )?;
    Ok(())
}

pub(super) fn decode_lease(payload: Option<Vec<u8>>) -> AnyResult<Option<Lease>> {
    payload
        .map(|bytes| Lease::decode(bytes.as_slice()).context("decoding lease"))
        .transpose()
}
