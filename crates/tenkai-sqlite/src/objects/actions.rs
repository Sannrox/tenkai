use super::links::insert_link_in;
use super::object_writes::object_in;
use super::*;

impl SqliteStore {
    pub fn register_schema(&self, schema: ObjectType) -> Result<()> {
        self.connection()?.execute(
            "INSERT OR REPLACE INTO catalog_schema_types(name,payload) VALUES(?1,?2)",
            params![schema.kind, schema.encode_to_vec()],
        )?;
        Ok(())
    }

    pub fn schemas(&self) -> AnyResult<Vec<ObjectType>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT payload FROM catalog_schema_types")?;
        let payloads = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "schema")
    }

    pub fn register_action(&self, action: ActionTypeDef) -> Result<()> {
        self.connection()?.execute(
            "INSERT OR REPLACE INTO catalog_action_types(name,payload) VALUES(?1,?2)",
            params![action.name, action.encode_to_vec()],
        )?;
        Ok(())
    }

    pub fn execute_action(
        &self,
        action_name: &str,
        params_map: std::collections::HashMap<String, String>,
        dry_run: bool,
    ) -> AnyResult<ActionResult> {
        let payload = self
            .connection()?
            .query_row(
                "SELECT payload FROM catalog_action_types WHERE name=?1",
                [action_name],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .with_context(|| {
                format!("embedded action {action_name} is not registered; run `tenkaictl init`")
            })?;
        let action = ActionTypeDef::decode(payload.as_slice())?;
        let writes = ActionWrites::plan("embedded", action_name, &action, &params_map)?;
        let target_id = &writes.target_id;
        let planned_ops = action
            .ops
            .iter()
            .map(|op| op.op.clone())
            .collect::<Vec<_>>();
        let mut connection = self.connection()?;
        // A dry run only reads; a real run holds the write lock from the read on.
        let behavior = if dry_run {
            rusqlite::TransactionBehavior::Deferred
        } else {
            rusqlite::TransactionBehavior::Immediate
        };
        let tx = connection.transaction_with_behavior(behavior)?;
        let previous = object_in(&tx, target_id)?
            .with_context(|| format!("embedded action target {target_id} does not exist"))?;
        if !dry_run {
            for write in &writes.writes {
                match write {
                    ActionWrite::SetProperty { .. } => {}
                    ActionWrite::CreateLink(link) => {
                        insert_link_in(&tx, link)?;
                    }
                    ActionWrite::DeleteLink(id) => {
                        record_link_write(&tx, id)?;
                        tx.execute("DELETE FROM catalog_links WHERE id=?1", [id])?;
                    }
                }
            }
            let mut target = previous.clone();
            writes.apply_properties(&mut target);
            upsert_object_in(&tx, &target, &self.principal)?;
            record_changes(&tx, &previous, &target, &self.principal)?;
            insert_decision_in(
                &tx,
                &self.principal,
                action_name,
                target_id,
                "allow",
                &params_map,
            )?;
            tx.commit()?;
        }
        Ok(ActionResult {
            action: action_name.into(),
            message: "allowed by embedded host policy".into(),
            dry_run,
            planned_ops,
            decision: "allow".into(),
            approval_id: String::new(),
        })
    }

    pub fn decisions(&self, actor: &str, action: &str, after: i64) -> AnyResult<Vec<Decision>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT payload FROM catalog_decisions
             WHERE (?1='' OR actor=?1) AND (?2='' OR action=?2) AND timestamp>?3
             ORDER BY timestamp,id",
        )?;
        let payloads = statement
            .query_map(params![actor, action, after], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "decision")
    }

    pub fn changes(&self, object_id: &str) -> AnyResult<Vec<ObjectChange>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT payload FROM catalog_changes WHERE object_id=?1 ORDER BY timestamp,id",
        )?;
        let payloads = statement
            .query_map([object_id], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "object change")
    }
}

/// Record the allow decision of one executed action inside its transaction.
fn insert_decision_in(
    tx: &Transaction<'_>,
    principal: &str,
    action: &str,
    target_id: &str,
    outcome: &str,
    params_map: &std::collections::HashMap<String, String>,
) -> AnyResult<()> {
    let mut evidence = params_map.clone();
    evidence.insert("decision".into(), outcome.into());
    let decision = Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: tenkai::now_millis(),
        actor: principal.into(),
        action: action.into(),
        reason: "execute_action".into(),
        evidence,
        target_id: target_id.into(),
        outcome: outcome.into(),
    };
    tx.execute(
        "INSERT INTO catalog_decisions(id,timestamp,actor,action,payload)
         VALUES(?1,?2,?3,?4,?5)",
        params![
            decision.id,
            decision.timestamp,
            decision.actor,
            decision.action,
            decision.encode_to_vec()
        ],
    )?;
    Ok(())
}

/// Delete the written execution claim's change rows older than retention,
/// scoped to that claim as on the Postgres hub (#1554).
fn prune_execution_claim_history_in(
    tx: &Transaction<'_>,
    claim: &Object,
    now: i64,
) -> rusqlite::Result<()> {
    if claim.kind != tenkai::ontology::KIND_ENVIRONMENT_EXECUTION {
        return Ok(());
    }
    let cutoff = now.saturating_sub(tenkai::storage::CATALOG_HISTORY_RETENTION_MS);
    tx.execute(
        "DELETE FROM catalog_changes WHERE object_id = ?1 AND timestamp < ?2",
        params![claim.id, cutoff],
    )?;
    Ok(())
}

pub(super) fn record_changes(
    tx: &Transaction<'_>,
    previous: &Object,
    next: &Object,
    principal: &str,
) -> AnyResult<()> {
    let timestamp = tenkai::now_millis();
    prune_execution_claim_history_in(tx, next, timestamp)?;
    if tenkai::storage::skip_execution_claim_heartbeat(previous, next) {
        return Ok(());
    }
    for key in previous
        .properties
        .keys()
        .chain(next.properties.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let old = previous.properties.get(key).cloned().unwrap_or_default();
        let new = next.properties.get(key).cloned().unwrap_or_default();
        if old == new {
            continue;
        }
        let change = tenkai::pb::record::ObjectChange {
            id: uuid::Uuid::new_v4().to_string(),
            object_id: next.id.clone(),
            field: format!("properties.{key}"),
            old_value: old,
            new_value: new,
            changed_by: principal.into(),
            timestamp,
        };
        tx.execute(
            "INSERT INTO catalog_changes(id,object_id,timestamp,payload) VALUES(?1,?2,?3,?4)",
            params![
                change.id,
                change.object_id,
                change.timestamp,
                change.encode_to_vec()
            ],
        )?;
    }
    Ok(())
}
