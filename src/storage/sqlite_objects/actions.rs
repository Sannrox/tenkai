use super::*;

impl SqliteStore {
    pub fn register_schema(&self, schema: ObjectType) -> std::result::Result<(), tonic::Status> {
        self.connection()
            .map_err(|error| tonic::Status::internal(error.to_string()))?
            .execute(
                "INSERT OR REPLACE INTO catalog_schema_types(name,payload) VALUES(?1,?2)",
                params![schema.kind, schema.encode_to_vec()],
            )
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
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

    pub fn register_action(&self, action: ActionTypeDef) -> std::result::Result<(), tonic::Status> {
        self.connection()
            .map_err(|error| tonic::Status::internal(error.to_string()))?
            .execute(
                "INSERT OR REPLACE INTO catalog_action_types(name,payload) VALUES(?1,?2)",
                params![action.name, action.encode_to_vec()],
            )
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
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
        let target_id = params_map.get("id").with_context(|| {
            format!("embedded action {action_name} requires target parameter id")
        })?;
        let mut target = self
            .get_object(target_id)?
            .with_context(|| format!("embedded action target {target_id} does not exist"))?;
        let planned_ops = action
            .ops
            .iter()
            .map(|op| op.op.clone())
            .collect::<Vec<_>>();
        if !dry_run {
            for op in &action.ops {
                match op.op.as_str() {
                    "set_property" => {
                        let value = params_map.get(&op.value_from).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.value_from)
                        })?;
                        target.properties.insert(op.property.clone(), value.clone());
                    }
                    "create_link" => {
                        let to_id = params_map.get(&op.property).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.property)
                        })?;
                        self.create_link(
                            Link {
                                id: format!("{target_id}--{}--{to_id}", op.relation),
                                from_id: target_id.clone(),
                                to_id: to_id.clone(),
                                relation: op.relation.clone(),
                                created: crate::now_millis(),
                            },
                            false,
                        )
                        .map_err(anyhow::Error::from)?;
                    }
                    "delete_link" => {
                        let link_id = params_map.get(&op.value_from).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.value_from)
                        })?;
                        self.unlink(link_id)?;
                    }
                    other => bail!("unsupported embedded action operation {other:?}"),
                }
            }
            target.updated = crate::now_millis();
            self.put_object(target)?;
            self.record_decision(action_name, target_id, "allow", &params_map)?;
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

    pub(super) fn record_decision(
        &self,
        action: &str,
        target_id: &str,
        outcome: &str,
        params_map: &std::collections::HashMap<String, String>,
    ) -> AnyResult<()> {
        let timestamp = crate::now_millis();
        let mut evidence = params_map.clone();
        evidence.insert("decision".into(), outcome.into());
        let decision = Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            actor: self.principal.clone(),
            action: action.into(),
            reason: "execute_action".into(),
            evidence,
            target_id: target_id.into(),
            outcome: outcome.into(),
        };
        self.connection()?.execute(
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
}

pub(super) fn record_changes(
    tx: &Transaction<'_>,
    previous: &Object,
    next: &Object,
    principal: &str,
) -> AnyResult<()> {
    let timestamp = crate::now_millis();
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
        let change = crate::pb::sekai::ObjectChange {
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
