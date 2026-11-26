//! Resolve a catalog action into its writes before any store is touched.
//!
//! Every host checks the whole action against its parameters first, then
//! applies the writes in one transaction, so a missing later parameter leaves
//! nothing behind (#1304).

use std::collections::HashMap;

use thiserror::Error;

use crate::pb::graph_action::ActionTypeDef;
use crate::pb::record::{Link, Object};

/// One write of a resolved action, in definition order.
#[derive(Clone, Debug, PartialEq)]
pub enum ActionWrite {
    SetProperty { key: String, value: String },
    CreateLink(Link),
    DeleteLink(String),
}

/// An action whose every operation found its parameter.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionWrites {
    pub target_id: String,
    pub writes: Vec<ActionWrite>,
}

/// Why an action cannot run with the given parameters. `host` names the
/// caller ("embedded" or "remote") in the message.
#[derive(Debug, Error, PartialEq)]
pub enum ActionPlanError {
    #[error("{host} action {action} requires {parameter}")]
    MissingParameter {
        host: &'static str,
        action: String,
        parameter: String,
    },
    #[error("unsupported {host} action operation {operation:?}")]
    UnsupportedOperation {
        host: &'static str,
        operation: String,
    },
}

impl ActionWrites {
    /// Resolve `action` against `params`. The target is parameter `id`.
    pub fn plan(
        host: &'static str,
        action_name: &str,
        action: &ActionTypeDef,
        params: &HashMap<String, String>,
    ) -> Result<Self, ActionPlanError> {
        let missing = |parameter: &str| ActionPlanError::MissingParameter {
            host,
            action: action_name.into(),
            parameter: parameter.into(),
        };
        let param = |name: &str| params.get(name).cloned().ok_or_else(|| missing(name));
        let target_id = params
            .get("id")
            .cloned()
            .ok_or_else(|| missing("target parameter id"))?;
        let created = crate::now_millis();
        let writes = action
            .ops
            .iter()
            .map(|op| match op.op.as_str() {
                "set_property" => Ok(ActionWrite::SetProperty {
                    key: op.property.clone(),
                    value: param(&op.value_from)?,
                }),
                "create_link" => {
                    let to_id = param(&op.property)?;
                    Ok(ActionWrite::CreateLink(Link {
                        id: format!("{target_id}--{}--{to_id}", op.relation),
                        from_id: target_id.clone(),
                        to_id,
                        relation: op.relation.clone(),
                        created,
                    }))
                }
                "delete_link" => Ok(ActionWrite::DeleteLink(param(&op.value_from)?)),
                other => Err(ActionPlanError::UnsupportedOperation {
                    host,
                    operation: other.into(),
                }),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { target_id, writes })
    }

    /// Set the action's properties on `target` and stamp `updated`.
    pub fn apply_properties(&self, target: &mut Object) {
        for write in &self.writes {
            if let ActionWrite::SetProperty { key, value } = write {
                target.properties.insert(key.clone(), value.clone());
            }
        }
        target.updated = crate::now_millis();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::graph_action::ActionOp;

    fn op(op: &str, property: &str, value_from: &str, relation: &str) -> ActionOp {
        ActionOp {
            op: op.into(),
            property: property.into(),
            value_from: value_from.into(),
            relation: relation.into(),
        }
    }

    #[test]
    fn a_missing_later_parameter_fails_before_any_write() {
        let action = ActionTypeDef {
            name: "promote".into(),
            ops: vec![
                op("create_link", "to", "", "promoted_to"),
                op("set_property", "state", "state", ""),
            ],
            ..Default::default()
        };
        let params = HashMap::from([("id".into(), "a".into()), ("to".into(), "b".into())]);
        assert_eq!(
            ActionWrites::plan("embedded", "promote", &action, &params),
            Err(ActionPlanError::MissingParameter {
                host: "embedded",
                action: "promote".into(),
                parameter: "state".into(),
            })
        );
    }
}
