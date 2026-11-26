//! Shared action-actor and property-index helpers for the client facade.

use anyhow::Result;

use crate::pb::record::{Object, ObjectChange};

pub(crate) fn action_actor_from_changes(
    changes: &[ObjectChange],
    field: &str,
    correlation: &str,
) -> Option<String> {
    changes.iter().find_map(|change| {
        (change.field == field
            && change.new_value == correlation
            && !change.changed_by.trim().is_empty())
        .then(|| change.changed_by.clone())
    })
}

fn property_integer(object: &Object, key: &str) -> Option<i64> {
    object.properties.get(key)?.parse().ok()
}

/// Apply matching/equals/order/limit to an unfiltered `find_by_property` set.
///
/// Tenant catalogs answer only the plain property match; callers that need
/// several OFFSET windows reuse this set instead of re-reading it.
pub(crate) fn apply_property_index(
    mut objects: Vec<Object>,
    query: &crate::embedded::PropertyIndexQuery<'_>,
) -> Result<Vec<Object>> {
    if let Some(filter_key) = query.matching_key {
        objects.retain(|object| {
            object
                .properties
                .get(filter_key)
                .is_some_and(|value| query.matching_values.contains(&value.as_str()))
        });
    }
    if let (Some(equals_key), Some(equals_value)) = (query.equals_key, query.equals_value) {
        objects.retain(|object| match object.properties.get(equals_key) {
            Some(value) => value == equals_value,
            None if equals_key == "has_steps" => {
                payload_has_steps(object) == (equals_value == "true")
            }
            None => false,
        });
    }
    if let Some(order_key) = query.order_key {
        objects.sort_by(|left, right| {
            let order = property_integer(left, order_key).cmp(&property_integer(right, order_key));
            if query.descending {
                order.reverse()
            } else {
                order
            }
        });
    }
    if let Some(offset) = query.offset {
        anyhow::ensure!(
            query.limit.is_some(),
            "find_by_property offset requires a limit"
        );
        let offset = offset as usize;
        if offset >= objects.len() {
            objects.clear();
        } else {
            objects.drain(..offset);
        }
    }
    if let Some(limit) = query.limit {
        objects.truncate(limit as usize);
    }
    Ok(objects)
}

fn payload_has_steps(object: &Object) -> bool {
    object
        .properties
        .get("plan")
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|plan| plan.get("steps")?.as_array().map(|steps| !steps.is_empty()))
        .unwrap_or(false)
}
