//! JSON Schema helpers shared by domain types and the HTTP contract.

use schemars::Schema;
use serde_json::{Value, json};

/// Field transform for response-only `Option` fields serialized with
/// `skip_serializing_if = "Option::is_none"`: the wire omits the key and never
/// sends `null`, so the contract must not admit `null` either. The field stays
/// out of `required`. Types also used in requests keep `null`, which serde
/// accepts on input.
pub fn omitted_when_none(schema: &mut Schema) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(Value::Array(types)) = object.get_mut("type") {
        types.retain(|kind| kind != "null");
        if let [only] = types.as_slice() {
            let only = only.clone();
            object.insert("type".into(), only);
        }
    }
    if let Some(Value::Array(branches)) = object.remove("anyOf") {
        let mut branches: Vec<Value> = branches
            .into_iter()
            .filter(|branch| *branch != json!({"type": "null"}))
            .collect();
        match branches.pop() {
            Some(Value::Object(only)) if branches.is_empty() => object.extend(only),
            Some(last) => {
                branches.push(last);
                object.insert("anyOf".into(), Value::Array(branches));
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_when_none_strips_only_the_null_branch() {
        let mut nullable =
            Schema::try_from(json!({"type": ["integer", "null"], "format": "int64"})).unwrap();
        omitted_when_none(&mut nullable);
        assert_eq!(
            nullable.to_value(),
            json!({"type": "integer", "format": "int64"})
        );
        let mut referenced = Schema::try_from(json!({
            "anyOf": [{"$ref": "#/$defs/X"}, {"type": "null"}],
            "description": "d"
        }))
        .unwrap();
        omitted_when_none(&mut referenced);
        assert_eq!(
            referenced.to_value(),
            json!({"$ref": "#/$defs/X", "description": "d"})
        );
        let mut union = Schema::try_from(
            json!({"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]}),
        )
        .unwrap();
        omitted_when_none(&mut union);
        assert_eq!(
            union.to_value(),
            json!({"anyOf": [{"type": "string"}, {"type": "integer"}]})
        );
    }
}
