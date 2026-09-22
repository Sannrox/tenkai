use super::*;

pub(super) fn encode_object(object: &Object) -> String {
    serde_json::to_string(&StoredObject::from_proto(object)).expect("object json")
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct StoredObject {
    id: String,
    kind: String,
    name: String,
    namespace: String,
    properties: BTreeMap<String, String>,
    created: i64,
    updated: i64,
}

impl StoredObject {
    pub(super) fn from_proto(object: &Object) -> Self {
        Self {
            id: object.id.clone(),
            kind: object.kind.clone(),
            name: object.name.clone(),
            namespace: object.namespace.clone(),
            properties: object
                .properties
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            created: object.created,
            updated: object.updated,
        }
    }

    pub(super) fn into_proto(self) -> Object {
        Object {
            id: self.id,
            kind: self.kind,
            name: self.name,
            namespace: self.namespace,
            properties: self.properties.into_iter().collect(),
            created: self.created,
            updated: self.updated,
            ..Object::default()
        }
    }
}

pub(super) fn plan_record_to_object(record: &PlanRecord) -> AnyResult<Object> {
    let plan: Plan = serde_json::from_str(&record.plan_json)?;
    plan.to_object()
}

pub(super) fn environment_record_to_object(record: &EnvironmentRecord) -> AnyResult<Object> {
    if let Ok(stored) = serde_json::from_str::<StoredObject>(&record.configuration_json)
        && (stored.kind == KIND_ENVIRONMENT || stored.id == record.id)
    {
        return Ok(stored.into_proto());
    }
    let name = record
        .id
        .strip_prefix("tenkai:env:")
        .unwrap_or(&record.id)
        .to_string();
    Ok(Object {
        id: record.id.clone(),
        kind: KIND_ENVIRONMENT.into(),
        name,
        namespace: NS.into(),
        properties: std::collections::HashMap::from([(
            "configuration".into(),
            record.configuration_json.clone(),
        )]),
        ..Object::default()
    })
}

pub(super) fn release_record_to_object(record: &ReleaseRecord) -> AnyResult<Object> {
    if let Ok(stored) = serde_json::from_str::<StoredObject>(&record.descriptor_json)
        && (stored.kind == KIND_RELEASE || stored.id == record.id)
    {
        return Ok(stored.into_proto());
    }
    Ok(Object {
        id: record.id.clone(),
        kind: KIND_RELEASE.into(),
        name: format!("{}@{}", record.product, record.version),
        namespace: NS.into(),
        properties: std::collections::HashMap::from([
            ("product".into(), record.product.clone()),
            ("version".into(), record.version.clone()),
            ("digest".into(), record.content_digest.clone()),
            ("content_digest".into(), record.content_digest.clone()),
        ]),
        ..Object::default()
    })
}

pub(super) fn decode_optional(payload: Option<Vec<u8>>, kind: &str) -> AnyResult<Option<Object>> {
    payload
        .map(|bytes| Object::decode(bytes.as_slice()).with_context(|| format!("decoding {kind}")))
        .transpose()
}

pub(super) fn decode_many<T: Message + Default>(
    payloads: Vec<Vec<u8>>,
    kind: &str,
) -> AnyResult<Vec<T>> {
    payloads
        .into_iter()
        .map(|bytes| T::decode(bytes.as_slice()).with_context(|| format!("decoding {kind}")))
        .collect()
}

pub(super) fn is_strict_authority(kind: &str) -> bool {
    STRICT_AUTHORITY_KINDS.contains(&kind)
}
