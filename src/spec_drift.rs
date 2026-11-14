//! Report-only comparison of applied spec versus the live target (#1028),
//! and desired-versus-live target changes recorded on a Plan step (#1077).
//!
//! Drift never becomes a Plan. Secret and env values are never recorded.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// Inspect/status spelling when no fingerprint exists yet.
pub const SPEC_DRIFT_UNKNOWN: &str = "unknown";
/// Live spec matches what Tenkai applied.
pub const SPEC_DRIFT_CURRENT: &str = "current";
/// Live spec differs from what Tenkai applied.
pub const SPEC_DRIFT_MODIFIED: &str = "modified outside Tenkai";

/// Per-instance drift shown on inspect, status, and support bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpecDriftView {
    /// `unknown`, `current`, or `modified outside Tenkai`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<SpecDriftObject>,
}

impl SpecDriftView {
    pub fn unknown() -> Self {
        Self {
            status: SPEC_DRIFT_UNKNOWN.into(),
            objects: Vec::new(),
        }
    }

    pub fn from_objects(objects: Vec<SpecDriftObject>) -> Self {
        if objects.is_empty() {
            return Self::unknown();
        }
        let modified = objects
            .iter()
            .any(|object| object.status == SPEC_DRIFT_MODIFIED);
        let unknown = objects
            .iter()
            .any(|object| object.status == SPEC_DRIFT_UNKNOWN);
        let current = objects
            .iter()
            .any(|object| object.status == SPEC_DRIFT_CURRENT);
        // Unknown next to current must not report current: that would replace a
        // stored modified report. Confirmed modified still wins.
        let status = if modified {
            SPEC_DRIFT_MODIFIED
        } else if unknown || !current {
            SPEC_DRIFT_UNKNOWN
        } else {
            SPEC_DRIFT_CURRENT
        };
        Self {
            status: status.into(),
            objects,
        }
    }

    pub fn is_modified(&self) -> bool {
        self.status == SPEC_DRIFT_MODIFIED
    }
}

/// One named object in a spec-drift report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpecDriftObject {
    pub kind: String,
    pub name: String,
    /// `unknown`, `current`, or `modified outside Tenkai`.
    pub status: String,
    /// Cheap top-level names: `containers`, `images`, `env`. Never values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

/// Digest spelling when planning saw no live object.
pub const ABSENT_LIVE_DIGEST: &str = "absent";
/// Operator-facing field values longer than this become a digest.
pub const TARGET_FIELD_CAP: usize = 128;

/// Desired-versus-live change for one object, stored on a Plan step (#1077).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TargetChange {
    pub kind: String,
    pub name: String,
    /// Operator-owned fields that differ. Empty when live already matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<TargetFieldChange>,
    /// Count of changed fields. HTTP projections set this so inspect can omit
    /// `fields` and still return per-object counts. Planning leaves it absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub field_count: Option<usize>,
    /// Digest of the live object as planning saw it. `absent` when none.
    pub live_digest: String,
}

impl TargetChange {
    /// HTTP projection: always carry `field_count`. Inspect omits `fields`.
    pub(crate) fn for_http(mut self, include_fields: bool) -> Self {
        let count = self.fields.len();
        self.field_count = (count > 0).then_some(count);
        if !include_fields {
            self.fields.clear();
        }
        self
    }
}

/// Object whose live digest moved since planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StaleTarget {
    pub kind: String,
    pub name: String,
}

impl StaleTarget {
    pub fn from_change(change: &TargetChange) -> Self {
        Self {
            kind: change.kind.clone(),
            name: change.name.clone(),
        }
    }
}

/// One named field of a [`TargetChange`]. Secret values are never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TargetFieldChange {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub to: Option<String>,
}

/// Compare a desired render with the live object. Secret data is digested.
pub fn compare_desired_live(
    kind: &str,
    name: &str,
    desired: &Value,
    live: Option<&Value>,
) -> TargetChange {
    let live_digest = match live {
        None => ABSENT_LIVE_DIGEST.to_string(),
        Some(live) => digest_bytes(&canonical_object(kind, live)),
    };
    let fields = match live {
        None => vec![TargetFieldChange {
            field: "object".into(),
            from: None,
            to: Some("present".into()),
        }],
        Some(live) => diff_canonical(kind, desired, live),
    };
    TargetChange {
        kind: kind.into(),
        name: name.into(),
        fields,
        field_count: None,
        live_digest,
    }
}

/// First planned object whose live digest no longer matches.
pub fn stale_object<'a>(
    planned: &'a [TargetChange],
    live: &[TargetChange],
) -> Option<&'a TargetChange> {
    for planned in planned {
        let digest = live
            .iter()
            .find(|change| change.kind == planned.kind && change.name == planned.name)
            .map(|change| change.live_digest.as_str())
            .unwrap_or(ABSENT_LIVE_DIGEST);
        if digest != planned.live_digest {
            return Some(planned);
        }
    }
    None
}

/// Operator-facing reason to refuse a step whose recorded live target moved.
/// `live` is `None` when the executor that recorded the snapshot is missing.
pub fn stale_step_detail(
    step_id: &str,
    planned: &[TargetChange],
    live: Option<Result<Vec<TargetChange>, String>>,
) -> Option<String> {
    match live {
        None => Some(format!(
            "step {step_id} is stale: the executor that recorded target changes is not installed"
        )),
        Some(Err(error)) => Some(format!(
            "step {step_id} is stale: could not re-observe the target: {error}"
        )),
        Some(Ok(live)) => stale_object(planned, &live).map(|object| {
            format!(
                "step {step_id} is stale: {} {} changed since planning",
                object.kind, object.name
            )
        }),
    }
}

fn canonical_object(kind: &str, object: &Value) -> Value {
    match kind {
        "Secret" | "SealedSecret" => json!({ "data": secret_data_digests(object) }),
        "ConfigMap" => json!({
            "data": object.get("data").cloned().unwrap_or(Value::Null),
            "binaryData": digest_map_field(object, "binaryData"),
        }),
        "Service" => json!({
            "ports": service_ports(object),
            "selector": object.pointer("/spec/selector").cloned().unwrap_or(Value::Null),
        }),
        "Role" => json!({ "rules": object.pointer("/rules").cloned().unwrap_or(Value::Null) }),
        "RoleBinding" => json!({
            "roleRef": object.get("roleRef").cloned().unwrap_or(Value::Null),
            "subjects": object.get("subjects").cloned().unwrap_or(Value::Null),
        }),
        "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "Job" | "CronJob" => {
            plan_workload(object)
        }
        "file" => json!({ "content": object.get("content").cloned().unwrap_or(Value::Null) }),
        _ => json!({ "spec": object.get("spec").cloned().unwrap_or(Value::Null) }),
    }
}

/// Digest Secret `data` (base64) and `stringData` (plain) to the same bytes.
/// `stringData` wins on a colliding key, matching Kubernetes apply.
fn secret_data_digests(object: &Value) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    if let Some(data) = object.get("data").and_then(Value::as_object) {
        for (key, value) in data {
            entries.insert(key.clone(), digest_secret_data_value(value));
        }
    }
    if let Some(string_data) = object.get("stringData").and_then(Value::as_object) {
        for (key, value) in string_data {
            let digest = match value.as_str() {
                Some(raw) => digest_raw(raw.as_bytes()),
                None => digest_bytes(value),
            };
            entries.insert(key.clone(), digest);
        }
    }
    entries
}

fn digest_secret_data_value(value: &Value) -> String {
    match value.as_str() {
        Some(raw) => match STANDARD.decode(raw) {
            Ok(bytes) => digest_raw(&bytes),
            Err(_) => digest_raw(raw.as_bytes()),
        },
        None => digest_bytes(value),
    }
}

fn digest_map_field(object: &Value, field: &str) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    let Some(data) = object.get(field).and_then(Value::as_object) else {
        return entries;
    };
    for (key, value) in data {
        let digest = match value.as_str() {
            Some(raw) => digest_raw(raw.as_bytes()),
            None => digest_bytes(value),
        };
        entries.insert(key.clone(), digest);
    }
    entries
}

fn plan_workload(object: &Value) -> Value {
    let spec = object.get("spec").unwrap_or(&Value::Null);
    json!({
        "replicas": spec.get("replicas").cloned().unwrap_or(Value::Null),
        "schedule": spec.get("schedule").cloned().unwrap_or(Value::Null),
        "containers": plan_containers(pod_spec(object), "containers"),
        "initContainers": plan_containers(pod_spec(object), "initContainers"),
        "volumes": plan_volumes(pod_spec(object)),
    })
}

fn pod_spec(object: &Value) -> Option<&Value> {
    object
        .pointer("/spec/jobTemplate/spec/template/spec")
        .or_else(|| object.pointer("/spec/template/spec"))
}

fn plan_containers(spec: Option<&Value>, key: &str) -> Vec<Value> {
    let mut containers = spec
        .and_then(|spec| spec.get(key))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|container| {
            json!({
                "name": container.get("name").and_then(Value::as_str).unwrap_or(""),
                "image": container.get("image").and_then(Value::as_str).unwrap_or(""),
                "command": container.get("command").cloned().unwrap_or(Value::Null),
                "args": container.get("args").cloned().unwrap_or(Value::Null),
                "env": plan_env(container),
                "volumeMounts": plan_volume_mounts(container),
            })
        })
        .collect::<Vec<_>>();
    containers.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });
    containers
}

fn plan_env(container: &Value) -> Vec<Value> {
    let mut env = container
        .get("env")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| {
            json!({
                "name": entry.get("name").and_then(Value::as_str).unwrap_or(""),
                "value": entry.get("value").and_then(Value::as_str).map(digest_text),
                "valueFrom": entry.get("valueFrom").cloned().unwrap_or(Value::Null),
            })
        })
        .collect::<Vec<_>>();
    env.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });
    env
}

fn digest_text(value: &str) -> String {
    digest_raw(value.as_bytes())
}

fn plan_volume_mounts(container: &Value) -> Vec<Value> {
    let mut mounts = container
        .get("volumeMounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|mount| {
            json!({
                "name": mount.get("name").and_then(Value::as_str).unwrap_or(""),
                "mountPath": mount.get("mountPath").and_then(Value::as_str).unwrap_or(""),
            })
        })
        .collect::<Vec<_>>();
    mounts.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });
    mounts
}

fn plan_volumes(spec: Option<&Value>) -> Vec<Value> {
    let mut volumes = spec
        .and_then(|spec| spec.get("volumes"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|volume| {
            json!({
                "name": volume.get("name").and_then(Value::as_str).unwrap_or(""),
                "source": volume_source(volume),
            })
        })
        .collect::<Vec<_>>();
    volumes.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });
    volumes
}

fn volume_source(volume: &Value) -> Value {
    if let Some(name) = volume.pointer("/secret/secretName") {
        return json!({"secret": name});
    }
    if let Some(name) = volume.pointer("/configMap/name") {
        return json!({"configMap": name});
    }
    if let Some(name) = volume.pointer("/persistentVolumeClaim/claimName") {
        return json!({"persistentVolumeClaim": name});
    }
    if volume.get("emptyDir").is_some() {
        return json!({"emptyDir": true});
    }
    if let Some(path) = volume.pointer("/hostPath/path") {
        return json!({"hostPath": path});
    }
    json!(
        volume
            .as_object()
            .and_then(|map| map.keys().find(|key| *key != "name"))
            .cloned()
    )
}

fn service_ports(object: &Value) -> Value {
    let mut ports = object
        .pointer("/spec/ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|port| {
            json!({
                "name": port.get("name").and_then(Value::as_str).unwrap_or(""),
                "port": port.get("port").cloned().unwrap_or(Value::Null),
                "targetPort": port.get("targetPort").cloned().unwrap_or(Value::Null),
                "protocol": port.get("protocol").and_then(Value::as_str).unwrap_or("TCP"),
            })
        })
        .collect::<Vec<_>>();
    ports.sort_by(|left, right| {
        left.get("port")
            .map(ToString::to_string)
            .cmp(&right.get("port").map(ToString::to_string))
    });
    json!(ports)
}

fn diff_canonical(kind: &str, desired: &Value, live: &Value) -> Vec<TargetFieldChange> {
    let desired_canon = canonical_object(kind, desired);
    let live_canon = canonical_object(kind, live);
    if desired_canon == live_canon {
        return Vec::new();
    }
    let Some(desired_map) = desired_canon.as_object() else {
        return vec![field_change(
            "spec",
            Some(&live_canon),
            Some(&desired_canon),
        )];
    };
    let live_map = live_canon.as_object();
    let mut fields = Vec::new();
    for (key, to) in desired_map {
        let from = live_map.and_then(|map| map.get(key));
        if from != Some(to) {
            fields.push(field_change(key, from, Some(to)));
        }
    }
    if let Some(live_map) = live_map {
        for (key, from) in live_map {
            if !desired_map.contains_key(key) {
                fields.push(field_change(key, Some(from), None));
            }
        }
    }
    if fields.is_empty() {
        fields.push(field_change(
            "spec",
            Some(&live_canon),
            Some(&desired_canon),
        ));
    }
    fields
}

fn field_change(field: &str, from: Option<&Value>, to: Option<&Value>) -> TargetFieldChange {
    if field == "volumes" {
        return volumes_field_change(from, to);
    }
    TargetFieldChange {
        field: field.into(),
        from: from.map(display_field),
        to: to.map(display_field),
    }
}

/// Keep `{name, source}` when it fits. Over the cap, store a name array so
/// deleted-volume detection still works. Source-only edits over the cap keep
/// hashed `from`/`to` so the change stays visible.
fn volumes_field_change(from: Option<&Value>, to: Option<&Value>) -> TargetFieldChange {
    let from_raw = from.map(render_field);
    let to_raw = to.map(render_field);
    let over_cap = from_raw
        .as_ref()
        .is_some_and(|raw| raw.len() > TARGET_FIELD_CAP)
        || to_raw
            .as_ref()
            .is_some_and(|raw| raw.len() > TARGET_FIELD_CAP);
    if !over_cap {
        return TargetFieldChange {
            field: "volumes".into(),
            from: from_raw,
            to: to_raw,
        };
    }
    let from_names = from.and_then(compact_volume_names);
    let to_names = to.and_then(compact_volume_names);
    if from_names == to_names && from_raw != to_raw {
        return TargetFieldChange {
            field: "volumes".into(),
            from: from.map(display_field),
            to: to.map(display_field),
        };
    }
    TargetFieldChange {
        field: "volumes".into(),
        from: from_names.or_else(|| from.map(display_field)),
        to: to_names.or_else(|| to.map(display_field)),
    }
}

fn compact_volume_names(value: &Value) -> Option<String> {
    let names = volume_name_list(value)?;
    let raw = Value::Array(names.into_iter().map(Value::String).collect()).to_string();
    (raw.len() <= TARGET_FIELD_CAP).then_some(raw)
}

fn volume_name_list(value: &Value) -> Option<Vec<String>> {
    let array = value.as_array()?;
    Some(
        array
            .iter()
            .filter_map(|item| {
                item.get("name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
                    .or_else(|| {
                        item.as_str()
                            .filter(|name| !name.is_empty())
                            .map(str::to_string)
                    })
            })
            .collect(),
    )
}

fn render_field(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn display_field(value: &Value) -> String {
    let raw = render_field(value);
    if raw.len() <= TARGET_FIELD_CAP {
        return raw;
    }
    format!("sha256:{}", digest_bytes(&json!(raw)))
}

/// Digest of the operator-owned pod-template fields Tenkai compares.
pub fn workload_spec_fingerprint(object: &Value) -> Option<String> {
    Some(digest_bytes(&canonical_workload_spec(object)?))
}

/// Compare an applied workload object with the live object.
pub fn compare_workload_spec(
    kind: &str,
    name: &str,
    applied: &Value,
    live: &Value,
) -> SpecDriftObject {
    let Some(applied_spec) = canonical_workload_spec(applied) else {
        return SpecDriftObject {
            kind: kind.into(),
            name: name.into(),
            status: SPEC_DRIFT_UNKNOWN.into(),
            fields: Vec::new(),
        };
    };
    let Some(live_spec) = canonical_workload_spec(live) else {
        return SpecDriftObject {
            kind: kind.into(),
            name: name.into(),
            status: SPEC_DRIFT_UNKNOWN.into(),
            fields: Vec::new(),
        };
    };
    if applied_spec == live_spec {
        return SpecDriftObject {
            kind: kind.into(),
            name: name.into(),
            status: SPEC_DRIFT_CURRENT.into(),
            fields: Vec::new(),
        };
    }
    SpecDriftObject {
        kind: kind.into(),
        name: name.into(),
        status: SPEC_DRIFT_MODIFIED.into(),
        fields: differing_fields(&applied_spec, &live_spec),
    }
}

/// Digest of named host files or units as apply wrote them.
pub fn host_files_fingerprint(files: &BTreeMap<String, String>) -> String {
    let value = json!(files);
    digest_bytes(&value)
}

/// Compare recorded host file/unit digests with live hashes of those paths.
pub fn compare_host_files(
    applied: &BTreeMap<String, String>,
    live: &BTreeMap<String, String>,
) -> SpecDriftView {
    if applied.is_empty() {
        return SpecDriftView::unknown();
    }
    let mut objects = Vec::new();
    for (name, digest) in applied {
        let Some(live_digest) = live.get(name) else {
            objects.push(SpecDriftObject {
                kind: "file".into(),
                name: name.clone(),
                status: SPEC_DRIFT_UNKNOWN.into(),
                fields: Vec::new(),
            });
            continue;
        };
        if live_digest == digest {
            objects.push(SpecDriftObject {
                kind: "file".into(),
                name: name.clone(),
                status: SPEC_DRIFT_CURRENT.into(),
                fields: Vec::new(),
            });
        } else {
            objects.push(SpecDriftObject {
                kind: "file".into(),
                name: name.clone(),
                status: SPEC_DRIFT_MODIFIED.into(),
                fields: vec!["content".into()],
            });
        }
    }
    SpecDriftView::from_objects(objects)
}

/// SHA-256 hex of a regular file's bytes. Missing or unreadable paths yield `None`.
pub fn file_content_digest(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize()))
}

fn canonical_workload_spec(object: &Value) -> Option<Value> {
    let spec = object.pointer("/spec/template/spec")?;
    Some(json!({
        "containers": extract_containers(spec, "containers"),
        "initContainers": extract_containers(spec, "initContainers"),
    }))
}

fn extract_containers(spec: &Value, key: &str) -> Vec<Value> {
    let mut containers = spec
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(extract_container)
        .collect::<Vec<_>>();
    containers.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });
    containers
}

fn extract_container(container: &Value) -> Option<Value> {
    let name = container.get("name")?.as_str()?.to_string();
    let image = container
        .get("image")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut env = container
        .get("env")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("name")?.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    env.sort();
    env.dedup();
    Some(json!({
        "name": name,
        "image": image,
        "env": env,
    }))
}

fn differing_fields(applied: &Value, live: &Value) -> Vec<String> {
    let mut fields = Vec::new();
    if container_names(applied, "containers") != container_names(live, "containers")
        || container_names(applied, "initContainers") != container_names(live, "initContainers")
    {
        fields.push("containers".into());
        return fields;
    }
    if container_images(applied) != container_images(live) {
        fields.push("images".into());
    }
    if container_env_names(applied) != container_env_names(live) {
        fields.push("env".into());
    }
    if fields.is_empty() {
        fields.push("spec".into());
    }
    fields
}

fn container_names(spec: &Value, key: &str) -> Vec<String> {
    spec.get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|container| container.get("name")?.as_str().map(str::to_string))
        .collect()
}

fn container_images(spec: &Value) -> Vec<(String, String)> {
    ["containers", "initContainers"]
        .into_iter()
        .flat_map(|key| {
            spec.get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|container| {
                    Some((
                        container.get("name")?.as_str()?.to_string(),
                        container
                            .get("image")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    ))
                })
        })
        .collect()
}

fn container_env_names(spec: &Value) -> Vec<(String, Vec<String>)> {
    ["containers", "initContainers"]
        .into_iter()
        .flat_map(|key| {
            spec.get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|container| {
                    let name = container.get("name")?.as_str()?.to_string();
                    let env = container
                        .get("env")
                        .cloned()
                        .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
                        .unwrap_or_default();
                    Some((name, env))
                })
        })
        .collect()
}

fn digest_bytes(value: &Value) -> String {
    digest_raw(&serde_json::to_vec(value).unwrap_or_default())
}

fn digest_raw(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn deployment(containers: Value) -> Value {
        json!({
            "kind": "Deployment",
            "metadata": {
                "name": "web",
                "annotations": {
                    "deployment.kubernetes.io/revision": "2",
                    "kubectl.kubernetes.io/last-applied-configuration": "{}"
                }
            },
            "spec": {
                "replicas": 3,
                "template": {
                    "spec": {
                        "containers": containers
                    }
                }
            },
            "status": {"replicas": 3, "availableReplicas": 3}
        })
    }

    #[test]
    fn kubernetes_managed_fields_do_not_count_as_drift() {
        let applied = deployment(json!([{
            "name": "app",
            "image": "app:1",
            "imagePullPolicy": "IfNotPresent",
            "env": [{"name": "REGION", "value": "eu"}]
        }]));
        let mut live = applied.clone();
        live["status"]["replicas"] = json!(5);
        live["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = json!("9");
        live["spec"]["replicas"] = json!(5);
        live["spec"]["template"]["spec"]["containers"][0]["imagePullPolicy"] = json!("Always");
        live["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] = json!("secret");
        let report = compare_workload_spec("Deployment", "web", &applied, &live);
        assert_eq!(report.status, SPEC_DRIFT_CURRENT);
        assert!(report.fields.is_empty());
    }

    #[test]
    fn an_extra_container_is_modified_outside_tenkai() {
        let applied = deployment(json!([{
            "name": "app",
            "image": "app:1",
            "env": [{"name": "REGION"}]
        }]));
        let live = deployment(json!([
            {"name": "app", "image": "app:1", "env": [{"name": "REGION"}]},
            {"name": "sidecar", "image": "proxy:1"}
        ]));
        let report = compare_workload_spec("Deployment", "web", &applied, &live);
        assert_eq!(report.status, SPEC_DRIFT_MODIFIED);
        assert_eq!(report.fields, vec!["containers"]);
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("proxy:1"), "{encoded}");
    }

    #[test]
    fn image_and_env_name_changes_are_named() {
        let applied = deployment(json!([{
            "name": "app",
            "image": "app:1",
            "env": [{"name": "REGION"}]
        }]));
        let live = deployment(json!([{
            "name": "app",
            "image": "app:2",
            "env": [{"name": "REGION"}, {"name": "DEBUG"}]
        }]));
        let report = compare_workload_spec("Deployment", "web", &applied, &live);
        assert_eq!(report.status, SPEC_DRIFT_MODIFIED);
        assert_eq!(report.fields, vec!["images", "env"]);
    }

    #[test]
    fn mixed_unknown_and_current_is_unknown() {
        let view = SpecDriftView::from_objects(vec![
            SpecDriftObject {
                kind: "Deployment".into(),
                name: "a".into(),
                status: SPEC_DRIFT_CURRENT.into(),
                fields: Vec::new(),
            },
            SpecDriftObject {
                kind: "Deployment".into(),
                name: "b".into(),
                status: SPEC_DRIFT_UNKNOWN.into(),
                fields: Vec::new(),
            },
        ]);
        assert_eq!(view.status, SPEC_DRIFT_UNKNOWN);
        let mixed = SpecDriftView::from_objects(vec![
            SpecDriftObject {
                kind: "Deployment".into(),
                name: "a".into(),
                status: SPEC_DRIFT_MODIFIED.into(),
                fields: vec!["images".into()],
            },
            SpecDriftObject {
                kind: "Deployment".into(),
                name: "b".into(),
                status: SPEC_DRIFT_UNKNOWN.into(),
                fields: Vec::new(),
            },
        ]);
        assert_eq!(mixed.status, SPEC_DRIFT_MODIFIED);
    }

    #[test]
    fn host_file_digest_mismatch_is_modified_without_content() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-host-drift-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("unit");
        std::fs::write(&path, "applied\n").unwrap();
        let applied_digest = file_content_digest(&path).unwrap();
        std::fs::write(&path, "hand-patch\n").unwrap();
        let live_digest = file_content_digest(&path).unwrap();
        let mut applied = BTreeMap::new();
        applied.insert("web.service".into(), applied_digest);
        let mut live = BTreeMap::new();
        live.insert("web.service".into(), live_digest);
        let report = compare_host_files(&applied, &live);
        assert_eq!(report.status, SPEC_DRIFT_MODIFIED);
        assert_eq!(report.objects[0].fields, vec!["content"]);
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("hand-patch"), "{encoded}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_service_port_change_is_named() {
        let desired = json!({
            "kind": "Service",
            "metadata": {"name": "web"},
            "spec": {"ports": [{"port": 80, "targetPort": 8080}]}
        });
        let live = json!({
            "kind": "Service",
            "metadata": {"name": "web"},
            "spec": {"ports": [{"port": 8080, "targetPort": 8080}]}
        });
        let change = compare_desired_live("Service", "web", &desired, Some(&live));
        assert_eq!(change.fields.len(), 1);
        assert_eq!(change.fields[0].field, "ports");
        let from = change.fields[0].from.as_deref().unwrap();
        let to = change.fields[0].to.as_deref().unwrap();
        assert!(from.contains("8080"), "{from}");
        assert!(to.contains("80"), "{to}");
        let again = compare_desired_live("Service", "web", &desired, Some(&live));
        assert_eq!(change, again);
        let selector_live = json!({
            "kind": "Service",
            "metadata": {"name": "web"},
            "spec": {"ports": [{"port": 80, "targetPort": 8080}], "selector": {"app": "old"}}
        });
        let selector_desired = json!({
            "kind": "Service",
            "metadata": {"name": "web"},
            "spec": {"ports": [{"port": 80, "targetPort": 8080}], "selector": {"app": "web"}}
        });
        let selector =
            compare_desired_live("Service", "web", &selector_desired, Some(&selector_live));
        assert_eq!(selector.fields[0].field, "selector");
    }

    #[test]
    fn a_secret_change_shows_only_a_digest() {
        let desired = json!({
            "kind": "Secret",
            "metadata": {"name": "token"},
            "data": {"password": "c2VjcmV0LXZhbHVl"}
        });
        let live = json!({
            "kind": "Secret",
            "metadata": {"name": "token"},
            "data": {"password": "b2xkLXZhbHVl"}
        });
        let change = compare_desired_live("Secret", "token", &desired, Some(&live));
        assert_eq!(change.fields[0].field, "data");
        let encoded = serde_json::to_string(&change).unwrap();
        assert!(!encoded.contains("c2VjcmV0LXZhbHVl"), "{encoded}");
        assert!(!encoded.contains("b2xkLXZhbHVl"), "{encoded}");
        assert!(!encoded.contains("secret-value"), "{encoded}");
    }

    #[test]
    fn string_data_and_data_of_the_same_secret_match() {
        let desired = json!({"stringData": {"password": "secret-value"}});
        let live = json!({"data": {"password": "c2VjcmV0LXZhbHVl"}});
        let change = compare_desired_live("Secret", "token", &desired, Some(&live));
        assert!(change.fields.is_empty(), "{change:?}");
        let encoded = serde_json::to_string(&change).unwrap();
        assert!(!encoded.contains("secret-value"), "{encoded}");
    }

    #[test]
    fn an_env_value_change_is_digested() {
        let desired = json!({
            "spec": {"template": {"spec": {"containers": [{
                "name": "app",
                "image": "app:1",
                "env": [{"name": "TOKEN", "value": "next"}]
            }]}}}
        });
        let live = json!({
            "spec": {"template": {"spec": {"containers": [{
                "name": "app",
                "image": "app:1",
                "env": [{"name": "TOKEN", "value": "prev"}]
            }]}}}
        });
        let change = compare_desired_live("Deployment", "web", &desired, Some(&live));
        assert_eq!(change.fields[0].field, "containers");
        let encoded = serde_json::to_string(&change).unwrap();
        assert!(!encoded.contains("next"), "{encoded}");
        assert!(!encoded.contains("prev"), "{encoded}");
        assert!(
            stale_object(std::slice::from_ref(&change), std::slice::from_ref(&change)).is_none()
        );
        let moved = compare_desired_live("Deployment", "web", &desired, Some(&live));
        assert_eq!(change.live_digest, moved.live_digest);
        let other_live = json!({
            "spec": {"template": {"spec": {"containers": [{
                "name": "app",
                "image": "app:1",
                "env": [{"name": "TOKEN", "value": "other"}]
            }]}}}
        });
        let now = compare_desired_live("Deployment", "web", &desired, Some(&other_live));
        assert!(stale_object(std::slice::from_ref(&change), std::slice::from_ref(&now)).is_some());
    }

    #[test]
    fn a_dropped_volume_is_named() {
        let desired = json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "app", "image": "app:1"}],
                "volumes": [{"name": "config", "configMap": {"name": "app"}}]
            }}}
        });
        let live = json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "app", "image": "app:1"}],
                "volumes": [
                    {"name": "config", "configMap": {"name": "app"}},
                    {"name": "cache", "emptyDir": {}}
                ]
            }}}
        });
        let change = compare_desired_live("Deployment", "web", &desired, Some(&live));
        assert_eq!(change.fields[0].field, "volumes");
        let from = change.fields[0].from.as_deref().unwrap();
        assert!(from.contains("cache"), "{from}");
    }

    #[test]
    fn a_role_rule_change_is_named() {
        let desired = json!({"rules": [{"verbs": ["get"], "resources": ["pods"]}]});
        let live = json!({"rules": [{"verbs": ["*"], "resources": ["pods"]}]});
        let change = compare_desired_live("Role", "reader", &desired, Some(&live));
        assert_eq!(change.fields[0].field, "rules");
        assert!(change.fields[0].from.as_deref().unwrap().contains('*'));
    }

    #[test]
    fn a_cronjob_template_image_change_is_named() {
        let desired = json!({
            "spec": {
                "schedule": "0 * * * *",
                "jobTemplate": {"spec": {"template": {"spec": {
                    "containers": [{"name": "job", "image": "job:2"}]
                }}}}
            }
        });
        let live = json!({
            "spec": {
                "schedule": "0 * * * *",
                "jobTemplate": {"spec": {"template": {"spec": {
                    "containers": [{"name": "job", "image": "job:1"}]
                }}}}
            }
        });
        let change = compare_desired_live("CronJob", "nightly", &desired, Some(&live));
        assert_eq!(change.fields[0].field, "containers");
        assert!(change.fields[0].to.as_deref().unwrap().contains("job:2"));
    }

    #[test]
    fn a_moved_live_digest_is_stale() {
        let desired = json!({"kind": "Service", "metadata": {"name": "web"}, "spec": {"ports": [{"port": 80}]}});
        let live = json!({"kind": "Service", "metadata": {"name": "web"}, "spec": {"ports": [{"port": 8080}]}});
        let planned = compare_desired_live("Service", "web", &desired, Some(&live));
        let moved = json!({"kind": "Service", "metadata": {"name": "web"}, "spec": {"ports": [{"port": 9090}]}});
        let now = compare_desired_live("Service", "web", &desired, Some(&moved));
        let stale = stale_object(std::slice::from_ref(&planned), std::slice::from_ref(&now));
        assert_eq!(stale.map(|change| change.name.as_str()), Some("web"));
        assert!(
            stale_object(
                std::slice::from_ref(&planned),
                std::slice::from_ref(&planned)
            )
            .is_none()
        );
    }

    #[test]
    fn a_configmap_data_change_is_named() {
        let desired = json!({"data": {"note": "next"}});
        let live = json!({"data": {"note": "prev"}});
        let change = compare_desired_live("ConfigMap", "cfg", &desired, Some(&live));
        assert_eq!(change.fields[0].field, "data");
        assert_eq!(
            change.fields[0].from.as_deref(),
            Some("{\"note\":\"prev\"}")
        );
        assert_eq!(change.fields[0].to.as_deref(), Some("{\"note\":\"next\"}"));
    }

    #[test]
    fn a_long_field_value_is_capped_to_a_digest() {
        let long = "x".repeat(TARGET_FIELD_CAP + 8);
        let desired = json!({"data": {"note": long}});
        let live = json!({"data": {"note": "short"}});
        let change = compare_desired_live("ConfigMap", "cfg", &desired, Some(&live));
        let to = change.fields[0].to.as_deref().unwrap();
        assert!(to.starts_with("sha256:"), "{to}");
        assert!(!to.contains("xxxxxxxx"), "{to}");
    }
}
