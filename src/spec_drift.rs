//! Report-only comparison of applied spec versus the live target (#1028).
//!
//! Drift never becomes a Plan. Secret and env values are never recorded.

use std::collections::BTreeMap;
use std::path::Path;

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
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
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
}
