//! Declared Kubernetes namespaces as managed objects of an environment (#1096).
//!
//! Operators declare cluster namespaces on the environment, bind instances to
//! them, and create, change, or delete them only as approved plan steps. Removing
//! a declaration never deletes the namespace in the cluster.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::ontology::validate_identifier;
use crate::pb::sekai::Object;

pub const DECLARED_PROPERTY: &str = "cluster_namespaces";
pub const APPLIED_PROPERTY: &str = "applied_cluster_namespaces";
pub const DELETES_PROPERTY: &str = "cluster_namespace_deletes";
pub const BINDINGS_PROPERTY: &str = "cluster_namespace_bindings";

const QUOTA_OBJECT: &str = "tenkai";
const LIMIT_RANGE_OBJECT: &str = "tenkai";

const RESERVED: &[&str] = &["default", "kube-system", "kube-public", "kube-node-lease"];

/// Labels, quota, and limit range of one declared cluster namespace.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterNamespaceSpec {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// ResourceQuota `.spec.hard` quantities, for example `cpu` or `pods`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quota: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limit_range: Vec<LimitRangeItem>,
}

/// One LimitRange `.spec.limits` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LimitRangeItem {
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub max: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub min: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub default: BTreeMap<String, String>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        rename = "defaultRequest"
    )]
    pub default_request: BTreeMap<String, String>,
}

/// One create, update, or delete in an executable plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterNamespaceStep {
    pub name: String,
    pub action: ClusterNamespaceAction,
    pub spec: ClusterNamespaceSpec,
}

/// Request the cluster executor applies for one cluster-namespace plan step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterNamespaceApplyRequest {
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_config_path: Option<std::path::PathBuf>,
    pub name: String,
    pub action: ClusterNamespaceAction,
    pub spec: ClusterNamespaceSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterNamespaceAction {
    Create,
    Update,
    Delete,
}

impl ClusterNamespaceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// Inspect/status row: one cluster namespace and the instances in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClusterNamespaceStatus {
    pub name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quota: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<String>,
    /// `declared`, `applied`, or `pending_delete`.
    pub state: String,
}

/// DNS-1123 label: Kubernetes Namespace names.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 63 {
        bail!("cluster namespace name must be a DNS label of at most 63 characters");
    }
    let bytes = name.as_bytes();
    let start = bytes[0];
    let end = bytes[bytes.len() - 1];
    if !start.is_ascii_lowercase() && !start.is_ascii_digit() {
        bail!("cluster namespace name must start with a lowercase letter or digit");
    }
    if !end.is_ascii_lowercase() && !end.is_ascii_digit() {
        bail!("cluster namespace name must end with a lowercase letter or digit");
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        bail!("cluster namespace name must contain only lowercase letters, digits, or '-'");
    }
    Ok(())
}

pub(crate) fn validate_spec(spec: &ClusterNamespaceSpec) -> Result<()> {
    for (key, value) in spec.labels.iter().chain(spec.annotations.iter()) {
        if key.is_empty() || key.len() > 253 || key.chars().any(char::is_control) {
            bail!(
                "cluster namespace label or annotation key is empty, oversized, or contains a control character"
            );
        }
        if value.len() > 63 || value.chars().any(char::is_control) {
            bail!(
                "cluster namespace label or annotation value is oversized or contains a control character"
            );
        }
    }
    for (key, value) in &spec.quota {
        if key.is_empty() || value.is_empty() || key.chars().any(char::is_control) {
            bail!("cluster namespace quota entries must have a resource name and a quantity");
        }
    }
    for item in &spec.limit_range {
        if item.type_name.is_empty() {
            bail!("cluster namespace limit range items need a type");
        }
    }
    Ok(())
}

fn parse_map(
    properties: &std::collections::HashMap<String, String>,
    key: &str,
) -> Result<BTreeMap<String, ClusterNamespaceSpec>> {
    let Some(raw) = properties.get(key) else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_str(raw)
        .map_err(|error| anyhow::anyhow!("{key} is not valid cluster namespace JSON: {error}"))
}

fn parse_bindings(
    properties: &std::collections::HashMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let Some(raw) = properties.get(BINDINGS_PROPERTY) else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_str(raw)
        .map_err(|error| anyhow::anyhow!("{BINDINGS_PROPERTY} is not valid JSON: {error}"))
}

fn parse_deletes(
    properties: &std::collections::HashMap<String, String>,
) -> Result<BTreeSet<String>> {
    let Some(raw) = properties.get(DELETES_PROPERTY) else {
        return Ok(BTreeSet::new());
    };
    let names: Vec<String> = serde_json::from_str(raw)
        .map_err(|error| anyhow::anyhow!("{DELETES_PROPERTY} is not valid JSON: {error}"))?;
    Ok(names.into_iter().collect())
}

fn write_map(
    env_obj: &mut Object,
    key: &str,
    value: &BTreeMap<String, ClusterNamespaceSpec>,
) -> Result<()> {
    if value.is_empty() {
        env_obj.properties.remove(key);
    } else {
        env_obj
            .properties
            .insert(key.into(), serde_json::to_string(value)?);
    }
    Ok(())
}

fn write_bindings(env_obj: &mut Object, value: &BTreeMap<String, String>) -> Result<()> {
    if value.is_empty() {
        env_obj.properties.remove(BINDINGS_PROPERTY);
    } else {
        env_obj
            .properties
            .insert(BINDINGS_PROPERTY.into(), serde_json::to_string(value)?);
    }
    Ok(())
}

fn write_deletes(env_obj: &mut Object, value: &BTreeSet<String>) -> Result<()> {
    if value.is_empty() {
        env_obj.properties.remove(DELETES_PROPERTY);
    } else {
        env_obj.properties.insert(
            DELETES_PROPERTY.into(),
            serde_json::to_string(&value.iter().collect::<Vec<_>>())?,
        );
    }
    Ok(())
}

async fn put_env(ctx: &mut Ctx, mut env_obj: Object) -> Result<()> {
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(())
}

/// Cluster namespace an instance deploys into. Empty binding means the environment name.
pub fn instance_namespace(env_obj: &Object, instance: &str) -> Result<String> {
    let bindings = parse_bindings(&env_obj.properties)?;
    Ok(bindings
        .get(instance)
        .cloned()
        .unwrap_or_else(|| env_obj.name.clone()))
}

/// Stamp the instance's cluster namespace onto a software apply request.
/// Set `request.instance` first. The environment name is stored as empty so
/// [`crate::software_executor::SoftwareApplyRequest::target_namespace`] still
/// returns the environment name for unbound instances.
pub fn stamp_request(
    request: &mut crate::software_executor::SoftwareApplyRequest,
    env_obj: &Object,
) -> Result<()> {
    let name = instance_namespace(env_obj, request.instance_name())?;
    request.cluster_namespace = if name == request.environment {
        String::new()
    } else {
        name
    };
    Ok(())
}

pub fn declared(env_obj: &Object) -> Result<BTreeMap<String, ClusterNamespaceSpec>> {
    parse_map(&env_obj.properties, DECLARED_PROPERTY)
}

pub fn applied(env_obj: &Object) -> Result<BTreeMap<String, ClusterNamespaceSpec>> {
    parse_map(&env_obj.properties, APPLIED_PROPERTY)
}

/// Declare or replace one cluster namespace. Does not create it in the cluster.
pub async fn set(
    ctx: &mut Ctx,
    env: &str,
    name: &str,
    spec: ClusterNamespaceSpec,
) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_name(name)?;
    validate_spec(&spec)?;
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    let mut declared = parse_map(&env_obj.properties, DECLARED_PROPERTY)?;
    declared.insert(name.to_string(), spec);
    write_map(&mut env_obj, DECLARED_PROPERTY, &declared)?;
    let mut deletes = parse_deletes(&env_obj.properties)?;
    deletes.remove(name);
    write_deletes(&mut env_obj, &deletes)?;
    put_env(ctx, env_obj).await?;
    Ok(format!("set {env} cluster namespace {name}"))
}

/// Drop a declaration. The namespace stays in the cluster.
pub async fn clear(ctx: &mut Ctx, env: &str, name: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_name(name)?;
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    let mut declared = parse_map(&env_obj.properties, DECLARED_PROPERTY)?;
    if declared.remove(name).is_none() {
        bail!("environment {env} has no cluster namespace {name}");
    }
    write_map(&mut env_obj, DECLARED_PROPERTY, &declared)?;
    let mut deletes = parse_deletes(&env_obj.properties)?;
    deletes.remove(name);
    write_deletes(&mut env_obj, &deletes)?;
    put_env(ctx, env_obj).await?;
    Ok(format!(
        "cleared {env} cluster namespace {name} declaration"
    ))
}

/// Queue an approved delete step. Refused while instances still bind to it.
pub async fn request_delete(ctx: &mut Ctx, env: &str, name: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_name(name)?;
    refuse_reserved_delete(name)?;
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    refuse_unmanaged_delete(&env_obj, name)?;
    refuse_delete_with_instances(&env_obj, name)?;
    let mut deletes = parse_deletes(&env_obj.properties)?;
    deletes.insert(name.to_string());
    write_deletes(&mut env_obj, &deletes)?;
    put_env(ctx, env_obj).await?;
    Ok(format!(
        "queued delete of {env} cluster namespace {name}; the next approved plan removes it"
    ))
}

/// Bind an instance to a declared cluster namespace, or to the environment name.
pub async fn bind(ctx: &mut Ctx, env: &str, instance: &str, name: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("instance", instance)?;
    validate_name(name)?;
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    refuse_bind_while_deployed(&env_obj, instance)?;
    let deletes = parse_deletes(&env_obj.properties)?;
    if deletes.contains(name) {
        bail!(
            "cluster namespace {name} is pending delete; bind after the delete is cancelled or completed"
        );
    }
    let declared = parse_map(&env_obj.properties, DECLARED_PROPERTY)?;
    if name != env_obj.name && !declared.contains_key(name) {
        bail!("cluster namespace {name} is not declared on {env}");
    }
    let mut bindings = parse_bindings(&env_obj.properties)?;
    if name == env_obj.name {
        bindings.remove(instance);
    } else {
        bindings.insert(instance.to_string(), name.to_string());
    }
    write_bindings(&mut env_obj, &bindings)?;
    put_env(ctx, env_obj).await?;
    Ok(format!(
        "bound {env} instance {instance} to cluster namespace {name}"
    ))
}

/// Restore the default (environment name) for an instance.
pub async fn unbind(ctx: &mut Ctx, env: &str, instance: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_identifier("instance", instance)?;
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    refuse_bind_while_deployed(&env_obj, instance)?;
    let mut bindings = parse_bindings(&env_obj.properties)?;
    if bindings.remove(instance).is_none() {
        bail!("{env} instance {instance} already uses the default cluster namespace");
    }
    write_bindings(&mut env_obj, &bindings)?;
    put_env(ctx, env_obj).await?;
    Ok(format!(
        "cleared {env} instance {instance} cluster namespace binding"
    ))
}

fn refuse_bind_while_deployed(env_obj: &Object, instance: &str) -> Result<()> {
    if env_obj
        .properties
        .contains_key(&format!("deployed.{instance}"))
    {
        bail!("instance {instance} is deployed; remove it before changing its cluster namespace");
    }
    Ok(())
}

fn instances_in(env_obj: &Object, name: &str) -> Result<Vec<String>> {
    let bindings = parse_bindings(&env_obj.properties)?;
    let mut names = Vec::new();
    for (instance, bound) in &bindings {
        if bound == name {
            names.push(instance.clone());
        }
    }
    if name == env_obj.name {
        for key in env_obj.properties.keys() {
            let Some(instance) = key.strip_prefix("deployed.") else {
                continue;
            };
            if instance.starts_with("health.") || instance.is_empty() {
                continue;
            }
            if !bindings.contains_key(instance) {
                names.push(instance.to_string());
            }
        }
        for key in env_obj.properties.keys() {
            let Some(instance) = key.strip_prefix("subscription.") else {
                continue;
            };
            if !bindings.contains_key(instance)
                && !names.iter().any(|existing| existing == instance)
            {
                names.push(instance.to_string());
            }
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn refuse_delete_with_instances(env_obj: &Object, name: &str) -> Result<()> {
    let holders = instances_in(env_obj, name)?;
    if !holders.is_empty() {
        bail!(
            "cluster namespace {name} still holds instances {}; move or remove them first",
            holders.join(", ")
        );
    }
    Ok(())
}

fn refuse_unmanaged_delete(env_obj: &Object, name: &str) -> Result<()> {
    let applied = parse_map(&env_obj.properties, APPLIED_PROPERTY)?;
    if !applied.contains_key(name) {
        bail!(
            "cluster namespace {name} has not been applied on this environment; clear the declaration instead of deleting"
        );
    }
    Ok(())
}

/// Refuse a cluster-namespace step before the executor mutates the cluster.
pub(crate) fn admit_apply(env_obj: &Object, step: &ClusterNamespaceStep) -> Result<()> {
    validate_name(&step.name)?;
    if step.action == ClusterNamespaceAction::Delete {
        refuse_reserved_delete(&step.name)?;
        refuse_unmanaged_delete(env_obj, &step.name)?;
        refuse_delete_with_instances(env_obj, &step.name)?;
    }
    Ok(())
}

/// Plan steps that create, change, or delete declared cluster namespaces.
pub fn plan_steps(env_obj: &Object) -> Result<Vec<ClusterNamespaceStep>> {
    let declared = parse_map(&env_obj.properties, DECLARED_PROPERTY)?;
    let applied = parse_map(&env_obj.properties, APPLIED_PROPERTY)?;
    let deletes = parse_deletes(&env_obj.properties)?;
    let mut steps = Vec::new();
    for (name, spec) in &declared {
        if deletes.contains(name) {
            continue;
        }
        match applied.get(name) {
            None => steps.push(ClusterNamespaceStep {
                name: name.clone(),
                action: ClusterNamespaceAction::Create,
                spec: spec.clone(),
            }),
            Some(current) if current != spec => steps.push(ClusterNamespaceStep {
                name: name.clone(),
                action: ClusterNamespaceAction::Update,
                spec: spec.clone(),
            }),
            Some(_) => {}
        }
    }
    for name in &deletes {
        refuse_unmanaged_delete(env_obj, name)?;
        refuse_delete_with_instances(env_obj, name)?;
        let spec = declared
            .get(name)
            .cloned()
            .or_else(|| applied.get(name).cloned())
            .unwrap_or_default();
        steps.push(ClusterNamespaceStep {
            name: name.clone(),
            action: ClusterNamespaceAction::Delete,
            spec,
        });
    }
    Ok(steps)
}

/// Refuse delete of Kubernetes reserved namespaces.
pub fn refuse_reserved_delete(name: &str) -> Result<()> {
    if RESERVED.contains(&name) {
        bail!("cluster namespace {name} is reserved and is never deleted");
    }
    Ok(())
}

/// Stamp a succeeded cluster-namespace step onto `env_obj`.
pub(crate) fn apply_record(env_obj: &mut Object, step: &ClusterNamespaceStep) -> Result<()> {
    match step.action {
        ClusterNamespaceAction::Create | ClusterNamespaceAction::Update => {
            let mut applied = parse_map(&env_obj.properties, APPLIED_PROPERTY)?;
            applied.insert(step.name.clone(), step.spec.clone());
            write_map(env_obj, APPLIED_PROPERTY, &applied)?;
        }
        ClusterNamespaceAction::Delete => {
            refuse_delete_with_instances(env_obj, &step.name)?;
            let mut applied = parse_map(&env_obj.properties, APPLIED_PROPERTY)?;
            applied.remove(&step.name);
            write_map(env_obj, APPLIED_PROPERTY, &applied)?;
            let mut declared = parse_map(&env_obj.properties, DECLARED_PROPERTY)?;
            declared.remove(&step.name);
            write_map(env_obj, DECLARED_PROPERTY, &declared)?;
            let mut deletes = parse_deletes(&env_obj.properties)?;
            deletes.remove(&step.name);
            write_deletes(env_obj, &deletes)?;
        }
    }
    Ok(())
}

/// Record a successful cluster-namespace step on the environment.
pub async fn record_applied(ctx: &mut Ctx, env: &str, step: &ClusterNamespaceStep) -> Result<()> {
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    apply_record(&mut env_obj, step)?;
    put_env(ctx, env_obj).await?;
    Ok(())
}

/// Status rows for inspect and `status`. Empty when the environment declares none.
pub fn status(env_obj: &Object) -> Result<Vec<ClusterNamespaceStatus>> {
    let declared = parse_map(&env_obj.properties, DECLARED_PROPERTY)?;
    let applied = parse_map(&env_obj.properties, APPLIED_PROPERTY)?;
    let deletes = parse_deletes(&env_obj.properties)?;
    if declared.is_empty() && applied.is_empty() && deletes.is_empty() {
        return Ok(Vec::new());
    }
    let mut names: BTreeSet<String> = declared.keys().cloned().collect();
    names.extend(applied.keys().cloned());
    names.extend(deletes.iter().cloned());
    let mut rows = Vec::new();
    for name in names {
        let spec = declared
            .get(&name)
            .or_else(|| applied.get(&name))
            .cloned()
            .unwrap_or_default();
        let state = if deletes.contains(&name) {
            "pending_delete"
        } else if declared.contains_key(&name) {
            "declared"
        } else {
            "applied"
        };
        rows.push(ClusterNamespaceStatus {
            name: name.clone(),
            labels: spec.labels,
            quota: spec.quota,
            instances: instances_in(env_obj, &name)?,
            state: state.into(),
        });
    }
    Ok(rows)
}

/// Manifests a cluster executor applies for `request`.
pub fn manifests(request: &ClusterNamespaceApplyRequest) -> Result<Vec<serde_json::Value>> {
    validate_name(&request.name)?;
    validate_spec(&request.spec)?;
    if request.action == ClusterNamespaceAction::Delete {
        return Ok(Vec::new());
    }
    let mut objects = Vec::new();
    let mut metadata = serde_json::json!({
        "name": request.name,
    });
    if !request.spec.labels.is_empty() {
        metadata["labels"] = serde_json::to_value(&request.spec.labels)?;
    }
    if !request.spec.annotations.is_empty() {
        metadata["annotations"] = serde_json::to_value(&request.spec.annotations)?;
    }
    objects.push(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": metadata,
    }));
    if !request.spec.quota.is_empty() {
        objects.push(serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": QUOTA_OBJECT, "namespace": request.name },
            "spec": { "hard": request.spec.quota },
        }));
    }
    if !request.spec.limit_range.is_empty() {
        let mut limits = Vec::new();
        for item in &request.spec.limit_range {
            let mut object = serde_json::json!({ "type": item.type_name });
            if !item.max.is_empty() {
                object["max"] = serde_json::to_value(&item.max)?;
            }
            if !item.min.is_empty() {
                object["min"] = serde_json::to_value(&item.min)?;
            }
            if !item.default.is_empty() {
                object["default"] = serde_json::to_value(&item.default)?;
            }
            if !item.default_request.is_empty() {
                object["defaultRequest"] = serde_json::to_value(&item.default_request)?;
            }
            limits.push(object);
        }
        objects.push(serde_json::json!({
            "apiVersion": "v1",
            "kind": "LimitRange",
            "metadata": { "name": LIMIT_RANGE_OBJECT, "namespace": request.name },
            "spec": { "limits": limits },
        }));
    }
    Ok(objects)
}

pub fn quota_object_name() -> &'static str {
    QUOTA_OBJECT
}

pub fn limit_range_object_name() -> &'static str {
    LIMIT_RANGE_OBJECT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::environment::env_add;

    fn db(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tenkai-cluster-ns-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ))
    }

    async fn ctx(label: &str) -> (Ctx, std::path::PathBuf) {
        let database = db(label);
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "lab", "Lab").await.unwrap();
        (ctx, database)
    }

    fn spec() -> ClusterNamespaceSpec {
        ClusterNamespaceSpec {
            labels: BTreeMap::from([("team".into(), "pay".into())]),
            quota: BTreeMap::from([("pods".into(), "10".into())]),
            ..ClusterNamespaceSpec::default()
        }
    }

    #[tokio::test]
    async fn undeclared_environment_plans_no_cluster_namespace_steps() {
        let (ctx, database) = ctx("none").await;
        let mut ctx = ctx;
        let env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        let steps = plan_steps(&env).unwrap();
        assert!(steps.is_empty(), "{steps:?}");
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn declaring_a_namespace_plans_a_create_step() {
        let (mut ctx, database) = ctx("create").await;
        set(&mut ctx, "lab", "payments", spec()).await.unwrap();
        let env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        let steps = plan_steps(&env).unwrap();
        assert_eq!(steps.len(), 1, "{steps:?}");
        assert_eq!(steps[0].action, ClusterNamespaceAction::Create);
        assert_eq!(steps[0].name, "payments");
        assert_eq!(steps[0].spec.labels["team"], "pay");
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn matching_applied_spec_plans_nothing() {
        let (mut ctx, database) = ctx("match").await;
        set(&mut ctx, "lab", "payments", spec()).await.unwrap();
        let step = ClusterNamespaceStep {
            name: "payments".into(),
            action: ClusterNamespaceAction::Create,
            spec: spec(),
        };
        record_applied(&mut ctx, "lab", &step).await.unwrap();
        let env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        assert!(plan_steps(&env).unwrap().is_empty());
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn changing_labels_plans_an_update() {
        let (mut ctx, database) = ctx("update").await;
        set(&mut ctx, "lab", "payments", spec()).await.unwrap();
        record_applied(
            &mut ctx,
            "lab",
            &ClusterNamespaceStep {
                name: "payments".into(),
                action: ClusterNamespaceAction::Create,
                spec: spec(),
            },
        )
        .await
        .unwrap();
        let mut next = spec();
        next.labels.insert("team".into(), "edge".into());
        set(&mut ctx, "lab", "payments", next).await.unwrap();
        let env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        let steps = plan_steps(&env).unwrap();
        assert_eq!(steps[0].action, ClusterNamespaceAction::Update);
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn clearing_a_declaration_does_not_plan_a_delete() {
        let (mut ctx, database) = ctx("clear").await;
        set(&mut ctx, "lab", "payments", spec()).await.unwrap();
        record_applied(
            &mut ctx,
            "lab",
            &ClusterNamespaceStep {
                name: "payments".into(),
                action: ClusterNamespaceAction::Create,
                spec: spec(),
            },
        )
        .await
        .unwrap();
        request_delete(&mut ctx, "lab", "payments").await.unwrap();
        clear(&mut ctx, "lab", "payments").await.unwrap();
        let env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        let steps = plan_steps(&env).unwrap();
        assert!(
            steps
                .iter()
                .all(|step| step.action != ClusterNamespaceAction::Delete),
            "{steps:?}"
        );
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn delete_is_refused_while_an_instance_is_bound() {
        let (mut ctx, database) = ctx("held").await;
        set(&mut ctx, "lab", "payments", spec()).await.unwrap();
        record_applied(
            &mut ctx,
            "lab",
            &ClusterNamespaceStep {
                name: "payments".into(),
                action: ClusterNamespaceAction::Create,
                spec: spec(),
            },
        )
        .await
        .unwrap();
        bind(&mut ctx, "lab", "api", "payments").await.unwrap();
        let error = request_delete(&mut ctx, "lab", "payments")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("still holds instances"), "{error}");
        unbind(&mut ctx, "lab", "api").await.unwrap();
        request_delete(&mut ctx, "lab", "payments").await.unwrap();
        let env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        let steps = plan_steps(&env).unwrap();
        assert_eq!(steps.last().unwrap().action, ClusterNamespaceAction::Delete);
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn bind_refuses_an_undeclared_name_and_a_deployed_instance() {
        let (mut ctx, database) = ctx("bind").await;
        let missing = bind(&mut ctx, "lab", "api", "payments")
            .await
            .unwrap_err()
            .to_string();
        assert!(missing.contains("is not declared"), "{missing}");
        set(&mut ctx, "lab", "payments", spec()).await.unwrap();
        let mut env_obj = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        env_obj
            .properties
            .insert("deployed.api".into(), "1.0.0".into());
        env_obj.updated = crate::now_millis();
        ctx.put(env_obj).await.unwrap();
        let deployed = bind(&mut ctx, "lab", "api", "payments")
            .await
            .unwrap_err()
            .to_string();
        assert!(deployed.contains("is deployed"), "{deployed}");
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn delete_of_the_environment_namespace_is_refused_while_an_instance_is_deployed() {
        let (mut ctx, database) = ctx("env-held").await;
        set(&mut ctx, "lab", "lab", spec()).await.unwrap();
        record_applied(
            &mut ctx,
            "lab",
            &ClusterNamespaceStep {
                name: "lab".into(),
                action: ClusterNamespaceAction::Create,
                spec: spec(),
            },
        )
        .await
        .unwrap();
        let mut env_obj = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        env_obj
            .properties
            .insert("deployed.api".into(), "1.0.0".into());
        env_obj.updated = crate::now_millis();
        ctx.put(env_obj).await.unwrap();
        let error = request_delete(&mut ctx, "lab", "lab")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("still holds instances"), "{error}");
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn bind_refuses_a_namespace_pending_delete() {
        let (mut ctx, database) = ctx("pending").await;
        set(&mut ctx, "lab", "payments", spec()).await.unwrap();
        record_applied(
            &mut ctx,
            "lab",
            &ClusterNamespaceStep {
                name: "payments".into(),
                action: ClusterNamespaceAction::Create,
                spec: spec(),
            },
        )
        .await
        .unwrap();
        request_delete(&mut ctx, "lab", "payments").await.unwrap();
        let error = bind(&mut ctx, "lab", "api", "payments")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("pending delete"), "{error}");
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn applying_a_delete_step_with_instances_does_not_call_the_executor() {
        use crate::apply::{ExecutionAuthorization, ExecutionOptions, execute_with_options};
        use crate::software_executor::{FakeSoftwareExecutor, SoftwareExecutors};
        use std::sync::Arc;

        let (mut ctx, database) = ctx("apply-held").await;
        env_add(&mut ctx, "local", "Local").await.unwrap();
        set(&mut ctx, "local", "payments", spec()).await.unwrap();
        record_applied(
            &mut ctx,
            "local",
            &ClusterNamespaceStep {
                name: "payments".into(),
                action: ClusterNamespaceAction::Create,
                spec: spec(),
            },
        )
        .await
        .unwrap();
        request_delete(&mut ctx, "local", "payments").await.unwrap();
        let executor = Arc::new(FakeSoftwareExecutor::new());
        let executors = SoftwareExecutors::with_default(executor.clone());
        let plan = crate::plan::create_with(&mut ctx, "local", &executors)
            .await
            .unwrap();
        let mut env_obj = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env_obj.properties.insert(
            BINDINGS_PROPERTY.into(),
            serde_json::to_string(&BTreeMap::from([(
                "api".to_string(),
                "payments".to_string(),
            )]))
            .unwrap(),
        );
        env_obj.updated = crate::now_millis();
        ctx.put(env_obj).await.unwrap();
        let error = execute_with_options(
            &mut ctx,
            &plan.id,
            ExecutionOptions {
                rollback_hold: true,
                skip_gates: true,
                emergency_reason: None,
                authorization: ExecutionAuthorization::LocalDevelopment {
                    reason: "cluster namespace fixture",
                },
                software_executors: executors,
                model_runtime_executor: None,
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("still holds instances"), "{error}");
        assert!(
            executor.applied_cluster_namespaces().is_empty(),
            "{:?}",
            executor.applied_cluster_namespaces()
        );
        let _ = std::fs::remove_file(database);
    }

    #[test]
    fn manifests_carry_labels_and_quota() {
        let objects = manifests(&ClusterNamespaceApplyRequest {
            environment: "lab".into(),
            cluster_config_path: None,
            name: "payments".into(),
            action: ClusterNamespaceAction::Create,
            spec: spec(),
        })
        .unwrap();
        assert_eq!(objects[0]["kind"], "Namespace");
        assert_eq!(objects[0]["metadata"]["labels"]["team"], "pay");
        assert_eq!(objects[1]["kind"], "ResourceQuota");
        assert_eq!(objects[1]["spec"]["hard"]["pods"], "10");
    }

    #[tokio::test]
    async fn a_bound_instance_deploys_to_the_declared_cluster_namespace() {
        let (mut ctx, database) = ctx("bind-ns").await;
        set(&mut ctx, "lab", "payments", spec()).await.unwrap();
        bind(&mut ctx, "lab", "api", "payments").await.unwrap();
        let env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        assert_eq!(instance_namespace(&env, "api").unwrap(), "payments");
        assert_eq!(instance_namespace(&env, "other").unwrap(), "lab");
        let mut bound = crate::software_executor::request_from_parts(
            "api",
            "1.0.0",
            "lab",
            std::path::Path::new(""),
            "tenkai:release:api@1.0.0",
        );
        stamp_request(&mut bound, &env).unwrap();
        assert_eq!(bound.cluster_namespace, "payments");
        assert_eq!(bound.target_namespace(), "payments");
        let mut unbound = crate::software_executor::request_from_parts(
            "other",
            "1.0.0",
            "lab",
            std::path::Path::new(""),
            "tenkai:release:other@1.0.0",
        );
        stamp_request(&mut unbound, &env).unwrap();
        assert!(unbound.cluster_namespace.is_empty());
        assert_eq!(unbound.target_namespace(), "lab");
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn applying_a_create_step_records_the_namespace_as_applied() {
        use crate::apply::{ExecutionAuthorization, ExecutionOptions, execute_with_options};
        use crate::software_executor::{FakeSoftwareExecutor, SoftwareExecutors};
        use std::sync::Arc;

        let (mut ctx, database) = ctx("apply-create").await;
        env_add(&mut ctx, "local", "Local").await.unwrap();
        set(&mut ctx, "local", "payments", spec()).await.unwrap();
        let executor = Arc::new(FakeSoftwareExecutor::new());
        let executors = SoftwareExecutors::with_default(executor.clone());
        let plan = crate::plan::create_with(&mut ctx, "local", &executors)
            .await
            .unwrap();
        assert!(
            plan.steps.iter().any(|step| step.is_cluster_namespace()),
            "{:?}",
            plan.steps
        );
        execute_with_options(
            &mut ctx,
            &plan.id,
            ExecutionOptions {
                rollback_hold: true,
                skip_gates: true,
                emergency_reason: None,
                authorization: ExecutionAuthorization::LocalDevelopment {
                    reason: "cluster namespace fixture",
                },
                software_executors: executors,
                model_runtime_executor: None,
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
            },
        )
        .await
        .unwrap();
        let applied_requests = executor.applied_cluster_namespaces();
        assert_eq!(applied_requests.len(), 1, "{applied_requests:?}");
        assert_eq!(applied_requests[0].name, "payments");
        assert_eq!(applied_requests[0].action, ClusterNamespaceAction::Create);
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert!(applied(&env).unwrap().contains_key("payments"));
        let _ = std::fs::remove_file(database);
    }

    #[test]
    fn reserved_names_are_never_deleted() {
        let error = refuse_reserved_delete("kube-system")
            .unwrap_err()
            .to_string();
        assert!(error.contains("reserved"), "{error}");
        refuse_reserved_delete("payments").unwrap();
    }

    #[tokio::test]
    async fn delete_is_refused_for_a_namespace_this_environment_does_not_manage() {
        let (mut ctx, database) = ctx("unmanaged-delete").await;
        let error = request_delete(&mut ctx, "lab", "payments")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("has not been applied"), "{error}");
        set(&mut ctx, "lab", "payments", spec()).await.unwrap();
        let declared_only = request_delete(&mut ctx, "lab", "payments")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            declared_only.contains("has not been applied"),
            "{declared_only}"
        );
        let env = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        let step = ClusterNamespaceStep {
            name: "payments".into(),
            action: ClusterNamespaceAction::Delete,
            spec: ClusterNamespaceSpec::default(),
        };
        let admit = admit_apply(&env, &step).unwrap_err().to_string();
        assert!(admit.contains("has not been applied"), "{admit}");
        let _ = std::fs::remove_file(database);
    }
}
