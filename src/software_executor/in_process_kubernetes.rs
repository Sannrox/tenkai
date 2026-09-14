//! In-process Kubernetes apply with server-side apply and workload health (#376).
//!
//! The catalog is not a cluster. A kubeconfig file path is environment-scoped
//! and never placed on a command line. Cached objects cannot grant apply
//! authority: every apply re-reads the signed workdir and admits health from
//! live workload conditions.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{
    SoftwareApplyRequest, SoftwareExecutor, SoftwareObserveStatus, k8s_label_value,
    kubernetes_manifests_dir, list_manifest_files, validate_request,
};

pub const FIELD_MANAGER: &str = "tenkai";
pub const CLUSTER_CONFIG_PATH_PROPERTY: &str = "cluster_config_path";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadCondition {
    pub type_name: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadObservation {
    pub kind: String,
    pub name: String,
    pub field_manager: String,
    pub version_label: Option<String>,
    pub conditions: Vec<WorkloadCondition>,
}

pub trait ClusterApplyApi: Send + Sync {
    fn apply_server_side(
        &self,
        cluster_config: &Path,
        namespace: &str,
        field_manager: &str,
        object: &Value,
    ) -> Result<WorkloadObservation>;
    fn observe(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadObservation>>;
    fn remove(&self, cluster_config: &Path, namespace: &str, name: &str, kind: &str) -> Result<()>;
}

impl<T: ClusterApplyApi + ?Sized> ClusterApplyApi for &T {
    fn apply_server_side(
        &self,
        cluster_config: &Path,
        namespace: &str,
        field_manager: &str,
        object: &Value,
    ) -> Result<WorkloadObservation> {
        (**self).apply_server_side(cluster_config, namespace, field_manager, object)
    }

    fn observe(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadObservation>> {
        (**self).observe(cluster_config, namespace, name, kind)
    }

    fn remove(&self, cluster_config: &Path, namespace: &str, name: &str, kind: &str) -> Result<()> {
        (**self).remove(cluster_config, namespace, name, kind)
    }
}

#[derive(Default)]
pub struct MemoryClusterApi {
    objects: Mutex<BTreeMap<String, StoredObject>>,
}

#[derive(Clone)]
struct StoredObject {
    field_manager: String,
    object: Value,
    conditions: Vec<WorkloadCondition>,
}

impl MemoryClusterApi {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_conditions(
        &self,
        namespace: &str,
        name: &str,
        kind: &str,
        conditions: Vec<WorkloadCondition>,
    ) {
        let key = object_key(namespace, kind, name);
        if let Some(stored) = self.objects.lock().expect("cluster mutex").get_mut(&key) {
            stored.conditions = conditions;
        }
    }
}

impl ClusterApplyApi for MemoryClusterApi {
    fn apply_server_side(
        &self,
        _cluster_config: &Path,
        namespace: &str,
        field_manager: &str,
        object: &Value,
    ) -> Result<WorkloadObservation> {
        let (kind, name) = object_identity(object)?;
        let key = object_key(namespace, &kind, &name);
        let mut objects = self.objects.lock().expect("cluster mutex");
        if let Some(existing) = objects.get(&key)
            && existing.field_manager != field_manager
        {
            bail!(
                "server-side apply conflict for {kind}/{name} in {namespace}: field manager {} owns the object; {field_manager} refused to overwrite",
                existing.field_manager
            );
        }
        let conditions = objects
            .get(&key)
            .map(|stored| stored.conditions.clone())
            .unwrap_or_else(healthy_deployment_conditions);
        objects.insert(
            key,
            StoredObject {
                field_manager: field_manager.into(),
                object: object.clone(),
                conditions: conditions.clone(),
            },
        );
        Ok(WorkloadObservation {
            kind,
            name,
            field_manager: field_manager.into(),
            version_label: object_version_label(object),
            conditions,
        })
    }

    fn observe(
        &self,
        _cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadObservation>> {
        let key = object_key(namespace, kind, name);
        Ok(self
            .objects
            .lock()
            .expect("cluster mutex")
            .get(&key)
            .map(|stored| WorkloadObservation {
                kind: kind.into(),
                name: name.into(),
                field_manager: stored.field_manager.clone(),
                version_label: object_version_label(&stored.object),
                conditions: stored.conditions.clone(),
            }))
    }

    fn remove(
        &self,
        _cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<()> {
        self.objects
            .lock()
            .expect("cluster mutex")
            .remove(&object_key(namespace, kind, name));
        Ok(())
    }
}

/// Live cluster adapter. Builds a client from the environment-scoped file only.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveKubeApi;

impl ClusterApplyApi for LiveKubeApi {
    fn apply_server_side(
        &self,
        cluster_config: &Path,
        namespace: &str,
        field_manager: &str,
        object: &Value,
    ) -> Result<WorkloadObservation> {
        block_on(live_apply(cluster_config, namespace, field_manager, object))
    }

    fn observe(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadObservation>> {
        block_on(live_observe(cluster_config, namespace, name, kind))
    }

    fn remove(&self, cluster_config: &Path, namespace: &str, name: &str, kind: &str) -> Result<()> {
        block_on(live_remove(cluster_config, namespace, name, kind))
    }
}

pub struct InProcessKubernetesExecutor<A> {
    api: A,
    timeout: Duration,
    poll_interval: Duration,
}

impl<A: ClusterApplyApi> InProcessKubernetesExecutor<A> {
    pub fn new(api: A) -> Self {
        Self {
            api,
            timeout: Duration::from_secs(60),
            poll_interval: Duration::from_secs(1),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    fn require_cluster_config(request: &SoftwareApplyRequest) -> Result<&Path> {
        let Some(path) = request.cluster_config_path.as_deref() else {
            bail!(
                "environment {} has no cluster_config_path; implicit kubeconfig discovery is refused",
                request.environment
            );
        };
        validate_cluster_config_path(path)?;
        if !path.is_file() {
            bail!(
                "environment {} cluster_config_path {} is not a readable kubeconfig file",
                request.environment,
                path.display()
            );
        }
        Ok(path)
    }

    fn apply_manifests(&self, request: &SoftwareApplyRequest) -> Result<Vec<WorkloadObservation>> {
        validate_request(request)?;
        let cluster_config = Self::require_cluster_config(request)?;
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        if files.is_empty() {
            bail!(
                "in-process kubernetes apply requires at least one .yaml/.yml under {}",
                manifests.display()
            );
        }
        let mut observations = Vec::new();
        for path in &files {
            for mut object in parse_manifest_objects(path)? {
                stamp_ownership(&mut object, request);
                let observed = self.api.apply_server_side(
                    cluster_config,
                    &request.environment,
                    FIELD_MANAGER,
                    &object,
                )?;
                observations.push(observed);
            }
        }
        self.wait_for_health(request, cluster_config, &observations)?;
        Ok(observations)
    }

    fn wait_for_health(
        &self,
        request: &SoftwareApplyRequest,
        cluster_config: &Path,
        applied: &[WorkloadObservation],
    ) -> Result<()> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let mut failed = Vec::new();
            for applied in applied {
                let Some(live) = self.api.observe(
                    cluster_config,
                    &request.environment,
                    &applied.name,
                    &applied.kind,
                )?
                else {
                    failed.push(format!(
                        "{} {} is absent after server-side apply",
                        applied.kind, applied.name
                    ));
                    continue;
                };
                if let Some(error) = disagreeing_condition(&live) {
                    failed.push(error);
                }
                if live.version_label.as_deref() != Some(k8s_label_value(&request.version).as_str())
                    && is_workload(&live.kind)
                {
                    failed.push(format!(
                        "{} {} version label {:?} does not match {}",
                        live.kind, live.name, live.version_label, request.version
                    ));
                }
            }
            if failed.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "in-process kubernetes apply refused to complete for {}@{} in {}: {}",
                    request.product,
                    request.version,
                    request.environment,
                    failed.join("; ")
                );
            }
            std::thread::sleep(self.poll_interval);
        }
    }
}

impl InProcessKubernetesExecutor<LiveKubeApi> {
    pub fn from_selected() -> Self {
        Self::new(LiveKubeApi).with_timeout(Duration::from_secs(300))
    }
}

pub fn selected_in_process_executor() -> InProcessKubernetesExecutor<LiveKubeApi> {
    InProcessKubernetesExecutor::from_selected()
}

impl<A: ClusterApplyApi> SoftwareExecutor for InProcessKubernetesExecutor<A> {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        self.apply_manifests(request)?;
        Ok(())
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let cluster_config = Self::require_cluster_config(request)?;
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        for path in files.iter().rev() {
            for object in parse_manifest_objects(path)? {
                let (kind, name) = object_identity(&object)?;
                self.api
                    .remove(cluster_config, &request.environment, &name, &kind)?;
            }
        }
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let Ok(cluster_config) = Self::require_cluster_config(request) else {
            return Ok(SoftwareObserveStatus::Unknown);
        };
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        if files.is_empty() {
            return Ok(SoftwareObserveStatus::Unknown);
        }
        let mut saw_workload = false;
        for path in &files {
            for object in parse_manifest_objects(path)? {
                let (kind, name) = object_identity(&object)?;
                if !is_workload(&kind) {
                    continue;
                }
                saw_workload = true;
                match self
                    .api
                    .observe(cluster_config, &request.environment, &name, &kind)?
                {
                    None => return Ok(SoftwareObserveStatus::Absent),
                    Some(live) if disagreeing_condition(&live).is_some() => {
                        return Ok(SoftwareObserveStatus::Mismatched);
                    }
                    Some(live)
                        if live.version_label.as_deref()
                            != Some(k8s_label_value(&request.version).as_str()) =>
                    {
                        return Ok(SoftwareObserveStatus::Mismatched);
                    }
                    Some(_) => {}
                }
            }
        }
        if saw_workload {
            Ok(SoftwareObserveStatus::Present)
        } else {
            Ok(SoftwareObserveStatus::Unknown)
        }
    }
}

pub fn validate_cluster_config_path(path: &Path) -> Result<()> {
    let raw = path.to_string_lossy();
    if raw.is_empty() || raw.contains('\0') || raw.contains('\n') {
        bail!("cluster_config_path must be a single filesystem path");
    }
    let lower = raw.to_ascii_lowercase();
    for needle in [
        "-----begin ",
        "bearer ",
        "token=",
        "password=",
        "client-key-data",
    ] {
        if lower.contains(needle) {
            bail!("cluster_config_path must be a file path, not credential material");
        }
    }
    Ok(())
}

pub fn cluster_config_path_from_properties(
    properties: &std::collections::HashMap<String, String>,
) -> Result<Option<PathBuf>> {
    match properties.get(CLUSTER_CONFIG_PATH_PROPERTY) {
        None => Ok(None),
        Some(value) => {
            let path = PathBuf::from(value);
            validate_cluster_config_path(&path)?;
            Ok(Some(path))
        }
    }
}

fn parse_manifest_objects(path: &Path) -> Result<Vec<Value>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("reading manifest {}: {error}", path.display()))?;
    let mut objects = Vec::new();
    for document in serde_yaml::Deserializer::from_str(&raw) {
        let yaml_value = serde_yaml::Value::deserialize(document)
            .map_err(|error| anyhow::anyhow!("parsing manifest {}: {error}", path.display()))?;
        if yaml_value.is_null() {
            continue;
        }
        let value = serde_json::to_value(yaml_value)
            .map_err(|error| anyhow::anyhow!("normalizing manifest {}: {error}", path.display()))?;
        if !value.is_null() {
            objects.push(value);
        }
    }
    Ok(objects)
}

fn object_identity(object: &Value) -> Result<(String, String)> {
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("manifest object is missing kind"))?;
    let name = object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("manifest object is missing metadata.name"))?;
    Ok((kind.into(), name.into()))
}

fn object_version_label(object: &Value) -> Option<String> {
    object
        .pointer("/metadata/labels/tenkai.version")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn object_key(namespace: &str, kind: &str, name: &str) -> String {
    format!("{namespace}/{kind}/{name}")
}

fn stamp_ownership(object: &mut Value, request: &SoftwareApplyRequest) {
    let labels = object
        .pointer_mut("/metadata/labels")
        .and_then(Value::as_object_mut);
    let labels = match labels {
        Some(labels) => labels,
        None => {
            let metadata = object
                .as_object_mut()
                .map(|root| {
                    root.entry("metadata")
                        .or_insert_with(|| Value::Object(Map::new()))
                })
                .and_then(Value::as_object_mut);
            let Some(metadata) = metadata else {
                return;
            };
            metadata
                .entry("labels")
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .expect("labels object")
        }
    };
    labels.insert(
        "tenkai.product".into(),
        Value::String(k8s_label_value(&request.product)),
    );
    labels.insert(
        "tenkai.version".into(),
        Value::String(k8s_label_value(&request.version)),
    );
    labels.insert(
        "tenkai.release-id".into(),
        Value::String(k8s_label_value(&request.release_id)),
    );
}

fn is_workload(kind: &str) -> bool {
    matches!(kind, "Deployment" | "StatefulSet" | "DaemonSet")
}

fn healthy_deployment_conditions() -> Vec<WorkloadCondition> {
    vec![
        WorkloadCondition {
            type_name: "Progressing".into(),
            status: "True".into(),
            reason: "NewReplicaSetAvailable".into(),
        },
        WorkloadCondition {
            type_name: "Available".into(),
            status: "True".into(),
            reason: "MinimumReplicasAvailable".into(),
        },
    ]
}

fn disagreeing_condition(observation: &WorkloadObservation) -> Option<String> {
    if !is_workload(&observation.kind) {
        return None;
    }
    let available = observation
        .conditions
        .iter()
        .find(|condition| condition.type_name == "Available");
    match available {
        Some(condition) if condition.status == "True" => {}
        Some(condition) => {
            return Some(format!(
                "{} {} condition Available={} reason {}",
                observation.kind, observation.name, condition.status, condition.reason
            ));
        }
        None => {
            return Some(format!(
                "{} {} has no Available condition after server-side apply",
                observation.kind, observation.name
            ));
        }
    }
    observation.conditions.iter().find_map(|condition| {
        if condition.type_name == "Progressing"
            && condition.status == "False"
            && condition.reason != "NewReplicaSetAvailable"
        {
            Some(format!(
                "{} {} condition Progressing=False reason {}",
                observation.kind, observation.name, condition.reason
            ))
        } else {
            None
        }
    })
}

fn block_on<T, F>(fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("in-process kubernetes runtime")?
            .block_on(fut),
    }
}

async fn live_client(cluster_config: &Path) -> Result<kube::Client> {
    validate_cluster_config_path(cluster_config)?;
    if !cluster_config.is_file() {
        bail!(
            "cluster_config_path {} is not a readable kubeconfig file",
            cluster_config.display()
        );
    }
    let kubeconfig = kube::config::Kubeconfig::read_from(cluster_config).with_context(|| {
        format!(
            "reading environment-scoped cluster config {}",
            cluster_config.display()
        )
    })?;
    let config = kube::Config::from_custom_kubeconfig(
        kubeconfig,
        &kube::config::KubeConfigOptions::default(),
    )
    .await
    .with_context(|| format!("loading cluster client from {}", cluster_config.display()))?;
    kube::Client::try_from(config).context("building in-process kubernetes client")
}

async fn live_apply(
    cluster_config: &Path,
    namespace: &str,
    field_manager: &str,
    object: &Value,
) -> Result<WorkloadObservation> {
    let client = live_client(cluster_config).await?;
    ensure_namespace(&client, namespace).await?;
    let (kind, name) = object_identity(object)?;
    let api_version = object
        .get("apiVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("manifest object is missing apiVersion"))?;
    let api = dynamic_api(client, namespace, &kind, api_version)?;
    let mut payload = object.clone();
    if let Some(metadata) = payload.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata
            .entry("namespace")
            .or_insert_with(|| Value::String(namespace.into()));
    }
    let params = kube::api::PatchParams::apply(field_manager);
    let applied = api
        .patch(&name, &params, &kube::api::Patch::Apply(&payload))
        .await
        .map_err(|error| map_apply_error(&kind, &name, namespace, field_manager, error))?;
    Ok(observation_from_dynamic(&applied, &kind, &name))
}

async fn live_observe(
    cluster_config: &Path,
    namespace: &str,
    name: &str,
    kind: &str,
) -> Result<Option<WorkloadObservation>> {
    let client = live_client(cluster_config).await?;
    let api_version = builtin_api_version(kind)?;
    let api = dynamic_api(client, namespace, kind, api_version)?;
    match api.get_opt(name).await {
        Ok(Some(object)) => Ok(Some(observation_from_dynamic(&object, kind, name))),
        Ok(None) => Ok(None),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "observing {kind}/{name} in {namespace}: {error}"
        )),
    }
}

async fn live_remove(cluster_config: &Path, namespace: &str, name: &str, kind: &str) -> Result<()> {
    let client = live_client(cluster_config).await?;
    let api_version = builtin_api_version(kind)?;
    let api = dynamic_api(client, namespace, kind, api_version)?;
    match api.delete(name, &kube::api::DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(error) if is_not_found(&error) => Ok(()),
        Err(error) => Err(anyhow::anyhow!(
            "removing {kind}/{name} in {namespace}: {error}"
        )),
    }
}

async fn ensure_namespace(client: &kube::Client, namespace: &str) -> Result<()> {
    use k8s_openapi::api::core::v1::Namespace;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    let api: kube::Api<Namespace> = kube::Api::all(client.clone());
    if api
        .get_opt(namespace)
        .await
        .context("looking up namespace")?
        .is_some()
    {
        return Ok(());
    }
    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(namespace.into()),
            ..ObjectMeta::default()
        },
        ..Namespace::default()
    };
    api.create(&kube::api::PostParams::default(), &ns)
        .await
        .map(|_| ())
        .or_else(|error| {
            if is_already_exists(&error) {
                Ok(())
            } else {
                Err(anyhow::anyhow!("creating namespace {namespace}: {error}"))
            }
        })
}

fn dynamic_api(
    client: kube::Client,
    namespace: &str,
    kind: &str,
    api_version: &str,
) -> Result<kube::Api<kube::api::DynamicObject>> {
    let (ar, namespaced) = builtin_resource(kind, api_version)?;
    Ok(if namespaced {
        kube::Api::namespaced_with(client, namespace, &ar)
    } else {
        kube::Api::all_with(client, &ar)
    })
}

fn builtin_api_version(kind: &str) -> Result<&'static str> {
    Ok(match kind {
        "Namespace"
        | "ConfigMap"
        | "Secret"
        | "Service"
        | "ServiceAccount"
        | "PersistentVolumeClaim" => "v1",
        "Deployment" | "StatefulSet" | "DaemonSet" => "apps/v1",
        "Job" | "CronJob" => "batch/v1",
        "Ingress" | "NetworkPolicy" => "networking.k8s.io/v1",
        "Role" | "RoleBinding" => "rbac.authorization.k8s.io/v1",
        other => bail!(
            "in-process kubernetes apply refuses kind {other}; custom resource operators are out of scope"
        ),
    })
}

fn builtin_resource(kind: &str, api_version: &str) -> Result<(kube::api::ApiResource, bool)> {
    let (group, version, plural, namespaced) = match (kind, api_version) {
        ("Namespace", "v1") => ("", "v1", "namespaces", false),
        ("ConfigMap", "v1") => ("", "v1", "configmaps", true),
        ("Secret", "v1") => ("", "v1", "secrets", true),
        ("Service", "v1") => ("", "v1", "services", true),
        ("ServiceAccount", "v1") => ("", "v1", "serviceaccounts", true),
        ("PersistentVolumeClaim", "v1") => ("", "v1", "persistentvolumeclaims", true),
        ("Deployment", "apps/v1") => ("apps", "v1", "deployments", true),
        ("StatefulSet", "apps/v1") => ("apps", "v1", "statefulsets", true),
        ("DaemonSet", "apps/v1") => ("apps", "v1", "daemonsets", true),
        ("Job", "batch/v1") => ("batch", "v1", "jobs", true),
        ("CronJob", "batch/v1") => ("batch", "v1", "cronjobs", true),
        ("Ingress", "networking.k8s.io/v1") => ("networking.k8s.io", "v1", "ingresses", true),
        ("NetworkPolicy", "networking.k8s.io/v1") => {
            ("networking.k8s.io", "v1", "networkpolicies", true)
        }
        ("Role", "rbac.authorization.k8s.io/v1") => {
            ("rbac.authorization.k8s.io", "v1", "roles", true)
        }
        ("RoleBinding", "rbac.authorization.k8s.io/v1") => {
            ("rbac.authorization.k8s.io", "v1", "rolebindings", true)
        }
        _ => bail!(
            "in-process kubernetes apply refuses kind {kind} ({api_version}); custom resource operators are out of scope"
        ),
    };
    let gvk = kube::core::GroupVersionKind::gvk(group, version, kind);
    Ok((
        kube::api::ApiResource::from_gvk_with_plural(&gvk, plural),
        namespaced,
    ))
}

fn observation_from_dynamic(
    object: &kube::api::DynamicObject,
    kind: &str,
    name: &str,
) -> WorkloadObservation {
    let value = serde_json::to_value(object).unwrap_or(Value::Null);
    WorkloadObservation {
        kind: kind.into(),
        name: name.into(),
        field_manager: managed_field_manager(&value).unwrap_or_else(|| FIELD_MANAGER.into()),
        version_label: object_version_label(&value),
        conditions: conditions_from_value(&value),
    }
}

fn managed_field_manager(object: &Value) -> Option<String> {
    let fields = object.pointer("/metadata/managedFields")?.as_array()?;
    fields
        .iter()
        .rev()
        .find_map(|entry| {
            let manager = entry.get("manager").and_then(Value::as_str)?;
            if manager == FIELD_MANAGER {
                Some(manager.to_string())
            } else {
                None
            }
        })
        .or_else(|| {
            fields
                .last()
                .and_then(|entry| entry.get("manager"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

fn conditions_from_value(object: &Value) -> Vec<WorkloadCondition> {
    object
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|condition| {
            Some(WorkloadCondition {
                type_name: condition.get("type")?.as_str()?.to_string(),
                status: condition.get("status")?.as_str()?.to_string(),
                reason: condition
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect()
}

fn map_apply_error(
    kind: &str,
    name: &str,
    namespace: &str,
    field_manager: &str,
    error: kube::Error,
) -> anyhow::Error {
    let text = error.to_string();
    if text.to_ascii_lowercase().contains("conflict") {
        anyhow::anyhow!(
            "server-side apply conflict for {kind}/{name} in {namespace}: {text}; {field_manager} refused to overwrite"
        )
    } else {
        anyhow::anyhow!("server-side apply failed for {kind}/{name} in {namespace}: {text}")
    }
}

fn is_not_found(error: &kube::Error) -> bool {
    matches!(
        error,
        kube::Error::Api(status) if status.code == 404
    )
}

fn is_already_exists(error: &kube::Error) -> bool {
    matches!(
        error,
        kube::Error::Api(status) if status.code == 409
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software_executor::SoftwareApplyRequest;
    use std::collections::BTreeMap;

    fn write_deployment(root: &Path, version: &str, replicas: u64) -> PathBuf {
        let manifests = root.join("manifests");
        std::fs::create_dir_all(&manifests).unwrap();
        std::fs::write(
            manifests.join("deploy.yaml"),
            format!(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: edge\nspec:\n  replicas: {replicas}\n"
            ),
        )
        .unwrap();
        let kubeconfig = root.join("kubeconfig");
        std::fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\nclusters: []\n").unwrap();
        let _ = version;
        kubeconfig
    }

    fn request(root: &Path, kubeconfig: &Path, version: &str) -> SoftwareApplyRequest {
        SoftwareApplyRequest {
            product: "edge-app".into(),
            version: version.into(),
            environment: "lab".into(),
            workdir: root.to_path_buf(),
            release_id: format!("tenkai:release:edge-app@{version}"),
            overlays: BTreeMap::new(),
            config_digest: String::new(),
            artifact_pulls: Vec::new(),
            cluster_config_path: Some(kubeconfig.to_path_buf()),
        }
    }

    #[test]
    fn apply_waits_on_rollout_and_rolls_back_by_reapplying_previous_payload() {
        let root_a = std::env::temp_dir().join(format!("tenkai-ssa-a-{}", std::process::id()));
        let root_b = std::env::temp_dir().join(format!("tenkai-ssa-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root_a);
        let _ = std::fs::remove_dir_all(&root_b);
        let kube_a = write_deployment(&root_a, "1.0.0", 1);
        let kube_b = write_deployment(&root_b, "2.0.0", 2);
        let api = MemoryClusterApi::new();
        let executor = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_millis(200))
            .with_poll_interval(Duration::from_millis(20));
        executor.apply(&request(&root_a, &kube_a, "1.0.0")).unwrap();
        executor.apply(&request(&root_b, &kube_b, "2.0.0")).unwrap();
        executor.apply(&request(&root_a, &kube_a, "1.0.0")).unwrap();
        let live = api
            .observe(Path::new("/unused"), "lab", "edge", "Deployment")
            .unwrap()
            .unwrap();
        assert_eq!(live.version_label.as_deref(), Some("1.0.0"));
        let _ = std::fs::remove_dir_all(root_a);
        let _ = std::fs::remove_dir_all(root_b);
    }

    #[test]
    fn failing_available_condition_is_named_and_fails_closed() {
        let root = std::env::temp_dir().join(format!("tenkai-ssa-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let kubeconfig = write_deployment(&root, "1.0.0", 1);
        let api = MemoryClusterApi::new();
        api.apply_server_side(
            Path::new("/unused"),
            "lab",
            FIELD_MANAGER,
            &serde_json::json!({"kind":"Deployment","metadata":{"name":"edge","labels":{}}}),
        )
        .unwrap();
        api.set_conditions(
            "lab",
            "edge",
            "Deployment",
            vec![WorkloadCondition {
                type_name: "Available".into(),
                status: "False".into(),
                reason: "MinimumReplicasUnavailable".into(),
            }],
        );
        let executor = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_millis(30))
            .with_poll_interval(Duration::from_millis(10));
        let err = executor
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("Available=False"), "{err}");
        assert!(err.contains("MinimumReplicasUnavailable"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn foreign_field_manager_is_an_explicit_conflict() {
        let root = std::env::temp_dir().join(format!("tenkai-ssa-conflict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let kubeconfig = write_deployment(&root, "1.0.0", 1);
        let api = MemoryClusterApi::new();
        api.apply_server_side(
            Path::new("/unused"),
            "lab",
            "helm",
            &serde_json::json!({"kind":"Deployment","metadata":{"name":"edge"}}),
        )
        .unwrap();
        let executor = InProcessKubernetesExecutor::new(&api);
        let err = executor
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("server-side apply conflict"), "{err}");
        assert!(err.contains("helm"), "{err}");
        assert!(err.contains("tenkai"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_available_condition_is_named_and_fails_closed() {
        let root = std::env::temp_dir().join(format!("tenkai-ssa-noavail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let kubeconfig = write_deployment(&root, "1.0.0", 1);
        let api = MemoryClusterApi::new();
        api.apply_server_side(
            Path::new("/unused"),
            "lab",
            FIELD_MANAGER,
            &serde_json::json!({"kind":"Deployment","metadata":{"name":"edge","labels":{}}}),
        )
        .unwrap();
        api.set_conditions("lab", "edge", "Deployment", Vec::new());
        let executor = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_millis(30))
            .with_poll_interval(Duration::from_millis(10));
        let err = executor
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("has no Available condition"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_cluster_config_path_refuses_implicit_kubeconfig() {
        let root = std::env::temp_dir().join(format!("tenkai-ssa-noconfig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        write_deployment(&root, "1.0.0", 1);
        let executor = InProcessKubernetesExecutor::new(MemoryClusterApi::new());
        let mut req = request(&root, Path::new("/tmp/unused"), "1.0.0");
        req.cluster_config_path = None;
        let err = executor.apply(&req).unwrap_err().to_string();
        assert!(
            err.contains("implicit kubeconfig discovery is refused"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cluster_config_path_cannot_carry_credential_bytes() {
        let err = validate_cluster_config_path(Path::new("-----BEGIN PRIVATE KEY-----"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("file path"), "{err}");
    }
}
