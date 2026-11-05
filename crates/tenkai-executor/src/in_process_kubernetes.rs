//! In-process Kubernetes apply with server-side apply and workload health (#376).
//!
//! The catalog is not a cluster. A kubeconfig file path is environment-scoped
//! and never placed on a command line. Cached objects cannot grant apply
//! authority: every apply re-reads the signed workdir and admits health from
//! live workload conditions.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::workload_stall::{Stall, StallClassifier, WorkloadEvidence};

use tenkai::software_executor::{
    RolloutPhaseTimes, SoftwareApplyRequest, SoftwareExecutor, SoftwareObserveStatus,
    TargetUnavailable, k8s_label_value, kubernetes_manifests_dir, list_manifest_files,
    validate_cluster_config_path, validate_request,
};

pub const FIELD_MANAGER: &str = "tenkai";
/// First readiness poll after apply. Keeps post-ready wait under 250 ms.
const DEFAULT_HEALTH_POLL: Duration = Duration::from_millis(100);
/// Backoff cap so a long rollout cannot reintroduce a 1 s post-ready stall.
const MAX_HEALTH_POLL: Duration = Duration::from_millis(200);
/// How often a workload that is not Available is diagnosed. Diagnosis lists
/// pods, so it runs less often than the condition poll.
const DIAGNOSIS_INTERVAL: Duration = Duration::from_secs(2);
/// Stop flag for a call outside an apply lease; it is never set.
static NOT_STOPPED: AtomicBool = AtomicBool::new(false);

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
    /// The workload object and the pods of its current revision, read to
    /// explain why it is not Available. `None` when this adapter cannot tell.
    fn workload_evidence(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadEvidence>> {
        let _ = (cluster_config, namespace, name, kind);
        Ok(None)
    }
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

    fn workload_evidence(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadEvidence>> {
        (**self).workload_evidence(cluster_config, namespace, name, kind)
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryClusterApi {
    objects: Mutex<BTreeMap<String, StoredObject>>,
    evidence: Mutex<BTreeMap<String, WorkloadEvidence>>,
}

#[cfg(test)]
#[derive(Clone)]
struct StoredObject {
    field_manager: String,
    object: Value,
    conditions: Vec<WorkloadCondition>,
}

#[cfg(test)]
impl MemoryClusterApi {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn object(&self, namespace: &str, kind: &str, name: &str) -> Option<Value> {
        self.objects
            .lock()
            .expect("cluster mutex")
            .get(&object_key(namespace, kind, name))
            .map(|stored| stored.object.clone())
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

    pub fn set_evidence(
        &self,
        namespace: &str,
        name: &str,
        kind: &str,
        evidence: WorkloadEvidence,
    ) {
        self.evidence
            .lock()
            .expect("evidence mutex")
            .insert(object_key(namespace, kind, name), evidence);
    }
}

#[cfg(test)]
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

    fn workload_evidence(
        &self,
        _cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadEvidence>> {
        Ok(self
            .evidence
            .lock()
            .expect("evidence mutex")
            .get(&object_key(namespace, kind, name))
            .cloned())
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

    fn workload_evidence(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadEvidence>> {
        block_on(live_workload_evidence(
            cluster_config,
            namespace,
            name,
            kind,
        ))
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
            poll_interval: DEFAULT_HEALTH_POLL,
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

    fn apply_manifests_timed(
        &self,
        request: &SoftwareApplyRequest,
        stop: &AtomicBool,
    ) -> Result<(Vec<WorkloadObservation>, RolloutPhaseTimes)> {
        let mut times = RolloutPhaseTimes::default();
        let planned = Instant::now();
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
        let mut objects = Vec::new();
        for path in &files {
            for object in parse_manifest_objects(path)? {
                objects.push(object);
            }
        }
        times.plan_ms = planned.elapsed().as_millis() as u64;
        let applied = Instant::now();
        let mut observations = Vec::new();
        for mut object in objects {
            stamp_ownership(&mut object, request);
            let observed = self.api.apply_server_side(
                cluster_config,
                &request.environment,
                FIELD_MANAGER,
                &object,
            )?;
            observations.push(observed);
        }
        times.apply_ms = applied.elapsed().as_millis() as u64;
        let health = Instant::now();
        self.wait_for_health(request, cluster_config, &observations, stop)?;
        times.health_ms = health.elapsed().as_millis() as u64;
        Ok((observations, times))
    }

    /// Apply one generation and return wall time per phase. `apply` drops the times.
    pub fn apply_with_phases(&self, request: &SoftwareApplyRequest) -> Result<RolloutPhaseTimes> {
        self.apply_timed(request, &NOT_STOPPED)
    }

    fn apply_timed(
        &self,
        request: &SoftwareApplyRequest,
        stop: &AtomicBool,
    ) -> Result<RolloutPhaseTimes> {
        self.apply_manifests_timed(request, stop)
            .map(|(_, times)| times)
    }

    /// Wait until every applied workload is Available at the requested
    /// version. A workload that is not is diagnosed every
    /// [`DIAGNOSIS_INTERVAL`]: a terminal stall fails the wait at once, and
    /// the timeout error names the last cause seen. `stop` ends the wait
    /// when the caller lost its apply lease.
    fn wait_for_health(
        &self,
        request: &SoftwareApplyRequest,
        cluster_config: &Path,
        applied: &[WorkloadObservation],
        stop: &AtomicBool,
    ) -> Result<()> {
        let started = Instant::now();
        let deadline = started + self.timeout;
        let mut interval = self.poll_interval;
        let mut next_diagnosis = started;
        let mut classifiers: HashMap<(String, String), StallClassifier> = HashMap::new();
        let mut causes: Vec<String> = Vec::new();
        loop {
            if stop.load(Ordering::SeqCst) {
                bail!(
                    "in-process kubernetes apply stopped waiting for {}@{} in {} after {}s: the apply lease was lost",
                    request.product,
                    request.version,
                    request.environment,
                    started.elapsed().as_secs()
                );
            }
            let mut failed = Vec::new();
            let mut stalled = Vec::new();
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
                let mut ready = true;
                if let Some(error) = disagreeing_condition(&live) {
                    failed.push(error);
                    ready = false;
                }
                if live.version_label.as_deref() != Some(k8s_label_value(&request.version).as_str())
                    && is_workload(&live.kind)
                {
                    failed.push(format!(
                        "{} {} version label {:?} does not match {}",
                        live.kind, live.name, live.version_label, request.version
                    ));
                    ready = false;
                }
                if !ready && is_workload(&live.kind) {
                    stalled.push((live.kind, live.name));
                }
            }
            if failed.is_empty() {
                return Ok(());
            }
            let now = Instant::now();
            if now >= next_diagnosis || now >= deadline {
                next_diagnosis = now + DIAGNOSIS_INTERVAL;
                causes.clear();
                for (kind, name) in stalled {
                    let stall = self.diagnose(
                        cluster_config,
                        &request.environment,
                        &kind,
                        &name,
                        classifiers.entry((kind.clone(), name.clone())).or_default(),
                        now,
                    );
                    let Some(stall) = stall else { continue };
                    if stall.terminal {
                        bail!(
                            "in-process kubernetes apply failed for {}@{} in {} after {}s: {kind} {name} cannot become Available: {}; {}",
                            request.product,
                            request.version,
                            request.environment,
                            started.elapsed().as_secs(),
                            stall.cause,
                            failed.join("; ")
                        );
                    }
                    causes.push(stall.cause);
                }
            }
            if now >= deadline {
                let cause = if causes.is_empty() {
                    String::new()
                } else {
                    format!("; cause: {}", causes.join("; "))
                };
                bail!(
                    "in-process kubernetes apply refused to complete for {}@{} in {} after {}s: {}{cause}",
                    request.product,
                    request.version,
                    request.environment,
                    started.elapsed().as_secs(),
                    failed.join("; ")
                );
            }
            wait_poll(interval);
            interval = next_health_poll(interval, self.poll_interval);
        }
    }

    /// Classify one workload's live evidence. An error reading the evidence
    /// never fails the wait; it is named as the cause instead.
    fn diagnose(
        &self,
        cluster_config: &Path,
        namespace: &str,
        kind: &str,
        name: &str,
        classifier: &mut StallClassifier,
        now: Instant,
    ) -> Option<Stall> {
        match self
            .api
            .workload_evidence(cluster_config, namespace, name, kind)
        {
            Ok(Some(evidence)) => classifier.classify(kind, name, &evidence, now),
            Ok(None) => None,
            Err(error) => Some(Stall {
                cause: format!(
                    "{kind} {name} could not be diagnosed: {}",
                    format!("{error:#}").chars().take(240).collect::<String>()
                ),
                terminal: false,
            }),
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
    /// The cluster is the target: without a readable cluster config file
    /// nothing can have been applied to it, whether the file is not there
    /// yet or the environment names none.
    fn require_target(&self, request: &SoftwareApplyRequest) -> Result<(), TargetUnavailable> {
        Self::require_cluster_config(request)
            .map(|_| ())
            .map_err(|error| TargetUnavailable(format!("{error:#}")))
    }

    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        self.apply_timed(request, &NOT_STOPPED).map(|_| ())
    }

    fn apply_until_stopped(&self, request: &SoftwareApplyRequest, stop: &AtomicBool) -> Result<()> {
        self.apply_timed(request, stop).map(|_| ())
    }

    /// Restart re-applies the current pin, so it stops like apply.
    fn restart_until_stopped(
        &self,
        request: &SoftwareApplyRequest,
        stop: &AtomicBool,
    ) -> Result<()> {
        self.apply_until_stopped(request, stop)
    }

    fn apply_with_phases(&self, request: &SoftwareApplyRequest) -> Result<RolloutPhaseTimes> {
        self.apply_timed(request, &NOT_STOPPED)
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

#[cfg(test)]
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

#[cfg(test)]
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

pub(crate) fn disagreeing_condition(observation: &WorkloadObservation) -> Option<String> {
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

fn next_health_poll(current: Duration, floor: Duration) -> Duration {
    current
        .saturating_mul(2)
        .min(MAX_HEALTH_POLL.max(floor))
        .max(floor)
}

/// Blocking poll. `SoftwareExecutor::apply` is a blocking API; callers on a
/// Tokio runtime run it on `spawn_blocking` or `block_in_place`. Sleep here
/// instead of queueing a nested blocking task, which can deadlock a saturated
/// blocking pool.
fn wait_poll(duration: Duration) {
    std::thread::sleep(duration);
}

pub(crate) fn block_on<T, F>(fut: F) -> Result<T>
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

/// Pods read per diagnosis. Enough to name a cause, bounded for large
/// workloads.
const DIAGNOSED_PODS: u32 = 20;

async fn live_workload_evidence(
    cluster_config: &Path,
    namespace: &str,
    name: &str,
    kind: &str,
) -> Result<Option<WorkloadEvidence>> {
    use k8s_openapi::api::core::v1::Pod;
    let client = live_client(cluster_config).await?;
    let api = dynamic_api(client.clone(), namespace, kind, builtin_api_version(kind)?)?;
    let Some(object) = api
        .get_opt(name)
        .await
        .with_context(|| format!("reading {kind}/{name} in {namespace}"))?
    else {
        return Ok(None);
    };
    let workload = serde_json::to_value(&object).context("encoding workload status")?;
    let pods = match current_revision_selector(&client, namespace, kind, &workload).await? {
        Some(selector) => {
            kube::Api::<Pod>::namespaced(client, namespace)
                .list(
                    &kube::api::ListParams::default()
                        .labels(&selector)
                        .limit(DIAGNOSED_PODS),
                )
                .await
                .with_context(|| format!("listing pods of {kind}/{name} in {namespace}"))?
                .items
        }
        None => Vec::new(),
    };
    Ok(Some(WorkloadEvidence { workload, pods }))
}

/// Label selector for the pods of the workload's current revision: the
/// Deployment's newest ReplicaSet, or the StatefulSet's update revision.
/// `None` while that revision does not exist yet, or for other kinds.
async fn current_revision_selector(
    client: &kube::Client,
    namespace: &str,
    kind: &str,
    workload: &Value,
) -> Result<Option<String>> {
    use k8s_openapi::api::apps::v1::ReplicaSet;
    let Some(match_labels) = workload
        .pointer("/spec/selector/matchLabels")
        .and_then(Value::as_object)
        .filter(|labels| !labels.is_empty())
    else {
        return Ok(None);
    };
    let selector = match_labels
        .iter()
        .filter_map(|(key, value)| Some(format!("{key}={}", value.as_str()?)))
        .collect::<Vec<_>>()
        .join(",");
    let revision = match kind {
        "Deployment" => {
            const REVISION: &str = "/metadata/annotations/deployment.kubernetes.io~1revision";
            let Some(revision) = workload.pointer(REVISION).and_then(Value::as_str) else {
                return Ok(None);
            };
            let uid = workload.pointer("/metadata/uid").and_then(Value::as_str);
            let sets = kube::Api::<ReplicaSet>::namespaced(client.clone(), namespace)
                .list(&kube::api::ListParams::default().labels(&selector))
                .await
                .with_context(|| format!("listing ReplicaSets in {namespace}"))?;
            let hash = sets.items.into_iter().find_map(|set| {
                let owned = set
                    .metadata
                    .owner_references
                    .iter()
                    .flatten()
                    .any(|owner| Some(owner.uid.as_str()) == uid);
                let current = set
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.get("deployment.kubernetes.io/revision"))
                    .is_some_and(|value| value == revision);
                if owned && current {
                    set.metadata.labels?.remove("pod-template-hash")
                } else {
                    None
                }
            });
            hash.map(|hash| format!("pod-template-hash={hash}"))
        }
        "StatefulSet" => workload
            .pointer("/status/updateRevision")
            .and_then(Value::as_str)
            .map(|revision| format!("controller-revision-hash={revision}")),
        _ => None,
    };
    Ok(revision.map(|revision| format!("{selector},{revision}")))
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
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tenkai::software_executor::SoftwareApplyRequest;

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
            secret_dir_path: None,
            apply_attempt: String::new(),
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
    fn a_missing_cluster_config_is_an_unavailable_target() {
        let root = unique_root("target");
        write_deployment(&root, "1.0.0", 1);
        let kubeconfig = root.join("cluster.kubeconfig");
        let executor = InProcessKubernetesExecutor::new(MemoryClusterApi::new());
        let req = request(&root, &kubeconfig, "1.0.0");

        let refused = executor.require_target(&req).unwrap_err();
        assert!(
            refused.0.contains("is not a readable kubeconfig file"),
            "{refused}"
        );

        std::fs::write(&kubeconfig, "apiVersion: v1\n").unwrap();
        executor.require_target(&req).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    fn unique_root(tag: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "tenkai-k8s-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn unavailable_conditions() -> Vec<WorkloadCondition> {
        vec![
            WorkloadCondition {
                type_name: "Progressing".into(),
                status: "True".into(),
                reason: "ReplicaSetUpdated".into(),
            },
            WorkloadCondition {
                type_name: "Available".into(),
                status: "False".into(),
                reason: "MinimumReplicasUnavailable".into(),
            },
        ]
    }

    /// Apply stores the object as not ready; observe flips to healthy after `ready_after`.
    /// `released` overrides the timer so a runtime test can hold readiness until it has
    /// proven the current-thread executor still makes progress.
    struct DelayedReadyApi {
        inner: MemoryClusterApi,
        ready_after: Duration,
        applied_at: Mutex<Option<Instant>>,
        identity: Mutex<Option<(String, String, String)>>,
        entered_wait: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
        released: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    }

    impl DelayedReadyApi {
        fn new(ready_after: Duration) -> Self {
            Self {
                inner: MemoryClusterApi::new(),
                ready_after,
                applied_at: Mutex::new(None),
                identity: Mutex::new(None),
                entered_wait: Mutex::new(None),
                released: None,
            }
        }

        fn gated() -> (
            Self,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
            std::sync::mpsc::Receiver<()>,
        ) {
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let api = Self {
                inner: MemoryClusterApi::new(),
                ready_after: Duration::from_secs(3600),
                applied_at: Mutex::new(None),
                identity: Mutex::new(None),
                entered_wait: Mutex::new(Some(entered_tx)),
                released: Some(released.clone()),
            };
            (api, released, entered_rx)
        }

        fn ready_at(&self) -> Instant {
            self.applied_at
                .lock()
                .expect("applied_at")
                .expect("apply before ready_at")
                + self.ready_after
        }

        fn is_released(&self) -> bool {
            self.released
                .as_ref()
                .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    impl ClusterApplyApi for DelayedReadyApi {
        fn apply_server_side(
            &self,
            cluster_config: &Path,
            namespace: &str,
            field_manager: &str,
            object: &Value,
        ) -> Result<WorkloadObservation> {
            let observed =
                self.inner
                    .apply_server_side(cluster_config, namespace, field_manager, object)?;
            self.inner.set_conditions(
                namespace,
                &observed.name,
                &observed.kind,
                unavailable_conditions(),
            );
            *self.identity.lock().expect("identity") = Some((
                namespace.into(),
                observed.name.clone(),
                observed.kind.clone(),
            ));
            *self.applied_at.lock().expect("applied_at") = Some(Instant::now());
            Ok(WorkloadObservation {
                conditions: unavailable_conditions(),
                ..observed
            })
        }

        fn observe(
            &self,
            cluster_config: &Path,
            namespace: &str,
            name: &str,
            kind: &str,
        ) -> Result<Option<WorkloadObservation>> {
            if let Some(tx) = self.entered_wait.lock().expect("entered_wait").take() {
                let _ = tx.send(());
            }
            if let Some(applied_at) = *self.applied_at.lock().expect("applied_at")
                && (self.is_released() || applied_at.elapsed() >= self.ready_after)
                && let Some((ns, stored_name, stored_kind)) =
                    self.identity.lock().expect("identity").clone()
            {
                self.inner.set_conditions(
                    &ns,
                    &stored_name,
                    &stored_kind,
                    healthy_deployment_conditions(),
                );
            }
            self.inner.observe(cluster_config, namespace, name, kind)
        }

        fn remove(
            &self,
            cluster_config: &Path,
            namespace: &str,
            name: &str,
            kind: &str,
        ) -> Result<()> {
            self.inner.remove(cluster_config, namespace, name, kind)
        }

        fn workload_evidence(
            &self,
            cluster_config: &Path,
            namespace: &str,
            name: &str,
            kind: &str,
        ) -> Result<Option<WorkloadEvidence>> {
            self.inner
                .workload_evidence(cluster_config, namespace, name, kind)
        }
    }

    fn percentile(mut samples: Vec<Duration>, q: f64) -> Duration {
        samples.sort();
        let index = ((samples.len() as f64 - 1.0) * q).round() as usize;
        samples[index.min(samples.len().saturating_sub(1))]
    }

    #[test]
    fn ready_workload_completes_apply_within_250ms_p95() {
        let mut samples = Vec::new();
        for _ in 0..8 {
            let root = unique_root("ready");
            let _ = std::fs::remove_dir_all(&root);
            let kubeconfig = write_deployment(&root, "1.0.0", 1);
            let api = DelayedReadyApi::new(Duration::from_millis(20));
            let executor = InProcessKubernetesExecutor::new(&api);
            executor
                .apply(&request(&root, &kubeconfig, "1.0.0"))
                .expect("apply after delayed ready");
            let after_ready = Instant::now().saturating_duration_since(api.ready_at());
            samples.push(after_ready);
            let _ = std::fs::remove_dir_all(root);
        }
        let p95 = percentile(samples.clone(), 0.95);
        assert!(
            p95 <= Duration::from_millis(250),
            "p95 ready-to-complete {p95:?} exceeds 250 ms; samples {samples:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn readiness_wait_does_not_block_current_thread_runtime() {
        let root = unique_root("runtime");
        let _ = std::fs::remove_dir_all(&root);
        let kubeconfig = write_deployment(&root, "1.0.0", 1);
        let (api, released, entered_rx) = DelayedReadyApi::gated();
        let executor = InProcessKubernetesExecutor::new(api)
            .with_timeout(Duration::from_secs(5))
            .with_poll_interval(Duration::from_millis(20));
        let req = request(&root, &kubeconfig, "1.0.0");
        let apply = tokio::task::spawn_blocking(move || executor.apply(&req));

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if entered_rx.try_recv().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("apply did not enter readiness wait");

        let progressed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        tokio::spawn({
            let progressed = progressed.clone();
            async move {
                progressed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if progressed.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("current-thread runtime stalled while apply waited");

        released.store(true, std::sync::atomic::Ordering::SeqCst);
        apply.await.expect("join apply").expect("apply");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A Deployment held unavailable with the given evidence, and an executor
    /// whose timeout is far longer than any fail-fast path may take.
    fn stalled(
        evidence: serde_json::Value,
        pods: serde_json::Value,
    ) -> (MemoryClusterApi, PathBuf) {
        let root = unique_root("stall");
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
        api.set_conditions("lab", "edge", "Deployment", unavailable_conditions());
        api.set_evidence(
            "lab",
            "edge",
            "Deployment",
            WorkloadEvidence {
                workload: evidence,
                pods: serde_json::from_value(pods).unwrap(),
            },
        );
        (api, kubeconfig)
    }

    fn fail_fast(api: &MemoryClusterApi, kubeconfig: &Path) -> String {
        let root = kubeconfig.parent().unwrap().to_path_buf();
        let executor = InProcessKubernetesExecutor::new(api)
            .with_timeout(Duration::from_secs(60))
            .with_poll_interval(Duration::from_millis(10));
        let started = Instant::now();
        let err = executor
            .apply(&request(&root, kubeconfig, "1.0.0"))
            .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "terminal stall waited {:?}",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(root);
        format!("{err:#}")
    }

    #[test]
    fn a_crash_loop_fails_the_wait_naming_the_exit() {
        let (api, kubeconfig) = stalled(
            serde_json::json!({"kind": "Deployment", "metadata": {"name": "edge"}}),
            serde_json::json!([{
                "metadata": {"name": "edge-7c9f-x2"},
                "status": {"containerStatuses": [{
                    "name": "nginx",
                    "restartCount": 4,
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                    "lastState": {"terminated": {"exitCode": 1,
                        "message": "host not found in upstream \"api\""}},
                }]},
            }]),
        );
        let err = fail_fast(&api, &kubeconfig);
        assert!(
            err.contains(
                "Deployment edge cannot become Available: pod edge-7c9f-x2 container nginx CrashLoopBackOff after 4 restarts, last exit code 1: host not found in upstream"
            ),
            "{err}"
        );
    }

    #[test]
    fn an_admission_refusal_fails_the_wait_naming_the_refusal() {
        let (api, kubeconfig) = stalled(
            serde_json::json!({
                "kind": "Deployment",
                "metadata": {"name": "edge"},
                "status": {"conditions": [{
                    "type": "ReplicaFailure", "status": "True", "reason": "FailedCreate",
                    "message": "pods \"edge-7c9f\" is forbidden: violates PodSecurity \"restricted:latest\": runAsNonRoot != true",
                }]},
            }),
            serde_json::json!([]),
        );
        let err = fail_fast(&api, &kubeconfig);
        assert!(
            err.contains("ReplicaFailure=True FailedCreate: pods \"edge-7c9f\" is forbidden: violates PodSecurity"),
            "{err}"
        );
    }

    #[test]
    fn a_timeout_names_the_last_cause_seen() {
        let (api, kubeconfig) = stalled(
            serde_json::json!({"kind": "Deployment", "metadata": {"name": "edge"}}),
            serde_json::json!([{
                "metadata": {"name": "edge-7c9f-x2"},
                "status": {"conditions": [{"type": "PodScheduled", "status": "False",
                    "reason": "Unschedulable", "message": "0/1 nodes are available"}]},
            }]),
        );
        let root = kubeconfig.parent().unwrap().to_path_buf();
        let executor = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_millis(50))
            .with_poll_interval(Duration::from_millis(10));
        let err = executor
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("refused to complete"), "{err}");
        assert!(
            err.contains(
                "cause: pod edge-7c9f-x2 is pending: Unschedulable: 0/1 nodes are available"
            ),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_slow_rollout_with_starting_pods_still_succeeds() {
        let root = unique_root("slow");
        let _ = std::fs::remove_dir_all(&root);
        let kubeconfig = write_deployment(&root, "1.0.0", 1);
        let api = DelayedReadyApi::new(Duration::from_millis(400));
        api.inner.set_evidence(
            "lab",
            "edge",
            "Deployment",
            WorkloadEvidence {
                workload: serde_json::json!({"kind": "Deployment"}),
                pods: serde_json::from_value(serde_json::json!([{
                    "metadata": {"name": "edge-7c9f-x2"},
                    "status": {"containerStatuses": [{"name": "app", "restartCount": 0,
                        "state": {"waiting": {"reason": "ContainerCreating"}}}]},
                }]))
                .unwrap(),
            },
        );
        InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_secs(10))
            .with_poll_interval(Duration::from_millis(20))
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .expect("a slow healthy rollout completes");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_lost_lease_stops_the_wait() {
        let root = unique_root("stop");
        let _ = std::fs::remove_dir_all(&root);
        let kubeconfig = write_deployment(&root, "1.0.0", 1);
        let (api, _released, entered) = DelayedReadyApi::gated();
        let executor = InProcessKubernetesExecutor::new(api)
            .with_timeout(Duration::from_secs(60))
            .with_poll_interval(Duration::from_millis(10));
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let waiting = std::thread::spawn({
            let stop = stop.clone();
            let req = request(&root, &kubeconfig, "1.0.0");
            move || executor.apply_until_stopped(&req, &stop)
        });
        entered.recv().expect("apply entered the wait");
        let stopped = Instant::now();
        stop.store(true, Ordering::SeqCst);
        let err = waiting.join().unwrap().unwrap_err().to_string();
        assert!(
            stopped.elapsed() < Duration::from_secs(2),
            "{:?}",
            stopped.elapsed()
        );
        assert!(err.contains("the apply lease was lost"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }
}
