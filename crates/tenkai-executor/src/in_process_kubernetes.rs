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
    substitute_instance_placeholder, validate_cluster_config_path, validate_request,
};

pub const FIELD_MANAGER: &str = "tenkai";
/// First readiness poll after apply. Keeps post-ready wait under 250 ms.
const DEFAULT_HEALTH_POLL: Duration = Duration::from_millis(100);
/// Backoff cap so a long rollout cannot reintroduce a 1 s post-ready stall.
const MAX_HEALTH_POLL: Duration = Duration::from_millis(200);
/// How often a workload that is not Available is diagnosed. Diagnosis lists
/// pods, so it runs less often than the condition poll.
const DIAGNOSIS_INTERVAL: Duration = Duration::from_secs(2);
/// Bound on one live API call, so a stalled API server cannot hold the wait
/// past a stop for longer than this.
const LIVE_CALL_TIMEOUT: Duration = Duration::from_secs(10);
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

/// Workload status the wait uses to decide whether the applied revision is
/// the one serving. Counts are `None` until the API has populated them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct WorkloadRollout {
    pub generation: Option<i64>,
    pub observed_generation: Option<i64>,
    pub desired_replicas: Option<i64>,
    pub replicas: Option<i64>,
    pub updated_replicas: Option<i64>,
    pub ready_replicas: Option<i64>,
    pub available_replicas: Option<i64>,
    pub current_revision: Option<String>,
    pub update_revision: Option<String>,
    pub desired_number_scheduled: Option<i64>,
    pub updated_number_scheduled: Option<i64>,
    pub number_available: Option<i64>,
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
    /// Live object JSON for spec-drift comparison (#1028). Default is none.
    fn observe_object(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<Value>> {
        let _ = (cluster_config, namespace, name, kind);
        Ok(None)
    }
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
    /// Generation and replica/revision counts for the applied-revision wait.
    /// `None` when the object is absent or this adapter has no rollout data;
    /// a workload wait then fails closed instead of succeeding on `Available`.
    fn workload_rollout(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadRollout>> {
        let _ = (cluster_config, namespace, name, kind);
        Ok(None)
    }
    /// Observation and rollout from one live read so identity and replica
    /// counts cannot be mixed across revisions. The default does not pair a
    /// second read; missing rollout data fails the wait closed.
    fn observe_with_rollout(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<(WorkloadObservation, Option<WorkloadRollout>)>> {
        Ok(self
            .observe(cluster_config, namespace, name, kind)?
            .map(|observation| (observation, None)))
    }
    /// Workloads Tenkai labeled in `namespace` (`tenkai.product`). Bounded.
    fn list_tenkai_workloads(
        &self,
        cluster_config: &Path,
        namespace: &str,
    ) -> Result<Vec<(String, String)>> {
        let _ = (cluster_config, namespace);
        Ok(Vec::new())
    }
    /// Event reasons and counts for one workload. Messages are not returned.
    fn workload_event_counts(
        &self,
        cluster_config: &Path,
        namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<Vec<(String, i32)>> {
        let _ = (cluster_config, namespace, kind, name);
        Ok(Vec::new())
    }
    /// One kubeconfig, one pass: labeled workloads, their pods, and event
    /// reasons. Default is none.
    fn collect_support_workloads(
        &self,
        cluster_config: &Path,
        namespace: &str,
    ) -> Result<Vec<tenkai::support_bundle::SupportWorkload>> {
        let listed = self.list_tenkai_workloads(cluster_config, namespace)?;
        let mut workloads = Vec::new();
        for (kind, name) in listed
            .into_iter()
            .take(tenkai::support_bundle::MAX_SUPPORT_PODS)
        {
            let evidence = self
                .workload_evidence(cluster_config, namespace, &name, &kind)?
                .unwrap_or_default();
            let rollout = self
                .workload_rollout(cluster_config, namespace, &name, &kind)?
                .unwrap_or_default();
            let events = self
                .workload_event_counts(cluster_config, namespace, &kind, &name)
                .unwrap_or_default();
            workloads.push(support_workload(
                namespace, &kind, &name, &rollout, &evidence, &events,
            ));
        }
        Ok(workloads)
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

    fn observe_object(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<Value>> {
        (**self).observe_object(cluster_config, namespace, name, kind)
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

    fn workload_rollout(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadRollout>> {
        (**self).workload_rollout(cluster_config, namespace, name, kind)
    }

    fn observe_with_rollout(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<(WorkloadObservation, Option<WorkloadRollout>)>> {
        (**self).observe_with_rollout(cluster_config, namespace, name, kind)
    }

    fn list_tenkai_workloads(
        &self,
        cluster_config: &Path,
        namespace: &str,
    ) -> Result<Vec<(String, String)>> {
        (**self).list_tenkai_workloads(cluster_config, namespace)
    }

    fn workload_event_counts(
        &self,
        cluster_config: &Path,
        namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<Vec<(String, i32)>> {
        (**self).workload_event_counts(cluster_config, namespace, kind, name)
    }

    fn collect_support_workloads(
        &self,
        cluster_config: &Path,
        namespace: &str,
    ) -> Result<Vec<tenkai::support_bundle::SupportWorkload>> {
        (**self).collect_support_workloads(cluster_config, namespace)
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryClusterApi {
    objects: Mutex<BTreeMap<String, StoredObject>>,
    evidence: Mutex<BTreeMap<String, WorkloadEvidence>>,
    events: Mutex<BTreeMap<String, Vec<(String, i32)>>>,
}

#[cfg(test)]
#[derive(Clone)]
struct StoredObject {
    field_manager: String,
    object: Value,
    conditions: Vec<WorkloadCondition>,
    rollout: WorkloadRollout,
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

    pub fn mutate_object(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
        mutate: impl FnOnce(&mut Value),
    ) {
        let key = object_key(namespace, kind, name);
        if let Some(stored) = self.objects.lock().expect("cluster mutex").get_mut(&key) {
            mutate(&mut stored.object);
        }
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

    pub fn set_rollout(&self, namespace: &str, name: &str, kind: &str, rollout: WorkloadRollout) {
        let key = object_key(namespace, kind, name);
        if let Some(stored) = self.objects.lock().expect("cluster mutex").get_mut(&key) {
            stored.rollout = rollout;
        }
    }

    pub fn complete_stored_rollout(&self, namespace: &str, name: &str, kind: &str) {
        let key = object_key(namespace, kind, name);
        if let Some(stored) = self.objects.lock().expect("cluster mutex").get_mut(&key) {
            stored.rollout = complete_rollout(kind, &stored.object);
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

    pub fn set_events(&self, namespace: &str, name: &str, kind: &str, events: Vec<(String, i32)>) {
        self.events
            .lock()
            .expect("events mutex")
            .insert(object_key(namespace, kind, name), events);
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
        let rollout = objects
            .get(&key)
            .map(|stored| stored.rollout.clone())
            .unwrap_or_else(|| complete_rollout(&kind, object));
        objects.insert(
            key,
            StoredObject {
                field_manager: field_manager.into(),
                object: object.clone(),
                conditions: conditions.clone(),
                rollout,
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

    fn observe_object(
        &self,
        _cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<Value>> {
        Ok(self.object(namespace, kind, name))
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

    fn workload_rollout(
        &self,
        _cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadRollout>> {
        Ok(self
            .objects
            .lock()
            .expect("cluster mutex")
            .get(&object_key(namespace, kind, name))
            .map(|stored| stored.rollout.clone()))
    }

    fn observe_with_rollout(
        &self,
        _cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<(WorkloadObservation, Option<WorkloadRollout>)>> {
        let key = object_key(namespace, kind, name);
        Ok(self
            .objects
            .lock()
            .expect("cluster mutex")
            .get(&key)
            .map(|stored| {
                (
                    WorkloadObservation {
                        kind: kind.into(),
                        name: name.into(),
                        field_manager: stored.field_manager.clone(),
                        version_label: object_version_label(&stored.object),
                        conditions: stored.conditions.clone(),
                    },
                    Some(stored.rollout.clone()),
                )
            }))
    }

    fn list_tenkai_workloads(
        &self,
        _cluster_config: &Path,
        namespace: &str,
    ) -> Result<Vec<(String, String)>> {
        let prefix = format!("{namespace}/");
        let mut found = Vec::new();
        for (key, stored) in self.objects.lock().expect("cluster mutex").iter() {
            let Some(rest) = key.strip_prefix(&prefix) else {
                continue;
            };
            let Some((kind, name)) = rest.split_once('/') else {
                continue;
            };
            if !is_workload(kind) {
                continue;
            }
            if stored
                .object
                .pointer("/metadata/labels/tenkai.product")
                .and_then(Value::as_str)
                .is_none()
            {
                continue;
            }
            found.push((kind.to_string(), name.to_string()));
            if found.len() >= tenkai::support_bundle::MAX_SUPPORT_PODS {
                break;
            }
        }
        Ok(found)
    }

    fn workload_event_counts(
        &self,
        _cluster_config: &Path,
        namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<Vec<(String, i32)>> {
        Ok(self
            .events
            .lock()
            .expect("events mutex")
            .get(&object_key(namespace, kind, name))
            .cloned()
            .unwrap_or_default())
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
        block_on(bounded(live_apply(
            cluster_config,
            namespace,
            field_manager,
            object,
        )))
    }

    fn observe(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadObservation>> {
        block_on(bounded(live_observe(cluster_config, namespace, name, kind)))
    }

    fn observe_object(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<Value>> {
        block_on(bounded(live_observe_object(
            cluster_config,
            namespace,
            name,
            kind,
        )))
    }

    fn remove(&self, cluster_config: &Path, namespace: &str, name: &str, kind: &str) -> Result<()> {
        block_on(bounded(live_remove(cluster_config, namespace, name, kind)))
    }

    fn workload_evidence(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadEvidence>> {
        block_on(bounded(live_workload_evidence(
            cluster_config,
            namespace,
            name,
            kind,
        )))
    }

    fn workload_rollout(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<WorkloadRollout>> {
        block_on(bounded(live_rollout(cluster_config, namespace, name, kind)))
    }

    fn observe_with_rollout(
        &self,
        cluster_config: &Path,
        namespace: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<(WorkloadObservation, Option<WorkloadRollout>)>> {
        block_on(bounded(live_observe_with_rollout(
            cluster_config,
            namespace,
            name,
            kind,
        )))
    }

    fn list_tenkai_workloads(
        &self,
        cluster_config: &Path,
        namespace: &str,
    ) -> Result<Vec<(String, String)>> {
        block_on(bounded(live_list_tenkai_workloads(
            cluster_config,
            namespace,
        )))
    }

    fn workload_event_counts(
        &self,
        cluster_config: &Path,
        namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<Vec<(String, i32)>> {
        block_on(bounded(live_workload_event_counts(
            cluster_config,
            namespace,
            kind,
            name,
        )))
    }

    fn collect_support_workloads(
        &self,
        cluster_config: &Path,
        namespace: &str,
    ) -> Result<Vec<tenkai::support_bundle::SupportWorkload>> {
        // Each inner list is bounded; wrapping the whole pass in one
        // LIVE_CALL_TIMEOUT would drop every fact on a slow API.
        block_on(live_collect_support_workloads(cluster_config, namespace))
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
            for object in parse_manifest_objects(path, request.instance_name())? {
                objects.push(object);
            }
        }
        times.plan_ms = planned.elapsed().as_millis() as u64;
        let applied = Instant::now();
        if let Some(json) = tenkai::dependency_document::configmap_json(request) {
            let mut object: Value =
                serde_json::from_str(&json).context("parsing dependency ConfigMap")?;
            stamp_ownership(&mut object, request);
            stop_if_lease_lost(stop, request, &[], &[])?;
            let _ = self.api.apply_server_side(
                cluster_config,
                &request.environment,
                FIELD_MANAGER,
                &object,
            )?;
        }
        let mut observations = Vec::new();
        for mut object in objects {
            stop_if_lease_lost(stop, request, &[], &[])?;
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

    /// Wait until every applied workload has rolled out the requested
    /// version. A workload that has not is diagnosed every
    /// [`DIAGNOSIS_INTERVAL`]: a terminal stall fails the wait at once, and
    /// both the timeout and a lost-lease stop name the last cause seen.
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
        let mut last_failed: Vec<String> = Vec::new();
        loop {
            let mut failed = Vec::new();
            let mut stalled = Vec::new();
            for applied in applied {
                stop_if_lease_lost(stop, request, &last_failed, &causes)?;
                let Some((live, rollout)) = self.api.observe_with_rollout(
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
                if let Some(error) = disagreeing_condition(&live, rollout.as_ref()) {
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
            last_failed.clone_from(&failed);
            let now = Instant::now();
            if now >= next_diagnosis || now >= deadline {
                next_diagnosis = now + DIAGNOSIS_INTERVAL;
                let mut next_causes = Vec::new();
                for (kind, name) in stalled {
                    stop_if_lease_lost(stop, request, &failed, &causes)?;
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
                    next_causes.push(stall.cause);
                }
                causes = next_causes;
            }
            if now >= deadline {
                bail!(
                    "in-process kubernetes apply refused to complete for {}@{} in {} after {}s: {}",
                    request.product,
                    request.version,
                    request.environment,
                    started.elapsed().as_secs(),
                    health_wait_detail(&failed, &causes)
                );
            }
            stop_if_lease_lost(stop, request, &failed, &causes)?;
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
        self.remove_until_stopped(request, &NOT_STOPPED)
    }

    fn remove_until_stopped(
        &self,
        request: &SoftwareApplyRequest,
        stop: &AtomicBool,
    ) -> Result<()> {
        validate_request(request)?;
        let cluster_config = Self::require_cluster_config(request)?;
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        for path in files.iter().rev() {
            for object in parse_manifest_objects(path, request.instance_name())? {
                if stop.load(Ordering::SeqCst) {
                    anyhow::bail!(
                        "removal of {} stopped: the apply lease was lost",
                        request.instance_name()
                    );
                }
                let (kind, name) = object_identity(&object)?;
                self.api
                    .remove(cluster_config, &request.environment, &name, &kind)?;
            }
        }
        let name = tenkai::dependency_document::configmap_name(request.instance_name());
        let _ = self
            .api
            .remove(cluster_config, &request.environment, &name, "ConfigMap");
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
            for object in parse_manifest_objects(path, request.instance_name())? {
                let (kind, name) = object_identity(&object)?;
                if !is_workload(&kind) {
                    continue;
                }
                saw_workload = true;
                match self.api.observe_with_rollout(
                    cluster_config,
                    &request.environment,
                    &name,
                    &kind,
                )? {
                    None => return Ok(SoftwareObserveStatus::Absent),
                    Some((live, rollout)) => {
                        if disagreeing_condition(&live, rollout.as_ref()).is_some() {
                            return Ok(SoftwareObserveStatus::Mismatched);
                        }
                        if live.version_label.as_deref()
                            != Some(k8s_label_value(&request.version).as_str())
                        {
                            return Ok(SoftwareObserveStatus::Mismatched);
                        }
                    }
                }
            }
        }
        if saw_workload {
            Ok(SoftwareObserveStatus::Present)
        } else {
            Ok(SoftwareObserveStatus::Unknown)
        }
    }

    fn observe_spec_drift(
        &self,
        request: &SoftwareApplyRequest,
    ) -> Result<tenkai::spec_drift::SpecDriftView> {
        validate_request(request)?;
        let Ok(cluster_config) = Self::require_cluster_config(request) else {
            return Ok(tenkai::spec_drift::SpecDriftView::unknown());
        };
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        if files.is_empty() {
            return Ok(tenkai::spec_drift::SpecDriftView::unknown());
        }
        let mut objects = Vec::new();
        for path in &files {
            for applied in parse_manifest_objects(path, request.instance_name())? {
                let (kind, name) = object_identity(&applied)?;
                if !is_workload(&kind) {
                    continue;
                }
                match self
                    .api
                    .observe_object(cluster_config, &request.environment, &name, &kind)?
                {
                    None => objects.push(tenkai::spec_drift::SpecDriftObject {
                        kind,
                        name,
                        status: tenkai::spec_drift::SPEC_DRIFT_UNKNOWN.into(),
                        fields: Vec::new(),
                    }),
                    Some(live) => objects.push(tenkai::spec_drift::compare_workload_spec(
                        &kind, &name, &applied, &live,
                    )),
                }
            }
        }
        Ok(tenkai::spec_drift::SpecDriftView::from_objects(objects))
    }

    fn support_workloads(
        &self,
        environment: &str,
        cluster_config: &Path,
    ) -> Result<Vec<tenkai::support_bundle::SupportWorkload>> {
        validate_cluster_config_path(cluster_config)?;
        if !cluster_config.is_file() {
            bail!(
                "environment {environment} cluster_config_path is not a readable kubeconfig file"
            );
        }
        self.api
            .collect_support_workloads(cluster_config, environment)
    }
}

fn parse_manifest_objects(path: &Path, instance: &str) -> Result<Vec<Value>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("reading manifest {}: {error}", path.display()))?;
    let raw = substitute_instance_placeholder(&raw, instance);
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
        "tenkai.instance".into(),
        Value::String(k8s_label_value(request.instance_name())),
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

fn support_workload(
    environment: &str,
    kind: &str,
    name: &str,
    rollout: &WorkloadRollout,
    evidence: &WorkloadEvidence,
    events: &[(String, i32)],
) -> tenkai::support_bundle::SupportWorkload {
    let revision = rollout
        .update_revision
        .as_deref()
        .or(rollout.current_revision.as_deref())
        .and_then(tenkai::support_bundle::allowlisted_revision);
    let pods = evidence
        .pods
        .iter()
        .take(tenkai::support_bundle::MAX_SUPPORT_PODS)
        .map(support_pod)
        .collect();
    let mut counted = Vec::new();
    for (reason, count) in events
        .iter()
        .take(tenkai::support_bundle::MAX_SUPPORT_EVENTS)
    {
        let Some(reason) = tenkai::support_bundle::allowlisted_reason(reason) else {
            continue;
        };
        counted.push(tenkai::support_bundle::SupportEventCount {
            reason,
            count: *count,
        });
    }
    tenkai::support_bundle::SupportWorkload {
        environment: environment.into(),
        kind: kind.into(),
        name: name.into(),
        desired: rollout
            .desired_replicas
            .or(rollout.desired_number_scheduled),
        // Status replica counters use omitempty: missing means 0.
        ready: Some(
            rollout
                .ready_replicas
                .or(rollout.number_available)
                .unwrap_or(0),
        ),
        updated: Some(
            rollout
                .updated_replicas
                .or(rollout.updated_number_scheduled)
                .unwrap_or(0),
        ),
        revision,
        pods,
        events: counted,
        spec_drift: None,
    }
}

fn support_pod(pod: &k8s_openapi::api::core::v1::Pod) -> tenkai::support_bundle::SupportPod {
    let status = pod.status.as_ref();
    let phase = status
        .and_then(|s| s.phase.as_deref())
        .and_then(tenkai::support_bundle::allowlisted_reason)
        .unwrap_or_default();
    let ready = status
        .and_then(|s| s.conditions.as_ref())
        .into_iter()
        .flatten()
        .any(|condition| condition.type_ == "Ready" && condition.status == "True");
    let mut restarts = 0_i32;
    let mut waiting_reason = None;
    let mut last_reason = None;
    let mut last_exit_code = None;
    if let Some(status) = status {
        let mut waiting_exit: Option<(Option<String>, i32)> = None;
        let mut any_exit: Option<(Option<String>, i32)> = None;
        for container in status
            .init_container_statuses
            .iter()
            .flatten()
            .chain(status.container_statuses.iter().flatten())
        {
            restarts = restarts.saturating_add(container.restart_count);
            let terminated = container
                .last_state
                .as_ref()
                .and_then(|state| state.terminated.as_ref())
                .map(|terminated| {
                    (
                        terminated
                            .reason
                            .as_deref()
                            .and_then(tenkai::support_bundle::allowlisted_reason),
                        terminated.exit_code,
                    )
                });
            let waiting = container
                .state
                .as_ref()
                .and_then(|state| state.waiting.as_ref())
                .and_then(|waiting| waiting.reason.as_deref())
                .and_then(tenkai::support_bundle::allowlisted_reason);
            if waiting_reason.is_none()
                && let Some(reason) = waiting
            {
                waiting_reason = Some(reason);
                waiting_exit = terminated.clone();
            }
            if any_exit.is_none() {
                any_exit = terminated;
            }
        }
        let exit = waiting_exit.or(any_exit);
        if let Some((reason, code)) = exit {
            last_reason = reason;
            last_exit_code = Some(code);
        }
    }
    tenkai::support_bundle::SupportPod {
        phase,
        ready,
        restarts,
        waiting_reason,
        last_reason,
        last_exit_code,
    }
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

pub(crate) fn disagreeing_condition(
    observation: &WorkloadObservation,
    rollout: Option<&WorkloadRollout>,
) -> Option<String> {
    if !is_workload(&observation.kind) {
        return None;
    }
    if let Some(error) = incomplete_rollout(observation, rollout) {
        return Some(error);
    }
    if observation.kind == "Deployment" {
        let available = observation
            .conditions
            .iter()
            .find(|condition| condition.type_name == "Available");
        if let Some(condition) = available
            && condition.status != "True"
        {
            return Some(format!(
                "{} {} condition Available={} reason {}",
                observation.kind, observation.name, condition.status, condition.reason
            ));
        }
        return observation.conditions.iter().find_map(|condition| {
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
        });
    }
    None
}

/// Why the applied revision is not the one serving yet. `Available=True` is
/// not enough: an upgrade keeps that condition on the old ReplicaSet.
fn incomplete_rollout(
    observation: &WorkloadObservation,
    rollout: Option<&WorkloadRollout>,
) -> Option<String> {
    let kind = observation.kind.as_str();
    let name = observation.name.as_str();
    let Some(rollout) = rollout else {
        return Some(format!("{kind} {name} rollout status is unavailable"));
    };
    match (rollout.observed_generation, rollout.generation) {
        (Some(observed), Some(generation)) if observed >= generation => {}
        (observed, generation) => {
            return Some(format!(
                "{kind} {name} observedGeneration {observed:?} has not reached generation {generation:?}"
            ));
        }
    }
    match kind {
        "Deployment" => {
            // Status replica counters use omitempty, so a scaled-to-zero
            // object omits 0 after the controller has observed the generation.
            let desired = rollout.desired_replicas.unwrap_or(1);
            let updated = rollout.updated_replicas.unwrap_or(0);
            let available = rollout.available_replicas.unwrap_or(0);
            let replicas = rollout.replicas.unwrap_or(0);
            if updated != desired || available != desired || replicas != updated {
                return Some(format!(
                    "{kind} {name} rollout incomplete: {updated}/{desired} updated, {available} available, {replicas} total"
                ));
            }
            None
        }
        "StatefulSet" => {
            let desired = rollout.desired_replicas.unwrap_or(1);
            let ready = rollout.ready_replicas.unwrap_or(0);
            match (
                rollout.current_revision.as_deref(),
                rollout.update_revision.as_deref(),
            ) {
                (Some(current), Some(update)) if current == update => {}
                (current, update) => {
                    return Some(format!(
                        "{kind} {name} currentRevision {current:?} does not match updateRevision {update:?}"
                    ));
                }
            }
            if ready != desired {
                return Some(format!(
                    "{kind} {name} readyReplicas {ready} does not equal desired {desired}"
                ));
            }
            None
        }
        "DaemonSet" => {
            let desired = rollout.desired_number_scheduled.unwrap_or(0);
            let updated = rollout.updated_number_scheduled.unwrap_or(0);
            let available = rollout.number_available.unwrap_or(0);
            if updated != desired || available != desired {
                return Some(format!(
                    "{kind} {name} rollout incomplete: {updated}/{desired} updated, {available} available"
                ));
            }
            None
        }
        _ => None,
    }
}

/// Last observed failures and diagnosed stall causes, formatted the way the
/// timeout path already reports them.
fn health_wait_detail(failed: &[String], causes: &[String]) -> String {
    let failed_part = failed.join("; ");
    if causes.is_empty() {
        failed_part
    } else if failed_part.is_empty() {
        format!("cause: {}", causes.join("; "))
    } else {
        format!("{failed_part}; cause: {}", causes.join("; "))
    }
}

/// Checked before every live API call, so a lost lease stops apply and the
/// wait within one call ([`LIVE_CALL_TIMEOUT`]) plus one poll. A wait that
/// already diagnosed a stall names those causes the same way a timeout does.
fn stop_if_lease_lost(
    stop: &AtomicBool,
    request: &SoftwareApplyRequest,
    failed: &[String],
    causes: &[String],
) -> Result<()> {
    if !stop.load(Ordering::SeqCst) {
        return Ok(());
    }
    let detail = health_wait_detail(failed, causes);
    if detail.is_empty() {
        bail!(
            "in-process kubernetes apply for {}@{} in {} stopped: the apply lease was lost",
            request.product,
            request.version,
            request.environment
        );
    }
    bail!(
        "in-process kubernetes apply for {}@{} in {} stopped: the apply lease was lost: {detail}",
        request.product,
        request.version,
        request.environment
    );
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

/// `fut`, failing after [`LIVE_CALL_TIMEOUT`].
pub(crate) async fn bounded<T>(fut: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(LIVE_CALL_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| {
            bail!(
                "kubernetes API call timed out after {}s",
                LIVE_CALL_TIMEOUT.as_secs()
            )
        })
}

pub(crate) async fn live_client(cluster_config: &Path) -> Result<kube::Client> {
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
    Ok(
        live_observe_with_rollout(cluster_config, namespace, name, kind)
            .await?
            .map(|(observation, _)| observation),
    )
}

async fn live_observe_object(
    cluster_config: &Path,
    namespace: &str,
    name: &str,
    kind: &str,
) -> Result<Option<Value>> {
    let client = live_client(cluster_config).await?;
    let api_version = builtin_api_version(kind)?;
    let api = dynamic_api(client, namespace, kind, api_version)?;
    match api.get_opt(name).await {
        Ok(Some(object)) => Ok(Some(serde_json::to_value(&object).unwrap_or(Value::Null))),
        Ok(None) => Ok(None),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "reading {kind}/{name} in {namespace}: {error}"
        )),
    }
}

async fn live_observe_with_rollout(
    cluster_config: &Path,
    namespace: &str,
    name: &str,
    kind: &str,
) -> Result<Option<(WorkloadObservation, Option<WorkloadRollout>)>> {
    let client = live_client(cluster_config).await?;
    let api_version = builtin_api_version(kind)?;
    let api = dynamic_api(client, namespace, kind, api_version)?;
    match api.get_opt(name).await {
        Ok(Some(object)) => {
            let value = serde_json::to_value(&object).unwrap_or(Value::Null);
            Ok(Some((
                observation_from_dynamic(&object, kind, name),
                Some(rollout_from_value(kind, &value)),
            )))
        }
        Ok(None) => Ok(None),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "observing {kind}/{name} in {namespace}: {error}"
        )),
    }
}

async fn live_rollout(
    cluster_config: &Path,
    namespace: &str,
    name: &str,
    kind: &str,
) -> Result<Option<WorkloadRollout>> {
    let client = live_client(cluster_config).await?;
    let api_version = builtin_api_version(kind)?;
    let api = dynamic_api(client, namespace, kind, api_version)?;
    match api.get_opt(name).await {
        Ok(Some(object)) => {
            let value = serde_json::to_value(&object).unwrap_or(Value::Null);
            Ok(Some(rollout_from_value(kind, &value)))
        }
        Ok(None) => Ok(None),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "reading rollout for {kind}/{name} in {namespace}: {error}"
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
    // Pods only add detail; the workload's conditions are classified even
    // when the pods cannot be read.
    let pods = match current_revision_selector(&client, namespace, kind, &workload).await {
        Ok(Some(selector)) => kube::Api::<Pod>::namespaced(client, namespace)
            .list(
                &kube::api::ListParams::default()
                    .labels(&selector)
                    .limit(DIAGNOSED_PODS),
            )
            .await
            .map(|pods| pods.items)
            .with_context(|| format!("listing pods of {kind}/{name} in {namespace}")),
        Ok(None) => Ok(Vec::new()),
        Err(error) => Err(error),
    };
    Ok(Some(match pods {
        Ok(pods) => WorkloadEvidence {
            workload,
            pods,
            pods_unavailable: None,
        },
        Err(error) => WorkloadEvidence {
            workload,
            pods: Vec::new(),
            pods_unavailable: Some(format!("{error:#}")),
        },
    }))
}

async fn live_list_tenkai_workloads(
    cluster_config: &Path,
    namespace: &str,
) -> Result<Vec<(String, String)>> {
    let client = live_client(cluster_config).await?;
    let params = kube::api::ListParams::default()
        .labels("tenkai.product")
        .limit(tenkai::support_bundle::MAX_SUPPORT_PODS as u32);
    let mut found = Vec::new();
    for kind in ["Deployment", "StatefulSet", "DaemonSet"] {
        if found.len() >= tenkai::support_bundle::MAX_SUPPORT_PODS {
            break;
        }
        let api = dynamic_api(client.clone(), namespace, kind, builtin_api_version(kind)?)?;
        let list = api
            .list(&params)
            .await
            .with_context(|| format!("listing {kind} in {namespace}"))?;
        for object in list.items {
            let Some(name) = object.metadata.name.clone() else {
                continue;
            };
            found.push((kind.into(), name));
            if found.len() >= tenkai::support_bundle::MAX_SUPPORT_PODS {
                break;
            }
        }
    }
    Ok(found)
}

async fn live_collect_support_workloads(
    cluster_config: &Path,
    namespace: &str,
) -> Result<Vec<tenkai::support_bundle::SupportWorkload>> {
    use k8s_openapi::api::core::v1::{Event, Pod};
    let client = bounded(live_client(cluster_config)).await?;
    let params = kube::api::ListParams::default()
        .labels("tenkai.product")
        .limit(tenkai::support_bundle::MAX_SUPPORT_PODS as u32);
    let mut objects = Vec::new();
    let mut listed_any = false;
    let mut list_failed = false;
    for kind in ["Deployment", "StatefulSet", "DaemonSet"] {
        if objects.len() >= tenkai::support_bundle::MAX_SUPPORT_PODS {
            break;
        }
        let api = dynamic_api(client.clone(), namespace, kind, builtin_api_version(kind)?)?;
        let list = match bounded(async {
            api.list(&params)
                .await
                .with_context(|| format!("listing {kind} in {namespace}"))
        })
        .await
        {
            Ok(list) => list,
            Err(_) => {
                list_failed = true;
                continue;
            }
        };
        listed_any = true;
        for object in list.items {
            let Some(name) = object.metadata.name.clone() else {
                continue;
            };
            let value = serde_json::to_value(&object).context("encoding workload status")?;
            objects.push((kind.to_string(), name, value));
            if objects.len() >= tenkai::support_bundle::MAX_SUPPORT_PODS {
                break;
            }
        }
    }
    if live_kind_lists_unreadable(objects.len(), listed_any, list_failed) {
        bail!("listing workloads in {namespace}");
    }
    // Events need a wider RBAC grant than apply; omit them rather than
    // dropping replica and pod facts the rest of the pass already has.
    let ns_events = match bounded(async {
        kube::Api::<Event>::namespaced(client.clone(), namespace)
            .list(&kube::api::ListParams::default().limit(
                (tenkai::support_bundle::MAX_SUPPORT_EVENTS
                    * tenkai::support_bundle::MAX_SUPPORT_PODS) as u32,
            ))
            .await
            .with_context(|| format!("listing events in {namespace}"))
    })
    .await
    {
        Ok(listed) => listed.items,
        Err(_) => Vec::new(),
    };
    let mut workloads = Vec::new();
    for (kind, name, workload) in objects {
        let rollout = rollout_from_value(&kind, &workload);
        let selector = match bounded(current_revision_selector(
            &client, namespace, &kind, &workload,
        ))
        .await
        {
            Ok(Some(selector)) => Some(selector),
            Ok(None) | Err(_) => workload
                .pointer("/spec/selector")
                .and_then(label_selector_query),
        };
        let pods = match selector {
            Some(selector) => match bounded(async {
                kube::Api::<Pod>::namespaced(client.clone(), namespace)
                    .list(
                        &kube::api::ListParams::default()
                            .labels(&selector)
                            .limit(tenkai::support_bundle::MAX_SUPPORT_PODS as u32),
                    )
                    .await
                    .with_context(|| format!("listing pods of {kind}/{name} in {namespace}"))
            })
            .await
            {
                Ok(listed) => listed.items,
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        let pod_names = pods
            .iter()
            .filter_map(|pod| pod.metadata.name.clone())
            .collect::<Vec<_>>();
        let events = support_event_counts(&ns_events, &kind, &name, &pod_names);
        workloads.push(support_workload(
            namespace,
            &kind,
            &name,
            &rollout,
            &WorkloadEvidence {
                workload,
                pods,
                pods_unavailable: None,
            },
            &events,
        ));
    }
    Ok(workloads)
}

/// Empty after a kind-list failure is unreadable, not "no workloads".
fn live_kind_lists_unreadable(collected: usize, listed_any: bool, list_failed: bool) -> bool {
    !listed_any || (collected == 0 && list_failed)
}

fn support_event_counts(
    events: &[k8s_openapi::api::core::v1::Event],
    kind: &str,
    name: &str,
    pod_names: &[String],
) -> Vec<(String, i32)> {
    let mut counts = std::collections::BTreeMap::<String, i32>::new();
    for event in events {
        let object_kind = event.involved_object.kind.as_deref().unwrap_or("");
        let object_name = event.involved_object.name.as_deref().unwrap_or("");
        let matches = (object_kind == kind && object_name == name)
            || (object_kind == "Pod" && pod_names.iter().any(|pod| pod == object_name));
        if !matches {
            continue;
        }
        let Some(reason) = event
            .reason
            .as_deref()
            .and_then(tenkai::support_bundle::allowlisted_reason)
        else {
            continue;
        };
        let n = event.count.unwrap_or(1);
        counts
            .entry(reason)
            .and_modify(|count| *count = count.saturating_add(n))
            .or_insert(n);
    }
    counts
        .into_iter()
        .take(tenkai::support_bundle::MAX_SUPPORT_EVENTS)
        .collect()
}

async fn live_workload_event_counts(
    cluster_config: &Path,
    namespace: &str,
    kind: &str,
    name: &str,
) -> Result<Vec<(String, i32)>> {
    use k8s_openapi::api::core::v1::Event;
    let client = live_client(cluster_config).await?;
    let selector = format!("involvedObject.name={name},involvedObject.kind={kind}");
    let listed = kube::Api::<Event>::namespaced(client, namespace)
        .list(
            &kube::api::ListParams::default()
                .fields(&selector)
                .limit(tenkai::support_bundle::MAX_SUPPORT_EVENTS as u32),
        )
        .await
        .with_context(|| format!("listing events of {kind}/{name} in {namespace}"))?;
    let mut counts = std::collections::BTreeMap::<String, i32>::new();
    for event in listed.items {
        let Some(reason) = event
            .reason
            .as_deref()
            .and_then(tenkai::support_bundle::allowlisted_reason)
        else {
            continue;
        };
        let n = event.count.unwrap_or(1);
        counts
            .entry(reason)
            .and_modify(|count| *count = count.saturating_add(n))
            .or_insert(n);
    }
    Ok(counts
        .into_iter()
        .take(tenkai::support_bundle::MAX_SUPPORT_EVENTS)
        .collect())
}

/// Label selector for the pods of the workload's current revision: the
/// Deployment's newest ReplicaSet, or the StatefulSet's update revision.
/// `None` while the controller has not observed the applied generation or
/// that revision does not exist yet, and for other kinds.
async fn current_revision_selector(
    client: &kube::Client,
    namespace: &str,
    kind: &str,
    workload: &Value,
) -> Result<Option<String>> {
    use k8s_openapi::api::apps::v1::ReplicaSet;
    // Until the controller observes the applied generation, the revision it
    // reports is the previous rollout's, whose pods must not fail this one.
    let generation = workload
        .pointer("/metadata/generation")
        .and_then(Value::as_i64);
    let observed = workload
        .pointer("/status/observedGeneration")
        .and_then(Value::as_i64);
    if observed.is_none() || observed < generation {
        return Ok(None);
    }
    let Some(selector) = workload
        .pointer("/spec/selector")
        .and_then(label_selector_query)
    else {
        return Ok(None);
    };
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

/// A workload's `spec.selector` as a label selector query, with both
/// `matchLabels` and `matchExpressions`. `None` when it selects nothing
/// expressible, so no pods are read.
fn label_selector_query(selector: &Value) -> Option<String> {
    let labels = selector
        .get("matchLabels")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(key, value)| Some(format!("{key}={}", value.as_str()?)));
    let expressions = selector
        .get("matchExpressions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|expression| {
            let key = expression.get("key")?.as_str()?;
            let values = || -> Option<String> {
                let values = expression
                    .get("values")?
                    .as_array()?
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Option<Vec<_>>>()?;
                Some(values.join(","))
            };
            Some(match expression.get("operator")?.as_str()? {
                "In" => format!("{key} in ({})", values()?),
                "NotIn" => format!("{key} notin ({})", values()?),
                "Exists" => key.to_string(),
                "DoesNotExist" => format!("!{key}"),
                _ => return None,
            })
        });
    let terms = labels.chain(expressions).collect::<Option<Vec<_>>>()?;
    (!terms.is_empty()).then(|| terms.join(","))
}

pub(crate) async fn ensure_namespace(client: &kube::Client, namespace: &str) -> Result<()> {
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

fn json_i64(object: &Value, pointer: &str) -> Option<i64> {
    let value = object.pointer(pointer)?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
}

fn json_str(object: &Value, pointer: &str) -> Option<String> {
    object.pointer(pointer)?.as_str().map(str::to_string)
}

fn rollout_from_value(kind: &str, object: &Value) -> WorkloadRollout {
    WorkloadRollout {
        generation: json_i64(object, "/metadata/generation"),
        observed_generation: json_i64(object, "/status/observedGeneration"),
        desired_replicas: json_i64(object, "/spec/replicas")
            .or_else(|| matches!(kind, "Deployment" | "StatefulSet").then_some(1)),
        replicas: json_i64(object, "/status/replicas"),
        updated_replicas: json_i64(object, "/status/updatedReplicas"),
        ready_replicas: json_i64(object, "/status/readyReplicas"),
        available_replicas: json_i64(object, "/status/availableReplicas"),
        current_revision: json_str(object, "/status/currentRevision").or_else(|| {
            json_str(
                object,
                "/metadata/annotations/deployment.kubernetes.io~1revision",
            )
        }),
        update_revision: json_str(object, "/status/updateRevision"),
        desired_number_scheduled: json_i64(object, "/status/desiredNumberScheduled"),
        updated_number_scheduled: json_i64(object, "/status/updatedNumberScheduled"),
        number_available: json_i64(object, "/status/numberAvailable"),
    }
}

#[cfg(test)]
fn complete_rollout(kind: &str, object: &Value) -> WorkloadRollout {
    let generation = json_i64(object, "/metadata/generation").unwrap_or(1);
    let desired = json_i64(object, "/spec/replicas").unwrap_or(1);
    match kind {
        "StatefulSet" => WorkloadRollout {
            generation: Some(generation),
            observed_generation: Some(generation),
            desired_replicas: Some(desired),
            replicas: Some(desired),
            updated_replicas: Some(desired),
            ready_replicas: Some(desired),
            current_revision: Some("complete".into()),
            update_revision: Some("complete".into()),
            ..WorkloadRollout::default()
        },
        "DaemonSet" => WorkloadRollout {
            generation: Some(generation),
            observed_generation: Some(generation),
            desired_number_scheduled: Some(1),
            updated_number_scheduled: Some(1),
            number_available: Some(1),
            ..WorkloadRollout::default()
        },
        _ => WorkloadRollout {
            generation: Some(generation),
            observed_generation: Some(generation),
            desired_replicas: Some(desired),
            replicas: Some(desired),
            updated_replicas: Some(desired),
            ready_replicas: Some(desired),
            available_replicas: Some(desired),
            ..WorkloadRollout::default()
        },
    }
}

#[cfg(test)]
fn incomplete_rollout_status(kind: &str, object: &Value) -> WorkloadRollout {
    let mut rollout = complete_rollout(kind, object);
    match kind {
        "StatefulSet" => {
            rollout.current_revision = Some("old".into());
            rollout.update_revision = Some("new".into());
            rollout.ready_replicas = Some(0);
        }
        "DaemonSet" => {
            rollout.updated_number_scheduled = Some(0);
            rollout.number_available = Some(0);
        }
        _ => {
            rollout.updated_replicas = Some(0);
            rollout.replicas = rollout.desired_replicas;
            rollout.available_replicas = rollout.desired_replicas;
        }
    }
    rollout
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

pub(crate) fn is_already_exists(error: &kube::Error) -> bool {
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
        write_deployment_with_containers(
            root,
            version,
            replicas,
            "        - name: app\n          image: app:1\n",
        )
    }

    fn write_deployment_with_containers(
        root: &Path,
        version: &str,
        replicas: u64,
        containers: &str,
    ) -> PathBuf {
        let manifests = root.join("manifests");
        std::fs::create_dir_all(&manifests).unwrap();
        std::fs::write(
            manifests.join("deploy.yaml"),
            format!(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: edge\nspec:\n  replicas: {replicas}\n  template:\n    spec:\n      containers:\n{containers}"
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
            instance: String::new(),
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
            dependency_document: String::new(),
            opened_secrets: Vec::new(),
            remove_owned_secrets: false,
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
    fn a_stopped_removal_deletes_nothing_more() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-ssa-remove-stop-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let kubeconfig = write_deployment(&root, "1.0.0", 1);
        let api = MemoryClusterApi::new();
        let executor = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_millis(200))
            .with_poll_interval(Duration::from_millis(20));
        let request = request(&root, &kubeconfig, "1.0.0");
        executor.apply(&request).unwrap();

        let error = executor
            .remove_until_stopped(&request, &AtomicBool::new(true))
            .unwrap_err()
            .to_string();

        assert!(error.contains("apply lease was lost"), "{error}");
        assert!(
            api.observe(Path::new("/unused"), "lab", "edge", "Deployment")
                .unwrap()
                .is_some()
        );
        executor.remove(&request).unwrap();
        assert!(
            api.observe(Path::new("/unused"), "lab", "edge", "Deployment")
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn extra_container_is_spec_drift_and_observe_stays_present() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-ssa-drift-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let kubeconfig = write_deployment(&root, "1.0.0", 1);
        let api = MemoryClusterApi::new();
        let executor = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_millis(200))
            .with_poll_interval(Duration::from_millis(20));
        let request = request(&root, &kubeconfig, "1.0.0");
        executor.apply(&request).unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        assert_eq!(
            executor.observe_spec_drift(&request).unwrap().status,
            tenkai::spec_drift::SPEC_DRIFT_CURRENT
        );
        api.mutate_object("lab", "Deployment", "edge", |object| {
            let containers = object
                .pointer_mut("/spec/template/spec/containers")
                .and_then(Value::as_array_mut)
                .expect("containers");
            containers.push(serde_json::json!({
                "name": "sidecar",
                "image": "proxy:1",
                "env": [{"name": "TOKEN", "value": "secret-value"}]
            }));
            object["status"]["replicas"] = serde_json::json!(9);
            object["metadata"]["annotations"] = serde_json::json!({
                "deployment.kubernetes.io/revision": "9"
            });
        });
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        let drift = executor.observe_spec_drift(&request).unwrap();
        assert_eq!(drift.status, tenkai::spec_drift::SPEC_DRIFT_MODIFIED);
        assert_eq!(drift.objects[0].fields, vec!["containers"]);
        let encoded = serde_json::to_string(&drift).unwrap();
        assert!(!encoded.contains("secret-value"), "{encoded}");
        executor.apply(&request).unwrap();
        assert_eq!(
            executor.observe_spec_drift(&request).unwrap().status,
            tenkai::spec_drift::SPEC_DRIFT_CURRENT
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn support_workloads_keep_crash_loop_counts_and_drop_messages() {
        use k8s_openapi::api::core::v1::Pod;
        use serde_json::json;
        let root = std::env::temp_dir().join(format!(
            "tenkai-support-wl-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let kubeconfig = root.join("kubeconfig");
        std::fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\nclusters: []\n").unwrap();
        let api = MemoryClusterApi::new();
        api.apply_server_side(
            Path::new("/unused"),
            "lab",
            FIELD_MANAGER,
            &json!({
                "kind": "Deployment",
                "metadata": {
                    "name": "web",
                    "labels": {"tenkai.product": "api"}
                },
                "spec": {"replicas": 1}
            }),
        )
        .unwrap();
        api.set_rollout(
            "lab",
            "web",
            "Deployment",
            WorkloadRollout {
                desired_replicas: Some(1),
                ready_replicas: Some(0),
                updated_replicas: Some(1),
                current_revision: Some("1".into()),
                ..WorkloadRollout::default()
            },
        );
        let pod: Pod = serde_json::from_value(json!({
            "metadata": {"name": "web-1"},
            "status": {
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": "False"}],
                "containerStatuses": [{
                    "name": "app",
                    "ready": false,
                    "restartCount": 4,
                    "state": {
                        "waiting": {
                            "reason": "CrashLoopBackOff",
                            "message": "back-off 40s restarting failed container=app pod=web-1"
                        }
                    },
                    "lastState": {
                        "terminated": {
                            "exitCode": 1,
                            "reason": "Error",
                            "message": "host not found in upstream \"api\""
                        }
                    }
                }]
            }
        }))
        .unwrap();
        api.set_evidence(
            "lab",
            "web",
            "Deployment",
            WorkloadEvidence {
                workload: json!({"kind": "Deployment"}),
                pods: vec![pod],
                pods_unavailable: None,
            },
        );
        api.set_events(
            "lab",
            "web",
            "Deployment",
            vec![
                ("BackOff".into(), 6),
                ("Unhealthy".into(), 2),
                ("host not found in upstream".into(), 1),
            ],
        );
        let executor = InProcessKubernetesExecutor::new(&api);
        let workloads = executor.support_workloads("lab", &kubeconfig).unwrap();
        assert_eq!(workloads.len(), 1);
        let workload = &workloads[0];
        assert_eq!(workload.kind, "Deployment");
        assert_eq!(workload.name, "web");
        assert_eq!(workload.desired, Some(1));
        assert_eq!(workload.ready, Some(0));
        assert_eq!(workload.pods.len(), 1);
        assert_eq!(workload.pods[0].restarts, 4);
        assert_eq!(
            workload.pods[0].waiting_reason.as_deref(),
            Some("CrashLoopBackOff")
        );
        assert_eq!(workload.pods[0].last_reason.as_deref(), Some("Error"));
        assert_eq!(workload.pods[0].last_exit_code, Some(1));
        assert_eq!(
            workload.events,
            vec![
                tenkai::support_bundle::SupportEventCount {
                    reason: "BackOff".into(),
                    count: 6,
                },
                tenkai::support_bundle::SupportEventCount {
                    reason: "Unhealthy".into(),
                    count: 2,
                },
            ]
        );
        let rendered = serde_json::to_string(workload).unwrap();
        assert!(
            !rendered.contains("host not found"),
            "message leaked: {rendered}"
        );
        assert!(!rendered.contains("back-off"), "message leaked: {rendered}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn live_kind_lists_unreadable_when_empty_after_a_failed_kind() {
        assert!(live_kind_lists_unreadable(0, false, false));
        assert!(live_kind_lists_unreadable(0, true, true));
        assert!(!live_kind_lists_unreadable(0, true, false));
        assert!(!live_kind_lists_unreadable(2, true, true));
    }

    #[test]
    fn support_event_counts_match_workload_and_pods_and_drop_messages() {
        use k8s_openapi::api::core::v1::{Event, ObjectReference};
        let event = |kind: &str, name: &str, reason: &str, count: i32| Event {
            involved_object: ObjectReference {
                kind: Some(kind.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            reason: Some(reason.into()),
            count: Some(count),
            message: Some("host not found in upstream".into()),
            ..Default::default()
        };
        let counts = support_event_counts(
            &[
                event("Deployment", "web", "BackOff", 6),
                event("Pod", "web-1", "Unhealthy", 2),
                event("Pod", "other", "BackOff", 9),
                event("Deployment", "web", "host not found", 1),
            ],
            "Deployment",
            "web",
            &["web-1".into()],
        );
        assert_eq!(counts, vec![("BackOff".into(), 6), ("Unhealthy".into(), 2)]);
    }

    #[test]
    fn support_workload_reports_omitted_replica_zeros() {
        use serde_json::json;
        let rollout = rollout_from_value(
            "Deployment",
            &json!({
                "kind": "Deployment",
                "spec": {"replicas": 1},
                "status": {}
            }),
        );
        let workload = support_workload(
            "lab",
            "Deployment",
            "web",
            &rollout,
            &WorkloadEvidence {
                workload: json!({}),
                pods: Vec::new(),
                pods_unavailable: None,
            },
            &[],
        );
        assert_eq!(workload.desired, Some(1));
        assert_eq!(workload.ready, Some(0));
        assert_eq!(workload.updated, Some(0));
        let rendered = serde_json::to_string(&workload).unwrap();
        assert!(rendered.contains("\"ready\":0"), "{rendered}");
        assert!(rendered.contains("\"updated\":0"), "{rendered}");
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
    fn incomplete_deployment_rollout_is_named_and_fails_closed() {
        let root =
            std::env::temp_dir().join(format!("tenkai-ssa-norollout-{}", std::process::id()));
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
        api.set_conditions("lab", "edge", "Deployment", healthy_deployment_conditions());
        api.set_rollout(
            "lab",
            "edge",
            "Deployment",
            WorkloadRollout {
                generation: Some(2),
                observed_generation: Some(2),
                desired_replicas: Some(1),
                replicas: Some(1),
                updated_replicas: Some(0),
                ready_replicas: Some(1),
                available_replicas: Some(1),
                ..WorkloadRollout::default()
            },
        );
        let executor = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_millis(30))
            .with_poll_interval(Duration::from_millis(10));
        let err = executor
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("0/1 updated"), "{err}");
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
        diagnosed: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
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
                diagnosed: Mutex::new(None),
                released: None,
            }
        }

        fn notify_on_diagnosis(self, tx: std::sync::mpsc::SyncSender<()>) -> Self {
            *self.diagnosed.lock().expect("diagnosed") = Some(tx);
            self
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
                diagnosed: Mutex::new(None),
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
            self.inner.set_rollout(
                namespace,
                &observed.name,
                &observed.kind,
                incomplete_rollout_status(&observed.kind, object),
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
                self.inner
                    .complete_stored_rollout(&ns, &stored_name, &stored_kind);
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
            let evidence = self
                .inner
                .workload_evidence(cluster_config, namespace, name, kind)?;
            if let Some(tx) = self.diagnosed.lock().expect("diagnosed").take() {
                let _ = tx.send(());
            }
            Ok(evidence)
        }

        fn workload_rollout(
            &self,
            cluster_config: &Path,
            namespace: &str,
            name: &str,
            kind: &str,
        ) -> Result<Option<WorkloadRollout>> {
            self.inner
                .workload_rollout(cluster_config, namespace, name, kind)
        }

        fn observe_with_rollout(
            &self,
            cluster_config: &Path,
            namespace: &str,
            name: &str,
            kind: &str,
        ) -> Result<Option<(WorkloadObservation, Option<WorkloadRollout>)>> {
            // Apply the same delayed-ready mutation as `observe`, then read
            // observation and rollout from one stored snapshot.
            let _ = self.observe(cluster_config, namespace, name, kind)?;
            self.inner
                .observe_with_rollout(cluster_config, namespace, name, kind)
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
                pods_unavailable: None,
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
    fn label_selectors_keep_match_expressions() {
        let selector = serde_json::json!({
            "matchLabels": {"app": "edge"},
            "matchExpressions": [
                {"key": "tier", "operator": "In", "values": ["web", "api"]},
                {"key": "canary", "operator": "DoesNotExist"},
            ],
        });
        assert_eq!(
            label_selector_query(&selector).as_deref(),
            Some("app=edge,tier in (web,api),!canary")
        );
        assert_eq!(label_selector_query(&serde_json::json!({})), None);
        assert_eq!(
            label_selector_query(&serde_json::json!({"matchExpressions": [
                {"key": "tier", "operator": "Unknown"},
            ]})),
            None
        );
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
                pods_unavailable: None,
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

    #[test]
    fn a_lost_lease_names_the_last_cause_seen() {
        let root = unique_root("stop-cause");
        let _ = std::fs::remove_dir_all(&root);
        let kubeconfig = write_deployment(&root, "1.0.0", 1);
        let (api, _released, _entered) = DelayedReadyApi::gated();
        api.inner.set_evidence(
            "lab",
            "edge",
            "Deployment",
            WorkloadEvidence {
                workload: serde_json::json!({"kind": "Deployment", "metadata": {"name": "edge"}}),
                pods: serde_json::from_value(serde_json::json!([{
                    "metadata": {"name": "edge-7c9f-x2"},
                    "status": {"conditions": [{"type": "PodScheduled", "status": "False",
                        "reason": "Unschedulable", "message": "0/1 nodes are available"}]},
                }]))
                .unwrap(),
                pods_unavailable: None,
            },
        );
        let (diagnosed_tx, diagnosed_rx) = std::sync::mpsc::sync_channel(1);
        let api = api.notify_on_diagnosis(diagnosed_tx);
        let executor = InProcessKubernetesExecutor::new(api)
            .with_timeout(Duration::from_secs(60))
            .with_poll_interval(Duration::from_millis(10));
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let waiting = std::thread::spawn({
            let stop = stop.clone();
            let req = request(&root, &kubeconfig, "1.0.0");
            move || executor.apply_until_stopped(&req, &stop)
        });
        diagnosed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("wait diagnosed the stall");
        let stopped = Instant::now();
        stop.store(true, Ordering::SeqCst);
        let err = waiting.join().unwrap().unwrap_err().to_string();
        assert!(
            stopped.elapsed() < Duration::from_secs(2),
            "{:?}",
            stopped.elapsed()
        );
        assert!(err.contains("the apply lease was lost"), "{err}");
        assert!(
            err.contains(
                "cause: pod edge-7c9f-x2 is pending: Unschedulable: 0/1 nodes are available"
            ),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn write_workload(root: &Path, kind: &str, name: &str) -> PathBuf {
        let manifests = root.join("manifests");
        std::fs::create_dir_all(&manifests).unwrap();
        std::fs::write(
            manifests.join("workload.yaml"),
            format!("apiVersion: apps/v1\nkind: {kind}\nmetadata:\n  name: {name}\nspec:\n  replicas: 1\n"),
        )
        .unwrap();
        let kubeconfig = root.join("kubeconfig");
        std::fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\nclusters: []\n").unwrap();
        kubeconfig
    }

    fn crash_loop_pods() -> serde_json::Value {
        serde_json::json!([{
            "metadata": {"name": "edge-7c9f-x2"},
            "status": {"containerStatuses": [{
                "name": "nginx",
                "restartCount": 4,
                "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                "lastState": {"terminated": {"exitCode": 1,
                    "message": "host not found in upstream \"api\""}},
            }]},
        }])
    }

    #[test]
    fn an_upgrade_to_a_crash_loop_fails_while_old_pods_keep_available() {
        let root_a = unique_root("upgrade-a");
        let root_b = unique_root("upgrade-b");
        let kube_a = write_deployment(&root_a, "1.0.0", 1);
        let kube_b = write_deployment(&root_b, "2.0.0", 1);
        let api = MemoryClusterApi::new();
        let executor = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_secs(60))
            .with_poll_interval(Duration::from_millis(10));
        executor
            .apply(&request(&root_a, &kube_a, "1.0.0"))
            .expect("first revision is Available");
        api.set_conditions("lab", "edge", "Deployment", healthy_deployment_conditions());
        api.set_rollout(
            "lab",
            "edge",
            "Deployment",
            WorkloadRollout {
                generation: Some(2),
                observed_generation: Some(2),
                desired_replicas: Some(1),
                replicas: Some(1),
                updated_replicas: Some(0),
                ready_replicas: Some(1),
                available_replicas: Some(1),
                ..WorkloadRollout::default()
            },
        );
        api.set_evidence(
            "lab",
            "edge",
            "Deployment",
            WorkloadEvidence {
                workload: serde_json::json!({"kind": "Deployment", "metadata": {"name": "edge"}}),
                pods: serde_json::from_value(crash_loop_pods()).unwrap(),
                pods_unavailable: None,
            },
        );
        let started = Instant::now();
        let err = executor
            .apply(&request(&root_b, &kube_b, "2.0.0"))
            .unwrap_err()
            .to_string();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "upgrade stall waited {:?}",
            started.elapsed()
        );
        assert!(
            err.contains("CrashLoopBackOff"),
            "upgrade must fail on the new revision, not succeed because old pods kept Available: {err}"
        );
        let _ = std::fs::remove_dir_all(root_a);
        let _ = std::fs::remove_dir_all(root_b);
    }

    #[test]
    fn missing_rollout_data_is_not_success() {
        let observation = WorkloadObservation {
            kind: "Deployment".into(),
            name: "edge".into(),
            field_manager: FIELD_MANAGER.into(),
            version_label: Some("2.0.0".into()),
            conditions: healthy_deployment_conditions(),
        };
        let err =
            disagreeing_condition(&observation, None).expect("missing rollout is not success");
        assert!(err.contains("rollout status is unavailable"), "{err}");
    }

    #[test]
    fn a_scale_to_zero_deployment_completes_when_status_omits_zero_counts() {
        let observation = WorkloadObservation {
            kind: "Deployment".into(),
            name: "edge".into(),
            field_manager: FIELD_MANAGER.into(),
            version_label: Some("2.0.0".into()),
            conditions: healthy_deployment_conditions(),
        };
        let rollout = WorkloadRollout {
            generation: Some(2),
            observed_generation: Some(2),
            desired_replicas: Some(0),
            replicas: None,
            updated_replicas: None,
            ready_replicas: None,
            available_replicas: None,
            ..WorkloadRollout::default()
        };
        assert_eq!(disagreeing_condition(&observation, Some(&rollout)), None);
    }

    #[test]
    fn omitted_replica_counts_wait_until_the_generation_is_observed() {
        let observation = WorkloadObservation {
            kind: "Deployment".into(),
            name: "edge".into(),
            field_manager: FIELD_MANAGER.into(),
            version_label: Some("2.0.0".into()),
            conditions: healthy_deployment_conditions(),
        };
        let rollout = WorkloadRollout {
            generation: Some(2),
            observed_generation: Some(1),
            desired_replicas: Some(0),
            ..WorkloadRollout::default()
        };
        let err = disagreeing_condition(&observation, Some(&rollout))
            .expect("unobserved generation is not success");
        assert!(err.contains("observedGeneration"), "{err}");
    }

    #[test]
    fn old_replicas_keeping_available_is_not_rollout_success() {
        let observation = WorkloadObservation {
            kind: "Deployment".into(),
            name: "edge".into(),
            field_manager: FIELD_MANAGER.into(),
            version_label: Some("2.0.0".into()),
            conditions: healthy_deployment_conditions(),
        };
        let rollout = WorkloadRollout {
            generation: Some(2),
            observed_generation: Some(2),
            desired_replicas: Some(1),
            replicas: Some(1),
            updated_replicas: Some(0),
            ready_replicas: Some(1),
            available_replicas: Some(1),
            ..WorkloadRollout::default()
        };
        let err = disagreeing_condition(&observation, Some(&rollout))
            .expect("old replicas are not success");
        assert!(err.contains("0/1 updated"), "{err}");
    }

    #[test]
    fn statefulset_waits_for_matching_revisions_and_ready_replicas() {
        let root = unique_root("sts-wait");
        let kubeconfig = write_workload(&root, "StatefulSet", "db");
        let api = DelayedReadyApi::new(Duration::from_millis(40));
        InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_secs(5))
            .with_poll_interval(Duration::from_millis(10))
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .expect("StatefulSet rollout is waited on");
        let rollout = api
            .inner
            .workload_rollout(Path::new("/unused"), "lab", "db", "StatefulSet")
            .unwrap()
            .expect("StatefulSet rollout is recorded");
        assert_eq!(rollout.current_revision.as_deref(), Some("complete"));
        assert_eq!(rollout.update_revision.as_deref(), Some("complete"));
        assert_eq!(rollout.ready_replicas, Some(1));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn statefulset_mismatched_revisions_fail_closed() {
        let root = unique_root("sts-fail");
        let kubeconfig = write_workload(&root, "StatefulSet", "db");
        let api = MemoryClusterApi::new();
        api.apply_server_side(
            Path::new("/unused"),
            "lab",
            FIELD_MANAGER,
            &serde_json::json!({"kind":"StatefulSet","metadata":{"name":"db","labels":{}}}),
        )
        .unwrap();
        api.set_rollout(
            "lab",
            "db",
            "StatefulSet",
            WorkloadRollout {
                generation: Some(1),
                observed_generation: Some(1),
                desired_replicas: Some(1),
                ready_replicas: Some(0),
                current_revision: Some("db-1".into()),
                update_revision: Some("db-2".into()),
                ..WorkloadRollout::default()
            },
        );
        let err = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_millis(30))
            .with_poll_interval(Duration::from_millis(10))
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("currentRevision"), "{err}");
        assert!(err.contains("updateRevision"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn daemonset_waits_for_updated_and_available_pods() {
        let root = unique_root("ds-wait");
        let kubeconfig = write_workload(&root, "DaemonSet", "agent");
        let api = DelayedReadyApi::new(Duration::from_millis(40));
        InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_secs(5))
            .with_poll_interval(Duration::from_millis(10))
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .expect("DaemonSet rollout is waited on");
        let rollout = api
            .inner
            .workload_rollout(Path::new("/unused"), "lab", "agent", "DaemonSet")
            .unwrap()
            .expect("DaemonSet rollout is recorded");
        assert_eq!(rollout.updated_number_scheduled, Some(1));
        assert_eq!(rollout.number_available, Some(1));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn daemonset_without_updated_pods_fails_closed() {
        let root = unique_root("ds-fail");
        let kubeconfig = write_workload(&root, "DaemonSet", "agent");
        let api = MemoryClusterApi::new();
        api.apply_server_side(
            Path::new("/unused"),
            "lab",
            FIELD_MANAGER,
            &serde_json::json!({"kind":"DaemonSet","metadata":{"name":"agent","labels":{}}}),
        )
        .unwrap();
        api.set_rollout(
            "lab",
            "agent",
            "DaemonSet",
            WorkloadRollout {
                generation: Some(1),
                observed_generation: Some(1),
                desired_number_scheduled: Some(2),
                updated_number_scheduled: Some(1),
                number_available: Some(1),
                ..WorkloadRollout::default()
            },
        );
        let err = InProcessKubernetesExecutor::new(&api)
            .with_timeout(Duration::from_millis(30))
            .with_poll_interval(Duration::from_millis(10))
            .apply(&request(&root, &kubeconfig, "1.0.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("1/2 updated"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn statefulset_and_daemonset_do_not_require_available() {
        let sts = WorkloadObservation {
            kind: "StatefulSet".into(),
            name: "db".into(),
            field_manager: FIELD_MANAGER.into(),
            version_label: Some("1.0.0".into()),
            conditions: Vec::new(),
        };
        let sts_rollout = WorkloadRollout {
            generation: Some(1),
            observed_generation: Some(1),
            desired_replicas: Some(1),
            ready_replicas: Some(1),
            current_revision: Some("db-1".into()),
            update_revision: Some("db-1".into()),
            ..WorkloadRollout::default()
        };
        assert_eq!(disagreeing_condition(&sts, Some(&sts_rollout)), None);
        let ds = WorkloadObservation {
            kind: "DaemonSet".into(),
            name: "agent".into(),
            field_manager: FIELD_MANAGER.into(),
            version_label: Some("1.0.0".into()),
            conditions: Vec::new(),
        };
        let ds_rollout = WorkloadRollout {
            generation: Some(1),
            observed_generation: Some(1),
            desired_number_scheduled: Some(1),
            updated_number_scheduled: Some(1),
            number_available: Some(1),
            ..WorkloadRollout::default()
        };
        assert_eq!(disagreeing_condition(&ds, Some(&ds_rollout)), None);
    }
}
