//! Live worker-lifecycle observation port (ADR 0028).
//!
//! Tenkai authorizes drain and replacement from generation-bound live
//! observations. Process lifetime stays with the selected executor adapter.
//! Retained snapshots cannot grant process-change authority.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result, bail};

use super::{
    INTAKE_PLANE, LIFECYCLE_PROTOCOL, LIFECYCLE_SCHEMA_VERSION, WorkerLifecycleSnapshot,
    WorkerPoolDecision, WorkerPoolObservation, WorkerPoolSpec, observation, pool_is_converged,
    ready_snapshot, reconcile, validate_snapshot,
};

pub const LIVE_OBSERVATION_MIN_TTL_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleObservationSource {
    Live,
    Retained,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LiveWorkerObservation {
    pub snapshot: WorkerLifecycleSnapshot,
    pub observed_at_ms: i64,
    pub fencing_generation: u64,
    pub source: LifecycleObservationSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerLifecycleScope {
    pub product: String,
    pub version: String,
    pub environment: String,
    pub expected_generation: u64,
    pub worker_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerReplicaRequest {
    pub scope: WorkerLifecycleScope,
    pub worker_id: String,
    pub version: String,
}

/// Versioned live observation and executor-owned process lifetime.
pub trait WorkerLifecyclePort: Send + Sync {
    fn observe(&self, request: &WorkerLifecycleScope) -> Result<Vec<LiveWorkerObservation>>;
    fn request_drain(&self, request: &WorkerLifecycleScope) -> Result<()>;
    fn start_replica(&self, request: &WorkerReplicaRequest) -> Result<LiveWorkerObservation>;
    fn stop_replica(&self, request: &WorkerReplicaRequest) -> Result<()>;
    /// Bind live processes to the current execution fence after a liveness check.
    fn bind_fence(&self, request: &WorkerLifecycleScope) -> Result<()> {
        let _ = request;
        Ok(())
    }
}

pub fn replica_slots(replicas: u32) -> Vec<String> {
    (1..=replicas).map(|slot| format!("w{slot}")).collect()
}

pub fn live_ttl_ms(spec: &WorkerPoolSpec) -> u64 {
    spec.drain_timeout_ms.max(LIVE_OBSERVATION_MIN_TTL_MS)
}

pub fn authorize_observations(
    spec: &WorkerPoolSpec,
    observations: &[LiveWorkerObservation],
    expected_generation: u64,
    now_ms: i64,
) -> Result<Vec<WorkerLifecycleSnapshot>> {
    let max_age = live_ttl_ms(spec);
    let mut snapshots = Vec::with_capacity(observations.len());
    for observation in observations {
        if observation.source != LifecycleObservationSource::Live {
            bail!("retained snapshots cannot authorize live worker-pool admission");
        }
        if observation.fencing_generation != expected_generation {
            bail!(
                "stale fencing generation {} cannot authorize replacement; expected {expected_generation}",
                observation.fencing_generation
            );
        }
        if observation.observed_at_ms > now_ms {
            // Heartbeats published during observe are still live evidence.
        } else if now_ms.saturating_sub(observation.observed_at_ms) as u64 > max_age {
            bail!("stale worker-lifecycle observation cannot authorize replacement completion");
        }
        validate_snapshot(&observation.snapshot, spec)?;
        snapshots.push(observation.snapshot.clone());
    }
    Ok(snapshots)
}

pub fn retained_observation(
    snapshot: WorkerLifecycleSnapshot,
    fencing_generation: u64,
    observed_at_ms: i64,
) -> LiveWorkerObservation {
    LiveWorkerObservation {
        snapshot,
        observed_at_ms,
        fencing_generation,
        source: LifecycleObservationSource::Retained,
    }
}

fn workers_are_busy(snapshots: &[WorkerLifecycleSnapshot]) -> bool {
    snapshots
        .iter()
        .any(|snapshot| snapshot.active_claims > 0 || snapshot.state == "active")
}

fn governance_blocks_mutation(decision: &WorkerPoolDecision) -> bool {
    matches!(
        decision,
        WorkerPoolDecision::Degraded { reason }
            if reason.contains("governance") || reason.contains("plane outage")
    )
}

fn drain_timed_out(decision: &WorkerPoolDecision) -> bool {
    matches!(
        decision,
        WorkerPoolDecision::Degraded { reason } if reason.contains("drain timed out")
    )
}

pub fn persist_observation_source(
    properties: &mut std::collections::HashMap<String, String>,
    product: &str,
    source: LifecycleObservationSource,
) {
    let label = match source {
        LifecycleObservationSource::Live => "live",
        LifecycleObservationSource::Retained => "retained",
    };
    properties.insert(
        format!("worker_pool.{product}.observation_source"),
        label.into(),
    );
}

pub struct LivePoolAdmission<'a> {
    pub spec: &'a WorkerPoolSpec,
    pub port: &'a dyn WorkerLifecyclePort,
    pub environment: &'a str,
    pub expected_generation: u64,
    pub previous_replicas: u32,
    pub drain_started_at_ms: Option<i64>,
    pub now_ms: i64,
    pub restart: bool,
}

/// Observe, authorize, drain, and align replicas through a live port.
pub fn admit_live_pool(
    request: LivePoolAdmission<'_>,
) -> Result<(
    WorkerPoolDecision,
    WorkerPoolObservation,
    Option<i64>,
    LifecycleObservationSource,
)> {
    let LivePoolAdmission {
        spec,
        port,
        environment,
        expected_generation,
        previous_replicas,
        drain_started_at_ms,
        now_ms,
        restart,
    } = request;
    let scope = WorkerLifecycleScope {
        product: spec.product.clone(),
        version: spec.version.clone(),
        environment: environment.to_string(),
        expected_generation,
        worker_id: None,
    };
    port.bind_fence(&scope)?;
    let live = port.observe(&scope)?;
    let snapshots = authorize_observations(spec, &live, expected_generation, now_ms)?;
    let decision = reconcile(
        spec,
        &snapshots,
        previous_replicas,
        drain_started_at_ms,
        now_ms,
    )?;
    if matches!(decision, WorkerPoolDecision::Deny { .. })
        || drain_timed_out(&decision)
        || governance_blocks_mutation(&decision)
    {
        return Ok((
            decision.clone(),
            observation(spec, &snapshots, &decision),
            None,
            LifecycleObservationSource::Live,
        ));
    }
    if restart && workers_are_busy(&snapshots) {
        if let Some(started) = drain_started_at_ms
            && now_ms.saturating_sub(started) as u64 >= spec.drain_timeout_ms
        {
            let timed_out = WorkerPoolDecision::Degraded {
                reason: "drain timed out; pool stays degraded and active work is not acknowledged"
                    .into(),
            };
            return Ok((
                timed_out.clone(),
                observation(spec, &snapshots, &timed_out),
                None,
                LifecycleObservationSource::Live,
            ));
        }
        request_drains(port, &scope, &snapshots)?;
        let wait = WorkerPoolDecision::WaitDrain;
        return Ok((
            wait.clone(),
            observation(spec, &snapshots, &wait),
            Some(drain_started_at_ms.unwrap_or(now_ms)),
            LifecycleObservationSource::Live,
        ));
    }
    if matches!(decision, WorkerPoolDecision::WaitDrain) {
        let removing = workers_to_remove(spec, &snapshots, restart);
        request_drains(port, &scope, &removing)?;
        return Ok((
            decision.clone(),
            observation(spec, &snapshots, &decision),
            Some(drain_started_at_ms.unwrap_or(now_ms)),
            LifecycleObservationSource::Live,
        ));
    }
    if may_align(&decision, spec, &snapshots, restart) {
        if align_replicas(port, spec, &scope, &snapshots, restart)? {
            let wait = WorkerPoolDecision::WaitDrain;
            return Ok((
                wait.clone(),
                observation(spec, &snapshots, &wait),
                Some(drain_started_at_ms.unwrap_or(now_ms)),
                LifecycleObservationSource::Live,
            ));
        }
        let live = port.observe(&scope)?;
        let snapshots =
            authorize_observations(spec, &live, expected_generation, crate::now_millis())?;
        let decision = reconcile(
            spec,
            &snapshots,
            previous_replicas.max(spec.replicas),
            None,
            crate::now_millis(),
        )?;
        return Ok((
            decision.clone(),
            observation(spec, &snapshots, &decision),
            None,
            LifecycleObservationSource::Live,
        ));
    }
    Ok((
        decision.clone(),
        observation(spec, &snapshots, &decision),
        if matches!(decision, WorkerPoolDecision::WaitDrain) {
            Some(drain_started_at_ms.unwrap_or(now_ms))
        } else {
            None
        },
        LifecycleObservationSource::Live,
    ))
}

fn may_align(
    decision: &WorkerPoolDecision,
    spec: &WorkerPoolSpec,
    snapshots: &[WorkerLifecycleSnapshot],
    restart: bool,
) -> bool {
    if restart && !workers_are_busy(snapshots) {
        return true;
    }
    if pool_is_converged(spec, snapshots) {
        return false;
    }
    match decision {
        WorkerPoolDecision::Apply { .. } => true,
        WorkerPoolDecision::Degraded { reason } if reason.contains("desired replica count") => true,
        _ => false,
    }
}

fn workers_to_remove(
    spec: &WorkerPoolSpec,
    observed: &[WorkerLifecycleSnapshot],
    restart: bool,
) -> Vec<WorkerLifecycleSnapshot> {
    if restart {
        return observed.to_vec();
    }
    let desired = replica_slots(spec.replicas);
    observed
        .iter()
        .filter(|snapshot| {
            !(desired.iter().any(|slot| slot == &snapshot.worker_id)
                && snapshot.version == spec.version)
        })
        .cloned()
        .collect()
}

fn request_drains(
    port: &dyn WorkerLifecyclePort,
    scope: &WorkerLifecycleScope,
    snapshots: &[WorkerLifecycleSnapshot],
) -> Result<()> {
    for snapshot in snapshots {
        let mut drain = scope.clone();
        drain.worker_id = Some(snapshot.worker_id.clone());
        port.request_drain(&drain)?;
    }
    Ok(())
}

fn align_replicas(
    port: &dyn WorkerLifecyclePort,
    spec: &WorkerPoolSpec,
    scope: &WorkerLifecycleScope,
    observed: &[WorkerLifecycleSnapshot],
    restart: bool,
) -> Result<bool> {
    let desired = replica_slots(spec.replicas);
    let stopping = workers_to_remove(spec, observed, restart);
    request_drains(port, scope, &stopping)?;
    let deadline = Instant::now() + Duration::from_millis(spec.drain_timeout_ms.min(500));
    let live = loop {
        let live = port.observe(scope)?;
        let blocked = stopping.iter().any(|snapshot| {
            live.iter().any(|observation| {
                observation.snapshot.worker_id == snapshot.worker_id
                    && (observation.snapshot.active_claims > 0
                        || observation.snapshot.state == "active"
                        || observation.snapshot.accepting_claims)
            })
        });
        if !blocked || Instant::now() >= deadline {
            break live;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    authorize_observations(spec, &live, scope.expected_generation, crate::now_millis())?;
    if live.iter().any(|observation| {
        observation.source != LifecycleObservationSource::Live
            || observation.snapshot.state == "fence_lost"
            || !observation.snapshot.fencing_ok
            || observation.snapshot.state == "unhealthy"
            || !observation.snapshot.governance_ok
            || observation.snapshot.state == "governance_unavailable"
    }) {
        bail!(
            "lost fencing, governance outage, or non-live observation cannot authorize replica stop"
        );
    }
    for snapshot in &stopping {
        let current = live
            .iter()
            .find(|observation| observation.snapshot.worker_id == snapshot.worker_id);
        if let Some(current) = current {
            if current.snapshot.active_claims > 0
                || current.snapshot.state == "active"
                || current.snapshot.accepting_claims
            {
                return Ok(true);
            }
            port.stop_replica(&WorkerReplicaRequest {
                scope: scope.clone(),
                worker_id: snapshot.worker_id.clone(),
                version: snapshot.version.clone(),
            })?;
        }
    }
    let live = port.observe(scope)?;
    authorize_observations(spec, &live, scope.expected_generation, crate::now_millis())?;
    let present: Vec<String> = live
        .iter()
        .filter(|observation| {
            observation.snapshot.version == spec.version
                && observation.snapshot.product == spec.product
        })
        .map(|observation| observation.snapshot.worker_id.clone())
        .collect();
    for worker_id in desired {
        if present.iter().any(|id| id == &worker_id) {
            continue;
        }
        port.start_replica(&WorkerReplicaRequest {
            scope: scope.clone(),
            worker_id,
            version: spec.version.clone(),
        })?;
    }
    Ok(false)
}

#[derive(Default)]
struct FakeInner {
    stale_generation: Option<u64>,
    workers: BTreeMap<String, WorkerLifecycleSnapshot>,
    drain_requested: Vec<String>,
    instant_drain: bool,
    governance_outage_on_drain: bool,
    observed_at_ms: Option<i64>,
}

/// Deterministic in-memory live port for unit tests.
pub struct FakeWorkerLifecycle {
    inner: Mutex<FakeInner>,
}

impl Default for FakeWorkerLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeWorkerLifecycle {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(FakeInner::default()),
        }
    }

    pub fn seed(&self, snapshot: WorkerLifecycleSnapshot) {
        let mut inner = self.inner.lock().expect("fake worker mutex");
        inner.workers.insert(snapshot.worker_id.clone(), snapshot);
    }

    pub fn set_instant_drain(&self, instant: bool) {
        self.inner.lock().expect("fake worker mutex").instant_drain = instant;
    }

    pub fn set_observed_at_ms(&self, now_ms: i64) {
        self.inner.lock().expect("fake worker mutex").observed_at_ms = Some(now_ms);
    }

    pub fn set_stale_generation(&self, generation: u64) {
        self.inner
            .lock()
            .expect("fake worker mutex")
            .stale_generation = Some(generation);
    }

    pub fn set_governance_outage_on_drain(&self, outage: bool) {
        self.inner
            .lock()
            .expect("fake worker mutex")
            .governance_outage_on_drain = outage;
    }

    pub fn drain_requested(&self) -> Vec<String> {
        self.inner
            .lock()
            .expect("fake worker mutex")
            .drain_requested
            .clone()
    }
}

impl WorkerLifecyclePort for FakeWorkerLifecycle {
    fn observe(&self, request: &WorkerLifecycleScope) -> Result<Vec<LiveWorkerObservation>> {
        let inner = self.inner.lock().expect("fake worker mutex");
        Ok(inner
            .workers
            .values()
            .filter(|snapshot| snapshot.product == request.product)
            .map(|snapshot| LiveWorkerObservation {
                snapshot: snapshot.clone(),
                observed_at_ms: inner.observed_at_ms.unwrap_or_else(crate::now_millis),
                fencing_generation: inner
                    .stale_generation
                    .unwrap_or(request.expected_generation),
                source: LifecycleObservationSource::Live,
            })
            .collect())
    }

    fn request_drain(&self, request: &WorkerLifecycleScope) -> Result<()> {
        let mut inner = self.inner.lock().expect("fake worker mutex");
        let worker_id = request
            .worker_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("drain request requires a worker_id"))?;
        inner.drain_requested.push(worker_id.clone());
        let instant = inner.instant_drain;
        let governance_outage = inner.governance_outage_on_drain;
        let Some(snapshot) = inner.workers.get_mut(&worker_id) else {
            bail!("cannot drain unknown worker {worker_id}");
        };
        snapshot.state = "draining".into();
        snapshot.accepting_claims = false;
        if instant {
            snapshot.active_claims = 0;
            snapshot.active_runs = 0;
            snapshot.state = "ready".into();
        }
        if governance_outage {
            snapshot.governance_ok = false;
            snapshot.state = "governance_unavailable".into();
            snapshot.accepting_claims = false;
            snapshot.active_claims = 0;
            snapshot.active_runs = 0;
        }
        Ok(())
    }

    fn start_replica(&self, request: &WorkerReplicaRequest) -> Result<LiveWorkerObservation> {
        let spec = WorkerPoolSpec {
            product: request.scope.product.clone(),
            version: request.version.clone(),
            intake: INTAKE_PLANE.into(),
            replicas: 1,
            drain_timeout_ms: 1_000,
        };
        let snapshot = ready_snapshot(&spec, &request.worker_id);
        let mut inner = self.inner.lock().expect("fake worker mutex");
        inner
            .workers
            .insert(request.worker_id.clone(), snapshot.clone());
        Ok(LiveWorkerObservation {
            snapshot,
            observed_at_ms: inner.observed_at_ms.unwrap_or_else(crate::now_millis),
            fencing_generation: inner
                .stale_generation
                .unwrap_or(request.scope.expected_generation),
            source: LifecycleObservationSource::Live,
        })
    }

    fn stop_replica(&self, request: &WorkerReplicaRequest) -> Result<()> {
        let mut inner = self.inner.lock().expect("fake worker mutex");
        inner.workers.remove(&request.worker_id);
        Ok(())
    }
}

struct WorkerFiles {
    live: PathBuf,
    control: PathBuf,
    pid: PathBuf,
    generation: PathBuf,
    cookie: PathBuf,
    cookie_live: PathBuf,
}

/// Local fixture supervisor. Process lifetime stays in this adapter.
pub struct LocalProcessWorkerLifecycle {
    runtime_root: PathBuf,
    fixture_bin: PathBuf,
}

impl LocalProcessWorkerLifecycle {
    pub fn new(runtime_root: PathBuf, fixture_bin: PathBuf) -> Self {
        Self {
            runtime_root,
            fixture_bin,
        }
    }

    pub fn from_env() -> Result<Self> {
        let runtime_root = match std::env::var("TENKAI_WORKER_LIFECYCLE_ROOT") {
            Ok(path) => PathBuf::from(path),
            Err(_) => match std::env::var("TENKAI_STATE_DIR") {
                Ok(path) => PathBuf::from(path).join("worker-lifecycle"),
                Err(_) => PathBuf::from(".tenkai-state/worker-lifecycle"),
            },
        };
        let fixture_bin = match std::env::var("TENKAI_WORKER_LIFECYCLE_FIXTURE") {
            Ok(path) => PathBuf::from(path),
            Err(_) => discover_fixture_executable()?,
        };
        Ok(Self::new(runtime_root, fixture_bin))
    }

    fn worker_dir(&self, scope: &WorkerLifecycleScope) -> PathBuf {
        self.runtime_root
            .join(&scope.environment)
            .join(&scope.product)
    }

    fn paths(dir: &Path, worker_id: &str) -> WorkerFiles {
        WorkerFiles {
            live: dir.join(format!("{worker_id}.live.json")),
            control: dir.join(format!("{worker_id}.control")),
            pid: dir.join(format!("{worker_id}.pid")),
            generation: dir.join(format!("{worker_id}.generation")),
            cookie: dir.join(format!("{worker_id}.cookie")),
            cookie_live: dir.join(format!("{worker_id}.cookie.live")),
        }
    }

    fn read_live_file(
        &self,
        _scope: &WorkerLifecycleScope,
        worker_id: &str,
        live_path: &Path,
    ) -> Result<LiveWorkerObservation> {
        let raw = std::fs::read(live_path)
            .with_context(|| format!("reading live worker observation {}", live_path.display()))?;
        let snapshot: WorkerLifecycleSnapshot = serde_json::from_slice(&raw)?;
        if snapshot.worker_id != worker_id {
            bail!(
                "live observation worker {} does not match file {}",
                snapshot.worker_id,
                worker_id
            );
        }
        let fencing_generation = std::fs::read_to_string(
            Self::paths(
                live_path.parent().unwrap_or_else(|| Path::new(".")),
                worker_id,
            )
            .generation,
        )
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
        .ok_or_else(|| {
            anyhow::anyhow!("live worker {worker_id} has no recorded fencing generation")
        })?;
        Ok(LiveWorkerObservation {
            snapshot,
            observed_at_ms: file_observed_at_ms(live_path)?,
            fencing_generation,
            source: LifecycleObservationSource::Live,
        })
    }
}

impl WorkerLifecyclePort for LocalProcessWorkerLifecycle {
    fn observe(&self, request: &WorkerLifecycleScope) -> Result<Vec<LiveWorkerObservation>> {
        let dir = self.worker_dir(request);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut observations = Vec::new();
        let mut entries = std::fs::read_dir(&dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".live.json"))
            })
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            let worker_id = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".live.json"))
                .unwrap_or_default()
                .to_string();
            if let Some(expected) = request.worker_id.as_deref()
                && expected != worker_id
            {
                continue;
            }
            let files = Self::paths(&dir, &worker_id);
            if !process_identity_matches(&files) {
                continue;
            }
            observations.push(read_live_file_retry(self, request, &worker_id, &path)?);
        }
        Ok(observations)
    }

    fn request_drain(&self, request: &WorkerLifecycleScope) -> Result<()> {
        let worker_id = request
            .worker_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("drain request requires a worker_id"))?;
        let dir = self.worker_dir(request);
        let files = Self::paths(&dir, worker_id);
        std::fs::create_dir_all(&dir)?;
        require_generation(&files, request.expected_generation)?;
        std::fs::write(files.control, "drain\n")?;
        Ok(())
    }

    fn start_replica(&self, request: &WorkerReplicaRequest) -> Result<LiveWorkerObservation> {
        let dir = self.worker_dir(&request.scope);
        std::fs::create_dir_all(&dir)?;
        let files = Self::paths(&dir, &request.worker_id);
        if files.generation.exists() {
            require_generation(&files, request.scope.expected_generation)?;
        }
        let _ = std::fs::remove_file(&files.live);
        let _ = std::fs::remove_file(&files.control);
        let cookie = uuid::Uuid::new_v4().to_string();
        let mut command = Command::new(&self.fixture_bin);
        command
            .env("TENKAI_WORKER_FIXTURE_LIVE", &files.live)
            .env("TENKAI_WORKER_FIXTURE_CONTROL", &files.control)
            .env("TENKAI_WORKER_ID", &request.worker_id)
            .env("TENKAI_WORKER_PRODUCT", &request.scope.product)
            .env("TENKAI_WORKER_VERSION", &request.version)
            .env("TENKAI_WORKER_NAMESPACE", "default")
            .env("TENKAI_WORKER_RUNTIME_ID", "runtime-1")
            .env("TENKAI_WORKER_COOKIE", &cookie)
            .env("TENKAI_WORKER_COOKIE_LIVE", &files.cookie_live)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().with_context(|| {
            format!(
                "starting local worker fixture {}",
                self.fixture_bin.display()
            )
        })?;
        std::fs::write(&files.cookie, &cookie)?;
        std::fs::write(files.pid, child.id().to_string())?;
        std::fs::write(
            files.generation,
            request.scope.expected_generation.to_string(),
        )?;
        std::mem::forget(child);
        wait_for_path(&files.live, Duration::from_secs(2))?;
        wait_for_path(&files.cookie_live, Duration::from_secs(2))?;
        self.read_live_file(&request.scope, &request.worker_id, &files.live)
    }

    fn stop_replica(&self, request: &WorkerReplicaRequest) -> Result<()> {
        let dir = self.worker_dir(&request.scope);
        let files = Self::paths(&dir, &request.worker_id);
        if files.generation.exists() {
            require_generation(&files, request.scope.expected_generation)?;
        }
        let _ = std::fs::write(&files.control, "stop\n");
        if process_identity_matches(&files) {
            terminate_pidfile(&files.pid);
        }
        let _ = std::fs::remove_file(&files.live);
        let _ = std::fs::remove_file(&files.control);
        let _ = std::fs::remove_file(&files.pid);
        let _ = std::fs::remove_file(&files.generation);
        let _ = std::fs::remove_file(&files.cookie);
        let _ = std::fs::remove_file(&files.cookie_live);
        Ok(())
    }

    fn bind_fence(&self, request: &WorkerLifecycleScope) -> Result<()> {
        let dir = self.worker_dir(request);
        if !dir.exists() {
            return Ok(());
        }
        for path in std::fs::read_dir(&dir)?.filter_map(|entry| entry.ok()) {
            let name = path.file_name();
            let Some(worker_id) = name.to_str().and_then(|name| name.strip_suffix(".pid")) else {
                continue;
            };
            let files = Self::paths(&dir, worker_id);
            if !process_identity_matches(&files) {
                continue;
            }
            let recorded = std::fs::read_to_string(&files.generation)
                .ok()
                .and_then(|raw| raw.trim().parse::<u64>().ok());
            if let Some(current) = recorded
                && request.expected_generation < current
            {
                bail!(
                    "stale fencing generation {} cannot rebind live workers; current is {current}",
                    request.expected_generation
                );
            }
            std::fs::write(files.generation, request.expected_generation.to_string())?;
        }
        Ok(())
    }
}

fn discover_fixture_executable() -> Result<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.with_file_name("tenkai-worker-lifecycle-fixture");
        if candidate.exists() {
            return Ok(candidate);
        }
        if let Some(parent) = exe.parent() {
            let debug = parent
                .parent()
                .unwrap_or(parent)
                .join("tenkai-worker-lifecycle-fixture");
            if debug.exists() {
                return Ok(debug);
            }
        }
    }
    bail!("worker-lifecycle fixture executable not found; set TENKAI_WORKER_LIFECYCLE_FIXTURE");
}

fn file_observed_at_ms(path: &Path) -> Result<i64> {
    let modified = std::fs::metadata(path)?.modified()?;
    let elapsed = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    Ok(elapsed.as_millis() as i64)
}

fn read_live_file_retry(
    port: &LocalProcessWorkerLifecycle,
    request: &WorkerLifecycleScope,
    worker_id: &str,
    path: &Path,
) -> Result<LiveWorkerObservation> {
    let mut last = None;
    for _ in 0..20 {
        match port.read_live_file(request, worker_id, path) {
            Ok(observation) => return Ok(observation),
            Err(error) => {
                last = Some(error);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("live observation disappeared")))
}

fn process_identity_matches(files: &WorkerFiles) -> bool {
    if !process_is_alive(&files.pid) {
        return false;
    }
    let Ok(expected) = std::fs::read_to_string(&files.cookie) else {
        return false;
    };
    let Ok(observed) = std::fs::read_to_string(&files.cookie_live) else {
        return false;
    };
    expected.trim() == observed.trim()
        && !expected.trim().is_empty()
        && cookie_lock_is_held(&files.cookie_live)
}

fn require_generation(files: &WorkerFiles, expected: u64) -> Result<()> {
    let recorded = std::fs::read_to_string(&files.generation)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("worker has no recorded fencing generation"))?;
    if recorded != expected {
        bail!("stale fencing generation {expected} cannot mutate worker; current is {recorded}");
    }
    Ok(())
}

fn cookie_lock_is_held(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
        return false;
    };
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked == 0 {
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
        false
    } else {
        true
    }
}

fn process_is_alive(pid_path: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(pid_path) else {
        return false;
    };
    let Ok(pid) = raw.trim().parse::<i32>() else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    unsafe { libc::kill(pid, 0) == 0 }
}

fn terminate_pidfile(pid_path: &Path) {
    let Ok(raw) = std::fs::read_to_string(pid_path) else {
        return;
    };
    let Ok(pid) = raw.trim().parse::<i32>() else {
        return;
    };
    if pid <= 0 {
        return;
    }
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(200) && process_is_alive(pid_path) {
        std::thread::sleep(Duration::from_millis(20));
    }
    if process_is_alive(pid_path) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    bail!(
        "worker process did not publish a live observation at {}",
        path.display()
    );
}

pub fn selected_worker_lifecycle() -> Result<Option<Box<dyn WorkerLifecyclePort>>> {
    match std::env::var("TENKAI_WORKER_LIFECYCLE") {
        Err(_) => Ok(None),
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) if value == "local-process" => {
            Ok(Some(Box::new(LocalProcessWorkerLifecycle::from_env()?)))
        }
        Ok(value) => {
            bail!("unknown TENKAI_WORKER_LIFECYCLE {value:?}; supported value: local-process")
        }
    }
}

pub fn run_fixture_worker() -> Result<()> {
    let live = required_env("TENKAI_WORKER_FIXTURE_LIVE")?;
    let control = required_env("TENKAI_WORKER_FIXTURE_CONTROL")?;
    let cookie = required_env("TENKAI_WORKER_COOKIE")?;
    let cookie_live = required_env("TENKAI_WORKER_COOKIE_LIVE")?;
    if let Some(parent) = Path::new(&cookie_live).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let cookie_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&cookie_live)?;
    if unsafe { libc::flock(cookie_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("worker fixture could not lock its identity file");
    }
    use std::io::Write as _;
    let mut cookie_file = cookie_file;
    cookie_file.write_all(cookie.as_bytes())?;
    cookie_file.flush()?;
    let _cookie_lock = cookie_file;
    let worker_id = required_env("TENKAI_WORKER_ID")?;
    let product = required_env("TENKAI_WORKER_PRODUCT")?;
    let version = required_env("TENKAI_WORKER_VERSION")?;
    let namespace = std::env::var("TENKAI_WORKER_NAMESPACE").unwrap_or_else(|_| "default".into());
    let runtime_id =
        std::env::var("TENKAI_WORKER_RUNTIME_ID").unwrap_or_else(|_| "runtime-1".into());
    let mut snapshot = WorkerLifecycleSnapshot {
        schema_version: LIFECYCLE_SCHEMA_VERSION,
        protocol: LIFECYCLE_PROTOCOL.into(),
        product,
        version,
        worker_id,
        namespace,
        runtime_id,
        intake: INTAKE_PLANE.into(),
        state: "ready".into(),
        accepting_claims: true,
        active_claims: 0,
        active_runs: 0,
        configured_concurrency: 1,
        governance_ok: true,
        fencing_ok: true,
    };
    loop {
        if let Ok(command) = std::fs::read_to_string(&control) {
            if command.contains("stop") {
                return Ok(());
            }
            if command.contains("fence_lost") {
                snapshot.state = "fence_lost".into();
                snapshot.fencing_ok = false;
                snapshot.accepting_claims = false;
            } else if command.contains("busy") {
                snapshot.state = "active".into();
                snapshot.accepting_claims = true;
                snapshot.active_claims = 1;
                snapshot.active_runs = 1;
            } else if command.contains("drain") {
                snapshot.state = "draining".into();
                snapshot.accepting_claims = false;
                snapshot.active_claims = 0;
                snapshot.active_runs = 0;
            } else if command.contains("ready") {
                snapshot.state = "ready".into();
                snapshot.accepting_claims = true;
                snapshot.active_claims = 0;
                snapshot.active_runs = 0;
                snapshot.fencing_ok = true;
            }
        }
        if let Some(parent) = Path::new(&live).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = format!("{live}.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&snapshot)?)?;
        std::fs::rename(&tmp, &live)?;
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required for the worker fixture"))
}
