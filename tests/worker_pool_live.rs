//! Live local worker-process replacement (#336 / ADR 0028).
//!
//! Drives one fixture process from release A to B through the versioned
//! lifecycle port. The fixture never claims or schedules individual runs.

use std::path::PathBuf;

use tenkai::worker_pool::{
    LivePoolAdmission, LocalProcessWorkerLifecycle, WorkerLifecyclePort, WorkerLifecycleScope,
    WorkerPoolDecision, WorkerPoolSpec, WorkerReplicaRequest, admit_live_pool,
    authorize_observations, load_snapshots, ready_snapshot, retained_observation,
};

/// Temp root for one test, removed on drop even when the test panics. The
/// fixture exits once its worker directory is gone, so no process outlives
/// the test (#779).
struct TestRoot(PathBuf);

impl TestRoot {
    fn new(prefix: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const PRODUCT: &str = "edge-workers";
const ENV: &str = "local";

fn fixture_bin() -> PathBuf {
    workspace_bin("tenkai-worker-lifecycle-fixture")
}

fn workspace_bin(name: &str) -> PathBuf {
    let key = format!("CARGO_BIN_EXE_{name}");
    if let Ok(path) = std::env::var(&key) {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(deps) = exe.parent()
        && deps.file_name().is_some_and(|n| n == "deps")
        && let Some(profile_dir) = deps.parent()
    {
        let candidate = profile_dir.join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut dirs = Vec::new();
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        dirs.push(PathBuf::from(target_dir).join(profile).join(name));
    }
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..5 {
        dirs.push(dir.join("target").join(profile).join(name));
        if !dir.pop() {
            break;
        }
    }
    dirs.into_iter()
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("workspace binary {name} not found under target/{profile}"))
}

fn spec(version: &str) -> WorkerPoolSpec {
    WorkerPoolSpec {
        product: PRODUCT.into(),
        version: version.into(),
        intake: tenkai::worker_pool::INTAKE_PLANE.into(),
        replicas: 1,
        drain_timeout_ms: 1_000,
    }
}

fn scope(version: &str, generation: u64) -> WorkerLifecycleScope {
    WorkerLifecycleScope {
        product: PRODUCT.into(),
        version: version.into(),
        environment: ENV.into(),
        expected_generation: generation,
        worker_id: None,
    }
}

#[test]
fn live_process_replaces_release_a_with_b_and_recovers_from_retained_files() {
    let root = TestRoot::new("tenkai-worker-live");
    let port = LocalProcessWorkerLifecycle::new(root.0.join("runtime"), fixture_bin());

    port.start_replica(&WorkerReplicaRequest {
        scope: scope("1.0.0", 1),
        worker_id: "w1".into(),
        version: "1.0.0".into(),
    })
    .unwrap();
    let before = port.observe(&scope("1.0.0", 1)).unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].snapshot.version, "1.0.0");
    assert_eq!(before[0].snapshot.state, "ready");
    assert_eq!(before[0].snapshot.active_claims, 0);

    let desired = spec("2.0.0");
    let (decision, observed, drain, source) = admit_live_pool(LivePoolAdmission {
        spec: &desired,
        port: &port,
        environment: ENV,
        expected_generation: 1,
        previous_replicas: 1,
        drain_started_at_ms: None,
        now_ms: tenkai::now_millis(),
        restart: false,
    })
    .unwrap();
    assert_eq!(decision, WorkerPoolDecision::Apply { replicas: 1 });
    assert_eq!(observed.state, "healthy");
    assert!(!observed.degraded);
    assert!(drain.is_none());
    assert_eq!(
        source,
        tenkai::worker_pool::LifecycleObservationSource::Live
    );

    let after = port.observe(&scope("2.0.0", 1)).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].snapshot.version, "2.0.0");
    assert_eq!(after[0].snapshot.worker_id, "w1");
    assert_eq!(after[0].snapshot.active_claims, 0);
    assert_eq!(after[0].snapshot.active_runs, 0);

    let retained_dir = root.0.join("retained");
    std::fs::create_dir_all(&retained_dir).unwrap();
    std::fs::write(
        retained_dir.join("w1.json"),
        serde_json::to_vec_pretty(&ready_snapshot(&spec("1.0.0"), "w1")).unwrap(),
    )
    .unwrap();
    let retained = load_snapshots(&retained_dir, &spec("2.0.0")).unwrap();
    let wrapped = retained
        .into_iter()
        .map(|snapshot| retained_observation(snapshot, 1, tenkai::now_millis()))
        .collect::<Vec<_>>();
    let err = authorize_observations(&desired, &wrapped, 1, tenkai::now_millis())
        .unwrap_err()
        .to_string();
    assert!(err.contains("retained snapshots cannot authorize"), "{err}");

    let recovered = port.observe(&scope("2.0.0", 1)).unwrap();
    assert_eq!(recovered[0].snapshot.version, "2.0.0");
    drop(port);
    let surviving = LocalProcessWorkerLifecycle::new(root.0.join("runtime"), fixture_bin());
    let after_drop = surviving.observe(&scope("2.0.0", 1)).unwrap();
    assert_eq!(after_drop[0].snapshot.version, "2.0.0");
    surviving
        .stop_replica(&WorkerReplicaRequest {
            scope: scope("2.0.0", 1),
            worker_id: "w1".into(),
            version: "2.0.0".into(),
        })
        .unwrap();
}

#[test]
fn busy_live_process_drains_and_lost_fence_cannot_complete_replacement() {
    let root = TestRoot::new("tenkai-worker-live-busy");
    let port = LocalProcessWorkerLifecycle::new(root.0.join("runtime"), fixture_bin());
    port.start_replica(&WorkerReplicaRequest {
        scope: scope("1.0.0", 1),
        worker_id: "w1".into(),
        version: "1.0.0".into(),
    })
    .unwrap();

    let control = root
        .0
        .join("runtime")
        .join(ENV)
        .join(PRODUCT)
        .join("w1.control");
    std::fs::write(&control, "busy\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(80));
    let busy = port.observe(&scope("1.0.0", 1)).unwrap();
    assert_eq!(busy[0].snapshot.state, "active");
    assert_eq!(busy[0].snapshot.active_claims, 1);

    let desired = spec("2.0.0");
    let (decision, _, drain, _) = admit_live_pool(LivePoolAdmission {
        spec: &desired,
        port: &port,
        environment: ENV,
        expected_generation: 1,
        previous_replicas: 1,
        drain_started_at_ms: None,
        now_ms: tenkai::now_millis(),
        restart: false,
    })
    .unwrap();
    assert_eq!(decision, WorkerPoolDecision::WaitDrain);
    assert!(drain.is_some());
    std::thread::sleep(std::time::Duration::from_millis(80));
    let draining = port.observe(&scope("1.0.0", 1)).unwrap();
    assert_eq!(draining[0].snapshot.state, "draining");
    assert_eq!(draining[0].snapshot.active_claims, 0);
    assert!(!draining[0].snapshot.accepting_claims);

    std::fs::write(&control, "fence_lost\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(80));
    let (denied, _, _, _) = admit_live_pool(LivePoolAdmission {
        spec: &desired,
        port: &port,
        environment: ENV,
        expected_generation: 1,
        previous_replicas: 1,
        drain_started_at_ms: None,
        now_ms: tenkai::now_millis(),
        restart: false,
    })
    .unwrap();
    assert!(
        matches!(denied, WorkerPoolDecision::Deny { ref reason } if reason.contains("fence")),
        "{denied:?}"
    );
    let still_a = port.observe(&scope("1.0.0", 1)).unwrap();
    assert_eq!(still_a[0].snapshot.version, "1.0.0");
}

#[test]
fn stale_generation_cannot_mutate_live_process() {
    let root = TestRoot::new("tenkai-worker-live-gen");
    let port = LocalProcessWorkerLifecycle::new(root.0.join("runtime"), fixture_bin());
    port.start_replica(&WorkerReplicaRequest {
        scope: scope("1.0.0", 1),
        worker_id: "w1".into(),
        version: "1.0.0".into(),
    })
    .unwrap();

    let mut drain = scope("1.0.0", 2);
    drain.worker_id = Some("w1".into());
    let drain_err = port.request_drain(&drain).unwrap_err().to_string();
    assert!(
        drain_err.contains("stale fencing generation"),
        "{drain_err}"
    );

    let stop_err = port
        .stop_replica(&WorkerReplicaRequest {
            scope: scope("1.0.0", 2),
            worker_id: "w1".into(),
            version: "1.0.0".into(),
        })
        .unwrap_err()
        .to_string();
    assert!(stop_err.contains("stale fencing generation"), "{stop_err}");

    let still = port.observe(&scope("1.0.0", 1)).unwrap();
    assert_eq!(still.len(), 1);
    assert_eq!(still[0].snapshot.version, "1.0.0");
    port.stop_replica(&WorkerReplicaRequest {
        scope: scope("1.0.0", 1),
        worker_id: "w1".into(),
        version: "1.0.0".into(),
    })
    .unwrap();
}

#[test]
fn worker_exits_once_its_directory_is_removed() {
    let root = TestRoot::new("tenkai-worker-live-orphan");
    let port = LocalProcessWorkerLifecycle::new(root.0.join("runtime"), fixture_bin());
    port.start_replica(&WorkerReplicaRequest {
        scope: scope("1.0.0", 1),
        worker_id: "w1".into(),
        version: "1.0.0".into(),
    })
    .unwrap();
    let pid_file = root
        .0
        .join("runtime")
        .join(ENV)
        .join(PRODUCT)
        .join("w1.pid");
    let pid: i32 = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    drop(root);
    // This test spawned the fixture, so reap it rather than probe it: an
    // exited but unreaped child still answers kill(pid, 0).
    let mut status = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut exited = false;
    while !exited && std::time::Instant::now() < deadline {
        exited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid;
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(exited, "fixture {pid} outlived its directory");
}
