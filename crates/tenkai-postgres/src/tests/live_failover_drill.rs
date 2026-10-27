//! Kill-the-leader failover drill (#749).
//!
//! Each hub replica is a real process: this test binary started again with
//! `TENKAI_DRILL_HOLDER` set, running [`drill_replica`]. A replica renews the
//! hub writer lease and, while it leads, works one plan a step at a time
//! under the reconcile tick claim and an environment lease, recording one
//! receipt per step. At `STALL_STEP` the leader stalls inside the write
//! transaction, and the drill kills or stops it there. It checks that a
//! standby takes the lease within the bound, finishes the plan without
//! applying a step twice, and that a stopped leader which resumes is refused.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use tenkai::auth_context::{
    AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, PrincipalIdentity,
    PrincipalKind, TenantDerivationAuthority,
};
use tenkai::reconcile_fence::FenceAdmission;
use tenkai::storage::{
    EnvironmentRecord, OperationalStore, PlanRecord, PlanStatus, ReceiptRecord, StoreError,
};
use tenkai::writer_fence::{WriterFence, WriterRole};

use super::super::*;
use super::live_writer_lease::ScratchDatabase;

const WRITER_TTL_MS: i64 = 1_500;
/// Environment lease and reconcile tick claim lifetime; a replica renews
/// both on every step.
const WORK_TTL_MS: i64 = 2_000;
const TICK: Duration = Duration::from_millis(200);
const STEPS: usize = 6;
/// The step the first leader (`hub-a`) writes slowly, announcing
/// `stalling` first; the drill kills or stops it there.
const STALL_STEP: usize = 2;
const STALL: Duration = Duration::from_secs(3);
const ENVIRONMENT: &str = "drill-environment";
const PLAN: &str = "drill-plan";

fn context(tenant: &str) -> AuthenticatedRequestContext {
    AuthenticatedRequestContextBuilder::new(
        format!("failover-drill-{tenant}"),
        PrincipalIdentity {
            id: "failover-drill".into(),
            kind: PrincipalKind::Service,
        },
        "test",
    )
    .with_tenant(tenant.to_owned(), &TenantDerivationAuthority::new("test"))
    .unwrap()
    .build()
    .unwrap()
}

fn receipt_id(step: usize) -> String {
    format!("{PLAN}-step-{step}")
}

/// One hub replica. Runs only when the drill starts this binary as a
/// replica; a normal `--ignored` run returns at once.
#[test]
#[ignore = "started by the failover drill as a replica process"]
fn drill_replica() {
    let (Ok(holder), Ok(url), Ok(tenant), Some(go)) = (
        std::env::var("TENKAI_DRILL_HOLDER"),
        std::env::var("TENKAI_DRILL_URL"),
        std::env::var("TENKAI_DRILL_TENANT"),
        std::env::var_os("TENKAI_DRILL_GO").map(std::path::PathBuf::from),
    ) else {
        return;
    };
    let config = PostgresTenantConfig::new(url).expect("config");
    let fence = Arc::new(WriterFence::default());
    let store = config.open().expect("connect");
    store.fence_writes(fence.clone()).expect("fence");
    let partition = store.partition_for(&context(&tenant)).expect("partition");
    let lease = PostgresHubWriterLease::open(&config, &holder, WRITER_TTL_MS, fence.clone())
        .expect("lease");
    let ticks = store.reconcile_tick_fence();
    let mut last_role = None;
    loop {
        // Work first, then renew: a replica that was stopped and resumes
        // writes with the role it last saw, as a paused process would. No
        // replica works before the drill has every replica running.
        if fence.is_leader() && go.exists() {
            match work_one_step(&partition, &*ticks, &holder) {
                Ok(Some(line)) => println!("drill: {line}"),
                Ok(None) => {}
                Err(error) => println!("drill: refused {error}"),
            }
        }
        let role = match lease.renew() {
            Ok(WriterRole::Leader { generation, .. }) => format!("leader {generation}"),
            Ok(WriterRole::Standby) => "standby".to_owned(),
            Err(error) => format!("standby ({error})"),
        };
        if last_role.as_ref() != Some(&role) {
            println!("drill: role {role}");
            last_role = Some(role);
        }
        std::thread::sleep(TICK);
    }
}

/// Applies the plan's next step, or finishes the plan, as the reconciler
/// would: under the tick claim and the environment lease. A step whose
/// receipt exists was applied already and is not applied again.
fn work_one_step(
    partition: &PostgresTenantPartition,
    ticks: &dyn tenkai::reconcile_fence::ReconcileTickFence,
    holder: &str,
) -> std::result::Result<Option<String>, String> {
    let now = tenkai::now_millis();
    match ticks
        .try_begin(ENVIRONMENT, holder, now, WORK_TTL_MS)
        .map_err(|error| error.to_string())?
    {
        FenceAdmission::Started { .. } => {}
        FenceAdmission::Busy { .. } | FenceAdmission::Stale => return Ok(None),
    }
    let lease = match partition.acquire_lease(ENVIRONMENT, holder, now + WORK_TTL_MS) {
        Ok(lease) => lease,
        Err(StoreError::LeaseHeld { .. }) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let plan = partition
        .get_plan(PLAN)
        .map_err(|error| error.to_string())?
        .expect("seeded plan");
    if plan.status == PlanStatus::Succeeded {
        return Ok(None);
    }
    partition
        .transition_plan(
            PLAN,
            holder,
            lease.generation,
            PlanStatus::Running,
            "running",
        )
        .map_err(|error| error.to_string())?;
    for step in 0..STEPS {
        if partition
            .get_receipt(&receipt_id(step))
            .map_err(|error| error.to_string())?
            .is_some()
        {
            continue;
        }
        let receipt = ReceiptRecord {
            id: receipt_id(step),
            environment_id: ENVIRONMENT.into(),
            plan_id: PLAN.into(),
            step_id: format!("step-{step}"),
            lease_generation: lease.generation,
            payload_json: format!(r#"{{"applied_by":"{holder}"}}"#),
        };
        let written = if step == STALL_STEP && holder == "hub-a" {
            partition.inner.record_receipt_stalled_for_test(
                partition.schema(),
                holder,
                &receipt,
                || {
                    println!("drill: stalling");
                    std::thread::sleep(STALL);
                },
            )
        } else {
            partition.record_receipt(holder, &receipt)
        };
        written.map_err(|error| error.to_string())?;
        return Ok(Some(format!("step {step}")));
    }
    partition
        .transition_plan(
            PLAN,
            holder,
            lease.generation,
            PlanStatus::Succeeded,
            "done",
        )
        .map_err(|error| error.to_string())?;
    Ok(Some("done".into()))
}

/// A replica process and the lines it prints.
struct Replica {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl Replica {
    fn start(drill: &Drill, holder: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "tests::live_failover_drill::drill_replica",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TENKAI_DRILL_HOLDER", holder)
            .env("TENKAI_DRILL_URL", &drill.scratch.url)
            .env("TENKAI_DRILL_TENANT", &drill.tenant)
            .env("TENKAI_DRILL_GO", &drill.go)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start replica");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in stdout.lines().map_while(Result::ok) {
                // The test harness may print its own header before the
                // first line on the same line.
                if let Some((_, line)) = line.split_once("drill: ")
                    && sender.send(line.to_owned()).is_err()
                {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    /// Waits for a line starting with `prefix` and returns it.
    fn wait_for(&mut self, prefix: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.starts_with(prefix) {
                        return line;
                    }
                }
                Err(_) => panic!(
                    "no `{prefix}` within {within:?}; replica printed {:?}",
                    self.seen
                ),
            }
        }
    }

    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .args([signal, &self.child.id().to_string()])
            .status()
            .expect("kill");
        assert!(status.success(), "kill {signal}");
    }
}

impl Drop for Replica {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One run: a fresh database with one environment and one computed plan in
/// a tenant, and the file whose existence lets the replicas start working.
struct Drill {
    scratch: ScratchDatabase,
    tenant: String,
    go: std::path::PathBuf,
}

impl Drill {
    fn go(&self) {
        std::fs::write(&self.go, b"").expect("start the replicas");
    }
}

impl Drop for Drill {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.go);
    }
}

fn seed() -> Drill {
    let scratch = ScratchDatabase::create();
    let tenant = format!("drill-{}", uuid::Uuid::new_v4().simple());
    let store = PostgresTenantConfig::new(scratch.url.clone())
        .expect("config")
        .open()
        .expect("connect");
    let partition = store.partition_for(&context(&tenant)).expect("partition");
    partition
        .put_environment(&EnvironmentRecord {
            id: ENVIRONMENT.into(),
            revision: 0,
            configuration_json: "{}".into(),
        })
        .expect("environment");
    partition
        .create_plan(&PlanRecord {
            id: PLAN.into(),
            environment_id: ENVIRONMENT.into(),
            format_version: 1,
            content_digest: "sha256:drill".into(),
            plan_json: "{}".into(),
            status: PlanStatus::Computed,
            status_detail: String::new(),
        })
        .expect("plan");
    let go = std::env::temp_dir().join(format!(
        "tenkai-drill-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    Drill {
        scratch,
        tenant,
        go,
    }
}

/// Every step has exactly one receipt. The old leader wrote the steps before
/// the stall and the new leader, under a later environment lease, the rest.
fn assert_applied_once(drill: &Drill) {
    let store = PostgresTenantConfig::new(drill.scratch.url.clone())
        .expect("config")
        .open()
        .expect("connect");
    let partition = store
        .partition_for(&context(&drill.tenant))
        .expect("partition");
    let receipts: Vec<ReceiptRecord> = (0..STEPS)
        .map(|step| {
            partition
                .get_receipt(&receipt_id(step))
                .expect("read")
                .unwrap_or_else(|| panic!("step {step} has a receipt"))
        })
        .collect();
    let (old, new) = receipts.split_at(STALL_STEP);
    assert!(
        old.iter().all(|r| r.payload_json.contains("hub-a")),
        "{receipts:?}"
    );
    assert!(
        new.iter().all(|r| r.payload_json.contains("hub-b")),
        "{receipts:?}"
    );
    assert!(
        new.iter()
            .all(|r| r.lease_generation > old[0].lease_generation),
        "{receipts:?}"
    );
    assert_eq!(
        partition
            .inner
            .delivery_effect_counts_for_test(partition.schema())
            .unwrap()
            .2,
        STEPS as i64,
        "one receipt per step and no more"
    );
    assert_eq!(
        partition.get_plan(PLAN).unwrap().unwrap().status,
        PlanStatus::Succeeded
    );
}

/// The standby must lead within the writer lease plus one renewal, with
/// slack for a loaded machine.
fn takeover_bound() -> Duration {
    Duration::from_millis(WRITER_TTL_MS as u64) + TICK + Duration::from_secs(2)
}

/// The leader is killed mid-plan: the standby takes the lease within the
/// bound, resumes from the next unapplied step and finishes the plan.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_failover_drill_killed_leader() {
    let drill = seed();
    let mut a = Replica::start(&drill, "hub-a");
    a.wait_for("role leader", Duration::from_secs(20));
    let mut b = Replica::start(&drill, "hub-b");
    b.wait_for("role standby", Duration::from_secs(20));
    drill.go();
    a.wait_for("stalling", Duration::from_secs(20));
    a.child.kill().expect("SIGKILL the leader");
    let killed = Instant::now();
    b.wait_for("role leader", takeover_bound());
    let took = killed.elapsed();
    assert!(took <= takeover_bound(), "took over after {took:?}");
    b.wait_for("done", Duration::from_secs(30));
    assert_applied_once(&drill);
    drop((a, b));
    drop(drill);
}

/// The leader is stopped (as a paused or partitioned process) after writing
/// a receipt and before its transaction commits: the standby takes the
/// lease, and when the old leader resumes, the writer fence refuses its
/// commit at the old generation. The standby then finishes the plan.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_failover_drill_resumed_leader_is_refused() {
    let drill = seed();
    let mut a = Replica::start(&drill, "hub-a");
    a.wait_for("role leader", Duration::from_secs(20));
    let mut b = Replica::start(&drill, "hub-b");
    b.wait_for("role standby", Duration::from_secs(20));
    drill.go();
    a.wait_for("stalling", Duration::from_secs(20));
    a.signal("-STOP");
    let stopped = Instant::now();
    b.wait_for("role leader", takeover_bound());
    assert!(stopped.elapsed() <= takeover_bound());
    // Resume at once, well inside the database's idle transaction limit,
    // so the write reaches its commit-time check rather than being ended.
    let before = a.seen.len();
    a.signal("-CONT");
    let refused = a.wait_for("refused", Duration::from_secs(20));
    assert!(
        refused.contains("not the active hub writer") && refused.contains("superseded"),
        "the writer fence refuses the late commit: {refused}"
    );
    a.wait_for("role standby", Duration::from_secs(10));
    b.wait_for("done", Duration::from_secs(30));
    assert!(
        !a.seen[before..]
            .iter()
            .any(|line| line.starts_with("step") || line == "done"),
        "the resumed leader wrote: {:?}",
        a.seen
    );
    assert_applied_once(&drill);
    drop((a, b));
    drop(drill);
}
