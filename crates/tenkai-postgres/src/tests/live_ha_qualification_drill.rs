//! Hub HA qualification drill (#903).
//!
//! Two replica processes share one PostgreSQL hub, apply two environments,
//! and lose the writer mid-step. The standby must take over within the
//! bound and finish each plan with one receipt per step. The same store
//! then runs the drill again after the replica processes are replaced
//! (a server rollback). A run with the writer fence left unset must not
//! refuse a superseded commit.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use tenkai::auth_context::{
    AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, PrincipalIdentity,
    PrincipalKind, TenantDerivationAuthority,
};
use tenkai::hub_ha_qualification::{self, Statement};
use tenkai::reconcile_fence::FenceAdmission;
use tenkai::storage::{
    EnvironmentRecord, OperationalStore, PlanRecord, PlanStatus, ReceiptRecord, StoreError,
};
use tenkai::writer_fence::{WriterFence, WriterRole};

use super::super::*;
use super::live_writer_lease::ScratchDatabase;

const WRITER_TTL_MS: i64 = 1_500;
const WORK_TTL_MS: i64 = 2_000;
const TICK: Duration = Duration::from_millis(200);
const STEPS: usize = 6;
const STALL_STEP: usize = 2;
const STALL: Duration = Duration::from_secs(3);
const ENV_A: &str = "env-a";
const ENV_B: &str = "env-b";

fn context(tenant: &str) -> AuthenticatedRequestContext {
    AuthenticatedRequestContextBuilder::new(
        format!("ha-qualification-{tenant}"),
        PrincipalIdentity {
            id: "ha-qualification".into(),
            kind: PrincipalKind::Service,
        },
        "test",
    )
    .with_tenant(tenant.to_owned(), &TenantDerivationAuthority::new("test"))
    .unwrap()
    .build()
    .unwrap()
}

fn work_pairs() -> Vec<(String, String)> {
    std::env::var("TENKAI_DRILL_WORK")
        .unwrap_or_else(|_| format!("{ENV_A}:plan-a,{ENV_B}:plan-b"))
        .split(',')
        .filter_map(|pair| {
            let (env, plan) = pair.split_once(':')?;
            Some((env.to_owned(), plan.to_owned()))
        })
        .collect()
}

fn receipt_id(plan: &str, step: usize) -> String {
    format!("{plan}-step-{step}")
}

/// One hub replica. Runs only when the qualification drill starts this
/// binary as a replica.
#[test]
#[ignore = "started by the hub HA qualification drill as a replica process"]
fn drill_replica() {
    let (Ok(holder), Ok(url), Ok(tenant), Some(go)) = (
        std::env::var("TENKAI_DRILL_HOLDER"),
        std::env::var("TENKAI_DRILL_URL"),
        std::env::var("TENKAI_DRILL_TENANT"),
        std::env::var_os("TENKAI_DRILL_GO").map(std::path::PathBuf::from),
    ) else {
        return;
    };
    let unfenced = std::env::var("TENKAI_DRILL_UNFENCED").ok().as_deref() == Some("1");
    let config = PostgresTenantConfig::new(url).expect("config");
    let fence = Arc::new(WriterFence::default());
    let store = config.open().expect("connect");
    if !unfenced {
        store.fence_writes(fence.clone()).expect("fence");
    }
    let partition = store.partition_for(&context(&tenant)).expect("partition");
    let lease = PostgresHubWriterLease::open(&config, &holder, WRITER_TTL_MS, fence.clone())
        .expect("lease");
    let ticks = store.reconcile_tick_fence();
    let mut last_role = None;
    let mut turn = 0usize;
    loop {
        if fence.is_leader() && go.exists() {
            let pairs = work_pairs();
            if !pairs.is_empty() {
                for offset in 0..pairs.len() {
                    let idx = (turn + offset) % pairs.len();
                    let (env, plan) = &pairs[idx];
                    match work_one_step(&partition, &*ticks, &holder, env, plan) {
                        Ok(Some(line)) => {
                            turn = idx + 1;
                            println!("drill: {line}");
                            break;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            println!("drill: refused {error}");
                            break;
                        }
                    }
                }
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

fn work_one_step(
    partition: &PostgresTenantPartition,
    ticks: &dyn tenkai::reconcile_fence::ReconcileTickFence,
    holder: &str,
    environment: &str,
    plan_id: &str,
) -> std::result::Result<Option<String>, String> {
    let now = tenkai::now_millis();
    match ticks
        .try_begin(environment, holder, now, WORK_TTL_MS)
        .map_err(|error| error.to_string())?
    {
        FenceAdmission::Started { .. } => {}
        FenceAdmission::Busy { .. } | FenceAdmission::Stale => return Ok(None),
    }
    let lease = match partition.acquire_lease(environment, holder, now + WORK_TTL_MS) {
        Ok(lease) => lease,
        Err(StoreError::LeaseHeld { .. }) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let plan = partition
        .get_plan(plan_id)
        .map_err(|error| error.to_string())?
        .expect("seeded plan");
    if plan.status == PlanStatus::Succeeded {
        return Ok(None);
    }
    partition
        .transition_plan(
            plan_id,
            holder,
            lease.generation,
            PlanStatus::Running,
            "running",
        )
        .map_err(|error| error.to_string())?;
    for step in 0..STEPS {
        if partition
            .get_receipt(&receipt_id(plan_id, step))
            .map_err(|error| error.to_string())?
            .is_some()
        {
            continue;
        }
        let receipt = ReceiptRecord {
            id: receipt_id(plan_id, step),
            environment_id: environment.into(),
            plan_id: plan_id.into(),
            step_id: format!("step-{step}"),
            lease_generation: lease.generation,
            payload_json: format!(r#"{{"applied_by":"{holder}"}}"#),
        };
        let stall = step == STALL_STEP && holder == "hub-a" && environment == ENV_A;
        let written = if stall {
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
        return Ok(Some(format!("step {environment} {step}")));
    }
    partition
        .transition_plan(
            plan_id,
            holder,
            lease.generation,
            PlanStatus::Succeeded,
            "done",
        )
        .map_err(|error| error.to_string())?;
    Ok(Some(format!("done {plan_id}")))
}

struct Replica {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl Replica {
    fn start(drill: &Drill, holder: &str) -> Self {
        let mut command = Command::new(std::env::current_exe().expect("test binary"));
        command.args([
            "--exact",
            "tests::live_ha_qualification_drill::drill_replica",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
        command
            .env("TENKAI_DRILL_HOLDER", holder)
            .env("TENKAI_DRILL_URL", &drill.scratch.url)
            .env("TENKAI_DRILL_TENANT", &drill.tenant)
            .env("TENKAI_DRILL_GO", &drill.go)
            .env("TENKAI_DRILL_WORK", &drill.work)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if drill.unfenced {
            command.env("TENKAI_DRILL_UNFENCED", "1");
        }
        let mut child = command.spawn().expect("start replica");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in stdout.lines().map_while(Result::ok) {
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

    fn wait_for(&mut self, prefix: &str, within: Duration) -> String {
        if let Some(line) = self.seen.iter().find(|line| line.starts_with(prefix)) {
            return line.clone();
        }
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

struct Drill {
    scratch: ScratchDatabase,
    tenant: String,
    go: std::path::PathBuf,
    work: String,
    unfenced: bool,
}

impl Drill {
    fn go(&self) {
        std::fs::write(&self.go, b"").expect("start the replicas");
    }

    fn set_work(&mut self, work: &str) {
        self.work = work.to_owned();
        let _ = std::fs::remove_file(&self.go);
    }
}

impl Drop for Drill {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.go);
    }
}

fn seed_plan(partition: &PostgresTenantPartition, environment: &str, plan: &str) {
    partition
        .create_plan(&PlanRecord {
            id: plan.into(),
            environment_id: environment.into(),
            format_version: 1,
            content_digest: format!("sha256:{plan}"),
            plan_json: "{}".into(),
            status: PlanStatus::Computed,
            status_detail: String::new(),
        })
        .expect("plan");
}

fn seed(unfenced: bool) -> Drill {
    let scratch = ScratchDatabase::create();
    let tenant = format!("ha-{}", uuid::Uuid::new_v4().simple());
    let store = PostgresTenantConfig::new(scratch.url.clone())
        .expect("config")
        .open()
        .expect("connect");
    let partition = store.partition_for(&context(&tenant)).expect("partition");
    for environment in [ENV_A, ENV_B] {
        partition
            .put_environment(&EnvironmentRecord {
                id: environment.into(),
                revision: 0,
                configuration_json: "{}".into(),
            })
            .expect("environment");
    }
    seed_plan(&partition, ENV_A, "plan-a");
    seed_plan(&partition, ENV_B, "plan-b");
    let go = std::env::temp_dir().join(format!(
        "tenkai-ha-drill-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    Drill {
        scratch,
        tenant,
        go,
        work: format!("{ENV_A}:plan-a,{ENV_B}:plan-b"),
        unfenced,
    }
}

fn assert_applied_once(drill: &Drill, plan: &str, environment: &str) {
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
                .get_receipt(&receipt_id(plan, step))
                .expect("read")
                .unwrap_or_else(|| panic!("{plan} step {step} has a receipt"))
        })
        .collect();
    assert_eq!(receipts.len(), STEPS, "{plan} {receipts:?}");
    assert!(
        receipts
            .iter()
            .all(|r| r.environment_id == environment && r.plan_id == plan),
        "{plan} {receipts:?}"
    );
    assert_eq!(
        partition.get_plan(plan).unwrap().unwrap().status,
        PlanStatus::Succeeded
    );
}

fn takeover_bound() -> Duration {
    Duration::from_millis(WRITER_TTL_MS as u64) + TICK + Duration::from_secs(2)
}

fn kill_and_takeover(drill: &Drill) -> Duration {
    let mut a = Replica::start(drill, "hub-a");
    a.wait_for("role leader", Duration::from_secs(20));
    let mut b = Replica::start(drill, "hub-b");
    b.wait_for("role standby", Duration::from_secs(20));
    drill.go();
    a.wait_for("stalling", Duration::from_secs(20));
    a.child.kill().expect("SIGKILL the leader");
    let killed = Instant::now();
    b.wait_for("role leader", takeover_bound());
    let took = killed.elapsed();
    assert!(took <= takeover_bound(), "took over after {took:?}");
    for plan in drill
        .work
        .split(',')
        .filter_map(|pair| pair.split_once(':').map(|(_, plan)| plan))
    {
        b.wait_for(&format!("done {plan}"), Duration::from_secs(30));
    }
    drop((a, b));
    took
}

/// Two environments, kill the writer, takeover, exactly-once receipts,
/// then replace the replica processes on the same store and repeat.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_ha_qualification_drill() {
    let mut drill = seed(false);
    let first = kill_and_takeover(&drill);
    assert_applied_once(&drill, "plan-a", ENV_A);
    assert_applied_once(&drill, "plan-b", ENV_B);

    let store = PostgresTenantConfig::new(drill.scratch.url.clone())
        .expect("config")
        .open()
        .expect("connect");
    let partition = store
        .partition_for(&context(&drill.tenant))
        .expect("partition");
    seed_plan(&partition, ENV_A, "plan-a-r2");
    seed_plan(&partition, ENV_B, "plan-b-r2");
    drill.set_work(&format!("{ENV_A}:plan-a-r2,{ENV_B}:plan-b-r2"));
    let second = kill_and_takeover(&drill);
    assert_applied_once(&drill, "plan-a-r2", ENV_A);
    assert_applied_once(&drill, "plan-b-r2", ENV_B);

    assert_fenced_stale_commit_refused();
    assert_unfenced_stale_commit();

    let bound_ms = takeover_bound().as_millis() as i64;
    let statement = Statement {
        passed: true,
        environments: vec![ENV_A.into(), ENV_B.into()],
        takeover_ms: first.as_millis().max(second.as_millis()) as i64,
        takeover_bound_ms: bound_ms,
        receipts_once: true,
        restart_repeat: true,
        fence_required: true,
    };
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed_bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let evidence = hub_ha_qualification::sign(&seed_bytes, &statement).expect("sign");
    let public_key = hub_ha_qualification::public_key(&seed_bytes);
    let verified = hub_ha_qualification::verify(&evidence, &public_key).expect("verify");
    assert_eq!(verified, statement);
    let out = std::env::var_os("TENKAI_HA_DRILL_OUT").map(std::path::PathBuf::from);
    if let Some(path) = out {
        std::fs::write(&path, serde_json::to_vec_pretty(&evidence).expect("json"))
            .expect("write evidence");
        let pubkey_path = {
            let mut pubkey_path = path.clone();
            let name = path.file_name().expect("evidence file name");
            pubkey_path.set_file_name(format!("{}.pub", name.to_string_lossy()));
            pubkey_path
        };
        std::fs::write(
            &pubkey_path,
            hub_ha_qualification::public_key_hex(&public_key),
        )
        .expect("write public key");
        let from_file = hub_ha_qualification::verify_file(&path, &public_key).expect("verify file");
        assert_eq!(from_file, statement);
        println!("drill: evidence {}", path.display());
        println!("drill: pubkey {}", pubkey_path.display());
    }
    drop(drill);
}

/// With the writer fence, a stopped leader's in-flight commit is refused as
/// a superseded hub writer. Called before evidence is signed.
fn assert_fenced_stale_commit_refused() {
    let drill = seed(false);
    let mut a = Replica::start(&drill, "hub-a");
    a.wait_for("role leader", Duration::from_secs(20));
    let mut b = Replica::start(&drill, "hub-b");
    b.wait_for("role standby", Duration::from_secs(20));
    drill.go();
    a.wait_for("stalling", Duration::from_secs(20));
    a.signal("-STOP");
    b.wait_for("role leader", takeover_bound());
    a.signal("-CONT");
    let refused = a.wait_for("refused", Duration::from_secs(20));
    assert!(
        refused.contains("not the active hub writer") && refused.contains("superseded"),
        "the writer fence refuses the late commit: {refused}"
    );
    drop((a, b));
    drop(drill);
}

/// Without the writer fence, a stopped leader's in-flight stall step commits
/// after takeover. Called before evidence is signed.
fn assert_unfenced_stale_commit() {
    let drill = seed(true);
    let mut a = Replica::start(&drill, "hub-a");
    a.wait_for("role leader", Duration::from_secs(20));
    let mut b = Replica::start(&drill, "hub-b");
    b.wait_for("role standby", Duration::from_secs(20));
    drill.go();
    a.wait_for("stalling", Duration::from_secs(20));
    a.signal("-STOP");
    b.wait_for("role leader", takeover_bound());
    a.signal("-CONT");
    let committed = a.wait_for("step env-a 2", Duration::from_secs(20));
    assert!(
        !a.seen
            .iter()
            .any(|line| line.contains("not the active hub writer")),
        "an unfenced resume was refused as a superseded writer: {:?}",
        a.seen
    );
    assert!(
        committed.starts_with("step env-a 2"),
        "unfenced stall step did not commit: {committed}"
    );
    drop((a, b));
    drop(drill);
}
