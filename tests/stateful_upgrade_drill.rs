//! Signed stateful upgrade drill with executor crash recovery (#334).
//!
//! Proves Catalog, approval, plan, executor, migration, rollback, and
//! backup/restore against a separately observable fixture target. Signing
//! uses `tenkaictl dev` keys; no unsigned or unapproved development bypass.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tenkai::environment::EnvironmentInspectReport;
use tenkai::package_migration::{
    CheckpointClass, CheckpointDecl, CompatibilityEvidence, CompatibilityStatus,
    MigrationDeclaration, PackagePin,
};

const ENV: &str = "drill";
const PRODUCT: &str = "pkg";
const SOURCE_VERSION: &str = "1.0.0";
const TARGET_VERSION: &str = "1.1.0";
const SEED: &str = "fixture-record-1";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tenkaictl_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tenkaictl"))
}

fn executor_guard_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tenkai-executor-guard"))
}

struct Drill {
    root: PathBuf,
    db: PathBuf,
    keys: PathBuf,
    state_dir: PathBuf,
    release_trust: PathBuf,
    approval_trust: PathBuf,
    approvals: PathBuf,
}

impl Drill {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "tenkai-stateful-drill-{}-{}",
            std::process::id(),
            tenkai::now_millis()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let keys = root.join("keys");
        let state_dir = root.join("state");
        let approvals = root.join("approvals");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&approvals).unwrap();
        Self {
            db: root.join("tenkai.db"),
            release_trust: root.join("release-trust.toml"),
            approval_trust: root.join("approval-trust.toml"),
            keys,
            state_dir,
            approvals,
            root,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(tenkaictl_bin());
        command
            .arg("--database")
            .arg(&self.db)
            .args(args)
            .env("TENKAI_MANAGEMENT_TOKEN", "stateful-drill-token")
            .env("TENKAI_STATE_DIR", &self.state_dir)
            .env("TENKAI_EXECUTOR_GUARD", executor_guard_bin())
            .env("TMPDIR", &self.root)
            .env_remove("TENKAI_PLAN_APPROVAL_DIR")
            .env_remove("TENKAI_PLAN_APPROVAL_TRUST_ROOTS")
            .env_remove("TENKAI_SOFTWARE_EXECUTOR")
            .env_remove("TENKAI_HELM_BIN")
            .env_remove("TENKAI_KUBECTL_BIN")
            .env_remove("TENKAI_RUNTIME_EXECUTOR")
            .env_remove("TENKAI_DELIVERY_ADAPTER");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args)
            .output()
            .unwrap_or_else(|error| panic!("failed to launch tenkaictl {args:?}: {error}"))
    }

    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "tenkaictl {args:?} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        stdout
    }

    fn fail(&self, args: &[&str]) -> String {
        let output = self.run(args);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let combined = format!("{stdout}{stderr}");
        assert!(
            !output.status.success(),
            "tenkaictl {args:?} unexpectedly succeeded\n{combined}"
        );
        combined
    }

    fn target_root(&self) -> PathBuf {
        self.root.join("tenkai-stateful-drill").join(ENV)
    }

    fn control_path(&self, name: &str) -> PathBuf {
        self.target_root().join("control").join(name)
    }

    fn write_control(&self, name: &str, value: &str) {
        let path = self.control_path(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("{value}\n")).unwrap();
    }

    fn clear_control(&self, name: &str) {
        let _ = fs::remove_file(self.control_path(name));
    }

    fn current_version(&self) -> Option<String> {
        fs::read_to_string(self.target_root().join("target/current_version"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn seed(&self) -> Option<String> {
        fs::read_to_string(self.target_root().join("target/records/seed"))
            .ok()
            .map(|value| value.trim().to_string())
    }

    fn mutation_count(&self) -> u32 {
        fs::read_to_string(self.target_root().join("target/mutation_count"))
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0)
    }

    fn ledger_contains(&self, version: &str) -> bool {
        self.target_root()
            .join("target/ledger")
            .join(format!("{PRODUCT}@{version}"))
            .is_file()
    }

    fn forget_ledger(&self, version: &str) {
        let _ = fs::remove_file(
            self.target_root()
                .join("target/ledger")
                .join(format!("{PRODUCT}@{version}")),
        );
    }

    fn inspect_env(&self) -> EnvironmentInspectReport {
        let stdout = self.ok(&["env", "inspect", ENV]);
        serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!("env inspect JSON: {error}\n{stdout}");
        })
    }

    fn deployed(&self) -> Option<String> {
        self.inspect_env()
            .subscriptions
            .into_iter()
            .find(|row| row.product == PRODUCT)
            .and_then(|row| row.deployed)
    }

    fn sign_release(&self, manifest: &Path, signature: &Path) {
        self.ok(&[
            "dev",
            "sign-release",
            manifest.to_str().unwrap(),
            "--keys",
            self.keys.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
            "--trust-roots",
            self.release_trust.to_str().unwrap(),
        ]);
    }

    fn publish_signed(&self, manifest: &Path, signature: &Path, version: &str) -> String {
        self.ok(&[
            "publish",
            manifest.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
            "--trust-roots",
            self.release_trust.to_str().unwrap(),
        ]);
        let spec = format!("{PRODUCT}@{version}");
        let stdout = self.ok(&["release", "inspect", &spec]);
        let view: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!("release inspect JSON: {error}\n{stdout}");
        });
        assert_eq!(
            view["status"].as_str(),
            Some("verified"),
            "release {spec} was not verified: {stdout}"
        );
        let digest = view["manifest_digest"]
            .as_str()
            .unwrap_or_else(|| panic!("release {spec} missing manifest_digest: {stdout}"));
        if digest.starts_with("sha256:") {
            digest.to_string()
        } else {
            format!("sha256:{digest}")
        }
    }

    fn sign_plan(&self, plan_id: &str, approval: &Path) {
        self.ok(&[
            "dev",
            "sign-approval",
            plan_id,
            "--keys",
            self.keys.to_str().unwrap(),
            "--approval",
            approval.to_str().unwrap(),
            "--trust-roots",
            self.approval_trust.to_str().unwrap(),
        ]);
    }

    fn apply_signed(&self, plan_id: &str, approval: &Path) -> String {
        self.ok(&[
            "apply",
            plan_id,
            "--approval",
            approval.to_str().unwrap(),
            "--approval-trust-roots",
            self.approval_trust.to_str().unwrap(),
        ])
    }

    fn plan_and_apply(&self) -> String {
        let stdout = self.ok(&["plan", "--env", ENV]);
        let plan_id = plan_id_from(&stdout);
        let approval = self.approvals.join(format!("{plan_id}.json"));
        self.sign_plan(&plan_id, &approval);
        self.apply_signed(&plan_id, &approval);
        plan_id
    }

    fn promote(&self, version: &str) {
        self.ok(&["promote", &format!("{PRODUCT}@{version}"), "stable"]);
    }
}

impl Drop for Drill {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn plan_id_from(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("plan id: "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("missing plan id in:\n{stdout}"))
        .to_string()
}

fn identity_from(stdout: &str) -> String {
    stdout
        .split_whitespace()
        .find_map(|token| token.strip_prefix("identity="))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("missing identity in:\n{stdout}"))
}

fn pending_plan_from(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("pending-plan "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("missing pending-plan in:\n{stdout}"))
        .to_string()
}

fn sha256_file(path: &Path) -> String {
    let output = Command::new("openssl")
        .args(["dgst", "-sha256", "-r"])
        .arg(path)
        .output()
        .unwrap_or_else(|error| panic!("openssl dgst failed: {error}"));
    assert!(
        output.status.success(),
        "openssl dgst failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hex = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("openssl digest missing hex"))
        .to_string();
    format!("sha256:{hex}")
}

fn wait_for(timeout: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    probe()
}

fn process_group_id(pid: u32) -> Option<u32> {
    let output = Command::new("ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
}

fn kill_group(child: &std::process::Child) {
    let pid = child.id();
    if pid <= 1 {
        return;
    }
    // Only signal a process group when this child is its leader. `kill -- -pid`
    // otherwise targets an unrelated group and can SIGKILL the CI runner.
    if process_group_id(pid) == Some(pid) {
        let _ = Command::new("kill")
            .args(["-s", "KILL", "--", &format!("-{pid}")])
            .status();
    }
    let _ = Command::new("kill")
        .args(["-s", "KILL", "--", &pid.to_string()])
        .status();
}

fn wait_exited(child: &mut std::process::Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            Err(_) => return,
        }
    }
}

#[derive(serde::Serialize)]
struct Check {
    id: &'static str,
    passed: bool,
    detail: String,
}

#[derive(serde::Serialize)]
struct Report {
    schema: &'static str,
    passed: bool,
    checks: Vec<Check>,
}

fn check(id: &'static str, passed: bool, detail: impl Into<String>) -> Check {
    Check {
        id,
        passed,
        detail: detail.into(),
    }
}

#[test]
fn signed_stateful_upgrade_survives_executor_loss() {
    let examples = repo_root().join("examples/package-migration");
    let fixture = fs::read(examples.join("fixture/target.sh")).unwrap();
    for name in ["source", "target"] {
        let copy = fs::read(examples.join(name).join("target.sh")).unwrap();
        assert_eq!(
            fixture, copy,
            "{name}/target.sh drifted from fixture/target.sh"
        );
    }
    let source = examples.join("source/tenkai.toml");
    let target = examples.join("target/tenkai.toml");
    let drill = Drill::new();

    drill.ok(&["init"]);
    drill.ok(&["env", "add", ENV, "--description", "stateful upgrade drill"]);
    drill.ok(&["dev", "init-keys", "--dir", drill.keys.to_str().unwrap()]);

    let source_sig = drill.root.join("source.sig.json");
    let target_sig = drill.root.join("target.sig.json");
    drill.sign_release(&source, &source_sig);
    drill.sign_release(&target, &target_sig);
    let source_digest = drill.publish_signed(&source, &source_sig, SOURCE_VERSION);
    let target_digest = drill.publish_signed(&target, &target_sig, TARGET_VERSION);
    drill.ok(&[
        "release",
        "verify",
        &format!("{PRODUCT}@{SOURCE_VERSION}"),
        "--trust-roots",
        drill.release_trust.to_str().unwrap(),
    ]);
    drill.ok(&[
        "release",
        "verify",
        &format!("{PRODUCT}@{TARGET_VERSION}"),
        "--trust-roots",
        drill.release_trust.to_str().unwrap(),
    ]);

    drill.promote(SOURCE_VERSION);
    drill.ok(&["env", "subscribe", ENV, &format!("{PRODUCT}=stable")]);
    drill.plan_and_apply();
    assert_eq!(drill.current_version().as_deref(), Some(SOURCE_VERSION));
    assert_eq!(drill.seed().as_deref(), Some(SEED));
    assert_eq!(drill.deployed().as_deref(), Some(SOURCE_VERSION));
    let mutations_after_a = drill.mutation_count();
    assert_eq!(mutations_after_a, 1);

    let mut checks = Vec::new();
    checks.push(check(
        "healthy_install_a",
        drill.current_version().as_deref() == Some(SOURCE_VERSION)
            && drill.seed().as_deref() == Some(SEED),
        "signed release A installed with fixture seed",
    ));

    let bad_sig = drill.root.join("bad.sig.json");
    fs::write(&bad_sig, "{\"schema\":\"tenkai.release-signature.v1\"}").unwrap();
    let unsigned = drill.fail(&[
        "publish",
        target.to_str().unwrap(),
        "--signature",
        bad_sig.to_str().unwrap(),
        "--trust-roots",
        drill.release_trust.to_str().unwrap(),
    ]);
    assert!(
        unsigned.contains("signature")
            || unsigned.contains("schema")
            || unsigned.contains("verify"),
        "{unsigned}"
    );
    assert_eq!(drill.current_version().as_deref(), Some(SOURCE_VERSION));

    let incompatible = MigrationDeclaration {
        version: 1,
        profile: tenkai::package_migration::MIGRATION_PROFILE.into(),
        source: PackagePin {
            product: PRODUCT.into(),
            version: SOURCE_VERSION.into(),
            digest: source_digest.clone(),
        },
        target: PackagePin {
            product: PRODUCT.into(),
            version: TARGET_VERSION.into(),
            digest: target_digest.clone(),
        },
        compatibility: CompatibilityEvidence {
            version: 1,
            status: CompatibilityStatus::Incompatible,
            evidence_digest: format!("sha256:{}", "e".repeat(64)),
        },
        checkpoints: vec![CheckpointDecl {
            id: "preflight".into(),
            class: CheckpointClass::Reversible,
            pre_admission: None,
        }],
    };
    let incompatible_path = drill.root.join("incompatible.json");
    fs::write(
        &incompatible_path,
        serde_json::to_vec_pretty(&incompatible).unwrap(),
    )
    .unwrap();
    let rejected = drill.fail(&[
        "migrate",
        "preview",
        "bad-cutover",
        "--env",
        ENV,
        "--declaration",
        incompatible_path.to_str().unwrap(),
    ]);
    assert!(rejected.contains("not compatible"), "{rejected}");
    assert_eq!(drill.current_version().as_deref(), Some(SOURCE_VERSION));
    checks.push(check(
        "invalid_evidence_rejected",
        drill.current_version().as_deref() == Some(SOURCE_VERSION)
            && drill.mutation_count() == mutations_after_a,
        "invalid signing and incompatible evidence left the target unchanged",
    ));

    drill.write_control("fail-health", TARGET_VERSION);
    drill.promote(TARGET_VERSION);
    let unhealthy_plan = {
        let stdout = drill.ok(&["plan", "--env", ENV]);
        let plan_id = plan_id_from(&stdout);
        let approval = drill.approvals.join(format!("{plan_id}.json"));
        drill.sign_plan(&plan_id, &approval);
        let failed = drill.fail(&[
            "apply",
            &plan_id,
            "--approval",
            approval.to_str().unwrap(),
            "--approval-trust-roots",
            drill.approval_trust.to_str().unwrap(),
        ]);
        assert!(
            failed.contains("ROLLBACK") || failed.contains("FAILED") || failed.contains("health"),
            "{failed}"
        );
        plan_id
    };
    drill.clear_control("fail-health");
    assert_eq!(drill.current_version().as_deref(), Some(SOURCE_VERSION));
    assert_eq!(drill.seed().as_deref(), Some(SEED));
    assert_eq!(drill.deployed().as_deref(), Some(SOURCE_VERSION));
    checks.push(check(
        "unhealthy_rollback",
        drill.current_version().as_deref() == Some(SOURCE_VERSION)
            && drill.seed().as_deref() == Some(SEED)
            && drill.deployed().as_deref() == Some(SOURCE_VERSION),
        format!("unhealthy {unhealthy_plan} restored A and preserved fixture data"),
    ));

    // Unhealthy B already accepted 1.1.0 on the target ledger. Forget that
    // key so the crash scenario pauses after a new accept, not a no-op replay.
    drill.forget_ledger(TARGET_VERSION);
    drill.write_control("crash-after-accept", TARGET_VERSION);
    let crash_plan = {
        let stdout = drill.ok(&["plan", "--env", ENV]);
        plan_id_from(&stdout)
    };
    let crash_approval = drill.approvals.join(format!("{crash_plan}.json"));
    drill.sign_plan(&crash_plan, &crash_approval);
    let mut apply_cmd = drill.command(&[
        "apply",
        &crash_plan,
        "--approval",
        crash_approval.to_str().unwrap(),
        "--approval-trust-roots",
        drill.approval_trust.to_str().unwrap(),
    ]);
    apply_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        apply_cmd.process_group(0);
    }
    let mut child = apply_cmd.spawn().expect("spawn crashing apply");
    let accepted = wait_for(Duration::from_secs(20), || {
        drill.ledger_contains(TARGET_VERSION)
            && drill.current_version().as_deref() == Some(TARGET_VERSION)
    });
    assert!(accepted, "fixture did not accept B before crash");
    let mutations_after_accept = drill.mutation_count();
    kill_group(&child);
    wait_exited(&mut child, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(200));
    drill.clear_control("crash-after-accept");

    let inspect_after_crash = drill.inspect_env();
    let tenkai_after_crash = inspect_after_crash
        .subscriptions
        .iter()
        .find(|row| row.product == PRODUCT)
        .and_then(|row| row.deployed.clone());
    let mismatch = tenkai_after_crash.as_deref() != Some(TARGET_VERSION)
        && drill.current_version().as_deref() == Some(TARGET_VERSION);
    checks.push(check(
        "crash_after_accept_mismatch",
        mismatch && drill.ledger_contains(TARGET_VERSION),
        format!(
            "target accepted B while Tenkai deployed={tenkai_after_crash:?}; recovery requires reconciliation"
        ),
    ));

    let lease_released = wait_for(Duration::from_secs(45), || {
        let inspect = drill.inspect_env();
        !inspect.lease.held
            || inspect
                .lease
                .expires_at_ms
                .is_some_and(|expires| expires <= tenkai::now_millis())
    });
    assert!(
        lease_released,
        "apply lease did not expire after executor loss"
    );
    let _ = drill.run(&["env", "unlock", ENV]);
    let _ = drill.run(&["reconcile", "--once"]);
    let resume_stdout = drill.ok(&["plan", "--env", ENV]);
    let resume_plan = plan_id_from(&resume_stdout);
    if resume_plan == crash_plan {
        let retry = drill.fail(&[
            "apply",
            &crash_plan,
            "--approval",
            crash_approval.to_str().unwrap(),
            "--approval-trust-roots",
            drill.approval_trust.to_str().unwrap(),
        ]);
        assert!(
            retry.contains("only computed or blocked")
                || retry.contains("running")
                || retry.contains("stale"),
            "{retry}"
        );
        drill.ok(&[
            "env",
            "reconcile",
            ENV,
            PRODUCT,
            "--deployed",
            TARGET_VERSION,
        ]);
    } else if resume_stdout.contains("up to date") {
        drill.ok(&[
            "env",
            "reconcile",
            ENV,
            PRODUCT,
            "--deployed",
            TARGET_VERSION,
        ]);
    } else {
        let approval = drill.approvals.join(format!("{resume_plan}.json"));
        drill.sign_plan(&resume_plan, &approval);
        drill.apply_signed(&resume_plan, &approval);
    }
    assert_eq!(drill.mutation_count(), mutations_after_accept);
    assert_eq!(drill.current_version().as_deref(), Some(TARGET_VERSION));
    assert_eq!(drill.seed().as_deref(), Some(SEED));
    assert_eq!(drill.deployed().as_deref(), Some(TARGET_VERSION));
    checks.push(check(
        "no_duplicate_after_restart",
        drill.mutation_count() == mutations_after_accept
            && drill.deployed().as_deref() == Some(TARGET_VERSION)
            && drill.current_version().as_deref() == Some(TARGET_VERSION),
        "restart reused the target ledger and did not repeat the accepted step",
    ));

    let stale = drill.inspect_env();
    let generation = stale.lease.generation.unwrap_or(0);
    let declaration = MigrationDeclaration {
        version: 1,
        profile: tenkai::package_migration::MIGRATION_PROFILE.into(),
        source: PackagePin {
            product: PRODUCT.into(),
            version: SOURCE_VERSION.into(),
            digest: source_digest.clone(),
        },
        target: PackagePin {
            product: PRODUCT.into(),
            version: TARGET_VERSION.into(),
            digest: target_digest.clone(),
        },
        compatibility: CompatibilityEvidence {
            version: 1,
            status: CompatibilityStatus::Compatible,
            evidence_digest: format!("sha256:{}", "c".repeat(64)),
        },
        checkpoints: vec![
            CheckpointDecl {
                id: "preflight".into(),
                class: CheckpointClass::Reversible,
                pre_admission: None,
            },
            CheckpointDecl {
                id: "switch".into(),
                class: CheckpointClass::Compensating,
                pre_admission: None,
            },
            CheckpointDecl {
                id: "drop-old".into(),
                class: CheckpointClass::Irreversible,
                pre_admission: Some("require_backup_receipt".into()),
            },
        ],
    };
    let declaration_path = drill.root.join("cutover.json");
    fs::write(
        &declaration_path,
        serde_json::to_vec_pretty(&declaration).unwrap(),
    )
    .unwrap();
    let backup = drill.root.join("tenkai.backup.db");
    drill.ok(&["backup", backup.to_str().unwrap()]);
    let backup_digest = sha256_file(&backup);
    let preview = drill.ok(&[
        "migrate",
        "preview",
        "cutover",
        "--env",
        ENV,
        "--declaration",
        declaration_path.to_str().unwrap(),
        "--backup-receipt-digest",
        &backup_digest,
    ]);
    let identity = identity_from(&preview);
    let migration_approval = drill.approvals.join("cutover.json");
    let migration_trust = drill.root.join("migration-trust.toml");
    drill.ok(&[
        "dev",
        "sign-migration-approval",
        "--identity",
        &identity,
        "--env",
        ENV,
        "--keys",
        drill.keys.to_str().unwrap(),
        "--approval",
        migration_approval.to_str().unwrap(),
        "--trust-roots",
        migration_trust.to_str().unwrap(),
    ]);
    let mut last = drill.ok(&[
        "migrate",
        "apply",
        "cutover",
        "--env",
        ENV,
        "--declaration",
        declaration_path.to_str().unwrap(),
        "--backup-receipt-digest",
        &backup_digest,
        "--approval",
        migration_approval.to_str().unwrap(),
        "--approval-trust-roots",
        migration_trust.to_str().unwrap(),
    ]);
    if last.contains("pending-plan") {
        let pending = pending_plan_from(&last);
        let plan_approval = drill.approvals.join(format!("{pending}.json"));
        drill.sign_plan(&pending, &plan_approval);
        last = drill.ok(&[
            "migrate",
            "resume",
            "cutover",
            "--approval",
            migration_approval.to_str().unwrap(),
            "--approval-trust-roots",
            migration_trust.to_str().unwrap(),
        ]);
    }
    let stale_resume = drill.fail(&[
        "migrate",
        "resume",
        "cutover",
        "--expected-generation",
        "999",
        "--approval",
        migration_approval.to_str().unwrap(),
        "--approval-trust-roots",
        migration_trust.to_str().unwrap(),
    ]);
    assert!(stale_resume.contains("stale fencing"), "{stale_resume}");
    checks.push(check(
        "stale_generation_rejected",
        stale_resume.contains("stale fencing"),
        format!("stale generation rejected; live generation was {generation}"),
    ));

    while last.contains("pending-plan") {
        let pending = pending_plan_from(&last);
        let plan_approval = drill.approvals.join(format!("{pending}.json"));
        if !plan_approval.is_file() {
            drill.sign_plan(&pending, &plan_approval);
        }
        last = drill.ok(&[
            "migrate",
            "resume",
            "cutover",
            "--approval",
            migration_approval.to_str().unwrap(),
            "--approval-trust-roots",
            migration_trust.to_str().unwrap(),
        ]);
    }
    assert!(
        last.contains("status=succeeded") || last.contains("status=running"),
        "{last}"
    );
    if !last.contains("status=succeeded") {
        last = drill.ok(&[
            "migrate",
            "resume",
            "cutover",
            "--approval",
            migration_approval.to_str().unwrap(),
            "--approval-trust-roots",
            migration_trust.to_str().unwrap(),
        ]);
        assert!(last.contains("status=succeeded"), "{last}");
    }
    let rollback_output = drill.run(&[
        "migrate",
        "rollback",
        "cutover",
        "--approval",
        migration_approval.to_str().unwrap(),
        "--approval-trust-roots",
        migration_trust.to_str().unwrap(),
    ]);
    let rollback = format!(
        "{}{}",
        String::from_utf8_lossy(&rollback_output.stdout),
        String::from_utf8_lossy(&rollback_output.stderr)
    );
    assert!(
        !rollback_output.status.success(),
        "irreversible rollback unexpectedly succeeded\n{rollback}"
    );
    assert!(
        rollback.to_ascii_lowercase().contains("recovery")
            || rollback.contains("irreversible")
            || rollback.contains("cannot claim success"),
        "{rollback}"
    );
    let status = drill.ok(&["migrate", "status", "cutover"]);
    assert!(status.contains("recovery_required"), "{status}");
    assert_eq!(drill.current_version().as_deref(), Some(TARGET_VERSION));
    assert_eq!(drill.seed().as_deref(), Some(SEED));
    checks.push(check(
        "irreversible_recovery_required",
        status.contains("recovery_required")
            && drill.current_version().as_deref() == Some(TARGET_VERSION)
            && drill.seed().as_deref() == Some(SEED),
        "accepted irreversible work stayed recovery_required without rolling application data",
    ));

    let isolated_db = drill.root.join("isolated.db");
    let mutations_before_restore = drill.mutation_count();
    let restored = Command::new(tenkaictl_bin())
        .arg("--database")
        .arg(&isolated_db)
        .args(["restore", backup.to_str().unwrap()])
        .env("TENKAI_MANAGEMENT_TOKEN", "stateful-drill-token")
        .env("TMPDIR", &drill.root)
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "isolated restore failed: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let isolated = Command::new(tenkaictl_bin())
        .arg("--database")
        .arg(&isolated_db)
        .args(["inspect"])
        .env("TENKAI_MANAGEMENT_TOKEN", "stateful-drill-token")
        .env("TMPDIR", &drill.root)
        .output()
        .unwrap();
    assert!(isolated.status.success());
    let isolated_out = String::from_utf8_lossy(&isolated.stdout);
    assert!(isolated_out.contains("embedded"), "{isolated_out}");
    assert!(
        !isolated_out.contains(SEED),
        "isolated inspect leaked application payload: {isolated_out}"
    );
    assert_eq!(drill.mutation_count(), mutations_before_restore);
    assert_eq!(drill.current_version().as_deref(), Some(TARGET_VERSION));
    checks.push(check(
        "backup_restore_isolated",
        drill.mutation_count() == mutations_before_restore
            && drill.current_version().as_deref() == Some(TARGET_VERSION),
        "restoring Tenkai state into an isolated database did not mutate or authorize the original target",
    ));

    let report = Report {
        schema: "tenkai.stateful-upgrade-drill/v1",
        passed: checks.iter().all(|item| item.passed),
        checks,
    };
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    assert!(
        report.passed,
        "stateful upgrade drill reported a failed check"
    );
}
