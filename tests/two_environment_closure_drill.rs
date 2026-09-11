//! Two isolated environments share one signed multi-resource closure (#360).
//!
//! Proves Catalog pin identities, denial, restart idempotence, and rollback
//! without rebuilding member definitions. Signing uses `tenkaictl dev` keys.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tenkai::environment::EnvironmentInspectReport;

const PRODUCT: &str = "pkg";
const SOURCE: &str = "1.0.0";
const TARGET: &str = "1.1.0";
const ENVS: [&str; 2] = ["site-a", "site-b"];

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
            "tenkai-two-env-closure-{}-{}",
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
            .env("TENKAI_MANAGEMENT_TOKEN", "two-env-closure-token")
            .env("TENKAI_STATE_DIR", &self.state_dir)
            .env("TENKAI_EXECUTOR_GUARD", executor_guard_bin())
            .env("TMPDIR", &self.root)
            .env_remove("TENKAI_PLAN_APPROVAL_DIR")
            .env_remove("TENKAI_PLAN_APPROVAL_TRUST_ROOTS")
            .env_remove("TENKAI_SOFTWARE_EXECUTOR")
            .env_remove("TENKAI_HELM_BIN")
            .env_remove("TENKAI_KUBECTL_BIN")
            .env_remove("TENKAI_RUNTIME_EXECUTOR")
            .env_remove("TENKAI_DELIVERY_ADAPTER")
            .env_remove("TENKAI_GATE_URL")
            .env_remove("TENKAI_GATE_TOKEN");
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

    fn inspect_env(&self, env: &str) -> EnvironmentInspectReport {
        let stdout = self.ok(&["env", "inspect", env]);
        serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!("env inspect JSON: {error}\n{stdout}");
        })
    }

    fn deployed(&self, env: &str) -> Option<String> {
        self.inspect_env(env)
            .subscriptions
            .into_iter()
            .find(|row| row.product == PRODUCT)
            .and_then(|row| row.deployed)
    }

    fn inspect_release(&self, version: &str) -> serde_json::Value {
        let spec = format!("{PRODUCT}@{version}");
        let stdout = self.ok(&["release", "inspect", &spec]);
        serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!("release inspect JSON: {error}\n{stdout}");
        })
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

    fn publish_signed(&self, manifest: &Path, signature: &Path, evidence: Option<&Path>) {
        let mut args = vec![
            "publish",
            manifest.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
            "--trust-roots",
            self.release_trust.to_str().unwrap(),
        ];
        let evidence_s;
        if let Some(path) = evidence {
            evidence_s = path.to_str().unwrap().to_string();
            args.push("--change-set-evidence");
            args.push(&evidence_s);
        }
        self.ok(&args);
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

    fn apply_fail(&self, plan_id: &str, approval: &Path) -> String {
        self.fail(&[
            "apply",
            plan_id,
            "--approval",
            approval.to_str().unwrap(),
            "--approval-trust-roots",
            self.approval_trust.to_str().unwrap(),
        ])
    }

    fn plan_and_apply(&self, env: &str) -> String {
        let stdout = self.ok(&["plan", "--env", env]);
        let plan_id = plan_id_from(&stdout);
        let approval = self.approvals.join(format!("{plan_id}.json"));
        self.sign_plan(&plan_id, &approval);
        self.apply_signed(&plan_id, &approval);
        plan_id
    }

    fn rollback_and_apply(&self, env: &str) {
        let combined = self.fail(&["rollback", PRODUCT, "--env", env]);
        let plan_id = plan_id_from_approval_required(&combined);
        let approval = self.approvals.join(format!("{plan_id}.json"));
        self.sign_plan(&plan_id, &approval);
        self.apply_signed(&plan_id, &approval);
    }

    fn fail_publish(&self, manifest: &Path, signature: &Path, evidence: &Path) -> String {
        self.fail(&[
            "publish",
            manifest.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
            "--trust-roots",
            self.release_trust.to_str().unwrap(),
            "--change-set-evidence",
            evidence.to_str().unwrap(),
        ])
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

fn plan_id_from_approval_required(text: &str) -> String {
    text.split_whitespace()
        .skip_while(|token| *token != "plan")
        .nth(1)
        .map(|token| token.trim_end_matches(['.', '`', '\'']).to_string())
        .filter(|value| value.starts_with("tenkai:plan:"))
        .unwrap_or_else(|| panic!("missing rollback plan id in:\n{text}"))
}

fn pin_members(view: &serde_json::Value) -> Vec<(String, String, String)> {
    view["change_set_pin"]["members"]
        .as_array()
        .unwrap_or_else(|| panic!("missing change_set_pin.members: {view}"))
        .iter()
        .map(|member| {
            (
                member["kind"].as_str().unwrap_or_default().to_string(),
                member["id"].as_str().unwrap_or_default().to_string(),
                member["digest"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[test]
fn signed_closure_reaches_two_environments_without_rebuilding_members() {
    let examples = repo_root().join("examples/two-environment-closure");
    let source = examples.join("source/tenkai.toml");
    let target = examples.join("target/tenkai.toml");
    let evidence = examples.join("closure.json");
    let drill = Drill::new();

    drill.ok(&["init"]);
    for env in ENVS {
        drill.ok(&["env", "add", env, "--description", "two-env closure drill"]);
    }
    drill.ok(&["dev", "init-keys", "--dir", drill.keys.to_str().unwrap()]);

    let source_sig = drill.root.join("source.sig.json");
    let target_sig = drill.root.join("target.sig.json");
    drill.sign_release(&source, &source_sig);
    drill.sign_release(&target, &target_sig);
    drill.publish_signed(&source, &source_sig, None);

    let accepted: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&evidence).unwrap()).unwrap();
    let mut unaccepted = accepted.clone();
    unaccepted["status"] = serde_json::Value::String("unaccepted".into());
    let unaccepted_path = drill.root.join("unaccepted-closure.json");
    fs::write(
        &unaccepted_path,
        serde_json::to_vec_pretty(&unaccepted).unwrap(),
    )
    .unwrap();
    let unaccepted_err = drill.fail_publish(&target, &target_sig, &unaccepted_path);
    assert!(unaccepted_err.contains("not accepted"), "{unaccepted_err}");

    let mut missing = accepted.clone();
    missing["members"] = serde_json::Value::Array(Vec::new());
    let missing_path = drill.root.join("missing-members.json");
    fs::write(&missing_path, serde_json::to_vec_pretty(&missing).unwrap()).unwrap();
    let missing_err = drill.fail_publish(&target, &target_sig, &missing_path);
    assert!(
        missing_err.contains("incomplete")
            || missing_err.contains("members do not match")
            || missing_err.contains("at least one member"),
        "{missing_err}"
    );

    let mut tampered = accepted.clone();
    tampered["members"][0]["digest"] =
        serde_json::Value::String(format!("sha256:{}", "f".repeat(64)));
    let tampered_path = drill.root.join("tampered-closure.json");
    fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let tampered_err = drill.fail_publish(&target, &target_sig, &tampered_path);
    assert!(
        tampered_err.contains("members do not match"),
        "{tampered_err}"
    );

    drill.publish_signed(&target, &target_sig, Some(&evidence));

    let first = drill.inspect_release(TARGET);
    assert_eq!(first["status"].as_str(), Some("verified"), "{first}");
    let pin_digest = first["change_set_pin"]["pin_digest"]
        .as_str()
        .expect("pin_digest")
        .to_string();
    let members = pin_members(&first);
    assert_eq!(members.len(), 2, "{first}");

    drill.publish_signed(&target, &target_sig, Some(&evidence));
    let replay = drill.inspect_release(TARGET);
    assert_eq!(
        replay["change_set_pin"]["pin_digest"].as_str(),
        Some(pin_digest.as_str()),
        "{replay}"
    );
    assert_eq!(pin_members(&replay), members);

    let conflict = drill.fail_publish(&target, &target_sig, &tampered_path);
    assert!(
        conflict.contains("members do not match")
            || conflict.contains("different immutable change-set pin"),
        "{conflict}"
    );

    drill.promote(SOURCE);
    for env in ENVS {
        drill.ok(&["env", "subscribe", env, &format!("{PRODUCT}=stable")]);
        drill.plan_and_apply(env);
        assert_eq!(drill.deployed(env).as_deref(), Some(SOURCE), "{env}");
    }

    drill.promote(TARGET);
    let mut completed = Vec::new();
    for env in ENVS {
        let stdout = drill.ok(&["plan", "--env", env]);
        let plan_id = plan_id_from(&stdout);
        let approval = drill.approvals.join(format!("{plan_id}.json"));
        drill.sign_plan(&plan_id, &approval);
        completed.push(plan_id);
    }
    let stale = drill.apply_fail(
        &completed[0],
        &drill.approvals.join(format!("{}.json", completed[1])),
    );
    assert!(
        stale.contains("approval") || stale.contains("identity") || stale.contains("bound"),
        "{stale}"
    );
    for env in ENVS {
        assert_eq!(drill.deployed(env).as_deref(), Some(SOURCE), "{env}");
    }
    for (env, plan_id) in ENVS.iter().zip(completed.iter()) {
        let approval = drill.approvals.join(format!("{plan_id}.json"));
        drill.apply_signed(plan_id, &approval);
        assert_eq!(drill.deployed(env).as_deref(), Some(TARGET), "{env}");
    }
    assert_eq!(
        pin_members(&drill.inspect_release(TARGET)),
        members,
        "member identities changed after promotion"
    );

    for plan_id in &completed {
        let approval = drill.approvals.join(format!("{plan_id}.json"));
        let replayed = drill.apply_fail(plan_id, &approval);
        assert!(
            replayed.contains("stale")
                || replayed.contains("cannot transition")
                || replayed.contains("succeeded"),
            "completed plan replayed effects:\n{replayed}"
        );
    }
    for env in ENVS {
        assert_eq!(drill.deployed(env).as_deref(), Some(TARGET), "{env}");
    }

    for env in ENVS {
        drill.rollback_and_apply(env);
        assert_eq!(drill.deployed(env).as_deref(), Some(SOURCE), "{env}");
    }
    let after_rollback = drill.inspect_release(TARGET);
    assert_eq!(
        after_rollback["change_set_pin"]["pin_digest"].as_str(),
        Some(pin_digest.as_str()),
        "rollback must not rewrite the Catalog pin: {after_rollback}"
    );
    assert_eq!(pin_members(&after_rollback), members);

    drill.ok(&["release", "recall", &format!("{PRODUCT}@{TARGET}")]);
    for env in ENVS {
        let blocked = drill.fail(&["plan", "--env", env]);
        assert!(
            blocked.contains("recall") || blocked.contains("recalled"),
            "{env}: {blocked}"
        );
        assert_eq!(drill.deployed(env).as_deref(), Some(SOURCE), "{env}");
    }
}
