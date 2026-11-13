//! Governed laptop path: signed release, required approval, health, rollback (#1081).
//!
//! `tenkaictl quickstart` prepares lab keys and a non-local environment. The
//! journey then publishes hello-local, refuses apply without a signed approval,
//! applies 0.1.0, and rolls 0.2.0 back to 0.1.0. Duration is recorded; a run
//! longer than 15 minutes fails the job.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

mod common;

use tenkai::environment::EnvironmentInspectReport;

const ENV: &str = "lab";
const PRODUCT: &str = "hello-local";
const MAX_JOURNEY_MS: u128 = 900_000;

fn repo_product(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("tenkai.toml"),
        r#"
[product]
name = "hello-local"
version = "0.1.0"
description = "Demo product: writes its version to .state/version"

[deploy]
workdir = "."
install = "mkdir -p .state && echo 0.1.0 > .state/version"
health = "grep -qx 0.1.0 .state/version"
uninstall = "rm -f .state/version"
"#,
    )
    .unwrap();
    fs::write(
        dir.join("broken.toml"),
        r#"
[product]
name = "hello-local"
version = "0.2.0"
description = "Demo release whose health probe always fails, to show automatic rollback"

[deploy]
workdir = "."
install = "mkdir -p .state && echo 0.2.0 > .state/version"
health = "false"
uninstall = "rm -f .state/version"
"#,
    )
    .unwrap();
}

struct Journey {
    cli: common::CliDrill,
    lab: PathBuf,
    product: PathBuf,
}

impl Journey {
    fn new() -> Self {
        let cli = common::CliDrill::new(
            "tenkai-governed-quickstart",
            "governed-quickstart-token",
            &["TENKAI_GATE_URL", "TENKAI_GATE_TOKEN"],
        );
        let lab = cli.root.join("lab");
        let product = cli.root.join("hello-local");
        repo_product(&product);
        Self { cli, lab, product }
    }

    fn bind_lab_keys(&mut self) {
        self.cli.keys = self.lab.join("keys");
        self.cli.release_trust = self.lab.join("release-trust.toml");
        self.cli.approval_trust = self.lab.join("approval-trust.toml");
    }

    fn deployed(&self) -> Option<String> {
        let stdout = self.cli.ok(&["env", "inspect", ENV]);
        let report: EnvironmentInspectReport = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("env inspect JSON: {error}\n{stdout}"));
        report
            .subscriptions
            .into_iter()
            .find(|row| row.product == PRODUCT)
            .and_then(|row| row.deployed)
    }

    fn publish_signed(&self, manifest: &Path, signature: &Path) {
        self.cli.ok(&[
            "publish",
            manifest.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
            "--trust-roots",
            self.cli.release_trust.to_str().unwrap(),
        ]);
    }
}

#[test]
fn governed_quickstart_requires_approval_and_rolls_back() {
    let started = Instant::now();
    let mut journey = Journey::new();
    let lab = journey.lab.to_str().unwrap();

    let refused = journey
        .cli
        .fail(&["quickstart", "--dir", lab, "--env", "local"]);
    assert!(
        refused.contains("refuses the built-in local environment"),
        "{refused}"
    );

    let prepared = journey.cli.ok(&["quickstart", "--dir", lab, "--env", ENV]);
    journey.cli.ok(&["quickstart", "--dir", lab, "--env", ENV]);
    journey
        .cli
        .ok(&["env", "add", "stage", "--description", "existing"]);
    let rebound = journey
        .cli
        .fail(&["quickstart", "--dir", lab, "--env", "stage"]);
    assert!(
        rebound.contains("refuses to bind an existing environment"),
        "{rebound}"
    );
    assert!(
        prepared.contains("WARNING: development-only keys"),
        "{prepared}"
    );
    assert!(prepared.contains("lab-only"), "{prepared}");
    journey.bind_lab_keys();
    assert!(journey.cli.keys.join("release.ed25519").is_file());
    assert!(journey.cli.release_trust.is_file());
    assert!(journey.cli.approval_trust.is_file());
    assert!(journey.lab.join("approval-policy.toml").is_file());

    let healthy = journey.product.join("tenkai.toml");
    let broken = journey.product.join("broken.toml");
    let sig_ok = journey.cli.root.join("hello-local-0.1.0.sig.json");
    let sig_bad = journey.cli.root.join("hello-local-0.2.0.sig.json");

    journey.cli.sign_release(&healthy, &sig_ok);
    journey.publish_signed(&healthy, &sig_ok);
    journey.cli.ok(&["promote", "hello-local@0.1.0", "stable"]);
    journey
        .cli
        .ok(&["env", "subscribe", ENV, "hello-local=stable"]);

    let plan_out = journey.cli.ok(&["plan", "--env", ENV]);
    let plan_id = common::plan_id_from(&plan_out);
    let unapproved = journey.cli.fail(&["apply", &plan_id]);
    assert!(
        unapproved.to_lowercase().contains("approval"),
        "apply without approval must fail closed:\n{unapproved}"
    );
    let bypass = journey.cli.fail(&[
        "apply",
        &plan_id,
        "--allow-unapproved-development",
        "--development-reason",
        "lab",
    ]);
    assert!(
        bypass.contains("built-in local environment"),
        "lab must refuse the local-development bypass:\n{bypass}"
    );

    let approval = journey.cli.approvals.join(format!("{plan_id}.json"));
    journey.cli.sign_plan(&plan_id, &approval);
    journey.cli.apply_signed(&plan_id, &approval);
    assert_eq!(journey.deployed().as_deref(), Some("0.1.0"));

    journey.cli.sign_release(&broken, &sig_bad);
    journey.publish_signed(&broken, &sig_bad);
    journey.cli.ok(&["promote", "hello-local@0.2.0", "stable"]);
    let broken_plan = common::plan_id_from(&journey.cli.ok(&["plan", "--env", ENV]));
    let broken_approval = journey.cli.approvals.join(format!("{broken_plan}.json"));
    journey.cli.sign_plan(&broken_plan, &broken_approval);
    let rolled = journey.cli.fail(&[
        "apply",
        &broken_plan,
        "--approval",
        broken_approval.to_str().unwrap(),
        "--approval-trust-roots",
        journey.cli.approval_trust.to_str().unwrap(),
    ]);
    assert!(
        rolled.contains("ROLLBACK"),
        "broken 0.2.0 must roll back:\n{rolled}"
    );
    assert_eq!(journey.deployed().as_deref(), Some("0.1.0"));

    let elapsed_ms = started.elapsed().as_millis();
    eprintln!("governed_quickstart journey_ms={elapsed_ms}");
    assert!(
        elapsed_ms <= MAX_JOURNEY_MS,
        "governed quickstart journey took {elapsed_ms}ms (limit {MAX_JOURNEY_MS}ms)"
    );
}
