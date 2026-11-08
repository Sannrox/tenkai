//! Drive `tenkaictl env bind` / `env unbind` against two providers of one contract.

use std::collections::BTreeMap;
use std::fs;

use tenkai::software_compatibility::{
    CompatibilityEvidence, ComponentObservation, ComponentPin, MigrationState,
};

#[allow(dead_code)]
mod common;

const PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct BindDrill {
    cli: common::CliDrill,
}

impl BindDrill {
    fn new() -> Self {
        Self {
            cli: common::CliDrill::new("tenkai-env-bind", "env-bind-token", &[]),
        }
    }

    fn write_release(&self, product: &str, extra: &str) -> String {
        let dir = self.cli.root.join(product);
        fs::create_dir_all(&dir).unwrap();
        let raw = format!(
            "[product]\nname = \"{product}\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n[compatibility]\nversion = 1\nmax_evidence_age_ms = 60000\n[compatibility.components.{product}.pin]\nkind = \"revision\"\nvalue = \"{PIN}\"\n{extra}"
        );
        fs::write(dir.join("tenkai.toml"), &raw).unwrap();
        raw
    }

    fn publish(&self, product: &str) {
        let manifest = self.cli.root.join(product).join("tenkai.toml");
        self.cli.ok(&[
            "publish",
            manifest.to_str().unwrap(),
            "--allow-unsigned-development",
        ]);
        self.cli
            .ok(&["promote", &format!("{product}@1.0.0"), "stable"]);
    }

    fn record_evidence(
        &self,
        product: &str,
        raw: &str,
        requires: BTreeMap<String, String>,
        provides: BTreeMap<String, String>,
    ) {
        let evidence = CompatibilityEvidence {
            version: 1,
            release_digest: tenkai::manifest::digest(raw),
            environment: "local".into(),
            observed_at_ms: tenkai::now_millis() - 1_000,
            components: BTreeMap::from([(
                product.into(),
                ComponentObservation {
                    pin: ComponentPin::Revision(PIN.into()),
                    requires,
                    provides,
                },
            )]),
            contracts: BTreeMap::new(),
            capabilities: Vec::new(),
            schema_version: None,
            migration: MigrationState::Stable,
        };
        let path = self.cli.root.join(format!("{product}-evidence.json"));
        fs::write(&path, serde_json::to_vec(&evidence).unwrap()).unwrap();
        self.cli.ok(&[
            "env",
            "compatibility",
            "record",
            "local",
            path.to_str().unwrap(),
        ]);
    }
}

fn run_sequence(drill: &BindDrill) {
    let app = drill.write_release(
        "app",
        "[compatibility.components.app.requires]\ndatabase = \"1.0.0\"\n",
    );
    let db_a = drill.write_release(
        "db-a",
        "[compatibility.components.db-a.provides]\ndatabase = \"1.0.0\"\n",
    );
    let db_b = drill.write_release(
        "db-b",
        "[compatibility.components.db-b.provides]\ndatabase = \"1.1.0\"\n",
    );
    drill.cli.ok(&["init"]);
    drill.cli.ok(&["env", "add", "local"]);
    for product in ["app", "db-a", "db-b"] {
        drill.publish(product);
        drill
            .cli
            .ok(&["env", "subscribe", "local", &format!("{product}=stable")]);
    }
    drill.record_evidence(
        "app",
        &app,
        BTreeMap::from([("database".into(), "1.0.0".into())]),
        BTreeMap::new(),
    );
    drill.record_evidence(
        "db-a",
        &db_a,
        BTreeMap::new(),
        BTreeMap::from([("database".into(), "1.0.0".into())]),
    );
    drill.record_evidence(
        "db-b",
        &db_b,
        BTreeMap::new(),
        BTreeMap::from([("database".into(), "1.1.0".into())]),
    );
    drill
        .cli
        .ok(&["env", "reconcile", "local", "db-a", "--deployed", "1.0.0"]);
    drill
        .cli
        .ok(&["env", "reconcile", "local", "db-b", "--deployed", "1.0.0"]);

    let unbound = drill.cli.fail(&["plan", "--env", "local"]);
    assert!(unbound.contains("db-a"), "{unbound}");
    assert!(unbound.contains("db-b"), "{unbound}");

    let deps = drill.cli.ok(&["env", "dependencies", "local"]);
    assert!(deps.contains("db-a"), "{deps}");
    assert!(deps.contains("db-b"), "{deps}");

    let missing = drill
        .cli
        .fail(&["env", "bind", "local", "app", "database=missing"]);
    assert!(missing.contains("app"), "{missing}");
    assert!(missing.contains("database"), "{missing}");
    assert!(missing.contains("missing"), "{missing}");

    let bound = drill
        .cli
        .ok(&["env", "bind", "local", "app", "database=db-a"]);
    assert!(bound.contains("db-a"), "{bound}");

    let planned = drill.cli.ok(&["plan", "--env", "local"]);
    assert!(planned.contains("plan id:"), "{planned}");

    drill
        .cli
        .ok(&["env", "reconcile", "local", "app", "--deployed", "1.0.0"]);
    let unbind = drill
        .cli
        .fail(&["env", "unbind", "local", "app", "database"]);
    assert!(unbind.contains("app"), "{unbind}");
    assert!(unbind.contains("database"), "{unbind}");
}

#[test]
fn tenkaictl_env_bind_selects_one_of_several_providers() {
    run_sequence(&BindDrill::new());
    run_sequence(&BindDrill::new());
}
