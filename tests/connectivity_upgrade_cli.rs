//! Launch `tenkaictl upgrade` across connected, intermittent, and isolated
//! environments and assert status content — not just environment connectivity.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use tenkai::client::Ctx;
use tenkai::connectivity;
use tenkai::release_signing::{TRUST_ROOT_VERSION, TrustRoots, key_id};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tenkaictl"))
}

fn tenkaictl(db: &Path, args: &[&str]) -> String {
    let output = Command::new(bin())
        .arg("--database")
        .arg(db)
        .args(args)
        .env("TENKAI_MANAGEMENT_TOKEN", "cli-upgrade-secret")
        .output()
        .unwrap_or_else(|error| panic!("failed to launch tenkaictl: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "tenkaictl {args:?} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    stdout
}

fn write_offline_trust(path: &Path, exporter: &SigningKey, runtime: &SigningKey) {
    let exporter_key =
        base64::engine::general_purpose::STANDARD.encode(exporter.verifying_key().to_bytes());
    let runtime_key =
        base64::engine::general_purpose::STANDARD.encode(runtime.verifying_key().to_bytes());
    std::fs::write(
        path,
        format!(
            r#"version = {TRUST_ROOT_VERSION}

[[signers]]
key_id = "{}"
identity = "exporter"
public_key = "{exporter_key}"

[[signers]]
key_id = "{}"
identity = "airgap-runtime"
public_key = "{runtime_key}"
"#,
            key_id(&exporter.verifying_key().to_bytes()),
            key_id(&runtime.verifying_key().to_bytes()),
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn tenkaictl_upgrade_reports_three_class_status() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-upgrade-cli-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("tenkai.db");
    let product = root.join("product");
    std::fs::create_dir_all(&product).unwrap();
    std::fs::write(
        product.join("tenkai.toml"),
        r#"
[product]
name = "edge-app"
version = "1.0.0"

[deploy]
install = "true"
"#,
    )
    .unwrap();

    tenkaictl(&db, &["init"]);
    tenkaictl(
        &db,
        &[
            "dev",
            "init-keys",
            "--dir",
            root.join("keys").to_str().unwrap(),
        ],
    );
    tenkaictl(
        &db,
        &[
            "dev",
            "sign-release",
            product.join("tenkai.toml").to_str().unwrap(),
            "--keys",
            root.join("keys").to_str().unwrap(),
            "--signature",
            product.join("release.sig.json").to_str().unwrap(),
            "--trust-roots",
            product.join("release-trust.toml").to_str().unwrap(),
        ],
    );
    tenkaictl(
        &db,
        &[
            "publish",
            product.join("tenkai.toml").to_str().unwrap(),
            "--signature",
            product.join("release.sig.json").to_str().unwrap(),
            "--trust-roots",
            product.join("release-trust.toml").to_str().unwrap(),
        ],
    );
    tenkaictl(&db, &["promote", "edge-app@1.0.0", "stable"]);
    for (env, class) in [
        ("site-a", "connected"),
        ("site-b", "intermittent"),
        ("site-c", "isolated"),
    ] {
        tenkaictl(&db, &["env", "add", env, "--description", class]);
        tenkaictl(&db, &["env", "connectivity", env, class]);
        tenkaictl(&db, &["env", "subscribe", env, "edge-app=stable"]);
    }

    let started = tenkaictl(
        &db,
        &[
            "upgrade",
            "start",
            "fleet-1",
            "--product",
            "edge-app",
            "--version",
            "1.0.0",
            "--channel",
            "stable",
            "--cohort",
            "site-a,site-b,site-c",
        ],
    );
    eprintln!("upgrade start:\n{started}");
    assert!(started.contains("status admitted"), "{started}");

    let record = {
        let mut ctx = Ctx::embedded(&db).unwrap();
        connectivity::load_upgrade(&mut ctx, "fleet-1")
            .await
            .unwrap()
    };
    let approval_dir = root.join("approvals");
    std::fs::create_dir_all(&approval_dir).unwrap();
    let approval_trust = root.join("approval-trust.toml");
    for environment in &record.environments {
        let plan_id = environment.plan_id.as_deref().unwrap();
        let envelope = approval_dir.join(format!("{}.json", environment.name));
        tenkaictl(
            &db,
            &[
                "dev",
                "sign-approval",
                plan_id,
                "--keys",
                root.join("keys").to_str().unwrap(),
                "--approval",
                envelope.to_str().unwrap(),
                "--trust-roots",
                approval_trust.to_str().unwrap(),
            ],
        );
    }

    let connected = tenkaictl(
        &db,
        &[
            "upgrade",
            "advance",
            "fleet-1",
            "--approval",
            approval_dir.join("site-a.json").to_str().unwrap(),
            "--approval-trust-roots",
            approval_trust.to_str().unwrap(),
        ],
    );
    eprintln!("upgrade advance connected:\n{connected}");
    assert!(
        connected.contains("site-a connected applied"),
        "{connected}"
    );

    let interrupted = tenkaictl(&db, &["upgrade", "interrupt", "fleet-1", "site-b"]);
    eprintln!("upgrade interrupt:\n{interrupted}");
    assert!(
        interrupted.contains("site-b intermittent interrupted"),
        "{interrupted}"
    );
    tenkaictl(&db, &["upgrade", "resume", "fleet-1", "site-b"]);
    let resumed = tenkaictl(
        &db,
        &[
            "upgrade",
            "advance",
            "fleet-1",
            "--approval",
            approval_dir.join("site-b.json").to_str().unwrap(),
            "--approval-trust-roots",
            approval_trust.to_str().unwrap(),
        ],
    );
    eprintln!("upgrade advance intermittent:\n{resumed}");
    assert!(resumed.contains("site-b intermittent applied"), "{resumed}");

    let isolated = tenkaictl(
        &db,
        &[
            "upgrade",
            "advance",
            "fleet-1",
            "--approval",
            approval_dir.join("site-c.json").to_str().unwrap(),
            "--approval-trust-roots",
            approval_trust.to_str().unwrap(),
        ],
    );
    eprintln!("upgrade advance isolated before bundle:\n{isolated}");
    assert!(
        isolated.contains("site-c isolated interrupted"),
        "{isolated}"
    );
    assert!(
        isolated.contains("verified offline bundle") || isolated.contains("requires a verified"),
        "{isolated}"
    );

    let record = {
        let mut ctx = Ctx::embedded(&db).unwrap();
        connectivity::load_upgrade(&mut ctx, "fleet-1")
            .await
            .unwrap()
    };
    let exporter = SigningKey::from_bytes(&[7; 32]);
    let runtime = SigningKey::from_bytes(&[9; 32]);
    let now = tenkai::now_millis();
    let bundle = connectivity::export_isolated_bundle(
        "site-c",
        record.environments[2].plan_id.as_deref().unwrap(),
        &record.release_id,
        b"immutable payload",
        &exporter,
        now,
    )
    .unwrap();
    let offline_trust = root.join("offline-trust.toml");
    write_offline_trust(&offline_trust, &exporter, &runtime);
    let bundle_path = root.join("site-c.bundle.json");
    bundle.save(&bundle_path).unwrap();
    tenkaictl(
        &db,
        &[
            "upgrade",
            "bind-bundle",
            "fleet-1",
            "site-c",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--trust-roots",
            offline_trust.to_str().unwrap(),
        ],
    );
    let verified = bundle
        .verify(
            &TrustRoots::load(&offline_trust).unwrap(),
            tenkai::ontology::NS,
            "site-c",
            tenkai::now_millis(),
        )
        .unwrap();
    let receipt = connectivity::export_isolated_receipt(
        &verified,
        &runtime,
        "runtime-1",
        "step-1",
        b"installed",
        tenkai::now_millis(),
    )
    .unwrap();
    let receipt_path = root.join("site-c.receipt.json");
    receipt.save(&receipt_path).unwrap();
    tenkaictl(
        &db,
        &[
            "upgrade",
            "import-receipt",
            "fleet-1",
            "site-c",
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--trust-roots",
            offline_trust.to_str().unwrap(),
        ],
    );
    let finished = tenkaictl(
        &db,
        &[
            "upgrade",
            "advance",
            "fleet-1",
            "--approval",
            approval_dir.join("site-c.json").to_str().unwrap(),
            "--approval-trust-roots",
            approval_trust.to_str().unwrap(),
        ],
    );
    eprintln!("upgrade advance isolated applied:\n{finished}");
    assert!(finished.contains("status succeeded"), "{finished}");
    assert!(finished.contains("site-a connected applied"), "{finished}");
    assert!(
        finished.contains("site-b intermittent applied"),
        "{finished}"
    );
    assert!(finished.contains("site-c isolated applied"), "{finished}");
    let status = tenkaictl(&db, &["upgrade", "status", "fleet-1"]);
    eprintln!("upgrade status:\n{status}");
    assert!(status.contains("site-a connected applied"), "{status}");
    assert!(status.contains("site-b intermittent applied"), "{status}");
    assert!(status.contains("site-c isolated applied"), "{status}");

    let _ = std::fs::remove_dir_all(root);
}
