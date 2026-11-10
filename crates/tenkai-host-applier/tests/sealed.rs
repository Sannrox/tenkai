//! Sealed host values (ADR 0048 §4): read only from a memory-backed spool,
//! bound to the approved step, and written to root-owned files the applier
//! derives itself, atomically and idempotently.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tenkai::host_apply::HostAction;
use tenkai::host_apply::fixture::{HostFixture, StepSpec};
use tenkai::host_apply::sealed::{HostSealedValue, HostSealedValues, SEALED_FILE};
use tenkai::plan::{Action, SealedStep};
use tenkai::sealed_secret::{SealedTarget, SealedValue, SecretRef};
use tenkai_host_applier::{ApplierConfig, ApplierPaths, intake, secrets};
use zeroize::Zeroizing;

const VALUE: &str = "s3cret-plain-value";
const CIPHERTEXT: &[u8] = b"approved-ciphertext";

struct Host {
    roots: Vec<PathBuf>,
    paths: ApplierPaths,
    config: ApplierConfig,
    fixture: HostFixture,
}

impl Host {
    /// A host whose spool lives under `spool_base`.
    fn new(spool_base: &Path) -> Self {
        let name = format!(
            "tenkai-host-sealed-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let root = std::env::temp_dir().join(&name);
        let spool_root = spool_base.join(&name);
        let paths = ApplierPaths {
            config_dir: root.join("etc"),
            state_dir: root.join("state"),
            run_dir: root.join("run"),
        };
        for dir in [&paths.config_dir, &paths.state_dir, &paths.run_dir] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let config = ApplierConfig {
            version: 1,
            spool_dir: spool_root.join("spool"),
            timeout_seconds: 60,
            max_artifact_bytes: 1024 * 1024,
            max_artifact_entries: 1_000,
        };
        std::fs::create_dir_all(&config.spool_dir).unwrap();
        Self {
            roots: vec![root, spool_root],
            paths,
            config,
            fixture: HostFixture::new(&[("alice", &["ops"])], Vec::new()),
        }
    }

    /// Spool an approved install of `api` that writes `db/password`, with
    /// `values` next to the request. Returns the instance.
    fn spool(&self, approved_ciphertext: &[u8], values: Option<HostSealedValues>) -> String {
        // Staged on the spool's filesystem, so it can be renamed into place.
        let stage = self.roots[1].join(format!("stage-{}", uuid::Uuid::new_v4()));
        let release = self.fixture.release(
            &stage,
            "api",
            "1.0.0",
            ["./install.sh", "./uninstall.sh", "./health.sh"],
            &[("install.sh", b"#!/bin/sh\nexit 0\n")],
        );
        let now = tenkai::now_millis();
        let mut plan = self.fixture.plan(
            "edge",
            now,
            &[StepSpec {
                release: release.clone(),
                action: HostAction::Install,
                step_action: Action::Install,
                from: None,
                expected_generation: 0,
            }],
        );
        plan.steps[0].sealed = vec![SealedStep {
            secret: "db".into(),
            key: "password".into(),
            digest: digest(approved_ciphertext),
        }];
        let request = self.fixture.request(
            &plan,
            0,
            &release,
            vec![self.fixture.approve(&plan, 0, now)],
        );
        let instance = request.instance().unwrap();
        let dir = self.config.spool_dir.join(&instance);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("request.json"),
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        std::fs::rename(stage, dir.join("artifacts")).unwrap();
        if let Some(values) = values {
            std::fs::write(dir.join(SEALED_FILE), serde_json::to_vec(&values).unwrap()).unwrap();
        }
        instance
    }

    fn intake(&self, instance: &str) -> anyhow::Result<tenkai_host_applier::Intake> {
        intake(
            &self.paths,
            &self.config,
            &self.fixture.trust,
            instance,
            tenkai::now_millis(),
        )
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        for root in &self.roots {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

fn digest(ciphertext: &[u8]) -> String {
    let target =
        SealedTarget::new("edge", "api", SecretRef::new("db", "password").unwrap()).unwrap();
    tenkai::sealed_secret::digest(
        &target,
        &SealedValue {
            format_version: 1,
            ciphertext: STANDARD.encode(ciphertext),
            wraps: Vec::new(),
        },
    )
    .unwrap()
}

fn values(secret: &str, ciphertext: &[u8]) -> HostSealedValues {
    HostSealedValues::new(
        vec![HostSealedValue {
            secret: secret.into(),
            key: "password".into(),
            ciphertext: STANDARD.encode(ciphertext),
            value: Zeroizing::new(STANDARD.encode(VALUE)),
        }],
        None,
    )
}

/// A memory-backed directory for the spool, or `None` where there is none,
/// in which case the test that needs one says so and passes.
fn memory_backed() -> Option<PathBuf> {
    let shm = PathBuf::from("/dev/shm");
    tenkai::host_apply::sealed::require_memory_backed(&shm)
        .is_ok()
        .then_some(shm)
}

fn refusal(result: anyhow::Result<tenkai_host_applier::Intake>) -> String {
    let error = format!("{:#}", result.expect_err("intake must refuse"));
    assert!(
        !error.contains(VALUE),
        "a refusal carries the value: {error}"
    );
    error
}

#[test]
fn sealed_values_bind_to_the_approved_step_and_are_written_once() {
    let Some(shm) = memory_backed() else {
        eprintln!("skipped: no memory-backed /dev/shm on this host");
        return;
    };
    let host = Host::new(&shm);
    let instance = host.spool(CIPHERTEXT, Some(values("db", CIPHERTEXT)));
    let intake = host.intake(&instance).unwrap();
    assert_eq!(intake.secrets.len(), 1);
    // Nothing of the value is copied into the applier's work directory.
    let copied = host.paths.work_dir(&instance);
    assert!(!copied.join(SEALED_FILE).exists());

    let dir = secrets::write(&host.paths, &intake.verified, &intake.secrets).unwrap();
    assert_eq!(
        dir,
        secrets::instance_dir(&host.paths, secrets::SECRETS, &intake.verified).unwrap()
    );
    let file = dir.join("db").join("password");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), VALUE);
    let metadata = std::fs::metadata(&file).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());

    // A crash after the temporary file was written and before the rename
    // leaves it behind; the retry removes it and writes the same value.
    std::fs::write(
        dir.join("db")
            .join(format!(".tmp-{}", uuid::Uuid::new_v4().simple())),
        "partial",
    )
    .unwrap();
    secrets::write(&host.paths, &intake.verified, &intake.secrets).unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), VALUE);
    let names: Vec<_> = std::fs::read_dir(dir.join("db"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["password"]);
}

#[test]
fn values_that_do_not_match_the_approved_step_are_refused() {
    let Some(shm) = memory_backed() else {
        eprintln!("skipped: no memory-backed /dev/shm on this host");
        return;
    };
    let host = Host::new(&shm);
    // Another ciphertext than the approved one.
    let forged = host.spool(CIPHERTEXT, Some(values("db", b"forged-ciphertext")));
    assert!(refusal(host.intake(&forged)).contains("digest"));
    // A slot the approved step does not write.
    let other_slot = host.spool(CIPHERTEXT, Some(values("cache", CIPHERTEXT)));
    assert!(refusal(host.intake(&other_slot)).contains("slots"));
    // An approved step that writes values, with none spooled.
    let missing = host.spool(CIPHERTEXT, None);
    assert!(refusal(host.intake(&missing)).contains("none were spooled"));
}

#[test]
fn a_spool_on_persistent_storage_is_refused() {
    let disk = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    if tenkai::host_apply::sealed::require_memory_backed(&disk).is_ok() {
        eprintln!("skipped: the target directory is memory-backed on this host");
        return;
    }
    let host = Host::new(&disk);
    let instance = host.spool(CIPHERTEXT, Some(values("db", CIPHERTEXT)));
    assert!(refusal(host.intake(&instance)).contains("persistent storage"));
}

#[test]
fn a_directory_tenkai_did_not_create_is_never_written() {
    let Some(shm) = memory_backed() else {
        eprintln!("skipped: no memory-backed /dev/shm on this host");
        return;
    };
    let host = Host::new(&shm);
    let instance = host.spool(CIPHERTEXT, Some(values("db", CIPHERTEXT)));
    let intake = host.intake(&instance).unwrap();
    let dir = secrets::instance_dir(&host.paths, secrets::SECRETS, &intake.verified).unwrap();
    std::fs::create_dir_all(dir.join("db")).unwrap();
    std::fs::write(dir.join("db").join("password"), "someone else's").unwrap();

    let error = format!(
        "{:#}",
        secrets::write(&host.paths, &intake.verified, &intake.secrets).unwrap_err()
    );
    assert!(error.contains("not created by Tenkai"), "{error}");
    assert!(!error.contains(VALUE), "{error}");
    assert_eq!(
        std::fs::read_to_string(dir.join("db").join("password")).unwrap(),
        "someone else's"
    );
}

#[test]
fn a_crash_while_creating_the_instance_directory_never_strands_it() {
    let Some(shm) = memory_backed() else {
        eprintln!("skipped: no memory-backed /dev/shm on this host");
        return;
    };
    let host = Host::new(&shm);
    let instance = host.spool(CIPHERTEXT, Some(values("db", CIPHERTEXT)));
    let intake = host.intake(&instance).unwrap();
    let dir = secrets::instance_dir(&host.paths, secrets::SECRETS, &intake.verified).unwrap();
    // A crash left a half-made staging directory next to where the instance
    // directory goes, and no instance directory.
    let parent = dir.parent().unwrap().to_path_buf();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let key = |name: &str| tenkai::host_apply::product_key(name, "")[..16].to_string();
    std::fs::create_dir_all(parent.join(format!(".tmp-{}-{suffix}", key("api")))).unwrap();
    // Another instance's staging, never cleaned up for this one.
    let neighbour = format!(".tmp-{}-{suffix}", key("api-worker"));
    std::fs::create_dir_all(parent.join(&neighbour)).unwrap();

    secrets::write(&host.paths, &intake.verified, &intake.secrets).unwrap();
    assert!(dir.join(secrets::OWNED_MARKER).is_file());
    let names: Vec<_> = std::fs::read_dir(&parent)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let mut names = names;
    names.sort();
    assert_eq!(names, [neighbour.as_str(), "api"]);
}

#[test]
fn a_key_at_the_length_limit_is_written() {
    let Some(shm) = memory_backed() else {
        eprintln!("skipped: no memory-backed /dev/shm on this host");
        return;
    };
    let host = Host::new(&shm);
    let instance = host.spool(CIPHERTEXT, Some(values("db", CIPHERTEXT)));
    let intake = host.intake(&instance).unwrap();
    // The longest key a sealed value may name.
    let key = format!("k{}", "e".repeat(252));
    let secrets = [tenkai::host_apply::sealed::BoundSecret {
        secret: "db".into(),
        key: key.clone(),
        value: Zeroizing::new(VALUE.as_bytes().to_vec()),
    }];
    let dir = secrets::write(&host.paths, &intake.verified, &secrets).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.join("db").join(&key)).unwrap(),
        VALUE
    );
}

#[test]
fn a_long_instance_name_gets_its_secrets_directory() {
    let Some(shm) = memory_backed() else {
        eprintln!("skipped: no memory-backed /dev/shm on this host");
        return;
    };
    let host = Host::new(&shm);
    let instance = host.spool(CIPHERTEXT, Some(values("db", CIPHERTEXT)));
    let mut intake = host.intake(&instance).unwrap();
    // An instance name that fits a filename, with no room for a prefix.
    intake.verified.product_instance = format!("i{}", "n".repeat(250));
    let dir = secrets::write(&host.paths, &intake.verified, &intake.secrets).unwrap();
    assert!(dir.join(secrets::OWNED_MARKER).is_file());
    assert_eq!(
        std::fs::read_to_string(dir.join("db").join("password")).unwrap(),
        VALUE
    );
}
