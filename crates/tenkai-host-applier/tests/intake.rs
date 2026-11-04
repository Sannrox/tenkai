//! Intake: the spooled request is copied without following links, and only
//! the copy is verified.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tenkai::host_apply::fixture::{HostFixture, SignedRelease, StepSpec};
use tenkai::host_apply::{HostAction, HostApplyRequest};
use tenkai::plan::Action;
use tenkai_host_applier::{ApplierConfig, ApplierPaths, config, intake};

struct Host {
    root: PathBuf,
    paths: ApplierPaths,
    config: ApplierConfig,
    fixture: HostFixture,
}

impl Host {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "tenkai-host-applier-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
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
            spool_dir: root.join("spool"),
            timeout_seconds: 60,
            max_artifact_bytes: 1024 * 1024,
            max_artifact_entries: 1_000,
        };
        std::fs::create_dir_all(&config.spool_dir).unwrap();
        Self {
            root,
            paths,
            config,
            fixture: HostFixture::new(&[("alice", &["ops"])], Vec::new()),
        }
    }

    /// Sign a release with an install script and a binary directory.
    fn release(&self) -> (PathBuf, SignedRelease) {
        let stage = self.root.join(format!("stage-{}", uuid::Uuid::new_v4()));
        let release = self.fixture.release(
            &stage,
            "k3s",
            "1.2.0",
            ["./install.sh", "./uninstall.sh", "./health.sh"],
            &[
                ("install.sh", b"#!/bin/sh\nexit 0\n"),
                ("bin/k3s", b"binary"),
                ("bin/lib/helper", b"helper"),
            ],
        );
        (stage, release)
    }

    /// Spool a signed, approved install request and return its instance.
    fn spool(&self) -> (String, HostApplyRequest) {
        let (stage, release) = self.release();
        self.spool_release(stage, release)
    }

    fn spool_release(&self, stage: PathBuf, release: SignedRelease) -> (String, HostApplyRequest) {
        let now = tenkai::now_millis();
        let plan = self.fixture.plan(
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
        (instance, request)
    }

    fn spooled(&self, instance: &str) -> PathBuf {
        self.config.spool_dir.join(instance)
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
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn refusal(result: anyhow::Result<tenkai_host_applier::Intake>) -> String {
    format!("{:#}", result.expect_err("intake must refuse"))
}

#[test]
fn intake_copies_then_verifies_the_copy() {
    let host = Host::new();
    let (instance, _) = host.spool();
    let intake = host.intake(&instance).unwrap();
    assert_eq!(intake.verified.instance, instance);
    let work = host.paths.work_dir(&instance);
    assert_eq!(intake.copied.workdir, work.join("artifacts"));
    assert_eq!(
        std::fs::read(work.join("artifacts/bin/lib/helper")).unwrap(),
        b"helper"
    );
    assert_eq!(
        std::fs::metadata(&work).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // A second run of the same instance starts from a fresh copy.
    host.intake(&instance).unwrap();
}

#[test]
fn a_file_swapped_after_the_copy_is_never_read() {
    let host = Host::new();
    let (instance, _) = host.spool();
    let intake = host.intake(&instance).unwrap();
    std::fs::write(
        host.spooled(&instance).join("artifacts/install.sh"),
        b"rm -rf /",
    )
    .unwrap();
    // The verified workdir is the copy, which still matches the signature.
    assert_eq!(
        std::fs::read(intake.copied.workdir.join("install.sh")).unwrap(),
        b"#!/bin/sh\nexit 0\n"
    );
    let reverified = tenkai::host_apply::verify_copied_request(
        &intake.copied.request,
        &instance,
        &intake.copied.workdir,
        &host.fixture.trust,
        tenkai::now_millis(),
    );
    reverified.unwrap();
    // A fresh intake copies the tampered spool and refuses it.
    assert!(refusal(host.intake(&instance)).contains("do not match their signed digest"));
}

#[test]
fn symlinks_anywhere_in_the_request_are_refused() {
    let host = Host::new();
    let outside = host.root.join("outside");
    std::fs::write(&outside, b"secret").unwrap();

    let (instance, _) = host.spool();
    let file = host.spooled(&instance).join("artifacts/bin/k3s");
    std::fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(&outside, &file).unwrap();
    assert!(refusal(host.intake(&instance)).contains("symbolic link"));

    let (instance, _) = host.spool();
    let dir = host.spooled(&instance).join("artifacts/bin");
    std::fs::rename(&dir, host.root.join(format!("moved-{instance}"))).unwrap();
    std::os::unix::fs::symlink(host.root.join(format!("moved-{instance}")), &dir).unwrap();
    assert!(refusal(host.intake(&instance)).contains("symbolic link"));

    let (instance, _) = host.spool();
    let request = host.spooled(&instance).join("request.json");
    let moved = host.root.join(format!("request-{instance}.json"));
    std::fs::rename(&request, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &request).unwrap();
    assert!(refusal(host.intake(&instance)).contains("symbolic link"));

    let (instance, _) = host.spool();
    let spooled = host.spooled(&instance);
    let moved = host.root.join(format!("instance-{instance}"));
    std::fs::rename(&spooled, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &spooled).unwrap();
    assert!(refusal(host.intake(&instance)).contains("symbolic link"));
}

#[test]
fn hard_links_and_special_files_are_refused() {
    let host = Host::new();
    let (instance, _) = host.spool();
    let file = host.spooled(&instance).join("artifacts/bin/k3s");
    std::fs::hard_link(&file, host.root.join(format!("link-{instance}"))).unwrap();
    assert!(refusal(host.intake(&instance)).contains("hard link"));

    let (instance, _) = host.spool();
    let fifo = host.spooled(&instance).join("artifacts/bin/fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert!(refusal(host.intake(&instance)).contains("not a regular file or directory"));
}

#[test]
fn set_id_bits_are_refused() {
    let host = Host::new();
    let (instance, _) = host.spool();
    let file = host.spooled(&instance).join("artifacts/bin/k3s");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o4755)).unwrap();
    assert!(refusal(host.intake(&instance)).contains("set-id"));
}

#[test]
fn artifacts_over_the_size_limit_are_refused() {
    let mut host = Host::new();
    host.config.max_artifact_bytes = 4;
    let (instance, _) = host.spool();
    assert!(refusal(host.intake(&instance)).contains("size limit"));
}

#[test]
fn an_input_inside_another_input_is_copied_once() {
    let host = Host::new();
    let stage = host.root.join("stage-overlap");
    let release = host.fixture.release_with_inputs(
        &stage,
        "k3s",
        "1.2.0",
        ["./bin/install.sh", "./bin/install.sh", "./bin/install.sh"],
        &[("bin/install.sh", b"#!/bin/sh\n"), ("bin/sbom.json", b"{}")],
        &["bin/sbom.json", "bin"],
    );
    let (instance, _) = host.spool_release(stage, release);
    let intake = host.intake(&instance).unwrap();
    assert_eq!(
        std::fs::read(intake.copied.workdir.join("bin/sbom.json")).unwrap(),
        b"{}"
    );
}

#[test]
fn a_directory_over_the_entry_limit_fails_while_it_is_listed() {
    let mut host = Host::new();
    host.config.max_artifact_entries = 3;
    let (instance, _) = host.spool();
    assert!(refusal(host.intake(&instance)).contains("too many entries"));
}

#[test]
fn a_malformed_instance_name_never_touches_a_path() {
    let host = Host::new();
    assert!(refusal(host.intake("../../etc")).contains("host apply instance"));
}

fn write_trusted(path: &Path, raw: &str) {
    std::fs::write(path, raw).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn trust_loads_only_from_files_no_other_user_can_write() {
    let host = Host::new();
    let etc = &host.paths.config_dir;
    write_trusted(
        &etc.join(config::RELEASE_TRUST_ROOTS_FILE),
        &toml::to_string(&host.fixture.trust.release_roots).unwrap(),
    );
    write_trusted(
        &etc.join(config::HOST_APPROVAL_POLICY_FILE),
        &toml::to_string(&host.fixture.trust.policy).unwrap(),
    );
    let trust = config::load_trust(&host.paths).unwrap();
    assert_eq!(trust.policy, host.fixture.trust.policy);

    let policy = etc.join(config::HOST_APPROVAL_POLICY_FILE);
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o664)).unwrap();
    let error = config::load_trust(&host.paths).unwrap_err();
    assert!(format!("{error:#}").contains("writable by group or others"));
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();

    // An installed revocation list without its authorities fails closed.
    write_trusted(&etc.join(config::KEY_REVOCATIONS_FILE), "{}");
    let error = config::load_trust(&host.paths).unwrap_err();
    assert!(format!("{error:#}").contains("cannot verify revocations"));
}
