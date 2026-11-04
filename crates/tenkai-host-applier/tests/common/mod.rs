//! A throwaway applier host: unique temporary config, state, run, and spool
//! directories, and fixture keys that sign releases and approve plans.

#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tenkai::approval_policy::QuorumRule;
use tenkai::host_apply::fixture::{HostFixture, SignedRelease, StepSpec};
use tenkai::host_apply::state::{HostApplyOutcome, HostApplyResult};
use tenkai::host_apply::{HostAction, HostApplyRequest};
use tenkai::plan::Action;
use tenkai_host_applier::store::Admission;
use tenkai_host_applier::{ApplierConfig, ApplierPaths, Intake, intake, store};

pub struct Host {
    pub root: PathBuf,
    pub paths: ApplierPaths,
    pub config: ApplierConfig,
    pub fixture: HostFixture,
}

/// A signed release whose workdir is staged once and copied per spool.
#[derive(Debug, Clone)]
pub struct Staged {
    pub dir: PathBuf,
    pub release: SignedRelease,
}

/// One host step to spool.
pub struct Step<'a> {
    pub release: &'a Staged,
    pub action: HostAction,
    pub step_action: Action,
    pub from: Option<&'a str>,
    pub generation: u64,
    pub approvers: &'a [usize],
}

impl Host {
    /// Approvers: alice (ops), bob (ops), carol (qa).
    pub fn new(quorum: Vec<QuorumRule>) -> Self {
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
            fixture: HostFixture::new(
                &[("alice", &["ops"]), ("bob", &["ops"]), ("carol", &["qa"])],
                quorum,
            ),
        }
    }

    /// Sign release `version` of `k3s` with an install script and a binary.
    pub fn release(&self, version: &str) -> Staged {
        self.release_with(version, ["./install.sh", "./uninstall.sh", "./health.sh"])
    }

    /// Sign release `version` of `k3s` with the given commands.
    pub fn release_with(&self, version: &str, commands: [&str; 3]) -> Staged {
        let dir = self.root.join(format!("stage-{}", uuid::Uuid::new_v4()));
        let release = self.fixture.release(
            &dir,
            "k3s",
            version,
            commands,
            &[
                ("install.sh", b"#!/bin/sh\nexit 0\n"),
                ("bin/k3s", b"binary"),
                ("bin/lib/helper", b"helper"),
            ],
        );
        Staged { dir, release }
    }

    /// Spool a plan with one host step; returns its instance and request.
    pub fn spool(&self, step: Step<'_>) -> (String, HostApplyRequest) {
        let now = tenkai::now_millis();
        let plan = self.fixture.plan(
            "edge",
            now + i64::from(rand_suffix()),
            &[StepSpec {
                release: step.release.release.clone(),
                action: step.action,
                step_action: step.step_action,
                from: step.from.map(str::to_string),
                expected_generation: step.generation,
            }],
        );
        let approvals = step
            .approvers
            .iter()
            .map(|index| self.fixture.approve(&plan, *index, now))
            .collect();
        let request = self
            .fixture
            .request(&plan, 0, &step.release.release, approvals);
        let instance = self.spool_request(&request, &step.release.dir);
        (instance, request)
    }

    /// Write `request` and a copy of `artifacts` into the spool.
    pub fn spool_request(&self, request: &HostApplyRequest, artifacts: &Path) -> String {
        let instance = request.instance().unwrap();
        let dir = self.config.spool_dir.join(&instance);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("request.json"),
            serde_json::to_vec(request).unwrap(),
        )
        .unwrap();
        copy_dir(artifacts, &dir.join("artifacts"));
        instance
    }

    pub fn intake(&self, instance: &str) -> anyhow::Result<Intake> {
        intake(
            &self.paths,
            &self.config,
            &self.fixture.trust,
            instance,
            tenkai::now_millis(),
        )
    }

    /// Intake and admit `instance`.
    pub fn admit(&self, instance: &str) -> anyhow::Result<Admission> {
        let intake = self.intake(instance)?;
        store::admit(&self.paths, &intake.verified, tenkai::now_millis())
    }

    /// Admit `instance` and, when admitted, finish it with `outcome` without
    /// running anything: the state machine alone.
    pub fn step(
        &self,
        instance: &str,
        outcome: HostApplyOutcome,
    ) -> anyhow::Result<HostApplyResult> {
        match self.admit(instance)? {
            Admission::Recorded(result) => Ok(result),
            Admission::Run(running) => running.finish(
                outcome,
                Some(if outcome.succeeded() { 0 } else { 1 }),
                "",
                tenkai::now_millis(),
            ),
        }
    }

    /// The applied-state record of `k3s` in `edge`.
    pub fn record(&self) -> tenkai::host_apply::state::AppliedStateRecord {
        store::read_record(&self.paths, "edge", "k3s").unwrap()
    }

    /// A reboot: everything under the run directory is gone.
    pub fn reboot(&self) {
        std::fs::remove_dir_all(&self.paths.run_dir).unwrap();
        std::fs::create_dir_all(&self.paths.run_dir).unwrap();
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A small distinct offset so plans created in the same millisecond differ.
fn rand_suffix() -> u16 {
    (uuid::Uuid::new_v4().as_u128() & 0xffff) as u16
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}
