use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Arc;

use super::*;
use crate::host_apply::HostAction;
use crate::host_apply::fixture::{HostFixture, StepSpec};
use crate::host_apply::state::{AppliedState, HostApplyOutcome};
use crate::plan::Action;

/// Units that never run; these tests drive the records directly.
struct Inert;

impl HostUnits for Inert {
    fn start<'a>(&'a self, _instance: &'a str) -> UnitFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn stop(&self, _instance: &str) -> Result<()> {
        Ok(())
    }

    fn running(&self) -> UnitFuture<'_, Vec<String>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct Dirs {
    root: PathBuf,
    executor: HostExecutor,
}

impl Dirs {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "tenkai-host-executor-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let spool = root.join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o750)).unwrap();
        let executor = HostExecutor::new(spool, root.join("state"), Arc::new(Inert));
        Self { root, executor }
    }

    fn write(&self, path: PathBuf, value: &impl serde::Serialize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }
}

impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A signed release in `dirs` and the request for its install step.
fn request(dirs: &Dirs) -> (HostApplyRequest, PathBuf, String) {
    let fixture = HostFixture::new(&[("alice@example.com", &[])], Vec::new());
    let workdir = dirs.root.join("release");
    let release = fixture.release(
        &workdir,
        "cluster",
        "1.0.0",
        ["sh bin/install.sh", "true", "true"],
        &[("bin/install.sh", b"echo installing\n")],
    );
    std::fs::set_permissions(
        workdir.join("bin/install.sh"),
        std::fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    let parsed = crate::manifest::parse_raw(&release.manifest).unwrap();
    let artifact_digest =
        crate::manifest::artifact_digest(&workdir, &parsed.immutable_inputs()).unwrap();
    let plan = fixture.plan(
        "edge",
        crate::now_millis(),
        &[StepSpec {
            release: release.clone(),
            action: HostAction::Install,
            step_action: Action::Install,
            from: None,
            expected_generation: 0,
        }],
    );
    let approval = fixture.approve(&plan, 0, crate::now_millis());
    (
        fixture.request(&plan, 0, &release, vec![approval]),
        workdir,
        artifact_digest,
    )
}

#[test]
fn spool_writes_the_request_and_an_exact_copy_of_the_inputs() {
    let dirs = Dirs::new("spool");
    let (request, workdir, digest) = request(&dirs);
    let inputs = vec!["bin".to_string()];

    let instance = dirs
        .executor
        .spool(&request, &workdir, &inputs, &digest)
        .unwrap();

    assert_eq!(instance, request.instance().unwrap());
    let spooled = dirs.executor.spool_dir.join(&instance);
    let parsed =
        HostApplyRequest::parse(&std::fs::read(spooled.join(REQUEST_FILE)).unwrap()).unwrap();
    assert_eq!(parsed, request);
    // Mode bits are part of the signed digest, so the copy keeps them.
    let script = spooled.join(ARTIFACTS_DIR).join("bin/install.sh");
    assert_eq!(
        std::fs::metadata(&script).unwrap().permissions().mode() & 0o7777,
        0o750
    );
    assert_eq!(
        crate::manifest::artifact_digest(&spooled.join(ARTIFACTS_DIR), &inputs).unwrap(),
        digest
    );

    // A retry replaces the earlier spool of the same instance.
    std::fs::write(workdir.join("bin/install.sh"), "tampered\n").unwrap();
    let error = dirs
        .executor
        .spool(&request, &workdir, &inputs, &digest)
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("does not match its signed artifact digest"),
        "{error:#}"
    );
    // The refused copy left nothing behind, and the first spool is intact.
    let entries: Vec<_> = std::fs::read_dir(&dirs.executor.spool_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, [std::ffi::OsString::from(&instance)]);
}

#[test]
fn spool_refuses_links_in_the_release_workdir() {
    let dirs = Dirs::new("links");
    let (request, workdir, digest) = request(&dirs);
    std::os::unix::fs::symlink("/etc/passwd", workdir.join("bin/passwd")).unwrap();

    let error = dirs
        .executor
        .spool(&request, &workdir, &["bin".to_string()], &digest)
        .unwrap_err();

    assert!(
        format!("{error:#}").contains("not a regular file or directory"),
        "{error:#}"
    );
}

#[test]
fn only_a_result_naming_the_started_instance_is_accepted() {
    let dirs = Dirs::new("result");
    let instance = "a".repeat(64);
    let expected = ExpectedResult {
        instance: &instance,
        environment: "edge",
        product: "cluster",
        action: HostAction::Install,
        release_digest: "d1",
    };
    assert_eq!(dirs.executor.result(&expected).unwrap(), None);

    let result = HostApplyResult {
        schema: RESULT_SCHEMA.into(),
        instance: instance.clone(),
        environment: "edge".into(),
        product: "cluster".into(),
        action: HostAction::Install,
        release_digest: "d1".into(),
        outcome: HostApplyOutcome::Succeeded,
        exit_status: Some(0),
        detail: "the command exited with status 0".into(),
        generation: 1,
        started_at: 1,
        finished_at: 2,
    };
    let path = instance_dir(&dirs.executor.state_dir, &instance).join(RESULT_FILE);
    dirs.write(path.clone(), &result);
    assert_eq!(
        dirs.executor.result(&expected).unwrap(),
        Some(result.clone())
    );

    for mismatched in [
        HostApplyResult {
            instance: "b".repeat(64),
            ..result.clone()
        },
        HostApplyResult {
            release_digest: "d2".into(),
            ..result.clone()
        },
        HostApplyResult {
            action: HostAction::Uninstall,
            ..result.clone()
        },
    ] {
        dirs.write(path.clone(), &mismatched);
        let error = dirs.executor.result(&expected).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match the step it started"),
            "{error:#}"
        );
    }
    assert!(
        dirs.executor
            .result(&ExpectedResult {
                instance: "../etc",
                ..expected
            })
            .is_err()
    );
}

#[test]
fn only_a_refusal_since_the_start_ends_the_attempt() {
    let dirs = Dirs::new("refused");
    let instance = "c".repeat(64);
    assert_eq!(dirs.executor.refusal_since(&instance, 0).unwrap(), None);
    dirs.write(
        instance_dir(&dirs.executor.state_dir, &instance).join(REFUSED_FILE),
        &HostApplyRefused {
            schema: REFUSED_SCHEMA.into(),
            instance: instance.clone(),
            reason: "host approval policy: execute_plan needs 2".into(),
            refused_at: 100,
        },
    );
    assert_eq!(
        dirs.executor
            .refusal_since(&instance, 100)
            .unwrap()
            .as_deref(),
        Some("host approval policy: execute_plan needs 2")
    );
    assert_eq!(dirs.executor.refusal_since(&instance, 101).unwrap(), None);
}

#[test]
fn applied_state_is_empty_until_the_applier_records_one_for_that_product() {
    let dirs = Dirs::new("record");
    let empty = dirs.executor.applied_state("edge", "cluster").unwrap();
    assert_eq!(empty, AppliedStateRecord::empty("edge", "cluster"));

    let mut record = AppliedStateRecord::empty("edge", "cluster");
    record.generation = 3;
    record.state = AppliedState::Applied {
        release: crate::host_apply::HostRelease {
            version: "1.0.0".into(),
            manifest_digest: "d1".into(),
        },
    };
    let path = record_path(&dirs.executor.state_dir, "edge", "cluster");
    dirs.write(path.clone(), &record);
    assert_eq!(
        dirs.executor.applied_state("edge", "cluster").unwrap(),
        record
    );

    // A record that names another product is refused, not trusted.
    dirs.write(
        path,
        &AppliedStateRecord {
            product: "other".into(),
            ..record
        },
    );
    assert!(dirs.executor.applied_state("edge", "cluster").is_err());
}

#[test]
fn readiness_needs_a_private_spool_directory() {
    let dirs = Dirs::new("ready");
    std::fs::set_permissions(
        &dirs.executor.spool_dir,
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let error = dirs.executor.check_ready().unwrap_err();
    assert!(
        error.to_string().contains("writable by group or others"),
        "{error:#}"
    );
    let missing = HostExecutor::new(
        dirs.root.join("missing"),
        dirs.root.join("state"),
        Arc::new(Inert),
    );
    assert!(missing.check_ready().is_err());
}
