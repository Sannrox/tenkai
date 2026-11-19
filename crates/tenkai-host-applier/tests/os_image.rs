//! OS image updates across a reboot (ADR 0051), through the binary, against
//! a fake on-host updater: a root-owned reader that prints what a state file
//! holds, a reboot command that only leaves a mark, and a boot id file the
//! test changes to stand for a reboot.

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output};

use common::{Host, Staged, Step};
use tenkai::host_apply::HostAction;
use tenkai::host_apply::os_image::AwaitingBoot;
use tenkai::host_apply::state::{AppliedState, HostApplyOutcome, HostApplyResult};
use tenkai::plan::Action;
use tenkai_host_applier::config::OsImageConfig;
use tenkai_host_applier::store::{self, Admission, Ended};

/// The image the host boots before the update, and the one it updates to.
const OLD: char = 'a';
const NEW: char = 'b';

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

/// A host whose updater boots `OLD`, confirmed, in boot `boot-1`.
struct Updater {
    host: Host,
    image: Staged,
}

impl Updater {
    fn new() -> Self {
        let mut host = Host::new(Vec::new());
        let script = |name: &str, body: String| {
            let path = host.root.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.display().to_string()
        };
        let state = host.root.join("updater.json");
        let reader = script("reader", format!("exec cat {}", state.display()));
        let reboot = script(
            "reboot",
            format!("touch {}", host.root.join("rebooted").display()),
        );
        host.config.os_image = Some(OsImageConfig {
            reader: vec![reader],
            reboot: vec![reboot],
        });
        host.write_config();
        let dir = host.root.join("image");
        let release = host.fixture.os_image_release(
            &dir,
            "os",
            "2.0.0",
            &digest(NEW),
            &[
                (
                    "install.sh",
                    format!("#!/bin/sh\ntouch {}\n", host.root.join("staged").display()).as_bytes(),
                ),
                (
                    "confirm.sh",
                    format!(
                        "#!/bin/sh\nprintf '{{\"booted_digest\":\"{}\",\"state\":\"confirmed\"}}' > {}\n",
                        digest(NEW),
                        state.display()
                    )
                    .as_bytes(),
                ),
                ("health.sh", b"#!/bin/sh\nexit 0\n"),
            ],
        );
        let updater = Self {
            host,
            image: Staged { dir, release },
        };
        updater.boots(OLD, "confirmed", "boot-1");
        updater
    }

    /// What the updater reports, and the current boot.
    fn boots(&self, image: char, state: &str, boot: &str) {
        std::fs::write(
            self.host.root.join("updater.json"),
            format!(
                r#"{{"booted_digest":"{}","state":"{state}"}}"#,
                digest(image)
            ),
        )
        .unwrap();
        std::fs::write(&self.host.paths.boot_id, format!("{boot}\n")).unwrap();
    }

    fn mark(&self, name: &str) -> PathBuf {
        self.host.root.join(name)
    }

    /// Spool `action` of the image release at `generation`.
    fn spool(&self, action: HostAction, generation: u64) -> String {
        self.host
            .spool(Step {
                release: &self.image,
                action,
                step_action: Action::Install,
                from: None,
                generation,
                approvers: &[0],
            })
            .0
    }

    fn run(&self, instance: &str) -> Output {
        self.command(instance).output().unwrap()
    }

    fn command(&self, instance: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tenkai-host-applier"));
        command
            .arg("run")
            .arg(instance)
            .arg("--config-dir")
            .arg(&self.host.paths.config_dir)
            .arg("--state-dir")
            .arg(&self.host.paths.state_dir)
            .arg("--run-dir")
            .arg(&self.host.paths.run_dir)
            .arg("--boot-id")
            .arg(&self.host.paths.boot_id);
        command
    }

    /// Run `instance` and return its result, which must end with `code`.
    fn result(&self, instance: &str, code: i32) -> HostApplyResult {
        let output = self.run(instance);
        assert_eq!(output.status.code(), Some(code), "{}", stderr(&output));
        serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("no result ({error}): {}", stderr(&output)))
    }

    /// Run `instance`, which must be refused, and return why.
    fn refused(&self, instance: &str) -> String {
        let output = self.run(instance);
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        stderr(&output)
    }

    /// Run a reboot instance, which must await its boot.
    fn awaits(&self, instance: &str) -> AwaitingBoot {
        let output = self.run(instance);
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn record(&self) -> tenkai::host_apply::state::AppliedStateRecord {
        store::read_os_image_record(&self.host.paths)
            .unwrap()
            .expect("an OS image step started")
    }

    /// Stage and reboot from an empty record; returns the reboot instance.
    fn stage_and_reboot(&self) -> String {
        let stage = self.spool(HostAction::Stage, 0);
        assert!(self.result(&stage, 0).outcome.succeeded());
        let reboot = self.spool(HostAction::Reboot, 1);
        self.awaits(&reboot);
        reboot
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn an_image_boots_verifies_from_the_root_side_and_confirms() {
    let updater = Updater::new();
    let stage = updater.spool(HostAction::Stage, 0);
    assert!(updater.result(&stage, 0).outcome.succeeded());
    assert!(updater.mark("staged").exists());
    // The old image still runs: neither side is applied.
    assert!(matches!(
        updater.record().state,
        AppliedState::Dirty { from: None, to: Some(ref to) } if to.version == "2.0.0"
    ));

    let reboot = updater.spool(HostAction::Reboot, 1);
    let awaiting = updater.awaits(&reboot);
    assert_eq!(
        (awaiting.expected_digest, awaiting.previous_digest),
        (digest(NEW), digest(OLD))
    );
    assert!(updater.mark("rebooted").exists());
    // A replay before the verify reports the same wait and reboots nothing.
    std::fs::remove_file(updater.mark("rebooted")).unwrap();
    updater.awaits(&reboot);
    assert!(!updater.mark("rebooted").exists());

    let verify = updater.spool(HostAction::Verify, 2);
    assert!(updater.refused(&verify).contains("has not rebooted"));
    updater.boots(NEW, "pending", "boot-2");
    let verified = updater.result(&verify, 0);
    assert!(
        verified.detail.contains(&digest(NEW)),
        "{}",
        verified.detail
    );
    assert_eq!(
        updater.result(&reboot, 0).outcome,
        HostApplyOutcome::Succeeded
    );
    assert_eq!(updater.record().awaiting_boot, None);

    let confirm = updater.spool(HostAction::Confirm, 2);
    assert!(updater.result(&confirm, 0).outcome.succeeded());
    let record = updater.record();
    assert_eq!(record.generation, 3);
    assert!(
        matches!(record.state, AppliedState::Applied { ref release } if release.version == "2.0.0")
    );
    assert_eq!(record.high_water.unwrap().version, "2.0.0");
    // Health of the OS release runs on the applied image.
    let (health, _) = updater.host.spool(Step {
        release: &updater.image,
        action: HostAction::Health,
        step_action: Action::Install,
        from: Some("2.0.0"),
        generation: 3,
        approvers: &[0],
    });
    assert!(updater.result(&health, 0).outcome.succeeded());
}

#[test]
fn a_failed_boot_falls_back_and_verify_reports_the_previous_image() {
    let updater = Updater::new();
    let reboot = updater.stage_and_reboot();
    updater.boots(OLD, "confirmed", "boot-2");
    let verify = updater.spool(HostAction::Verify, 2);
    let verified = updater.result(&verify, 1);
    assert_eq!(verified.outcome, HostApplyOutcome::FellBack);
    assert!(
        verified.detail.contains(&digest(OLD)),
        "{}",
        verified.detail
    );
    assert_eq!(
        updater.result(&reboot, 1).outcome,
        HostApplyOutcome::FellBack
    );
    let record = updater.record();
    assert!(matches!(record.state, AppliedState::Dirty { .. }));
    assert_eq!((record.generation, record.awaiting_boot), (2, None));
    // Confirming now would keep the old image under the new release's name.
    let confirm = updater.spool(HostAction::Confirm, 2);
    assert!(updater.refused(&confirm).contains("not the expected image"));
}

#[test]
fn an_interrupted_confirm_is_settled_by_what_the_updater_reports() {
    let updater = Updater::new();
    updater.stage_and_reboot();
    updater.boots(NEW, "pending", "boot-2");
    let verify = updater.spool(HostAction::Verify, 2);
    assert!(updater.result(&verify, 0).outcome.succeeded());
    // The applier dies after `started`, once the updater confirmed.
    let confirm = updater.spool(HostAction::Confirm, 2);
    let intake = updater.host.intake(&confirm).unwrap();
    let Admission::Run(running) = store::admit(&updater.host.paths, &intake.verified).unwrap()
    else {
        panic!("confirm is admitted");
    };
    drop(running);
    updater.boots(NEW, "confirmed", "boot-2");
    let Some(Ended::Result(settled)) = store::recover(&updater.host.paths, &confirm).unwrap()
    else {
        panic!("the confirm settles");
    };
    assert_eq!(settled.outcome, HostApplyOutcome::Succeeded);
    assert!(matches!(
        updater.record().state,
        AppliedState::Applied { ref release } if release.version == "2.0.0"
    ));
}

#[test]
fn a_reboot_stopped_by_the_shutdown_still_awaits_its_boot() {
    let updater = Updater::new();
    let stage = updater.spool(HostAction::Stage, 0);
    assert!(updater.result(&stage, 0).outcome.succeeded());
    // The shutdown signals the applier while the reboot command still runs.
    std::fs::write(
        updater.mark("reboot"),
        format!(
            "#!/bin/sh\ntouch {}\nexec sleep 30\n",
            updater.mark("rebooted").display()
        ),
    )
    .unwrap();
    let reboot = updater.spool(HostAction::Reboot, 1);
    let child = updater
        .command(&reboot)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !updater.mark("rebooted").exists() {
        assert!(std::time::Instant::now() < deadline, "the reboot never ran");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(updater.record().awaiting_boot.is_some());
    updater.boots(NEW, "pending", "boot-2");
    let verify = updater.spool(HostAction::Verify, 2);
    assert!(updater.result(&verify, 0).outcome.succeeded());
}

// #1338: a refusal is recorded even when discarding the work copy fails,
// and the reason keeps the refusal first with the cleanup failure attached.
#[test]
fn a_refusal_is_recorded_when_its_cleanup_fails() {
    let updater = Updater::new();
    let install = updater.spool(HostAction::Install, 0);
    // A file where the work directory goes: the copy is refused, and the
    // discard after it cannot empty a file either.
    let work = updater.host.paths.work_dir(&install);
    std::fs::create_dir_all(work.parent().unwrap()).unwrap();
    std::fs::write(&work, b"not a directory").unwrap();
    updater.refused(&install);
    let recorded = store::refusal(&updater.host.paths, &install)
        .unwrap()
        .expect("refused.json is written");
    let (refusal, cleanup) = recorded
        .reason
        .split_once("; discarding the work copy also failed: ")
        .unwrap_or_else(|| panic!("{}", recorded.reason));
    assert!(refusal.starts_with("creating "), "{refusal}");
    assert!(cleanup.contains("Not a directory"), "{cleanup}");
}

#[test]
fn image_steps_are_fenced_to_one_pending_update() {
    let updater = Updater::new();
    // An image release never settles through an ordinary install.
    let install = updater.spool(HostAction::Install, 0);
    assert!(
        updater
            .refused(&install)
            .contains("stage, reboot, verify and confirm")
    );
    let reboot = updater.stage_and_reboot();
    // Nothing but a verify moves while the host awaits its boot.
    let confirm = updater.spool(HostAction::Confirm, 2);
    assert!(updater.refused(&confirm).contains("awaits the boot"));
    // A host without an updater takes no image step.
    let mut bare = Updater::new();
    bare.host.config.os_image = None;
    bare.host.write_config();
    let stage = bare.spool(HostAction::Stage, 0);
    assert!(bare.refused(&stage).contains("no [os_image] section"));
    assert!(matches!(
        updater.awaits(&reboot),
        AwaitingBoot { ref instance, .. } if *instance == reboot
    ));
}
