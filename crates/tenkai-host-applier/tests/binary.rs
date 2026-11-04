//! The `tenkai-host-applier` binary end to end: the signed command runs in
//! the root-owned copy with a fixed environment, a timeout or a stop kills
//! its process group, a completed instance returns its recorded result, and
//! a refusal changes nothing.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use common::{Host, Staged, Step};
use tenkai::host_apply::HostAction;
use tenkai::host_apply::state::{AppliedState, HostApplyOutcome, HostApplyResult};
use tenkai::plan::Action;

/// A host with its config and trust written where the binary reads them.
fn host() -> Host {
    let host = Host::new(Vec::new());
    host.write_config();
    host
}

/// A directory the signed commands write their evidence to.
fn evidence(host: &Host) -> PathBuf {
    let dir = host.root.join("evidence");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn applier(host: &Host, instance: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tenkai-host-applier"));
    command
        .arg("run")
        .arg(instance)
        .arg("--config-dir")
        .arg(&host.paths.config_dir)
        .arg("--state-dir")
        .arg(&host.paths.state_dir)
        .arg("--run-dir")
        .arg(&host.paths.run_dir)
        // Server-side environment that must never reach the command.
        .env("TENKAI_MANAGEMENT_TOKEN", "server-secret");
    command
}

fn result_of(output: &Output) -> HostApplyResult {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "no result on stdout ({error}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn install<'a>(release: &'a Staged, generation: u64) -> Step<'a> {
    Step {
        release,
        action: HostAction::Install,
        step_action: Action::Install,
        from: None,
        generation,
        approvers: &[0],
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // The writer may not have finished the line yet.
    std::thread::sleep(Duration::from_millis(50));
}

fn alive(pid: &str) -> bool {
    let pid = rustix::process::Pid::from_raw(pid.trim().parse().unwrap()).unwrap();
    rustix::process::test_kill_process(pid).is_ok()
}

#[test]
fn the_signed_command_runs_once_in_the_copy_with_a_fixed_environment() {
    let host = host();
    let out = evidence(&host);
    let release = host.release_with(
        "1.0.0",
        [
            &format!(
                "echo run >> {out}/runs && env > {out}/env && pwd > {out}/pwd && cat bin/k3s > {out}/payload",
                out = out.display()
            ),
            "true",
            "true",
        ],
    );
    let (instance, _) = host.spool(install(&release, 0));
    let output = applier(&host, &instance).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let result = result_of(&output);
    assert_eq!(result.outcome, HostApplyOutcome::Succeeded);
    assert_eq!(std::fs::read(out.join("payload")).unwrap(), b"binary");

    let env = std::fs::read_to_string(out.join("env")).unwrap();
    let mut names: Vec<&str> = env
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .collect();
    names.sort();
    // The shell adds only its own working-directory and level variables.
    let shell = ["OLDPWD", "PWD", "SHLVL", "_"];
    let names: Vec<&str> = names
        .into_iter()
        .filter(|name| !shell.contains(name))
        .collect();
    assert_eq!(
        names,
        [
            "HOME",
            "LANG",
            "PATH",
            "TENKAI_ENVIRONMENT",
            "TENKAI_HOST_ACTION",
            "TENKAI_PLAN_ID",
            "TENKAI_PRODUCT",
            "TENKAI_RELEASE_DIGEST",
            "TENKAI_VERSION",
        ]
    );
    assert!(env.contains("TENKAI_PRODUCT=k3s\n"));
    assert!(env.contains("TENKAI_HOST_ACTION=install\n"));

    // It ran in the root-owned copy, never in the spool, and the copy is gone.
    let pwd = PathBuf::from(std::fs::read_to_string(out.join("pwd")).unwrap().trim());
    let work = host.paths.work_dir(&instance);
    assert_eq!(
        pwd.canonicalize().ok(),
        None,
        "the copy is removed after the step"
    );
    assert!(
        pwd.ends_with(Path::new(&instance).join("artifacts")),
        "{}",
        pwd.display()
    );
    assert!(!work.exists());

    // A replay returns the recorded result without running anything.
    let again = applier(&host, &instance).output().unwrap();
    assert!(again.status.success());
    assert_eq!(result_of(&again), result);
    assert_eq!(std::fs::read_to_string(out.join("runs")).unwrap(), "run\n");
    assert!(matches!(host.record().state, AppliedState::Applied { .. }));
}

#[test]
fn a_failed_command_is_recorded_and_leaves_the_product_dirty() {
    let host = host();
    let release = host.release_with("1.0.0", ["exit 3", "true", "true"]);
    let (instance, _) = host.spool(install(&release, 0));
    let output = applier(&host, &instance).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let result = result_of(&output);
    assert_eq!(
        (result.outcome, result.exit_status),
        (HostApplyOutcome::Failed, Some(3))
    );
    assert!(matches!(host.record().state, AppliedState::Dirty { .. }));
    // Recorded failures stay failures.
    assert_eq!(
        applier(&host, &instance).output().unwrap().status.code(),
        Some(1)
    );
}

#[test]
fn a_refusal_changes_nothing_and_does_not_block_a_later_start() {
    let host = host();
    let release = host.release_with("1.0.0", ["true", "true", "true"]);
    let (instance, request) = host.spool(Step {
        approvers: &[],
        ..install(&release, 0)
    });
    let output = applier(&host, &instance).output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let refused = tenkai_host_applier::store::refusal(&host.paths, &instance)
        .unwrap()
        .unwrap();
    assert!(
        refused.reason.contains("execute_plan"),
        "{}",
        refused.reason
    );
    assert_eq!(host.record().generation, 0);
    assert!(!host.paths.work_dir(&instance).exists());

    // Once approved, the same instance runs.
    let mut approved = request;
    approved.approvals.push(
        host.fixture
            .approve(&approved.plan, 0, tenkai::now_millis()),
    );
    host.spool_request(&approved, &release.dir);
    let output = applier(&host, &instance).output().unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn the_applier_timeout_kills_the_process_group() {
    let mut host = Host::new(Vec::new());
    host.config.timeout_seconds = 1;
    host.write_config();
    let out = evidence(&host);
    let release = host.release_with(
        "1.0.0",
        [
            &format!("sleep 60 & echo $! > {}/child; wait", out.display()),
            "true",
            "true",
        ],
    );
    let (instance, _) = host.spool(install(&release, 0));
    let output = applier(&host, &instance).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(result_of(&output).outcome, HostApplyOutcome::TimedOut);
    let child = std::fs::read_to_string(out.join("child")).unwrap();
    assert!(
        !alive(&child),
        "the command's background child outlived the timeout"
    );
}

#[test]
fn stop_kills_the_process_group_and_records_the_step_as_stopped() {
    let host = host();
    let out = evidence(&host);
    let release = host.release_with(
        "1.0.0",
        [
            &format!("sleep 60 & echo $! > {}/child; wait", out.display()),
            "true",
            "true",
        ],
    );
    let (instance, _) = host.spool(install(&release, 0));
    let applier = applier(&host, &instance)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait_for(&out.join("child"));
    let pid = rustix::process::Pid::from_raw(applier.id() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    let output = applier.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(result_of(&output).outcome, HostApplyOutcome::Stopped);
    let child = std::fs::read_to_string(out.join("child")).unwrap();
    assert!(
        !alive(&child),
        "the command's background child outlived the stop"
    );
    assert!(matches!(host.record().state, AppliedState::Dirty { .. }));
}

/// Nothing a command started outlives its step, even when the command exits
/// on its own and its children left its process group.
#[cfg(target_os = "linux")]
#[test]
fn processes_a_finished_command_left_behind_are_stopped_before_the_step_ends() {
    let host = host();
    let out = evidence(&host);
    let release = host.release_with(
        "1.0.0",
        [
            &format!(
                "sleep 300 & echo $! > {out}/background; setsid sh -c 'echo $$ > {out}/detached; exec sleep 300' & while [ ! -s {out}/detached ]; do sleep 0.01; done; exit 0",
                out = out.display()
            ),
            "true",
            "true",
        ],
    );
    let (instance, _) = host.spool(install(&release, 0));
    let started = Instant::now();
    // The leftovers hold the applier's stdout, so this returns only once
    // they are gone.
    let output = applier(&host, &instance).output().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "the leftovers ran to completion"
    );
    assert!(output.status.success(), "{output:?}");
    for name in ["background", "detached"] {
        let pid = std::fs::read_to_string(out.join(name)).unwrap();
        assert!(!alive(&pid), "the {name} process outlived the step");
    }
}
