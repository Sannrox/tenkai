//! The runtime guard ends its executor's whole process group when its parent
//! goes away, by signal (#1337) or by closing the guard's stdin, and reports
//! the executor's own exit otherwise.
#![cfg(unix)]

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GUARD: &str = env!("CARGO_BIN_EXE_tenkai-runtime-guard");

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// A scratch directory unique to this process and call.
fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tenkai-guard-signals-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Start the guard as the runtime does: leader of its own process group.
fn guard(script: &str) -> Child {
    Command::new(GUARD)
        .arg("--executor")
        .arg("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap()
}

fn read_pid(path: &Path) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(pid) = std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| raw.trim().parse().ok())
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "{} never written",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_gone(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while alive(pid) {
        assert!(
            Instant::now() < deadline,
            "process {pid} outlived its guard"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn sigterm_right_after_spawn_leaves_no_executor_behind() {
    let dir = scratch();
    let pid_file = dir.join("executor.pid");
    let mut guard = guard(&format!("echo $$ > {}; exec sleep 60", pid_file.display()));
    let executor = read_pid(&pid_file);
    // SAFETY: plain signal delivery to the guard this test spawned.
    unsafe { libc::kill(guard.id() as i32, libc::SIGTERM) };
    let _ = guard.wait().unwrap();
    assert_gone(executor);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn closing_stdin_ends_the_executor_and_its_descendants() {
    let dir = scratch();
    let executor_file = dir.join("executor.pid");
    let descendant_file = dir.join("descendant.pid");
    let mut guard = guard(&format!(
        "sleep 60 & echo $! > {}; echo $$ > {}; wait",
        descendant_file.display(),
        executor_file.display()
    ));
    let executor = read_pid(&executor_file);
    let descendant = read_pid(&descendant_file);
    // The runtime dying closes the guard's stdin.
    drop(guard.stdin.take());
    let status = guard.wait().unwrap();
    assert!(!status.success(), "{status}");
    assert_gone(executor);
    assert_gone(descendant);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_guard_reports_its_executors_exit() {
    for (script, success) in [("exit 0", true), ("exit 3", false)] {
        let mut guard = guard(script);
        // Hold stdin open (`wait` would close it): only the executor's exit
        // ends the guard.
        let _parent = guard.stdin.take();
        let status = guard.wait().unwrap();
        assert_eq!(status.success(), success, "{script}: {status}");
    }
}
