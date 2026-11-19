//! The runtime guard terminates its executor's process group on SIGTERM
//! (#1337).
#![cfg(unix)]

use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const GUARD: &str = env!("CARGO_BIN_EXE_tenkai-runtime-guard");

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn sigterm_right_after_spawn_leaves_no_executor_behind() {
    let dir = std::env::temp_dir().join(format!(
        "tenkai-guard-signals-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let pid_file = dir.join("executor.pid");
    // The guard leads its own process group, as the runtime starts it.
    let mut guard = Command::new(GUARD)
        .arg("--executor")
        .arg("/bin/sh")
        .arg("-c")
        .arg(format!("echo $$ > {}; exec sleep 60", pid_file.display()))
        .stdin(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let executor: i32 = loop {
        if let Some(pid) = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|raw| raw.trim().parse().ok())
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "executor never started");
        std::thread::sleep(Duration::from_millis(10));
    };
    // SAFETY: plain signal delivery to the guard this test spawned.
    unsafe { libc::kill(guard.id() as i32, libc::SIGTERM) };
    let _ = guard.wait().unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while alive(executor) {
        assert!(
            Instant::now() < deadline,
            "executor {executor} outlived its guard"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = std::fs::remove_dir_all(dir);
}
