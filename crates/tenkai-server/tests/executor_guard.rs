//! The server resolves tenkai-executor-guard (#552) and the host executor
//! (ADR 0041) at startup and reports them in `/readyz`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Output};

mod support;

use support::{DEADLINE, Spawned};

const TOKEN: &str = "executor-guard-test-management-token-0123456789";

fn server(label: &str, guard: &Path, extra: &[&str]) -> Spawned {
    Spawned::spawn(&mut command(label, guard, extra, None, None))
}

/// A server with `TENKAI_HOST_SPOOL_DIR` / `TENKAI_SOFTWARE_EXECUTOR` set when given.
fn server_with(
    label: &str,
    guard: &Path,
    extra: &[&str],
    host_spool: Option<&Path>,
    software_executor: Option<&str>,
) -> Spawned {
    Spawned::spawn(&mut command(
        label,
        guard,
        extra,
        host_spool,
        software_executor,
    ))
}

/// Runs a server expected to refuse to start, with a deadline.
fn refused(label: &str, guard: &Path, extra: &[&str], software_executor: Option<&str>) -> Output {
    support::output(&mut command(label, guard, extra, None, software_executor))
}

fn command(
    label: &str,
    guard: &Path,
    extra: &[&str],
    host_spool: Option<&Path>,
    software_executor: Option<&str>,
) -> Command {
    let state = std::env::temp_dir().join(format!("tenkai-guard-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let mut command = Command::new(env!("CARGO_BIN_EXE_tenkai-server"));
    command
        .args(["--listen", "127.0.0.1:0"])
        // The first stderr line is the warning under test; keep the host's
        // unix socket setup out of it.
        .arg("--no-unix-socket")
        .args(extra)
        .arg("--database")
        .arg(state.join("tenkai.db"))
        .env("TENKAI_MANAGEMENT_TOKEN", TOKEN)
        .env("TENKAI_EXECUTOR_GUARD", guard)
        .env_remove("TENKAI_HOST_SPOOL_DIR")
        .env_remove("TENKAI_SOFTWARE_EXECUTOR");
    if let Some(spool) = host_spool {
        command.env("TENKAI_HOST_SPOOL_DIR", spool);
    }
    if let Some(executor) = software_executor {
        command.env("TENKAI_SOFTWARE_EXECUTOR", executor);
    }
    command
}

/// The first stderr line, within the deadline.
fn first_warning(server: &Spawned) -> String {
    server
        .stderr_line(DEADLINE, |_| true)
        .expect("a startup warning before the deadline")
}

/// A spool directory for one test with `mode`.
fn spool(label: &str, mode: u32) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let dir =
        std::env::temp_dir().join(format!("tenkai-host-spool-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
    dir
}

/// Wait for readiness and return the `/readyz` body; the server stops when
/// `server` drops.
fn readyz(server: Spawned) -> String {
    let address = server
        .stdout_line(|line| line.starts_with("tenkai-server listening on "))
        .and_then(|line| {
            line.strip_prefix("tenkai-server listening on ")
                .and_then(|rest| rest.split_whitespace().next())
                .map(str::to_owned)
        })
        .expect("listening line");
    server.ready();
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(DEADLINE)).unwrap();
    stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn unusable_guard_is_reported_at_startup_and_absent_from_readiness() {
    // A guard without execute permission cannot run a deploy.
    let guard = std::env::temp_dir().join(format!("tenkai-guard-plain-{}", std::process::id()));
    std::fs::write(&guard, "").unwrap();
    let server = server("unusable", &guard, &[]);
    let warning = first_warning(&server);
    assert!(
        warning.contains("shell executor unavailable") && warning.contains("TENKAI_EXECUTOR_GUARD"),
        "{warning}"
    );
    let response = readyz(server);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(!response.contains("shell_executor"), "{response}");
    let _ = std::fs::remove_file(guard);
}

#[test]
fn resolved_guard_is_advertised_in_readiness() {
    let guard = Path::new(env!("CARGO_BIN_EXE_tenkai-server"));
    let response = readyz(server("present", guard, &[]));
    assert!(response.contains("shell_executor:v1"), "{response}");
    assert!(response.contains("software_executor:shell"), "{response}");
}

#[test]
fn require_executor_refuses_to_start_without_the_guard() {
    let output = refused(
        "required",
        Path::new("/nonexistent/tenkai-executor-guard"),
        &["--require-executor"],
        None,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("shell executor is unavailable"), "{stderr}");
    // Refused before binding: no listener was ever announced.
    assert!(output.stdout.is_empty());
}

#[test]
fn an_unusable_host_spool_is_reported_at_startup_and_absent_from_readiness() {
    let guard = Path::new(env!("CARGO_BIN_EXE_tenkai-server"));
    let spool = spool("open", 0o777);
    let server = server_with("host-open", guard, &[], Some(&spool), None);
    let warning = first_warning(&server);
    assert!(
        warning.contains("host executor unavailable")
            && warning.contains("writable by group or others"),
        "{warning}"
    );
    let response = readyz(server);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(!response.contains("host_executor"), "{response}");
    let _ = std::fs::remove_dir_all(spool);
}

/// systemctl is part of every Linux host this runs on in CI.
#[cfg(target_os = "linux")]
#[test]
fn a_usable_host_spool_is_advertised_in_readiness() {
    let guard = Path::new(env!("CARGO_BIN_EXE_tenkai-server"));
    let spool = spool("private", 0o750);
    let response = readyz(server_with("host-private", guard, &[], Some(&spool), None));
    assert!(response.contains("host_executor:v1"), "{response}");
    let _ = std::fs::remove_dir_all(spool);
}

#[test]
fn host_as_process_default_refuses_to_start() {
    let guard = Path::new(env!("CARGO_BIN_EXE_tenkai-server"));
    let output = refused("host-default", guard, &[], Some("host"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("TENKAI_SOFTWARE_EXECUTOR is set to \"host\"")
            && stderr.contains("not a process default"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn unknown_software_executor_refuses_to_start() {
    let guard = Path::new(env!("CARGO_BIN_EXE_tenkai-server"));
    let output = refused("unknown-executor", guard, &[], Some("kuberntes-inprocess"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("unknown software executor") && stderr.contains("kuberntes-inprocess"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn in_process_software_executor_is_advertised_in_readiness() {
    let guard = Path::new(env!("CARGO_BIN_EXE_tenkai-server"));
    let response = readyz(server_with(
        "inprocess-default",
        guard,
        &[],
        None,
        Some("kubernetes-inprocess"),
    ));
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains("software_executor:kubernetes-inprocess"),
        "{response}"
    );
}
