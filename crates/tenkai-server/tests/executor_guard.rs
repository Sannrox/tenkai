//! The server resolves tenkai-executor-guard at startup (#552).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

const TOKEN: &str = "executor-guard-test-management-token-0123456789";

fn server(label: &str, guard: &Path, extra: &[&str]) -> Child {
    let state = std::env::temp_dir().join(format!("tenkai-guard-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    Command::new(env!("CARGO_BIN_EXE_tenkai-server"))
        .args(["--listen", "127.0.0.1:0"])
        .args(extra)
        .arg("--database")
        .arg(state.join("tenkai.db"))
        .env("TENKAI_MANAGEMENT_TOKEN", TOKEN)
        .env("TENKAI_EXECUTOR_GUARD", guard)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Wait for readiness and return the `/readyz` body; stops the server afterwards.
fn readyz(mut server: Child) -> String {
    let mut lines = BufReader::new(server.stdout.take().unwrap()).lines();
    let mut address = None;
    for line in lines.by_ref().map_while(Result::ok) {
        if let Some(rest) = line.strip_prefix("tenkai-server listening on ") {
            address = rest.split_whitespace().next().map(str::to_owned);
        }
        if line.starts_with("tenkai-server ready") {
            break;
        }
    }
    let mut stream = TcpStream::connect(address.expect("listening line")).unwrap();
    stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    server.kill().unwrap();
    server.wait().unwrap();
    response
}

#[test]
fn unusable_guard_is_reported_at_startup_and_absent_from_readiness() {
    // A guard without execute permission cannot run a deploy.
    let guard = std::env::temp_dir().join(format!("tenkai-guard-plain-{}", std::process::id()));
    std::fs::write(&guard, "").unwrap();
    let mut server = server("unusable", &guard, &[]);
    let mut stderr = BufReader::new(server.stderr.take().unwrap());
    let mut warning = String::new();
    stderr.read_line(&mut warning).unwrap();
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
}

#[test]
fn require_executor_refuses_to_start_without_the_guard() {
    let output = server(
        "required",
        Path::new("/nonexistent/tenkai-executor-guard"),
        &["--require-executor"],
    )
    .wait_with_output()
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("shell executor is unavailable"), "{stderr}");
    // Refused before binding: no listener was ever announced.
    assert!(output.stdout.is_empty());
}
