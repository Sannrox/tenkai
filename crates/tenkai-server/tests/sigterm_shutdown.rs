//! Supervisors stop services with SIGTERM; the server must exit gracefully (#550).

use std::process::Command;
use std::time::Duration;

mod support;

#[test]
fn sigterm_stops_the_server_gracefully() {
    let state = std::env::temp_dir().join(format!("tenkai-sigterm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let mut server = support::Spawned::spawn(
        Command::new(env!("CARGO_BIN_EXE_tenkai-server"))
            .args(["--listen", "127.0.0.1:0", "--reconcile-interval", "1"])
            .arg("--database")
            .arg(state.join("tenkai.db"))
            .env(
                "TENKAI_MANAGEMENT_TOKEN",
                "sigterm-test-management-token-0123456789",
            ),
    );
    server.ready();

    let status = Command::new("kill")
        .args(["-TERM", &server.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let exit = server.wait(Duration::from_secs(10));
    let stderr = server.rest_of_stderr();
    assert!(exit.success(), "graceful exit: {exit:?}\n{stderr}");
    assert!(stderr.contains("shutting down signal=SIGTERM"), "{stderr}");
    let _ = std::fs::remove_dir_all(&state);
}
