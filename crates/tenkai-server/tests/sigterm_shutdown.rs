//! Supervisors stop services with SIGTERM; the server must exit gracefully (#550).

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn sigterm_stops_the_server_gracefully() {
    let state = std::env::temp_dir().join(format!("tenkai-sigterm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let mut server = Command::new(env!("CARGO_BIN_EXE_tenkai-server"))
        .args(["--listen", "127.0.0.1:0", "--reconcile-interval", "1"])
        .arg("--database")
        .arg(state.join("tenkai.db"))
        .env(
            "TENKAI_MANAGEMENT_TOKEN",
            "sigterm-test-management-token-0123456789",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep the pipe open until exit so later server output cannot hit EPIPE.
    let mut stdout = BufReader::new(server.stdout.take().unwrap()).lines();
    let ready = stdout
        .by_ref()
        .map_while(Result::ok)
        .any(|line| line.starts_with("tenkai-server ready"));
    assert!(ready, "server reported ready");

    let status = Command::new("kill")
        .args(["-TERM", &server.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let deadline = Instant::now() + Duration::from_secs(10);
    let exit = loop {
        if let Some(exit) = server.try_wait().unwrap() {
            break exit;
        }
        if Instant::now() > deadline {
            server.kill().unwrap();
            panic!("server ignored SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut server.stderr.take().unwrap(), &mut stderr).unwrap();
    assert!(exit.success(), "graceful exit: {exit:?}\n{stderr}");
    assert!(stderr.contains("shutting down signal=SIGTERM"), "{stderr}");
    drop(stdout);
    let _ = std::fs::remove_dir_all(&state);
}
