//! Bind refusals of the native TLS listener (#671).

use std::process::Command;

/// The server exits before binding and says why.
fn refused(args: &[&str]) -> String {
    let state = std::env::temp_dir().join(format!(
        "tenkai-listener-{}-{}",
        std::process::id(),
        args.len()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_tenkai-server"))
        .args(args)
        .arg("--database")
        .arg(state.join("tenkai.db"))
        .env(
            "TENKAI_MANAGEMENT_TOKEN",
            "listener-test-management-token-0123456789",
        )
        .env_remove("TENKAI_TLS_CERT")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&state);
    assert!(!output.status.success(), "the server must refuse {args:?}");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_plaintext_non_loopback_bind_is_refused() {
    let stderr = refused(&["--listen", "0.0.0.0:0"]);
    assert!(
        stderr.contains("refuses a plaintext non-loopback bind"),
        "{stderr}"
    );
}

#[test]
fn unauthenticated_metrics_stay_on_loopback() {
    let dir = std::env::temp_dir().join(format!("tenkai-listener-cert-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), "unused").unwrap();
    let cert = dir.join("cert.pem");
    let stderr = refused(&[
        "--listen",
        "0.0.0.0:0",
        "--tls-cert",
        cert.to_str().unwrap(),
        "--enable-metrics",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(stderr.contains("needs a loopback bind"), "{stderr}");
}
