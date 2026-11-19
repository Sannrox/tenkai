//! Rollback flag validation at the `tenkaictl` command boundary (#1346).

#[allow(dead_code)]
mod common;

/// An invalid embedded flag combination is refused before the rollback is
/// planned. On a store with no release history, planning would fail first with
/// a different error, so this also proves no plan is stored for the bad flags.
#[test]
fn embedded_rollback_refuses_no_hold_before_planning() {
    let cli = common::CliDrill::new("tenkai-rollback-flags", "rollback-flags-token", &[]);
    let output = cli.fail(&[
        "rollback",
        "api",
        "--env",
        "prod",
        "--no-hold",
        "--reason",
        "resume",
    ]);
    assert!(
        output.contains("--no-hold applies only when rollback executes now"),
        "{output}"
    );
}

/// Remote rollback only plans and its API carries neither reason, so a reason
/// flag is refused instead of silently dropped.
#[test]
fn remote_rollback_refuses_reasons_it_cannot_send() {
    let cli = common::CliDrill::new("tenkai-rollback-flags-remote", "rollback-flags-token", &[]);
    for reason_flag in ["--emergency-reason", "--reason"] {
        let output = cli.fail(&[
            "--target",
            "remote",
            "--server-url",
            "http://[::1]:9",
            "rollback",
            "api",
            "--env",
            "prod",
            "--generation",
            "1",
            reason_flag,
            "why",
        ]);
        assert!(output.contains("not sent by remote rollback"), "{output}");
    }
}
