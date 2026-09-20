use std::path::PathBuf;

use clap::Parser;

use crate::args::{Cli, Command, Target};
use crate::env_args::{EnvCommand, MaintenanceCommand, OverlayCommand};
use crate::wave_args::WaveCommand;

#[test]
fn parses_maintenance_window_configuration() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "maintenance",
        "set",
        "prod",
        "weekday",
        "--timezone",
        "Europe/Berlin",
        "--weekdays",
        "mon,tue,wed,thu,fri",
        "--start",
        "22:00",
        "--duration-minutes",
        "120",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Env {
            command: EnvCommand::Maintenance {
                command: MaintenanceCommand::Set {
                    duration_minutes: 120,
                    ..
                }
            }
        }
    ));
}

#[test]
fn parses_overlay_and_recalled_recovery() {
    let overlay = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "overlay",
        "set",
        "prod",
        "api",
        "region=eu",
    ])
    .unwrap();
    assert!(matches!(
        overlay.command,
        Command::Env {
            command: EnvCommand::Overlay {
                command: OverlayCommand::Set {
                    ref env,
                    ref product,
                    ref spec,
                }
            }
        } if env == "prod" && product == "api" && spec == "region=eu"
    ));
    let rollback = Cli::try_parse_from([
        "tenkaictl",
        "rollback",
        "api",
        "--env",
        "prod",
        "--allow-recalled-recovery",
        "--recovery-reason",
        "restore last known-good",
    ])
    .unwrap();
    assert!(matches!(
        rollback.command,
        Command::Rollback {
            ref product,
            allow_recalled_recovery: true,
            recovery_reason: Some(ref reason),
            ..
        } if product == "api" && reason == "restore last known-good"
    ));
}

#[test]
fn parses_emergency_override_reason() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "apply",
        "tenkai:plan:prod:1:digest",
        "--emergency-reason",
        "restore critical service",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Apply {
            emergency_reason: Some(ref reason),
            ..
        } if reason == "restore critical service"
    ));
}

#[test]
fn remote_target_is_explicit_and_carries_no_cli_secret() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "--target",
        "remote",
        "--server-url",
        "https://tenkai.example.test",
        "reconcile",
        "--once",
    ])
    .unwrap();
    assert_eq!(cli.target, Target::Remote);
    assert_eq!(
        cli.server_url.as_deref(),
        Some("https://tenkai.example.test")
    );
    assert!(matches!(cli.command, Command::Reconcile { once: true, .. }));
}

#[test]
fn parses_env_list_and_inspect() {
    let list = Cli::try_parse_from(["tenkaictl", "env", "list"]).unwrap();
    assert!(matches!(
        list.command,
        Command::Env {
            command: EnvCommand::List
        }
    ));
    let inspect = Cli::try_parse_from(["tenkaictl", "env", "inspect", "prod"]).unwrap();
    assert!(matches!(
        inspect.command,
        Command::Env {
            command: EnvCommand::Inspect { ref env }
        } if env == "prod"
    ));
    let preview = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "preview",
        "review",
        "--pin",
        "pin.json",
        "--expires-at",
        "2026-09-16T00:00:00Z",
    ])
    .unwrap();
    assert!(matches!(
        preview.command,
        Command::Env {
            command: EnvCommand::Preview { ref name, ref expires_at, .. }
        } if name == "review" && expires_at == "2026-09-16T00:00:00Z"
    ));
    let close = Cli::try_parse_from(["tenkaictl", "env", "close-preview", "review"]).unwrap();
    assert!(matches!(
        close.command,
        Command::Env {
            command: EnvCommand::ClosePreview { ref env }
        } if env == "review"
    ));
    let cluster = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "cluster-config",
        "set",
        "lab",
        "/tmp/lab.kubeconfig",
    ])
    .unwrap();
    assert!(matches!(
        cluster.command,
        Command::Env {
            command: EnvCommand::ClusterConfig {
                command: crate::env_args::ClusterConfigCommand::Set { ref env, ref path }
            }
        } if env == "lab" && path == std::path::Path::new("/tmp/lab.kubeconfig")
    ));
}

#[test]
fn parses_one_shot_reconciler_settings() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "reconcile",
        "--once",
        "--initial-backoff",
        "3",
        "--max-backoff",
        "30",
        "--max-concurrency",
        "4",
        "--skip-gates",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Reconcile {
            once: true,
            initial_backoff: 3,
            max_backoff: 30,
            max_concurrency: 4,
            skip_gates: true,
            ..
        }
    ));
}

#[test]
fn parses_shared_apply_and_wave_approval_flags() {
    let apply = Cli::try_parse_from([
        "tenkaictl",
        "apply",
        "tenkai:plan:local:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--approval",
        "plan.approval.json",
        "--approval-trust-roots",
        "approvers.toml",
    ])
    .unwrap();
    let Command::Apply { approval, .. } = apply.command else {
        panic!("expected apply");
    };
    assert_eq!(approval.approval, Some(PathBuf::from("plan.approval.json")));
    assert_eq!(
        approval.approval_trust_roots,
        Some(PathBuf::from("approvers.toml"))
    );
    assert!(!approval.allow_unapproved_development);

    let wave = Cli::try_parse_from([
        "tenkaictl",
        "wave",
        "resume",
        "cutover",
        "--allow-unapproved-development",
        "--development-reason",
        "local drill",
    ])
    .unwrap();
    let Command::Wave {
        command: WaveCommand::Resume { approval, .. },
    } = wave.command
    else {
        panic!("expected wave resume");
    };
    assert!(approval.approval_dir.is_none());
    assert!(approval.allow_unapproved_development);
    assert_eq!(approval.development_reason.as_deref(), Some("local drill"));
}
