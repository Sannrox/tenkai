use std::path::PathBuf;

use clap::Parser;

use crate::args::{
    Cli, Command, DarkSiteCommand, KeysCommand, RemediateCommand, SecretCommand,
    SpokeStandbyCommand, Target,
};
use crate::catalog_args::ChannelCommand;
use crate::env_args::{EnvCommand, MaintenanceCommand, OverlayCommand};
use crate::topology_args::TopologyCommand;
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
fn parses_keys_ceremony() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "keys",
        "ceremony",
        "--profile",
        "profile.toml",
        "--signing-key",
        "ceremony.ed25519",
        "--custodian",
        "alice",
        "--custodian",
        "bob",
        "--tenant",
        "acme",
        "--provider-dir",
        "provider",
        "--out",
        "evidence.json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Keys {
            command: KeysCommand::Ceremony {
                ref custodian,
                ref tenant,
                ..
            }
        } if custodian.as_slice() == ["alice", "bob"] && tenant.as_slice() == ["acme"]
    ));
}

#[test]
fn parses_dark_site_activate() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "dark-site",
        "activate",
        "--profile",
        "profile.toml",
        "--stack",
        "stack.json",
        "--state",
        "runtime",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::DarkSite {
            command: DarkSiteCommand::Activate { .. }
        }
    ));
}

#[test]
fn parses_dark_site_ready_and_rollback() {
    let ready = Cli::try_parse_from([
        "tenkaictl",
        "dark-site",
        "ready",
        "--state",
        "runtime",
        "--model-health",
        "healthy",
        "--ready-replicas",
        "2",
    ])
    .unwrap();
    assert!(matches!(
        ready.command,
        Command::DarkSite {
            command: DarkSiteCommand::Ready {
                ready_replicas: 2,
                ..
            }
        }
    ));
    let rollback = Cli::try_parse_from([
        "tenkaictl",
        "dark-site",
        "rollback",
        "--state",
        "runtime",
        "--active-claims",
        "1",
    ])
    .unwrap();
    assert!(matches!(
        rollback.command,
        Command::DarkSite {
            command: DarkSiteCommand::Rollback {
                active_claims: 1,
                ..
            }
        }
    ));
}

#[test]
fn parses_channel_remove_expected_head() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "channel",
        "remove",
        "api",
        "stable",
        "--expected-head",
        "api@1.0.0",
    ])
    .unwrap();
    match cli.command {
        Command::Channel {
            command:
                ChannelCommand::Remove {
                    product,
                    channel,
                    expected_head,
                },
        } => {
            assert_eq!(product, "api");
            assert_eq!(channel, "stable");
            assert_eq!(expected_head.as_deref(), Some("api@1.0.0"));
        }
        _ => panic!("expected channel remove"),
    }
}

#[test]
fn parses_spoke_standby_validate_promote_and_drill() {
    let validate = Cli::try_parse_from([
        "tenkaictl",
        "spoke-standby",
        "validate",
        "--profile",
        "profile.toml",
    ])
    .unwrap();
    assert!(matches!(
        validate.command,
        Command::SpokeStandby {
            command: SpokeStandbyCommand::Validate { .. }
        }
    ));
    let promote = Cli::try_parse_from([
        "tenkaictl",
        "spoke-standby",
        "promote",
        "--profile",
        "profile.toml",
        "--holder",
        "spoke-b",
        "--environment",
        "site",
        "--state",
        "spoke.db",
        "--lease-dir",
        "locks",
        "--signing-key",
        "seed",
    ])
    .unwrap();
    assert!(matches!(
        promote.command,
        Command::SpokeStandby {
            command: SpokeStandbyCommand::Promote { .. }
        }
    ));
    let drill = Cli::try_parse_from([
        "tenkaictl",
        "spoke-standby",
        "drill",
        "--profile",
        "profile.toml",
        "--signing-key",
        "seed",
        "--out",
        "drill.json",
    ])
    .unwrap();
    assert!(matches!(
        drill.command,
        Command::SpokeStandby {
            command: SpokeStandbyCommand::Drill { .. }
        }
    ));
}

#[test]
fn parses_environment_freeze_schedule() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "hold",
        "prod",
        "schedule",
        "black-friday",
        "--from",
        "2026-11-24T00:00:00Z",
        "--until",
        "2026-11-28T00:00:00Z",
        "--reason",
        "holiday freeze",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Env {
            command: EnvCommand::Hold {
                action: crate::env_args::HoldAction::Schedule {
                    ref name,
                    ref until,
                    ref reason,
                    ..
                },
                ..
            }
        } if name == "black-friday"
            && until == "2026-11-28T00:00:00Z"
            && reason == "holiday freeze"
    ));
}

#[test]
fn parses_environment_failure_threshold() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "hold",
        "prod",
        "threshold",
        "--count",
        "2",
        "--window",
        "15m",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Env {
            command: EnvCommand::Hold {
                action: crate::env_args::HoldAction::Threshold {
                    count: 2,
                    ref window,
                },
                ..
            }
        } if window == "15m"
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
fn status_without_target_or_env_stays_unspecified() {
    let cli = Cli::try_parse_from(["tenkaictl", "status"]).unwrap();
    assert_eq!(cli.target, None);
    assert!(matches!(cli.command, Command::Status { env: None }));
}

#[test]
fn parses_apply_cancel_env_and_reason() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "apply",
        "cancel",
        "prod",
        "--reason",
        "stop the rollout",
        "--generation",
        "4",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Apply {
            command: Some(crate::args::ApplyCommand::Cancel {
                ref env,
                ref reason,
                generation: Some(4),
                no_hold: false,
            }),
            ..
        } if env == "prod" && reason.as_deref() == Some("stop the rollout")
    ));
}

#[test]
fn apply_cancel_parses_no_hold() {
    let cli = Cli::try_parse_from(["tenkaictl", "apply", "cancel", "prod", "--no-hold"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Apply {
            command: Some(crate::args::ApplyCommand::Cancel { no_hold: true, .. }),
            ..
        }
    ));
}

#[test]
fn rollback_no_hold_requires_reason() {
    assert!(
        Cli::try_parse_from(["tenkaictl", "rollback", "api", "--env", "prod", "--no-hold"])
            .is_err()
    );
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "rollback",
        "api",
        "--env",
        "prod",
        "--no-hold",
        "--reason",
        "resume",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Rollback {
            no_hold: true,
            ref reason,
            ..
        } if reason.as_deref() == Some("resume")
    ));
}

#[test]
fn parses_explain_env_and_instance() {
    let cli = Cli::try_parse_from(["tenkaictl", "explain", "prod", "api"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Explain {
            ref env,
            ref instance,
        } if env == "prod" && instance == "api"
    ));
}

#[test]
fn parses_secret_trust_and_recipients() {
    let trust = Cli::try_parse_from([
        "tenkaictl",
        "secret",
        "trust",
        "prod",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ])
    .unwrap();
    assert!(matches!(
        trust.command,
        Command::Secret {
            command: SecretCommand::Trust { ref env, ref fingerprint },
        } if env == "prod"
            && fingerprint
                == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    let recipients = Cli::try_parse_from(["tenkaictl", "secret", "recipients", "prod"]).unwrap();
    assert!(matches!(
        recipients.command,
        Command::Secret {
            command: SecretCommand::Recipients { ref env },
        } if env == "prod"
    ));
}

#[test]
fn secret_set_takes_no_value_argument() {
    let set = Cli::try_parse_from([
        "tenkaictl",
        "secret",
        "set",
        "prod",
        "api",
        "db/password",
        "--generation",
        "3",
        "--reason",
        "rotate",
    ])
    .unwrap();
    assert!(matches!(
        set.command,
        Command::Secret {
            command: SecretCommand::Set { ref env, ref instance, ref secret, ref remote },
        } if env == "prod" && instance == "api" && secret == "db/password"
            && remote.generation == Some(3)
    ));
    for value in [
        &["s3cret"][..],
        &["--value", "s3cret"][..],
        &["--from-env", "DB_PASSWORD"][..],
    ] {
        let mut args = vec!["tenkaictl", "secret", "set", "prod", "api", "db/password"];
        args.extend_from_slice(value);
        assert!(Cli::try_parse_from(args).is_err(), "{value:?}");
    }
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
    assert_eq!(cli.target, Some(Target::Remote));
    assert_eq!(
        cli.server_url.as_deref(),
        Some("https://tenkai.example.test")
    );
    assert!(matches!(cli.command, Command::Reconcile { once: true, .. }));
}

#[test]
fn remote_configuration_commands_map_to_their_changes() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "maintenance",
        "set",
        "prod",
        "nightly",
        "--timezone",
        "UTC",
        "--weekdays",
        "mon,tue",
        "--start",
        "02:00",
        "--duration-minutes",
        "60",
        "--generation",
        "7",
        "--reason",
        "night changes",
    ])
    .unwrap();
    let Command::Env { command } = cli.command else {
        panic!("expected env command");
    };
    let (env, change, remote) = crate::remote_env_config::change(&command).unwrap().unwrap();
    assert_eq!(env, "prod");
    assert_eq!(
        change.path(env),
        "/v1/environments/prod/maintenance-windows/nightly"
    );
    assert_eq!(
        (remote.generation, remote.reason.as_deref()),
        (Some(7), Some("night changes"))
    );

    let criticality = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "criticality",
        "set",
        "prod",
        "--level",
        "critical",
        "--owner",
        "alice",
        "--reason",
        "pci",
        "--generation",
        "7",
    ])
    .unwrap();
    let Command::Env { command } = criticality.command else {
        panic!("expected env command");
    };
    let (env, change, remote) = crate::remote_env_config::change(&command).unwrap().unwrap();
    assert_eq!(env, "prod");
    assert_eq!(change.path(env), "/v1/environments/prod/criticality");
    assert_eq!(
        (remote.generation, remote.reason.as_deref()),
        (Some(7), Some("pci"))
    );

    let list = Cli::try_parse_from(["tenkaictl", "env", "facts", "list", "prod"]).unwrap();
    let Command::Env { command } = list.command else {
        panic!("expected env command");
    };
    assert!(crate::remote_env_config::change(&command).is_none());

    let bind = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "bind",
        "prod",
        "app",
        "database=db-a",
        "--generation",
        "7",
        "--reason",
        "select db-a",
    ])
    .unwrap();
    let Command::Env { command } = bind.command else {
        panic!("expected env command");
    };
    let (env, change, remote) = crate::remote_env_config::change(&command).unwrap().unwrap();
    assert_eq!(env, "prod");
    assert_eq!(change.path(env), "/v1/environments/prod/bindings");
    assert_eq!(
        (remote.generation, remote.reason.as_deref()),
        (Some(7), Some("select db-a"))
    );
}

#[test]
fn bundle_build_parses_hosts_only_without_release() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "bundle",
        "build",
        "--env",
        "dark-1",
        "--out",
        "hosts.bundle.json",
        "--signing-key",
        "exporter.seed",
        "--trust-roots",
        "offline-trust.toml",
        "--hosts-dir",
        "hosts",
        "--host-tag",
        "v0.5.0",
        "--host-git-sha",
        "0123456789abcdef0123456789abcdef01234567",
        "--host-workflow",
        "release",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Bundle {
            command: crate::bundle_args::BundleCommand::Build(ref args)
        } if args.releases.is_empty()
            && args.hosts_dir.as_deref() == Some(std::path::Path::new("hosts"))
            && args.env == "dark-1"
    ));
}

#[test]
fn bundle_build_without_release_or_hosts_dir_is_refused() {
    let err = Cli::try_parse_from([
        "tenkaictl",
        "bundle",
        "build",
        "--env",
        "dark-1",
        "--out",
        "site.bundle.json",
        "--signing-key",
        "exporter.seed",
        "--trust-roots",
        "offline-trust.toml",
    ])
    .err()
    .expect("bundle build without --release or --hosts-dir is refused");
    let text = err.to_string();
    assert!(
        text.contains("required") || text.contains("hosts-dir") || text.contains("release"),
        "{text}"
    );
}

#[test]
fn bundle_build_parses_release_set_and_public_trust_roots() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "bundle",
        "build",
        "--release",
        "edge-app@1.0.0",
        "--release",
        "weights@1.0.0",
        "--env",
        "dark-1",
        "--out",
        "site.bundle.json",
        "--signing-key",
        "exporter.seed",
        "--trust-roots",
        "offline-trust.toml",
        "--hosts-dir",
        "hosts",
        "--host-tag",
        "v0.5.0",
        "--host-git-sha",
        "0123456789abcdef0123456789abcdef01234567",
        "--host-workflow",
        "release",
        "--issued-at-unix-ms",
        "1700000000000",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Bundle {
            command: crate::bundle_args::BundleCommand::Build(ref args)
        } if args.releases == ["edge-app@1.0.0".to_string(), "weights@1.0.0".into()]
            && args.env == "dark-1"
            && args.out == std::path::Path::new("site.bundle.json")
    ));
}

#[test]
fn bundle_build_parses_advisory_feed() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "bundle",
        "build",
        "--release",
        "edge-app@1.0.0",
        "--env",
        "dark-1",
        "--out",
        "site.bundle.json",
        "--signing-key",
        "exporter.seed",
        "--trust-roots",
        "offline-trust.toml",
        "--advisory-feed",
        "advisories.json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Bundle {
            command: crate::bundle_args::BundleCommand::Build(ref args)
        } if args.advisory_feed.as_deref() == Some(std::path::Path::new("advisories.json"))
    ));
}

#[test]
fn bundle_build_parses_derived_criticality() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "bundle",
        "build",
        "--release",
        "edge-app@1.0.0",
        "--env",
        "dark-1",
        "--out",
        "site.bundle.json",
        "--signing-key",
        "exporter.seed",
        "--trust-roots",
        "offline-trust.toml",
        "--derived-criticality",
        "criticality.json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Bundle {
            command: crate::bundle_args::BundleCommand::Build(ref args)
        } if args.derived_criticality.as_deref() == Some(std::path::Path::new("criticality.json"))
    ));
}

#[test]
fn parses_exposure_import_inspect_and_query() {
    let import = Cli::try_parse_from([
        "tenkaictl",
        "exposure",
        "import",
        "--bundle",
        "site.bundle.json",
        "--trust-roots",
        "offline-trust.toml",
        "--env",
        "dark-1",
    ])
    .unwrap();
    assert!(matches!(
        import.command,
        Command::Exposure {
            command: crate::args::ExposureCommand::Import {
                ref bundle,
                ref trust_roots,
                ref env,
            }
        } if bundle == std::path::Path::new("site.bundle.json")
            && trust_roots == std::path::Path::new("offline-trust.toml")
            && env == "dark-1"
    ));
    let inspect = Cli::try_parse_from(["tenkaictl", "exposure", "inspect"]).unwrap();
    assert!(matches!(
        inspect.command,
        Command::Exposure {
            command: crate::args::ExposureCommand::Inspect
        }
    ));
    let query = Cli::try_parse_from([
        "tenkaictl",
        "exposure",
        "query",
        "--component",
        "openssl",
        "--range",
        ">=1.0.0",
    ])
    .unwrap();
    assert!(matches!(
        query.command,
        Command::Exposure {
            command: crate::args::ExposureCommand::Query {
                ref component,
                ref range,
                min_criticality: None,
            }
        } if component == "openssl" && range == ">=1.0.0"
    ));
}

#[test]
fn support_bundle_export_parses_beside_the_global_output_format() {
    let cli = Cli::try_parse_from([
        "tenkaictl",
        "--output",
        "json-v1",
        "support-bundle",
        "export",
        "--out",
        "support.json",
        "--signing-key",
        "support.seed",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::SupportBundle {
            command: crate::args::SupportBundleCommand::Export { ref out, .. }
        } if out == std::path::Path::new("support.json")
    ));
}

#[test]
fn parses_login_and_logout() {
    let login = Cli::try_parse_from([
        "tenkaictl",
        "--server-url",
        "https://tenkai.example.test",
        "login",
        "--no-browser",
        "--callback-port",
        "9876",
        "--client-id",
        "tenkai-cli",
    ])
    .unwrap();
    assert!(matches!(
        login.command,
        Command::Login {
            no_browser: true,
            client_credentials: false,
            callback_port: 9876,
            ref client_id,
            timeout: 300,
        } if client_id.as_deref() == Some("tenkai-cli")
    ));
    let client_credentials = Cli::try_parse_from([
        "tenkaictl",
        "--server-url",
        "https://tenkai.example.test",
        "login",
        "--client-credentials",
        "--client-id",
        "tenkai-ci",
    ])
    .unwrap();
    assert!(matches!(
        client_credentials.command,
        Command::Login {
            client_credentials: true,
            ref client_id,
            ..
        } if client_id.as_deref() == Some("tenkai-ci")
    ));
    let logout = Cli::try_parse_from([
        "tenkaictl",
        "--server-url",
        "https://tenkai.example.test",
        "logout",
    ])
    .unwrap();
    assert!(matches!(logout.command, Command::Logout));
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
    let history = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "history",
        "prod",
        "--product",
        "api",
        "--limit",
        "10",
        "--cursor",
        "1000:tenkai:deployment:prod:api:1000",
    ])
    .unwrap();
    assert!(matches!(
        history.command,
        Command::Env {
            command: EnvCommand::History {
                ref env,
                ref product,
                limit: Some(10),
                ref cursor,
            }
        } if env == "prod"
            && product.as_deref() == Some("api")
            && cursor.as_deref() == Some("1000:tenkai:deployment:prod:api:1000")
    ));
    let dependencies = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "dependencies",
        "prod",
        "--format",
        "json",
    ])
    .unwrap();
    assert!(matches!(
        dependencies.command,
        Command::Env {
            command: EnvCommand::Dependencies {
                ref env,
                format: crate::env_args::DependencyFormat::Json,
            }
        } if env == "prod"
    ));
    let retire = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "retire",
        "prod",
        "--reason",
        "service ended",
    ])
    .unwrap();
    assert!(matches!(
        retire.command,
        Command::Env {
            command: EnvCommand::Retire { ref env, ref reason }
        } if env == "prod" && reason == "service ended"
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
    let docker_secrets = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "docker-secrets",
        "set",
        "lab",
        "/var/lib/tenkai/lab-secrets",
    ])
    .unwrap();
    assert!(matches!(
        docker_secrets.command,
        Command::Env {
            command: EnvCommand::DockerSecrets {
                command: crate::env_args::DockerSecretsCommand::Set { ref env, ref path }
            }
        } if env == "lab" && path == std::path::Path::new("/var/lib/tenkai/lab-secrets")
    ));
    let webhooks = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "webhooks",
        "set",
        "lab",
        "--url",
        "https://hooks.example.test/tenkai",
        "--secret-env",
        "TENKAI_WEBHOOK_SECRET",
        "--events",
        "apply.succeeded,apply.rolled_back",
    ])
    .unwrap();
    assert!(matches!(
        webhooks.command,
        Command::Env {
            command: EnvCommand::Webhooks {
                command: crate::env_args::WebhooksCommand::Set {
                    ref env,
                    ref url,
                    ref secret_env,
                    ref events,
                    ..
                }
            }
        } if env == "lab"
            && url == "https://hooks.example.test/tenkai"
            && secret_env == "TENKAI_WEBHOOK_SECRET"
            && events.as_deref() == Some("apply.succeeded,apply.rolled_back")
    ));
}

#[test]
fn parse_webhook_events_splits_apply_operational_and_feedback() {
    let (events, operational, feedback) = crate::embedded_env_config::parse_webhook_events(Some(
        "apply.succeeded,plan.held,feedback.observation",
    ))
    .unwrap();
    assert_eq!(
        events,
        [tenkai::deploy_webhook::WebhookEvent::ApplySucceeded]
    );
    assert_eq!(
        operational,
        [tenkai::deploy_webhook::OperationalEvent::PlanHeld]
    );
    assert_eq!(
        feedback,
        [tenkai::deploy_webhook::FeedbackEvent::Observation]
    );
    let error = crate::embedded_env_config::parse_webhook_events(Some("not.an.event"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown webhook event"), "{error}");
}

#[test]
fn webhook_list_shows_feedback_and_does_not_imply_apply_for_feedback_only() {
    use tenkai::deploy_webhook::{FeedbackEvent, OperationalEvent, WebhookEndpoint, WebhookEvent};
    let feedback_only = WebhookEndpoint {
        url: "https://hooks.example/feedback".into(),
        secret_env: "HOOK".into(),
        events: Vec::new(),
        operational: Vec::new(),
        feedback: vec![FeedbackEvent::Observation],
    };
    assert_eq!(
        crate::embedded_env_config::format_webhook_subscription(&feedback_only),
        "feedback.observation"
    );
    let mixed = WebhookEndpoint {
        url: "https://hooks.example/mixed".into(),
        secret_env: "HOOK".into(),
        events: vec![WebhookEvent::ApplySucceeded],
        operational: vec![OperationalEvent::PlanHeld],
        feedback: vec![FeedbackEvent::Observation],
    };
    assert_eq!(
        crate::embedded_env_config::format_webhook_subscription(&mixed),
        "apply.succeeded,plan.held,feedback.observation"
    );
    let apply_default = WebhookEndpoint {
        url: "https://hooks.example/apply".into(),
        secret_env: "HOOK".into(),
        events: Vec::new(),
        operational: Vec::new(),
        feedback: Vec::new(),
    };
    assert_eq!(
        crate::embedded_env_config::format_webhook_subscription(&apply_default),
        "apply.succeeded,apply.failed,apply.rolled_back"
    );
}

#[test]
fn parses_approval_policy_configuration() {
    let approval_policy = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "approval-policy",
        "set",
        "lab",
        "/etc/tenkai/lab-approval-policy.toml",
    ])
    .unwrap();
    assert!(matches!(
        approval_policy.command,
        Command::Env {
            command: EnvCommand::ApprovalPolicy {
                command: crate::env_args::ApprovalPolicyCommand::Set { ref env, ref path, .. }
            }
        } if env == "lab" && path == std::path::Path::new("/etc/tenkai/lab-approval-policy.toml")
    ));
}

#[test]
fn parses_env_subscribe_and_unsubscribe_instance() {
    let subscribe = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "subscribe",
        "prod",
        "database=stable",
        "--instance",
        "db-a",
    ])
    .unwrap();
    assert!(matches!(
        subscribe.command,
        Command::Env {
            command: EnvCommand::Subscribe {
                ref env,
                ref spec,
                ref instance,
                ..
            }
        } if env == "prod" && spec == "database=stable" && instance.as_deref() == Some("db-a")
    ));
    let default =
        Cli::try_parse_from(["tenkaictl", "env", "subscribe", "prod", "database=stable"]).unwrap();
    assert!(matches!(
        default.command,
        Command::Env {
            command: EnvCommand::Subscribe {
                ref instance,
                ..
            }
        } if instance.is_none()
    ));
    let unsubscribe = Cli::try_parse_from([
        "tenkaictl",
        "env",
        "unsubscribe",
        "prod",
        "database",
        "--instance",
        "db-a",
    ])
    .unwrap();
    assert!(matches!(
        unsubscribe.command,
        Command::Env {
            command: EnvCommand::Unsubscribe {
                ref env,
                ref product,
                ref instance,
                ..
            }
        } if env == "prod" && product == "database" && instance.as_deref() == Some("db-a")
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

    let propose = Cli::try_parse_from([
        "tenkaictl",
        "remediate",
        "propose",
        "--exposure",
        "TENKAI-2026-1",
        "--fix",
        "api@1.1.0",
        "--channel",
        "stable",
        "--cohort",
        "canary,prod",
        "--signing-key",
        "notice.seed",
        "--notice-out",
        "notice.json",
    ])
    .unwrap();
    let Command::Remediate {
        command:
            RemediateCommand::Propose {
                ref exposure,
                ref fix,
                ref cohort,
                ref wave_name,
                ..
            },
    } = propose.command
    else {
        panic!("expected remediate propose");
    };
    assert_eq!(exposure, "TENKAI-2026-1");
    assert_eq!(fix, "api@1.1.0");
    assert_eq!(cohort, "canary,prod");
    assert!(wave_name.is_none());

    let import = Cli::try_parse_from([
        "tenkaictl",
        "remediate",
        "import-notice",
        "--notice",
        "notice.json",
        "--trust-roots",
        "notice-roots.toml",
    ])
    .unwrap();
    assert!(matches!(
        import.command,
        Command::Remediate {
            command: RemediateCommand::ImportNotice { .. }
        }
    ));

    let drill = Cli::try_parse_from([
        "tenkaictl",
        "topology",
        "drill",
        "ledger@1.0.0",
        "ledger-a",
        "--signing-key",
        "drill.seed",
        "--out",
        "drill.json",
    ])
    .unwrap();
    let Command::Topology {
        command:
            TopologyCommand::Drill {
                ref release,
                ref replica,
                ref signing_key,
                ref out,
            },
    } = drill.command
    else {
        panic!("expected topology drill");
    };
    assert_eq!(release, "ledger@1.0.0");
    assert_eq!(replica, "ledger-a");
    assert_eq!(signing_key, &PathBuf::from("drill.seed"));
    assert_eq!(out, &PathBuf::from("drill.json"));
}
