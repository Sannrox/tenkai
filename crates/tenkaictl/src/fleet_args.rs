use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum FleetCommand {
    /// Summarize delivery posture for every environment (embedded or remote).
    Status,
    /// Materialize a deterministic thousand-environment synthetic fleet.
    Generate {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        product: String,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        current_version: String,
        #[arg(long)]
        behind_version: String,
    },
    /// Measure the generated thousand-environment workload against named budgets.
    Measure {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        product: String,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        current_version: String,
        #[arg(long)]
        behind_version: String,
    },
    /// Check that failing synthetic environments do not starve the fleet.
    Fairness {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        product: String,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        current_version: String,
        #[arg(long)]
        behind_version: String,
        #[arg(long)]
        backup: PathBuf,
    },
    /// Poll fleet status and report posture drift versus a baseline or prior sample.
    Watch {
        /// Seconds between samples when not using --once.
        #[arg(long, default_value_t = 10)]
        interval: u64,
        /// Take one sample, compare, print, and exit (embedded automation / tests).
        #[arg(long)]
        once: bool,
        /// Optional JSON posture baseline (`tenkai.fleet-posture.v1`). Missing file = empty.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Write the latest posture snapshot as JSON after each sample.
        #[arg(long)]
        write_baseline: Option<PathBuf>,
        /// Exit non-zero on any posture change (not only new behind/unhealthy).
        #[arg(long)]
        exit_on_any_posture_change: bool,
        /// Exit non-zero when any environment is currently behind or unhealthy.
        #[arg(long)]
        exit_on_any_hard_drift: bool,
        /// Emit the drift summary as JSON (default is human text).
        #[arg(long)]
        json: bool,
        /// Maximum samples before exit (0 = unlimited). Implies continuous watch.
        #[arg(long, default_value_t = 0)]
        max_samples: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cli, Command, Target};
    use clap::Parser;

    #[test]
    fn parses_fleet_status() {
        let cli = Cli::try_parse_from(["tenkaictl", "fleet", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Fleet {
                command: FleetCommand::Status
            }
        ));
        let remote = Cli::try_parse_from([
            "tenkaictl",
            "--target",
            "remote",
            "--server-url",
            "http://127.0.0.1:8080",
            "fleet",
            "status",
        ])
        .unwrap();
        assert_eq!(remote.target, Target::Remote);
        assert!(matches!(
            remote.command,
            Command::Fleet {
                command: FleetCommand::Status
            }
        ));
        let generate = Cli::try_parse_from([
            "tenkaictl",
            "fleet",
            "generate",
            "--seed",
            "demo-seed",
            "--product",
            "scale-app",
            "--channel",
            "stable",
            "--current-version",
            "1.1.0",
            "--behind-version",
            "1.0.0",
        ])
        .unwrap();
        assert!(matches!(
            generate.command,
            Command::Fleet {
                command: FleetCommand::Generate { ref seed, .. }
            } if seed == "demo-seed"
        ));
        let measure = Cli::try_parse_from([
            "tenkaictl",
            "fleet",
            "measure",
            "--seed",
            "demo-seed",
            "--product",
            "scale-app",
            "--channel",
            "stable",
            "--current-version",
            "1.1.0",
            "--behind-version",
            "1.0.0",
        ])
        .unwrap();
        assert!(matches!(
            measure.command,
            Command::Fleet {
                command: FleetCommand::Measure { ref seed, .. }
            } if seed == "demo-seed"
        ));
    }

    #[test]
    fn parses_fleet_watch() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "fleet",
            "watch",
            "--once",
            "--baseline",
            "/tmp/baseline.json",
            "--write-baseline",
            "/tmp/out.json",
            "--exit-on-any-hard-drift",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Command::Fleet {
                command:
                    FleetCommand::Watch {
                        once,
                        baseline,
                        write_baseline,
                        exit_on_any_hard_drift,
                        json,
                        interval,
                        ..
                    },
            } => {
                assert!(once);
                assert_eq!(
                    baseline.as_deref(),
                    Some(std::path::Path::new("/tmp/baseline.json"))
                );
                assert_eq!(
                    write_baseline.as_deref(),
                    Some(std::path::Path::new("/tmp/out.json"))
                );
                assert!(exit_on_any_hard_drift);
                assert!(json);
                assert_eq!(interval, 10);
            }
            _ => panic!("expected fleet watch command"),
        }
    }
}
