use std::path::PathBuf;

use clap::Subcommand;

use crate::flags::{ApprovalFileFlags, DevelopmentBypassFlags};

#[derive(Subcommand)]
pub(crate) enum UpgradeCommand {
    /// Admit a durable connectivity-class upgrade.
    Start {
        name: String,
        #[arg(long)]
        product: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        channel: String,
        /// Comma-separated environment names.
        #[arg(long)]
        cohort: String,
    },
    /// Show uniform upgrade status across connectivity classes.
    Status { name: String },
    /// Advance the next pending or interrupted environment.
    Advance {
        name: String,
        #[command(flatten)]
        approval: ApprovalFileFlags,
    },
    /// Interrupt an intermittent transfer before verified content.
    Interrupt { name: String, env: String },
    /// Resume a verified intermittent transfer.
    Resume { name: String, env: String },
    /// Install verified Tenkai host binaries from a signed offline bundle.
    InstallHosts {
        env: String,
        /// Path to a tenkai.offline-bundle.v1 JSON archive.
        #[arg(long)]
        bundle: PathBuf,
        /// Trust roots that must authenticate the bundle exporter.
        #[arg(long)]
        trust_roots: PathBuf,
        /// Directory that receives unsuffixed tenkaictl, tenkai-server, and tenkai-executor-guard.
        #[arg(long)]
        dest: PathBuf,
        /// Packaged host platform: linux-x86_64 or darwin-aarch64. Defaults to this process.
        #[arg(long)]
        platform: Option<String>,
    },
    /// First-install an empty isolated environment from one signed bundle.
    InstallBundle {
        name: String,
        env: String,
        #[arg(long)]
        product: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        channel: String,
        /// Path to a tenkai.offline-bundle.v1 JSON archive.
        #[arg(long)]
        bundle: PathBuf,
        /// Trust roots that must authenticate the bundle exporter.
        #[arg(long)]
        trust_roots: PathBuf,
        /// Mirror every image registry to this local seed registry
        /// (`host[:port]`), served by `tenkaictl registry serve`.
        #[arg(long)]
        seed_registry: Option<String>,
    },
    /// Bind a verified ADR 0003 isolated bundle.
    BindBundle {
        name: String,
        env: String,
        /// Path to a tenkai.offline-bundle.v1 JSON archive.
        #[arg(long)]
        bundle: PathBuf,
        /// Trust roots that must authenticate the bundle exporter.
        #[arg(long)]
        trust_roots: PathBuf,
    },
    /// Import a signed ADR 0003 isolated receipt (idempotent; conflicts fail closed).
    ImportReceipt {
        name: String,
        env: String,
        /// Path to a tenkai.offline-receipt.v1 JSON envelope.
        #[arg(long)]
        receipt: PathBuf,
        /// Path to the matching tenkai.offline-bundle.v1 JSON archive.
        #[arg(long)]
        bundle: PathBuf,
        /// Trust roots that must authenticate the bundle exporter and receipt runtime.
        #[arg(long)]
        trust_roots: PathBuf,
    },
    /// Roll back applied environments through Tenkai rollback plans.
    Rollback {
        name: String,
        #[command(flatten)]
        bypass: DevelopmentBypassFlags,
    },
    /// Remove stored layers and weights no kept release names. Kept: channel
    /// heads, deployed and previous deployed releases, unfinished upgrades.
    CollectContent {
        /// Remove the content; without it, only list what would go.
        #[arg(long)]
        apply: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cli, Command};
    use crate::env_args::EnvCommand;
    use clap::Parser;

    #[test]
    fn parses_connectivity_upgrade_commands() {
        let connectivity =
            Cli::try_parse_from(["tenkaictl", "env", "connectivity", "site-b", "intermittent"])
                .unwrap();
        assert!(matches!(
            connectivity.command,
            Command::Env {
                command: EnvCommand::Connectivity { ref env, ref class }
            } if env == "site-b" && class == "intermittent"
        ));
        let start = Cli::try_parse_from([
            "tenkaictl",
            "upgrade",
            "start",
            "fleet-1",
            "--product",
            "edge-app",
            "--version",
            "1.0.0",
            "--channel",
            "stable",
            "--cohort",
            "site-a,site-b,site-c",
        ])
        .unwrap();
        assert!(matches!(
            start.command,
            Command::Upgrade {
                command: UpgradeCommand::Start { ref name, .. }
            } if name == "fleet-1"
        ));
        let advance = Cli::try_parse_from([
            "tenkaictl",
            "upgrade",
            "advance",
            "fleet-1",
            "--approval",
            "site-a.json",
            "--approval-trust-roots",
            "release-trust.toml",
        ])
        .unwrap();
        assert!(matches!(
            advance.command,
            Command::Upgrade {
                command: UpgradeCommand::Advance {
                    ref name,
                    ref approval,
                    ..
                }
            } if name == "fleet-1" && approval.approval.as_deref() == Some(std::path::Path::new("site-a.json"))
        ));
        let install_hosts = Cli::try_parse_from([
            "tenkaictl",
            "upgrade",
            "install-hosts",
            "site-c",
            "--bundle",
            "site-c.bundle.json",
            "--trust-roots",
            "offline-trust.toml",
            "--dest",
            "hosts",
            "--platform",
            "linux-x86_64",
        ])
        .unwrap();
        assert!(matches!(
            install_hosts.command,
            Command::Upgrade {
                command: UpgradeCommand::InstallHosts { ref env, ref dest, ref platform, .. }
            } if env == "site-c"
                && dest == std::path::Path::new("hosts")
                && platform.as_deref() == Some("linux-x86_64")
        ));
        let install = Cli::try_parse_from([
            "tenkaictl",
            "upgrade",
            "install-bundle",
            "first-1",
            "site-c",
            "--product",
            "edge-app",
            "--version",
            "1.0.0",
            "--channel",
            "stable",
            "--bundle",
            "site-c.bundle.json",
            "--trust-roots",
            "offline-trust.toml",
        ])
        .unwrap();
        assert!(matches!(
            install.command,
            Command::Upgrade {
                command: UpgradeCommand::InstallBundle { ref name, ref env, .. }
            } if name == "first-1" && env == "site-c"
        ));
        let bind = Cli::try_parse_from([
            "tenkaictl",
            "upgrade",
            "bind-bundle",
            "fleet-1",
            "site-c",
            "--bundle",
            "site-c.bundle.json",
            "--trust-roots",
            "offline-trust.toml",
        ])
        .unwrap();
        assert!(matches!(
            bind.command,
            Command::Upgrade {
                command: UpgradeCommand::BindBundle { ref name, ref env, .. }
            } if name == "fleet-1" && env == "site-c"
        ));
        let import = Cli::try_parse_from([
            "tenkaictl",
            "upgrade",
            "import-receipt",
            "fleet-1",
            "site-c",
            "--receipt",
            "site-c.receipt.json",
            "--bundle",
            "site-c.bundle.json",
            "--trust-roots",
            "offline-trust.toml",
        ])
        .unwrap();
        assert!(matches!(
            import.command,
            Command::Upgrade {
                command: UpgradeCommand::ImportReceipt { ref name, ref env, .. }
            } if name == "fleet-1" && env == "site-c"
        ));
    }
}
