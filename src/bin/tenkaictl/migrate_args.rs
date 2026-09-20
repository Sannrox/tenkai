use std::path::PathBuf;

use clap::Subcommand;

use crate::flags::ApprovalFileFlags;

#[derive(Subcommand)]
pub(crate) enum MigrateCommand {
    /// Preview admission without persisting a migration record.
    Preview {
        name: String,
        #[arg(long, default_value = "local")]
        env: String,
        /// tenkai.package_migration.v1 JSON declaration.
        #[arg(long)]
        declaration: PathBuf,
        /// Content-bound backup receipt required before irreversible checkpoints.
        #[arg(long)]
        backup_receipt_digest: Option<String>,
    },
    /// Admit, approve, and execute a package migration until it is blocked or terminal.
    Apply {
        name: String,
        #[arg(long, default_value = "local")]
        env: String,
        #[arg(long)]
        declaration: PathBuf,
        #[arg(long)]
        backup_receipt_digest: Option<String>,
        /// Current fencing generation; required with --target remote.
        #[arg(long)]
        expected_generation: Option<u64>,
        #[command(flatten)]
        approval: ApprovalFileFlags,
    },
    /// Show a stored package migration and its checkpoint receipts.
    Status { name: String },
    /// Resume an approved migration from the last accepted checkpoint.
    Resume {
        name: String,
        #[arg(long)]
        expected_generation: Option<u64>,
        #[command(flatten)]
        approval: ApprovalFileFlags,
    },
    /// Roll back reversible or compensating checkpoints; irreversible work stays recovery-required.
    Rollback {
        name: String,
        #[arg(long)]
        expected_generation: Option<u64>,
        #[command(flatten)]
        approval: ApprovalFileFlags,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cli, Command};
    use crate::dev_args::DevCommand;
    use clap::Parser;

    #[test]
    fn parses_package_migration_commands() {
        let preview = Cli::try_parse_from([
            "tenkaictl",
            "migrate",
            "preview",
            "cutover",
            "--declaration",
            "declaration.json",
            "--backup-receipt-digest",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .unwrap();
        assert!(matches!(
            preview.command,
            Command::Migrate {
                command: MigrateCommand::Preview { ref name, .. }
            } if name == "cutover"
        ));
        let apply = Cli::try_parse_from([
            "tenkaictl",
            "migrate",
            "apply",
            "cutover",
            "--declaration",
            "declaration.json",
            "--allow-unapproved-development",
            "--development-reason",
            "drill",
        ])
        .unwrap();
        assert!(matches!(
            apply.command,
            Command::Migrate {
                command: MigrateCommand::Apply {
                    ref name,
                    approval: ApprovalFileFlags {
                        allow_unapproved_development: true,
                        ..
                    },
                    ..
                }
            } if name == "cutover"
        ));
        let resume = Cli::try_parse_from([
            "tenkaictl",
            "migrate",
            "resume",
            "cutover",
            "--approval",
            "cutover.approval.json",
            "--approval-trust-roots",
            "approvers.toml",
            "--expected-generation",
            "1",
        ])
        .unwrap();
        assert!(matches!(
            resume.command,
            Command::Migrate {
                command: MigrateCommand::Resume {
                    ref name,
                    expected_generation: Some(1),
                    ..
                }
            } if name == "cutover"
        ));
        let sign = Cli::try_parse_from([
            "tenkaictl",
            "dev",
            "sign-migration-approval",
            "--identity",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--env",
            "drill",
            "--keys",
            "keys",
            "--approval",
            "cutover.approval.json",
            "--trust-roots",
            "approvers.toml",
        ])
        .unwrap();
        assert!(matches!(
            sign.command,
            Command::Dev {
                command: DevCommand::SignMigrationApproval { ref env, .. }
            } if env == "drill"
        ));
    }
}
