use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum ProductCommand {
    /// Manage recurring product maintenance windows.
    Maintenance {
        #[command(subcommand)]
        command: ProductMaintenanceCommand,
    },
    /// Declare or clear product criticality (#694). Fleet management only.
    Criticality {
        #[command(subcommand)]
        command: ProductCriticalityCommand,
    },
    /// Name the product owner contact for display, audit, and notifications.
    Owner {
        #[command(subcommand)]
        command: ProductOwnerCommand,
    },
    /// Manage signed notification endpoints on the product. Never secret bytes.
    Webhooks {
        #[command(subcommand)]
        command: ProductWebhooksCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum ProductOwnerCommand {
    Show { product: String },
    Set { product: String, contact: String },
    Clear { product: String },
}

#[derive(Subcommand)]
pub(crate) enum ProductWebhooksCommand {
    List {
        product: String,
    },
    Set {
        product: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        secret_env: String,
        #[arg(long)]
        events: Option<String>,
    },
    Clear {
        product: String,
        #[arg(long)]
        url: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ProductCriticalityCommand {
    Show {
        product: String,
    },
    Set {
        product: String,
        #[arg(long)]
        level: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        reason: String,
    },
    Clear {
        product: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ProductMaintenanceCommand {
    Set {
        product: String,
        identity: String,
        #[arg(long)]
        timezone: String,
        #[arg(long)]
        weekdays: String,
        #[arg(long)]
        start: String,
        #[arg(long)]
        duration_minutes: u32,
    },
    List {
        product: String,
    },
    Remove {
        product: String,
        identity: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cli, Command};
    use clap::Parser;

    #[test]
    fn parses_restart_and_product_maintenance() {
        let restart =
            Cli::try_parse_from(["tenkaictl", "restart", "api", "--env", "prod"]).unwrap();
        assert!(matches!(
            restart.command,
            Command::Restart {
                ref product,
                ref env,
                ..
            } if product == "api" && env.as_deref() == Some("prod")
        ));
        let product = Cli::try_parse_from([
            "tenkaictl",
            "product",
            "maintenance",
            "set",
            "api",
            "sunday",
            "--timezone",
            "UTC",
            "--weekdays",
            "sun",
            "--start",
            "02:00",
            "--duration-minutes",
            "60",
        ])
        .unwrap();
        assert!(matches!(
            product.command,
            Command::Product {
                command: ProductCommand::Maintenance {
                    command: ProductMaintenanceCommand::Set {
                        duration_minutes: 60,
                        ..
                    }
                }
            }
        ));
    }
}
