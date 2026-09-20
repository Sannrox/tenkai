use anyhow::Result;
use tenkai::client;

use crate::args::{Cli, Command};

pub(crate) async fn run(cli: Cli) -> Result<()> {
    let output = cli.output;
    let database = cli.database.clone();
    let mut ctx = client::Ctx::embedded(&database)?;
    match cli.command {
        command @ (Command::Init
        | Command::Publish { .. }
        | Command::Release { .. }
        | Command::Approval { .. }
        | Command::Promote { .. }
        | Command::Canary { .. }) => crate::embedded_catalog::run(&mut ctx, command, output).await,
        Command::Fleet { command } => {
            crate::embedded_fleet::run(&mut ctx, command, &database).await
        }
        Command::Upgrade { command } => crate::embedded_upgrade::run(&mut ctx, command).await,
        Command::Migrate { command } => crate::embedded_migrate::run(&mut ctx, command).await,
        Command::Wave { command } => crate::embedded_wave::run(&mut ctx, command).await,
        Command::Env { command } => crate::embedded_env::run(&mut ctx, command, output).await,
        command @ (Command::Plan { .. }
        | Command::Apply { .. }
        | Command::Status { .. }
        | Command::Recovery { .. }
        | Command::Inspect
        | Command::Backup { .. }) => {
            crate::embedded_apply::run(&mut ctx, command, output, &database).await
        }
        command @ (Command::Rollback { .. } | Command::Restart { .. }) => {
            crate::embedded_rollback::run(&mut ctx, command, output).await
        }
        Command::Product { command } => crate::embedded_product::run(&mut ctx, command).await,
        command @ Command::Reconcile { .. } => crate::embedded_reconcile::run(ctx, command).await,
        Command::Restore { .. } | Command::Dev { .. } | Command::ExecutorGuard { .. } => {
            unreachable!("handled before opening the embedded database")
        }
    }
}
