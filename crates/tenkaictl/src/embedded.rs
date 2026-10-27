use anyhow::Result;
use tenkai::client;

use crate::args::{Cli, Command};

pub(crate) async fn run(cli: Cli) -> Result<()> {
    let output = cli.output;
    let database = cli.database.clone();
    // A support bundle is most needed when the store cannot open, so it
    // reads a copy of the store itself and reports it unreadable instead of
    // failing; the live database is never opened for writing.
    if let Command::SupportBundle {
        command:
            crate::args::SupportBundleCommand::Export {
                out,
                signing_key,
                log_file,
            },
    } = cli.command
    {
        let mut log = log_file
            .map(std::fs::File::open)
            .transpose()
            .map_err(|error| anyhow::anyhow!("reading the log file: {error}"))?
            .map(std::io::BufReader::new);
        let bundle = tenkai::support_bundle::export_from_database(
            &database,
            log.as_mut()
                .map(|log| log as &mut (dyn std::io::BufRead + Send)),
            &signing_key,
            tenkai::now_millis(),
        )
        .await?;
        // A new file only: the output can never replace the database, the
        // seed or the log it was collected from.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out)
            .and_then(|mut file| {
                std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(&bundle)?)
            })
            .map_err(|error| anyhow::anyhow!("writing {}: {error}", out.display()))?;
        println!(
            "wrote support bundle {} ({} settings, {} recovery diagnostics, {} log events)",
            out.display(),
            bundle.statement.config.len(),
            bundle.statement.recovery.len(),
            bundle.statement.log_events.len()
        );
        return Ok(());
    }
    let mut ctx = client::Ctx::embedded(&database)?;
    match cli.command {
        command @ (Command::Init
        | Command::Publish { .. }
        | Command::Release { .. }
        | Command::Approval { .. }
        | Command::Promote { .. }
        | Command::EvalEvidence { .. }
        | Command::Canary { .. }) => crate::embedded_catalog::run(&mut ctx, command, output).await,
        Command::Channel {
            command:
                crate::catalog_args::ChannelCommand::Hold {
                    product,
                    channel,
                    action,
                },
        } => {
            crate::embedded_hold::run(
                &mut ctx,
                tenkai::delivery_hold::HoldScope::channel(&product, &channel),
                action,
            )
            .await
        }
        Command::Fleet { command } => {
            crate::embedded_fleet::run(&mut ctx, command, &database, output).await
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
        Command::Preflight {
            env,
            config,
            signing_key,
        } => crate::embedded_preflight::run(&mut ctx, &env, &config, &signing_key).await,
        command @ Command::Reconcile { .. } => crate::embedded_reconcile::run(ctx, command).await,
        Command::Runtime { .. } => anyhow::bail!(
            "runtime agents enroll with a Tenkai server; run this with --target remote"
        ),
        Command::Restore { .. }
        | Command::SupportBundle { .. }
        | Command::RestoreDrill { .. }
        | Command::Audit { .. }
        | Command::Dev { .. }
        | Command::ExecutorGuard { .. }
        | Command::Login { .. }
        | Command::Revocations { .. }
        | Command::Keys { .. }
        | Command::Registry { .. }
        | Command::SelfUpgrade { .. }
        | Command::Logout => {
            unreachable!("handled before opening the embedded database")
        }
    }
}
