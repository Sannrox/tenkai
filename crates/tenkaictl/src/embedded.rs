use anyhow::Result;
use tenkai::client;

use crate::args::{Cli, Command};
use crate::client_config::{self, ClientConfig};

pub(crate) async fn run(mut cli: Cli, config: &ClientConfig) -> Result<()> {
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
    let fill_env = client_config::needs_env_resolution(&mut cli.command);
    if fill_env {
        let names = if config.default_environment.is_some() {
            Vec::new()
        } else {
            tenkai::environment::registered_environment_names(&mut ctx).await?
        };
        client_config::apply_resolved_environment(&mut cli.command, config, &names)?;
    }
    match cli.command {
        Command::Release {
            command: crate::catalog_args::ReleaseCommand::Render { .. },
        } => unreachable!("handled before opening the embedded database"),
        command @ (Command::Init
        | Command::Publish { .. }
        | Command::Release { .. }
        | Command::Exposure { .. }
        | Command::Criticality { .. }
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
        Command::Channel {
            command:
                crate::catalog_args::ChannelCommand::Remove {
                    product,
                    channel,
                    expected_head,
                },
        } => {
            let actor = crate::authorization::embedded_management_actor()?;
            let removed = tenkai::catalog::remove_channel_head(
                &mut ctx,
                &actor,
                &product,
                &channel,
                expected_head.as_deref(),
            )
            .await?;
            match removed {
                Some(head) => println!("removed {head} from channel {product}/{channel}"),
                None => println!("channel {product}/{channel} has no head"),
            }
            Ok(())
        }
        Command::Channel {
            command:
                crate::catalog_args::ChannelCommand::Policy {
                    product,
                    channel,
                    source,
                    soak,
                    require_canary,
                    require_health_slo,
                    require_evaluation,
                    recall_on_failing,
                    pause,
                    resume,
                },
        } => {
            let actor = crate::authorization::embedded_management_actor()?;
            if pause || resume {
                let active = tenkai::channel_promotion::set_paused(
                    &mut ctx, &actor, &product, &channel, pause,
                )
                .await?;
                println!(
                    "channel promotion policy {} {} for {product}/{channel}",
                    active.id(),
                    if active.paused { "paused" } else { "resumed" }
                );
                return Ok(());
            }
            let source = source.ok_or_else(|| {
                anyhow::anyhow!("channel policy requires --from <source-channel>")
            })?;
            let soak =
                soak.ok_or_else(|| anyhow::anyhow!("channel policy requires --soak <duration>"))?;
            let active = tenkai::channel_promotion::configure(
                &mut ctx,
                &actor,
                tenkai::channel_promotion::ChannelPromotionPolicy {
                    product: product.clone(),
                    target_channel: channel.clone(),
                    source_channel: source,
                    soak_duration_ms: tenkai::channel_promotion::parse_soak(&soak)?,
                    stale_after_ms: 0,
                    evidence: tenkai::channel_promotion::ChannelPromotionEvidence {
                        canary: require_canary,
                        health_slo: require_health_slo,
                        evaluation: require_evaluation,
                        recall_on_failing,
                        ..Default::default()
                    },
                },
            )
            .await?;
            println!(
                "channel promotion policy {} active for {product}/{channel} soak {}ms",
                active.id(),
                active.policy.soak_duration_ms
            );
            Ok(())
        }
        Command::Fleet { command } => {
            crate::embedded_fleet::run(&mut ctx, command, &database, output).await
        }
        Command::Upgrade { command } => crate::embedded_upgrade::run(&mut ctx, command).await,
        Command::Bundle { command } => crate::embedded_bundle::run(&mut ctx, command).await,
        Command::Migrate { command } => crate::embedded_migrate::run(&mut ctx, command).await,
        Command::Wave { command } => crate::embedded_wave::run(&mut ctx, command).await,
        Command::Remediate { command } => crate::embedded_remediate::run(&mut ctx, command).await,
        Command::Topology { command } => crate::embedded_topology::run(&mut ctx, command).await,
        Command::Env { command } => crate::embedded_env::run(&mut ctx, command, output).await,
        command @ (Command::Plan { .. }
        | Command::Apply { .. }
        | Command::Status { .. }
        | Command::Explain { .. }
        | Command::Recovery { .. }
        | Command::Inspect
        | Command::Backup { .. }) => {
            crate::embedded_apply::run(&mut ctx, command, output, &database).await
        }
        command @ (Command::Rollback { .. } | Command::Restart { .. }) => {
            crate::embedded_rollback::run(&mut ctx, command, output).await
        }
        Command::Product { command } => crate::embedded_product::run(&mut ctx, command).await,
        Command::Train { command } => crate::embedded_train::run(&mut ctx, command).await,
        Command::Preflight {
            env,
            config,
            signing_key,
        } => crate::embedded_preflight::run(&mut ctx, &env, &config, &signing_key).await,
        command @ Command::Reconcile { .. } => crate::embedded_reconcile::run(ctx, command).await,
        Command::Runtime { .. } => anyhow::bail!(
            "runtime agents enroll with a Tenkai server; run this with --target remote"
        ),
        Command::Secret {
            command:
                crate::args::SecretCommand::RecoveryKey {
                    command: crate::args::RecoveryKeyCommand::Generate { path },
                },
        } => crate::secret::generate_recovery_key(&path),
        Command::Secret { .. } => anyhow::bail!(
            "sealed secrets and recipient pins need a Tenkai server; run this with --target remote"
        ),
        Command::IdentityIssuer { .. } => anyhow::bail!(
            "the identity issuer lives in environment runtimes; run this with --target remote"
        ),
        Command::Restore { .. }
        | Command::SupportBundle { .. }
        | Command::RestoreDrill { .. }
        | Command::BackupEvidence { .. }
        | Command::Audit { .. }
        | Command::Dev { .. }
        | Command::ExecutorGuard { .. }
        | Command::Login { .. }
        | Command::Revocations { .. }
        | Command::Keys { .. }
        | Command::DarkSite { .. }
        | Command::SpokeStandby { .. }
        | Command::Registry { .. }
        | Command::SelfUpgrade { .. }
        | Command::RunnerCa { .. }
        | Command::Logout => {
            unreachable!("handled before opening the embedded database")
        }
    }
}
