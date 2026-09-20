use anyhow::Result;

use crate::args::{Cli, Command};
use crate::dev_args::DevCommand;
use tenkai::dev_sign;

pub(crate) async fn restore(cli: &Cli) -> Result<()> {
    let Command::Restore { source } = &cli.command else {
        unreachable!("restore dispatcher received a non-restore command");
    };
    tenkai::storage::refuse_postgres_on_embedded()?;
    tenkai::storage::SqliteStore::restore(source, &cli.database)?;
    println!(
        "restored embedded state from {} to {}",
        source.display(),
        cli.database.display()
    );
    Ok(())
}

pub(crate) async fn run_dev(cli: &Cli) -> Result<()> {
    let Command::Dev { command } = &cli.command else {
        unreachable!("dev dispatcher received a non-dev command");
    };
    match command {
        DevCommand::InitKeys { dir } => {
            let path = dev_sign::init_dev_keys(dir)?;
            println!("{}", dev_sign::warning_line());
            println!("initialized development keys in {}", path.display());
            Ok(())
        }
        DevCommand::SignRelease {
            manifest,
            keys,
            signature,
            trust_roots,
        } => {
            let written = dev_sign::sign_release(keys, manifest, signature, trust_roots)?;
            println!("{}", dev_sign::warning_line());
            println!("wrote signature  {}", written.envelope.display());
            println!("wrote trust roots {}", written.trust_roots.display());
            println!(
                "publish with: tenkaictl publish {} --signature {} --trust-roots {}",
                manifest.display(),
                written.envelope.display(),
                written.trust_roots.display()
            );
            Ok(())
        }
        DevCommand::SignApproval {
            plan_id,
            plan_digest,
            env,
            keys,
            approval,
            trust_roots,
            ttl_secs,
        } => {
            let written = if let (Some(plan_digest), Some(env)) = (plan_digest, env) {
                dev_sign::sign_plan_approval_for_digest(
                    keys,
                    plan_digest,
                    env,
                    approval,
                    trust_roots,
                    *ttl_secs,
                )?
            } else {
                let plan_id = plan_id.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("plan id is required unless --plan-digest and --env are set")
                })?;
                dev_sign::sign_plan_approval(
                    keys,
                    &cli.database,
                    plan_id,
                    approval,
                    trust_roots,
                    *ttl_secs,
                )
                .await?
            };
            println!("{}", dev_sign::warning_line());
            println!("wrote approval   {}", written.envelope.display());
            println!("wrote trust roots {}", written.trust_roots.display());
            if let Some(plan_id) = plan_id {
                println!(
                    "apply with: tenkaictl --database {} apply {} --approval {} --approval-trust-roots {}",
                    cli.database.display(),
                    plan_id,
                    written.envelope.display(),
                    written.trust_roots.display()
                );
            }
            Ok(())
        }
        DevCommand::SignMigrationApproval {
            identity,
            env,
            keys,
            approval,
            trust_roots,
            ttl_secs,
        } => {
            let written = dev_sign::sign_migration_approval(
                keys,
                identity,
                env,
                approval,
                trust_roots,
                *ttl_secs,
            )?;
            println!("{}", dev_sign::warning_line());
            println!("wrote approval   {}", written.envelope.display());
            println!("wrote trust roots {}", written.trust_roots.display());
            println!(
                "migrate with: tenkaictl migrate apply <name> --env {env} --declaration <file> --approval {} --approval-trust-roots {}",
                written.envelope.display(),
                written.trust_roots.display()
            );
            Ok(())
        }
    }
}
