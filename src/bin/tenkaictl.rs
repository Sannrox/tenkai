//! tenkaictl — local delivery control plane CLI, backed by sekai-chisei.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use tenkai::{apply, catalog, client, ontology, plan};

#[derive(Parser)]
#[command(
    name = "tenkaictl",
    version,
    about = "Constraint-based local delivery on sekai-chisei"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register the tenkai schema in sekai and create the `local` environment.
    Init,
    /// Publish a manifest as an immutable release.
    Publish { manifest: PathBuf },
    /// Point a channel at a published release, e.g. `promote hello@0.1.0 stable`.
    Promote { spec: String, channel: String },
    /// Manage environments.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Show the steps that would converge the environment (dry run).
    Plan {
        #[arg(long, default_value = "local")]
        env: String,
    },
    /// Execute a stored plan: gates, install, health probe, auto-rollback.
    Apply {
        plan_id: String,
        /// Bypass eval gates (recorded like any other apply).
        #[arg(long)]
        skip_gates: bool,
    },
    /// Deployed vs channel head, per subscribed product.
    Status {
        #[arg(long, default_value = "local")]
        env: String,
    },
    /// Roll a product back to its previously deployed version.
    Rollback {
        product: String,
        #[arg(long, default_value = "local")]
        env: String,
    },
}

#[derive(Subcommand)]
enum EnvCommand {
    /// Register an environment.
    Add {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Subscribe an environment to a product channel, e.g. `subscribe local hello=stable`.
    Subscribe { env: String, spec: String },
    /// Remove an abandoned apply lease after verifying no apply is running.
    Unlock { env: String },
    /// Record manually reconciled deployment state; omit --deployed after cleanup.
    Reconcile {
        env: String,
        product: String,
        #[arg(long)]
        deployed: Option<String>,
    },
}

fn print_steps(steps: &[plan::Step]) {
    for s in steps {
        let from = s.from.as_deref().unwrap_or("none");
        println!(
            "  {:<9} {:<24} {} -> {}",
            s.action.to_string(),
            s.product,
            from,
            s.to
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut ctx = client::connect().await?;

    match cli.command {
        Command::Init => {
            let registered = ontology::register(&mut ctx).await?;
            if registered.is_empty() {
                println!("schema already registered");
            } else {
                println!("registered schema types: {}", registered.join(", "));
            }
            println!(
                "{}",
                plan::env_add(&mut ctx, "local", "this machine").await?
            );
        }
        Command::Publish { manifest } => {
            println!("{}", catalog::publish(&mut ctx, &manifest).await?);
        }
        Command::Promote { spec, channel } => {
            println!("{}", catalog::promote(&mut ctx, &spec, &channel).await?);
        }
        Command::Env { command } => match command {
            EnvCommand::Add { name, description } => {
                println!("{}", plan::env_add(&mut ctx, &name, &description).await?);
            }
            EnvCommand::Subscribe { env, spec } => {
                let Some((product, channel)) = spec.split_once('=') else {
                    bail!("expected <product>=<channel>, got {spec:?}");
                };
                println!(
                    "{}",
                    plan::subscribe(&mut ctx, &env, product, channel).await?
                );
            }
            EnvCommand::Unlock { env } => {
                println!("{}", apply::unlock_environment(&mut ctx, &env).await?);
            }
            EnvCommand::Reconcile {
                env,
                product,
                deployed,
            } => {
                println!(
                    "{}",
                    plan::reconcile_deployment(&mut ctx, &env, &product, deployed.as_deref())
                        .await?
                );
            }
        },
        Command::Plan { env } => {
            let stored = plan::create(&mut ctx, &env).await?;
            println!("plan id: {}", stored.id);
            if stored.steps.is_empty() {
                println!("{env} is up to date");
            } else {
                println!("plan for {env}:");
                print_steps(&stored.steps);
            }
        }
        Command::Apply {
            plan_id,
            skip_gates,
        } => {
            let stored = plan::load(&mut ctx, &plan_id).await?;
            println!("applying {} to {}:", stored.id, stored.environment);
            print_steps(&stored.steps);
            run_plan(&mut ctx, &plan_id, skip_gates).await?;
        }
        Command::Status { env } => {
            let rows = plan::status(&mut ctx, &env).await?;
            if rows.is_empty() {
                println!("{env} has no channel subscriptions");
                return Ok(());
            }
            println!(
                "{:<24} {:<10} {:<12} {:<12} state",
                "product", "channel", "deployed", "head"
            );
            for r in rows {
                let deployed = r.deployed.clone().unwrap_or_else(|| "-".into());
                let state = match (&r.deployed, r.health.as_deref()) {
                    (_, Some("unknown")) => "unknown",
                    (Some(v), _) if *v == r.head => "current",
                    (Some(_), _) => "behind",
                    (None, _) => "missing",
                };
                println!(
                    "{:<24} {:<10} {:<12} {:<12} {state}",
                    r.product, r.channel, deployed, r.head
                );
                if state == "unknown"
                    && let Some(error) = r.error.as_deref()
                {
                    println!("  recovery required: {error}");
                }
            }
        }
        Command::Rollback { product, env } => {
            let stored = plan::create_rollback(&mut ctx, &env, &product).await?;
            println!("rollback plan id: {}", stored.id);
            println!("rolling back in {env}:");
            print_steps(&stored.steps);
            run_plan(&mut ctx, &stored.id, false).await?;
        }
    }
    Ok(())
}

async fn run_plan(ctx: &mut client::Ctx, plan_id: &str, skip_gates: bool) -> Result<()> {
    let outcomes = apply::execute(ctx, plan_id, skip_gates).await?;
    let mut failed = false;
    for o in &outcomes {
        match o.status.as_str() {
            "succeeded" => println!("  ok        {:<24} {}", o.step.product, o.step.to),
            "blocked" => {
                failed = true;
                println!("  BLOCKED   {:<24} {}", o.step.product, o.detail);
            }
            "rolled_back" => {
                failed = true;
                println!("  ROLLBACK  {:<24} {}", o.step.product, o.detail);
            }
            _ => {
                failed = true;
                println!("  FAILED    {:<24} {}", o.step.product, o.detail);
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
    Ok(())
}
