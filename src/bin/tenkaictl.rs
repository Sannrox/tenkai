//! tenkaictl — local delivery control plane CLI, backed by sekai-chisei.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use tenkai::{apply, catalog, client, constraint, ontology, plan};

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
    /// Manage environment and subscription constraints.
    Constraint {
        #[command(subcommand)]
        command: ConstraintCommand,
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

#[derive(Subcommand)]
enum ConstraintCommand {
    /// Create a constraint for an environment or one of its subscriptions.
    Add {
        env: String,
        identity: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        reason: String,
        /// Evaluator parameter in key=value form; repeat for multiple parameters.
        #[arg(long = "param")]
        parameters: Vec<String>,
        /// Target one subscription in product=channel form instead of the whole environment.
        #[arg(long)]
        subscription: Option<String>,
        /// Create the constraint disabled.
        #[arg(long)]
        disabled: bool,
    },
    /// List every constraint for an environment.
    List { env: String },
    /// Enable a constraint.
    Enable { env: String, identity: String },
    /// Disable a constraint.
    Disable { env: String, identity: String },
}

fn parameters(values: &[String]) -> Result<BTreeMap<String, String>> {
    let mut parameters = BTreeMap::new();
    for value in values {
        let Some((key, value)) = value.split_once('=') else {
            bail!("expected constraint parameter <key>=<value>, got {value:?}");
        };
        if parameters.insert(key.into(), value.into()).is_some() {
            bail!("constraint parameter {key:?} was provided more than once");
        }
    }
    Ok(parameters)
}

fn constraint_target(
    env: &str,
    subscription: Option<&str>,
) -> Result<constraint::ConstraintTarget> {
    let Some(subscription) = subscription else {
        return Ok(constraint::ConstraintTarget::Environment {
            environment: env.into(),
        });
    };
    let Some((product, channel)) = subscription.split_once('=') else {
        bail!("expected subscription <product>=<channel>, got {subscription:?}");
    };
    ontology::validate_identifier("product", product)?;
    ontology::validate_identifier("channel", channel)?;
    Ok(constraint::ConstraintTarget::Subscription {
        environment: env.into(),
        channel_id: ontology::channel_id(product, channel),
    })
}

fn print_constraints(constraints: &[constraint::Constraint]) {
    for constraint in constraints {
        let target = match &constraint.target {
            constraint::ConstraintTarget::Environment { .. } => "environment".into(),
            constraint::ConstraintTarget::Subscription { channel_id, .. } => {
                format!("subscription:{channel_id}")
            }
        };
        let state = if constraint.enabled {
            "enabled"
        } else {
            "disabled"
        };
        println!(
            "{:<24} {:<20} {:<8} {:<40} {}",
            constraint.identity, constraint.kind, state, target, constraint.reason
        );
        if !constraint.parameters.is_empty() {
            println!(
                "  parameters: {}",
                serde_json::to_string(&constraint.parameters)
                    .unwrap_or_else(|_| "<invalid>".into())
            );
        }
    }
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
        Command::Constraint { command } => match command {
            ConstraintCommand::Add {
                env,
                identity,
                kind,
                reason,
                parameters: raw_parameters,
                subscription,
                disabled,
            } => {
                let target = constraint_target(&env, subscription.as_deref())?;
                let created = constraint::create(
                    &mut ctx,
                    &identity,
                    &kind,
                    parameters(&raw_parameters)?,
                    !disabled,
                    &reason,
                    target,
                )
                .await?;
                println!(
                    "constraint {} created ({})",
                    created.identity,
                    if created.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
            }
            ConstraintCommand::List { env } => {
                let constraints = constraint::list(&mut ctx, &env).await?;
                if constraints.is_empty() {
                    println!("{env} has no constraints");
                } else {
                    print_constraints(&constraints);
                }
            }
            ConstraintCommand::Enable { env, identity } => {
                constraint::set_enabled(&mut ctx, &env, &identity, true).await?;
                println!("constraint {identity} enabled in {env}");
            }
            ConstraintCommand::Disable { env, identity } => {
                constraint::set_enabled(&mut ctx, &env, &identity, false).await?;
                println!("constraint {identity} disabled in {env}");
            }
        },
        Command::Plan { env } => {
            let stored = plan::create(&mut ctx, &env).await?;
            println!("plan id: {}", stored.id);
            if stored.state == plan::PlanState::Blocked {
                bail!("plan blocked by constraints: {}", stored.status_detail);
            } else if stored.steps.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_environment_constraint_creation() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "constraint",
            "add",
            "prod",
            "release-freeze",
            "--kind",
            "always.deny",
            "--reason",
            "release freeze",
            "--disabled",
        ])
        .unwrap();
        let Command::Constraint {
            command:
                ConstraintCommand::Add {
                    env,
                    identity,
                    kind,
                    disabled,
                    ..
                },
        } = cli.command
        else {
            panic!("expected constraint add command");
        };
        assert_eq!(env, "prod");
        assert_eq!(identity, "release-freeze");
        assert_eq!(kind, "always.deny");
        assert!(disabled);
    }

    #[test]
    fn parses_subscription_target_and_rejects_duplicate_parameters() {
        assert_eq!(
            constraint_target("prod", Some("api=stable")).unwrap(),
            constraint::ConstraintTarget::Subscription {
                environment: "prod".into(),
                channel_id: ontology::channel_id("api", "stable"),
            }
        );
        assert!(parameters(&["key=one".into(), "key=two".into()]).is_err());
    }
}
