//! tenkaictl — local delivery control plane CLI, backed by sekai-chisei.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use tenkai::{apply, canary, catalog, client, maintenance, ontology, plan};

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
    Publish {
        manifest: PathBuf,
        /// Detached tenkai.release-signature.v1 JSON envelope.
        #[arg(long)]
        signature: Option<PathBuf>,
        /// Versioned TOML file containing trusted Ed25519 release signers.
        #[arg(long)]
        trust_roots: Option<PathBuf>,
        /// Permit an unsigned release for local development only.
        #[arg(long)]
        allow_unsigned_development: bool,
    },
    /// Inspect or reverify published release trust evidence.
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// Point a channel at a published release, e.g. `promote hello@0.1.0 stable`.
    Promote { spec: String, channel: String },
    /// Manage canary designation, promotion policy, and evidence repair.
    Canary {
        #[command(subcommand)]
        command: CanaryCommand,
    },
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
        /// Start outside maintenance policy and record this reason with the authenticated principal.
        #[arg(long)]
        emergency_reason: Option<String>,
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
        /// Start outside maintenance policy and record this reason with the authenticated principal.
        #[arg(long)]
        emergency_reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum CanaryCommand {
    /// Mark an environment as eligible for canary cohorts.
    Designate {
        env: String,
        /// Remove the explicit canary designation.
        #[arg(long)]
        remove: bool,
    },
    /// Require successful evidence from every named environment before promotion.
    Policy {
        spec: String,
        channel: String,
        /// Required canary environment; repeat for the complete cohort.
        #[arg(long = "env", required = true)]
        cohort: Vec<String>,
        /// Start a fresh activation; prior evidence remains audited but no longer applies.
        #[arg(long)]
        reactivate: bool,
    },
    /// Rebuild durable canary outcomes for a completed apply.
    Repair { plan_id: String },
    /// Remove an abandoned promotion lock after verifying no operation is running.
    Unlock { product: String, channel: String },
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Show stored release verification evidence as JSON.
    Inspect { spec: String },
    /// Reverify stored release content and evidence against current trust roots.
    Verify {
        spec: String,
        #[arg(long)]
        trust_roots: PathBuf,
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
    /// Manage recurring maintenance windows.
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
    },
}

#[derive(Subcommand)]
enum MaintenanceCommand {
    /// Create or replace a named recurring window.
    Set {
        env: String,
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
    /// List recurring windows for an environment.
    List { env: String },
    /// Remove a named recurring window.
    Remove { env: String, identity: String },
    /// Replace an invalid configuration with an empty governed schedule.
    Repair { env: String },
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
            let migrated = maintenance::migrate_all(&mut ctx).await?;
            println!("maintenance configuration ready for {migrated} environment(s)");
        }
        Command::Publish {
            manifest,
            signature,
            trust_roots,
            allow_unsigned_development,
        } => {
            let options = catalog::PublishOptions {
                signature,
                trust_roots,
                allow_unsigned_development,
            };
            println!("{}", catalog::publish(&mut ctx, &manifest, &options).await?);
        }
        Command::Release { command } => match command {
            ReleaseCommand::Inspect { spec } => {
                let evidence = catalog::inspect_release(&mut ctx, &spec).await?;
                println!("{}", serde_json::to_string_pretty(&evidence)?);
            }
            ReleaseCommand::Verify { spec, trust_roots } => {
                let evidence = catalog::reverify_release(&mut ctx, &spec, &trust_roots).await?;
                println!("{}", serde_json::to_string_pretty(&evidence)?);
            }
        },
        Command::Promote { spec, channel } => {
            println!("{}", catalog::promote(&mut ctx, &spec, &channel).await?);
        }
        Command::Canary { command } => match command {
            CanaryCommand::Designate { env, remove } => {
                println!("{}", canary::set_designated(&mut ctx, &env, !remove).await?);
            }
            CanaryCommand::Policy {
                spec,
                channel,
                cohort,
                reactivate,
            } => {
                let active =
                    canary::configure(&mut ctx, &spec, &channel, cohort, reactivate).await?;
                println!(
                    "canary policy {} active for {} -> {} with cohort {}",
                    active.digest(),
                    spec,
                    channel,
                    active.policy().cohort.join(", ")
                );
            }
            CanaryCommand::Repair { plan_id } => {
                let repaired = canary::repair_pending(&mut ctx, &plan_id).await?;
                println!("repaired {repaired} canary attempt(s) for {plan_id}");
            }
            CanaryCommand::Unlock { product, channel } => {
                println!(
                    "{}",
                    canary::unlock_promotion(&mut ctx, &product, &channel).await?
                );
            }
        },
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
            EnvCommand::Maintenance { command } => match command {
                MaintenanceCommand::Set {
                    env,
                    identity,
                    timezone,
                    weekdays,
                    start,
                    duration_minutes,
                } => {
                    let window = maintenance::Window::new(
                        identity,
                        timezone,
                        maintenance::weekday_values(&weekdays)?,
                        start,
                        duration_minutes,
                    )?;
                    println!("{}", maintenance::set(&mut ctx, &env, window).await?);
                }
                MaintenanceCommand::List { env } => {
                    let windows = maintenance::list(&mut ctx, &env).await?;
                    if windows.is_empty() {
                        println!("{env} has no maintenance windows");
                    } else {
                        for window in windows {
                            println!(
                                "{}: {} {:?} {} for {} minutes",
                                window.identity,
                                window.timezone,
                                window.weekdays,
                                window.start,
                                window.duration_minutes
                            );
                        }
                    }
                }
                MaintenanceCommand::Remove { env, identity } => {
                    println!("{}", maintenance::remove(&mut ctx, &env, &identity).await?);
                }
                MaintenanceCommand::Repair { env } => {
                    println!("{}", maintenance::repair(&mut ctx, &env).await?);
                }
            },
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
            emergency_reason,
        } => {
            let stored = plan::load(&mut ctx, &plan_id).await?;
            println!("applying {} to {}:", stored.id, stored.environment);
            print_steps(&stored.steps);
            run_plan(&mut ctx, &plan_id, skip_gates, emergency_reason.as_deref()).await?;
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
        Command::Rollback {
            product,
            env,
            emergency_reason,
        } => {
            let step = plan::rollback_step(&mut ctx, &env, &product).await?;
            let stored = plan::create_from_steps(&mut ctx, &env, vec![step]).await?;
            println!("rolling back in {env}:");
            print_steps(&stored.steps);
            run_plan(&mut ctx, &stored.id, true, emergency_reason.as_deref()).await?;
        }
    }
    Ok(())
}

async fn run_plan(
    ctx: &mut client::Ctx,
    plan_id: &str,
    skip_gates: bool,
    emergency_reason: Option<&str>,
) -> Result<()> {
    let outcomes = apply::execute_with_options(
        ctx,
        plan_id,
        apply::ExecutionOptions {
            skip_gates,
            emergency_reason,
        },
    )
    .await?;
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
    fn parses_canary_policy_cohort_and_reactivation() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "canary",
            "policy",
            "api@1.2.3",
            "stable",
            "--env",
            "canary-a",
            "--env",
            "canary-b",
            "--reactivate",
        ])
        .unwrap();
        let Command::Canary {
            command:
                CanaryCommand::Policy {
                    spec,
                    channel,
                    cohort,
                    reactivate,
                },
        } = cli.command
        else {
            panic!("expected canary policy command");
        };
        assert_eq!(spec, "api@1.2.3");
        assert_eq!(channel, "stable");
        assert_eq!(cohort, ["canary-a", "canary-b"]);
        assert!(reactivate);
    }

    #[test]
    fn parses_maintenance_window_configuration() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "env",
            "maintenance",
            "set",
            "prod",
            "weekday",
            "--timezone",
            "Europe/Berlin",
            "--weekdays",
            "mon,tue,wed,thu,fri",
            "--start",
            "22:00",
            "--duration-minutes",
            "120",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Env {
                command: EnvCommand::Maintenance {
                    command: MaintenanceCommand::Set {
                        duration_minutes: 120,
                        ..
                    }
                }
            }
        ));
    }

    #[test]
    fn parses_emergency_override_reason() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "apply",
            "tenkai:plan:prod:1:digest",
            "--emergency-reason",
            "restore critical service",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Apply {
                emergency_reason: Some(ref reason),
                ..
            } if reason == "restore critical service"
        ));
    }

    #[test]
    fn parses_signed_and_explicit_unsigned_publication() {
        let signed = Cli::try_parse_from([
            "tenkaictl",
            "publish",
            "tenkai.toml",
            "--signature",
            "tenkai.sig.json",
            "--trust-roots",
            "release-trust.toml",
        ])
        .unwrap();
        let Command::Publish {
            signature,
            trust_roots,
            allow_unsigned_development,
            ..
        } = signed.command
        else {
            panic!("expected publish command");
        };
        assert_eq!(signature, Some(PathBuf::from("tenkai.sig.json")));
        assert_eq!(trust_roots, Some(PathBuf::from("release-trust.toml")));
        assert!(!allow_unsigned_development);

        let unsigned = Cli::try_parse_from([
            "tenkaictl",
            "publish",
            "tenkai.toml",
            "--allow-unsigned-development",
        ])
        .unwrap();
        assert!(matches!(
            unsigned.command,
            Command::Publish {
                allow_unsigned_development: true,
                ..
            }
        ));
    }

    #[test]
    fn parses_release_inspection_and_reverification() {
        let inspect =
            Cli::try_parse_from(["tenkaictl", "release", "inspect", "api@1.2.3"]).unwrap();
        assert!(matches!(
            inspect.command,
            Command::Release {
                command: ReleaseCommand::Inspect { spec }
            } if spec == "api@1.2.3"
        ));

        let verify = Cli::try_parse_from([
            "tenkaictl",
            "release",
            "verify",
            "api@1.2.3",
            "--trust-roots",
            "release-trust.toml",
        ])
        .unwrap();
        assert!(matches!(
            verify.command,
            Command::Release {
                command: ReleaseCommand::Verify { spec, trust_roots }
            } if spec == "api@1.2.3" && trust_roots == std::path::Path::new("release-trust.toml")
        ));
    }
}
