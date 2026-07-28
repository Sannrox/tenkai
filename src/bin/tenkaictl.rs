//! tenkaictl — embedded and remote delivery control-plane CLI.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::error::ErrorKind;
use clap::{Parser, Subcommand, ValueEnum};

use tenkai::command_result::{CommandName, CommandOutcome, CommandResultV1, RetryGuidance};
use tenkai::{
    apply, canary, catalog, client, dev_sign, inventory, maintenance, ontology, plan, reconciler,
    wave,
};

#[derive(Parser)]
#[command(name = "tenkaictl", version, about = "Constraint-based local delivery")]
struct Cli {
    /// Select the embedded application core or an authenticated remote server.
    #[arg(long, value_enum, default_value_t = Target::Embedded, global = true)]
    target: Target,
    /// Tenkai server URL; required with --target remote.
    #[arg(long, env = "TENKAI_SERVER_URL", global = true)]
    server_url: Option<String>,
    /// Embedded SQLite state file. Ignored by remote mode.
    #[arg(
        long,
        env = "TENKAI_DATABASE",
        default_value = ".tenkai-state/tenkai.db",
        global = true
    )]
    database: PathBuf,
    /// Stable output contract for typed adapters. Human output remains the default.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human, global = true)]
    output: OutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Target {
    Embedded,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    JsonV1,
}

#[derive(Subcommand)]
enum Command {
    #[command(name = "__executor-guard", hide = true)]
    ExecutorGuard {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        workdir: PathBuf,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        product: String,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        command: String,
    },
    /// Initialize Tenkai state and create the `local` environment.
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
    /// Inspect recorded plan-approval verification evidence.
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
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
    /// Fleet-wide delivery posture across all registered environments.
    Fleet {
        #[command(subcommand)]
        command: FleetCommand,
    },
    /// Ordered multi-environment rollout wave observation.
    Wave {
        #[command(subcommand)]
        command: WaveCommand,
    },
    /// Show the steps that would converge the environment (dry run).
    Plan {
        #[arg(long, default_value = "local")]
        env: String,
    },
    /// Execute a stored plan: gates, install, health probe, auto-rollback.
    Apply {
        plan_id: String,
        /// Detached tenkai.plan-approval.v1 JSON envelope.
        #[arg(
            long,
            requires = "approval_trust_roots",
            conflicts_with = "allow_unapproved_development"
        )]
        approval: Option<PathBuf>,
        /// Current Ed25519 trust roots for plan approvers.
        #[arg(
            long,
            requires = "approval",
            conflicts_with = "allow_unapproved_development"
        )]
        approval_trust_roots: Option<PathBuf>,
        /// Explicitly bypass signed approval for the built-in local environment.
        #[arg(long, requires = "development_reason")]
        allow_unapproved_development: bool,
        /// Audited justification for the local-development bypass.
        #[arg(long, requires = "allow_unapproved_development")]
        development_reason: Option<String>,
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
    /// Inspect the embedded control-plane state without distributed diagnostics.
    Inspect,
    /// Create a transactionally consistent embedded-state backup.
    Backup { destination: PathBuf },
    /// Replace embedded state from a verified backup. The CLI must be the only writer.
    Restore { source: PathBuf },
    /// Roll a product back to its previously deployed version.
    Rollback {
        product: String,
        #[arg(long, default_value = "local")]
        env: String,
        /// Execute immediately using the explicit local-development bypass.
        #[arg(long, requires = "development_reason")]
        allow_unapproved_development: bool,
        /// Audited justification for the local-development bypass.
        #[arg(long, requires = "allow_unapproved_development")]
        development_reason: Option<String>,
        /// Start outside maintenance policy and record this reason with the authenticated principal.
        #[arg(long)]
        emergency_reason: Option<String>,
    },
    /// Continuously converge all registered environments.
    Reconcile {
        /// Run one reconciliation tick and exit.
        #[arg(long)]
        once: bool,
        /// Seconds between reconciliation ticks.
        #[arg(long, default_value_t = 10)]
        interval: u64,
        /// Initial retry delay in seconds for a failing environment.
        #[arg(long, default_value_t = 5)]
        initial_backoff: u64,
        /// Maximum retry delay in seconds for a failing environment.
        #[arg(long, default_value_t = 300)]
        max_backoff: u64,
        /// Maximum environments reconciled at the same time.
        #[arg(long, default_value_t = 8)]
        max_concurrency: usize,
        /// Bypass eval gates for automatically created executions.
        #[arg(long)]
        skip_gates: bool,
        /// Explicitly permit automatic execution only for the built-in local environment.
        #[arg(long, requires = "development_reason")]
        allow_unapproved_development: bool,
        /// Audited justification for automatic local-development execution.
        #[arg(long, requires = "allow_unapproved_development")]
        development_reason: Option<String>,
    },
    /// Development-only signing helpers for laptop dogfood (not production KMS).
    Dev {
        #[command(subcommand)]
        command: DevCommand,
    },
}

#[derive(Subcommand)]
enum DevCommand {
    /// Create a local directory of development Ed25519 keys (mode 0600).
    InitKeys {
        /// Directory for private key material (default `.tenkai-dev-keys`).
        #[arg(long, default_value = dev_sign::DEFAULT_DEV_KEYS_DIR)]
        dir: PathBuf,
    },
    /// Sign a release for publish --signature / --trust-roots (dogfood only).
    SignRelease {
        /// Path to tenkai.toml
        manifest: PathBuf,
        /// Keys directory from `dev init-keys`
        #[arg(long, default_value = dev_sign::DEFAULT_DEV_KEYS_DIR)]
        keys: PathBuf,
        /// Output path for detached release signature JSON
        #[arg(long)]
        signature: PathBuf,
        /// Output path for release trust-roots TOML
        #[arg(long)]
        trust_roots: PathBuf,
    },
    /// Sign a plan approval for apply --approval (dogfood only; non-local envs).
    SignApproval {
        plan_id: String,
        /// Keys directory from `dev init-keys`
        #[arg(long, default_value = dev_sign::DEFAULT_DEV_KEYS_DIR)]
        keys: PathBuf,
        /// Output path for plan-approval JSON envelope
        #[arg(long)]
        approval: PathBuf,
        /// Output path for approval trust-roots TOML
        #[arg(long)]
        trust_roots: PathBuf,
        /// Approval lifetime in seconds
        #[arg(long, default_value_t = 3600)]
        ttl_secs: i64,
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
enum ApprovalCommand {
    /// Show signer, policy, scope, expiry, and bypass evidence without credentials.
    Inspect { plan_id: String },
}

#[derive(Subcommand)]
enum FleetCommand {
    /// Summarize delivery posture for every environment (embedded or remote).
    Status,
    /// Poll fleet status and report posture drift versus a baseline or prior sample.
    Watch {
        /// Seconds between samples when not using --once.
        #[arg(long, default_value_t = 10)]
        interval: u64,
        /// Take one sample, compare, print, and exit (embedded automation / tests).
        #[arg(long)]
        once: bool,
        /// Optional JSON posture baseline (`tenkai.fleet-posture.v1`). Missing file = empty.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Write the latest posture snapshot as JSON after each sample.
        #[arg(long)]
        write_baseline: Option<PathBuf>,
        /// Exit non-zero on any posture change (not only new behind/unhealthy).
        #[arg(long)]
        exit_on_any_posture_change: bool,
        /// Exit non-zero when any environment is currently behind or unhealthy.
        #[arg(long)]
        exit_on_any_hard_drift: bool,
        /// Emit the drift summary as JSON (default is human text).
        #[arg(long)]
        json: bool,
        /// Maximum samples before exit (0 = unlimited). Implies continuous watch.
        #[arg(long, default_value_t = 0)]
        max_samples: u64,
    },
}

#[derive(Subcommand)]
enum WaveCommand {
    /// Observe an ordered environment cohort (embedded).
    Run {
        /// Comma-separated environment names in wave order, e.g. `canary,stage,prod`.
        cohort: String,
        /// Continue after failures (default: stop and skip remaining).
        #[arg(long)]
        continue_on_failure: bool,
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
    /// List registered environments with compact delivery summaries.
    List,
    /// Inspect one environment: subscriptions, deployed versions, lease/fence, latest plan.
    Inspect { env: String },
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
    /// Manage environment capability / inventory facts (architecture, memory, …).
    Facts {
        #[command(subcommand)]
        command: FactsCommand,
    },
    /// Manage planning constraints (version pins/ranges, required facts).
    Constraints {
        #[command(subcommand)]
        command: ConstraintsCommand,
    },
}

#[derive(Subcommand)]
enum FactsCommand {
    /// List capability facts for an environment.
    List { env: String },
    /// Set a fact, e.g. `set prod architecture=arm64`.
    Set { env: String, spec: String },
    /// Clear one fact key.
    Clear { env: String, key: String },
    /// Probe local hardware inventory (dry-run by default).
    Probe {
        env: String,
        /// Write probed facts via the normal fact API.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum ConstraintsCommand {
    /// List constraints for an environment.
    List { env: String },
    /// Set a constraint: `set <env> version_pin <product> <version>`,
    /// `version_range <product> <min>..<max>`, or `require_fact <key> <value|*>`.
    Set {
        env: String,
        kind: String,
        name: String,
        value: String,
    },
    /// Clear a constraint.
    Clear {
        env: String,
        kind: String,
        name: String,
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

#[derive(Debug)]
struct ReportedMachineFailure(CommandResultV1);

impl std::fmt::Display for ReportedMachineFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("machine-readable command failure")
    }
}

impl std::error::Error for ReportedMachineFailure {}

fn machine_output_requested(args: &[OsString]) -> bool {
    args.windows(2).any(|pair| {
        pair[0] == std::ffi::OsStr::new("--output") && pair[1] == std::ffi::OsStr::new("json-v1")
    }) || args
        .iter()
        .any(|arg| arg == std::ffi::OsStr::new("--output=json-v1"))
}

fn command_name(command: &Command) -> Option<CommandName> {
    match command {
        Command::Publish { .. } => Some(CommandName::Publish),
        Command::Promote { .. } => Some(CommandName::Promote),
        Command::Plan { .. } => Some(CommandName::Plan),
        Command::Apply { .. } => Some(CommandName::Apply),
        Command::Status { .. } => Some(CommandName::Status),
        Command::Env {
            command: EnvCommand::Inspect { .. },
        } => Some(CommandName::InspectEnvironment),
        Command::Rollback { .. } => Some(CommandName::Rollback),
        _ => None,
    }
}

fn mutation_retry(command: CommandName) -> RetryGuidance {
    match command {
        CommandName::Publish
        | CommandName::Promote
        | CommandName::Plan
        | CommandName::Apply
        | CommandName::Rollback => RetryGuidance::ReconcileBeforeRetry,
        _ => RetryGuidance::CorrectRequest,
    }
}

fn print_machine_result(result: &CommandResultV1) -> Result<()> {
    result
        .validate()
        .map_err(|message| anyhow::anyhow!(message))?;
    println!("{}", serde_json::to_string(result)?);
    Ok(())
}

fn reported_machine_failure(result: CommandResultV1) -> anyhow::Error {
    ReportedMachineFailure(result).into()
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = std::env::args_os().collect::<Vec<_>>();
    let requested_machine_output = machine_output_requested(&args);
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            if requested_machine_output {
                let result = CommandResultV1::failed(
                    CommandName::Invocation,
                    "invocation_rejected",
                    "The command line is invalid",
                    RetryGuidance::CorrectRequest,
                );
                if let Ok(encoded) = serde_json::to_string(&result) {
                    println!("{encoded}");
                }
            } else {
                let _ = error.print();
            }
            return ExitCode::from(error.exit_code().clamp(1, 255) as u8);
        }
    };
    let output = cli.output;
    let machine_command = command_name(&cli.command).unwrap_or(CommandName::Invocation);
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if output == OutputFormat::JsonV1 {
                let result = error
                    .downcast_ref::<ReportedMachineFailure>()
                    .map(|reported| reported.0.clone())
                    .unwrap_or_else(|| {
                        CommandResultV1::failed(
                            machine_command,
                            "operation_failed",
                            "Tenkai rejected the operation",
                            mutation_retry(machine_command),
                        )
                    });
                let _ = print_machine_result(&result);
            } else {
                eprintln!("error: {error:#}");
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    if cli.output == OutputFormat::JsonV1 && command_name(&cli.command).is_none() {
        return Err(reported_machine_failure(CommandResultV1::failed(
            CommandName::Invocation,
            "unsupported_command",
            "This command does not support tenkai.command-result/v1",
            RetryGuidance::CorrectRequest,
        )));
    }
    if cli.output == OutputFormat::JsonV1 && cli.target == Target::Remote {
        return Err(reported_machine_failure(CommandResultV1::failed(
            command_name(&cli.command).unwrap_or(CommandName::Invocation),
            "unsupported_target",
            "Machine-readable results currently require --target embedded",
            RetryGuidance::CorrectRequest,
        )));
    }
    let output = cli.output;
    if let Command::ExecutorGuard {
        lock,
        workdir,
        environment,
        product,
        generation,
        command,
    } = &cli.command
    {
        return tenkai::apply::executor_guard(
            lock,
            workdir,
            environment,
            product,
            *generation,
            command,
        )
        .await;
    }
    if cli.target == Target::Remote {
        let server_url = cli
            .server_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--server-url is required with --target remote"))?;
        let token = std::env::var("TENKAI_MANAGEMENT_TOKEN")
            .map_err(|_| anyhow::anyhow!("TENKAI_MANAGEMENT_TOKEN is required for remote mode"))?;
        let client = tenkai::server::RemoteClient::new(server_url, token)?;
        match cli.command {
            Command::Reconcile {
                once: true,
                allow_unapproved_development,
                development_reason,
                ..
            } => {
                if allow_unapproved_development || development_reason.is_some() {
                    bail!(
                        "the local-development reconciliation bypass is available only with --target embedded"
                    );
                }
                let report = client.reconcile().await?;
                let failures = report.failures();
                print_reconcile_report(report);
                if failures > 0 {
                    bail!("{failures} environment(s) failed to reconcile");
                }
                return Ok(());
            }
            Command::Reconcile { once: false, .. } => {
                bail!(
                    "remote servers reconcile continuously; use --once to request an immediate tick"
                )
            }
            Command::Fleet {
                command: FleetCommand::Status,
            } => {
                let report = client.fleet_status().await?;
                print_fleet_status(&report);
                return Ok(());
            }
            Command::Fleet {
                command:
                    FleetCommand::Watch {
                        interval,
                        once,
                        baseline,
                        write_baseline,
                        exit_on_any_posture_change,
                        exit_on_any_hard_drift,
                        json,
                        max_samples,
                    },
            } => {
                run_fleet_watch(
                    || {
                        let client = client.clone();
                        async move { client.fleet_status().await }
                    },
                    FleetWatchOptions {
                        interval,
                        once,
                        baseline,
                        write_baseline,
                        exit_on_any_posture_change,
                        exit_on_any_hard_drift,
                        json,
                        max_samples,
                    },
                )
                .await?;
                return Ok(());
            }
            Command::Env {
                command: EnvCommand::List,
            } => {
                let entries = client.list_environments().await?;
                if entries.is_empty() {
                    println!("no environments registered");
                } else {
                    println!(
                        "{:<20} {:<8} {:<10} {:<6} description",
                        "name", "subs", "deployed", "lease"
                    );
                    for entry in entries {
                        let lease = if entry.lease_held { "held" } else { "-" };
                        println!(
                            "{:<20} {:<8} {:<10} {:<6} {}",
                            entry.name,
                            entry.subscription_count,
                            entry.deployed_product_count,
                            lease,
                            entry.description
                        );
                    }
                }
                return Ok(());
            }
            Command::Env {
                command: EnvCommand::Inspect { env },
            } => {
                let report = client.inspect_environment(&env).await?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            Command::Status { env } => {
                let rows = client.environment_status(&env).await?;
                if rows.is_empty() {
                    println!("{env} has no channel subscriptions");
                } else {
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
                    }
                }
                return Ok(());
            }
            _ => bail!(
                "this command is not available through the v1 remote API; use --target embedded"
            ),
        }
    }
    if let Command::Restore { source } = &cli.command {
        tenkai::embedded::EmbeddedStore::restore(source, &cli.database)?;
        println!(
            "restored embedded state from {} to {}",
            source.display(),
            cli.database.display()
        );
        return Ok(());
    }
    if let Command::Dev { command } = &cli.command {
        match command {
            DevCommand::InitKeys { dir } => {
                let path = dev_sign::init_dev_keys(dir)?;
                println!("{}", dev_sign::warning_line());
                println!("initialized development keys in {}", path.display());
                return Ok(());
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
                return Ok(());
            }
            DevCommand::SignApproval {
                plan_id,
                keys,
                approval,
                trust_roots,
                ttl_secs,
            } => {
                let written = dev_sign::sign_plan_approval(
                    keys,
                    &cli.database,
                    plan_id,
                    approval,
                    trust_roots,
                    *ttl_secs,
                )
                .await?;
                println!("{}", dev_sign::warning_line());
                println!("wrote approval   {}", written.envelope.display());
                println!("wrote trust roots {}", written.trust_roots.display());
                println!(
                    "apply with: tenkaictl --database {} apply {} --approval {} --approval-trust-roots {}",
                    cli.database.display(),
                    plan_id,
                    written.envelope.display(),
                    written.trust_roots.display()
                );
                return Ok(());
            }
        }
    }
    let mut ctx = client::Ctx::embedded(&cli.database)?;

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
            if output == OutputFormat::JsonV1 {
                let published = catalog::publish_with_result(&mut ctx, &manifest, &options).await?;
                print_machine_result(
                    &CommandResultV1::succeeded(CommandName::Publish)
                        .resource("release", published.release),
                )?;
            } else {
                println!("{}", catalog::publish(&mut ctx, &manifest, &options).await?);
            }
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
        Command::Approval { command } => match command {
            ApprovalCommand::Inspect { plan_id } => {
                let mut evidence = ctx
                    .list_kind(ontology::KIND_PLAN_APPROVAL_VERIFICATION)
                    .await?
                    .into_iter()
                    .filter(|object| {
                        object
                            .properties
                            .get("plan_id")
                            .is_some_and(|id| id == &plan_id)
                    })
                    .filter_map(|object| object.properties.get("evidence").cloned())
                    .map(|raw| serde_json::from_str::<serde_json::Value>(&raw))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                evidence.sort_by_key(|item| {
                    item.get("verified_at").and_then(serde_json::Value::as_i64)
                });
                println!("{}", serde_json::to_string_pretty(&evidence)?);
            }
        },
        Command::Promote { spec, channel } => {
            if output == OutputFormat::JsonV1 {
                let product = spec.split_once('@').map_or(spec.as_str(), |value| value.0);
                tenkai::command_result::validate_resource_reference(
                    "channel",
                    &format!("{product}/{channel}"),
                )
                .map_err(|message| anyhow::anyhow!(message))?;
            }
            let message = catalog::promote(&mut ctx, &spec, &channel).await?;
            if output == OutputFormat::JsonV1 {
                let product = spec.split_once('@').map_or(spec.as_str(), |value| value.0);
                print_machine_result(
                    &CommandResultV1::succeeded(CommandName::Promote)
                        .resource("channel", format!("{product}/{channel}")),
                )?;
            } else {
                println!("{message}");
            }
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
        Command::Fleet {
            command: FleetCommand::Status,
        } => {
            let report = plan::fleet_status(&mut ctx).await?;
            print_fleet_status(&report);
        }
        Command::Fleet {
            command:
                FleetCommand::Watch {
                    interval,
                    once,
                    baseline,
                    write_baseline,
                    exit_on_any_posture_change,
                    exit_on_any_hard_drift,
                    json,
                    max_samples,
                },
        } => {
            run_fleet_watch(
                || {
                    // Re-open embedded ctx per sample so long watches see durable writes.
                    let database = cli.database.clone();
                    async move {
                        let mut sample_ctx = client::Ctx::embedded(&database)?;
                        plan::fleet_status(&mut sample_ctx).await
                    }
                },
                FleetWatchOptions {
                    interval,
                    once,
                    baseline,
                    write_baseline,
                    exit_on_any_posture_change,
                    exit_on_any_hard_drift,
                    json,
                    max_samples,
                },
            )
            .await?;
        }
        Command::Wave {
            command:
                WaveCommand::Run {
                    cohort,
                    continue_on_failure,
                },
        } => {
            let environments: Vec<String> = cohort
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect();
            let spec = wave::WaveSpec::new(environments, !continue_on_failure)?;
            let report = wave::run_wave_observe(&mut ctx, &spec).await?;
            println!("{}", wave::format_report(&report));
            if report.failed_count > 0 {
                bail!("wave failed for {} environment(s)", report.failed_count);
            }
        }
        Command::Env { command } => match command {
            EnvCommand::Add { name, description } => {
                println!("{}", plan::env_add(&mut ctx, &name, &description).await?);
            }
            EnvCommand::List => {
                let entries = plan::list_environments(&mut ctx).await?;
                if entries.is_empty() {
                    println!("no environments registered (tenkaictl env add <name>)");
                    return Ok(());
                }
                println!(
                    "{:<20} {:<8} {:<10} {:<6} description",
                    "name", "subs", "deployed", "lease"
                );
                for entry in entries {
                    let lease = if entry.lease_held { "held" } else { "-" };
                    println!(
                        "{:<20} {:<8} {:<10} {:<6} {}",
                        entry.name,
                        entry.subscription_count,
                        entry.deployed_product_count,
                        lease,
                        entry.description
                    );
                }
            }
            EnvCommand::Inspect { env } => {
                let report = plan::inspect_environment(&mut ctx, &env).await?;
                if output == OutputFormat::JsonV1 {
                    print_machine_result(
                        &CommandResultV1::succeeded(CommandName::InspectEnvironment)
                            .resource("environment", report.id)
                            .counts(None, Some(report.subscriptions.len())),
                    )?;
                } else {
                    // JSON keeps multi-env inspect machine-readable without secrets.
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
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
            EnvCommand::Facts { command } => match command {
                FactsCommand::List { env } => {
                    let facts = plan::list_environment_facts(&mut ctx, &env).await?;
                    if facts.is_empty() {
                        println!("{env} has no capability facts");
                    } else {
                        for (key, value) in facts {
                            println!("{key}={value}");
                        }
                    }
                }
                FactsCommand::Set { env, spec } => {
                    let Some((key, value)) = spec.split_once('=') else {
                        bail!("expected <key>=<value>, got {spec:?}");
                    };
                    println!(
                        "{}",
                        plan::set_environment_fact(&mut ctx, &env, key, value).await?
                    );
                }
                FactsCommand::Clear { env, key } => {
                    println!(
                        "{}",
                        plan::clear_environment_fact(&mut ctx, &env, &key).await?
                    );
                }
                FactsCommand::Probe { env, apply } => {
                    let facts = inventory::probe_local_inventory()?;
                    if !apply {
                        println!("{}", inventory::format_dry_run(&env, &facts));
                    } else if facts.is_empty() {
                        println!("no inventory facts detected for {env}");
                    } else {
                        for fact in &facts {
                            println!(
                                "{}",
                                plan::set_environment_fact(&mut ctx, &env, &fact.key, &fact.value)
                                    .await?
                            );
                        }
                        println!("applied {} local-probe fact(s) to {env}", facts.len());
                    }
                }
            },
            EnvCommand::Constraints { command } => match command {
                ConstraintsCommand::List { env } => {
                    let constraints = plan::list_environment_constraints(&mut ctx, &env).await?;
                    if constraints.is_empty() {
                        println!("{env} has no planning constraints");
                    } else {
                        for (key, value) in constraints {
                            println!("{key}={value}");
                        }
                    }
                }
                ConstraintsCommand::Set {
                    env,
                    kind,
                    name,
                    value,
                } => {
                    println!(
                        "{}",
                        plan::set_environment_constraint(&mut ctx, &env, &kind, &name, &value)
                            .await?
                    );
                }
                ConstraintsCommand::Clear { env, kind, name } => {
                    println!(
                        "{}",
                        plan::clear_environment_constraint(&mut ctx, &env, &kind, &name).await?
                    );
                }
            },
        },
        Command::Plan { env } => {
            if output == OutputFormat::JsonV1 {
                tenkai::command_result::validate_resource_reference(
                    "plan",
                    &format!("tenkai:plan:{env}:18446744073709551615:{}", "0".repeat(64)),
                )
                .map_err(|message| anyhow::anyhow!(message))?;
            }
            let stored = plan::create(&mut ctx, &env).await?;
            if output == OutputFormat::JsonV1 {
                print_machine_result(
                    &CommandResultV1::succeeded(CommandName::Plan)
                        .resource("plan", stored.id)
                        .resource("environment", stored.environment)
                        .counts(Some(stored.steps.len()), None),
                )?;
            } else {
                println!("plan id: {}", stored.id);
                if stored.steps.is_empty() {
                    println!("{env} is up to date");
                } else {
                    println!("plan for {env}:");
                    print_steps(&stored.steps);
                }
            }
        }
        Command::Apply {
            plan_id,
            approval,
            approval_trust_roots,
            allow_unapproved_development,
            development_reason,
            skip_gates,
            emergency_reason,
        } => {
            let stored = plan::load(&mut ctx, &plan_id).await?;
            if output == OutputFormat::JsonV1 {
                CommandResultV1::succeeded(CommandName::Apply)
                    .resource("plan", &stored.id)
                    .resource("environment", &stored.environment)
                    .counts(Some(stored.steps.len()), None)
                    .validate()
                    .map_err(|message| anyhow::anyhow!(message))?;
            }
            if output == OutputFormat::Human {
                println!("applying {} to {}:", stored.id, stored.environment);
                print_steps(&stored.steps);
            }
            run_plan(
                &mut ctx,
                &plan_id,
                apply::ExecutionOptions {
                    skip_gates,
                    emergency_reason: emergency_reason.as_deref(),
                    approval: approval.as_deref(),
                    approval_trust_roots: approval_trust_roots.as_deref(),
                    unapproved_development_reason: allow_unapproved_development.then(|| {
                        development_reason
                            .as_deref()
                            .expect("clap requires a development reason")
                    }),
                },
                PlanResultContext {
                    command: CommandName::Apply,
                    environment: &stored.environment,
                    step_count: stored.steps.len(),
                    output,
                },
            )
            .await?;
        }
        Command::Status { env } => {
            let rows = plan::status(&mut ctx, &env).await?;
            if output == OutputFormat::JsonV1 {
                print_machine_result(
                    &CommandResultV1::succeeded(CommandName::Status)
                        .resource("environment", env)
                        .counts(None, Some(rows.len())),
                )?;
                return Ok(());
            }
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
        Command::Inspect => {
            let summary = serde_json::json!({
                "mode": "embedded",
                "database": cli.database,
                "products": ctx.list_kind(tenkai::ontology::KIND_PRODUCT).await?.len(),
                "releases": ctx.list_kind(tenkai::ontology::KIND_RELEASE).await?.len(),
                "channels": ctx.list_kind(tenkai::ontology::KIND_CHANNEL).await?.len(),
                "environments": ctx.list_kind(tenkai::ontology::KIND_ENVIRONMENT).await?.len(),
                "plans": ctx.list_kind(tenkai::ontology::KIND_PLAN).await?.len(),
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::Backup { destination } => {
            ctx.backup_embedded(&destination)?;
            println!("backed up embedded state to {}", destination.display());
        }
        Command::Restore { .. } => unreachable!("restore is handled before opening the database"),
        Command::Dev { .. } => unreachable!("dev signing is handled before opening the database"),
        Command::ExecutorGuard { .. } => {
            unreachable!("executor guard is handled before opening the database")
        }
        Command::Rollback {
            product,
            env,
            allow_unapproved_development,
            development_reason,
            emergency_reason,
        } => {
            if output == OutputFormat::JsonV1 {
                tenkai::command_result::validate_resource_reference(
                    "plan",
                    &format!("tenkai:plan:{env}:18446744073709551615:{}", "0".repeat(64)),
                )
                .map_err(|message| anyhow::anyhow!(message))?;
            }
            let step = plan::rollback_step(&mut ctx, &env, &product).await?;
            let stored = plan::create_from_steps(&mut ctx, &env, vec![step]).await?;
            if output == OutputFormat::Human {
                println!("rolling back in {env}:");
                print_steps(&stored.steps);
            }
            if allow_unapproved_development {
                run_plan(
                    &mut ctx,
                    &stored.id,
                    apply::ExecutionOptions {
                        skip_gates: true,
                        emergency_reason: emergency_reason.as_deref(),
                        approval: None,
                        approval_trust_roots: None,
                        unapproved_development_reason: Some(
                            development_reason
                                .as_deref()
                                .expect("clap requires a development reason"),
                        ),
                    },
                    PlanResultContext {
                        command: CommandName::Rollback,
                        environment: &stored.environment,
                        step_count: stored.steps.len(),
                        output,
                    },
                )
                .await?;
            } else if output == OutputFormat::JsonV1 {
                let mut result = CommandResultV1::failed(
                    CommandName::Rollback,
                    "approval_required",
                    "The rollback plan requires signed approval",
                    RetryGuidance::NotSafe,
                )
                .resource("plan", stored.id)
                .resource("environment", stored.environment)
                .counts(Some(stored.steps.len()), None);
                result.outcome = CommandOutcome::AwaitingApproval;
                return Err(reported_machine_failure(result));
            } else {
                bail!(
                    "rollback was not executed; plan {} requires signed approval. Run `tenkaictl apply {}` with --approval and --approval-trust-roots{}",
                    stored.id,
                    stored.id,
                    if emergency_reason.is_some() {
                        " and repeat --emergency-reason"
                    } else {
                        ""
                    }
                );
            }
        }
        Command::Reconcile {
            once,
            interval,
            initial_backoff,
            max_backoff,
            max_concurrency,
            skip_gates,
            allow_unapproved_development,
            development_reason,
        } => {
            let reconciler = reconciler::Reconciler::new(
                ctx.clone(),
                reconciler::Config {
                    initial_backoff: Duration::from_secs(initial_backoff),
                    max_backoff: Duration::from_secs(max_backoff),
                    max_concurrency,
                    skip_gates,
                    unapproved_development_reason: allow_unapproved_development.then(|| {
                        development_reason
                            .clone()
                            .expect("clap requires a development reason")
                    }),
                    approval_directory: std::env::var_os("TENKAI_PLAN_APPROVAL_DIR")
                        .map(PathBuf::from),
                    approval_trust_roots: std::env::var_os("TENKAI_PLAN_APPROVAL_TRUST_ROOTS")
                        .map(PathBuf::from),
                    ..reconciler::Config::default()
                },
            )?;
            if once {
                let report = reconciler.run_once().await?;
                let failures = report.failures();
                print_reconcile_report(report);
                if failures > 0 {
                    bail!("{failures} environment(s) failed to reconcile");
                }
            } else {
                reconciler
                    .run_until(Duration::from_secs(interval), |report| match report {
                        Ok(report) => print_reconcile_report(report),
                        Err(error) => eprintln!("reconciliation tick failed: {error:#}"),
                    })
                    .await?;
            }
        }
    }
    Ok(())
}

fn print_fleet_status(report: &plan::FleetStatusReport) {
    println!(
        "fleet environments={} current={} behind={} unhealthy={} empty={}",
        report.environment_count,
        report.environments_current,
        report.environments_behind,
        report.environments_unhealthy,
        report.environments_empty
    );
    if report.environments.is_empty() {
        println!("no environments registered (tenkaictl env add <name>)");
        return;
    }
    println!(
        "{:<16} {:<10} {:<6} {:<6} {:<6} {:<6} {:<8} {:<10} plan",
        "name", "posture", "subs", "cur", "behind", "miss", "health", "lease"
    );
    for row in &report.environments {
        let lease = if row.lease_held { "held" } else { "-" };
        let plan = row.latest_plan_state.as_deref().unwrap_or("-");
        println!(
            "{:<16} {:<10} {:<6} {:<6} {:<6} {:<6} {:<8} {:<10} {plan}",
            row.name,
            row.posture,
            row.subscription_count,
            row.products_current,
            row.products_behind,
            row.products_missing,
            row.health_summary,
            lease
        );
    }
}

struct FleetWatchOptions {
    interval: u64,
    once: bool,
    baseline: Option<PathBuf>,
    write_baseline: Option<PathBuf>,
    exit_on_any_posture_change: bool,
    exit_on_any_hard_drift: bool,
    json: bool,
    max_samples: u64,
}

async fn run_fleet_watch<F, Fut>(mut sample: F, opts: FleetWatchOptions) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<plan::FleetStatusReport>>,
{
    let mut previous = if let Some(path) = &opts.baseline {
        plan::load_fleet_posture_baseline(path)?
    } else {
        plan::FleetPostureSnapshot::default()
    };
    let mut samples = 0u64;
    loop {
        let report = sample().await?;
        let current = plan::fleet_posture_snapshot(&report);
        let delta = plan::compare_fleet_posture(&previous, &current);
        if opts.json {
            println!("{}", serde_json::to_string_pretty(&delta)?);
        } else {
            print_fleet_drift(&delta, &report);
        }
        if let Some(path) = &opts.write_baseline {
            plan::write_fleet_posture_baseline(path, &current)?;
        }
        samples += 1;
        let should_exit_error = if opts.exit_on_any_posture_change {
            delta.has_any_posture_change
        } else if opts.exit_on_any_hard_drift {
            delta.has_any_hard_drift
        } else {
            // Default: non-zero only when *new* hard drift appears vs baseline/prior sample.
            delta.has_new_hard_drift
        };
        if should_exit_error {
            bail!(
                "fleet drift watch: new hard drift detected ({})",
                if delta.new_hard_drift.is_empty() {
                    if delta.has_any_hard_drift {
                        "hard drift present".to_string()
                    } else {
                        "posture changed".to_string()
                    }
                } else {
                    delta.new_hard_drift.join(",")
                }
            );
        }
        if opts.once || (opts.max_samples > 0 && samples >= opts.max_samples) {
            return Ok(());
        }
        previous = current;
        tokio::time::sleep(Duration::from_secs(opts.interval.max(1))).await;
    }
}

fn print_fleet_drift(delta: &plan::FleetDriftSummary, report: &plan::FleetStatusReport) {
    let change = if delta.has_any_posture_change {
        "changed"
    } else {
        "stable"
    };
    println!(
        "fleet watch {change} new_hard_drift={} any_hard_drift={} environments={} current={} behind={} unhealthy={} empty={}",
        delta.has_new_hard_drift,
        delta.has_any_hard_drift,
        report.environment_count,
        report.environments_current,
        report.environments_behind,
        report.environments_unhealthy,
        report.environments_empty
    );
    if !delta.has_any_posture_change {
        println!("no posture drift vs baseline");
        return;
    }
    let print_list = |label: &str, names: &[String]| {
        if !names.is_empty() {
            println!("{label}: {}", names.join(", "));
        }
    };
    print_list("entered behind", &delta.entered_behind);
    print_list("left behind", &delta.left_behind);
    print_list("entered unhealthy", &delta.entered_unhealthy);
    print_list("left unhealthy", &delta.left_unhealthy);
    print_list("entered empty", &delta.entered_empty);
    print_list("left empty", &delta.left_empty);
    print_list("entered current", &delta.entered_current);
    print_list("left current", &delta.left_current);
    print_list("appeared", &delta.appeared);
    print_list("disappeared", &delta.disappeared);
    print_list("new hard drift", &delta.new_hard_drift);
}

fn print_reconcile_report(report: reconciler::TickReport) {
    for result in report.environments {
        match result.status {
            reconciler::EnvironmentStatus::Current => {
                println!("{:<24} current", result.environment);
            }
            reconciler::EnvironmentStatus::Applied { plan_id, steps } => {
                println!(
                    "{:<24} applied {steps} step(s) with {plan_id}",
                    result.environment
                );
            }
            reconciler::EnvironmentStatus::AwaitingRuntime { plan_id, steps } => {
                println!(
                    "{:<24} awaiting runtime for {steps} step(s) in {plan_id}",
                    result.environment
                );
            }
            reconciler::EnvironmentStatus::AwaitingApproval { plan_id, steps } => {
                println!(
                    "{:<24} awaiting signed approval for {steps} step(s) in {plan_id}",
                    result.environment
                );
            }
            reconciler::EnvironmentStatus::Failed { error } => {
                eprintln!("{:<24} FAILED {error}", result.environment);
            }
            reconciler::EnvironmentStatus::Deferred { retry_at } => {
                println!("{:<24} deferred until {retry_at}", result.environment);
            }
            reconciler::EnvironmentStatus::Busy => {
                println!("{:<24} already reconciling", result.environment);
            }
        }
    }
}

struct PlanResultContext<'a> {
    command: CommandName,
    environment: &'a str,
    step_count: usize,
    output: OutputFormat,
}

async fn run_plan(
    ctx: &mut client::Ctx,
    plan_id: &str,
    execution: apply::ExecutionOptions<'_>,
    result_context: PlanResultContext<'_>,
) -> Result<()> {
    let outcomes = apply::execute_with_options(ctx, plan_id, execution).await?;
    let mut failed = false;
    for o in &outcomes {
        if result_context.output == OutputFormat::JsonV1 {
            failed |= o.status != "succeeded";
            continue;
        }
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
        if result_context.output == OutputFormat::JsonV1 {
            return Err(reported_machine_failure(
                CommandResultV1::failed(
                    result_context.command,
                    "execution_failed",
                    "One or more delivery steps did not succeed",
                    RetryGuidance::ReconcileBeforeRetry,
                )
                .resource("plan", plan_id)
                .resource("environment", result_context.environment)
                .counts(Some(result_context.step_count), None),
            ));
        }
        bail!("one or more delivery steps did not succeed");
    }
    if result_context.output == OutputFormat::JsonV1 {
        print_machine_result(
            &CommandResultV1::succeeded(result_context.command)
                .resource("plan", plan_id)
                .resource("environment", result_context.environment)
                .counts(Some(result_context.step_count), None),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_output_flag_is_explicit_and_bounded_to_supported_commands() {
        let args = ["tenkaictl", "plan", "--output", "json-v1"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        assert!(machine_output_requested(&args));

        let cli = Cli::try_parse_from(["tenkaictl", "plan", "--output=json-v1"]).unwrap();
        assert_eq!(cli.output, OutputFormat::JsonV1);
        assert_eq!(command_name(&cli.command), Some(CommandName::Plan));

        let unsupported = Cli::try_parse_from(["tenkaictl", "init", "--output=json-v1"]).unwrap();
        assert_eq!(command_name(&unsupported.command), None);

        let help = Cli::try_parse_from(["tenkaictl", "plan", "--output=json-v1", "--help"])
            .err()
            .expect("help exits through Clap's display path");
        assert_eq!(help.kind(), ErrorKind::DisplayHelp);
        assert_eq!(help.exit_code(), 0);
    }

    #[test]
    fn every_machine_command_has_a_deterministic_bounded_envelope() {
        let cases = [
            (CommandName::Publish, "release"),
            (CommandName::Promote, "channel"),
            (CommandName::Plan, "plan"),
            (CommandName::Apply, "plan"),
            (CommandName::Status, "environment"),
            (CommandName::InspectEnvironment, "environment"),
            (CommandName::Rollback, "plan"),
        ];
        for (command, resource_kind) in cases {
            let result = CommandResultV1::succeeded(command)
                .resource(resource_kind, "opaque")
                .counts(Some(1), Some(1));
            let first = serde_json::to_string(&result).unwrap();
            let second = serde_json::to_string(&result).unwrap();
            assert_eq!(first, second);
            assert_eq!(
                serde_json::from_str::<CommandResultV1>(&first).unwrap(),
                result
            );
            assert!(!first.contains('\n'));
            assert!(first.len() < 1024);
        }
    }

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
    fn remote_target_is_explicit_and_carries_no_cli_secret() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "--target",
            "remote",
            "--server-url",
            "https://tenkai.example.test",
            "reconcile",
            "--once",
        ])
        .unwrap();
        assert_eq!(cli.target, Target::Remote);
        assert_eq!(
            cli.server_url.as_deref(),
            Some("https://tenkai.example.test")
        );
        assert!(matches!(cli.command, Command::Reconcile { once: true, .. }));
    }

    #[test]
    fn parses_fleet_status() {
        let cli = Cli::try_parse_from(["tenkaictl", "fleet", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Fleet {
                command: FleetCommand::Status
            }
        ));
        let remote = Cli::try_parse_from([
            "tenkaictl",
            "--target",
            "remote",
            "--server-url",
            "http://127.0.0.1:8080",
            "fleet",
            "status",
        ])
        .unwrap();
        assert_eq!(remote.target, Target::Remote);
        assert!(matches!(
            remote.command,
            Command::Fleet {
                command: FleetCommand::Status
            }
        ));
    }

    #[test]
    fn parses_fleet_watch() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "fleet",
            "watch",
            "--once",
            "--baseline",
            "/tmp/baseline.json",
            "--write-baseline",
            "/tmp/out.json",
            "--exit-on-any-hard-drift",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Command::Fleet {
                command:
                    FleetCommand::Watch {
                        once,
                        baseline,
                        write_baseline,
                        exit_on_any_hard_drift,
                        json,
                        interval,
                        ..
                    },
            } => {
                assert!(once);
                assert_eq!(
                    baseline.as_deref(),
                    Some(std::path::Path::new("/tmp/baseline.json"))
                );
                assert_eq!(
                    write_baseline.as_deref(),
                    Some(std::path::Path::new("/tmp/out.json"))
                );
                assert!(exit_on_any_hard_drift);
                assert!(json);
                assert_eq!(interval, 10);
            }
            _ => panic!("expected fleet watch command"),
        }
    }

    #[test]
    fn parses_env_list_and_inspect() {
        let list = Cli::try_parse_from(["tenkaictl", "env", "list"]).unwrap();
        assert!(matches!(
            list.command,
            Command::Env {
                command: EnvCommand::List
            }
        ));
        let inspect = Cli::try_parse_from(["tenkaictl", "env", "inspect", "prod"]).unwrap();
        assert!(matches!(
            inspect.command,
            Command::Env {
                command: EnvCommand::Inspect { ref env }
            } if env == "prod"
        ));
    }

    #[test]
    fn parses_one_shot_reconciler_settings() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "reconcile",
            "--once",
            "--initial-backoff",
            "3",
            "--max-backoff",
            "30",
            "--max-concurrency",
            "4",
            "--skip-gates",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Reconcile {
                once: true,
                initial_backoff: 3,
                max_backoff: 30,
                max_concurrency: 4,
                skip_gates: true,
                ..
            }
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
