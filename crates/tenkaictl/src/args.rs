use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::catalog_args::{ApprovalCommand, CanaryCommand, ReleaseCommand};
use crate::dev_args::DevCommand;
use crate::env_args::EnvCommand;
use crate::flags::{ApprovalFileFlags, DevelopmentBypassFlags};
use crate::fleet_args::FleetCommand;
use crate::migrate_args::MigrateCommand;
use crate::product_args::ProductCommand;
use crate::upgrade_args::UpgradeCommand;
use crate::wave_args::WaveCommand;

#[derive(Parser)]
#[command(name = "tenkaictl", version, about = "Constraint-based local delivery")]
pub(crate) struct Cli {
    /// Select the embedded application core or an authenticated remote server.
    #[arg(long, value_enum, default_value_t = Target::Embedded, global = true)]
    pub(crate) target: Target,
    /// Tenkai server URL; required with --target remote.
    #[arg(long, env = "TENKAI_SERVER_URL", global = true)]
    pub(crate) server_url: Option<String>,
    /// Embedded SQLite state file. Ignored by remote mode.
    #[arg(
        long,
        env = "TENKAI_DATABASE",
        default_value = ".tenkai-state/tenkai.db",
        global = true
    )]
    pub(crate) database: PathBuf,
    /// Stable output contract for typed adapters. Human output remains the default.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human, global = true)]
    pub(crate) output: OutputFormat,
    /// Inbound delivery correlation identity for spans and metrics.
    #[arg(long, env = "TENKAI_OPERATION_ID", global = true)]
    pub(crate) operation_id: Option<String>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Target {
    Embedded,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    Human,
    JsonV1,
}

#[derive(Subcommand)]
pub(crate) enum RecoveryCommand {
    /// Write a versioned allowlisted diagnostic for one plan.
    Export {
        #[arg(long)]
        env: String,
        #[arg(long)]
        plan: String,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum Command {
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
        /// Registered, versioned release-provenance envelope (repeatable).
        #[arg(long = "provenance")]
        provenance: Vec<PathBuf>,
        /// Trust roots authenticating release-provenance issuers.
        #[arg(long, requires = "provenance")]
        provenance_trust_roots: Option<PathBuf>,
        /// Bounded change-set publication evidence for a `[change_set_pin]` manifest.
        #[arg(long)]
        change_set_evidence: Option<PathBuf>,
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
    /// Ordered multi-environment rollout waves (observe or execute).
    Wave {
        #[command(subcommand)]
        command: WaveCommand,
    },
    /// One signed upgrade across connected, intermittent, and isolated environments.
    Upgrade {
        #[command(subcommand)]
        command: UpgradeCommand,
    },
    /// Immutable source-to-target package migration plans.
    Migrate {
        #[command(subcommand)]
        command: MigrateCommand,
    },
    /// Show the steps that would converge the environment (dry run).
    Plan {
        #[arg(long, default_value = "local")]
        env: String,
        /// Current fencing generation; required with --target remote.
        #[arg(long)]
        generation: Option<u64>,
    },
    /// Execute a stored plan: gates, install, health probe, auto-rollback.
    Apply {
        plan_id: String,
        #[command(flatten)]
        approval: ApprovalFileFlags,
        /// Bypass eval gates (recorded like any other apply).
        #[arg(long)]
        skip_gates: bool,
        /// Start outside maintenance policy and record this reason with the authenticated principal.
        #[arg(long)]
        emergency_reason: Option<String>,
        /// Current fencing generation; required with --target remote.
        #[arg(long)]
        generation: Option<u64>,
    },
    /// Deployed vs channel head, per subscribed product.
    Status {
        #[arg(long, default_value = "local")]
        env: String,
    },
    /// Inspect the embedded control-plane state without distributed diagnostics.
    Inspect,
    /// Export a bounded, read-only recovery diagnostic (no authority).
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    /// Create a transactionally consistent embedded-state backup.
    Backup { destination: PathBuf },
    /// Replace embedded state from a verified backup. The CLI must be the only writer.
    Restore { source: PathBuf },
    /// Roll a product back to its previously deployed version.
    Rollback {
        product: String,
        #[arg(long, default_value = "local")]
        env: String,
        #[command(flatten)]
        bypass: DevelopmentBypassFlags,
        /// Start outside maintenance policy and record this reason with the authenticated principal.
        #[arg(long)]
        emergency_reason: Option<String>,
        /// Admit rollback onto a recalled previous pin.
        #[arg(long, requires = "recovery_reason")]
        allow_recalled_recovery: bool,
        /// Audited reason for restoring recalled Catalog content.
        #[arg(long, requires = "allow_recalled_recovery")]
        recovery_reason: Option<String>,
        /// Current fencing generation; required with --target remote.
        #[arg(long)]
        generation: Option<u64>,
    },
    /// Bounce the currently deployed release of a product without changing version.
    Restart {
        product: String,
        #[arg(long, default_value = "local")]
        env: String,
        #[command(flatten)]
        bypass: DevelopmentBypassFlags,
        #[arg(long)]
        emergency_reason: Option<String>,
    },
    /// Manage product-level maintenance windows (intersected with environment windows).
    Product {
        #[command(subcommand)]
        command: ProductCommand,
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
        #[command(flatten)]
        bypass: DevelopmentBypassFlags,
    },
    /// Development-only signing helpers for laptop dogfood (not production KMS).
    Dev {
        #[command(subcommand)]
        command: DevCommand,
    },
}
