use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::bundle_args::BundleCommand;
use crate::catalog_args::{
    ApprovalCommand, CanaryCommand, ChannelCommand, EvalEvidenceCommand, ReleaseCommand,
};
use crate::dev_args::DevCommand;
use crate::env_args::EnvCommand;
use crate::flags::{ApprovalFileFlags, DevelopmentBypassFlags};
use crate::fleet_args::FleetCommand;
use crate::migrate_args::MigrateCommand;
use crate::product_args::ProductCommand;
use crate::topology_args::TopologyCommand;
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
    /// Sign in to a remote server through the configured OIDC provider.
    Login {
        /// Pre-registered OIDC client ID. Defaults to GET /v1/auth/oidc.
        #[arg(long)]
        client_id: Option<String>,
        /// Non-interactive client-credentials login. Reads TENKAI_OIDC_CLIENT_SECRET.
        #[arg(long)]
        client_credentials: bool,
        /// Loopback port for the authorization redirect. 0 binds an ephemeral port.
        #[arg(long, default_value_t = 0)]
        callback_port: u16,
        /// Print the authorization URL instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
        /// Seconds to wait for the browser callback.
        #[arg(long, default_value_t = 300)]
        timeout: u64,
    },
    /// Forget the saved OIDC login for a remote server.
    Logout,
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
    /// Check this host for an environment and record signed preflight evidence.
    Preflight {
        env: String,
        /// Version 1 TOML naming the disk, memory, port, clock, certificate,
        /// registry, and identity-provider checks.
        #[arg(long)]
        config: PathBuf,
        /// 32-byte Ed25519 seed (mode 0600) of a trust root scoped to the
        /// `preflight` provider for this environment.
        #[arg(long)]
        signing_key: PathBuf,
    },
    /// Sign, import, or show signed offline key revocation lists.
    Revocations {
        #[command(subcommand)]
        command: RevocationsCommand,
    },
    /// On-site customer key-provider profile and ceremony.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Local-only dark-site profile: model_runtime plus site-agent workers.
    DarkSite {
        #[command(subcommand)]
        command: DarkSiteCommand,
    },
    /// Enroll, list, inspect and revoke runtime agents (server only).
    #[command(visible_alias = "runner")]
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    /// The read-only seed registry over the local artifact store.
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// Inspect or reverify published release trust evidence.
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// Import a signed advisory feed, inspect it, or query component exposure.
    Exposure {
        #[command(subcommand)]
        command: ExposureCommand,
    },
    /// Import a signed derived-criticality envelope (#694).
    Criticality {
        #[command(subcommand)]
        command: DerivedCriticalityCommand,
    },
    /// Inspect recorded plan-approval verification evidence.
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    /// Point a channel at a published release, e.g. `promote hello@0.1.0 stable`.
    Promote { spec: String, channel: String },
    /// Install evaluation trust roots or record a signed Chisei evaluation.
    EvalEvidence {
        #[command(subcommand)]
        command: EvalEvidenceCommand,
    },
    /// Manage canary designation, promotion policy, and evidence repair.
    Canary {
        #[command(subcommand)]
        command: CanaryCommand,
    },
    /// Channel operations.
    Channel {
        #[command(subcommand)]
        command: ChannelCommand,
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
    /// Recall matching releases and admit a fix-forward wave, or import a notice.
    Remediate {
        #[command(subcommand)]
        command: RemediateCommand,
    },
    /// Failover-drill a replica of a declared topology (explicit request only).
    Topology {
        #[command(subcommand)]
        command: TopologyCommand,
    },
    /// Create a runner certificate authority (local only, #674).
    RunnerCa {
        #[command(subcommand)]
        command: RunnerCaCommand,
    },
    /// Upgrade or roll back this host's Tenkai server binaries from a signed
    /// bundle, gated on the store check and readiness (local only).
    SelfUpgrade {
        #[command(subcommand)]
        command: crate::self_upgrade::SelfUpgradeCommand,
    },
    /// One signed upgrade across connected, intermittent, and isolated environments.
    Upgrade {
        #[command(subcommand)]
        command: UpgradeCommand,
    },
    /// Build a signed full-stack offline bundle from published releases.
    Bundle {
        #[command(subcommand)]
        command: BundleCommand,
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
    /// Rehearse restoring a server backup into a scratch store and print the
    /// evidence. Never touches live state.
    /// Export or verify a redacted, signed support bundle.
    SupportBundle {
        #[command(subcommand)]
        command: SupportBundleCommand,
    },
    /// Export or verify signed, period-chained audit and usage records.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    RestoreDrill {
        /// A `tenkai-backup-<ms>.db` backup with its manifest beside it.
        backup: PathBuf,
        /// Where the scratch store is created and removed again (default: the temp directory).
        #[arg(long)]
        scratch_dir: Option<PathBuf>,
        /// Refuse unless the manifest carries a signature by one of these signers.
        #[arg(long)]
        trust_roots: Option<PathBuf>,
    },
    /// Record a database-native backup of a tenant-mode hub's PostgreSQL
    /// store in the hub's backup directory and print the backup status.
    /// Tenkai does not copy the database; health reports the age of this evidence.
    BackupEvidence {
        /// The hub's `TENKAI_BACKUP_DIR`.
        dir: PathBuf,
        /// The backup file; its name, sha256 and size are recorded.
        #[arg(long)]
        backup: PathBuf,
        /// What took the backup, such as the dump tool and its version.
        #[arg(long)]
        tool: String,
        /// When the backup was taken (default: now).
        #[arg(long)]
        taken_at_ms: Option<i64>,
    },
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

#[derive(Subcommand)]
pub(crate) enum RuntimeCommand {
    /// Issue a single-use enrollment token for an environment's runtime
    /// agent. The token is printed once; the agent exchanges it for its own
    /// credential with `tenkai-runtime --enrollment-token`.
    Enroll {
        env: String,
        /// How long the token may be redeemed, in seconds (default 900).
        #[arg(long)]
        ttl_seconds: Option<u64>,
    },
    /// List runners: enrolled credentials and static tokens, with each
    /// instance's last work pull, heartbeat and version.
    List,
    /// Show one runner by its id (`sha256:...`).
    Inspect { runner_id: String },
    /// Revoke a runner's credential by its id (`sha256:...`).
    Revoke {
        credential_id: String,
        /// Why; recorded and shown on inspect.
        #[arg(long)]
        reason: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum RunnerCaCommand {
    /// Generate a runner CA: `runner-ca.pem` and the owner-only
    /// `runner-ca-key.pem` in `dir`. Point the server's
    /// `TENKAI_RUNNER_CA_CERT`/`TENKAI_RUNNER_CA_KEY` and its TLS client CA
    /// at them. Bring your own CA instead by supplying those files.
    Init {
        #[arg(long)]
        dir: std::path::PathBuf,
        /// The CA's common name.
        #[arg(long, default_value = "Tenkai runner CA")]
        name: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum RemediateCommand {
    /// Recall releases matching an advisory and admit a stop-on-failure wave.
    Propose {
        /// Advisory id from the imported feed (`tenkaictl exposure query`).
        #[arg(long)]
        exposure: String,
        /// Patched release to wave, e.g. `api@1.1.0`.
        #[arg(long)]
        fix: String,
        #[arg(long)]
        channel: String,
        /// Comma-separated environment names in wave order.
        #[arg(long)]
        cohort: String,
        /// Durable wave name. Defaults to `recall-<advisory-id>`.
        #[arg(long)]
        wave_name: Option<String>,
        /// 32-byte Ed25519 seed (mode 0600) that signs the recall notice.
        #[arg(long)]
        signing_key: PathBuf,
        /// Where to write the signed recall notice.
        #[arg(long)]
        notice_out: PathBuf,
    },
    /// Import a signed recall notice and refuse planning of the named releases.
    ImportNotice {
        #[arg(long)]
        notice: PathBuf,
        /// Release-format trust roots naming the recall-notice authorities.
        #[arg(long)]
        trust_roots: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ExposureCommand {
    /// Verify a signed bundle and import `advisories/feed.json` into the catalog.
    Import {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        trust_roots: PathBuf,
        #[arg(long)]
        env: String,
    },
    /// Show imported feed age and the releases it currently flags.
    Inspect,
    /// List releases, channels, and environments matching a component range.
    Query {
        #[arg(long)]
        component: String,
        #[arg(long)]
        range: String,
        /// Keep matches whose effective criticality is at least this.
        #[arg(long)]
        min_criticality: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum DerivedCriticalityCommand {
    /// Verify and apply a signed `tenkai.derived-criticality.v1` envelope.
    Import {
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long)]
        trust_roots: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum RegistryCommand {
    /// Serve `TENKAI_OCI_STORE` as a read-only OCI registry over TLS, by
    /// digest only, so executors on a dark site can pull imported images.
    Serve {
        /// The artifact store bundles were imported into.
        #[arg(long, env = "TENKAI_OCI_STORE")]
        store: PathBuf,
        /// The `host[:port]` executors pull from; the environment's mirror
        /// (`upgrade install-bundle --seed-registry`).
        #[arg(long)]
        name: String,
        /// Address to listen on.
        #[arg(long)]
        listen: std::net::SocketAddr,
        /// PEM certificate chain for `name`, issued by the site's CA.
        #[arg(long)]
        tls_cert: PathBuf,
        /// PEM private key of that certificate.
        #[arg(long)]
        tls_key: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum DarkSiteCommand {
    /// Load and validate a version 1 dark-site profile.
    Validate {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Bind an offline stack index and write the active profile beside runtime state.
    Activate {
        #[arg(long)]
        profile: PathBuf,
        /// `tenkai.offline-stack.v1` JSON (from `stack/manifest.json`).
        #[arg(long)]
        stack: PathBuf,
        /// Environment runtime directory that will hold `dark-site.json`.
        #[arg(long)]
        state: PathBuf,
    },
    /// Report combined model and site-agent readiness for the active profile.
    Ready {
        #[arg(long)]
        state: PathBuf,
        /// `healthy` or `unhealthy` from the running model_runtime.
        #[arg(long)]
        model_health: String,
        /// Workers currently `ready` or `active` at the pinned version.
        #[arg(long, default_value_t = 0)]
        ready_replicas: u32,
    },
    /// Decide digest-pinned rollback using existing worker drain.
    Rollback {
        #[arg(long)]
        state: PathBuf,
        /// Active claims still held by current workers.
        #[arg(long, default_value_t = 0)]
        active_claims: u32,
    },
}

#[derive(Subcommand)]
pub(crate) enum KeysCommand {
    /// Create a root key reference and per-tenant data-key ids, then sign evidence.
    Ceremony {
        /// Version 1 deploy profile TOML (`class` plus `[key_provider].kind`).
        #[arg(long)]
        profile: PathBuf,
        /// 32-byte Ed25519 seed (mode 0600) that signs the ceremony evidence.
        #[arg(long)]
        signing_key: PathBuf,
        /// Named custodian present at the ceremony. Repeatable.
        #[arg(long = "custodian", required = true)]
        custodian: Vec<String>,
        /// Tenant that receives a data-key id. Repeatable.
        #[arg(long = "tenant", required = true)]
        tenant: Vec<String>,
        /// Lab software-provider directory. Owner-only; never a bundle or plan path.
        #[arg(long)]
        provider_dir: PathBuf,
        /// Where to write the signed evidence JSON.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum RevocationsCommand {
    /// Sign a revocation list with a revocation authority seed.
    Sign {
        /// 32-byte Ed25519 seed (mode 0600) of a revocation authority.
        #[arg(long)]
        signing_key: PathBuf,
        /// Higher than every list installed anywhere it will be imported.
        #[arg(long)]
        sequence: u64,
        /// `<key_id>=<reason>`; repeat for each key. Keep earlier revocations.
        #[arg(long = "revoke", required = true)]
        revoke: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a list against TENKAI_KEY_REVOCATION_TRUST_ROOTS and install it
    /// at TENKAI_KEY_REVOCATIONS.
    Import { list: PathBuf },
    /// Print the installed list.
    Show,
}

#[derive(clap::Subcommand)]
pub(crate) enum AuditCommand {
    /// Write the next export of the chain in `dir`: everything written since
    /// its newest export, signed with the Ed25519 seed. The existing chain
    /// must verify first.
    Export {
        dir: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        /// Trust roots for exports in `dir` signed before a key rotation.
        #[arg(long)]
        trust_roots: Option<PathBuf>,
    },
    /// Write the chain's existing exports `--from..=--to` in `dir` to
    /// `--out` as one ranged export. The range must verify first.
    ExportRange {
        dir: PathBuf,
        #[arg(long)]
        from: u64,
        #[arg(long)]
        to: u64,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        trust_roots: PathBuf,
    },
    /// Verify exports in order: signatures, contiguous cursors, chaining.
    /// A single ranged export verifies as the chain it holds.
    Verify {
        #[arg(required = true, num_args = 1..)]
        exports: Vec<PathBuf>,
        #[arg(long)]
        trust_roots: PathBuf,
        /// Digest of the export before the first one given, when the files
        /// continue an earlier chain.
        #[arg(long)]
        anchor: Option<String>,
    },
}

#[derive(clap::Subcommand)]
pub(crate) enum SupportBundleCommand {
    /// Collect version, redacted configuration, store and executor status
    /// and recovery diagnostics from the embedded store, signed with the seed.
    Export {
        /// New file to write; an existing file is never replaced.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        /// A server log to take `tenkai.*` events from (allowlisted fields only).
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Verify a bundle after transfer.
    Verify {
        bundle: PathBuf,
        #[arg(long)]
        trust_roots: PathBuf,
    },
}
