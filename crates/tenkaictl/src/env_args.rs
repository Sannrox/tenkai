use std::path::PathBuf;

use clap::Subcommand;

/// Fence and reason for a configuration change. Both are required with
/// `--target remote`; the embedded target does not use them.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct RemoteChange {
    /// Current fencing generation; required with --target remote.
    #[arg(long)]
    pub(crate) generation: Option<u64>,
    /// Why the change is made, recorded in the audit; required with --target remote.
    #[arg(long)]
    pub(crate) reason: Option<String>,
}

#[derive(Subcommand)]
pub(crate) enum EnvCommand {
    /// Record or inspect software compatibility preflight evidence.
    Compatibility {
        #[command(subcommand)]
        command: CompatibilityCommand,
    },
    /// Register an environment.
    Add {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        /// Connectivity class to set on registration (connected, intermittent, isolated).
        #[arg(long)]
        connectivity: Option<String>,
        /// Why the environment is registered; required with --target remote.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Register a non-promotable preview environment from a branch pin.
    Preview {
        name: String,
        /// Content-addressed `tenkai.branch_pin.v1` document.
        #[arg(long)]
        pin: PathBuf,
        /// RFC 3339 expiry. Teardown never deletes a non-preview environment.
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Record branch close and tear down a preview environment.
    ClosePreview { env: String },
    /// List registered environments with compact delivery summaries.
    List,
    /// Inspect one environment: subscriptions, deployed versions, lease/fence, latest plan.
    Inspect { env: String },
    /// Retire an environment after its active apply has been unlocked.
    Retire {
        env: String,
        #[arg(long)]
        reason: String,
    },
    /// Subscribe an environment to a product channel, e.g. `subscribe local hello=stable`.
    Subscribe {
        env: String,
        spec: String,
        /// Current fencing generation; required with --target remote.
        #[arg(long)]
        generation: Option<u64>,
    },
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
    /// Set the environment connectivity class (connected, intermittent, isolated).
    Connectivity { env: String, class: String },
    /// Manage environment capability / inventory facts (architecture, memory, …).
    Facts {
        #[command(subcommand)]
        command: FactsCommand,
    },
    /// Record observed type and runtime digests for workshop-module admission.
    Observe {
        env: String,
        #[arg(long)]
        type_digest: String,
        #[arg(long)]
        runtime_digest: String,
    },
    /// Manage planning constraints (version pins/ranges, required facts).
    Constraints {
        #[command(subcommand)]
        command: ConstraintsCommand,
    },
    /// Manage non-secret product overlays that can force a same-version re-apply.
    Overlay {
        #[command(subcommand)]
        command: OverlayCommand,
    },
    /// Manage environment-scoped OCI artifact mirrors. Origin pull is refused.
    ArtifactMirror {
        #[command(subcommand)]
        command: ArtifactMirrorCommand,
    },
    /// Manage the environment-scoped cluster config file path. Never credential bytes.
    ClusterConfig {
        #[command(subcommand)]
        command: ClusterConfigCommand,
    },
    /// Manage the environment-scoped Docker secret-file directory. Never secret bytes.
    DockerSecrets {
        #[command(subcommand)]
        command: DockerSecretsCommand,
    },
    /// Manage the environment-scoped plan approval policy file path. Never key bytes.
    ApprovalPolicy {
        #[command(subcommand)]
        command: ApprovalPolicyCommand,
    },
    /// Require attested runner enrollment and renewal (#675).
    RunnerAttestation {
        #[command(subcommand)]
        command: RunnerAttestationCommand,
    },
    /// Manage signed post-deploy webhook endpoints. Never secret bytes.
    Webhooks {
        #[command(subcommand)]
        command: WebhooksCommand,
    },
    /// Pause delivery to an environment. The reconciler still plans.
    Hold {
        env: String,
        /// Current fencing generation; required with --target remote.
        #[arg(long)]
        generation: Option<u64>,
        #[command(subcommand)]
        action: HoldAction,
    },
    /// Plan an explicit retry of a held failed target.
    Retry {
        env: String,
        product: String,
        #[arg(long)]
        reason: String,
        /// Current fencing generation; required with --target remote.
        #[arg(long)]
        generation: Option<u64>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ArtifactMirrorCommand {
    /// List origin registry → mirror host mappings.
    List { env: String },
    /// Set one mapping, e.g. `set edge ghcr.io=mirror.internal`.
    Set { env: String, spec: String },
    /// Clear the mirror for one origin registry.
    Clear { env: String, registry: String },
}

#[derive(Subcommand)]
pub(crate) enum ClusterConfigCommand {
    /// Show the stored kubeconfig file path (never file contents).
    Show { env: String },
    /// Set the environment-scoped kubeconfig file path.
    Set { env: String, path: PathBuf },
    /// Clear the stored kubeconfig file path.
    Clear { env: String },
}

#[derive(Subcommand)]
pub(crate) enum DockerSecretsCommand {
    /// Show the stored secret-file directory path (never file contents).
    Show { env: String },
    /// Set the environment-scoped secret-file directory.
    Set { env: String, path: PathBuf },
    /// Clear the stored secret-file directory path.
    Clear { env: String },
}

/// Set, clear, or show an environment or channel delivery hold. The actor is
/// the authenticated management principal.
#[derive(Subcommand)]
pub(crate) enum HoldAction {
    /// Pause new execution; in-flight applies finish.
    Set {
        #[arg(long)]
        reason: String,
    },
    /// Resume execution on the next reconcile tick.
    Clear,
    /// Show the active hold and its set/clear history.
    Show,
}

#[derive(Subcommand)]
pub(crate) enum WebhooksCommand {
    /// List configured webhook URLs and secret-env names (never secret bytes).
    List { env: String },
    /// Add or replace one endpoint, keyed by URL.
    Set {
        env: String,
        #[arg(long)]
        url: String,
        /// Process environment variable that holds the HMAC secret.
        #[arg(long)]
        secret_env: String,
        /// Comma-separated events. Default: every apply outcome.
        #[arg(long)]
        events: Option<String>,
        #[command(flatten)]
        remote: RemoteChange,
    },
    /// Clear one URL, or every webhook on the environment.
    Clear {
        env: String,
        #[arg(long)]
        url: Option<String>,
        #[command(flatten)]
        remote: RemoteChange,
    },
}

#[derive(Subcommand)]
pub(crate) enum ApprovalPolicyCommand {
    /// Show the effective plan approval policy (never key bytes).
    Show { env: String },
    /// Set the environment-scoped plan approval policy file. With
    /// --target remote the path is on the server host.
    Set {
        env: String,
        path: PathBuf,
        #[command(flatten)]
        remote: RemoteChange,
    },
    /// Clear the stored plan approval policy path.
    Clear {
        env: String,
        #[command(flatten)]
        remote: RemoteChange,
    },
}

#[derive(Subcommand)]
pub(crate) enum RunnerAttestationCommand {
    /// Show the stored runner attestation policy.
    Show { env: String },
    /// Require runner attestation: every enrollment and certificate renewal
    /// carries host evidence signed with the runner key, at most
    /// --max-age-ms old, that matches the operator-declared facts.
    Set {
        env: String,
        #[arg(long)]
        max_age_ms: u64,
        /// Refuse a file runner key; the runner must generate its key in a
        /// hardware store (TPM 2.0 on Linux).
        #[arg(long)]
        require_hardware_key: bool,
        #[command(flatten)]
        remote: RemoteChange,
    },
    /// Stop requiring runner attestation.
    Clear {
        env: String,
        #[command(flatten)]
        remote: RemoteChange,
    },
}

#[derive(Subcommand)]
pub(crate) enum OverlayCommand {
    /// List overlays, optionally for one product.
    List {
        env: String,
        product: Option<String>,
    },
    /// Set one overlay, e.g. `set prod api region=eu`.
    Set {
        env: String,
        product: String,
        spec: String,
    },
    /// Clear one overlay key, or every overlay for the product.
    Clear {
        env: String,
        product: String,
        key: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum FactsCommand {
    /// List capability facts for an environment.
    List { env: String },
    /// Set a fact, e.g. `set prod architecture=arm64`.
    Set {
        env: String,
        spec: String,
        #[command(flatten)]
        remote: RemoteChange,
    },
    /// Clear one fact key.
    Clear {
        env: String,
        key: String,
        #[command(flatten)]
        remote: RemoteChange,
    },
    /// Probe local hardware inventory (dry-run by default).
    Probe {
        env: String,
        /// Write probed facts via the normal fact API.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConstraintsCommand {
    /// List constraints for an environment.
    List { env: String },
    /// Set a constraint: `set <env> version_pin <product> <version>`,
    /// `version_range <product> <min>..<max>`, or `require_fact <key> <value|*>`.
    Set {
        env: String,
        kind: String,
        name: String,
        value: String,
        #[command(flatten)]
        remote: RemoteChange,
    },
    /// Clear a constraint.
    Clear {
        env: String,
        kind: String,
        name: String,
        #[command(flatten)]
        remote: RemoteChange,
    },
}
#[derive(Subcommand)]
pub(crate) enum MaintenanceCommand {
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
        #[command(flatten)]
        remote: RemoteChange,
    },
    /// List recurring windows for an environment.
    List { env: String },
    /// Remove a named recurring window.
    Remove {
        env: String,
        identity: String,
        #[command(flatten)]
        remote: RemoteChange,
    },
    /// Replace an invalid configuration with an empty governed schedule.
    Repair { env: String },
}

#[derive(Subcommand)]
pub(crate) enum CompatibilityCommand {
    /// Store a versioned observation JSON document for one environment.
    Record { env: String, evidence: PathBuf },
    /// Print the compatibility report for product@version; fail if blocked.
    Check { env: String, release: String },
}
