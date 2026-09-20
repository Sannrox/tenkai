use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum EnvCommand {
    /// Register an environment.
    Add {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
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
    },
    /// Clear a constraint.
    Clear {
        env: String,
        kind: String,
        name: String,
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
    },
    /// List recurring windows for an environment.
    List { env: String },
    /// Remove a named recurring window.
    Remove { env: String, identity: String },
    /// Replace an invalid configuration with an empty governed schedule.
    Repair { env: String },
}
