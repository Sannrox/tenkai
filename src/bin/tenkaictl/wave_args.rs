use clap::Subcommand;

use crate::flags::ApprovalDirFlags;

#[derive(Subcommand)]
pub(crate) enum WaveCommand {
    /// Observe an ordered environment cohort without applying or promoting.
    Run {
        /// Comma-separated environment names in wave order, e.g. `canary,stage,prod`.
        cohort: String,
        /// Continue after failures (default: stop and skip remaining).
        #[arg(long)]
        continue_on_failure: bool,
    },
    /// Admit and execute a durable release wave through named cohorts.
    Execute {
        /// Durable wave name (content-bound identity key).
        name: String,
        #[arg(long)]
        product: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        channel: String,
        /// Comma-separated environment names in wave order.
        #[arg(long)]
        cohort: String,
        #[arg(long)]
        continue_on_failure: bool,
        #[command(flatten)]
        approval: ApprovalDirFlags,
    },
    /// Show a durable wave's cohort status.
    Status { name: String },
    /// Stop advancing a durable wave without rewriting completed cohorts.
    Stop { name: String },
    /// Resume an admitted or awaiting-approval wave.
    Resume {
        name: String,
        #[command(flatten)]
        approval: ApprovalDirFlags,
    },
    /// Roll back succeeded cohorts of a durable wave through Tenkai rollback plans.
    Rollback {
        name: String,
        #[command(flatten)]
        approval: ApprovalDirFlags,
    },
}
