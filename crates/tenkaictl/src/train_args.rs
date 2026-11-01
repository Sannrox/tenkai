use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum TrainCommand {
    /// Admit a signed family release train into the candidate channel.
    Admit {
        /// tenkai.release-train.v1 JSON naming each component version and
        /// family release digest tested together.
        profile: PathBuf,
        /// Release signature over the train profile.
        #[arg(long)]
        signature: PathBuf,
        /// Release trust roots that authenticate the signature.
        #[arg(long)]
        trust_roots: PathBuf,
    },
    /// Promote an admitted train from candidate to stable.
    Promote {
        name: String,
        /// Approve the gate flags (breaking, migration, realm) its member
        /// releases carry. Required when any member carries one.
        #[arg(long)]
        approve_gates: bool,
    },
    /// Show an admitted train, its channel, and its components.
    Show { name: String },
}
