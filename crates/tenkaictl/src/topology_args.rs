use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum TopologyCommand {
    /// Take one replica out of service, prove the minimum holds, restore it, and sign evidence.
    Drill {
        /// Published release that declares the topology.
        release: String,
        /// Replica environment to take out of service.
        replica: String,
        /// 32-byte Ed25519 seed (mode 0600) that signs the evidence.
        #[arg(long)]
        signing_key: PathBuf,
        /// Where to write the signed evidence JSON.
        #[arg(long)]
        out: PathBuf,
    },
}
