//! Private process supervisor for generation-fenced deployment commands.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "tenkai-executor-guard", hide = true)]
struct Args {
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tenkai::fenced_mutation::supervise(
        tenkai::fenced_mutation::MutationCommand {
            lock_path: &args.lock,
            workdir: &args.workdir,
            environment: &args.environment,
            product: &args.product,
            command: &args.command,
        },
        args.generation,
    )
    .await
}
