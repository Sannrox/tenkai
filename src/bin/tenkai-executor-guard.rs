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
    tenkai::apply::executor_guard(
        &args.lock,
        &args.workdir,
        &args.environment,
        &args.product,
        args.generation,
        &args.command,
    )
    .await
}
