//! Private process supervisor for generation-fenced deployment commands.

use std::path::PathBuf;

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
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let code = tenkai::fenced_mutation::guard(
        tenkai::fenced_mutation::MutationCommand {
            lock_path: &args.lock,
            workdir: &args.workdir,
            environment: &args.environment,
            product: &args.product,
            command: &args.command,
        },
        args.generation,
    )
    .await;
    std::process::ExitCode::from(code)
}
