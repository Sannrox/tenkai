use anyhow::Result;
use std::io::Write as _;
use tenkai::client::Ctx;

use crate::topology_args::TopologyCommand;

/// Run an explicit topology drill against the embedded store.
pub(crate) async fn run(ctx: &mut Ctx, command: TopologyCommand) -> Result<()> {
    match command {
        TopologyCommand::Drill {
            release,
            replica,
            signing_key,
            out,
        } => {
            // A new file only: --out must not replace the database or the seed.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&out)
                .map_err(|error| anyhow::anyhow!("writing {}: {error}", out.display()))?;
            let evidence =
                tenkai::topology_drill::run(ctx, &release, &replica, &signing_key).await?;
            file.write_all(&serde_json::to_vec_pretty(&evidence)?)
                .map_err(|error| anyhow::anyhow!("writing {}: {error}", out.display()))?;
            let statement = &evidence.statement;
            println!(
                "loss: {} at {}",
                statement.loss.replica, statement.loss.at_ms
            );
            println!(
                "recovery: {} remaining available in {} ms; traffic continued",
                statement.recovery.remaining_available.len(),
                statement.recovery.duration_ms
            );
            println!(
                "restore: {} at {}",
                statement.restore.replica, statement.restore.at_ms
            );
            println!(
                "wrote topology drill evidence {} signed by {}",
                out.display(),
                evidence.key_id
            );
            Ok(())
        }
    }
}
