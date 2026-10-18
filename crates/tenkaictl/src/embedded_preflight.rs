use std::path::Path;

use anyhow::{Result, bail};
use tenkai::client::Ctx;
use tenkai::host_preflight::{self, PreflightConfig};

/// Run the host checks for `env`, sign them, and record them on the
/// environment. A failed preflight is still recorded, then reported as an error.
pub(crate) async fn run(ctx: &mut Ctx, env: &str, config: &Path, signing_key: &Path) -> Result<()> {
    let config = PreflightConfig::load(config)?;
    let now = tenkai::now_millis();
    let checks = host_preflight::run_checks(&config, now);
    let evidence = host_preflight::sign(env, checks, now, signing_key)?;
    host_preflight::record(ctx, &evidence).await?;
    for check in &evidence.statement.checks {
        let verdict = if check.passed { "pass" } else { "FAIL" };
        println!("{verdict} {}: {}", check.check, check.reason);
    }
    println!("recorded preflight for {env} signed by {}", evidence.key_id);
    if !evidence.statement.passed {
        bail!("host preflight failed for {env}");
    }
    Ok(())
}
