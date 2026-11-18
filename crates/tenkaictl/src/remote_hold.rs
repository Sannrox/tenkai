use anyhow::Result;

use crate::env_args::HoldAction;

/// Run a hold action on `env`. `selector` is the selector the operator named
/// to reach `env`; a hold set records it.
pub(crate) async fn environment(
    client: &tenkai_http::RemoteClient,
    env: &str,
    selector: Option<&str>,
    generation: Option<u64>,
    action: HoldAction,
) -> Result<()> {
    match action {
        HoldAction::Set { reason } => {
            let generation = require_generation(generation)?;
            let result = client
                .set_environment_hold(env, &reason, generation, selector)
                .await?;
            println!("{}", result.message);
        }
        HoldAction::Clear => {
            let generation = require_generation(generation)?;
            let result = client.release_environment_hold(env, generation).await?;
            println!("{}", result.message);
        }
        HoldAction::Show => {
            crate::output::print_hold_view(&client.environment_hold(env).await?);
        }
        HoldAction::Schedule {
            name,
            from,
            until,
            reason,
        } => {
            let generation = require_generation(generation)?;
            let result = client
                .schedule_environment_freeze(
                    env,
                    &name,
                    from.as_deref(),
                    &until,
                    &reason,
                    generation,
                )
                .await?;
            println!("{}", result.message);
        }
        HoldAction::Cancel { name } => {
            let generation = require_generation(generation)?;
            let result = client
                .cancel_environment_freeze(env, &name, generation)
                .await?;
            println!("{}", result.message);
        }
        HoldAction::Threshold { count, window } => {
            let generation = require_generation(generation)?;
            let result = client
                .set_environment_failure_threshold(env, count, &window, generation)
                .await?;
            println!("{}", result.message);
        }
        HoldAction::ThresholdClear => {
            let generation = require_generation(generation)?;
            let result = client
                .clear_environment_failure_threshold(env, generation)
                .await?;
            println!("{}", result.message);
        }
    }
    Ok(())
}

pub(crate) async fn channel(
    client: &tenkai_http::RemoteClient,
    product: &str,
    channel: &str,
    action: HoldAction,
) -> Result<()> {
    match action {
        HoldAction::Set { reason } => {
            let result = client.set_channel_hold(product, channel, &reason).await?;
            println!("{}", result.message);
        }
        HoldAction::Clear => {
            let result = client.release_channel_hold(product, channel).await?;
            println!("{}", result.message);
        }
        HoldAction::Show => {
            crate::output::print_hold_view(&client.channel_hold(product, channel).await?);
        }
        HoldAction::Schedule { .. }
        | HoldAction::Cancel { .. }
        | HoldAction::Threshold { .. }
        | HoldAction::ThresholdClear => {
            anyhow::bail!("change freezes and failure thresholds are per environment");
        }
    }
    Ok(())
}

pub(crate) async fn retry(
    client: &tenkai_http::RemoteClient,
    env: &str,
    product: &str,
    reason: &str,
    generation: Option<u64>,
) -> Result<()> {
    let generation = require_generation(generation)?;
    let result = client
        .retry_failed_target(env, product, reason, generation)
        .await?;
    println!("{}", result.message);
    if let Some(plan_id) = &result.resource {
        println!("plan id: {plan_id}");
    }
    if let Some(digest) = &result.digest {
        println!("plan digest: {digest}");
    }
    Ok(())
}

fn require_generation(generation: Option<u64>) -> Result<u64> {
    generation.ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))
}

/// Run `apply` for every environment in `names`, not stopping at the first
/// refusal. One environment fails with its own error; several report which
/// changed and which refused, because each is fenced to its own generation
/// and a selector can leave them partly changed (#1310).
pub(crate) async fn each(
    names: std::collections::BTreeSet<String>,
    mut apply: impl AsyncFnMut(&str) -> Result<()>,
) -> Result<()> {
    let mut changed = Vec::new();
    let mut refused = Vec::new();
    let single = names.len() == 1;
    for name in &names {
        match apply(name).await {
            Ok(()) => changed.push(name.as_str()),
            Err(error) if single => return Err(error),
            Err(error) => refused.push(format!("{name}: {error:#}")),
        }
    }
    if refused.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "changed: {}; refused: {}",
        if changed.is_empty() {
            "none".to_string()
        } else {
            changed.join(", ")
        },
        refused.join("; ")
    )
}

#[cfg(test)]
mod tests {
    // #1310: a refusal for one matched environment does not stop the rest,
    // and the error names both groups.
    #[tokio::test]
    async fn each_tries_every_environment_and_names_the_split() {
        let names = ["a", "b", "c"].map(String::from).into_iter().collect();
        let mut tried = Vec::new();
        let error = super::each(names, async |name| {
            tried.push(name.to_string());
            anyhow::ensure!(name != "b", "stale generation");
            Ok(())
        })
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(tried, ["a", "b", "c"]);
        assert_eq!(error, "changed: a, c; refused: b: stale generation");
    }
}
