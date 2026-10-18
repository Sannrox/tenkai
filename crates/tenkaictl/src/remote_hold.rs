use anyhow::Result;
use tenkai::delivery_hold::DeliveryHoldView;

use crate::env_args::HoldAction;

pub(crate) async fn environment(
    client: &tenkai_http::RemoteClient,
    env: &str,
    generation: Option<u64>,
    action: HoldAction,
) -> Result<()> {
    match action {
        HoldAction::Set { reason } => {
            let generation = require_generation(generation)?;
            let result = client
                .set_environment_hold(env, &reason, generation)
                .await?;
            println!("{}", result.message);
        }
        HoldAction::Clear => {
            let generation = require_generation(generation)?;
            let result = client.release_environment_hold(env, generation).await?;
            println!("{}", result.message);
        }
        HoldAction::Show => {
            print_view(&client.environment_hold(env).await?);
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
            print_view(&client.channel_hold(product, channel).await?);
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

fn print_view(view: &DeliveryHoldView) {
    match &view.hold {
        Some(hold) => println!(
            "held at {} by {}: {}",
            hold.held_at, hold.actor, hold.reason
        ),
        None => println!("no delivery hold"),
    }
    for event in &view.audit {
        println!(
            "{} {} by {}: {}",
            event.at, event.action, event.actor, event.reason
        );
    }
}
