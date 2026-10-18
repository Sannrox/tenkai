use anyhow::{Result, bail};
use tenkai::client;
use tenkai::delivery_hold::{self, HoldScope};

use crate::authorization::embedded_management_actor;
use crate::env_args::HoldAction;

/// Run one hold action for an environment or channel scope.
pub(crate) async fn run(ctx: &mut client::Ctx, scope: HoldScope, action: HoldAction) -> Result<()> {
    let label = scope.key();
    match action {
        HoldAction::Set { reason } => {
            let actor = embedded_management_actor()?;
            let hold = delivery_hold::set(ctx, &scope, &reason, actor.principal_id()).await?;
            println!(
                "held {label} at {} by {}: {}",
                hold.held_at, hold.actor, hold.reason
            );
        }
        HoldAction::Clear => {
            let actor = embedded_management_actor()?;
            let cleared = delivery_hold::clear(ctx, &scope, actor.principal_id()).await?;
            println!("cleared {label} hold: {}", cleared.reason);
        }
        HoldAction::Show => {
            match delivery_hold::get(ctx, &scope).await? {
                Some(hold) => println!(
                    "held at {} by {}: {}",
                    hold.held_at, hold.actor, hold.reason
                ),
                None => println!("no delivery hold"),
            }
            for event in delivery_hold::audit(ctx, &scope).await? {
                println!(
                    "{} {} by {}: {}",
                    event.at, event.action, event.actor, event.reason
                );
            }
        }
    }
    Ok(())
}

/// Plan an explicit retry of a held failed target in embedded mode.
pub(crate) async fn retry(
    ctx: &mut client::Ctx,
    environment: &str,
    product: &str,
    reason: &str,
) -> Result<()> {
    let actor = embedded_management_actor()?;
    let Some(release) = tenkai::environment::held_failed_target(ctx, environment, product).await?
    else {
        bail!("environment {environment} has no held failed target for {product}");
    };
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "retry reason must not be empty");
    anyhow::ensure!(reason.len() <= 1024, "retry reason exceeds 1024 bytes");
    let plan = tenkai::plan::create_for_held_target(ctx, environment, product, &release).await?;
    delivery_hold::record_retry(ctx, environment, reason, actor.principal_id()).await?;
    println!(
        "planned retry of {product} ({release}) with {} step(s); plan id: {}",
        plan.steps.len(),
        plan.id
    );
    Ok(())
}
