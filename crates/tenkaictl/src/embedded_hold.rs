use anyhow::Result;
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
