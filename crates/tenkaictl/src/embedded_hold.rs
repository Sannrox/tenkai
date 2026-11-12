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
            crate::output::print_hold_view(&delivery_hold::view(ctx, &scope).await?);
        }
        HoldAction::Schedule {
            name,
            from,
            until,
            reason,
        } => {
            let HoldScope::Environment(env) = &scope else {
                bail!("change freezes are per environment");
            };
            let actor = embedded_management_actor()?;
            let from_ms = match from.as_deref() {
                Some(from) => delivery_hold::parse_freeze_instant("--from", from)?,
                None => tenkai::now_millis(),
            };
            let until_ms = delivery_hold::parse_freeze_instant("--until", &until)?;
            let freeze = delivery_hold::schedule_freeze(
                ctx,
                env,
                &name,
                from_ms,
                until_ms,
                &reason,
                actor.principal_id(),
            )
            .await?;
            println!(
                "scheduled freeze {} on {env} from {} until {} by {}: {}",
                freeze.name,
                delivery_hold::format_freeze_instant(freeze.from_ms),
                delivery_hold::format_freeze_instant(freeze.until_ms),
                freeze.actor,
                freeze.reason
            );
        }
        HoldAction::Cancel { name } => {
            let HoldScope::Environment(env) = &scope else {
                bail!("change freezes are per environment");
            };
            let actor = embedded_management_actor()?;
            let freeze =
                delivery_hold::cancel_freeze(ctx, env, &name, actor.principal_id()).await?;
            println!(
                "cancelled freeze {} on {env}: {}",
                freeze.name, freeze.reason
            );
        }
        HoldAction::Threshold { count, window } => {
            let HoldScope::Environment(env) = &scope else {
                bail!("failure thresholds are per environment");
            };
            let actor = embedded_management_actor()?;
            let window_ms = delivery_hold::parse_failure_window(&window)?;
            let threshold = delivery_hold::set_failure_threshold(
                ctx,
                env,
                count,
                window_ms,
                actor.principal_id(),
            )
            .await?;
            println!(
                "threshold on {env}: more than {} failed targets in {}ms",
                threshold.count, threshold.window_ms
            );
        }
        HoldAction::ThresholdClear => {
            let HoldScope::Environment(env) = &scope else {
                bail!("failure thresholds are per environment");
            };
            let actor = embedded_management_actor()?;
            delivery_hold::clear_failure_threshold(ctx, env, actor.principal_id()).await?;
            println!("cleared failure threshold on {env}");
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
