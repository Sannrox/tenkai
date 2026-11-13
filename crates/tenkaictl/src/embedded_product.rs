use anyhow::Result;
use tenkai::{client, maintenance};

use crate::product_args::{
    ProductCommand, ProductCriticalityCommand, ProductMaintenanceCommand, ProductOwnerCommand,
    ProductWebhooksCommand,
};

pub(crate) async fn run(ctx: &mut client::Ctx, command: ProductCommand) -> Result<()> {
    match command {
        ProductCommand::Criticality { command } => match command {
            ProductCriticalityCommand::Show { product } => {
                let view = tenkai::criticality_store::inspect_product(ctx, &product).await?;
                if view.is_empty() {
                    println!("product {product} has no criticality");
                } else {
                    println!("{}", serde_json::to_string_pretty(&view)?);
                }
            }
            ProductCriticalityCommand::Set {
                product,
                level,
                owner,
                reason,
            } => {
                println!(
                    "{}",
                    tenkai::criticality_store::set_product(
                        ctx,
                        &product,
                        &tenkai::criticality::SetCriticalityRequest {
                            level: tenkai::criticality::CriticalityLevel::parse(&level)?,
                            owner,
                            reason,
                        },
                    )
                    .await?
                );
            }
            ProductCriticalityCommand::Clear { product } => {
                println!(
                    "{}",
                    tenkai::criticality_store::clear_product(ctx, &product).await?
                );
            }
        },
        ProductCommand::Owner { command } => match command {
            ProductOwnerCommand::Show { product } => {
                match tenkai::owner::product_owner(ctx, &product).await? {
                    Some(owner) => {
                        if owner.endpoints.is_empty() {
                            println!("{} (no notification endpoint)", owner.contact);
                        } else {
                            println!("{} endpoints={}", owner.contact, owner.endpoints.join(","));
                        }
                    }
                    None => println!("product {product} has no owner"),
                }
            }
            ProductOwnerCommand::Set { product, contact } => {
                println!(
                    "{}",
                    tenkai::owner::set_product_owner(ctx, &product, &contact).await?
                );
            }
            ProductOwnerCommand::Clear { product } => {
                println!(
                    "{}",
                    tenkai::owner::clear_product_owner(ctx, &product).await?
                );
            }
        },
        ProductCommand::Webhooks { command } => match command {
            ProductWebhooksCommand::List { product } => {
                let endpoints = tenkai::owner::list_product_webhooks(ctx, &product).await?;
                if endpoints.is_empty() {
                    println!("{product} has no webhooks");
                } else {
                    for endpoint in endpoints {
                        println!(
                            "{} secret_env={} events={}",
                            endpoint.url,
                            endpoint.secret_env,
                            crate::embedded_env_config::format_webhook_subscription(&endpoint)
                        );
                    }
                }
            }
            ProductWebhooksCommand::Set {
                product,
                url,
                secret_env,
                events,
            } => {
                let (events, operational, feedback) =
                    crate::embedded_env_config::parse_webhook_events(events.as_deref())?;
                println!(
                    "{}",
                    tenkai::owner::set_product_webhook(
                        ctx,
                        &product,
                        tenkai::deploy_webhook::WebhookEndpoint {
                            url,
                            secret_env,
                            events,
                            operational,
                            feedback,
                        },
                    )
                    .await?
                );
            }
            ProductWebhooksCommand::Clear { product, url } => {
                println!(
                    "{}",
                    tenkai::owner::clear_product_webhooks(ctx, &product, url.as_deref()).await?
                );
            }
        },
        ProductCommand::Maintenance { command } => match command {
            ProductMaintenanceCommand::Set {
                product,
                identity,
                timezone,
                weekdays,
                start,
                duration_minutes,
            } => {
                let window = maintenance::Window::new(
                    identity,
                    timezone,
                    maintenance::weekday_values(&weekdays)?,
                    start,
                    duration_minutes,
                )?;
                println!("{}", maintenance::set_product(ctx, &product, window).await?);
            }
            ProductMaintenanceCommand::List { product } => {
                let windows = maintenance::list_product(ctx, &product).await?;
                if windows.is_empty() {
                    println!("{product} has no product maintenance windows");
                } else {
                    for window in windows {
                        println!(
                            "{} {} weekdays={:?} {} {}m",
                            window.identity,
                            window.timezone,
                            window.weekdays,
                            window.start,
                            window.duration_minutes
                        );
                    }
                }
            }
            ProductMaintenanceCommand::Remove { product, identity } => {
                println!(
                    "{}",
                    maintenance::remove_product(ctx, &product, &identity).await?
                );
            }
        },
    }
    Ok(())
}
