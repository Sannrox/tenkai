use anyhow::Result;
use tenkai::{client, maintenance};

use crate::product_args::{ProductCommand, ProductCriticalityCommand, ProductMaintenanceCommand};

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
