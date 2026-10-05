use anyhow::Result;
use tenkai::{client, maintenance};

use crate::product_args::{ProductCommand, ProductMaintenanceCommand};

pub(crate) async fn run(ctx: &mut client::Ctx, command: ProductCommand) -> Result<()> {
    match command {
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
