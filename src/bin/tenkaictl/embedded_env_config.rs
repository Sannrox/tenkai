use anyhow::{Result, bail};
use tenkai::{client, inventory, maintenance, plan};

use crate::env_args::{
    ArtifactMirrorCommand, ClusterConfigCommand, ConstraintsCommand, FactsCommand,
    MaintenanceCommand, OverlayCommand,
};

pub(crate) async fn maintenance(ctx: &mut client::Ctx, command: MaintenanceCommand) -> Result<()> {
    match command {
        MaintenanceCommand::Set {
            env,
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
            println!("{}", maintenance::set(ctx, &env, window).await?);
        }
        MaintenanceCommand::List { env } => {
            let windows = maintenance::list(ctx, &env).await?;
            if windows.is_empty() {
                println!("{env} has no maintenance windows");
            } else {
                for window in windows {
                    println!(
                        "{}: {} {:?} {} for {} minutes",
                        window.identity,
                        window.timezone,
                        window.weekdays,
                        window.start,
                        window.duration_minutes
                    );
                }
            }
        }
        MaintenanceCommand::Remove { env, identity } => {
            println!("{}", maintenance::remove(ctx, &env, &identity).await?);
        }
        MaintenanceCommand::Repair { env } => {
            println!("{}", maintenance::repair(ctx, &env).await?);
        }
    }
    Ok(())
}

pub(crate) async fn facts(ctx: &mut client::Ctx, command: FactsCommand) -> Result<()> {
    match command {
        FactsCommand::List { env } => {
            let facts = plan::list_environment_facts(ctx, &env).await?;
            if facts.is_empty() {
                println!("{env} has no capability facts");
            } else {
                for (key, value) in facts {
                    println!("{key}={value}");
                }
            }
        }
        FactsCommand::Set { env, spec } => {
            let Some((key, value)) = spec.split_once('=') else {
                bail!("expected <key>=<value>, got {spec:?}");
            };
            println!(
                "{}",
                plan::set_environment_fact(ctx, &env, key, value).await?
            );
        }
        FactsCommand::Clear { env, key } => {
            println!("{}", plan::clear_environment_fact(ctx, &env, &key).await?);
        }
        FactsCommand::Probe { env, apply } => {
            let facts = inventory::probe_local_inventory()?;
            if !apply {
                println!("{}", inventory::format_dry_run(&env, &facts));
            } else if facts.is_empty() {
                println!("no inventory facts detected for {env}");
            } else {
                for fact in &facts {
                    println!(
                        "{}",
                        plan::set_environment_fact(ctx, &env, &fact.key, &fact.value).await?
                    );
                }
                println!("applied {} local-probe fact(s) to {env}", facts.len());
            }
        }
    }
    Ok(())
}

pub(crate) async fn constraints(ctx: &mut client::Ctx, command: ConstraintsCommand) -> Result<()> {
    match command {
        ConstraintsCommand::List { env } => {
            let constraints = plan::list_environment_constraints(ctx, &env).await?;
            if constraints.is_empty() {
                println!("{env} has no planning constraints");
            } else {
                for (key, value) in constraints {
                    println!("{key}={value}");
                }
            }
        }
        ConstraintsCommand::Set {
            env,
            kind,
            name,
            value,
        } => {
            println!(
                "{}",
                plan::set_environment_constraint(ctx, &env, &kind, &name, &value).await?
            );
        }
        ConstraintsCommand::Clear { env, kind, name } => {
            println!(
                "{}",
                plan::clear_environment_constraint(ctx, &env, &kind, &name).await?
            );
        }
    }
    Ok(())
}

pub(crate) async fn overlay(ctx: &mut client::Ctx, command: OverlayCommand) -> Result<()> {
    match command {
        OverlayCommand::List { env, product } => {
            let overlays = plan::list_environment_overlays(ctx, &env, product.as_deref()).await?;
            if overlays.is_empty() {
                println!("{env} has no product overlays");
            } else {
                for (key, value) in overlays {
                    println!("{key}={value}");
                }
            }
        }
        OverlayCommand::Set { env, product, spec } => {
            let Some((key, value)) = spec.split_once('=') else {
                bail!("expected <key>=<value>, got {spec:?}");
            };
            println!(
                "{}",
                plan::set_environment_overlay(ctx, &env, &product, key, value).await?
            );
        }
        OverlayCommand::Clear { env, product, key } => {
            println!(
                "{}",
                plan::clear_environment_overlay(ctx, &env, &product, key.as_deref()).await?
            );
        }
    }
    Ok(())
}

pub(crate) async fn artifact_mirror(
    ctx: &mut client::Ctx,
    command: ArtifactMirrorCommand,
) -> Result<()> {
    match command {
        ArtifactMirrorCommand::List { env } => {
            let mirrors = plan::list_artifact_mirrors(ctx, &env).await?;
            if mirrors.is_empty() {
                println!("{env} has no artifact mirrors");
            } else {
                for (registry, mirror) in mirrors {
                    println!("{registry}={mirror}");
                }
            }
        }
        ArtifactMirrorCommand::Set { env, spec } => {
            let Some((registry, mirror)) = spec.split_once('=') else {
                bail!("expected <registry>=<mirror>, got {spec:?}");
            };
            println!(
                "{}",
                plan::set_artifact_mirror(ctx, &env, registry, mirror).await?
            );
        }
        ArtifactMirrorCommand::Clear { env, registry } => {
            println!(
                "{}",
                plan::clear_artifact_mirror(ctx, &env, &registry).await?
            );
        }
    }
    Ok(())
}

pub(crate) async fn cluster_config(
    ctx: &mut client::Ctx,
    command: ClusterConfigCommand,
) -> Result<()> {
    match command {
        ClusterConfigCommand::Show { env } => match plan::cluster_config_path(ctx, &env).await? {
            Some(path) => println!("{}", path.display()),
            None => println!("{env} has no cluster_config_path"),
        },
        ClusterConfigCommand::Set { env, path } => {
            println!("{}", plan::set_cluster_config_path(ctx, &env, &path).await?);
        }
        ClusterConfigCommand::Clear { env } => {
            println!("{}", plan::clear_cluster_config_path(ctx, &env).await?);
        }
    }
    Ok(())
}
