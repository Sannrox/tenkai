use anyhow::{Result, bail};
use tenkai::{client, inventory, maintenance, plan};

use crate::env_args::{
    ApprovalPolicyCommand, ArtifactMirrorCommand, ClusterConfigCommand, ConstraintsCommand,
    DockerSecretsCommand, FactsCommand, MaintenanceCommand, OverlayCommand,
    RunnerAttestationCommand, WebhooksCommand,
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
            ..
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
        MaintenanceCommand::Remove { env, identity, .. } => {
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
        FactsCommand::Set { env, spec, .. } => {
            let Some((key, value)) = spec.split_once('=') else {
                bail!("expected <key>=<value>, got {spec:?}");
            };
            println!(
                "{}",
                plan::set_environment_fact(ctx, &env, key, value).await?
            );
        }
        FactsCommand::Clear { env, key, .. } => {
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
            ..
        } => {
            println!(
                "{}",
                plan::set_environment_constraint(ctx, &env, &kind, &name, &value).await?
            );
        }
        ConstraintsCommand::Clear {
            env, kind, name, ..
        } => {
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

pub(crate) async fn docker_secrets(
    ctx: &mut client::Ctx,
    command: DockerSecretsCommand,
) -> Result<()> {
    match command {
        DockerSecretsCommand::Show { env } => match plan::docker_secret_dir(ctx, &env).await? {
            Some(path) => println!("{}", path.display()),
            None => println!("{env} has no docker_secret_dir"),
        },
        DockerSecretsCommand::Set { env, path } => {
            println!("{}", plan::set_docker_secret_dir(ctx, &env, &path).await?);
        }
        DockerSecretsCommand::Clear { env } => {
            println!("{}", plan::clear_docker_secret_dir(ctx, &env).await?);
        }
    }
    Ok(())
}

pub(crate) async fn webhooks(ctx: &mut client::Ctx, command: WebhooksCommand) -> Result<()> {
    match command {
        WebhooksCommand::List { env } => {
            let endpoints = tenkai::deploy_webhook::list_environment_webhooks(ctx, &env).await?;
            if endpoints.is_empty() {
                println!("{env} has no webhooks");
                return Ok(());
            }
            for endpoint in endpoints {
                let events = if endpoint.events.is_empty() {
                    "apply.succeeded,apply.failed,apply.rolled_back".into()
                } else {
                    endpoint
                        .events
                        .iter()
                        .map(|event| event.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                };
                println!(
                    "{} secret_env={} events={}",
                    endpoint.url, endpoint.secret_env, events
                );
            }
        }
        WebhooksCommand::Set {
            env,
            url,
            secret_env,
            events,
            ..
        } => {
            let (events, operational) = parse_webhook_events(events.as_deref())?;
            println!(
                "{}",
                tenkai::deploy_webhook::set_environment_webhook(
                    ctx,
                    &env,
                    tenkai::deploy_webhook::WebhookEndpoint {
                        url,
                        secret_env,
                        events,
                        operational,
                    },
                )
                .await?
            );
        }
        WebhooksCommand::Clear { env, url, .. } => {
            println!(
                "{}",
                tenkai::deploy_webhook::clear_environment_webhooks(ctx, &env, url.as_deref())
                    .await?
            );
        }
    }
    Ok(())
}

/// `--events` split into apply outcomes and operational events, which an
/// endpoint stores in separate fields.
pub(crate) fn parse_webhook_events(
    raw: Option<&str>,
) -> Result<(
    Vec<tenkai::deploy_webhook::WebhookEvent>,
    Vec<tenkai::deploy_webhook::OperationalEvent>,
)> {
    let Some(raw) = raw else {
        return Ok((Vec::new(), Vec::new()));
    };
    let (mut events, mut operational) = (Vec::new(), Vec::new());
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part {
            "apply.succeeded" => events.push(tenkai::deploy_webhook::WebhookEvent::ApplySucceeded),
            "apply.failed" => events.push(tenkai::deploy_webhook::WebhookEvent::ApplyFailed),
            "apply.rolled_back" => {
                events.push(tenkai::deploy_webhook::WebhookEvent::ApplyRolledBack)
            }
            other => match tenkai::deploy_webhook::OperationalEvent::parse(other) {
                Some(event) => operational.push(event),
                None => bail!("unknown webhook event {other:?}"),
            },
        }
    }
    Ok((events, operational))
}

pub(crate) async fn runner_attestation(
    ctx: &mut client::Ctx,
    command: RunnerAttestationCommand,
) -> Result<()> {
    use tenkai::runner_attestation as attestation;
    match command {
        RunnerAttestationCommand::Show { env } => match attestation::policy(ctx, &env).await? {
            Some(policy) => println!("{}", serde_json::to_string_pretty(&policy)?),
            None => println!("{env} does not require runner attestation"),
        },
        RunnerAttestationCommand::Set {
            env,
            max_age_ms,
            require_hardware_key,
            ..
        } => println!(
            "{}",
            attestation::set_policy(ctx, &env, max_age_ms, require_hardware_key).await?
        ),
        RunnerAttestationCommand::Clear { env, .. } => {
            println!("{}", attestation::clear_policy(ctx, &env).await?)
        }
    }
    Ok(())
}

pub(crate) async fn approval_policy(
    ctx: &mut client::Ctx,
    command: ApprovalPolicyCommand,
) -> Result<()> {
    match command {
        ApprovalPolicyCommand::Show { env } => match plan::plan_approval_policy(ctx, &env).await? {
            Some(path) => println!("{}", path.display()),
            None => println!("{env} has no plan_approval_policy"),
        },
        ApprovalPolicyCommand::Set { env, path, .. } => {
            println!(
                "{}",
                plan::set_plan_approval_policy(ctx, &env, &path).await?
            );
        }
        ApprovalPolicyCommand::Clear { env, .. } => {
            println!("{}", plan::clear_plan_approval_policy(ctx, &env).await?);
        }
    }
    Ok(())
}

pub(crate) async fn compatibility(
    ctx: &mut client::Ctx,
    command: crate::env_args::CompatibilityCommand,
) -> Result<()> {
    match command {
        crate::env_args::CompatibilityCommand::Record { env, evidence } => {
            let evidence = serde_json::from_slice(&std::fs::read(evidence)?)?;
            tenkai::software_compatibility::record_evidence(ctx, &env, evidence).await?;
            println!("recorded software compatibility evidence for {env}");
        }
        crate::env_args::CompatibilityCommand::Check { env, release } => {
            let report = tenkai::software_compatibility::report(ctx, &env, &release).await?;
            print_compatibility_report(report)?;
        }
    }
    Ok(())
}

pub(crate) fn print_compatibility_report(
    report: Option<tenkai::software_compatibility::CompatibilityReport>,
) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.is_some_and(|report| !report.failures.is_empty()) {
        bail!("software compatibility blocked");
    }
    Ok(())
}
