//! `--target remote` registration and configuration of environments (#679).

use anyhow::{Result, bail};
use tenkai::environment_config::EnvironmentConfigChange as Change;

use crate::env_args::{
    ApprovalPolicyCommand, ConstraintsCommand, EnvCommand, FactsCommand, MaintenanceCommand,
    RemoteChange, RunnerAttestationCommand, WebhooksCommand,
};

/// The environment, change and fence of a configuration command, or `None`
/// when `command` is not one (lists and shows go elsewhere).
pub(crate) fn change(command: &EnvCommand) -> Option<Result<(&str, Change, &RemoteChange)>> {
    Some(match command {
        EnvCommand::Facts { command } => match command {
            FactsCommand::Set { env, spec, remote } => spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("expected <key>=<value>, got {spec:?}"))
                .map(|(key, value)| {
                    let change = Change::SetFact {
                        key: key.into(),
                        value: value.into(),
                    };
                    (env.as_str(), change, remote)
                }),
            FactsCommand::Clear { env, key, remote } => {
                Ok((env.as_str(), Change::ClearFact { key: key.clone() }, remote))
            }
            _ => return None,
        },
        EnvCommand::Constraints { command } => match command {
            ConstraintsCommand::Set {
                env,
                kind,
                name,
                value,
                remote,
            } => Ok((
                env.as_str(),
                Change::SetConstraint {
                    constraint: kind.clone(),
                    name: name.clone(),
                    value: value.clone(),
                },
                remote,
            )),
            ConstraintsCommand::Clear {
                env,
                kind,
                name,
                remote,
            } => Ok((
                env.as_str(),
                Change::ClearConstraint {
                    constraint: kind.clone(),
                    name: name.clone(),
                },
                remote,
            )),
            ConstraintsCommand::List { .. } => return None,
        },
        EnvCommand::Maintenance { command } => match command {
            MaintenanceCommand::Set {
                env,
                identity,
                timezone,
                weekdays,
                start,
                duration_minutes,
                remote,
            } => tenkai::maintenance::weekday_values(weekdays).map(|weekdays| {
                let change = Change::SetMaintenanceWindow {
                    name: identity.clone(),
                    timezone: timezone.clone(),
                    weekdays,
                    start: start.clone(),
                    duration_minutes: *duration_minutes,
                };
                (env.as_str(), change, remote)
            }),
            MaintenanceCommand::Remove {
                env,
                identity,
                remote,
            } => Ok((
                env.as_str(),
                Change::RemoveMaintenanceWindow {
                    name: identity.clone(),
                },
                remote,
            )),
            _ => return None,
        },
        EnvCommand::Webhooks { command } => match command {
            WebhooksCommand::Set {
                env,
                url,
                secret_env,
                events,
                remote,
            } => crate::embedded_env_config::parse_webhook_events(events.as_deref()).map(
                |(events, operational)| {
                    let change = Change::SetWebhook {
                        url: url.clone(),
                        secret_env: secret_env.clone(),
                        events,
                        operational,
                    };
                    (env.as_str(), change, remote)
                },
            ),
            WebhooksCommand::Clear { env, url, remote } => Ok((
                env.as_str(),
                Change::ClearWebhooks { url: url.clone() },
                remote,
            )),
            WebhooksCommand::List { .. } => return None,
        },
        EnvCommand::ApprovalPolicy { command } => match command {
            ApprovalPolicyCommand::Set { env, path, remote } => {
                let change = Change::SetApprovalPolicy {
                    path: path.display().to_string(),
                };
                Ok((env.as_str(), change, remote))
            }
            ApprovalPolicyCommand::Clear { env, remote } => {
                Ok((env.as_str(), Change::ClearApprovalPolicy, remote))
            }
            ApprovalPolicyCommand::Show { .. } => return None,
        },
        EnvCommand::RunnerAttestation { command } => match command {
            RunnerAttestationCommand::Set {
                env,
                max_age_ms,
                require_hardware_key,
                remote,
            } => Ok((
                env.as_str(),
                Change::SetRunnerAttestation {
                    max_age_ms: *max_age_ms,
                    require_hardware_key: *require_hardware_key,
                },
                remote,
            )),
            RunnerAttestationCommand::Clear { env, remote } => {
                Ok((env.as_str(), Change::ClearRunnerAttestation, remote))
            }
            RunnerAttestationCommand::Show { .. } => return None,
        },
        _ => return None,
    })
}

/// Send the configuration change `command` names. Callers check [`change`] first.
pub(crate) async fn run(client: &tenkai_http::RemoteClient, command: &EnvCommand) -> Result<()> {
    let Some(planned) = change(command) else {
        bail!("this command is not an environment configuration change");
    };
    let (env, change, remote) = planned?;
    let (generation, reason) = require(remote)?;
    let result = client
        .configure_environment(env, change, reason, generation)
        .await?;
    println!("{}", result.message);
    Ok(())
}

/// `env add` with --target remote.
pub(crate) async fn register(
    client: &tenkai_http::RemoteClient,
    name: &str,
    description: &str,
    connectivity: Option<&str>,
    reason: Option<&str>,
) -> Result<()> {
    let reason =
        reason.ok_or_else(|| anyhow::anyhow!("--reason is required with --target remote"))?;
    let class = connectivity
        .map(tenkai::connectivity::ConnectivityClass::parse)
        .transpose()?;
    let result = client
        .register_environment(name, description, class, reason)
        .await?;
    println!("{}", result.message);
    Ok(())
}

fn require(remote: &RemoteChange) -> Result<(u64, &str)> {
    let generation = remote
        .generation
        .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
    let reason = remote
        .reason
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--reason is required with --target remote"))?;
    Ok((generation, reason))
}
