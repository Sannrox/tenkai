use anyhow::{Context as _, Result, bail};
use tenkai::plan;

use crate::args::{Cli, Command, OutputFormat};
use crate::client_config::{self, ClientConfig};
use crate::env_args::EnvCommand;
use crate::fleet_args::FleetCommand;
use crate::fleet_watch::{FleetWatchOptions, print_fleet_status, run_fleet_watch};
use crate::output::{print_history_page, print_machine_result, print_reconcile_report};

pub(crate) async fn run(
    mut cli: Cli,
    config: &ClientConfig,
    token_file_required: bool,
    unix_socket: Option<std::path::PathBuf>,
) -> Result<()> {
    let (client, watch_auth) = if let Some(socket) = unix_socket {
        #[cfg(unix)]
        {
            (tenkai_http::RemoteClient::unix_socket(&socket)?, None)
        }
        #[cfg(not(unix))]
        {
            let _ = socket;
            bail!("unix socket client requires a Unix host")
        }
    } else {
        let server_url = crate::login::require_server_url(cli.server_url.as_deref())?;
        let runtime = crate::login::LoginRuntime::from_env_with_token_file(
            cli.token_file.as_deref(),
            token_file_required,
        )?;
        let token = crate::login::bearer_token(&runtime, &server_url).await?;
        (
            tenkai_http::RemoteClient::new(&server_url, token)?,
            Some((runtime, server_url)),
        )
    };
    let output = cli.output;
    let fill_env = client_config::needs_env_resolution(&mut cli.command);
    if fill_env {
        let names = if config.default_environment.is_some() {
            Vec::new()
        } else {
            client
                .list_environments()
                .await?
                .into_iter()
                .map(|entry| entry.name)
                .collect()
        };
        client_config::apply_resolved_environment(&mut cli.command, config, &names)?;
    }
    match cli.command {
        Command::Reconcile {
            once: true, bypass, ..
        } => {
            if bypass.allow_unapproved_development || bypass.development_reason.is_some() {
                bail!(
                    "the local-development reconciliation bypass is available only with --target embedded"
                );
            }
            let report = client.reconcile().await?;
            let failures = report.failures();
            print_reconcile_report(report);
            if failures > 0 {
                bail!("{failures} environment(s) failed to reconcile");
            }
            Ok(())
        }
        Command::Reconcile { once: false, .. } => {
            bail!("remote servers reconcile continuously; use --once to request an immediate tick")
        }
        Command::Fleet {
            command: FleetCommand::Status,
        } => {
            let report = client.fleet_status().await?;
            if output == OutputFormat::JsonV1 {
                return print_machine_result(&crate::output::fleet_status_result(&report));
            }
            print_fleet_status(&report);
            Ok(())
        }
        Command::Fleet {
            command:
                FleetCommand::Watch {
                    interval,
                    once,
                    baseline,
                    write_baseline,
                    exit_on_any_posture_change,
                    exit_on_any_hard_drift,
                    json,
                    max_samples,
                },
        } => {
            run_fleet_watch(
                {
                    let unix_client = client.clone();
                    let watch_auth = watch_auth.clone();
                    move || {
                        let unix_client = unix_client.clone();
                        let watch_auth = watch_auth.clone();
                        async move {
                            match watch_auth {
                                Some((runtime, server_url)) => {
                                    // Refresh each sample so a saved OIDC access token
                                    // can expire during watch.
                                    let token =
                                        crate::login::bearer_token(&runtime, &server_url).await?;
                                    let client =
                                        tenkai_http::RemoteClient::new(&server_url, token)?;
                                    client.fleet_status().await
                                }
                                None => unix_client.fleet_status().await,
                            }
                        }
                    }
                },
                FleetWatchOptions {
                    interval,
                    once,
                    baseline,
                    write_baseline,
                    exit_on_any_posture_change,
                    exit_on_any_hard_drift,
                    json,
                    max_samples,
                },
            )
            .await?;
            Ok(())
        }
        Command::Env {
            command: EnvCommand::List,
        } => {
            let entries = client.list_environments().await?;
            if output == OutputFormat::JsonV1 {
                return print_machine_result(&crate::output::list_environments_result(
                    entries.len(),
                ));
            }
            if entries.is_empty() {
                println!("no environments registered");
            } else {
                println!(
                    "{:<20} {:<8} {:<10} {:<6} {:<6} description",
                    "name", "subs", "deployed", "lease", "hold"
                );
                for entry in entries {
                    let lease = if entry.lease_held { "held" } else { "-" };
                    let hold = if entry.delivery_held { "hold" } else { "-" };
                    println!(
                        "{:<20} {:<8} {:<10} {:<6} {:<6} {}",
                        entry.name,
                        entry.subscription_count,
                        entry.deployed_product_count,
                        lease,
                        hold,
                        entry.description
                    );
                }
            }
            Ok(())
        }
        Command::Env {
            command: EnvCommand::Inspect { env },
        } => {
            let report = client.inspect_environment(&env).await?;
            if output == OutputFormat::JsonV1 {
                return print_machine_result(&crate::output::inspect_result(&report));
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::Env {
            command:
                EnvCommand::History {
                    env,
                    product,
                    limit,
                    cursor,
                },
        } => {
            let page = client
                .environment_history(
                    &env,
                    &tenkai::deployment_history::DeploymentHistoryQuery {
                        limit,
                        cursor,
                        product,
                    },
                )
                .await?;
            if output == OutputFormat::JsonV1 {
                // The machine form is the history page, not a command-result envelope.
                println!("{}", serde_json::to_string_pretty(&page)?);
            } else {
                print_history_page(&page);
            }
            Ok(())
        }
        Command::Env {
            command: EnvCommand::Dependencies { env, format },
        } => {
            let view = client.environment_dependencies(&env).await?;
            match format {
                crate::env_args::DependencyFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&view)?)
                }
                crate::env_args::DependencyFormat::Dot => println!("{}", view.to_dot()),
                crate::env_args::DependencyFormat::Text => println!("{}", view.to_text()),
            }
            Ok(())
        }
        Command::Env {
            command:
                EnvCommand::Hold {
                    env,
                    generation,
                    action,
                },
        } => {
            crate::remote_hold::environment(&client, &env, generation, action).await?;
            Ok(())
        }
        Command::Env {
            command:
                EnvCommand::Retry {
                    env,
                    product,
                    reason,
                    generation,
                },
        } => {
            crate::remote_hold::retry(&client, &env, &product, &reason, generation).await?;
            Ok(())
        }
        Command::Channel {
            command:
                crate::catalog_args::ChannelCommand::Hold {
                    product,
                    channel,
                    action,
                },
        } => {
            crate::remote_hold::channel(&client, &product, &channel, action).await?;
            Ok(())
        }
        Command::Channel {
            command:
                crate::catalog_args::ChannelCommand::Remove {
                    product,
                    channel,
                    expected_head,
                },
        } => {
            let result = client
                .remove_channel_head(&product, &channel, expected_head.as_deref())
                .await?;
            println!("{}", result.message);
            Ok(())
        }
        Command::Channel {
            command: crate::catalog_args::ChannelCommand::Policy { .. },
        } => anyhow::bail!("channel policy is available only with --target embedded"),
        Command::Env {
            command:
                EnvCommand::Add {
                    name,
                    description,
                    connectivity,
                    reason,
                },
        } => {
            crate::remote_env_config::register(
                &client,
                &name,
                &description,
                connectivity.as_deref(),
                reason.as_deref(),
            )
            .await
        }
        Command::Env { command } if crate::remote_env_config::change(&command).is_some() => {
            crate::remote_env_config::run(&client, &command).await
        }
        Command::Env {
            command:
                EnvCommand::ApprovalPolicy {
                    command: crate::env_args::ApprovalPolicyCommand::Show { env },
                },
        } => {
            let view = client.environment_approval_policy(&env).await?;
            println!("{}", serde_json::to_string_pretty(&view)?);
            Ok(())
        }
        Command::Env {
            command: EnvCommand::Compatibility { command },
        } => {
            match command {
                crate::env_args::CompatibilityCommand::Record { env, evidence } => {
                    let evidence = serde_json::from_slice(&std::fs::read(evidence)?)?;
                    client
                        .record_software_compatibility_evidence(&env, &evidence)
                        .await?;
                    println!("recorded software compatibility evidence for {env}");
                }
                crate::env_args::CompatibilityCommand::Check { env, release } => {
                    crate::embedded_env_config::print_compatibility_report(
                        client
                            .software_compatibility_outcome(&env, &release)
                            .await?,
                    )?;
                }
            }
            Ok(())
        }
        Command::Status { env } => {
            let env = crate::client_config::require_env(env)?;
            let rows = client.environment_status(&env).await?;
            if output == OutputFormat::JsonV1 {
                return print_machine_result(&crate::output::status_result(&env, rows.len()));
            }
            if let Ok(report) = client.inspect_environment(&env).await {
                if let Some(hold) = report.delivery_hold {
                    println!(
                        "{env} held at {} by {}: {}",
                        hold.held_at, hold.actor, hold.reason
                    );
                }
                if let Some(issuer) = report.identity_issuer {
                    println!(
                        "{}",
                        crate::output::issuer_line(&env, &issuer, &report.identity_issuer_waiting)
                    );
                }
            }
            if rows.is_empty() {
                println!("{env} has no channel subscriptions");
            } else {
                println!(
                    "{:<24} {:<10} {:<12} {:<12} state",
                    "product", "channel", "deployed", "head"
                );
                for r in rows {
                    let deployed = r.deployed.clone().unwrap_or_else(|| "-".into());
                    let state = plan::status_state(&r);
                    println!(
                        "{:<24} {:<10} {:<12} {:<12} {state}",
                        r.product, r.channel, deployed, r.head
                    );
                    if let Some(hold) = &r.dependency_hold {
                        let waiting = hold
                            .contracts
                            .iter()
                            .map(|c| format!("{} >= {}", c.contract, c.minimum))
                            .collect::<Vec<_>>()
                            .join(", ");
                        println!("  waiting on {waiting}");
                    }
                    if let Some(hold) = &r.delivery_hold {
                        println!(
                            "  channel hold at {} by {}: {}",
                            hold.held_at, hold.actor, hold.reason
                        );
                    }
                    if let Some(drift) = &r.spec_drift {
                        crate::output::print_spec_drift(drift);
                    }
                    if let Some(line) = r
                        .certificate
                        .as_ref()
                        .and_then(crate::output::certificate_line)
                    {
                        println!("{line}");
                    }
                }
            }
            Ok(())
        }
        Command::Migrate { command } => {
            crate::remote_delivery::run_migrate(&client, command).await?;
            Ok(())
        }
        Command::Runtime { command } => match command {
            crate::args::RuntimeCommand::Enroll { env, ttl_seconds } => {
                let issued = client
                    .create_runtime_enrollment(
                        &env,
                        &tenkai::management_operations::RuntimeEnrollmentRequest { ttl_seconds },
                    )
                    .await?;
                println!(
                    "enrollment token for {} (single use, expires at {}):",
                    issued.environment, issued.expires_at
                );
                println!("{}", issued.token);
                Ok(())
            }
            crate::args::RuntimeCommand::List => {
                for runner in client.list_runtime_runners().await?.runners {
                    let seen = runner
                        .instances
                        .first()
                        .and_then(|instance| {
                            instance
                                .last_work_at
                                .max(instance.last_heartbeat_at)
                                .max(instance.last_inventory_at)
                        })
                        .map_or("-".to_string(), |at| at.to_string());
                    println!(
                        "{} {} {} instances={} last_seen={}",
                        runner.id,
                        runner.environment,
                        runner.state,
                        runner.instances.len(),
                        seen
                    );
                }
                Ok(())
            }
            crate::args::RuntimeCommand::Inspect { runner_id } => {
                let runner = client.inspect_runtime_runner(&runner_id).await?;
                println!("{}", serde_json::to_string_pretty(&runner)?);
                Ok(())
            }
            crate::args::RuntimeCommand::Revoke {
                credential_id,
                reason,
            } => {
                let revoked = client
                    .revoke_runtime_credential(&credential_id, &reason)
                    .await?;
                println!(
                    "revoked runtime credential {} of {} at {}",
                    revoked.credential_id, revoked.environment, revoked.revoked_at
                );
                if !revoked.unopenable.is_empty() {
                    println!("no recipient can open these sealed values any more; set them again:");
                    for value in &revoked.unopenable {
                        println!("  {value}");
                    }
                }
                Ok(())
            }
        },
        Command::IdentityIssuer { command } => {
            let result = match command {
                crate::args::IdentityIssuerCommand::Prepare { env, generation } => {
                    client.prepare_identity_issuer(&env, generation).await?
                }
                crate::args::IdentityIssuerCommand::Plan { env, generation } => {
                    client.plan_identity_issuer(&env, generation).await?
                }
                crate::args::IdentityIssuerCommand::Rewrap {
                    env,
                    recipient,
                    generation,
                } => {
                    client
                        .rewrap_identity_issuer(&env, &recipient, generation)
                        .await?
                }
            };
            crate::secret::print_plan(&result);
            Ok(())
        }
        Command::Secret { command } => match command {
            crate::args::SecretCommand::Trust { env, fingerprint } => {
                crate::secret::require_fingerprint(&fingerprint)?;
                crate::secret::trust(cli.server_url.as_deref(), &env, &fingerprint)
            }
            crate::args::SecretCommand::Recipients { env } => {
                let offered = client.list_environment_recipients(&env).await?;
                crate::secret::show_recipients(cli.server_url.as_deref(), &env, offered.recipients)
            }
            crate::args::SecretCommand::Set {
                env,
                instance,
                secret,
                remote,
            } => {
                crate::secret::set(
                    &client,
                    cli.server_url.as_deref(),
                    (&env, &instance, &secret),
                    &remote,
                )
                .await
            }
            crate::args::SecretCommand::List { env } => {
                crate::secret::print_list(&client.list_sealed_secrets(&env, false).await?);
                Ok(())
            }
            crate::args::SecretCommand::Rewrap {
                env,
                recipient,
                generation,
            } => {
                let result = client
                    .rewrap_sealed_secrets(&env, &recipient, generation, Default::default())
                    .await?;
                crate::secret::print_plan(&result);
                Ok(())
            }
            crate::args::SecretCommand::RecoveryKey { command } => match command {
                crate::args::RecoveryKeyCommand::Generate { path } => {
                    crate::secret::generate_recovery_key(&path)
                }
                crate::args::RecoveryKeyCommand::Set {
                    env,
                    public_key,
                    remote,
                } => {
                    let (generation, reason) = crate::remote_env_config::require(&remote)?;
                    let change =
                        tenkai::environment_config::EnvironmentConfigChange::SetSealedRecoveryKey {
                            public_key,
                        };
                    let result = client
                        .configure_environment(&env, change, reason, generation)
                        .await?;
                    println!("{}", result.message);
                    Ok(())
                }
            },
            crate::args::SecretCommand::Recover {
                env,
                key,
                recipient,
                generation,
            } => {
                crate::secret::recover(
                    &client,
                    cli.server_url.as_deref(),
                    &env,
                    &key,
                    &recipient,
                    generation,
                )
                .await
            }
            crate::args::SecretCommand::Delete {
                env,
                instance,
                secret,
                present_in_target,
                remote,
            } => {
                let secret = tenkai::sealed_secret::SecretRef::parse(&secret)?;
                let (generation, reason) = crate::remote_env_config::require(&remote)?;
                let change =
                    tenkai::environment_config::EnvironmentConfigChange::DeleteSealedSecret {
                        instance,
                        secret: secret.secret,
                        key: secret.key,
                        present_in_target,
                    };
                let result = client
                    .configure_environment(&env, change, reason, generation)
                    .await?;
                println!("{}", result.message);
                Ok(())
            }
        },
        Command::Exposure { command } => match command {
            crate::args::ExposureCommand::Import { .. } => {
                bail!(
                    "advisory feed import over remote uses POST /v1/imports; feed-only import is --target embedded"
                )
            }
            crate::args::ExposureCommand::Inspect => {
                let status = client.inspect_advisory_feed().await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            crate::args::ExposureCommand::Query {
                component,
                range,
                min_criticality,
            } => {
                let min_criticality = min_criticality
                    .as_deref()
                    .map(tenkai::criticality::CriticalityLevel::parse)
                    .transpose()?;
                let result = client
                    .query_exposures(&component, &range, min_criticality)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                Ok(())
            }
        },
        Command::Criticality { command } => match command {
            crate::args::DerivedCriticalityCommand::Import { envelope, .. } => {
                // Send the file's bytes as they are; the server parses them by schema.
                let raw = std::fs::read(&envelope).with_context(|| {
                    format!("reading derived criticality {}", envelope.display())
                })?;
                tenkai::criticality::parse_envelope(&raw).with_context(|| {
                    format!("parsing derived criticality {}", envelope.display())
                })?;
                let result = client.import_derived_criticality(raw).await?;
                println!(
                    "imported {} derived criticality assignment(s)",
                    result.applied
                );
                Ok(())
            }
        },
        Command::Product {
            command: crate::product_args::ProductCommand::Criticality { command },
        } => match command {
            crate::product_args::ProductCriticalityCommand::Show { product } => {
                let view = client.inspect_product_criticality(&product).await?;
                if view.is_empty() {
                    println!("product {product} has no criticality");
                } else {
                    println!("{}", serde_json::to_string_pretty(&view)?);
                }
                Ok(())
            }
            crate::product_args::ProductCriticalityCommand::Set {
                product,
                level,
                owner,
                reason,
            } => {
                let view = client
                    .set_product_criticality(
                        &product,
                        &tenkai::criticality::SetCriticalityRequest {
                            level: tenkai::criticality::CriticalityLevel::parse(&level)?,
                            owner,
                            reason,
                        },
                    )
                    .await?;
                println!("{}", serde_json::to_string_pretty(&view)?);
                Ok(())
            }
            crate::product_args::ProductCriticalityCommand::Clear { product } => {
                let view = client.clear_product_criticality(&product).await?;
                println!("{}", serde_json::to_string_pretty(&view)?);
                Ok(())
            }
        },
        Command::Env {
            command:
                EnvCommand::Criticality {
                    command: crate::env_args::CriticalityCommand::Show { env },
                },
        } => {
            let report = client.inspect_environment(&env).await?;
            match report.criticality {
                Some(view) => println!("{}", serde_json::to_string_pretty(&view)?),
                None => println!("{env} has no criticality"),
            }
            Ok(())
        }
        Command::Bundle { .. } => {
            bail!("bundle build is available only with --target embedded")
        }
        Command::Train { .. } => {
            bail!("release trains are available only with --target embedded")
        }
        Command::DarkSite { .. } => {
            bail!("dark-site profiles run locally; use --target embedded")
        }
        Command::SpokeStandby { .. } => {
            bail!("spoke-standby profiles run locally; use --target embedded")
        }
        Command::Topology { .. } => {
            bail!("topology drills run against the embedded store; use --target embedded")
        }
        Command::Remediate { .. } => {
            bail!(
                "remediate propose and notice import run against the embedded store; use --target embedded"
            )
        }
        other => crate::remote_catalog::run(&client, other, output).await,
    }
}
