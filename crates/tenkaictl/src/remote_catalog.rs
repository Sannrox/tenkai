use anyhow::{Result, bail};
use tenkai::command_result::{CommandName, CommandOutcome, CommandResultV1, RetryGuidance};

use crate::args::{Command, OutputFormat};
use crate::catalog_args::{
    ApprovalCommand, EvalEvidenceCommand, ReleaseCommand, ReleaseLabelsCommand,
};
use crate::env_args::EnvCommand;
use crate::output::{print_machine_result, reported_machine_failure, with_remote_resources};

pub(crate) async fn run(
    client: &tenkai_http::RemoteClient,
    command: Command,
    output: OutputFormat,
) -> Result<()> {
    let machine = output == OutputFormat::JsonV1;
    match command {
        Command::Publish {
            manifest,
            signature,
            trust_roots,
            allow_unsigned_development,
            provenance,
            provenance_trust_roots,
            change_set_evidence,
            family_release,
            family_release_signature: _,
        } => {
            if allow_unsigned_development
                || !provenance.is_empty()
                || provenance_trust_roots.is_some()
                || change_set_evidence.is_some()
                || family_release.is_some()
            {
                bail!(
                    "the local-development publish bypass and extra publication evidence are available only with --target embedded"
                );
            }
            let signature = signature
                .ok_or_else(|| anyhow::anyhow!("--signature is required with --target remote"))?;
            let trust_roots = trust_roots
                .ok_or_else(|| anyhow::anyhow!("--trust-roots is required with --target remote"))?;
            let request = tenkai::management_lifecycle::load_publish_request(
                &manifest,
                &signature,
                &trust_roots,
            )?;
            // Older v1 servers omit the release id; name it before the mutation runs.
            let manifest = tenkai::manifest::parse_raw(&request.manifest)?;
            let release_spec = format!("{}@{}", manifest.product.name, manifest.product.version);
            let result = client.publish_release(&request).await?;
            if machine {
                let release = result.resource.unwrap_or(release_spec);
                return print_machine_result(
                    &CommandResultV1::succeeded(CommandName::Publish).resource("release", release),
                );
            }
            println!("{}", result.message);
            Ok(())
        }
        Command::EvalEvidence { command } => {
            match command {
                EvalEvidenceCommand::Trust { trust_roots } => {
                    let roots = tenkai::release_signing::TrustRoots::load(
                        &trust_roots,
                        tenkai::release_signing::TrustRootKind::ModelEvaluation,
                    )?;
                    client.install_model_evaluation_trust(&roots).await?;
                    println!(
                        "installed model evaluation trust roots ({} signer{})",
                        roots.signers.len(),
                        if roots.signers.len() == 1 { "" } else { "s" }
                    );
                }
                EvalEvidenceCommand::Record { evidence } => {
                    let evidence =
                        tenkai::model_release_evidence::ModelEvaluationEvidence::load(&evidence)?;
                    client.record_model_evaluation_evidence(&evidence).await?;
                    println!(
                        "recorded model evaluation evidence for {}/{} run {}",
                        evidence.identity.provider, evidence.identity.model, evidence.eval_run_id
                    );
                }
            }
            Ok(())
        }
        Command::Promote {
            spec,
            channel,
            expected_head,
        } => {
            let result = client
                .promote_release_expecting(&spec, &channel, expected_head.as_deref())
                .await?;
            if machine {
                return print_machine_result(&crate::output::promote_result(&spec, &channel));
            }
            println!("{}", result.message);
            Ok(())
        }
        Command::Release {
            command:
                ReleaseCommand::Recall {
                    spec,
                    from,
                    before,
                    close,
                    reason,
                },
        } => {
            let result = if let Some(from) = close {
                let before =
                    before.ok_or_else(|| anyhow::anyhow!("--before is required with --close"))?;
                client.close_recall_range(&spec, &from, &before).await?
            } else if let Some(from) = from {
                let reason =
                    reason.ok_or_else(|| anyhow::anyhow!("--reason is required with --from"))?;
                client
                    .record_recall_range(&spec, &from, before.as_deref(), &reason)
                    .await?
            } else {
                if before.is_some() {
                    anyhow::bail!("--before requires --from or --close");
                }
                client.recall_release(&spec).await?
            };
            if machine {
                return print_machine_result(
                    &CommandResultV1::succeeded(CommandName::Recall).resource("release", spec),
                );
            }
            println!("{}", result.message);
            Ok(())
        }
        Command::Release {
            command: ReleaseCommand::Labels { command },
        } => {
            match command {
                ReleaseLabelsCommand::List { spec } => {
                    let (product, version) = split_release_spec(&spec)?;
                    let labels = client.list_release_labels(product, version).await?;
                    if labels.is_empty() {
                        println!("{spec} has no labels");
                    } else {
                        for (key, value) in labels {
                            println!("{key}={value}");
                        }
                    }
                }
                ReleaseLabelsCommand::Set { spec, pair, reason } => {
                    let reason = reason.ok_or_else(|| {
                        anyhow::anyhow!("--reason is required with --target remote")
                    })?;
                    let (product, version) = split_release_spec(&spec)?;
                    let (key, value) = tenkai::labels::parse_label_pair(&pair)?;
                    let result = client
                        .set_release_label(product, version, &key, &value, &reason)
                        .await?;
                    println!("{}", result.message);
                }
                ReleaseLabelsCommand::Clear { spec, key, reason } => {
                    let reason = reason.ok_or_else(|| {
                        anyhow::anyhow!("--reason is required with --target remote")
                    })?;
                    let (product, version) = split_release_spec(&spec)?;
                    let result = client
                        .clear_release_label(product, version, &key, &reason)
                        .await?;
                    println!("{}", result.message);
                }
            }
            Ok(())
        }
        Command::Env {
            command:
                EnvCommand::Unsubscribe {
                    env,
                    product,
                    instance,
                    version,
                    generation,
                },
        } => {
            let generation = generation
                .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
            let result = client
                .unsubscribe_environment(
                    &env,
                    &product,
                    generation,
                    instance.as_deref(),
                    version.as_deref(),
                )
                .await?;
            println!("{}", result.message);
            Ok(())
        }
        Command::Env {
            command:
                EnvCommand::Subscribe {
                    env,
                    spec,
                    instance,
                    generation,
                },
        } => {
            let generation = generation
                .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
            let result = client
                .subscribe_environment(&env, &spec, generation, instance.as_deref())
                .await
                .map_err(|error| {
                    with_remote_resources(
                        error,
                        output,
                        CommandName::Subscribe,
                        &[("environment", &env), ("subscription", &spec)],
                    )
                })?;
            if machine {
                return print_machine_result(&crate::output::subscribe_result(&env, &spec));
            }
            println!("{}", result.message);
            Ok(())
        }
        Command::Env {
            command: EnvCommand::Retire { env, reason },
        } => {
            let result = client.retire_environment(&env, &reason).await?;
            println!("{}", result.message);
            Ok(())
        }
        Command::Plan {
            command: Some(crate::args::PlanCommand::Show { .. }),
            ..
        } => {
            anyhow::bail!("plan show is available with --target embedded")
        }
        Command::Plan {
            env,
            generation,
            command: None,
        } => {
            let env = crate::client_config::require_env(env)?;
            let generation = generation
                .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
            let result = client
                .plan_environment(&env, generation)
                .await
                .map_err(|error| {
                    with_remote_resources(
                        error,
                        output,
                        CommandName::Plan,
                        &[("environment", &env)],
                    )
                })?;
            if machine {
                return print_machine_result(&remote_plan_result(
                    CommandResultV1::succeeded(CommandName::Plan),
                    &result,
                    &env,
                    generation,
                )?);
            }
            println!("{}", result.message);
            if let Some(plan_id) = &result.resource {
                println!("plan id: {plan_id}");
            }
            if let Some(digest) = &result.digest {
                println!("plan digest: {digest}");
            }
            Ok(())
        }
        Command::Approval {
            command:
                ApprovalCommand::Submit {
                    plan_id,
                    env,
                    approval,
                    approval_trust_roots,
                    generation,
                },
        } => {
            let env = crate::client_config::require_env(env)?;
            let generation = generation
                .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
            let request = tenkai::management_lifecycle::load_approve_request(
                &env,
                generation,
                &approval,
                &approval_trust_roots,
            )?;
            let result = client
                .approve_plan(&plan_id, &request)
                .await
                .map_err(|error| {
                    with_remote_resources(
                        error,
                        output,
                        CommandName::Approve,
                        &[("plan", &plan_id), ("environment", &env)],
                    )
                })?;
            if machine {
                return print_machine_result(&crate::output::approve_result(&plan_id, &env));
            }
            println!("{}", result.message);
            Ok(())
        }
        other => crate::remote_delivery::run(client, other, output).await,
    }
}

fn split_release_spec(spec: &str) -> Result<(&str, &str)> {
    spec.split_once('@')
        .ok_or_else(|| anyhow::anyhow!("expected <product>@<version>, got {spec:?}"))
}

/// Add the plan a remote mutation created to `result`. Beyond the embedded
/// `plan` and `environment` resources, remote results carry the target-only
/// `plan_digest` and the `generation` that `approval submit` and `apply` need.
pub(crate) fn remote_plan_result(
    result: CommandResultV1,
    response: &tenkai::management_lifecycle::ManagementLifecycleResult,
    environment: &str,
    generation: u64,
) -> Result<CommandResultV1> {
    let Some(plan_id) = response.resource.as_deref() else {
        // The server acted but did not name the plan: the outcome is unknown.
        let mut unknown = CommandResultV1::failed(
            result.command,
            "incomplete_response",
            "The server accepted the request but did not report the plan",
            RetryGuidance::ReconcileBeforeRetry,
        )
        .resource("environment", environment);
        unknown.outcome = CommandOutcome::Unknown;
        return Err(reported_machine_failure(unknown));
    };
    let mut result = result
        .resource("plan", plan_id)
        .resource("environment", environment);
    if let Some(digest) = &response.digest {
        result = result.resource("plan_digest", digest);
    }
    Ok(result.resource("generation", generation.to_string()))
}
