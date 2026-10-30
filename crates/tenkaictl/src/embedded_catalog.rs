use anyhow::{Result, bail};
use tenkai::command_result::{CommandName, CommandResultV1};
use tenkai::{canary, catalog, client, maintenance, ontology, plan};

use crate::args::{Command, ExposureCommand, OutputFormat};
use crate::authorization::embedded_management_actor;
use crate::catalog_args::{ApprovalCommand, CanaryCommand, EvalEvidenceCommand, ReleaseCommand};
use crate::output::print_machine_result;

pub(crate) async fn run(
    ctx: &mut client::Ctx,
    command: Command,
    output: OutputFormat,
) -> Result<()> {
    match command {
        Command::Init => {
            let registered = ontology::register(ctx).await?;
            if registered.is_empty() {
                println!("schema already registered");
            } else {
                println!("registered schema types: {}", registered.join(", "));
            }
            println!("{}", plan::env_add(ctx, "local", "this machine").await?);
            let migrated = maintenance::migrate_all(ctx).await?;
            println!("maintenance configuration ready for {migrated} environment(s)");
        }
        Command::Publish {
            manifest,
            signature,
            trust_roots,
            allow_unsigned_development,
            provenance,
            provenance_trust_roots,
            change_set_evidence,
        } => {
            let options = catalog::PublishOptions {
                signature,
                trust_roots,
                allow_unsigned_development,
                provenance,
                provenance_trust_roots,
                change_set_evidence: change_set_evidence
                    .map(tenkai::change_set_pin::ChangeSetEvidenceInput::File),
                artifact_registry: tenkai::oci_artifact::selected_registry().ok().flatten(),
                state_dir: None,
            };
            if output == OutputFormat::JsonV1 {
                let published = catalog::publish_with_result(ctx, &manifest, &options).await?;
                let mut result = CommandResultV1::succeeded(CommandName::Publish)
                    .resource("release", published.release);
                for digest in published.provenance_digests {
                    result = result.resource("release_provenance", digest);
                }
                print_machine_result(&result)?;
            } else {
                println!("{}", catalog::publish(ctx, &manifest, &options).await?);
            }
        }
        Command::Release { command } => match command {
            ReleaseCommand::Inspect { spec } => {
                let evidence = catalog::inspect_release(ctx, &spec).await?;
                println!("{}", serde_json::to_string_pretty(&evidence)?);
            }
            ReleaseCommand::Verify { spec, trust_roots } => {
                let evidence = catalog::reverify_release(ctx, &spec, &trust_roots).await?;
                println!("{}", serde_json::to_string_pretty(&evidence)?);
            }
            ReleaseCommand::Recall { spec } => {
                let actor = embedded_management_actor()?;
                let message = catalog::recall(ctx, &actor, &spec).await?;
                if output == OutputFormat::JsonV1 {
                    print_machine_result(
                        &CommandResultV1::succeeded(CommandName::Recall).resource("release", spec),
                    )?;
                } else {
                    println!("{message}");
                }
            }
        },
        Command::Exposure { command } => match command {
            ExposureCommand::Import {
                bundle,
                trust_roots,
                env,
            } => {
                let envelope = tenkai::offline_bundle::BundleEnvelope::load(&bundle)?;
                let roots = tenkai::release_signing::TrustRoots::load(&trust_roots)?;
                let verified = tenkai::exposure::verify_envelope_for_import(
                    &envelope,
                    &roots,
                    &env,
                    tenkai::now_millis(),
                )?;
                let Some(status) =
                    tenkai::exposure::import_from_verified_bundle(ctx, &verified, &env).await?
                else {
                    bail!(
                        "bundle does not contain {}",
                        tenkai::exposure::ADVISORY_FEED_PATH
                    );
                };
                println!("{}", serde_json::to_string_pretty(&status)?);
            }
            ExposureCommand::Inspect => {
                let status = tenkai::exposure::inspect(ctx).await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
            }
            ExposureCommand::Query {
                component,
                range,
                min_criticality,
            } => {
                let min_criticality = min_criticality
                    .as_deref()
                    .map(tenkai::criticality::CriticalityLevel::parse)
                    .transpose()?;
                let result = tenkai::exposure::query_with(
                    ctx,
                    &tenkai::exposure::ExposureQueryRequest {
                        component,
                        range,
                        min_criticality,
                    },
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        },
        Command::Criticality { command } => match command {
            crate::args::DerivedCriticalityCommand::Import {
                envelope,
                trust_roots,
            } => {
                let envelope = tenkai::criticality::DerivedEnvelope::load(&envelope)?;
                let roots = tenkai::release_signing::TrustRoots::load(&trust_roots)?;
                let applied = tenkai::criticality_store::import_envelope(
                    ctx,
                    &envelope,
                    &roots,
                    tenkai::now_millis(),
                )
                .await?;
                println!("imported {applied} derived criticality assignment(s)");
            }
        },
        Command::Approval { command } => match command {
            ApprovalCommand::Submit {
                plan_id,
                env,
                approval,
                approval_trust_roots,
                generation: _,
            } => {
                let stored = plan::load(ctx, &plan_id).await?;
                if stored.environment != env {
                    bail!(
                        "approval environment {env} does not match plan {}",
                        stored.environment
                    );
                }
                // Collect always. Record only once the quorum is complete, and
                // then run the same live checks as execution (`require_preflight`,
                // automatic-signer, host auto-key).
                let now = tenkai::now_millis();
                let envelope = tenkai::plan_approval::load_envelopes(&approval)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing approval evidence"))?;
                let roots = tenkai::plan_approval::TrustRoots::load(&approval_trust_roots)?;
                tenkai::plan_approval::collect_envelope(ctx, &stored, &envelope, &roots, now)
                    .await?;
                let actor = crate::authorization::embedded_management_actor().ok();
                let requester = actor.as_ref().map(|actor| actor.principal_id());
                let skip_gates = envelope.statement.skip_gates;
                let view = tenkai::plan_approval::approvals_view(
                    ctx,
                    &stored,
                    Some(&roots),
                    now,
                    skip_gates,
                    requester,
                )
                .await?;
                let evidence = if view.missing == 0 {
                    let evidence = tenkai::plan_approval::verify_for_execution_named(
                        ctx,
                        &stored,
                        &approval,
                        &approval_trust_roots,
                        now,
                        skip_gates,
                        requester,
                    )
                    .await?;
                    tenkai::plan_approval::record(ctx, &evidence).await?;
                    evidence
                } else {
                    tenkai::plan_approval::verify_envelope(
                        &stored, &envelope, &roots, now, skip_gates,
                    )?
                };
                if output == OutputFormat::JsonV1 {
                    print_machine_result(&crate::output::approve_result(
                        &stored.id,
                        &stored.environment,
                    ))?;
                } else {
                    println!("recorded approval for {}", evidence.plan_id);
                    println!("plan digest: {}", evidence.plan_digest);
                }
            }
            ApprovalCommand::Inspect { plan_id } => {
                let mut evidence = ctx
                    .list_kind(ontology::KIND_PLAN_APPROVAL_VERIFICATION)
                    .await?
                    .into_iter()
                    .filter(|object| {
                        object
                            .properties
                            .get("plan_id")
                            .is_some_and(|id| id == &plan_id)
                    })
                    .filter_map(|object| object.properties.get("evidence").cloned())
                    .map(|raw| serde_json::from_str::<serde_json::Value>(&raw))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                evidence.sort_by_key(|item| {
                    item.get("verified_at").and_then(serde_json::Value::as_i64)
                });
                println!("{}", serde_json::to_string_pretty(&evidence)?);
            }
        },
        Command::EvalEvidence { command } => match command {
            EvalEvidenceCommand::Trust { trust_roots } => {
                let actor = embedded_management_actor()?;
                let roots =
                    tenkai::model_release_evidence::EvaluationTrustRoots::load(&trust_roots)?;
                tenkai::model_release_evidence::install_evaluation_trust_roots(ctx, &actor, &roots)
                    .await?;
                println!(
                    "installed model evaluation trust roots ({} signer{})",
                    roots.signers.len(),
                    if roots.signers.len() == 1 { "" } else { "s" }
                );
            }
            EvalEvidenceCommand::Record { evidence } => {
                let actor = embedded_management_actor()?;
                let evidence =
                    tenkai::model_release_evidence::ModelEvaluationEvidence::load(&evidence)?;
                tenkai::model_release_evidence::record_evaluation_evidence(
                    ctx,
                    &actor,
                    evidence.clone(),
                )
                .await?;
                println!(
                    "recorded model evaluation evidence for {}/{} run {}",
                    evidence.identity.provider, evidence.identity.model, evidence.eval_run_id
                );
            }
        },
        Command::Promote { spec, channel } => {
            if output == OutputFormat::JsonV1 {
                let product = spec.split_once('@').map_or(spec.as_str(), |value| value.0);
                tenkai::command_result::validate_resource_reference(
                    "channel",
                    &format!("{product}/{channel}"),
                )
                .map_err(|message| anyhow::anyhow!(message))?;
            }
            let actor = embedded_management_actor()?;
            let message = catalog::promote(ctx, &actor, &spec, &channel).await?;
            if output == OutputFormat::JsonV1 {
                print_machine_result(&crate::output::promote_result(&spec, &channel))?;
            } else {
                println!("{message}");
            }
        }
        Command::Canary { command } => match command {
            CanaryCommand::Designate { env, remove } => {
                let actor = embedded_management_actor()?;
                println!(
                    "{}",
                    canary::set_designated(ctx, &actor, &env, !remove).await?
                );
            }
            CanaryCommand::Policy {
                spec,
                channel,
                cohort,
                reactivate,
            } => {
                let actor = embedded_management_actor()?;
                let active =
                    canary::configure(ctx, &actor, &spec, &channel, cohort, reactivate).await?;
                println!(
                    "canary policy {} active for {} -> {} with cohort {}",
                    active.digest(),
                    spec,
                    channel,
                    active.policy().cohort.join(", ")
                );
            }
            CanaryCommand::Repair { plan_id } => {
                let actor = embedded_management_actor()?;
                let repaired = canary::repair_pending(ctx, &actor, &plan_id).await?;
                println!("repaired {repaired} canary attempt(s) for {plan_id}");
            }
            CanaryCommand::Unlock { product, channel } => {
                let actor = embedded_management_actor()?;
                println!(
                    "{}",
                    canary::unlock_promotion(ctx, &actor, &product, &channel).await?
                );
            }
        },
        _ => unreachable!("catalog dispatcher received a non-catalog command"),
    }
    Ok(())
}
