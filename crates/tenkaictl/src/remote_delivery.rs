use anyhow::{Result, bail};

use tenkai::command_result::{CommandName, CommandOutcome, CommandResultV1, RetryGuidance};

use crate::args::{Command, OutputFormat};
use crate::authorization::{load_remote_migration_authorization, reject_remote_migration_bypass};
use crate::migrate_args::MigrateCommand;
use crate::output::{print_machine_result, reported_machine_failure, with_remote_resources};
use tenkai::package_migration;

pub(crate) async fn run(
    client: &tenkai_http::RemoteClient,
    command: Command,
    output: OutputFormat,
) -> Result<()> {
    let machine = output == OutputFormat::JsonV1;
    match command {
        Command::Apply {
            plan_id,
            approval,
            skip_gates,
            emergency_reason,
            generation,
        } => {
            if approval.allow_unapproved_development || approval.development_reason.is_some() {
                bail!(
                    "the local-development apply bypass is available only with --target embedded"
                );
            }
            let generation = generation
                .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
            let approval_path = approval
                .approval
                .ok_or_else(|| anyhow::anyhow!("--approval is required with --target remote"))?;
            let approval_trust_roots = approval.approval_trust_roots.ok_or_else(|| {
                anyhow::anyhow!("--approval-trust-roots is required with --target remote")
            })?;
            let env = tenkai::management_lifecycle::plan_environment_from_id(&plan_id)?;
            let request = tenkai::management_lifecycle::load_apply_request(
                env,
                generation,
                &approval_path,
                &approval_trust_roots,
                skip_gates,
                emergency_reason,
            )?;
            let result = client
                .apply_plan(&plan_id, &request)
                .await
                .map_err(|error| {
                    if !machine {
                        print_refused_apply_steps(&error);
                    }
                    with_remote_resources(
                        error,
                        output,
                        CommandName::Apply,
                        &[("plan", &plan_id), ("environment", env)],
                    )
                })?;
            if machine {
                return print_machine_result(
                    &CommandResultV1::succeeded(CommandName::Apply)
                        .resource("plan", &plan_id)
                        .resource("environment", env),
                );
            }
            if result.steps.is_empty() {
                // A server that predates per-step results.
                println!("{}", result.message);
            } else {
                print_apply_steps(&result.steps);
            }
            Ok(())
        }
        Command::Rollback {
            product,
            env,
            bypass,
            emergency_reason: _,
            allow_recalled_recovery,
            recovery_reason,
            generation,
        } => {
            let env = crate::client_config::require_env(env)?;
            if bypass.allow_unapproved_development || bypass.development_reason.is_some() {
                bail!(
                    "the local-development rollback bypass is available only with --target embedded"
                );
            }
            let generation = generation
                .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
            let recovery = if allow_recalled_recovery {
                Some(
                    recovery_reason
                        .ok_or_else(|| anyhow::anyhow!("--recovery-reason is required"))?,
                )
            } else {
                None
            };
            let result = client
                .rollback_environment(&env, &product, generation, recovery)
                .await
                .map_err(|error| {
                    with_remote_resources(
                        error,
                        output,
                        CommandName::Rollback,
                        &[("environment", &env)],
                    )
                })?;
            if machine {
                // Remote rollback only plans; executing it always needs a signed approval.
                let mut awaiting = crate::remote_catalog::remote_plan_result(
                    CommandResultV1::failed(
                        CommandName::Rollback,
                        "approval_required",
                        "The rollback plan requires signed approval",
                        RetryGuidance::NotSafe,
                    ),
                    &result,
                    &env,
                    generation,
                )?;
                awaiting.outcome = CommandOutcome::AwaitingApproval;
                return Err(reported_machine_failure(awaiting));
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
        _ => {
            bail!("this command is not available through the v1 remote API; use --target embedded")
        }
    }
}

pub(crate) async fn run_migrate(
    client: &tenkai_http::RemoteClient,
    command: MigrateCommand,
) -> Result<()> {
    match command {
        MigrateCommand::Preview {
            name,
            env,
            declaration,
            backup_receipt_digest,
        } => {
            let env = crate::client_config::require_env(env)?;
            let declaration = package_migration::MigrationDeclaration::load(&declaration)?;
            let result = client
                .preview_package_migration(
                    &name,
                    &package_migration::PackageMigrationPreviewRequest {
                        version: package_migration::MIGRATION_API_VERSION,
                        environment: env,
                        declaration,
                        backup_receipt_digest,
                    },
                )
                .await?;
            println!("{}", package_migration::format_migration(&result.record));
            Ok(())
        }
        MigrateCommand::Apply {
            name,
            env,
            declaration,
            backup_receipt_digest,
            expected_generation,
            approval,
        } => {
            let env = crate::client_config::require_env(env)?;
            reject_remote_migration_bypass(approval.allow_unapproved_development)?;
            let expected_generation = expected_generation.ok_or_else(|| {
                anyhow::anyhow!("remote package migration apply requires --expected-generation")
            })?;
            let (approval, trust_roots, plan_approvals) = load_remote_migration_authorization(
                approval.approval,
                approval.approval_trust_roots,
            )?;
            let declaration = package_migration::MigrationDeclaration::load(&declaration)?;
            let result = client
                .apply_package_migration(
                    &name,
                    &package_migration::PackageMigrationApplyRequest {
                        version: package_migration::MIGRATION_API_VERSION,
                        environment: env,
                        declaration,
                        expected_generation,
                        approval,
                        trust_roots,
                        backup_receipt_digest,
                        plan_approvals,
                    },
                )
                .await?;
            println!("{}", package_migration::format_migration(&result.record));
            if matches!(
                result.record.status,
                package_migration::MigrationStatus::Failed
                    | package_migration::MigrationStatus::RecoveryRequired
            ) {
                bail!(
                    "package migration {} ended in {}",
                    result.record.name,
                    result.record.status.as_str()
                );
            }
            Ok(())
        }
        MigrateCommand::Status { name } => {
            let result = client.package_migration_status(&name).await?;
            println!("{}", package_migration::format_migration(&result.record));
            Ok(())
        }
        MigrateCommand::Resume {
            name,
            expected_generation,
            approval,
        } => {
            reject_remote_migration_bypass(approval.allow_unapproved_development)?;
            let expected_generation = expected_generation.ok_or_else(|| {
                anyhow::anyhow!("remote package migration resume requires --expected-generation")
            })?;
            let (approval, trust_roots, plan_approvals) = load_remote_migration_authorization(
                approval.approval,
                approval.approval_trust_roots,
            )?;
            let result = client
                .resume_package_migration(
                    &name,
                    &package_migration::PackageMigrationMutateRequest {
                        version: package_migration::MIGRATION_API_VERSION,
                        expected_generation,
                        approval,
                        trust_roots,
                        plan_approvals,
                    },
                )
                .await?;
            println!("{}", package_migration::format_migration(&result.record));
            if matches!(
                result.record.status,
                package_migration::MigrationStatus::Failed
                    | package_migration::MigrationStatus::RecoveryRequired
            ) {
                bail!(
                    "package migration {} ended in {}",
                    result.record.name,
                    result.record.status.as_str()
                );
            }
            Ok(())
        }
        MigrateCommand::Rollback {
            name,
            expected_generation,
            approval,
        } => {
            reject_remote_migration_bypass(approval.allow_unapproved_development)?;
            let expected_generation = expected_generation.ok_or_else(|| {
                anyhow::anyhow!("remote package migration rollback requires --expected-generation")
            })?;
            let (approval, trust_roots, plan_approvals) = load_remote_migration_authorization(
                approval.approval,
                approval.approval_trust_roots,
            )?;
            let result = client
                .rollback_package_migration(
                    &name,
                    &package_migration::PackageMigrationMutateRequest {
                        version: package_migration::MIGRATION_API_VERSION,
                        expected_generation,
                        approval,
                        trust_roots,
                        plan_approvals,
                    },
                )
                .await?;
            println!("{}", package_migration::format_migration(&result.record));
            if result.record.status == package_migration::MigrationStatus::RecoveryRequired {
                bail!(
                    "package migration {} rollback requires recovery",
                    result.record.name
                );
            }
            Ok(())
        }
    }
}

/// Print each step of a remote apply as an embedded apply does (#1076).
fn print_apply_steps(steps: &[tenkai::management_lifecycle::ApplyStepResult]) {
    for step in steps {
        let Some(status) = step.outcome_status() else {
            println!("  {:<9} {:<24} {}", step.status, step.product, step.detail);
            continue;
        };
        let cut = if step.detail_truncated { " [cut]" } else { "" };
        println!(
            "{}{cut}",
            crate::embedded_apply::step_line(status, &step.product, &step.to_version, &step.detail)
        );
    }
}

/// Print the steps a refused apply's body carries, when it carries them.
fn print_refused_apply_steps(error: &anyhow::Error) {
    let Some(tenkai_http::RemoteFailure::Rejected {
        status: 422,
        detail,
    }) = error.downcast_ref()
    else {
        return;
    };
    if let Ok(body) = serde_json::from_str::<tenkai::management_lifecycle::ApplyFailedBody>(detail)
    {
        print_apply_steps(&body.steps);
    }
}
