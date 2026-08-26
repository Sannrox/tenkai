//! Product target lifecycle behind the apply workflow's private execution seam.

use super::*;
use crate::product_kind::{CleanupPolicy, ProductTarget};

/// Refresh the environment fence and re-check release content integrity.
///
/// Outer errors from this helper are fence/control-plane failures; they must
/// not be collapsed into ordinary product-target failures.
async fn prepare_fenced_mutation(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
) -> Result<()> {
    refresh_environment_lease(ctx, lease).await?;
    verify_integrity(content)?;
    Ok(())
}

/// Activate one immutable release under the current environment fence.
///
/// Product target failures are returned in the inner result. Fence, integrity,
/// and executor-control failures remain outer errors so callers cannot mistake
/// an unsafe or indeterminate execution for an ordinary target failure.
pub(super) async fn activate(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    software: Option<&dyn crate::software_executor::SoftwareExecutor>,
) -> Result<Result<(), String>> {
    if content.manifest.product.kind.policy().target() == ProductTarget::RoutingConfig {
        prepare_fenced_mutation(ctx, lease, content).await?;
        let routing = content
            .manifest
            .routing
            .as_ref()
            .context("routing release has no routing contract")?;
        let config = crate::routing::load_and_validate(
            &content.workdir.join(&routing.config),
            &routing.allowed_providers,
        )?;
        let executor =
            crate::routing::LocalRoutingConfigExecutor::new(content.routing_state.clone());
        return Ok(executor
            .apply(&config)
            .map(|_| ())
            .map_err(|error| error.to_string()));
    }
    if content.manifest.product.kind.policy().target() == ProductTarget::ModelRuntime {
        prepare_fenced_mutation(ctx, lease, content).await?;
        let descriptor =
            crate::model_runtime::ModelRuntimeDescriptor::from_manifest(&content.manifest)?;
        // Reference llama.cpp plugin: fake by default; real binary when
        // TENKAI_LLAMA_SERVER / TENKAI_USE_REAL_LLAMA is set (see model-runtime.md).
        let executor = crate::model_runtime::ReferenceLlamaCppExecutor::for_operator_host(
            content.model_runtime_state.clone(),
        );
        return Ok(executor
            .apply(&descriptor)
            .map(|_| ())
            .map_err(|error| error.to_string()));
    }
    if content.manifest.product.kind.policy().target() == ProductTarget::WorkerPool {
        prepare_fenced_mutation(ctx, lease, content).await?;
        if let Err(error) = admit_worker_pool(ctx, content, false).await? {
            return Ok(Err(error));
        }
        if software.is_none() && content.manifest.deploy.install.trim().is_empty() {
            return Ok(Ok(()));
        }
    }
    if content.manifest.product.kind == crate::manifest::ProductKind::WorkshopModule {
        prepare_fenced_mutation(ctx, lease, content).await?;
        let state_root = content
            .routing_state
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        return Ok(crate::workshop_module::activate(
            ctx,
            &content.environment,
            &content.product,
            &content.manifest,
            &content.workdir,
            state_root,
        )
        .await
        .map_err(|error| error.to_string()));
    }
    if matches!(
        content.manifest.product.kind.policy().target(),
        ProductTarget::Staged(_)
    ) {
        prepare_fenced_mutation(ctx, lease, content).await?;
        let state_root = content
            .routing_state
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        return Ok(crate::staged_artifact::activate(
            &content.manifest,
            &content.workdir,
            state_root,
            &content.product,
        )
        .map_err(|error| error.to_string()));
    }
    if let Some(executor) = software {
        prepare_fenced_mutation(ctx, lease, content).await?;
        let request = software_request(ctx, content).await?;
        let install = executor.apply(&request).map_err(|error| {
            software_phase_error(
                crate::software_executor::SoftwareDeployPhase::Apply,
                content,
                &error.to_string(),
            )
        });
        let result = match install {
            Ok(()) => match &content.manifest.deploy.health {
                Some(command) if !command.is_empty() => {
                    match run_mutation_command(ctx, lease, content, command).await? {
                        Ok(()) => Ok(()),
                        Err(error) => Err(software_phase_error(
                            crate::software_executor::SoftwareDeployPhase::Health,
                            content,
                            &error,
                        )),
                    }
                }
                _ => Ok(()),
            },
            Err(error) => Err(error),
        };
        return Ok(result);
    }
    let install =
        run_mutation_command(ctx, lease, content, &content.manifest.deploy.install).await?;
    let result = match install {
        Ok(()) => match &content.manifest.deploy.health {
            Some(command) if !command.is_empty() => {
                run_mutation_command(ctx, lease, content, command).await
            }
            _ => Ok(Ok(())),
        },
        error => Ok(error),
    }?;
    match verify_integrity(content) {
        Ok(()) => Ok(result),
        Err(error) => Ok(Err(error.to_string())),
    }
}

/// Re-apply the current pin without changing the recorded version.
pub(super) async fn restart(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    software: Option<&dyn crate::software_executor::SoftwareExecutor>,
) -> Result<Result<(), String>> {
    if let Some(executor) = software {
        prepare_fenced_mutation(ctx, lease, content).await?;
        let request = software_request(ctx, content).await?;
        let bounce = executor.restart(&request).map_err(|error| {
            software_phase_error(
                crate::software_executor::SoftwareDeployPhase::Restart,
                content,
                &error.to_string(),
            )
        });
        let result = match bounce {
            Ok(()) => match &content.manifest.deploy.health {
                Some(command) if !command.is_empty() => {
                    match run_mutation_command(ctx, lease, content, command).await? {
                        Ok(()) => Ok(()),
                        Err(error) => Err(software_phase_error(
                            crate::software_executor::SoftwareDeployPhase::Health,
                            content,
                            &error,
                        )),
                    }
                }
                _ => Ok(()),
            },
            Err(error) => Err(error),
        };
        return Ok(result);
    }
    activate(ctx, lease, content, software).await
}

/// Deactivate one release under the current environment fence.
pub(super) async fn deactivate(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    software: Option<&dyn crate::software_executor::SoftwareExecutor>,
) -> Result<Result<(), String>> {
    if content.manifest.product.kind.policy().target() == ProductTarget::RoutingConfig {
        refresh_environment_lease(ctx, lease).await?;
        return Ok(
            crate::routing::LocalRoutingConfigExecutor::new(content.routing_state.clone())
                .remove()
                .map_err(|error| error.to_string()),
        );
    }
    if content.manifest.product.kind.policy().target() == ProductTarget::ModelRuntime {
        refresh_environment_lease(ctx, lease).await?;
        return Ok(
            crate::model_runtime::ReferenceLlamaCppExecutor::for_operator_host(
                content.model_runtime_state.clone(),
            )
            .remove()
            .map_err(|error| error.to_string()),
        );
    }
    if content.manifest.product.kind.policy().target() == ProductTarget::WorkerPool {
        refresh_environment_lease(ctx, lease).await?;
        if let Err(error) = admit_worker_pool(ctx, content, true).await? {
            return Ok(Err(error));
        }
    }
    if content.manifest.product.kind == crate::manifest::ProductKind::WorkshopModule {
        refresh_environment_lease(ctx, lease).await?;
        let state_root = content
            .routing_state
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        return Ok(crate::workshop_module::deactivate(
            ctx,
            &content.environment,
            &content.product,
            state_root,
        )
        .await
        .map_err(|error| error.to_string()));
    }
    if matches!(
        content.manifest.product.kind.policy().target(),
        ProductTarget::Staged(_)
    ) {
        refresh_environment_lease(ctx, lease).await?;
        let state_root = content
            .routing_state
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        return Ok(crate::staged_artifact::deactivate(
            content.manifest.product.kind,
            state_root,
            &content.product,
        )
        .map_err(|error| error.to_string()));
    }
    if let Some(executor) = software {
        refresh_environment_lease(ctx, lease).await?;
        return Ok(executor
            .remove(&software_request(ctx, content).await?)
            .map_err(|error| {
                software_phase_error(
                    crate::software_executor::SoftwareDeployPhase::Remove,
                    content,
                    &error.to_string(),
                )
            }));
    }
    match content.manifest.deploy.uninstall.as_deref() {
        Some(command) if !command.is_empty() => {
            let result = run_mutation_command(ctx, lease, content, command).await?;
            match verify_integrity(content) {
                Ok(()) => Ok(result),
                Err(error) => Ok(Err(error.to_string())),
            }
        }
        _ => Ok(Err("release has no uninstall command".into())),
    }
}

/// Apply the product-specific cleanup policy after activation fails.
pub(super) async fn cleanup_failed_activation(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    failure: String,
    software: Option<&dyn crate::software_executor::SoftwareExecutor>,
) -> Result<(bool, String)> {
    if content.manifest.product.kind.policy().cleanup() == CleanupPolicy::Atomic {
        // Descriptor validation is pre-mutation and local adapters publish
        // atomically, so a failed target does not require shell uninstall cleanup.
        return Ok((true, failure));
    }
    Ok(match content.manifest.deploy.uninstall.as_deref() {
        Some(_) => match deactivate(ctx, lease, content, software).await {
            Ok(Ok(())) => (true, format!("{failure}; cleaned up failed install")),
            Ok(Err(cleanup)) => (false, format!("{failure}; cleanup also failed: {cleanup}")),
            Err(error) => (
                false,
                format!("{failure}; cleanup executor also failed: {error}"),
            ),
        },
        None => (false, failure),
    })
}

async fn software_request(
    ctx: &mut Ctx,
    content: &ReleaseContent,
) -> Result<crate::software_executor::SoftwareApplyRequest> {
    let env_obj = crate::environment::environment(ctx, &content.environment).await?;
    let overlays = crate::environment::product_overlays(&env_obj, &content.product)?;
    Ok(crate::software_executor::with_overlays(
        crate::software_executor::request_from_parts(
            content.product.clone(),
            content.manifest.product.version.clone(),
            content.environment.clone(),
            &content.workdir,
            format!(
                "tenkai:release:{}@{}",
                content.product, content.manifest.product.version
            ),
        ),
        overlays,
    ))
}

async fn admit_worker_pool(
    ctx: &mut Ctx,
    content: &ReleaseContent,
    removing: bool,
) -> Result<Result<(), String>> {
    let mut spec = match crate::worker_pool::spec_from_manifest(&content.manifest) {
        Ok(spec) => spec,
        Err(error) => return Ok(Err(error.to_string())),
    };
    if removing {
        spec.replicas = 0;
    }
    let mut env = crate::environment::environment(ctx, &content.environment).await?;
    let previous = crate::worker_pool::previous_replicas(&env.properties, &spec.product);
    let drain_started = crate::worker_pool::drain_started_at(&env.properties, &spec.product);
    let snapshots = match crate::worker_pool::load_snapshots(&content.workdir.join("worker"), &spec)
    {
        Ok(snapshots) => snapshots,
        Err(error) => return Ok(Err(error.to_string())),
    };
    let now = crate::now_millis();
    let decision =
        match crate::worker_pool::reconcile(&spec, &snapshots, previous, drain_started, now) {
            Ok(decision) => decision,
            Err(error) => return Ok(Err(error.to_string())),
        };
    let observed = crate::worker_pool::observation(&spec, &snapshots, &decision);
    crate::worker_pool::persist_observation(&mut env.properties, &observed);
    if matches!(decision, crate::worker_pool::WorkerPoolDecision::WaitDrain) {
        env.properties.insert(
            format!("worker_pool.{}.drain_started_at", spec.product),
            drain_started.unwrap_or(now).to_string(),
        );
    } else {
        env.properties
            .remove(&format!("worker_pool.{}.drain_started_at", spec.product));
    }
    ctx.put(env).await?;
    match decision {
        crate::worker_pool::WorkerPoolDecision::Apply { .. } => Ok(Ok(())),
        crate::worker_pool::WorkerPoolDecision::WaitDrain => Ok(Err(observed.detail)),
        crate::worker_pool::WorkerPoolDecision::Degraded { reason }
        | crate::worker_pool::WorkerPoolDecision::Deny { reason } => Ok(Err(reason)),
    }
}

fn software_phase_error(
    phase: crate::software_executor::SoftwareDeployPhase,
    content: &ReleaseContent,
    detail: &str,
) -> String {
    crate::software_executor::format_software_phase_error(
        phase,
        &content.product,
        &content.manifest.product.version,
        &content.environment,
        detail,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ProductKind;

    #[test]
    fn cleanup_policy_covers_every_product_kind() {
        for kind in [
            ProductKind::RoutingConfig,
            ProductKind::ModelRuntime,
            ProductKind::PolicyBundle,
            ProductKind::EvalSuite,
            ProductKind::AgentDefinition,
            ProductKind::WorkerPool,
            ProductKind::PromptPackage,
            ProductKind::WorkshopModule,
        ] {
            assert_eq!(kind.policy().cleanup(), CleanupPolicy::Atomic);
        }
        assert_eq!(
            ProductKind::Software.policy().cleanup(),
            CleanupPolicy::UninstallIfDeclared
        );
    }
}
