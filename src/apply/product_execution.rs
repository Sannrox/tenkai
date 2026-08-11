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
    if let Some(executor) = crate::software_executor::selected_software_executor() {
        prepare_fenced_mutation(ctx, lease, content).await?;
        let request = software_request(content);
        let install = executor.apply(&request).map_err(|error| {
            crate::software_executor::format_software_phase_error(
                crate::software_executor::SoftwareDeployPhase::Apply,
                &content.product,
                &content.manifest.product.version,
                &content.environment,
                &error.to_string(),
            )
        });
        let result = match install {
            Ok(()) => match &content.manifest.deploy.health {
                Some(command) if !command.is_empty() => {
                    match run_mutation_command(ctx, lease, content, command).await? {
                        Ok(()) => Ok(()),
                        Err(error) => Err(crate::software_executor::format_software_phase_error(
                            crate::software_executor::SoftwareDeployPhase::Health,
                            &content.product,
                            &content.manifest.product.version,
                            &content.environment,
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

/// Deactivate one release under the current environment fence.
pub(super) async fn deactivate(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
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
    if let Some(executor) = crate::software_executor::selected_software_executor() {
        refresh_environment_lease(ctx, lease).await?;
        return Ok(executor
            .remove(&software_request(content))
            .map_err(|error| error.to_string()));
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
) -> Result<(bool, String)> {
    if content.manifest.product.kind.policy().cleanup() == CleanupPolicy::Atomic {
        // Descriptor validation is pre-mutation and local adapters publish
        // atomically, so a failed target does not require shell uninstall cleanup.
        return Ok((true, failure));
    }
    Ok(match content.manifest.deploy.uninstall.as_deref() {
        Some(_) => match deactivate(ctx, lease, content).await {
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

fn software_request(content: &ReleaseContent) -> crate::software_executor::SoftwareApplyRequest {
    crate::software_executor::request_from_parts(
        content.product.clone(),
        content.manifest.product.version.clone(),
        content.environment.clone(),
        &content.workdir,
        format!(
            "tenkai:release:{}@{}",
            content.product, content.manifest.product.version
        ),
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
        ] {
            assert_eq!(kind.policy().cleanup(), CleanupPolicy::Atomic);
        }
        assert_eq!(
            ProductKind::Software.policy().cleanup(),
            CleanupPolicy::UninstallIfDeclared
        );
    }
}
