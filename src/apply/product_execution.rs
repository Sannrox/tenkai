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
    adapters: TargetAdapters<'_>,
) -> Result<Result<(), String>> {
    crate::software_compatibility::require_manifest(
        ctx,
        &content.environment,
        &content.manifest,
        &content.manifest_digest,
    )
    .await?;
    // Every activation, a restore included, lands only in an allowed placement.
    crate::topology::require_manifest_placement(ctx, &content.environment, &content.manifest)
        .await?;
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
        // Engine selection: llama.cpp keeps the reference executor (fake by
        // default; real binary when TENKAI_LLAMA_SERVER / TENKAI_USE_REAL_LLAMA
        // is set, see model-runtime.md); mlx is the Apple-silicon host-process
        // executor (fake by default; real mlx_lm.server when TENKAI_MLX_SERVER /
        // TENKAI_USE_REAL_MLX is set); onnx verifies a signed registry
        // descriptor and runs the injected scoring port; other engines use the
        // host-injected executor and fail closed without one.
        let executor = match model_runtime_executor(ctx, content, adapters, &descriptor).await? {
            Ok(executor) => executor,
            Err(detail) => return Ok(Err(detail)),
        };
        let export_descriptor = descriptor.clone();
        let applied =
            run_guarded_mutation(ctx, lease, content, move || executor.apply(&descriptor)).await?;
        let (health, canary) = match &applied {
            Ok(_) => (
                crate::model_release_evidence::RuntimeHealth::Healthy,
                crate::model_release_evidence::RuntimeCanary::Incomplete,
            ),
            Err(_) => (
                crate::model_release_evidence::RuntimeHealth::Unhealthy,
                crate::model_release_evidence::RuntimeCanary::Failed,
            ),
        };
        let release_id =
            crate::ontology::release_id(&content.product, &content.manifest.product.version);
        let plan_digest =
            crate::model_release_evidence::smoke_plan_digest(&content.environment, &release_id);
        // Export is optional integration. A signing or outbox failure must not
        // turn a completed smoke into an activation error (and recovery).
        let _ = crate::model_release_evidence::export_completed_runtime_evidence(
            ctx,
            crate::model_release_evidence::CompletedRuntimeExport {
                descriptor: &export_descriptor,
                release_id: &release_id,
                release_digest: &content.manifest_digest,
                environment: &content.environment,
                plan_digest: &plan_digest,
                health,
                canary,
                observed_at: crate::now_millis(),
            },
        )
        .await;
        if applied.is_ok() {
            // Observation is a read-view side effect. A store failure must not
            // turn a completed activation into a product-target failure.
            let facts = crate::environment::list_environment_facts(ctx, &content.environment)
                .await
                .unwrap_or_default();
            let snapshot = crate::observed_runtime::from_model_runtime(&export_descriptor, &facts);
            let _ = crate::observed_runtime::persist_under_lease(ctx, lease, &snapshot).await;
        }
        return Ok(applied.map(|_| ()));
    }
    if content.manifest.product.kind.policy().target() == ProductTarget::WorkerPool {
        prepare_fenced_mutation(ctx, lease, content).await?;
        return admit_worker_pool(ctx, lease, content, adapters.worker_lifecycle, false, false)
            .await;
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
    if let Some(executor) = adapters.software {
        prepare_fenced_mutation(ctx, lease, content).await?;
        if let Err(detail) = require_artifact_pull_consumer(content, Some(executor)) {
            return Ok(Err(detail));
        }
        let request = software_request(ctx, content, lease).await?;
        let install = software_blocking(|| executor.apply(&request)).map_err(|error| {
            software_phase_error(
                crate::software_executor::SoftwareDeployPhase::Apply,
                content,
                &error.to_string(),
            )
        });
        let result = match install {
            Ok(()) => match &content.manifest.deploy.health {
                Some(command) if !command.is_empty() => {
                    let mut health = crate::telemetry::start_span(
                        "tenkai.health",
                        &health_attrs(lease, content),
                    );
                    match run_mutation_command(ctx, lease, content, command).await? {
                        Ok(()) => {
                            health.succeed();
                            Ok(())
                        }
                        Err(error) => {
                            health.fail();
                            Err(software_phase_error(
                                crate::software_executor::SoftwareDeployPhase::Health,
                                content,
                                &error,
                            ))
                        }
                    }
                }
                _ => {
                    let mut health = crate::telemetry::start_span(
                        "tenkai.health",
                        &health_attrs(lease, content),
                    );
                    health.succeed();
                    Ok(())
                }
            },
            Err(error) => Err(error),
        };
        if result.is_ok() {
            // Observation is a read-view side effect. A store or inspect failure
            // must not turn a completed activation into a product-target failure.
            if let Ok(Some(snapshot)) = software_blocking(|| executor.observed_runtime(&request)) {
                let _ = crate::observed_runtime::persist_under_lease(ctx, lease, &snapshot).await;
            }
        }
        return Ok(result);
    }
    if let Err(detail) = require_artifact_pull_consumer(content, None) {
        return Ok(Err(detail));
    }
    let install =
        run_mutation_command(ctx, lease, content, &content.manifest.deploy.install).await?;
    let result = match install {
        Ok(()) => match &content.manifest.deploy.health {
            Some(command) if !command.is_empty() => {
                let mut health =
                    crate::telemetry::start_span("tenkai.health", &health_attrs(lease, content));
                match run_mutation_command(ctx, lease, content, command).await? {
                    Ok(()) => {
                        health.succeed();
                        Ok(())
                    }
                    Err(error) => {
                        health.fail();
                        Err(error)
                    }
                }
            }
            _ => {
                let mut health =
                    crate::telemetry::start_span("tenkai.health", &health_attrs(lease, content));
                health.succeed();
                Ok(())
            }
        },
        error => error,
    };
    match verify_integrity(content) {
        Ok(()) => Ok(result),
        Err(error) => Ok(Err(error.to_string())),
    }
}

fn health_attrs(
    lease: &EnvironmentLease,
    content: &ReleaseContent,
) -> crate::telemetry::DeliveryAttributes {
    crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Health)
        .environment(content.environment.clone())
        .release_digest(content.artifact_digest.clone())
        .fencing_generation(lease.generation)
}

/// Re-apply the current pin without changing the recorded version.
pub(super) async fn restart(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    adapters: TargetAdapters<'_>,
) -> Result<Result<(), String>> {
    crate::software_compatibility::require_manifest(
        ctx,
        &content.environment,
        &content.manifest,
        &content.manifest_digest,
    )
    .await?;
    // Every activation, a restore included, lands only in an allowed placement.
    crate::topology::require_manifest_placement(ctx, &content.environment, &content.manifest)
        .await?;
    if content.manifest.product.kind.policy().target() == ProductTarget::WorkerPool {
        prepare_fenced_mutation(ctx, lease, content).await?;
        return admit_worker_pool(ctx, lease, content, adapters.worker_lifecycle, false, true)
            .await;
    }
    if let Some(executor) = adapters.software {
        prepare_fenced_mutation(ctx, lease, content).await?;
        if let Err(detail) = require_artifact_pull_consumer(content, Some(executor)) {
            return Ok(Err(detail));
        }
        let request = software_request(ctx, content, lease).await?;
        let bounce = software_blocking(|| executor.restart(&request)).map_err(|error| {
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
    activate(ctx, lease, content, adapters).await
}

/// Why a release is being deactivated.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Removal {
    /// Remove the deployed release.
    Release,
    /// Clean up after its activation failed; software adapters may already
    /// have restored the previous runtime.
    FailedApply,
}

/// Deactivate one release under the current environment fence.
pub(super) async fn deactivate(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    adapters: TargetAdapters<'_>,
) -> Result<Result<(), String>> {
    deactivate_for(ctx, lease, content, adapters, Removal::Release).await
}

async fn deactivate_for(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    adapters: TargetAdapters<'_>,
    removal: Removal,
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
        let descriptor =
            crate::model_runtime::ModelRuntimeDescriptor::from_manifest(&content.manifest)?;
        let executor = match model_runtime_executor(ctx, content, adapters, &descriptor).await? {
            Ok(executor) => executor,
            Err(detail) => return Ok(Err(detail)),
        };
        let removed = run_guarded_mutation(ctx, lease, content, move || executor.remove()).await?;
        if removed.is_ok() {
            let _ = crate::observed_runtime::clear_under_lease(ctx, lease, &content.product).await;
        }
        return Ok(removed);
    }
    if content.manifest.product.kind.policy().target() == ProductTarget::WorkerPool {
        refresh_environment_lease(ctx, lease).await?;
        return admit_worker_pool(ctx, lease, content, adapters.worker_lifecycle, true, false)
            .await;
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
    if let Some(executor) = adapters.software {
        refresh_environment_lease(ctx, lease).await?;
        if let Err(detail) = require_artifact_pull_consumer(content, Some(executor)) {
            return Ok(Err(detail));
        }
        let request = software_request(ctx, content, lease).await?;
        let removed = software_blocking(|| match removal {
            Removal::Release => executor.remove(&request),
            Removal::FailedApply => executor.cleanup_failed_apply(&request),
        })
        .map_err(|error| {
            software_phase_error(
                crate::software_executor::SoftwareDeployPhase::Remove,
                content,
                &error.to_string(),
            )
        });
        if removed.is_ok() {
            let _ = crate::observed_runtime::clear_under_lease(ctx, lease, &content.product).await;
        }
        return Ok(removed);
    }
    if let Err(detail) = require_artifact_pull_consumer(content, None) {
        return Ok(Err(detail));
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
    adapters: TargetAdapters<'_>,
) -> Result<(bool, String)> {
    if content.manifest.product.kind.policy().cleanup() == CleanupPolicy::Atomic {
        // Descriptor validation is pre-mutation and local adapters publish
        // atomically, so a failed target does not require shell uninstall cleanup.
        return Ok((true, failure));
    }
    Ok(match content.manifest.deploy.uninstall.as_deref() {
        Some(_) => {
            match deactivate_for(ctx, lease, content, adapters, Removal::FailedApply).await {
                Ok(Ok(())) => (true, format!("{failure}; cleaned up failed install")),
                Ok(Err(cleanup)) => (false, format!("{failure}; cleanup also failed: {cleanup}")),
                Err(error) if is_execution_fence_lost(&error) => return Err(error),
                Err(error) => (
                    false,
                    format!("{failure}; cleanup executor also failed: {error}"),
                ),
            }
        }
        None => (false, failure),
    })
}

/// Run a borrowed software-executor call off the async worker when the runtime
/// can compensate. `spawn_blocking` needs `'static`; the adapter is a borrow.
fn software_blocking<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

async fn software_request(
    ctx: &mut Ctx,
    content: &ReleaseContent,
    lease: &EnvironmentLease,
) -> Result<crate::software_executor::SoftwareApplyRequest> {
    let env_obj = crate::environment::environment(ctx, &content.environment).await?;
    let overlays = crate::environment::product_overlays(&env_obj, &content.product)?;
    let mut request = crate::software_executor::with_overlays(
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
    );
    request.artifact_pulls = content.artifact_pulls.clone();
    request.cluster_config_path =
        crate::software_executor::cluster_config_path_from_properties(&env_obj.properties)?;
    request.secret_dir_path =
        crate::software_executor::secret_dir_from_properties(&env_obj.properties)?;
    // Apply and its failed-apply cleanup run under the same lease.
    request.apply_attempt = format!("lease-{}", lease.generation);
    Ok(request)
}

fn require_artifact_pull_consumer(
    content: &ReleaseContent,
    executor: Option<&dyn crate::software_executor::SoftwareExecutor>,
) -> Result<(), String> {
    if content.artifact_pulls.is_empty() {
        return Ok(());
    }
    match executor {
        Some(executor) if executor.consumes_admitted_artifact_pulls() => Ok(()),
        Some(_) => Err(
            "executor does not consume admitted environment-mirror artifact pulls".into(),
        ),
        None => Err(
            "digest-bound artifacts require an executor that consumes admitted environment-mirror pulls"
                .into(),
        ),
    }
}

async fn admit_worker_pool(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    worker_lifecycle: Option<&dyn crate::worker_pool::WorkerLifecyclePort>,
    removing: bool,
    restart: bool,
) -> Result<Result<(), String>> {
    let mut spec = match crate::worker_pool::spec_from_manifest(&content.manifest) {
        Ok(spec) => spec,
        Err(error) => return Ok(Err(error.to_string())),
    };
    if removing {
        spec.replicas = 0;
    }
    let Some(port) = worker_lifecycle else {
        return Ok(Err(
            "live worker-lifecycle port required; retained snapshots cannot authorize process change"
                .into(),
        ));
    };
    let mut env = crate::environment::environment(ctx, &content.environment).await?;
    let previous = crate::worker_pool::previous_replicas(&env.properties, &spec.product);
    let drain_started = crate::worker_pool::drain_started_at(&env.properties, &spec.product);
    let now = crate::now_millis();
    let (decision, observed, next_drain, source) =
        match crate::worker_pool::admit_live_pool(crate::worker_pool::LivePoolAdmission {
            spec: &spec,
            port,
            environment: &content.environment,
            expected_generation: lease.generation,
            previous_replicas: previous,
            drain_started_at_ms: drain_started,
            now_ms: now,
            restart,
        }) {
            Ok(result) => result,
            Err(error) => return Ok(Err(error.to_string())),
        };
    crate::worker_pool::persist_observation(&mut env.properties, &observed);
    crate::worker_pool::persist_observation_source(&mut env.properties, &spec.product, source);
    if let Some(started) = next_drain {
        env.properties.insert(
            format!("worker_pool.{}.drain_started_at", spec.product),
            started.to_string(),
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

/// Select the model-runtime executor for one release by engine and by the
/// environment's cluster configuration. Selection refusals are inner target
/// failures; loading the environment stays an outer error.
async fn model_runtime_executor(
    ctx: &mut Ctx,
    content: &ReleaseContent,
    adapters: TargetAdapters<'_>,
    descriptor: &crate::model_runtime::ModelRuntimeDescriptor,
) -> Result<Result<std::sync::Arc<dyn crate::model_runtime::ModelRuntimeExecutor>, String>> {
    // The llama.cpp reference path never consults cluster or weight-origin
    // configuration. mlx is also a host process (no cluster) but still needs
    // environment mirrors, isolation, and registry for WeightCache.
    if descriptor.runtime.engine == "llama.cpp" {
        return Ok(crate::model_runtime::select_model_runtime_executor(
            descriptor,
            &content.environment,
            None,
            adapters.model_runtime,
            &content.model_runtime_state,
            None,
        )
        .map_err(|error| error.to_string()));
    }
    let env_obj = crate::environment::environment(ctx, &content.environment).await?;
    let cluster_config =
        crate::software_executor::cluster_config_path_from_properties(&env_obj.properties)
            .map_err(|error| error.to_string());
    let cluster_config = match cluster_config {
        Ok(path) => path,
        Err(detail) => return Ok(Err(detail)),
    };
    let isolated = env_obj
        .properties
        .get(crate::connectivity::CONNECTIVITY_CLASS_PROPERTY)
        .map(String::as_str)
        .map(crate::connectivity::ConnectivityClass::parse)
        .transpose()
        .map_err(|error| error.to_string());
    let isolated = match isolated {
        Ok(class) => class == Some(crate::connectivity::ConnectivityClass::Isolated),
        Err(detail) => return Ok(Err(detail)),
    };
    let artifacts = Some(crate::model_runtime::ModelRuntimeArtifacts {
        registry: adapters.artifact_registry_handle,
        mirrors: crate::oci_artifact::mirrors_from_properties(&env_obj.properties),
        isolated,
        workdir: Some(content.workdir.clone()),
    });
    Ok(crate::model_runtime::select_model_runtime_executor(
        descriptor,
        &content.environment,
        cluster_config.as_deref(),
        adapters.model_runtime,
        &content.model_runtime_state,
        artifacts,
    )
    .map_err(|error| error.to_string()))
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
