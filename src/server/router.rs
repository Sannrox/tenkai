use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use serde::Serialize;

use crate::management_operations::ManagementOperations;
use crate::runtime_delivery::{ReconcilePort, RuntimeDeliveryOperations};
use crate::storage::OperationalStore;
use crate::tenant_store::TenantOperationalStore;

use super::auth::{import_development_fixture, reset_development_fixture};
use super::config::ServerConfig;
use super::inspect::{
    environment_status, fleet_status, health, inspect_environment, list_environments, openmetrics,
    ready, reconcile,
};
use super::lifecycle::{
    apply_plan, approve_plan, plan_environment, promote_release, publish_release, recall_release,
    rollback_environment, subscribe_environment,
};
use super::package_migration::{
    apply_package_migration, package_migration_status, preview_package_migration,
    resume_package_migration, rollback_package_migration,
};
use super::runtime::{runtime_complete, runtime_heartbeat, runtime_inventory, runtime_work};

pub(super) struct AppState {
    pub(super) config: ServerConfig,
    pub(super) reconciler: Arc<dyn ReconcilePort>,
    pub(super) store: Arc<dyn OperationalStore>,
    pub(super) tenant_store: Option<Arc<dyn TenantOperationalStore>>,
    pub(super) management: Arc<ManagementOperations>,
    pub(super) runtime_delivery: Arc<RuntimeDeliveryOperations>,
}

#[derive(Debug, Serialize)]
pub(super) struct ServiceStatus {
    pub(super) status: &'static str,
    pub(super) profile: String,
    pub(super) capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct ErrorBody {
    pub(super) error: String,
}

pub fn router(
    config: ServerConfig,
    reconciler: Arc<dyn ReconcilePort>,
    store: Arc<dyn OperationalStore>,
) -> anyhow::Result<Router> {
    config.validate()?;
    let auth = config.build_auth_stack()?;
    let metrics_enabled = config.metrics_enabled;
    let development_fixtures_enabled = config.development_fixtures.is_some();
    let runtime_delivery = Arc::new(RuntimeDeliveryOperations::new(
        config.runtime_assignments.clone(),
        reconciler.clone(),
        store.clone(),
    ));
    let package_migration_trust_roots = match &config.package_migration_trust_roots {
        Some(path) => Some(crate::package_migration::load_trust_roots(path)?),
        None => None,
    };
    let management = Arc::new(ManagementOperations::new(
        auth,
        config.requirements.tenant_mode,
        reconciler.clone(),
        store.clone(),
        config.tenant_store.clone(),
        package_migration_trust_roots,
        config.environment_management_assignments.clone(),
    ));
    let mut router = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/reconcile", post(reconcile))
        .route("/v1/fleet/status", get(fleet_status))
        .route("/v1/environments", get(list_environments))
        .route("/v1/environments/{environment}", get(inspect_environment))
        .route(
            "/v1/environments/{environment}/status",
            get(environment_status),
        )
        .route(
            "/v1/migrations/{name}/preview",
            post(preview_package_migration),
        )
        .route("/v1/migrations/{name}/apply", post(apply_package_migration))
        .route("/v1/migrations/{name}", get(package_migration_status))
        .route(
            "/v1/migrations/{name}/resume",
            post(resume_package_migration),
        )
        .route(
            "/v1/migrations/{name}/rollback",
            post(rollback_package_migration),
        )
        .route("/v1/releases", post(publish_release))
        .route("/v1/channels/{channel}/promote", post(promote_release))
        .route("/v1/releases/{release}/recall", post(recall_release))
        .route(
            "/v1/environments/{environment}/subscriptions",
            post(subscribe_environment),
        )
        .route(
            "/v1/environments/{environment}/plans",
            post(plan_environment),
        )
        .route("/v1/plans/{plan_id}/approve", post(approve_plan))
        .route("/v1/plans/{plan_id}/apply", post(apply_plan))
        .route(
            "/v1/environments/{environment}/rollback",
            post(rollback_environment),
        )
        .route(
            "/v1/runtime/environments/{environment}/work",
            get(runtime_work),
        )
        .route(
            "/v1/runtime/environments/{environment}/complete",
            post(runtime_complete),
        )
        .route(
            "/v1/runtime/environments/{environment}/heartbeat",
            post(runtime_heartbeat),
        )
        .route(
            "/v1/runtime/environments/{environment}/inventory",
            post(runtime_inventory),
        );
    if metrics_enabled {
        router = router.route("/metrics", get(openmetrics));
    }
    if development_fixtures_enabled {
        router = router
            .route(
                "/v1/development/fixtures/import",
                post(import_development_fixture),
            )
            .route(
                "/v1/development/fixtures/{fixture_id}",
                axum::routing::delete(reset_development_fixture),
            );
    }
    Ok(router.with_state(Arc::new(AppState {
        tenant_store: config.tenant_store.clone(),
        management,
        config,
        reconciler,
        store,
        runtime_delivery,
    })))
}
