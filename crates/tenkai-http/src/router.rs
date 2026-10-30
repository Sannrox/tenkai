use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post, put};
use serde::Serialize;

use tenkai::management_operations::ManagementOperations;
use tenkai::runtime_delivery::{ReconcilePort, RuntimeDeliveryOperations};
use tenkai::storage::OperationalStore;
use tenkai::tenant_store::TenantOperationalStore;

use super::auth::{import_development_fixture, reset_development_fixture};
use super::config::ServerConfig;
use super::environment_config::{
    configure_approval_policy, configure_constraints, configure_criticality, configure_facts,
    configure_maintenance_window, configure_runner_attestation, configure_webhooks,
    register_environment,
};
use super::exports::{create_export, download_export, inspect_export, list_exports};
use super::grant_rules::{create_grant_rule, list_grant_rules, remove_grant_rule};
use super::imports::{
    content_inventory, environment_webhook_deliveries, host_webhook_deliveries, import_bundle,
    import_job, import_jobs, staged_imports, trust_posture, trust_runway,
};
use super::inspect::{
    backup_status, change_events, environment_approval_policy, environment_status, fleet_status,
    health, inspect_advisory_feed, inspect_environment, inspect_product_criticality, list_channels,
    list_environments, list_migrations, list_releases, observed_runtime, oidc_client, openmetrics,
    plan_approvals, query_exposures, ready, reconcile, take_backup,
};
use super::lifecycle::{
    apply_plan, approve_plan, channel_hold, clear_product_criticality, environment_hold,
    import_derived_criticality, install_model_evaluation_trust, plan_environment, promote_release,
    publish_release, recall_release, record_model_evaluation_evidence,
    record_software_compatibility_evidence, release_channel_hold, release_environment_hold,
    retire_environment, retry_failed_target, rollback_environment, set_channel_hold,
    set_environment_hold, set_product_criticality, software_compatibility_report,
    subscribe_environment,
};
use super::package_migration::{
    apply_package_migration, package_migration_status, preview_package_migration,
    resume_package_migration, rollback_package_migration,
};
use super::runtime::{
    create_runtime_enrollment, inspect_runtime_runner, list_runtime_runners,
    revoke_runtime_credential, revoke_runtime_credential_legacy, runtime_certificate,
    runtime_complete, runtime_enroll, runtime_heartbeat, runtime_inventory, runtime_self_release,
    runtime_work,
};

pub(super) struct AppState {
    pub(super) config: ServerConfig,
    pub(super) reconciler: Arc<dyn ReconcilePort>,
    pub(super) store: Arc<dyn OperationalStore>,
    pub(super) tenant_store: Option<Arc<dyn TenantOperationalStore>>,
    pub(super) management: Arc<ManagementOperations>,
    pub(super) runtime_delivery: Arc<RuntimeDeliveryOperations>,
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub(super) struct ServiceStatus {
    pub(super) status: &'static str,
    /// This server's version (#761).
    pub(super) version: &'static str,
    /// The worst status of the host's certificates (#676), when any are
    /// configured. It never fails readiness; `GET /v1/trust` has details.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = tenkai::schema_contract::omitted_when_none)]
    pub(super) trust: Option<tenkai::trust_posture::TrustStatus>,
    pub(super) profile: String,
    pub(super) capabilities: Vec<String>,
    /// API contract ids this server serves, for client compatibility checks.
    pub(super) contracts: Vec<&'static str>,
    /// `configured` when a grant rule gives fleet management, else `missing`
    /// (#815), for a console's first-run screen. Never names a rule. Absent
    /// while the server is still opening.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = tenkai::schema_contract::omitted_when_none)]
    pub(super) first_administrator: Option<tenkai::oidc_verifier::FirstAdministrator>,
    /// Backup age when backups are configured. `stale` or `missing` degrades
    /// health without failing readiness: the server can still do its work.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = tenkai::schema_contract::omitted_when_none)]
    pub(super) backup: Option<tenkai::backup::BackupHealth>,
    /// Clock skew against the configured time source. `refuse` blocks
    /// approvals, applies and runtime lease claims; readiness stays up.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = tenkai::schema_contract::omitted_when_none)]
    pub(super) clock: Option<tenkai::clock_guard::ClockHealth>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
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
    let mut runtime_delivery = RuntimeDeliveryOperations::new(
        config.runtime_assignments.clone(),
        reconciler.clone(),
        store.clone(),
    );
    if let Some(ca) = &config.runner_ca {
        runtime_delivery = runtime_delivery.with_runner_ca(ca.clone());
    }
    let runtime_delivery = Arc::new(runtime_delivery);
    let package_migration_trust_roots = match &config.package_migration_trust_roots {
        Some(path) => Some(tenkai::package_migration::load_trust_roots(path)?),
        None => None,
    };
    // Loaded once here, unlike the roots verifiers read per use, so
    // `/v1/trust` shows what is in force beside the file (#811).
    let mut config = config;
    if let Some(roots) = &package_migration_trust_roots {
        config
            .trust_sources
            .loaded_signing
            .push(tenkai::trust_posture::LoadedSigning {
                purpose: "package_migration_approval".into(),
                name: "package migration trust roots in use".into(),
                signers: roots
                    .signers
                    .iter()
                    .map(|signer| tenkai::trust_posture::LoadedSigner {
                        key_id: signer.key_id.clone(),
                        identity: signer.identity.clone(),
                        not_before: signer.not_before,
                        not_after: signer.not_after,
                    })
                    .collect(),
            });
    }
    let management = Arc::new(
        ManagementOperations::new(
            auth,
            config.requirements.tenant_mode,
            reconciler.clone(),
            store.clone(),
            config.tenant_store.clone(),
            package_migration_trust_roots,
            config.release_trust_roots.clone(),
            config.environment_management_assignments.clone(),
        )
        .with_agent_actor_policy(config.agent_actor_policy)
        .with_static_runtime_runners(&config.runtime_assignments)
        .with_runner_certificates_admitted(config.runner_certificates_admitted),
    );
    refresh_trust_status(&config);
    let mut router = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/auth/oidc", get(oidc_client))
        .route("/v1/reconcile", post(reconcile))
        .route("/v1/fleet/status", get(fleet_status))
        .route("/v1/backups", get(backup_status).post(take_backup))
        .route(
            "/v1/grant-rules",
            get(list_grant_rules)
                .post(create_grant_rule)
                .delete(remove_grant_rule),
        )
        .route("/v1/exports", get(list_exports).post(create_export))
        .route("/v1/exports/{id}", get(inspect_export))
        .route("/v1/exports/{id}/download", get(download_export))
        .route("/v1/imports", get(import_jobs).post(import_bundle))
        .route("/v1/imports/staged", get(staged_imports))
        .route("/v1/imports/{id}", get(import_job))
        .route("/v1/content/inventory", get(content_inventory))
        .route("/v1/trust", get(trust_posture))
        .route("/v1/trust/runway", get(trust_runway))
        .route("/v1/webhooks/deliveries", get(host_webhook_deliveries))
        .route(
            "/v1/environments/{environment}/webhooks/deliveries",
            get(environment_webhook_deliveries),
        )
        .route("/v1/events", get(change_events))
        .route(
            "/v1/environments",
            get(list_environments).post(register_environment),
        )
        .route("/v1/releases", get(list_releases).post(publish_release))
        .route("/v1/exposures", get(query_exposures))
        .route("/v1/advisory-feed", get(inspect_advisory_feed))
        .route("/v1/criticality/derived", post(import_derived_criticality))
        .route("/v1/channels", get(list_channels))
        .route("/v1/migrations", get(list_migrations))
        .route(
            "/v1/environments/{environment}/compatibility/evidence",
            post(record_software_compatibility_evidence),
        )
        .route(
            "/v1/environments/{environment}/compatibility/{release}",
            get(software_compatibility_report),
        )
        .route("/v1/environments/{environment}", get(inspect_environment))
        .route(
            "/v1/environments/{environment}/status",
            get(environment_status),
        )
        .route(
            "/v1/environments/{environment}/approval-policy",
            get(environment_approval_policy)
                .put(configure_approval_policy)
                .delete(configure_approval_policy),
        )
        .route(
            "/v1/environments/{environment}/facts",
            put(configure_facts).delete(configure_facts),
        )
        .route(
            "/v1/environments/{environment}/runner-attestation",
            put(configure_runner_attestation).delete(configure_runner_attestation),
        )
        .route(
            "/v1/environments/{environment}/criticality",
            put(configure_criticality).delete(configure_criticality),
        )
        .route(
            "/v1/products/{product}/criticality",
            get(inspect_product_criticality)
                .put(set_product_criticality)
                .delete(clear_product_criticality),
        )
        .route(
            "/v1/environments/{environment}/constraints",
            put(configure_constraints).delete(configure_constraints),
        )
        .route(
            "/v1/environments/{environment}/maintenance-windows/{window}",
            put(configure_maintenance_window).delete(configure_maintenance_window),
        )
        .route(
            "/v1/environments/{environment}/webhooks",
            put(configure_webhooks).delete(configure_webhooks),
        )
        .route(
            "/v1/environments/{environment}/runtime",
            get(observed_runtime),
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
        .route("/v1/channels/{channel}/promote", post(promote_release))
        .route(
            "/v1/model-evaluation/trust",
            post(install_model_evaluation_trust),
        )
        .route(
            "/v1/model-evaluation/evidence",
            post(record_model_evaluation_evidence),
        )
        .route("/v1/releases/{release}/recall", post(recall_release))
        .route(
            "/v1/environments/{environment}/subscriptions",
            post(subscribe_environment),
        )
        .route(
            "/v1/environments/{environment}/retire",
            post(retire_environment),
        )
        .route(
            "/v1/environments/{environment}/plans",
            post(plan_environment),
        )
        .route("/v1/plans/{plan_id}/approvals", get(plan_approvals))
        .route("/v1/plans/{plan_id}/approve", post(approve_plan))
        .route("/v1/plans/{plan_id}/apply", post(apply_plan))
        .route(
            "/v1/environments/{environment}/rollback",
            post(rollback_environment),
        )
        .route(
            "/v1/environments/{environment}/hold",
            get(environment_hold).post(set_environment_hold),
        )
        .route(
            "/v1/environments/{environment}/hold/release",
            post(release_environment_hold),
        )
        .route(
            "/v1/environments/{environment}/failed-targets/{product}/retry",
            post(retry_failed_target),
        )
        .route(
            "/v1/products/{product}/channels/{channel}/hold",
            get(channel_hold).post(set_channel_hold),
        )
        .route(
            "/v1/products/{product}/channels/{channel}/hold/release",
            post(release_channel_hold),
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
        )
        .route(
            "/v1/runtime/environments/{environment}/self-release",
            post(runtime_self_release),
        )
        .route(
            "/v1/runtime/environments/{environment}/enroll",
            post(runtime_enroll),
        )
        .route(
            "/v1/runtime/environments/{environment}/certificate",
            post(runtime_certificate),
        )
        .route(
            "/v1/environments/{environment}/runtime-enrollments",
            post(create_runtime_enrollment),
        )
        .route(
            "/v1/runtime-credentials/{credential_id}/revoke",
            post(revoke_runtime_credential_legacy),
        )
        .route("/v1/runners", get(list_runtime_runners))
        .route("/v1/runners/{credential_id}", get(inspect_runtime_runner))
        .route(
            "/v1/runners/{credential_id}/revoke",
            post(revoke_runtime_credential),
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

/// Keep `config.trust_status` current: computed now, then every minute on a
/// blocking thread, so health probes read a snapshot and never trust files.
fn refresh_trust_status(config: &ServerConfig) {
    if config.trust_sources.is_empty() {
        return;
    }
    let compute = {
        let sources = config.trust_sources.clone();
        move || tenkai::trust_posture::posture(&sources, tenkai::now_millis() / 1_000).snapshot()
    };
    if let Ok(mut status) = config.trust_status.write() {
        *status = Some(compute());
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let snapshot = Arc::downgrade(&config.trust_status);
    runtime.spawn(async move {
        let mut ticks = tokio::time::interval(std::time::Duration::from_secs(60));
        ticks.tick().await;
        loop {
            ticks.tick().await;
            // Stops once the server, and with it the snapshot, is gone.
            let Some(target) = snapshot.upgrade() else {
                return;
            };
            if let Ok(status) = tokio::task::spawn_blocking(compute.clone()).await
                && let Ok(mut current) = target.write()
            {
                *current = Some(status);
            }
        }
    });
}
