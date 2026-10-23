//! Published HTTP API contract (#471).
//!
//! [`http_contract`] renders every public `/v1` route plus health and OIDC
//! discovery as one JSON Schema document: `routes` lists method, path,
//! required capability, and request/response types; `$defs` holds the schemas
//! derived from the same serde types the handlers use. The checked-in copy at
//! `api/tenkai-http-v1.schema.json` must match (see the drift test), and each
//! release attaches it so clients such as the web console generate types.
//! The pull runtime (`/v1/runtime/*`) is excluded; its contract is
//! `proto/tenkai/runtime/v1` and `docs/runtime-protocol-v1.md`.

use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, SchemaGenerator};
use serde_json::{Value, json};

use super::router::{ErrorBody, ServiceStatus};
use tenkai::approval_policy::EffectiveApprovalPolicy;
use tenkai::backup::{BackupManifest, BackupStatus};
use tenkai::catalog::{ChannelPage, ReleasePage};
use tenkai::change_stream::ChangeEventPage;
use tenkai::content_inventory::ContentInventory;
use tenkai::delivery_hold::DeliveryHoldView;
use tenkai::environment::{EnvironmentInspectReport, EnvironmentListEntry, StatusRow};
use tenkai::environment_config::{EnvironmentConfigRequest, RegisterEnvironmentRequest};
use tenkai::fleet::FleetStatusReport;
use tenkai::management_lifecycle::{
    ApplyRequest, ApproveRequest, ChannelHoldRequest, DeliveryHoldRequest,
    ManagementLifecycleResult, PlanRequest, PromoteRequest, PublishRequest, RecallRequest,
    RetireEnvironmentRequest, RetryFailedTargetRequest, RollbackRequest, SubscribeRequest,
};
use tenkai::observed_runtime::EnvironmentRuntimeReport;
use tenkai::offline_import::{ImportJob, ImportRequest, StagedBundle};
use tenkai::oidc_verifier::OidcClientDiscovery;
use tenkai::package_migration::{
    MigrationPage, PackageMigrationApplyRequest, PackageMigrationMutateRequest,
    PackageMigrationPreviewRequest, PackageMigrationResult,
};
use tenkai::page::PageQuery;
use tenkai::reconciler::TickReport;

/// Contract id for this document; additive changes keep it.
pub const HTTP_CONTRACT_ID: &str = "tenkai.http.v1";

/// Contract ids `/healthz` advertises so clients can check compatibility.
pub const SERVED_CONTRACTS: &[&str] = &[HTTP_CONTRACT_ID, "tenkai.management-lifecycle.v1"];

enum Auth {
    None,
    Read,
    Management,
    Publish,
}

struct Route {
    method: &'static str,
    path: &'static str,
    auth: Auth,
    request: Option<Value>,
    response: Value,
}

pub use tenkai::schema_contract::omitted_when_none;

fn schema<T: JsonSchema>(generator: &mut SchemaGenerator) -> Value {
    generator.subschema_for::<T>().to_value()
}

/// The full contract document, deterministic for a given build.
pub fn http_contract() -> Value {
    let mut g = SchemaSettings::draft2020_12().into_generator();
    let lifecycle = schema::<ManagementLifecycleResult>(&mut g);
    let config = schema::<EnvironmentConfigRequest>(&mut g);
    let migration = schema::<PackageMigrationResult>(&mut g);
    let status = schema::<ServiceStatus>(&mut g);
    let routes = vec![
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/compatibility/{release}",
            auth: Auth::Read,
            request: None,
            response: schema::<Option<tenkai::software_compatibility::CompatibilityReport>>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/compatibility/evidence",
            auth: Auth::Management,
            request: Some(schema::<
                tenkai::software_compatibility::CompatibilityEvidence,
            >(&mut g)),
            response: schema::<()>(&mut g),
        },
        Route {
            method: "GET",
            path: "/healthz",
            auth: Auth::None,
            request: None,
            response: status.clone(),
        },
        Route {
            method: "GET",
            path: "/readyz",
            auth: Auth::None,
            request: None,
            response: status,
        },
        Route {
            method: "GET",
            path: "/v1/auth/oidc",
            auth: Auth::None,
            request: None,
            response: schema::<OidcClientDiscovery>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/reconcile",
            auth: Auth::Management,
            request: None,
            response: schema::<TickReport>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/fleet/status",
            auth: Auth::Read,
            request: None,
            response: schema::<FleetStatusReport>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/backups",
            auth: Auth::Read,
            request: None,
            response: schema::<BackupStatus>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/backups",
            auth: Auth::Management,
            request: None,
            response: schema::<BackupManifest>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/imports",
            auth: Auth::Management,
            request: Some(schema::<ImportRequest>(&mut g)),
            response: schema::<ImportJob>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/imports/staged",
            auth: Auth::Management,
            request: None,
            response: schema::<Vec<StagedBundle>>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/imports/{id}",
            auth: Auth::Management,
            request: None,
            response: schema::<ImportJob>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/content/inventory",
            auth: Auth::Read,
            request: None,
            response: schema::<ContentInventory>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/events",
            auth: Auth::Read,
            request: None,
            response: schema::<ChangeEventPage>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/environments",
            auth: Auth::Read,
            request: None,
            response: schema::<Vec<EnvironmentListEntry>>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/environments",
            auth: Auth::Management,
            request: Some(schema::<RegisterEnvironmentRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "GET",
            path: "/v1/releases",
            auth: Auth::Read,
            request: Some(schema::<PageQuery>(&mut g)),
            response: schema::<ReleasePage>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/channels",
            auth: Auth::Read,
            request: Some(schema::<PageQuery>(&mut g)),
            response: schema::<ChannelPage>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/migrations",
            auth: Auth::Read,
            request: Some(schema::<PageQuery>(&mut g)),
            response: schema::<MigrationPage>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/environments/{environment}",
            auth: Auth::Read,
            request: None,
            response: schema::<EnvironmentInspectReport>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/status",
            auth: Auth::Read,
            request: None,
            response: schema::<Vec<StatusRow>>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/approval-policy",
            auth: Auth::Read,
            request: None,
            response: schema::<EffectiveApprovalPolicy>(&mut g),
        },
        Route {
            method: "PUT",
            path: "/v1/environments/{environment}/approval-policy",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "DELETE",
            path: "/v1/environments/{environment}/approval-policy",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "PUT",
            path: "/v1/environments/{environment}/facts",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "DELETE",
            path: "/v1/environments/{environment}/facts",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "PUT",
            path: "/v1/environments/{environment}/constraints",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "DELETE",
            path: "/v1/environments/{environment}/constraints",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "PUT",
            path: "/v1/environments/{environment}/maintenance-windows/{window}",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "DELETE",
            path: "/v1/environments/{environment}/maintenance-windows/{window}",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "PUT",
            path: "/v1/environments/{environment}/webhooks",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "DELETE",
            path: "/v1/environments/{environment}/webhooks",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/runtime",
            auth: Auth::Read,
            request: None,
            response: schema::<EnvironmentRuntimeReport>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/subscriptions",
            auth: Auth::Management,
            request: Some(schema::<SubscribeRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/retire",
            auth: Auth::Management,
            request: Some(schema::<RetireEnvironmentRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/plans",
            auth: Auth::Management,
            request: Some(schema::<PlanRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/rollback",
            auth: Auth::Management,
            request: Some(schema::<RollbackRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/hold",
            auth: Auth::Read,
            request: None,
            response: schema::<DeliveryHoldView>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/hold",
            auth: Auth::Management,
            request: Some(schema::<DeliveryHoldRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/hold/release",
            auth: Auth::Management,
            request: Some(schema::<DeliveryHoldRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/failed-targets/{product}/retry",
            auth: Auth::Management,
            request: Some(schema::<RetryFailedTargetRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "GET",
            path: "/v1/products/{product}/channels/{channel}/hold",
            auth: Auth::Read,
            request: None,
            response: schema::<DeliveryHoldView>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/products/{product}/channels/{channel}/hold",
            auth: Auth::Management,
            request: Some(schema::<ChannelHoldRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/products/{product}/channels/{channel}/hold/release",
            auth: Auth::Management,
            request: Some(schema::<ChannelHoldRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/plans/{plan_id}/approve",
            auth: Auth::Management,
            request: Some(schema::<ApproveRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/plans/{plan_id}/apply",
            auth: Auth::Management,
            request: Some(schema::<ApplyRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/releases",
            auth: Auth::Publish,
            request: Some(schema::<PublishRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/releases/{release}/recall",
            auth: Auth::Management,
            request: Some(schema::<RecallRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/channels/{channel}/promote",
            auth: Auth::Publish,
            request: Some(schema::<PromoteRequest>(&mut g)),
            response: lifecycle,
        },
        Route {
            method: "POST",
            path: "/v1/model-evaluation/trust",
            auth: Auth::Management,
            request: Some(schema::<tenkai::model_release_evidence::EvaluationTrustRoots>(&mut g)),
            response: schema::<()>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/model-evaluation/evidence",
            auth: Auth::Publish,
            request: Some(schema::<
                tenkai::model_release_evidence::ModelEvaluationEvidence,
            >(&mut g)),
            response: schema::<()>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/migrations/{name}",
            auth: Auth::Read,
            request: None,
            response: migration.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/migrations/{name}/preview",
            auth: Auth::Read,
            request: Some(schema::<PackageMigrationPreviewRequest>(&mut g)),
            response: migration.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/migrations/{name}/apply",
            auth: Auth::Management,
            request: Some(schema::<PackageMigrationApplyRequest>(&mut g)),
            response: migration.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/migrations/{name}/resume",
            auth: Auth::Management,
            request: Some(schema::<PackageMigrationMutateRequest>(&mut g)),
            response: migration.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/migrations/{name}/rollback",
            auth: Auth::Management,
            request: Some(schema::<PackageMigrationMutateRequest>(&mut g)),
            response: migration,
        },
    ];
    let error = schema::<ErrorBody>(&mut g);
    let routes: Vec<Value> = routes
        .into_iter()
        .map(|route| {
            json!({
                "method": route.method,
                "path": route.path,
                "auth": match route.auth {
                    Auth::None => "none",
                    Auth::Read => "read",
                    Auth::Management => "management",
                    Auth::Publish => "publish",
                },
                "request": route.request,
                "response": route.response,
            })
        })
        .collect();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": HTTP_CONTRACT_ID,
        "title": "Tenkai HTTP API",
        "description": "Routes, required delivery capability, and request/response schemas. Non-2xx responses carry `error`.",
        "routes": routes,
        "error": error,
        "$defs": g.take_definitions(true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Response fields the server omits when unset are optional, never `null`.
    #[test]
    fn omitted_optionals_do_not_admit_null() {
        let contract = http_contract();
        let defs = &contract["$defs"];
        for (def, field) in [
            ("OidcClientDiscovery", "display_name"),
            ("ServiceStatus", "backup"),
            ("ServiceStatus", "clock"),
            ("ClockHealth", "skew_ms"),
            ("ClockHealth", "measured_at_ms"),
            ("StagedBundle", "environment"),
            ("StagedBundle", "plan_id"),
            ("StagedBundle", "expires_at_ms"),
            ("StagedBundle", "unreadable"),
            ("ImportJob", "finished_at_ms"),
            ("ImportJob", "preview"),
            ("ImportJob", "refusal"),
            ("ContentInventory", "oci_store_bytes"),
            ("ContentInventory", "weight_cache_bytes"),
            ("ContentItem", "stored"),
            ("ContentItem", "size_bytes"),
            ("BackupStatus", "last_success"),
            ("BackupStatus", "last_failure"),
            ("BackupStatus", "last_drill"),
            ("BackupHealth", "age_seconds"),
            ("EnvironmentInspectReport", "maintenance"),
            ("EnvironmentInspectReport", "observed_type_digest"),
            ("EnvironmentInspectReport", "preview"),
            ("EnvironmentInspectReport", "retirement"),
            ("EnvironmentInspectReport", "delivery_hold"),
            ("EnvironmentSubscriptionView", "delivery_hold"),
            ("StatusRow", "delivery_hold"),
            ("DeliveryHoldView", "hold"),
            ("ChannelListEntry", "hold"),
            ("EnvironmentMaintenanceInspect", "open_until_ms"),
            ("EnvironmentMaintenanceInspect", "next_opens_at_ms"),
            ("EnvironmentMaintenanceInspect", "detail"),
            ("EnvironmentMaintenanceWindow", "next_opens_at_ms"),
            ("EnvironmentPlanSummary", "digest"),
            ("EnvironmentPlanSummary", "approval"),
            ("EffectiveApprovalPolicy", "ttl_ms"),
            ("EffectiveApprovalPolicy", "digest"),
            ("PlanApprovalView", "reason"),
            ("PlanApprovalView", "policy_provider"),
            ("ManagementLifecycleResult", "resource"),
            ("MigrationRecord", "pending_plan_id"),
            ("ChangeEvent", "environment"),
            ("ReleasePage", "next_cursor"),
            ("ChannelPage", "next_cursor"),
            ("MigrationPage", "next_cursor"),
            ("ObservedRuntimeComponent", "health"),
            ("ObservedRuntimeComponent", "last_init_job"),
            ("ObservedRuntimeComponent", "model_runtime"),
            ("ObservedRuntimeUnit", "health"),
            ("ObservedInitJob", "exit_code"),
            ("ObservedModelRuntime", "accelerator"),
        ] {
            let property = &defs[def]["properties"][field];
            assert!(property.is_object(), "{def}.{field} missing");
            assert!(
                !property.to_string().contains("\"null\""),
                "{def}.{field} admits null: {property}"
            );
            let required = defs[def]["required"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert!(
                !required.contains(&json!(field)),
                "{def}.{field} is required"
            );
        }
        assert_eq!(
            defs["EnvironmentInspectReport"]["properties"]["maintenance"]["$ref"],
            "#/$defs/EnvironmentMaintenanceInspect"
        );
        assert_eq!(
            defs["OidcClientDiscovery"]["properties"]["display_name"]["type"],
            "string"
        );
        // Shared with requests, where serde accepts `null`.
        assert!(
            defs["CheckpointDecl"]["properties"]["pre_admission"]
                .to_string()
                .contains("\"null\"")
        );
    }

    #[test]
    fn change_event_shapes_are_in_the_contract() {
        let contract = http_contract();
        let kinds = contract["$defs"]["ChangeEventKind"]["enum"]
            .as_array()
            .expect("ChangeEventKind enum");
        for kind in tenkai::change_stream::ChangeEventKind::ALL {
            assert!(
                kinds.iter().any(|value| value == kind.as_str()),
                "missing kind {}",
                kind.as_str()
            );
        }
        assert_eq!(
            kinds.len(),
            tenkai::change_stream::ChangeEventKind::ALL.len()
        );
        let routes = contract["routes"].as_array().expect("routes");
        assert!(routes.iter().any(|route| {
            route["method"] == "GET" && route["path"] == "/v1/events" && route["auth"] == "read"
        }));
        assert_eq!(
            contract["$defs"]["ChangeEventPage"]["properties"]["events"]["items"]["$ref"],
            "#/$defs/ChangeEvent"
        );
    }

    const CHECKED_IN: &str = include_str!("../../../api/tenkai-http-v1.schema.json");

    /// Fails when a route type changes without regenerating the contract.
    /// Regenerate with `make update` (sets TENKAI_UPDATE_API_CONTRACT=1).
    #[test]
    fn checked_in_contract_matches_the_code() {
        let rendered = format!("{:#}\n", http_contract());
        if std::env::var_os("TENKAI_UPDATE_API_CONTRACT").is_some() {
            std::fs::write(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../api/tenkai-http-v1.schema.json"
                ),
                &rendered,
            )
            .unwrap();
            return;
        }
        assert!(
            rendered == CHECKED_IN,
            "api/tenkai-http-v1.schema.json is stale; run `make update`"
        );
    }
}
