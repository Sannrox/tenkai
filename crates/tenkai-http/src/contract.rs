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
use tenkai::criticality::{
    DerivedEnvelope, DerivedImportResult, EffectiveCriticality, SetCriticalityRequest,
};
use tenkai::delivery_hold::DeliveryHoldView;
use tenkai::deployment_history::{DeploymentHistoryPage, DeploymentHistoryQuery};
use tenkai::environment::{EnvironmentInspectReport, EnvironmentListEntry, StatusRow};
use tenkai::environment_config::{EnvironmentConfigRequest, RegisterEnvironmentRequest};
use tenkai::environment_dependencies::EnvironmentDependencies;
use tenkai::exposure::{AdvisoryFeedStatus, ExposureQueryRequest, ExposureQueryResult};
use tenkai::fleet::FleetStatusReport;
use tenkai::host_identity::AuthSession;
use tenkai::instance_explain::InstanceExplainReport;
use tenkai::management_lifecycle::{
    ApplyRequest, ApproveRequest, ChannelAdmitRequest, ChannelConfigureRequest,
    ChannelExposureGraceRequest, ChannelHoldRequest, ChannelRemoveRequest,
    DeliveryFailureThresholdRequest, DeliveryFreezeRequest, DeliveryHoldRequest,
    ExposureGraceRequest, ExposureWaiverClearRequest, ExposureWaiverRequest,
    ManagementLifecycleResult, PlanRequest, PromoteHttpRequest, PublishRequest,
    RecallRangeCloseRequest, RecallRangeRequest, RecallRequest, RetireEnvironmentRequest,
    RetryFailedTargetRequest, RollbackRequest, SubscribeRequest, UnsubscribeRequest,
};
use tenkai::observed_runtime::EnvironmentRuntimeReport;
use tenkai::offline_import::{ImportJob, ImportJobList, ImportRequest, StagedBundle};
use tenkai::oidc_verifier::OidcClientDiscovery;
use tenkai::operational_events::WebhookDelivery;
use tenkai::package_migration::{
    MigrationPage, PackageMigrationApplyRequest, PackageMigrationMutateRequest,
    PackageMigrationPreviewRequest, PackageMigrationResult,
};
use tenkai::page::PageQuery;
use tenkai::plan_approval::PlanApprovalsView;
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
            response: schema::<Option<tenkai::software_compatibility::CompatibilityOutcome>>(
                &mut g,
            ),
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
            method: "GET",
            path: "/v1/auth/me",
            auth: Auth::Read,
            request: None,
            response: schema::<AuthSession>(&mut g),
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
        // Stored grant rules (#837): fleet management only.
        Route {
            method: "GET",
            path: "/v1/grant-rules",
            auth: Auth::Management,
            request: None,
            response: schema::<tenkai::management_operations::GrantRuleList>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/grant-rules",
            auth: Auth::Management,
            request: Some(schema::<
                tenkai::management_operations::CreateGrantRuleRequest,
            >(&mut g)),
            response: schema::<tenkai::management_operations::GrantRuleList>(&mut g),
        },
        Route {
            method: "DELETE",
            path: "/v1/grant-rules",
            auth: Auth::Management,
            request: Some(schema::<
                tenkai::management_operations::RemoveGrantRuleRequest,
            >(&mut g)),
            response: schema::<tenkai::management_operations::GrantRuleList>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/exports",
            auth: Auth::Management,
            request: Some(schema::<tenkai::management_operations::ExportRequest>(
                &mut g,
            )),
            response: schema::<tenkai::exports::ExportEntry>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/exports",
            auth: Auth::Management,
            request: None,
            response: schema::<tenkai::exports::ExportList>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/exports/{id}",
            auth: Auth::Management,
            request: None,
            response: schema::<tenkai::exports::ExportEntry>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/exports/{id}/download",
            auth: Auth::Management,
            request: None,
            // Takes a required `reason` query parameter. Answers the stored
            // artifact in its own format: support bundle, audit export,
            // recovery bundle or offline receipt.
            response: schema::<serde_json::Value>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/imports",
            auth: Auth::Management,
            request: None,
            response: schema::<ImportJobList>(&mut g),
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
            path: "/v1/webhooks/deliveries",
            auth: Auth::Read,
            request: None,
            response: schema::<Vec<WebhookDelivery>>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/webhooks/deliveries",
            auth: Auth::Read,
            request: None,
            response: schema::<Vec<WebhookDelivery>>(&mut g),
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
            path: "/v1/exposures",
            auth: Auth::Read,
            request: Some(schema::<ExposureQueryRequest>(&mut g)),
            response: schema::<ExposureQueryResult>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/exposures/waivers",
            auth: Auth::Management,
            request: Some(schema::<ExposureWaiverRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/exposures/waivers/clear",
            auth: Auth::Management,
            request: Some(schema::<ExposureWaiverClearRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "GET",
            path: "/v1/advisory-feed",
            auth: Auth::Read,
            request: None,
            response: schema::<AdvisoryFeedStatus>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/criticality/derived",
            auth: Auth::Management,
            request: Some(schema::<DerivedEnvelope>(&mut g)),
            response: schema::<DerivedImportResult>(&mut g),
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
            path: "/v1/environments/{environment}/instances/{instance}/explain",
            auth: Auth::Read,
            request: None,
            response: schema::<InstanceExplainReport>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/dependencies",
            auth: Auth::Read,
            request: None,
            response: schema::<EnvironmentDependencies>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/history",
            auth: Auth::Read,
            request: Some(schema::<DeploymentHistoryQuery>(&mut g)),
            response: schema::<DeploymentHistoryPage>(&mut g),
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
            path: "/v1/environments/{environment}/runner-attestation",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "DELETE",
            path: "/v1/environments/{environment}/runner-attestation",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "PUT",
            path: "/v1/environments/{environment}/criticality",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "DELETE",
            path: "/v1/environments/{environment}/criticality",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "GET",
            path: "/v1/products/{product}/criticality",
            auth: Auth::Read,
            request: None,
            response: schema::<EffectiveCriticality>(&mut g),
        },
        Route {
            method: "PUT",
            path: "/v1/products/{product}/criticality",
            auth: Auth::Management,
            request: Some(schema::<SetCriticalityRequest>(&mut g)),
            response: schema::<EffectiveCriticality>(&mut g),
        },
        Route {
            method: "DELETE",
            path: "/v1/products/{product}/criticality",
            auth: Auth::Management,
            request: None,
            response: schema::<EffectiveCriticality>(&mut g),
        },
        Route {
            method: "PUT",
            path: "/v1/environments/{environment}/facts",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "PUT",
            path: "/v1/environments/{environment}/bindings",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "DELETE",
            path: "/v1/environments/{environment}/bindings",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        // `?sealed=true` adds each value's ciphertext and wraps for
        // `secret recover` (ADR 0045 §7) and needs management auth.
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/sealed-secrets",
            auth: Auth::Read,
            request: None,
            response: schema::<tenkai::sealed_secret::SealedSecretList>(&mut g),
        },
        Route {
            method: "PUT",
            path: "/v1/environments/{environment}/sealed-secrets",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "DELETE",
            path: "/v1/environments/{environment}/sealed-secrets",
            auth: Auth::Management,
            request: Some(config.clone()),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/sealed-secrets/rewrap",
            auth: Auth::Management,
            request: Some(schema::<tenkai::management_lifecycle::SealedRewrapRequest>(
                &mut g,
            )),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/identity-issuer/prepare",
            auth: Auth::Management,
            request: Some(schema::<PlanRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/identity-issuer/plan",
            auth: Auth::Management,
            request: Some(schema::<PlanRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/identity-issuer/rewrap",
            auth: Auth::Management,
            request: Some(schema::<tenkai::management_lifecycle::SealedRewrapRequest>(
                &mut g,
            )),
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
            method: "DELETE",
            path: "/v1/environments/{environment}/subscriptions/{product}",
            auth: Auth::Management,
            request: Some(schema::<UnsubscribeRequest>(&mut g)),
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
            path: "/v1/environments/{environment}/apply/cancel",
            auth: Auth::Management,
            request: Some(schema::<DeliveryHoldRequest>(&mut g)),
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
            path: "/v1/environments/{environment}/hold/schedule",
            auth: Auth::Management,
            request: Some(schema::<DeliveryFreezeRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/hold/cancel",
            auth: Auth::Management,
            request: Some(schema::<DeliveryFreezeRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/hold/threshold",
            auth: Auth::Management,
            request: Some(schema::<DeliveryFailureThresholdRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/hold/threshold/clear",
            auth: Auth::Management,
            request: Some(schema::<DeliveryFailureThresholdRequest>(&mut g)),
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
            method: "POST",
            path: "/v1/environments/{environment}/exposure-grace",
            auth: Auth::Management,
            request: Some(schema::<ExposureGraceRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/environments/{environment}/runtime-enrollments",
            auth: Auth::Management,
            request: Some(schema::<
                tenkai::management_operations::RuntimeEnrollmentRequest,
            >(&mut g)),
            response: schema::<tenkai::management_operations::RuntimeEnrollmentIssued>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/runtime-credentials/{credential_id}/revoke",
            auth: Auth::Management,
            request: None,
            response: schema::<tenkai::management_operations::RuntimeCredentialRevoked>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/trust",
            auth: Auth::Read,
            request: None,
            response: schema::<tenkai::trust_posture::TrustPosture>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/trust/runway",
            auth: Auth::Read,
            request: None,
            response: schema::<tenkai::trust_posture::PlanRunways>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/runners",
            auth: Auth::Management,
            request: None,
            response: schema::<tenkai::management_operations::RuntimeRunnerList>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/environments/{environment}/recipient-keys",
            auth: Auth::Read,
            request: None,
            response: schema::<tenkai::management_operations::EnvironmentRecipients>(&mut g),
        },
        Route {
            method: "GET",
            path: "/v1/runners/{credential_id}",
            auth: Auth::Management,
            request: None,
            response: schema::<tenkai::management_operations::RuntimeRunner>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/runners/{credential_id}/revoke",
            auth: Auth::Management,
            request: Some(schema::<tenkai::management_operations::RuntimeRevokeRequest>(&mut g)),
            response: schema::<tenkai::management_operations::RuntimeCredentialRevoked>(&mut g),
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
            path: "/v1/products/{product}/channels/{channel}/remove",
            auth: Auth::Publish,
            request: Some(schema::<ChannelRemoveRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/products/{product}/channels/{channel}/pace",
            auth: Auth::Management,
            request: Some(schema::<ChannelConfigureRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/products/{product}/channels/{channel}/admit",
            auth: Auth::Management,
            request: Some(schema::<ChannelAdmitRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/products/{product}/channels/{channel}/exposure-grace",
            auth: Auth::Management,
            request: Some(schema::<ChannelExposureGraceRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "GET",
            path: "/v1/plans/{plan_id}/approvals",
            auth: Auth::Read,
            request: None,
            response: schema::<PlanApprovalsView>(&mut g),
        },
        Route {
            method: "POST",
            path: "/v1/plans/{plan_id}/approve",
            auth: Auth::Management,
            request: Some(schema::<ApproveRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        // `?steps=true` adds one result per step to the response, and to a
        // refusal's 422 body (`ApplyFailedBody`) (#1076).
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
            path: "/v1/products/{product}/recall-range",
            auth: Auth::Management,
            request: Some(schema::<RecallRangeRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/products/{product}/recall-range/close",
            auth: Auth::Management,
            request: Some(schema::<RecallRangeCloseRequest>(&mut g)),
            response: lifecycle.clone(),
        },
        Route {
            method: "POST",
            path: "/v1/channels/{channel}/promote",
            auth: Auth::Publish,
            request: Some(schema::<PromoteHttpRequest>(&mut g)),
            response: lifecycle,
        },
        Route {
            method: "POST",
            path: "/v1/model-evaluation/trust",
            auth: Auth::Management,
            request: Some(schema::<tenkai::release_signing::TrustRoots>(&mut g)),
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
    use std::collections::BTreeSet;

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
            ("WebhookDelivery", "delivered_at"),
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
            ("EnvironmentSubscriptionView", "spec_drift"),
            ("StatusRow", "delivery_hold"),
            ("StatusRow", "dependency_hold"),
            ("StatusRow", "spec_drift"),
            ("SpecDriftView", "objects"),
            ("SpecDriftObject", "fields"),
            ("ProductDependencyView", "version"),
            ("ProductImpact", "remove"),
            ("ProductImpact", "upgrade"),
            ("ProductImpact", "rollback"),
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

    /// Response-only types that still refuse unknown fields, and why.
    /// Every other result accepts them, so a newer server can add a field
    /// without breaking older clients (#1172). Requests stay strict.
    const STRICT_RESPONSE_TYPES: &[(&str, &str)] = &[
        (
            "BackupStatus",
            "status.json, which backup runs read and rewrite",
        ),
        ("BackupFailure", "part of status.json"),
        (
            "BackupManifest",
            "the stored backup manifest a restore verifies",
        ),
        (
            "DrillEvidence",
            "keeps the signed drill statement bytes exactly",
        ),
        (
            "ImportJob",
            "the import job file, which import steps rewrite",
        ),
        (
            "ScanEvidence",
            "scanner output stored in the import job file",
        ),
        ("ExportEvent", "the export audit trail"),
        (
            "MigrationRecord",
            "the stored, digest-bound migration record",
        ),
        ("CheckpointReceipt", "part of the migration record"),
        (
            "ModuleActivationReceipt",
            "digest-bound by its receipt_digest",
        ),
        (
            "QuorumRule",
            "the approval policy file a plan is approved against",
        ),
    ];

    /// The `$defs` names `roots` reach, following `$ref`s.
    fn reachable(defs: &Value, roots: impl IntoIterator<Item = Value>) -> BTreeSet<String> {
        fn refs(value: &Value, out: &mut Vec<String>) {
            match value {
                Value::Object(map) => {
                    if let Some(Value::String(target)) = map.get("$ref") {
                        out.extend(target.rsplit('/').next().map(str::to_string));
                    }
                    map.values().for_each(|value| refs(value, out));
                }
                Value::Array(items) => items.iter().for_each(|value| refs(value, out)),
                _ => {}
            }
        }
        let mut todo = Vec::new();
        roots.into_iter().for_each(|root| refs(&root, &mut todo));
        let mut seen = BTreeSet::new();
        while let Some(name) = todo.pop() {
            if seen.insert(name.clone()) {
                refs(&defs[&name], &mut todo);
            }
        }
        seen
    }

    /// A result type refuses unknown fields only with a recorded reason, so
    /// adding a response field stays additive.
    #[test]
    fn results_accept_unknown_fields_unless_recorded() {
        let contract = http_contract();
        let defs = &contract["$defs"];
        let routes = contract["routes"].as_array().expect("routes");
        let responses = reachable(defs, routes.iter().map(|route| route["response"].clone()));
        let requests = reachable(defs, routes.iter().map(|route| route["request"].clone()));
        let strict: BTreeSet<&str> = responses
            .difference(&requests)
            .filter(|name| defs[name.as_str()]["additionalProperties"] == json!(false))
            .map(String::as_str)
            .collect();
        let recorded: BTreeSet<&str> = STRICT_RESPONSE_TYPES
            .iter()
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(
            strict, recorded,
            "record why a result refuses unknown fields, or drop the entry"
        );
        for result in ["ManagementLifecycleResult", "PackageMigrationResult"] {
            assert_ne!(
                defs[result]["additionalProperties"],
                json!(false),
                "{result}"
            );
        }
    }

    /// An older client decodes a result from a newer server that added a
    /// field, and keeps the fields it knows.
    #[test]
    fn a_result_with_an_added_field_still_decodes() {
        let lifecycle: tenkai::management_lifecycle::ManagementLifecycleResult =
            serde_json::from_value(json!({
                "version": 1,
                "operation": "promote",
                "message": "promoted",
                "digest": "sha256:aa",
                "added_later": {"any": "shape"},
            }))
            .unwrap();
        assert_eq!(lifecycle.digest.as_deref(), Some("sha256:aa"));
        let request =
            serde_json::from_value::<tenkai::management_lifecycle::PromoteHttpRequest>(json!({
                "version": 1,
                "operation": "promote",
                "spec": "api@1.0.0",
                "added_later": true,
            }));
        assert!(request.is_err(), "requests still refuse unknown fields");
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

    const CHECKED_IN_TERMINAL_OUTCOME: &str =
        include_str!("../../../api/tenkai-terminal-outcome-v2.schema.json");

    /// The terminal-outcome payload schema operators register (#867) lives
    /// beside the HTTP contract so `make update` and the API-contract
    /// validator cover both.
    #[test]
    fn checked_in_terminal_outcome_contract_matches_the_code() {
        let rendered = format!(
            "{:#}\n",
            tenkai::providers::terminal_outcome_payload_schema()
        );
        if std::env::var_os("TENKAI_UPDATE_API_CONTRACT").is_some() {
            std::fs::write(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../api/tenkai-terminal-outcome-v2.schema.json"
                ),
                &rendered,
            )
            .unwrap();
            return;
        }
        assert!(
            rendered == CHECKED_IN_TERMINAL_OUTCOME,
            "api/tenkai-terminal-outcome-v2.schema.json is stale; run `make update`"
        );
    }

    const CHECKED_IN_FEEDBACK_OBSERVATION: &str =
        include_str!("../../../api/tenkai-feedback-observation-v1.schema.json");

    /// The feedback-observation schema operators register (#1101) lives
    /// beside the HTTP contract so `make update` and the API-contract
    /// validator cover it.
    #[test]
    fn checked_in_feedback_observation_contract_matches_the_code() {
        let rendered = format!(
            "{:#}\n",
            tenkai::feedback_observation::feedback_observation_schema()
        );
        if std::env::var_os("TENKAI_UPDATE_API_CONTRACT").is_some() {
            std::fs::write(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../api/tenkai-feedback-observation-v1.schema.json"
                ),
                &rendered,
            )
            .unwrap();
            return;
        }
        assert!(
            rendered == CHECKED_IN_FEEDBACK_OBSERVATION,
            "api/tenkai-feedback-observation-v1.schema.json is stale; run `make update`"
        );
    }
}
