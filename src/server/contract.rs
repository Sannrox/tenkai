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
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde_json::{Value, json};

use super::router::{ErrorBody, ServiceStatus};
use crate::environment::{EnvironmentInspectReport, EnvironmentListEntry, StatusRow};
use crate::fleet::FleetStatusReport;
use crate::management_lifecycle::{
    ApplyRequest, ApproveRequest, ManagementLifecycleResult, PlanRequest, PromoteRequest,
    PublishRequest, RecallRequest, RetireEnvironmentRequest, RollbackRequest, SubscribeRequest,
};
use crate::oidc_verifier::OidcClientDiscovery;
use crate::package_migration::{
    PackageMigrationApplyRequest, PackageMigrationMutateRequest, PackageMigrationPreviewRequest,
    PackageMigrationResult,
};
use crate::reconciler::TickReport;

/// Contract id for this document; additive changes keep it.
pub const HTTP_CONTRACT_ID: &str = "tenkai.http.v1";

/// Contract ids `/healthz` advertises so clients can check compatibility.
pub const SERVED_CONTRACTS: &[&str] = &[HTTP_CONTRACT_ID, "tenkai.management-lifecycle.v1"];

enum Auth {
    None,
    Read,
    Management,
}

struct Route {
    method: &'static str,
    path: &'static str,
    auth: Auth,
    request: Option<Value>,
    response: Value,
}

/// Field transform for response-only `Option` fields serialized with
/// `skip_serializing_if = "Option::is_none"`: the wire omits the key and never
/// sends `null`, so the contract must not admit `null` either. The field stays
/// out of `required`. Types also used in requests keep `null`, which serde
/// accepts on input.
pub fn omitted_when_none(schema: &mut Schema) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(Value::Array(types)) = object.get_mut("type") {
        types.retain(|kind| kind != "null");
        if let [only] = types.as_slice() {
            let only = only.clone();
            object.insert("type".into(), only);
        }
    }
    if let Some(Value::Array(branches)) = object.remove("anyOf") {
        let mut branches: Vec<Value> = branches
            .into_iter()
            .filter(|branch| *branch != json!({"type": "null"}))
            .collect();
        match branches.pop() {
            Some(Value::Object(only)) if branches.is_empty() => object.extend(only),
            Some(last) => {
                branches.push(last);
                object.insert("anyOf".into(), Value::Array(branches));
            }
            None => {}
        }
    }
}

fn schema<T: JsonSchema>(generator: &mut SchemaGenerator) -> Value {
    generator.subschema_for::<T>().to_value()
}

/// The full contract document, deterministic for a given build.
pub fn http_contract() -> Value {
    let mut g = SchemaSettings::draft2020_12().into_generator();
    let lifecycle = schema::<ManagementLifecycleResult>(&mut g);
    let migration = schema::<PackageMigrationResult>(&mut g);
    let status = schema::<ServiceStatus>(&mut g);
    let routes = vec![
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
            path: "/v1/environments",
            auth: Auth::Read,
            request: None,
            response: schema::<Vec<EnvironmentListEntry>>(&mut g),
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
            auth: Auth::Management,
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
            auth: Auth::Management,
            request: Some(schema::<PromoteRequest>(&mut g)),
            response: lifecycle,
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
            ("EnvironmentInspectReport", "maintenance"),
            ("EnvironmentInspectReport", "observed_type_digest"),
            ("EnvironmentInspectReport", "preview"),
            ("EnvironmentInspectReport", "retirement"),
            ("EnvironmentMaintenanceInspect", "open_until_ms"),
            ("EnvironmentMaintenanceInspect", "next_opens_at_ms"),
            ("EnvironmentMaintenanceInspect", "detail"),
            ("EnvironmentMaintenanceWindow", "next_opens_at_ms"),
            ("EnvironmentPlanSummary", "digest"),
            ("ManagementLifecycleResult", "resource"),
            ("MigrationRecord", "pending_plan_id"),
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
    fn omitted_when_none_strips_only_the_null_branch() {
        let mut nullable =
            Schema::try_from(json!({"type": ["integer", "null"], "format": "int64"})).unwrap();
        omitted_when_none(&mut nullable);
        assert_eq!(
            nullable.to_value(),
            json!({"type": "integer", "format": "int64"})
        );
        let mut referenced = Schema::try_from(json!({
            "anyOf": [{"$ref": "#/$defs/X"}, {"type": "null"}],
            "description": "d"
        }))
        .unwrap();
        omitted_when_none(&mut referenced);
        assert_eq!(
            referenced.to_value(),
            json!({"$ref": "#/$defs/X", "description": "d"})
        );
        let mut union = Schema::try_from(
            json!({"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]}),
        )
        .unwrap();
        omitted_when_none(&mut union);
        assert_eq!(
            union.to_value(),
            json!({"anyOf": [{"type": "string"}, {"type": "integer"}]})
        );
    }

    const CHECKED_IN: &str = include_str!("../../api/tenkai-http-v1.schema.json");

    /// Fails when a route type changes without regenerating the contract.
    /// Regenerate with `make update` (sets TENKAI_UPDATE_API_CONTRACT=1).
    #[test]
    fn checked_in_contract_matches_the_code() {
        let rendered = format!("{:#}\n", http_contract());
        if std::env::var_os("TENKAI_UPDATE_API_CONTRACT").is_some() {
            std::fs::write(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/api/tenkai-http-v1.schema.json"
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
