//! The tenkai ontology: schema types and deterministic ids in the sekai graph.

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::pb::sekai::{
    ActionOp, ActionParamDef, ActionTypeDef, CreateActionTypeRequest, CreateSchemaTypeRequest,
    ListSchemaTypesRequest, ObjectType, PropertyDef,
};

pub const NS: &str = "tenkai";

pub const KIND_PRODUCT: &str = "tenkai.product";
pub const KIND_RELEASE: &str = "tenkai.release";
pub const KIND_RELEASE_VERIFICATION: &str = "tenkai.release_verification";
pub const KIND_CHANNEL: &str = "tenkai.channel";
pub const KIND_ENVIRONMENT: &str = "tenkai.environment";
pub const KIND_MAINTENANCE_CONFIG: &str = "tenkai.maintenance_config";
pub const KIND_PLAN: &str = "tenkai.plan";
pub const KIND_ENVIRONMENT_EXECUTION: &str = "tenkai.environment_execution";
pub const KIND_DEPLOYMENT: &str = "tenkai.deployment";
pub const KIND_CANARY_DESIGNATION: &str = "tenkai.canary_designation";
pub const KIND_CANARY_POLICY: &str = "tenkai.canary_policy";
pub const KIND_CANARY_POLICY_POINTER: &str = "tenkai.canary_policy_pointer";
pub const KIND_CANARY_ATTEMPT: &str = "tenkai.canary_attempt";
pub const KIND_CANARY_OUTCOME: &str = "tenkai.canary_outcome";
pub const KIND_PROMOTION_AUDIT: &str = "tenkai.promotion_audit";
pub const KIND_PROMOTION_LOCK: &str = "tenkai.promotion_lock";

pub const REL_RELEASE_OF: &str = "release_of";
pub const REL_HAS_RELEASE_VERIFICATION: &str = "has_release_verification";
pub const REL_PROMOTES: &str = "promotes";
pub const REL_SUBSCRIBES: &str = "subscribes";
pub const REL_DEPLOYED_RELEASE: &str = "deployed_release";
pub const REL_IN_ENVIRONMENT: &str = "in_environment";
pub const REL_PART_OF_PLAN: &str = "part_of_plan";
pub const REL_GOVERNS_RELEASE: &str = "governs_release";
pub const REL_EVIDENCE_FOR_POLICY: &str = "evidence_for_policy";
pub const REL_AUDITS_PROMOTION: &str = "audits_promotion";
pub const ACTION_SUBSCRIBE: &str = "tenkai.subscribe";
pub const ACTION_REPLACE_SUBSCRIPTION: &str = "tenkai.replace_subscription";
pub const ACTION_CONFIGURE_MAINTENANCE: &str = "tenkai.configure_maintenance_windows";
pub const ACTION_EMERGENCY_OVERRIDE: &str = "tenkai.emergency_maintenance_override";

pub fn validate_identifier(label: &str, value: &str) -> Result<()> {
    let mut chars = value.chars();
    if !matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+'))
    {
        bail!(
            "{label} must start with an ASCII letter or digit and contain only letters, digits, '.', '_', '-', or '+'"
        );
    }
    Ok(())
}

pub fn product_id(name: &str) -> String {
    format!("tenkai:product:{name}")
}
pub fn release_id(product: &str, version: &str) -> String {
    format!("tenkai:release:{product}@{version}")
}
pub fn release_verification_id(release_id: &str) -> String {
    format!("{release_id}:verification")
}
pub fn channel_id(product: &str, channel: &str) -> String {
    format!("tenkai:channel:{product}/{channel}")
}
pub fn env_id(name: &str) -> String {
    format!("tenkai:env:{name}")
}
pub fn plan_id(env: &str, ts: i64, content_id: &str) -> String {
    format!("tenkai:plan:{env}:{ts}:{content_id}")
}
pub fn deployment_id(env: &str, product: &str, ts: i64) -> String {
    format!("tenkai:deployment:{env}:{product}:{ts}")
}

fn prop(name: &str, required: bool, description: &str) -> PropertyDef {
    PropertyDef {
        name: name.into(),
        r#type: "string".into(),
        required,
        description: description.into(),
        classification: "public".into(),
        ..Default::default()
    }
}

fn object_type(kind: &str, description: &str, properties: Vec<PropertyDef>) -> ObjectType {
    ObjectType {
        kind: kind.into(),
        description: description.into(),
        properties,
        is_builtin: false,
        implements: vec![],
    }
}

fn string_param(name: &str) -> ActionParamDef {
    ActionParamDef {
        name: name.into(),
        r#type: "string".into(),
        required: true,
        enum_values: vec![],
    }
}

fn configure_maintenance_action() -> ActionTypeDef {
    ActionTypeDef {
        name: ACTION_CONFIGURE_MAINTENANCE.into(),
        description: "Authorize and replace an environment's maintenance windows".into(),
        params: vec![
            string_param("environment"),
            string_param("windows"),
            string_param("revision"),
            string_param("correlation"),
        ],
        ops: vec![
            ActionOp {
                op: "set_property".into(),
                property: "environment".into(),
                value_from: "environment".into(),
                relation: String::new(),
            },
            ActionOp {
                op: "set_property".into(),
                property: "windows".into(),
                value_from: "windows".into(),
                relation: String::new(),
            },
            ActionOp {
                op: "set_property".into(),
                property: "revision".into(),
                value_from: "revision".into(),
                relation: String::new(),
            },
            ActionOp {
                op: "set_property".into(),
                property: "last_update_correlation".into(),
                value_from: "correlation".into(),
                relation: String::new(),
            },
        ],
        target_kind: KIND_MAINTENANCE_CONFIG.into(),
        created: crate::now_millis(),
    }
}

fn schema_includes(actual: &ObjectType, expected: &ObjectType) -> bool {
    expected.properties.iter().all(|expected_property| {
        actual.properties.iter().any(|actual_property| {
            actual_property.name == expected_property.name
                && actual_property.r#type == expected_property.r#type
                && actual_property.required == expected_property.required
        })
    })
}

fn evolve_schema(actual: &ObjectType, expected: &ObjectType) -> Result<ObjectType> {
    let mut evolved = actual.clone();
    for expected_property in &expected.properties {
        match actual
            .properties
            .iter()
            .find(|property| property.name == expected_property.name)
        {
            Some(property)
                if property.r#type != expected_property.r#type
                    || property.required != expected_property.required =>
            {
                bail!(
                    "schema type {} has incompatible property {} (expected type {:?}, required {}; found type {:?}, required {})",
                    actual.kind,
                    expected_property.name,
                    expected_property.r#type,
                    expected_property.required,
                    property.r#type,
                    property.required
                );
            }
            Some(_) => {}
            None => evolved.properties.push(expected_property.clone()),
        }
    }
    Ok(evolved)
}

fn schema_preserves(actual: &ObjectType, expected: &ObjectType) -> bool {
    actual.kind == expected.kind
        && actual.description == expected.description
        && actual.is_builtin == expected.is_builtin
        && actual.implements == expected.implements
        && expected.properties.iter().all(|expected_property| {
            actual
                .properties
                .iter()
                .any(|property| property == expected_property)
        })
}

/// Register or evolve the tenkai schema types.
pub async fn register(ctx: &mut Ctx) -> Result<Vec<String>> {
    let types = vec![
        object_type(
            KIND_PRODUCT,
            "A deliverable unit of software or intelligence artifacts",
            vec![prop("description", false, "What this product is")],
        ),
        object_type(
            KIND_RELEASE,
            "An immutable, digest-pinned version of a product",
            vec![
                prop("product", true, "Product name"),
                prop("version", true, "Release version"),
                prop("digest", true, "sha256 of the manifest content"),
                prop(
                    "artifact_digest",
                    true,
                    "sha256 tree digest of the immutable deployment workdir",
                ),
                prop("manifest", true, "Raw manifest as published"),
                prop("workdir", false, "Absolute workdir for deploy commands"),
                prop(
                    "verification_status",
                    false,
                    "verified|unsigned-development publication trust result",
                ),
                prop(
                    "signature_algorithm",
                    false,
                    "Signature algorithm or none for unsigned development",
                ),
                prop("signer_identity", false, "Trusted signer identity"),
                prop("signer_key_id", false, "Trusted signer public-key digest"),
                prop(
                    "signature_statement_digest",
                    false,
                    "sha256 of the canonical signed release statement",
                ),
                prop(
                    "signature_envelope",
                    false,
                    "Detached signature envelope retained for reverification",
                ),
                prop("provenance", false, "Canonical signed provenance JSON"),
            ],
        ),
        object_type(
            KIND_RELEASE_VERIFICATION,
            "An immutable first-writer claim for legacy release verification evidence",
            vec![
                prop("release_id", true, "Verified release object id"),
                prop("verification_status", true, "verified"),
                prop("signature_algorithm", true, "Signature algorithm"),
                prop("signer_identity", true, "Trusted signer identity"),
                prop("signer_key_id", true, "Trusted signer public-key digest"),
                prop(
                    "signature_statement_digest",
                    true,
                    "sha256 of the canonical signed release statement",
                ),
                prop("signature_envelope", true, "Detached signature envelope"),
                prop("provenance", true, "Canonical signed provenance JSON"),
            ],
        ),
        object_type(
            KIND_CHANNEL,
            "A named release stream of a product (dev/canary/stable)",
            vec![
                prop("product", true, "Product name"),
                prop("channel", true, "Channel name"),
                prop("current_version", false, "Version the channel points at"),
                prop(
                    "current_release",
                    false,
                    "Release object id the channel points at",
                ),
            ],
        ),
        object_type(
            KIND_ENVIRONMENT,
            "A managed deployment target; deployed.* properties hold current state",
            vec![prop("description", false, "What this environment is")],
        ),
        object_type(
            KIND_MAINTENANCE_CONFIG,
            "Action-controlled maintenance-window configuration for one environment",
            vec![
                prop("environment", true, "Environment name"),
                prop(
                    "windows",
                    true,
                    "JSON list of recurring maintenance windows",
                ),
                prop("revision", true, "Digest of the current windows JSON"),
                prop(
                    "last_update_correlation",
                    false,
                    "Correlation recorded by the most recent governed update",
                ),
            ],
        ),
        object_type(
            KIND_PLAN,
            "A computed set of steps converging one environment on its channels",
            vec![
                prop("format_version", true, "Serialized plan contract version"),
                prop("environment", true, "Environment name"),
                prop(
                    "created_at",
                    true,
                    "Plan creation time in Unix milliseconds",
                ),
                prop(
                    "content_digest",
                    true,
                    "Digest of immutable executable content",
                ),
                prop("plan", true, "Versioned serialized plan document"),
                prop("status", true, "computed|running|blocked|succeeded|failed"),
                prop(
                    "last_emergency_override_reason",
                    false,
                    "Last governed maintenance override reason",
                ),
                prop(
                    "last_emergency_override_correlation",
                    false,
                    "Correlation token for the last governed maintenance override",
                ),
            ],
        ),
        object_type(
            KIND_ENVIRONMENT_EXECUTION,
            "An exclusive apply lock for one environment",
            vec![
                prop("environment", true, "Locked environment name"),
                prop("owner", true, "Plan id holding the lease"),
                prop("expires_at", true, "Lease expiry in Unix milliseconds"),
                prop("generation", false, "Sekai lease fencing generation"),
            ],
        ),
        object_type(
            KIND_DEPLOYMENT,
            "One executed step: a release applied to an environment",
            vec![
                prop("environment", true, "Environment name"),
                prop("product", true, "Product name"),
                prop("from_version", false, "Previously deployed version"),
                prop("to_version", true, "Applied version"),
                prop("status", true, "succeeded|failed|rolled_back"),
                prop("detail", false, "Failure or rollback detail"),
                prop("lease_generation", false, "Mutation fencing generation"),
            ],
        ),
        object_type(
            KIND_CANARY_DESIGNATION,
            "An explicit fact designating an environment for canary cohorts",
            vec![prop("environment", true, "Designated environment name")],
        ),
        object_type(
            KIND_CANARY_POLICY,
            "The immutable canary cohort and success rule for one release promotion",
            vec![
                prop("release_id", true, "Release governed by this policy"),
                prop("release_digest", true, "Pinned release manifest digest"),
                prop("artifact_digest", true, "Pinned release artifact digest"),
                prop("target_channel", true, "Wider channel gated by this policy"),
                prop("policy_digest", true, "Digest of the canonical policy"),
                prop("active", true, "Whether policy activation completed"),
                prop("policy", true, "Canonical JSON policy document"),
            ],
        ),
        object_type(
            KIND_CANARY_POLICY_POINTER,
            "The currently active immutable policy for one release promotion",
            vec![
                prop("release_id", true, "Release governed by the active policy"),
                prop("target_channel", true, "Wider channel gated by the policy"),
                prop("policy_id", true, "Immutable active policy object"),
                prop("policy_digest", true, "Digest of the active policy"),
            ],
        ),
        object_type(
            KIND_CANARY_ATTEMPT,
            "A durable execution-time snapshot of applicable canary policies",
            vec![
                prop("plan_id", true, "Plan being executed"),
                prop(
                    "initial_plan_state",
                    true,
                    "Plan lifecycle state before this execution attempt",
                ),
                prop(
                    "gates_skipped",
                    true,
                    "Whether evaluation gates were skipped",
                ),
                prop("status", true, "pending|ready|abandoned|complete"),
                prop(
                    "execution_started_at",
                    false,
                    "Apply start time in Unix milliseconds",
                ),
                prop(
                    "plan_state",
                    false,
                    "Terminal state captured for this attempt",
                ),
                prop(
                    "finished_at",
                    false,
                    "Attempt finish time in Unix milliseconds",
                ),
                prop(
                    "status_detail",
                    false,
                    "Terminal detail captured for this attempt",
                ),
                prop(
                    "outcomes",
                    false,
                    "Execution outcomes returned by the apply",
                ),
                prop("policies", true, "Policies active when execution began"),
            ],
        ),
        object_type(
            KIND_CANARY_OUTCOME,
            "An immutable canary deployment outcome bound to a release and policy",
            vec![
                prop("release_id", true, "Release exercised by the canary"),
                prop("policy_digest", true, "Policy in force during execution"),
                prop(
                    "policy_activated_at",
                    true,
                    "Activation time of the policy in force during execution",
                ),
                prop("environment", true, "Canary environment"),
                prop("plan_id", true, "Plan that produced the outcome"),
                prop("attempt_id", true, "Immutable execution attempt"),
                prop("step_order", true, "Plan step represented by the outcome"),
                prop("plan_state", true, "Terminal state of the producing plan"),
                prop(
                    "deployment_id",
                    false,
                    "Deployment proving a passing outcome",
                ),
                prop("executed_at", true, "Execution time in Unix milliseconds"),
                prop("recorded_at", true, "Outcome time in Unix milliseconds"),
                prop("outcome", true, "Canonical JSON outcome document"),
            ],
        ),
        object_type(
            KIND_PROMOTION_AUDIT,
            "An immutable allow or deny decision with its complete canary evidence",
            vec![
                prop("release_id", true, "Release considered for promotion"),
                prop("target_channel", true, "Destination channel"),
                prop("policy_digest", true, "Policy evaluated"),
                prop(
                    "policy_activated_at",
                    true,
                    "Activation time of the policy evaluated",
                ),
                prop("allowed", true, "Whether promotion was permitted"),
                prop("evaluated_at", true, "Decision time in Unix milliseconds"),
                prop("evaluation", true, "Canonical JSON decision and evidence"),
            ],
        ),
        object_type(
            KIND_PROMOTION_LOCK,
            "An exclusive lock serializing policy changes and channel promotion",
            vec![prop("owner", true, "Operation holding the lock")],
        ),
    ];

    let current_types = ctx
        .sekai
        .list_schema_types(ListSchemaTypesRequest {})
        .await?
        .into_inner()
        .types;
    let mut registered = Vec::new();
    for t in types {
        let kind = t.kind.clone();
        let schema = match current_types.iter().find(|schema| schema.kind == kind) {
            Some(current) if schema_includes(current, &t) => continue,
            Some(current) => evolve_schema(current, &t)?,
            None => t.clone(),
        };
        match ctx
            .sekai
            .create_schema_type(CreateSchemaTypeRequest {
                r#type: Some(schema.clone()),
            })
            .await
        {
            Ok(_) => {
                let refreshed = ctx
                    .sekai
                    .list_schema_types(ListSchemaTypesRequest {})
                    .await?
                    .into_inner()
                    .types;
                if !refreshed
                    .iter()
                    .find(|candidate| candidate.kind == kind)
                    .is_some_and(|candidate| {
                        schema_includes(candidate, &t) && schema_preserves(candidate, &schema)
                    })
                {
                    bail!(
                        "schema type {kind} was replaced during concurrent initialization; rerun tenkaictl init"
                    );
                }
                registered.push(kind)
            }
            Err(status)
                if status.code() == tonic::Code::AlreadyExists
                    || (status.code() == tonic::Code::Internal
                        && status.message().contains("UNIQUE")) =>
            {
                let refreshed = ctx
                    .sekai
                    .list_schema_types(ListSchemaTypesRequest {})
                    .await?
                    .into_inner()
                    .types;
                if refreshed
                    .iter()
                    .find(|candidate| candidate.kind == kind)
                    .is_some_and(|candidate| {
                        schema_includes(candidate, &t) && schema_preserves(candidate, &schema)
                    })
                {
                    continue;
                }
                bail!(
                    "sekai backend cannot evolve existing schema type {kind}; upgrade sekai-chisei and rerun tenkaictl init"
                );
            }
            Err(status) => return Err(status.into()),
        }
    }
    let actions = [
        ActionTypeDef {
            name: ACTION_SUBSCRIBE.into(),
            description: "Authorize and create an environment channel subscription".into(),
            params: vec![string_param("channel_id")],
            ops: vec![ActionOp {
                op: "create_link".into(),
                property: "channel_id".into(),
                value_from: String::new(),
                relation: REL_SUBSCRIBES.into(),
            }],
            target_kind: KIND_ENVIRONMENT.into(),
            created: crate::now_millis(),
        },
        configure_maintenance_action(),
        ActionTypeDef {
            name: ACTION_EMERGENCY_OVERRIDE.into(),
            description: "Authorize and audit an emergency maintenance-window override".into(),
            params: vec![string_param("reason"), string_param("correlation")],
            ops: vec![
                ActionOp {
                    op: "set_property".into(),
                    property: "last_emergency_override_reason".into(),
                    value_from: "reason".into(),
                    relation: String::new(),
                },
                ActionOp {
                    op: "set_property".into(),
                    property: "last_emergency_override_correlation".into(),
                    value_from: "correlation".into(),
                    relation: String::new(),
                },
            ],
            target_kind: KIND_PLAN.into(),
            created: crate::now_millis(),
        },
        ActionTypeDef {
            name: ACTION_REPLACE_SUBSCRIPTION.into(),
            description: "Authorize and atomically replace an environment channel subscription"
                .into(),
            params: vec![string_param("channel_id"), string_param("old_link_id")],
            ops: vec![
                ActionOp {
                    op: "create_link".into(),
                    property: "channel_id".into(),
                    value_from: String::new(),
                    relation: REL_SUBSCRIBES.into(),
                },
                ActionOp {
                    op: "delete_link".into(),
                    property: String::new(),
                    value_from: "old_link_id".into(),
                    relation: String::new(),
                },
            ],
            target_kind: KIND_ENVIRONMENT.into(),
            created: crate::now_millis(),
        },
    ];
    for action in actions {
        let name = action.name.clone();
        match ctx
            .sekai
            .create_action_type(CreateActionTypeRequest {
                action_type: Some(action),
            })
            .await
        {
            Ok(_) => registered.push(name),
            Err(status) if status.code() == tonic::Code::AlreadyExists => {}
            Err(status)
                if status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE") => {}
            Err(status) => return Err(status.into()),
        }
    }
    Ok(registered)
}

/// Verify once per connected client that an administrator ran the schema upgrade.
pub async fn require_canary_schema(ctx: &mut Ctx) -> Result<()> {
    let preflight = ctx.canary_schema_preflight();
    preflight
        .get_or_try_init(|| async {
            let schemas = ctx
                .sekai
                .list_schema_types(ListSchemaTypesRequest {})
                .await?
                .into_inner()
                .types;
            let required = [
                KIND_CANARY_DESIGNATION,
                KIND_CANARY_POLICY,
                KIND_CANARY_POLICY_POINTER,
                KIND_CANARY_ATTEMPT,
                KIND_CANARY_OUTCOME,
                KIND_PROMOTION_AUDIT,
                KIND_PROMOTION_LOCK,
            ];
            let missing = required
                .into_iter()
                .filter(|kind| !schemas.iter().any(|schema| schema.kind == *kind))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                bail!(
                    "canary schema upgrade required (missing {}); ask an administrator to run `tenkaictl init`",
                    missing.join(", ")
                );
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_identifier_components_reject_delimiters() {
        assert!(validate_identifier("product", "api-service_2.0").is_ok());
        assert!(validate_identifier("product", "api@1").is_err());
        assert!(validate_identifier("environment", "prod:eu").is_err());
        assert!(validate_identifier("channel", "stable/eu").is_err());
    }

    #[test]
    fn maintenance_action_mutates_the_configuration_object() {
        let action = configure_maintenance_action();
        assert_eq!(action.target_kind, KIND_MAINTENANCE_CONFIG);
        assert_eq!(
            action
                .ops
                .iter()
                .map(|operation| operation.property.as_str())
                .collect::<Vec<_>>(),
            vec![
                "environment",
                "windows",
                "revision",
                "last_update_correlation"
            ]
        );
    }

    #[test]
    fn schema_evolution_detects_missing_or_incompatible_properties() {
        let expected = object_type(
            "example",
            "expected",
            vec![prop("existing", true, ""), prop("added", false, "")],
        );
        let legacy = object_type("example", "legacy", vec![prop("existing", true, "")]);
        assert!(!schema_includes(&legacy, &expected));

        let current = object_type(
            "example",
            "current",
            vec![prop("existing", true, ""), prop("added", false, "")],
        );
        assert!(schema_includes(&current, &expected));

        let incompatible = object_type(
            "example",
            "incompatible",
            vec![prop("existing", true, ""), prop("added", true, "")],
        );
        assert!(!schema_includes(&incompatible, &expected));
        assert!(evolve_schema(&incompatible, &expected).is_err());

        let mut custom = object_type(
            "example",
            "custom description",
            vec![prop("existing", true, "custom metadata")],
        );
        custom.implements.push("custom.interface".into());
        custom
            .properties
            .push(prop("installation_specific", false, "must survive"));
        let evolved = evolve_schema(&custom, &expected).unwrap();
        assert_eq!(evolved.description, "custom description");
        assert_eq!(evolved.implements, vec!["custom.interface"]);
        assert_eq!(evolved.properties[0].description, "custom metadata");
        assert!(
            evolved
                .properties
                .iter()
                .any(|property| property.name == "installation_specific")
        );
        assert!(schema_includes(&evolved, &expected));
        assert!(schema_preserves(&evolved, &custom));
    }
}
