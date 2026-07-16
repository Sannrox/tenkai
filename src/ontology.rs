//! The tenkai ontology: schema types and deterministic ids in the sekai graph.

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::pb::sekai::{
    ActionOp, ActionParamDef, ActionTypeDef, CreateActionTypeRequest, CreateSchemaTypeRequest,
    ObjectType, PropertyDef,
};

pub const NS: &str = "tenkai";

pub const KIND_PRODUCT: &str = "tenkai.product";
pub const KIND_RELEASE: &str = "tenkai.release";
pub const KIND_CHANNEL: &str = "tenkai.channel";
pub const KIND_ENVIRONMENT: &str = "tenkai.environment";
pub const KIND_PLAN: &str = "tenkai.plan";
pub const KIND_ENVIRONMENT_EXECUTION: &str = "tenkai.environment_execution";
pub const KIND_DEPLOYMENT: &str = "tenkai.deployment";

pub const REL_RELEASE_OF: &str = "release_of";
pub const REL_PROMOTES: &str = "promotes";
pub const REL_SUBSCRIBES: &str = "subscribes";
pub const REL_DEPLOYED_RELEASE: &str = "deployed_release";
pub const REL_IN_ENVIRONMENT: &str = "in_environment";
pub const REL_PART_OF_PLAN: &str = "part_of_plan";
pub const ACTION_SUBSCRIBE: &str = "tenkai.subscribe";
pub const ACTION_REPLACE_SUBSCRIPTION: &str = "tenkai.replace_subscription";

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

/// Register the tenkai schema types; existing types are left untouched.
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
            ],
        ),
        object_type(
            KIND_ENVIRONMENT_EXECUTION,
            "An exclusive apply lock for one environment",
            vec![
                prop("environment", true, "Locked environment name"),
                prop("owner", true, "Plan id holding the lease"),
                prop("expires_at", true, "Lease expiry in Unix milliseconds"),
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
            ],
        ),
    ];

    let mut registered = Vec::new();
    for t in types {
        let kind = t.kind.clone();
        match ctx
            .sekai
            .create_schema_type(CreateSchemaTypeRequest { r#type: Some(t) })
            .await
        {
            Ok(_) => registered.push(kind),
            Err(status) if status.code() == tonic::Code::AlreadyExists => {}
            Err(status)
                if status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE") => {}
            Err(status) => return Err(status.into()),
        }
    }
    let string_param = |name: &str| ActionParamDef {
        name: name.into(),
        r#type: "string".into(),
        required: true,
        enum_values: vec![],
    };
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
}
