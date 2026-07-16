//! The tenkai ontology: schema types and deterministic ids in the sekai graph.

use anyhow::Result;

use crate::client::Ctx;
use crate::pb::sekai::{CreateSchemaTypeRequest, ObjectType, PropertyDef};

pub const NS: &str = "tenkai";

pub const KIND_PRODUCT: &str = "tenkai.product";
pub const KIND_RELEASE: &str = "tenkai.release";
pub const KIND_CHANNEL: &str = "tenkai.channel";
pub const KIND_ENVIRONMENT: &str = "tenkai.environment";
pub const KIND_PLAN: &str = "tenkai.plan";
pub const KIND_DEPLOYMENT: &str = "tenkai.deployment";

pub const REL_RELEASE_OF: &str = "release_of";
pub const REL_PROMOTES: &str = "promotes";
pub const REL_SUBSCRIBES: &str = "subscribes";
pub const REL_DEPLOYED_RELEASE: &str = "deployed_release";
pub const REL_IN_ENVIRONMENT: &str = "in_environment";
pub const REL_PART_OF_PLAN: &str = "part_of_plan";

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
pub fn plan_id(env: &str, ts: i64) -> String {
    format!("tenkai:plan:{env}:{ts}")
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
                prop("status", true, "computed|running|succeeded|failed"),
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
    Ok(registered)
}
