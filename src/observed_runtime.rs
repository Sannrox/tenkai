//! Read view of observed Docker and model-runtime state for one environment.
//!
//! Apply records a per-product snapshot. GET merges that snapshot with current
//! inventory facts and recorded deployment health.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::model_runtime::ModelRuntimeDescriptor;
use crate::ontology::validate_identifier;

const PROPERTY_PREFIX: &str = "observed_runtime.";

/// GET `/v1/environments/{environment}/runtime` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentRuntimeReport {
    pub environment: String,
    pub components: Vec<ObservedRuntimeComponent>,
}

/// Observed state of one deployed product on an environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ObservedRuntimeComponent {
    pub product: String,
    pub executor_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub health: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<ObservedRuntimeUnit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_init_job: Option<ObservedInitJob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub model_runtime: Option<ObservedModelRuntime>,
}

/// One running or declared Docker unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ObservedRuntimeUnit {
    pub name: String,
    pub image_digest: String,
    pub restart_policy: String,
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub health: Option<String>,
}

/// Last completed one-shot init job for a Docker topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ObservedInitJob {
    pub name: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub exit_code: Option<i64>,
}

/// Observed model_runtime identity and accelerator fit facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ObservedModelRuntime {
    pub variant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub accelerator: Option<String>,
    pub verified_weight_digest: String,
}

/// Persist a per-product observation snapshot on the environment object.
pub async fn persist(
    ctx: &mut Ctx,
    environment: &str,
    component: &ObservedRuntimeComponent,
) -> Result<()> {
    let env_obj = encode_snapshot(ctx, environment, component).await?;
    ctx.put(env_obj).await?;
    Ok(())
}

/// Persist under the apply lease so a stale executor cannot overwrite newer state.
pub(crate) async fn persist_under_lease(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    component: &ObservedRuntimeComponent,
) -> Result<()> {
    let env_obj = encode_snapshot(ctx, &lease.environment, component).await?;
    ctx.guarded_update(
        env_obj,
        crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

/// Drop a per-product snapshot after the runtime is removed.
pub async fn clear(ctx: &mut Ctx, environment: &str, product: &str) -> Result<()> {
    let env_obj = strip_snapshot(ctx, environment, product).await?;
    ctx.put(env_obj).await?;
    Ok(())
}

pub(crate) async fn clear_under_lease(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    product: &str,
) -> Result<()> {
    let env_obj = strip_snapshot(ctx, &lease.environment, product).await?;
    ctx.guarded_update(
        env_obj,
        crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

async fn strip_snapshot(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
) -> Result<crate::pb::sekai::Object> {
    validate_identifier("environment", environment)?;
    validate_identifier("product", product)?;
    let mut env_obj = crate::environment::environment(ctx, environment).await?;
    env_obj
        .properties
        .remove(&format!("{PROPERTY_PREFIX}{product}"));
    env_obj.updated = crate::now_millis();
    Ok(env_obj)
}

async fn encode_snapshot(
    ctx: &mut Ctx,
    environment: &str,
    component: &ObservedRuntimeComponent,
) -> Result<crate::pb::sekai::Object> {
    validate_identifier("environment", environment)?;
    validate_identifier("product", &component.product)?;
    let mut env_obj = crate::environment::environment(ctx, environment).await?;
    let encoded = serde_json::to_string(component).context("encoding observed runtime snapshot")?;
    env_obj
        .properties
        .insert(format!("{PROPERTY_PREFIX}{}", component.product), encoded);
    env_obj.updated = crate::now_millis();
    Ok(env_obj)
}

/// Build a model_runtime snapshot from the applied descriptor and current facts.
pub fn from_model_runtime(
    descriptor: &ModelRuntimeDescriptor,
    facts: &BTreeMap<String, String>,
) -> ObservedRuntimeComponent {
    ObservedRuntimeComponent {
        product: descriptor.product_name.clone(),
        executor_kind: "model_runtime".into(),
        health: None,
        units: Vec::new(),
        last_init_job: None,
        model_runtime: Some(ObservedModelRuntime {
            variant: format!("{}@{}", descriptor.product_name, descriptor.product_version),
            accelerator: facts.get("accelerator").cloned(),
            verified_weight_digest: descriptor.model.artifact_digest.clone(),
        }),
    }
}

/// Assemble the read view from stored snapshots, inventory facts, and health.
pub async fn report(ctx: &mut Ctx, environment: &str) -> Result<EnvironmentRuntimeReport> {
    validate_identifier("environment", environment)?;
    let env_obj = crate::environment::environment(ctx, environment).await?;
    let facts = crate::environment::list_environment_facts(ctx, environment).await?;
    let mut components = Vec::new();
    for (key, value) in &env_obj.properties {
        let Some(product) = key.strip_prefix(PROPERTY_PREFIX) else {
            continue;
        };
        let mut component: ObservedRuntimeComponent = serde_json::from_str(value)
            .with_context(|| format!("decoding observed runtime snapshot for {product}"))?;
        component.product = product.to_string();
        if component.health.is_none() {
            component.health = env_obj
                .properties
                .get(&format!("deployment_health.{product}"))
                .cloned();
        }
        if let Some(model) = component.model_runtime.as_mut() {
            model.accelerator = facts.get("accelerator").cloned();
        }
        components.push(component);
    }
    components.sort_by(|left, right| left.product.cmp(&right.product));
    Ok(EnvironmentRuntimeReport {
        environment: env_obj.name,
        components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan;

    async fn fixture_ctx() -> (Ctx, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "tenkai-observed-runtime-{}-{}-{}",
            std::process::id(),
            crate::now_millis(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&db).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        plan::env_add(&mut ctx, "lab", "fixture").await.unwrap();
        (ctx, root)
    }

    #[tokio::test]
    async fn report_merges_inventory_facts_and_recorded_health() {
        let (mut ctx, root) = fixture_ctx().await;
        persist(
            &mut ctx,
            "lab",
            &ObservedRuntimeComponent {
                product: "qwen".into(),
                executor_kind: "model_runtime".into(),
                health: None,
                units: Vec::new(),
                last_init_job: None,
                model_runtime: Some(ObservedModelRuntime {
                    variant: "qwen@1.0.0".into(),
                    accelerator: None,
                    verified_weight_digest:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .into(),
                }),
            },
        )
        .await
        .unwrap();
        plan::set_environment_fact(&mut ctx, "lab", "accelerator", "nvidia")
            .await
            .unwrap();
        crate::environment::record_observed_health(&mut ctx, "lab", "qwen", true, "")
            .await
            .unwrap();

        let report = report(&mut ctx, "lab").await.unwrap();
        assert_eq!(report.environment, "lab");
        assert_eq!(report.components.len(), 1);
        assert_eq!(report.components[0].executor_kind, "model_runtime");
        assert_eq!(report.components[0].health.as_deref(), Some("healthy"));
        let model = report.components[0].model_runtime.as_ref().unwrap();
        assert_eq!(model.variant, "qwen@1.0.0");
        assert_eq!(model.accelerator.as_deref(), Some("nvidia"));
        assert_eq!(
            model.verified_weight_digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        crate::environment::clear_environment_fact(&mut ctx, "lab", "accelerator")
            .await
            .unwrap();
        let cleared = super::report(&mut ctx, "lab").await.unwrap();
        assert!(
            cleared.components[0]
                .model_runtime
                .as_ref()
                .unwrap()
                .accelerator
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn empty_environment_has_no_components() {
        let (mut ctx, root) = fixture_ctx().await;
        let report = report(&mut ctx, "lab").await.unwrap();
        assert!(report.components.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn clear_drops_the_product_snapshot() {
        let (mut ctx, root) = fixture_ctx().await;
        persist(
            &mut ctx,
            "lab",
            &ObservedRuntimeComponent {
                product: "edge-app".into(),
                executor_kind: "docker".into(),
                health: None,
                units: Vec::new(),
                last_init_job: None,
                model_runtime: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(report(&mut ctx, "lab").await.unwrap().components.len(), 1);
        clear(&mut ctx, "lab", "edge-app").await.unwrap();
        assert!(report(&mut ctx, "lab").await.unwrap().components.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}
