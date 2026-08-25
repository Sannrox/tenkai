//! Desired-vs-deployed snapshot, model/routing rollout order, immutable plan
//! materialization, and rollback step construction.

use super::*;
use anyhow::{Result, bail};

fn classify_change(current: &str, desired: &str) -> Action {
    match (
        semver::Version::parse(current),
        semver::Version::parse(desired),
    ) {
        (Ok(current), Ok(target)) if target < current => Action::Downgrade,
        _ => Action::Upgrade,
    }
}

async fn pin_release(ctx: &mut Ctx, id: &str, environment: &str) -> Result<ReleasePin> {
    use crate::catalog::CatalogReader as _;

    let descriptor = crate::catalog::EmbeddedCatalog::new(ctx)
        .lookup_release(id, environment)
        .await?;
    Ok(release_pin(descriptor))
}

async fn pin_release_for_recovery(
    ctx: &mut Ctx,
    id: &str,
    environment: &str,
) -> Result<ReleasePin> {
    let snapshot = crate::catalog::load_recoverable_snapshot(ctx, id, environment).await?;
    Ok(release_pin(snapshot.descriptor))
}

fn release_pin(descriptor: crate::catalog::ReleaseDescriptor) -> ReleasePin {
    ReleasePin {
        release_id: descriptor.release_id,
        digest: descriptor.manifest_digest,
        artifact_digest: descriptor.artifact_digest,
        workdir: descriptor.content_path,
    }
}

#[derive(Clone, Copy)]
struct ConvergencePolicy {
    observe_live: bool,
}

impl ConvergencePolicy {
    fn catalog_only() -> Self {
        Self {
            observe_live: false,
        }
    }

    fn reconcile() -> Self {
        Self { observe_live: true }
    }
}

async fn release_is_recalled(ctx: &mut Ctx, release_id: &str) -> Result<bool> {
    crate::catalog::release_is_recalled(ctx, release_id).await
}

fn cluster_observe_executor() -> Option<Box<dyn crate::software_executor::SoftwareExecutor>> {
    match std::env::var("TENKAI_SOFTWARE_EXECUTOR") {
        Ok(value)
            if value.eq_ignore_ascii_case("helm")
                || value.eq_ignore_ascii_case("kubernetes")
                || value.eq_ignore_ascii_case("k8s")
                || value.eq_ignore_ascii_case("native") =>
        {
            crate::software_executor::selected_software_executor()
        }
        _ => None,
    }
}

async fn compute_snapshot(ctx: &mut Ctx, env: &str) -> Result<(Vec<DesiredStateInput>, Vec<Step>)> {
    compute_snapshot_with_policy(ctx, env, ConvergencePolicy::catalog_only()).await
}

async fn compute_snapshot_with_policy(
    ctx: &mut Ctx,
    env: &str,
    policy: ConvergencePolicy,
) -> Result<(Vec<DesiredStateInput>, Vec<Step>)> {
    let env_obj = crate::environment::environment(ctx, env).await?;
    let channels = ctx.linked(&env_obj.id, REL_SUBSCRIBES, "out").await?;

    let mut products = std::collections::HashSet::new();
    for channel in &channels {
        let product = channel
            .properties
            .get("product")
            .cloned()
            .unwrap_or_default();
        if !products.insert(product.clone()) {
            bail!(
                "environment {env} has multiple channel subscriptions for {product}; subscribe again after concurrent updates settle"
            );
        }
    }

    let mut inputs = Vec::new();
    let mut pending = Vec::new();
    for ch in channels {
        let product = ch.properties.get("product").cloned().unwrap_or_default();
        let channel = ch.properties.get("channel").cloned().unwrap_or_default();
        let channel_version = ch
            .properties
            .get("current_version")
            .cloned()
            .unwrap_or_default();
        let channel_release = ch
            .properties
            .get("current_release")
            .cloned()
            .unwrap_or_default();
        if channel_version.is_empty() || channel_release.is_empty() {
            continue; // channel exists but nothing promoted yet
        }
        let selected = release_selection::select(
            ctx,
            &env_obj,
            env,
            release_selection::ChannelHead {
                product: &product,
                version: &channel_version,
                release_id: &channel_release,
            },
        )
        .await?;
        let desired = selected.version;
        let release = selected.release_id;
        if release_is_recalled(ctx, &release).await? {
            bail!(
                "channel head {release} is recalled; promote another release before converging {product} in {env}"
            );
        }
        let target = pin_release(ctx, &release, env).await?;
        if env_obj
            .properties
            .get(&format!("deployment_health.{product}"))
            .is_some_and(|health| health == "unknown")
        {
            let detail = env_obj
                .properties
                .get(&format!("deployment_error.{product}"))
                .map(String::as_str)
                .unwrap_or("deployment state requires manual reconciliation");
            bail!(
                "deployment state for {product} in {env} is unknown: {detail}; reconcile it or use rollback before creating a new plan"
            );
        }
        let deployed = env_obj
            .properties
            .get(&format!("deployed.{product}"))
            .cloned();
        let kind = selected.kind;
        inputs.push(DesiredStateInput {
            product: product.clone(),
            channel,
            channel_id: ch.id,
            desired_version: desired.clone(),
            release_id: release.clone(),
            release_digest: target.digest.clone(),
            artifact_digest: target.artifact_digest.clone(),
            deployed_version: deployed.clone(),
        });
        match deployed {
            Some(v) if v == desired => {
                let mut restart = false;
                if policy.observe_live
                    && let Some(executor) = cluster_observe_executor()
                {
                    let request = crate::software_executor::request_from_parts(
                        product.clone(),
                        desired.clone(),
                        env,
                        &target.workdir,
                        release.clone(),
                    );
                    let request = crate::software_executor::with_overlays(
                        request,
                        crate::environment::product_overlays(&env_obj, &product)
                            .unwrap_or_default(),
                    );
                    match executor.observe(&request)? {
                        crate::software_executor::SoftwareObserveStatus::Absent
                        | crate::software_executor::SoftwareObserveStatus::Mismatched => {
                            restart = true;
                        }
                        crate::software_executor::SoftwareObserveStatus::Present
                        | crate::software_executor::SoftwareObserveStatus::Unknown => {}
                    }
                }
                let overlay_digest = crate::environment::overlay_digest(
                    &crate::environment::product_overlays(&env_obj, &product).unwrap_or_default(),
                );
                let applied = env_obj
                    .properties
                    .get(&format!("applied_config.{product}"))
                    .cloned()
                    .unwrap_or_default();
                if overlay_digest != applied {
                    restart = true;
                }
                if env_obj
                    .properties
                    .get(&format!("deployment_health.{product}"))
                    .is_some_and(|health| health == "unhealthy")
                {
                    restart = true;
                }
                if restart {
                    pending.push((
                        product,
                        Action::Restart,
                        Some(v),
                        desired,
                        target,
                        None,
                        kind,
                    ));
                }
            }
            Some(v) => {
                let action = classify_change(&v, &desired);
                let current_id = release_id(&product, &v);
                let restore = if release_is_recalled(ctx, &current_id).await? {
                    None
                } else {
                    Some(pin_release(ctx, &current_id, env).await?)
                };
                pending.push((product, action, Some(v), desired, target, restore, kind));
            }
            None => pending.push((product, Action::Install, None, desired, target, None, kind)),
        }
    }
    inputs.sort_by(|a, b| a.product.cmp(&b.product));
    // Enforce model_runtime ↔ routing_config rollout order (see docs).
    pending.sort_by(|a, b| {
        model_routing_rollout_rank(a.6, a.1)
            .cmp(&model_routing_rollout_rank(b.6, b.1))
            .then_with(|| a.0.cmp(&b.0))
    });
    validate_model_routing_rollout_order(
        &pending
            .iter()
            .map(|entry| (entry.6, entry.1))
            .collect::<Vec<_>>(),
    )?;
    let steps = pending
        .into_iter()
        .enumerate()
        .map(
            |(index, (product, action, from, to, release, restore, _kind))| Step {
                id: format!("{}:step:{index}", env_id(env)),
                order: index as u32,
                product,
                action,
                from,
                to,
                release_id: release.release_id,
                release_digest: release.digest,
                artifact_digest: release.artifact_digest,
                workdir: release.workdir,
                restore,
            },
        )
        .collect();
    Ok((inputs, steps))
}

/// Deterministic step ranking for coordinated model_runtime + routing_config
/// rollouts without merging the product kinds.
///
/// Forward (install/upgrade): model_runtime first, then routing_config.
/// Reverse (downgrade/rollback): routing_config first (drain traffic), then
/// model_runtime (retire generation). Other products keep a neutral rank and
/// sort by product name among themselves.
pub(super) fn model_routing_rollout_rank(kind: crate::manifest::ProductKind, action: Action) -> u8 {
    use crate::product_kind::RolloutDirection;
    let direction = match action {
        Action::Install | Action::Upgrade | Action::Restart => RolloutDirection::Forward,
        Action::Downgrade | Action::Rollback => RolloutDirection::Reverse,
    };
    kind.policy().rollout_rank(direction)
}

/// Reject unsafe model/routing step order (routing switch before model ready,
/// or model retire while routes still target it).
pub(super) fn validate_model_routing_rollout_order(
    steps: &[(crate::manifest::ProductKind, Action)],
) -> Result<()> {
    use crate::manifest::ProductKind;
    let mut last_forward_model = None;
    let mut last_forward_routing = None;
    let mut last_reverse_routing = None;
    let mut last_reverse_model = None;
    for (index, (kind, action)) in steps.iter().enumerate() {
        match (kind, action) {
            (ProductKind::ModelRuntime, Action::Install | Action::Upgrade) => {
                last_forward_model = Some(index);
            }
            (ProductKind::RoutingConfig, Action::Install | Action::Upgrade) => {
                last_forward_routing = Some(index);
            }
            (ProductKind::RoutingConfig, Action::Downgrade | Action::Rollback) => {
                last_reverse_routing = Some(index);
            }
            (ProductKind::ModelRuntime, Action::Downgrade | Action::Rollback) => {
                last_reverse_model = Some(index);
            }
            _ => {}
        }
    }
    let has_forward = last_forward_model.is_some() || last_forward_routing.is_some();
    let has_reverse = last_reverse_model.is_some() || last_reverse_routing.is_some();
    let has_model = last_forward_model.is_some() || last_reverse_model.is_some();
    let has_routing = last_forward_routing.is_some() || last_reverse_routing.is_some();
    // Rank bands collide across directions, so mixed model/routing directions
    // can sort by product name into an unsafe retire-before-drain order.
    if has_forward && has_reverse && has_model && has_routing {
        bail!(
            "unsafe mixed model/routing rollout directions; split forward and reverse changes into separate plans"
        );
    }
    if let (Some(model_i), Some(routing_i)) = (last_forward_model, last_forward_routing)
        && model_i > routing_i
    {
        bail!(
            "unsafe rollout order: routing_config step at {routing_i} precedes model_runtime step at {model_i}; install/verify model before switching routes"
        );
    }
    if let (Some(routing_i), Some(model_i)) = (last_reverse_routing, last_reverse_model)
        && routing_i > model_i
    {
        bail!(
            "unsafe rollback order: model_runtime step at {model_i} precedes routing_config step at {routing_i}; switch routes away before retiring the model"
        );
    }
    Ok(())
}

/// Compute the steps that converge the environment on its subscribed channels.
pub(super) async fn compute(ctx: &mut Ctx, env: &str) -> Result<Vec<Step>> {
    Ok(compute_snapshot(ctx, env).await?.1)
}

/// Compute and persist an immutable executable plan before any step is run.
pub(super) async fn create(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    let (inputs, mut steps) = compute_snapshot(ctx, env).await?;
    create_with_content(ctx, env, inputs, &mut steps, None).await
}

/// Reconcile planning may emit Restart steps from live observe/health evidence.
pub(super) async fn create_for_reconcile(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    let (inputs, mut steps) =
        compute_snapshot_with_policy(ctx, env, ConvergencePolicy::reconcile()).await?;
    create_with_content(ctx, env, inputs, &mut steps, None).await
}

/// Persist an explicitly constructed operation, such as a rollback, as a plan.
pub(super) async fn create_from_steps(
    ctx: &mut Ctx,
    env: &str,
    mut steps: Vec<Step>,
) -> Result<Plan> {
    crate::environment::environment(ctx, env).await?;
    create_with_content(ctx, env, Vec::new(), &mut steps, None).await
}

pub(super) async fn create_from_steps_with_recovery(
    ctx: &mut Ctx,
    env: &str,
    mut steps: Vec<Step>,
    reason: String,
) -> Result<Plan> {
    crate::environment::environment(ctx, env).await?;
    create_with_content(ctx, env, Vec::new(), &mut steps, Some(reason)).await
}

async fn create_with_content(
    ctx: &mut Ctx,
    env: &str,
    inputs: Vec<DesiredStateInput>,
    steps: &mut [Step],
    recalled_recovery_reason: Option<String>,
) -> Result<Plan> {
    let created_at = crate::now_millis();
    for (order, step) in steps.iter_mut().enumerate() {
        step.order = order as u32;
    }
    let content_id = content_address(
        env,
        created_at,
        &inputs,
        steps,
        recalled_recovery_reason.as_deref(),
    )?;
    let id = plan_id(env, created_at, &content_id);
    for (order, step) in steps.iter_mut().enumerate() {
        step.id = format!("{id}:step:{order}");
    }
    let plan = Plan {
        format_version: PLAN_FORMAT_VERSION,
        id,
        content_id,
        environment: env.to_string(),
        created_at,
        inputs,
        steps: steps.to_vec(),
        state: PlanState::Computed,
        gates_skipped: None,
        status_detail: String::new(),
        maintenance_blocked: false,
        prior_warnings: Vec::new(),
        recalled_recovery_reason,
    };
    // Optional advisory priors (default off). Never hard-block or change steps.
    let mut plan = plan;
    if let Ok(inspect) = inspect_environment(ctx, env).await {
        let _ = crate::plan_priors::annotate_plan_with_priors(
            &mut plan,
            &inspect,
            &crate::plan_priors::PriorConfig::from_env(),
        );
    }
    store(ctx, &plan).await?;
    Ok(plan)
}

/// A rollback step to the previously deployed version of one product.
pub(super) async fn rollback_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    rollback_step_with_recovery(ctx, env, product, None).await
}

pub(super) async fn rollback_step_with_recovery(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    recovery: Option<&str>,
) -> Result<Step> {
    validate_identifier("product", product)?;
    if let Some(reason) = recovery {
        let trimmed = reason.trim();
        if trimmed.is_empty() {
            bail!("recalled recovery requires a non-empty --recovery-reason");
        }
        if trimmed.chars().any(|c| c.is_control()) {
            bail!("recovery reason must not contain control characters");
        }
    }
    let env_obj = crate::environment::environment(ctx, env).await?;
    let current = env_obj
        .properties
        .get(&format!("deployed.{product}"))
        .cloned();
    let Some(prev) = env_obj
        .properties
        .get(&format!("deployed_prev.{product}"))
        .cloned()
        .filter(|v| !v.is_empty())
    else {
        bail!("no previous version of {product} recorded in {env} — nothing to roll back to");
    };
    let prev_id = release_id(product, &prev);
    let prev_recalled = release_is_recalled(ctx, &prev_id).await?;
    if prev_recalled && recovery.is_none() {
        bail!(
            "cannot roll back onto recalled release {prev_id}; pass --allow-recalled-recovery --recovery-reason"
        );
    }
    let target = if prev_recalled {
        pin_release_for_recovery(ctx, &prev_id, env).await?
    } else {
        pin_release(ctx, &prev_id, env).await?
    };
    let restore = match current.as_deref() {
        Some(version) => {
            let current_id = release_id(product, version);
            if release_is_recalled(ctx, &current_id).await? {
                if recovery.is_some() {
                    Some(pin_release_for_recovery(ctx, &current_id, env).await?)
                } else {
                    None
                }
            } else {
                Some(pin_release(ctx, &current_id, env).await?)
            }
        }
        None => None,
    };
    Ok(Step {
        id: format!("{}:rollback:{product}", env_id(env)),
        order: 0,
        release_id: target.release_id,
        release_digest: target.digest,
        artifact_digest: target.artifact_digest,
        workdir: target.workdir,
        restore,
        product: product.into(),
        action: Action::Rollback,
        from: current,
        to: prev,
    })
}

/// A same-version restart of the currently deployed release.
pub(super) async fn restart_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    validate_identifier("product", product)?;
    let env_obj = crate::environment::environment(ctx, env).await?;
    let Some(current) = env_obj
        .properties
        .get(&format!("deployed.{product}"))
        .cloned()
        .filter(|value| !value.is_empty())
    else {
        bail!("no deployed version of {product} recorded in {env} — nothing to restart");
    };
    let current_id = release_id(product, &current);
    if release_is_recalled(ctx, &current_id).await? {
        bail!("cannot restart recalled release {current_id}");
    }
    let target = pin_release(ctx, &current_id, env).await?;
    Ok(Step {
        id: format!("{}:restart:{product}", env_id(env)),
        order: 0,
        release_id: target.release_id,
        release_digest: target.digest,
        artifact_digest: target.artifact_digest,
        workdir: target.workdir,
        restore: None,
        product: product.into(),
        action: Action::Restart,
        from: Some(current.clone()),
        to: current,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_is_neutral_for_model_routing_order() {
        use crate::manifest::ProductKind;
        validate_model_routing_rollout_order(&[(ProductKind::Software, Action::Restart)]).unwrap();
    }

    #[test]
    fn semantic_version_direction_is_recorded() {
        assert_eq!(classify_change("2.0.0", "1.9.0"), Action::Downgrade);
        assert_eq!(classify_change("1.9.0", "2.0.0"), Action::Upgrade);
    }

    #[test]
    fn model_routing_forward_order_requires_model_before_routing() {
        use crate::manifest::ProductKind;
        validate_model_routing_rollout_order(&[
            (ProductKind::ModelRuntime, Action::Install),
            (ProductKind::RoutingConfig, Action::Upgrade),
        ])
        .unwrap();
        let err = validate_model_routing_rollout_order(&[
            (ProductKind::RoutingConfig, Action::Upgrade),
            (ProductKind::ModelRuntime, Action::Install),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("unsafe rollout order"), "{err}");
    }

    #[test]
    fn model_routing_rollback_order_requires_routing_before_model() {
        use crate::manifest::ProductKind;
        validate_model_routing_rollout_order(&[
            (ProductKind::RoutingConfig, Action::Rollback),
            (ProductKind::ModelRuntime, Action::Downgrade),
        ])
        .unwrap();
        let err = validate_model_routing_rollout_order(&[
            (ProductKind::ModelRuntime, Action::Downgrade),
            (ProductKind::RoutingConfig, Action::Rollback),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("unsafe rollback order"), "{err}");
    }

    #[test]
    fn model_routing_rejects_mixed_forward_and_reverse_directions() {
        use crate::manifest::ProductKind;
        let err = validate_model_routing_rollout_order(&[
            (ProductKind::ModelRuntime, Action::Downgrade),
            (ProductKind::RoutingConfig, Action::Upgrade),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("mixed model/routing"), "{err}");
    }

    #[test]
    fn model_routing_rank_orders_forward_and_reverse() {
        use crate::manifest::ProductKind;
        assert!(
            model_routing_rollout_rank(ProductKind::ModelRuntime, Action::Install)
                < model_routing_rollout_rank(ProductKind::RoutingConfig, Action::Install)
        );
        assert!(
            model_routing_rollout_rank(ProductKind::RoutingConfig, Action::Rollback)
                < model_routing_rollout_rank(ProductKind::ModelRuntime, Action::Rollback)
        );
    }

    fn write_model_runtime_manifest(
        dir: &std::path::Path,
        version: &str,
        memory_gib: u32,
        quantization: &str,
    ) {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let body = format!(
            r#"[product]
name = "qwen-coder"
version = "{version}"
kind = "model_runtime"
description = "variant fixture"

[model]
source = "file:///tmp/weights.bin"
revision = "fixture"
format = "gguf"
quantization = "{quantization}"
artifact_digest = "{digest}"
license = "apache-2.0"

[runtime]
engine = "llama.cpp"
port = 8080
context_length = 8192

[requirements]
architecture = ["arm64"]
memory_gib = {memory_gib}
accelerator = ["apple-metal"]

[health]
endpoint = "http://127.0.0.1:8080/v1/models"
smoke_prompt = "OK"
max_startup_seconds = 60
"#
        );
        std::fs::write(dir.join("tenkai.toml"), body).unwrap();
    }

    #[tokio::test]
    async fn plan_selects_feasible_model_runtime_variant() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-variant-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let q4_dir = root.join("q4");
        let q8_dir = root.join("q8");
        std::fs::create_dir_all(&q4_dir).unwrap();
        std::fs::create_dir_all(&q8_dir).unwrap();
        write_model_runtime_manifest(&q4_dir, "1.0.0", 16, "Q4_K_M");
        write_model_runtime_manifest(&q8_dir, "1.1.0", 48, "Q8_0");

        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = crate::catalog::PublishOptions {
            signature: None,
            trust_roots: None,
            allow_unsigned_development: true,
            provenance: Vec::new(),
            provenance_trust_roots: None,
            change_set_evidence: None,
        };
        crate::catalog::publish(&mut ctx, &q4_dir.join("tenkai.toml"), &options)
            .await
            .unwrap();
        crate::catalog::publish(&mut ctx, &q8_dir.join("tenkai.toml"), &options)
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("convergence-promote");
        crate::catalog::promote(&mut ctx, &actor, "qwen-coder@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "qwen-coder@1.1.0", "stable")
            .await
            .unwrap();

        env_add(&mut ctx, "local", "fixture").await.unwrap();
        subscribe(&mut ctx, "local", "qwen-coder", "stable")
            .await
            .unwrap();
        set_environment_fact(&mut ctx, "local", "architecture", "arm64")
            .await
            .unwrap();
        set_environment_fact(&mut ctx, "local", "accelerator", "apple-metal")
            .await
            .unwrap();
        // Only enough memory for Q4; channel head is Q8 (1.1.0).
        set_environment_fact(&mut ctx, "local", "memory_gib", "24")
            .await
            .unwrap();

        let plan = create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].product, "qwen-coder");
        assert_eq!(plan.steps[0].to, "1.0.0");
        assert_eq!(plan.steps[0].release_id, release_id("qwen-coder", "1.0.0"));

        // Infeasible: too little memory for any published variant.
        set_environment_fact(&mut ctx, "local", "memory_gib", "8")
            .await
            .unwrap();
        let err = create(&mut ctx, "local").await.unwrap_err().to_string();
        assert!(
            err.contains("no model_runtime variant") || err.contains("memory_gib"),
            "{err}"
        );

        // High memory selects channel head Q8.
        set_environment_fact(&mut ctx, "local", "memory_gib", "64")
            .await
            .unwrap();
        let plan = create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps[0].to, "1.1.0");

        let _ = std::fs::remove_dir_all(&root);
    }

    async fn published_software(ctx: &mut Ctx, root: &std::path::Path, version: &str) {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "api"
version = "{version}"

[deploy]
install = "true"
"#
            ),
        )
        .unwrap();
        crate::catalog::publish(
            ctx,
            &dir.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn overlay_change_emits_same_version_restart() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-overlay-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        let actor = crate::auth_context::test_management_context("overlay-promote");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        subscribe(&mut ctx, "local", "api", "stable").await.unwrap();
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties.insert("deployed.api".into(), "1.0.0".into());
        env.properties
            .insert("deployed_release.api".into(), release_id("api", "1.0.0"));
        ctx.put(env).await.unwrap();

        let idle = create(&mut ctx, "local").await.unwrap();
        assert!(idle.steps.is_empty(), "{idle:?}");

        set_environment_overlay(&mut ctx, "local", "api", "region", "eu")
            .await
            .unwrap();
        let plan = create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].action, Action::Restart);
        assert_eq!(plan.steps[0].from.as_deref(), Some("1.0.0"));
        assert_eq!(plan.steps[0].to, "1.0.0");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn rollback_onto_recalled_pin_requires_audited_reason() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-recovery-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        published_software(&mut ctx, &root, "1.1.0").await;
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties.insert("deployed.api".into(), "1.1.0".into());
        env.properties
            .insert("deployed_prev.api".into(), "1.0.0".into());
        ctx.put(env).await.unwrap();
        let actor = crate::auth_context::test_management_context("recovery-recall");
        crate::catalog::recall(&mut ctx, &actor, "api@1.0.0")
            .await
            .unwrap();

        let denied = rollback_step(&mut ctx, "local", "api")
            .await
            .unwrap_err()
            .to_string();
        assert!(denied.contains("recalled"), "{denied}");

        let step = rollback_step_with_recovery(
            &mut ctx,
            "local",
            "api",
            Some("restore last known-good after faulty recall"),
        )
        .await
        .unwrap();
        assert_eq!(step.action, Action::Rollback);
        assert_eq!(step.to, "1.0.0");

        let _ = std::fs::remove_dir_all(&root);
    }
}
