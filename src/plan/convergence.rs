//! Desired-vs-deployed snapshot, model/routing rollout order, immutable plan
//! materialization, and rollback step construction.

use super::*;
use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};

struct PendingChange {
    product: String,
    instance: String,
    action: Action,
    from: Option<String>,
    to: String,
    release: ReleasePin,
    restore: Option<ReleasePin>,
    kind: crate::manifest::ProductKind,
}

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

fn failed_target_is_held(
    properties: &std::collections::HashMap<String, String>,
    instance: &str,
    release: &str,
) -> bool {
    properties
        .get(&format!("failed_target.{instance}"))
        .is_some_and(|failed_target| failed_target == release)
}

fn product_of_release_id(id: &str) -> Option<&str> {
    id.strip_prefix("tenkai:release:")
        .and_then(|spec| spec.split_once('@'))
        .map(|(product, _)| product)
}

fn deployed_release_id(
    properties: &std::collections::HashMap<String, String>,
    instance: &str,
    version: &str,
) -> String {
    properties
        .get(&format!("deployed_release.{instance}"))
        .cloned()
        .unwrap_or_else(|| release_id(instance, version))
}

fn product_for_instance(
    properties: &std::collections::HashMap<String, String>,
    instance: &str,
) -> String {
    properties
        .get(&format!("deployed_release.{instance}"))
        .and_then(|id| product_of_release_id(id).map(str::to_string))
        .unwrap_or_else(|| instance.to_string())
}

/// The stored manifest of a catalog release.
async fn stored_release_manifest(
    ctx: &mut Ctx,
    release: &str,
) -> Result<crate::manifest::Manifest> {
    let object = ctx
        .get(release)
        .await?
        .with_context(|| format!("release {release} not found"))?;
    let raw = object
        .properties
        .get("manifest")
        .with_context(|| format!("release {release} has no stored manifest"))?;
    crate::manifest::parse_raw(raw).with_context(|| format!("parsing stored manifest of {release}"))
}

/// The stored manifest of `release`, or `None` when the release is missing or
/// its manifest does not parse; apply admission refuses such a release.
async fn readable_manifest(
    ctx: &mut Ctx,
    release: &str,
) -> Result<Option<crate::manifest::Manifest>> {
    Ok(ctx.get(release).await?.and_then(|object| {
        object
            .properties
            .get("manifest")
            .and_then(|raw| crate::manifest::parse_raw(raw).ok())
    }))
}

/// The executor the stored manifest of `release` declares.
pub(crate) async fn stored_release_executor(
    ctx: &mut Ctx,
    release: &str,
) -> Result<Option<crate::software_executor::SoftwareExecutorKind>> {
    Ok(stored_release_manifest(ctx, release).await?.deploy.executor)
}

/// Refuse a step whose target release resolves to a different executor than
/// the installed release of the same product (ADR 0041), when the plan is
/// made. Apply admission checks again and refuses releases that are missing,
/// so a step naming one is left to it. Install and restart steps have
/// nothing to compare.
async fn require_same_executor(
    ctx: &mut Ctx,
    executors: &crate::software_executor::SoftwareExecutors,
    step: &Step,
) -> Result<()> {
    let Some(installed) = step.from.as_deref() else {
        return Ok(());
    };
    if step.action == Action::Restart {
        return Ok(());
    }
    let installed = release_id(&step.product, installed);
    for release in [step.release_id.as_str(), installed.as_str()] {
        if ctx.get(release).await?.is_none() {
            return Ok(());
        }
    }
    executors.require_same_executor(
        &step.product,
        stored_release_executor(ctx, &installed).await?,
        stored_release_executor(ctx, &step.release_id).await?,
    )
}

/// Bind each step of a `host` release to the root-side applier's record for
/// its product (ADR 0041 section 2). The step installs its target from the
/// release the record holds, at the record's generation; both are part of
/// the plan, so its digest and approvals cover them. It gets no restore pin:
/// a failed host step is never restored automatically. When the release
/// declares `deploy.health`, an approved `health` step follows at the
/// generation the install leaves. Steps of other releases are unchanged.
async fn bind_host_steps(
    ctx: &mut Ctx,
    executors: &crate::software_executor::SoftwareExecutors,
    env: &str,
    steps: Vec<Step>,
) -> Result<Vec<Step>> {
    let mut bound = Vec::with_capacity(steps.len());
    for mut step in steps {
        // A release that is missing or unreadable is left to apply
        // admission, which refuses it.
        let Some(manifest) = readable_manifest(ctx, &step.release_id).await? else {
            bound.push(step);
            continue;
        };
        if manifest.deploy.executor != Some(crate::software_executor::SoftwareExecutorKind::Host) {
            if step.action == Action::Remove {
                bail!(
                    "{} is not a host release; only host releases are removed by a plan",
                    step.release_id
                );
            }
            bound.push(step);
            continue;
        }
        require_host_product(ctx, executors, env, &step.product).await?;
        let record = executors.host()?.applied_state(env, &step.product)?;
        match step.host {
            // An applied release's outstanding health step, at the record's
            // generation.
            Some(HostStep {
                action: HostAction::Health,
                ..
            }) => {
                step.host = Some(HostStep {
                    action: HostAction::Health,
                    expected_generation: record.generation,
                });
                bound.push(step);
                continue;
            }
            Some(_) => bail!("step for host release {} is already bound", step.release_id),
            None if step.action == Action::Restart => bail!(
                "host release {} is never restarted; plan a new install instead",
                step.release_id
            ),
            // Uninstall acts on the release the record holds, which the
            // planner pinned; its `from` is the release itself.
            None if step.action == Action::Remove => {
                step.from = Some(step.to.clone());
                step.restore = None;
                step.host = Some(HostStep {
                    action: HostAction::Uninstall,
                    expected_generation: record.generation,
                });
                bound.push(step);
                continue;
            }
            None => {}
        }
        let from = host_source(&record, step.from.as_deref());
        if step.action != Action::Rollback {
            step.action = match from.as_deref() {
                None => Action::Install,
                Some(current) => classify_change(current, &step.to),
            };
        }
        step.from = from;
        step.restore = None;
        step.host = Some(HostStep {
            action: HostAction::Install,
            expected_generation: record.generation,
        });
        if declares_health(&manifest) {
            let installed = record
                .generation
                .checked_add(1)
                .context("host applied-state generation overflow")?;
            bound.push(step.clone());
            // The health step of a rollback is part of that rollback, so it
            // keeps the rollback's admission, recalled recovery included.
            if step.action != Action::Rollback {
                step.action = Action::Restart;
            }
            step.from = Some(step.to.clone());
            step.host = Some(HostStep {
                action: HostAction::Health,
                expected_generation: installed,
            });
        }
        bound.push(step);
    }
    Ok(bound)
}

/// Whether a release declares a `deploy.health` command.
fn declares_health(manifest: &crate::manifest::Manifest) -> bool {
    manifest
        .deploy
        .health
        .as_deref()
        .is_some_and(|command| !command.trim().is_empty())
}

/// How far the applier's record has taken a host product toward `desired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostProgress {
    /// `desired` is applied, and its health step succeeded since if it
    /// declares one.
    Converged,
    /// `desired` is applied, but its health step failed or never ran.
    NeedsHealth,
    /// Anything else, a dirty record included.
    NeedsInstall,
}

fn host_progress(
    record: &crate::host_apply::state::AppliedStateRecord,
    desired: &str,
    health: bool,
) -> HostProgress {
    use crate::host_apply::state::AppliedState;
    let AppliedState::Applied { release } = &record.state else {
        return HostProgress::NeedsInstall;
    };
    if release.version != desired {
        return HostProgress::NeedsInstall;
    }
    // The last step the applier started for this product is a health step
    // of this very release, and it succeeded.
    let healthy = matches!(
        (&record.last_started, &record.last_result),
        (Some(started), Some(result))
            if started.action == HostAction::Health
                && &started.release == release
                && result.instance == started.instance
                && result.outcome.succeeded()
    );
    if health && !healthy {
        HostProgress::NeedsHealth
    } else {
        HostProgress::Converged
    }
}

/// Refuse to install a host release over a product the server records as
/// deployed with another executor; moving executors is a remove and an
/// install (ADR 0041 section 1). The applier's record, empty for a product
/// it never touched, cannot tell.
pub(crate) async fn require_host_product(
    ctx: &mut Ctx,
    executors: &crate::software_executor::SoftwareExecutors,
    env: &str,
    product: &str,
) -> Result<()> {
    let environment = crate::environment::environment(ctx, env).await?;
    let Some(deployed) = environment.properties.get(&format!("deployed.{product}")) else {
        return Ok(());
    };
    let Some(installed) = readable_manifest(ctx, &release_id(product, deployed)).await? else {
        return Ok(());
    };
    executors.require_same_executor(
        product,
        installed.deploy.executor,
        Some(crate::software_executor::SoftwareExecutorKind::Host),
    )
}

/// The version a host step starts from: what the applier's record holds.
/// For a `dirty` record either side may be the source; the one the server
/// recorded as deployed wins, else the side the interrupted step came from.
fn host_source(
    record: &crate::host_apply::state::AppliedStateRecord,
    deployed: Option<&str>,
) -> Option<String> {
    use crate::host_apply::state::AppliedState;
    match &record.state {
        AppliedState::Empty => None,
        AppliedState::Applied { release } => Some(release.version.clone()),
        AppliedState::Dirty { from, to } => {
            let sides = [from.as_ref(), to.as_ref()];
            sides
                .iter()
                .flatten()
                .find(|release| Some(release.version.as_str()) == deployed)
                .or(sides.iter().flatten().next())
                .map(|release| release.version.clone())
        }
    }
}

/// The adapter reconcile observes a deployed release with: the one its own
/// executor resolves to. The shell path and the unnamed test default observe
/// nothing, as before, and host releases get no periodic observation (ADR 0041
/// section 2).
fn observe_executor(
    executors: &crate::software_executor::SoftwareExecutors,
    manifest: &crate::manifest::Manifest,
) -> Result<Option<std::sync::Arc<dyn crate::software_executor::SoftwareExecutor>>> {
    let declared = manifest.deploy.executor;
    match executors.effective_kind(declared) {
        None | Some(crate::software_executor::SoftwareExecutorKind::Host) => Ok(None),
        Some(_) => executors.resolve(declared),
    }
}

async fn compute_snapshot(
    ctx: &mut Ctx,
    env: &str,
    executors: &crate::software_executor::SoftwareExecutors,
) -> Result<(Vec<DesiredStateInput>, Vec<Step>)> {
    compute_snapshot_with_policy(ctx, env, ConvergencePolicy::catalog_only(), executors).await
}

async fn compute_snapshot_with_policy(
    ctx: &mut Ctx,
    env: &str,
    policy: ConvergencePolicy,
    executors: &crate::software_executor::SoftwareExecutors,
) -> Result<(Vec<DesiredStateInput>, Vec<Step>)> {
    let env_obj = crate::environment::active_environment(ctx, env).await?;
    crate::preview::admit_plan(&env_obj, crate::now_millis())?;
    let subscriptions = crate::environment::list_subscriptions(ctx, &env_obj).await?;

    let mut instances = std::collections::HashSet::new();
    for sub in &subscriptions {
        if !instances.insert(sub.instance.clone()) {
            bail!(
                "environment {env} has duplicate instance {}; subscribe again after concurrent updates settle",
                sub.instance
            );
        }
    }

    let mut inputs = Vec::new();
    let mut pending = Vec::new();
    // Host products whose release is applied but whose health step has not
    // succeeded since: they get that health step alone.
    let mut host_health_only = std::collections::HashSet::new();
    // Products whose release runs on the host executor.
    let mut host_products = std::collections::HashSet::new();
    let mut held_model = false;
    let mut held_routing = false;
    let mut hold_sets = BTreeMap::new();
    let mut hold_clears = BTreeSet::new();
    for sub in subscriptions {
        let product = sub.product;
        let instance = sub.instance;
        let ch = sub.channel;
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
        if policy.observe_live {
            match admit_reconcile_dependency(ctx, env, &release).await? {
                DependencyAdmission::Hold {
                    release_id,
                    contracts,
                } => {
                    hold_sets.insert(
                        product.clone(),
                        crate::environment::DependencyHoldWrite {
                            release_id,
                            contracts,
                        },
                    );
                    held_model |= selected.kind == crate::manifest::ProductKind::ModelRuntime;
                    held_routing |= selected.kind == crate::manifest::ProductKind::RoutingConfig;
                    continue;
                }
                DependencyAdmission::Proceed => {
                    if crate::environment::dependency_hold(&env_obj.properties, &product).is_some()
                    {
                        hold_clears.insert(product.clone());
                    }
                }
            }
        } else {
            crate::software_compatibility::require_release(ctx, env, &release).await?;
        }
        crate::topology::require_placement(ctx, env, &release).await?;
        // The root-side applier's record, not the server's view, says what a
        // host release has applied (ADR 0041 section 2).
        let host_record = match readable_manifest(ctx, &release).await? {
            Some(manifest)
                if manifest.deploy.executor
                    == Some(crate::software_executor::SoftwareExecutorKind::Host) =>
            {
                Some((
                    executors.host()?.applied_state(env, &product)?,
                    declares_health(&manifest),
                ))
            }
            _ => None,
        };
        if host_record.is_none()
            && env_obj
                .properties
                .get(&format!("deployment_health.{instance}"))
                .is_some_and(|health| health == "unknown")
        {
            let detail = env_obj
                .properties
                .get(&format!("deployment_error.{instance}"))
                .map(String::as_str)
                .unwrap_or("deployment state requires manual reconciliation");
            bail!(
                "deployment state for {instance} in {env} is unknown: {detail}; reconcile it or use rollback before creating a new plan"
            );
        }
        if policy.observe_live && failed_target_is_held(&env_obj.properties, &instance, &release) {
            held_model |= selected.kind == crate::manifest::ProductKind::ModelRuntime;
            held_routing |= selected.kind == crate::manifest::ProductKind::RoutingConfig;
            continue;
        }
        let deployed = env_obj
            .properties
            .get(&format!("deployed.{instance}"))
            .cloned();
        let kind = selected.kind;
        if kind == crate::manifest::ProductKind::WorkshopModule {
            crate::workshop_module::admit_plan(ctx, env, &env_obj, &release).await?;
        }
        inputs.push(DesiredStateInput {
            product: product.clone(),
            instance: if instance == product {
                String::new()
            } else {
                instance.clone()
            },
            channel,
            channel_id: ch.id,
            desired_version: desired.clone(),
            release_id: release.clone(),
            release_digest: target.digest.clone(),
            artifact_digest: target.artifact_digest.clone(),
            deployed_version: deployed.clone(),
        });
        if let Some((record, health)) = &host_record {
            host_products.insert(product.clone());
            match host_progress(record, &desired, *health) {
                HostProgress::Converged => {
                    // The applier finished, but the server never recorded
                    // it (a crash or failed bookkeeping after the step).
                    // Nothing observes host releases, so say how to settle it.
                    let unknown = env_obj
                        .properties
                        .get(&format!("deployment_health.{instance}"))
                        .is_some_and(|health| health == "unknown");
                    if unknown || deployed.as_deref() != Some(desired.as_str()) {
                        bail!(
                            "the host applier records {product} {desired} applied in {env} at generation {}, but this server records {}; once no apply runs, record it with `tenkaictl env reconcile {env} {product} --deployed {desired}`",
                            record.generation,
                            if unknown {
                                "it as unknown".to_string()
                            } else {
                                deployed.as_deref().unwrap_or("nothing").to_string()
                            }
                        );
                    }
                }
                HostProgress::NeedsHealth => {
                    host_health_only.insert(product.clone());
                    pending.push(PendingChange {
                        product,
                        instance,
                        action: Action::Restart,
                        from: Some(desired.clone()),
                        to: desired,
                        release: target,
                        restore: None,
                        kind,
                    });
                }
                HostProgress::NeedsInstall => pending.push(PendingChange {
                    product,
                    instance,
                    action: Action::Install,
                    from: deployed,
                    to: desired,
                    release: target,
                    restore: None,
                    kind,
                }),
            }
            continue;
        }
        match deployed {
            Some(v) if v == desired => {
                let mut restart = !policy.observe_live
                    && failed_target_is_held(&env_obj.properties, &instance, &release);
                // Reconcile observes each release with its own executor, and
                // never restarts a host release on its own (ADR 0041).
                let live = if policy.observe_live {
                    Some(stored_release_manifest(ctx, &release).await?)
                } else {
                    None
                };
                let host = live.as_ref().is_some_and(|manifest| {
                    manifest.deploy.executor
                        == Some(crate::software_executor::SoftwareExecutorKind::Host)
                });
                if let Some(manifest) = live.as_ref()
                    && let Some(executor) = observe_executor(executors, manifest)?
                {
                    let request = crate::software_executor::request_from_parts(
                        product.clone(),
                        desired.clone(),
                        env,
                        &target.workdir,
                        release.clone(),
                    );
                    let mut request = crate::software_executor::with_overlays(
                        request,
                        crate::environment::product_overlays(&env_obj, &product)
                            .unwrap_or_default(),
                    );
                    request.cluster_config_path =
                        crate::software_executor::cluster_config_path_from_properties(
                            &env_obj.properties,
                        )?;
                    request.secret_dir_path =
                        crate::software_executor::secret_dir_from_properties(&env_obj.properties)?;
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
                    .get(&format!("deployment_health.{instance}"))
                    .is_some_and(|health| health == "unhealthy")
                {
                    restart = true;
                }
                if restart && !host {
                    pending.push(PendingChange {
                        product,
                        instance,
                        action: Action::Restart,
                        from: Some(v),
                        to: desired,
                        release: target,
                        restore: None,
                        kind,
                    });
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
                pending.push(PendingChange {
                    product,
                    instance,
                    action,
                    from: Some(v),
                    to: desired,
                    release: target,
                    restore,
                    kind,
                });
            }
            None => pending.push(PendingChange {
                product,
                instance,
                action: Action::Install,
                from: None,
                to: desired,
                release: target,
                restore: None,
                kind,
            }),
        }
    }
    // A host product the environment no longer subscribes to is removed
    // like any other change: by an approved host uninstall step, from what
    // the applier's record holds (ADR 0041 section 2).
    // Host products to consider for removal: every one the applier keeps a
    // record of, and every one the server records as deployed from a host
    // release, so a missing or unreadable record refuses the plan instead
    // of passing for "nothing to remove".
    let mut removable = std::collections::BTreeSet::new();
    let unknown = |instance: &str| {
        env_obj
            .properties
            .get(&format!("deployment_health.{instance}"))
            .is_some_and(|health| health == "unknown")
    };
    for (key, value) in &env_obj.properties {
        // The deployed release, or the target of a failed step that left
        // the deployment unknown. Property suffixes are instance names.
        let (instance, release) = if let Some(instance) = key.strip_prefix("deployed.") {
            (
                instance,
                deployed_release_id(&env_obj.properties, instance, value),
            )
        } else if let Some(instance) = key.strip_prefix("failed_target.")
            && unknown(instance)
        {
            (instance, value.clone())
        } else {
            continue;
        };
        if !instances.contains(instance)
            && readable_manifest(ctx, &release)
                .await?
                .is_some_and(|manifest| {
                    manifest.deploy.executor
                        == Some(crate::software_executor::SoftwareExecutorKind::Host)
                })
        {
            removable.insert(instance.to_string());
        }
    }
    match executors.host() {
        Ok(host) => {
            // Only products this server delivered to the environment: its
            // deployment history names them, or the step that last started
            // for them is one of its plans (a first install whose outcome
            // was never recorded). A record of a product it never managed
            // here is not its to remove.
            for record in host.applied_states(env)? {
                let recorded = ["deployed", "deployed_prev", "deployment_health"]
                    .iter()
                    .any(|key| {
                        env_obj
                            .properties
                            .contains_key(&format!("{key}.{}", record.product))
                    });
                let planned = match &record.last_started {
                    Some(started) => ctx.get(&started.plan_id).await?.is_some(),
                    None => false,
                };
                if (recorded || planned) && !instances.contains(&record.product) {
                    removable.insert(record.product);
                }
            }
            for instance in removable {
                let product = product_for_instance(&env_obj.properties, &instance);
                let record = host.applied_state(env, &product)?;
                let deployed = env_obj
                    .properties
                    .get(&format!("deployed.{instance}"))
                    .cloned();
                let Some(version) = host_source(&record, deployed.as_deref()) else {
                    let server = match deployed {
                        Some(deployed) => Some(deployed),
                        None if unknown(&instance) => Some("it as unknown".to_string()),
                        None => None,
                    };
                    if let Some(server) = server {
                        bail!(
                            "the host applier records nothing applied for {instance} in {env} at generation {}, but this server records {server}; once no apply runs, record it with `tenkaictl env reconcile {env} {product}`",
                            record.generation
                        );
                    }
                    continue;
                };
                // A recalled release can still be removed: removal deploys
                // nothing, and its signature and integrity are still checked.
                let target =
                    pin_release_for_recovery(ctx, &release_id(&product, &version), env).await?;
                pending.push(PendingChange {
                    product,
                    instance,
                    action: Action::Remove,
                    from: Some(version.clone()),
                    to: version,
                    release: target,
                    restore: None,
                    kind: crate::manifest::ProductKind::Software,
                });
            }
        }
        // Without the applier's records nothing here can remove a host
        // release that is deployed but no longer subscribed.
        Err(error) => {
            if let Some(product) = removable.first() {
                bail!("{product} is a host release to remove from {env}: {error:#}");
            }
        }
    }
    inputs.sort_by(|a, b| a.product.cmp(&b.product));
    if held_model {
        pending.retain(|entry| entry.kind != crate::manifest::ProductKind::RoutingConfig);
    }
    if held_routing {
        pending.retain(|entry| {
            entry.kind != crate::manifest::ProductKind::ModelRuntime
                || !matches!(entry.action, Action::Downgrade | Action::Rollback)
        });
    }
    let mut target_profiles = BTreeMap::new();
    for entry in &pending {
        if matches!(entry.action, Action::Remove) {
            continue;
        }
        if target_profiles.contains_key(&entry.product) {
            continue;
        }
        if let Some(manifest) = readable_manifest(ctx, &entry.release.release_id).await?
            && let Some(profile) = manifest.compatibility
        {
            target_profiles.insert(entry.product.clone(), profile);
        }
    }
    let mut installed_profiles = BTreeMap::new();
    for (key, value) in &env_obj.properties {
        let Some(instance) = key.strip_prefix("deployed.") else {
            continue;
        };
        let product = product_for_instance(&env_obj.properties, instance);
        if installed_profiles.contains_key(&product) {
            continue;
        }
        if let Some(manifest) = readable_manifest(
            ctx,
            &deployed_release_id(&env_obj.properties, instance, value),
        )
        .await?
            && let Some(profile) = manifest.compatibility
        {
            installed_profiles.insert(product, profile);
        }
    }
    schedule_dependency_rerenders(
        ctx,
        env,
        &mut pending,
        &installed_profiles,
        &target_profiles,
        &env_obj,
        &host_products,
    )
    .await?;
    let pending_actions = pending
        .iter()
        .map(|entry| (entry.product.as_str(), entry.action))
        .collect::<Vec<_>>();
    let contract_order =
        contract_plan_order(&pending_actions, &target_profiles, &installed_profiles)?;
    // Enforce model_runtime ↔ routing_config rollout order (see docs). The
    // runtime agent's own release always runs last: switching restarts the
    // agent, so nothing may follow it in the plan (#685). Host releases run
    // first: a plan stops at its first failed step, and releases in a cluster
    // a host release installs fail closed until it exists (ADR 0041 section
    // 4), so a host step sorted after them would never run. Contract edges
    // (ADR 0043 §3) order providers before dependents, and reverse that for
    // remove/downgrade/rollback; independent releases keep name order.
    let reverse_providers: BTreeSet<&str> = pending
        .iter()
        .filter(|entry| reverse_contract_action(entry.action))
        .map(|entry| entry.product.as_str())
        .collect();
    let rerender_after_reverse: BTreeSet<&str> = contract_order
        .installed_edges
        .iter()
        .filter(|(provider, dependent, _)| {
            reverse_providers.contains(provider.as_str())
                && pending
                    .iter()
                    .any(|entry| entry.product == *dependent && entry.action == Action::Restart)
        })
        .map(|(_, dependent, _)| dependent.as_str())
        .collect();
    pending.sort_by(|a, b| {
        let agent = |product: &str| product == crate::runtime_self_upgrade::SELF_PRODUCT;
        let not_host = |product: &String| !host_products.contains(product);
        // Removals run after in-cluster work so a host cluster can come
        // down last. A remaining dependent's re-render after losing a
        // provider must follow that reverse step (ADR 0043 §6).
        let band = |product: &str, action: Action| -> u8 {
            if action == Action::Restart && rerender_after_reverse.contains(product) {
                2
            } else if action == Action::Remove {
                1
            } else {
                0
            }
        };
        let contract = |product: &str| {
            contract_order
                .ranks
                .get(product)
                .copied()
                .unwrap_or(u32::MAX)
        };
        agent(&a.product)
            .cmp(&agent(&b.product))
            .then_with(|| band(&a.product, a.action).cmp(&band(&b.product, b.action)))
            .then_with(|| not_host(&a.product).cmp(&not_host(&b.product)))
            .then_with(|| {
                model_routing_rollout_rank(a.kind, a.action)
                    .cmp(&model_routing_rollout_rank(b.kind, b.action))
            })
            .then_with(|| contract(&a.product).cmp(&contract(&b.product)))
            .then_with(|| a.product.cmp(&b.product))
            .then_with(|| a.instance.cmp(&b.instance))
    });
    validate_model_routing_rollout_order(
        &pending
            .iter()
            .map(|entry| (entry.kind, entry.action))
            .collect::<Vec<_>>(),
    )?;
    refuse_inverted_contract_order(
        &pending
            .iter()
            .map(|entry| (entry.product.as_str(), entry.action))
            .collect::<Vec<_>>(),
        &contract_order.target_edges,
        &contract_order.installed_edges,
        &contract_order.overlay_edges,
    )?;
    let steps = pending
        .into_iter()
        .enumerate()
        .map(|index_entry| {
            let (index, entry) = index_entry;
            Step {
                id: format!("{}:step:{index}", env_id(env)),
                // Binding sets the generation from the applier's record.
                host: host_health_only
                    .contains(&entry.product)
                    .then_some(HostStep {
                        action: HostAction::Health,
                        expected_generation: 0,
                    }),
                order: index as u32,
                instance: if entry.instance == entry.product {
                    String::new()
                } else {
                    entry.instance
                },
                product: entry.product,
                action: entry.action,
                from: entry.from,
                to: entry.to,
                release_id: entry.release.release_id,
                release_digest: entry.release.digest,
                artifact_digest: entry.release.artifact_digest,
                workdir: entry.release.workdir,
                restore: entry.restore,
            }
        })
        .collect();
    crate::environment::persist_dependency_holds(ctx, env, &hold_sets, &hold_clears).await?;
    Ok((inputs, steps))
}

enum DependencyAdmission {
    Hold {
        release_id: String,
        contracts: Vec<(String, String)>,
    },
    Proceed,
}

/// Reconcile waits for an unmet required contract instead of failing the tick.
async fn admit_reconcile_dependency(
    ctx: &mut Ctx,
    env: &str,
    release: &str,
) -> Result<DependencyAdmission> {
    let Some(eval) = crate::software_compatibility::report_eval(ctx, env, release).await? else {
        return Ok(DependencyAdmission::Proceed);
    };
    if eval.outcome.failures.is_empty() {
        return Ok(DependencyAdmission::Proceed);
    }
    let profile = stored_release_manifest(ctx, release).await?.compatibility;
    let Some(profile) = profile else {
        return Err(crate::software_compatibility::CompatibilityBlocked {
            report: eval.into(),
        }
        .into());
    };
    let Some(unmet) = crate::software_compatibility::holdable_unmet_requirements(
        &eval.outcome,
        &eval.candidate_unmet,
        &profile,
    ) else {
        return Err(crate::software_compatibility::CompatibilityBlocked {
            report: eval.into(),
        }
        .into());
    };
    Ok(DependencyAdmission::Hold {
        release_id: release.to_string(),
        contracts: unmet,
    })
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
        Action::Downgrade | Action::Rollback | Action::Remove => RolloutDirection::Reverse,
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

/// Provider product, dependent product, and the contract that links them.
type ContractEdge = (String, String, String);

fn profile_provides_requires(
    profile: &crate::software_compatibility::CompatibilityProfile,
) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let mut provides = BTreeMap::new();
    let mut requires = BTreeSet::new();
    for component in profile.components.values() {
        for (contract, version) in &component.provides {
            provides.insert(contract.clone(), version.clone());
        }
        for contract in component.requires.keys() {
            requires.insert(contract.clone());
        }
    }
    (provides, requires)
}

/// Unique provider in `profiles` for each required contract of another profile.
fn cross_release_contract_edges(
    profiles: &BTreeMap<String, crate::software_compatibility::CompatibilityProfile>,
) -> Vec<ContractEdge> {
    let mut providers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut requires: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (product, profile) in profiles {
        let (provided, required) = profile_provides_requires(profile);
        for contract in provided.keys() {
            providers
                .entry(contract.clone())
                .or_default()
                .insert(product.clone());
        }
        requires.insert(product.clone(), required);
    }
    let mut edges = Vec::new();
    for (dependent, contracts) in &requires {
        for contract in contracts {
            let Some(offered) = providers.get(contract) else {
                continue;
            };
            if offered.len() != 1 {
                continue;
            }
            let Some(provider) = offered.iter().next() else {
                continue;
            };
            if provider == dependent {
                continue;
            }
            edges.push((provider.clone(), dependent.clone(), contract.clone()));
        }
    }
    edges
}

/// Target profile replaces installed for the same product; unchanged products stay.
/// Remove, or a pending product missing from `target` that is not a same-version
/// Restart, drops the installed profile. Restart keeps the remaining dependent
/// so arrival and leave re-render edges stay on the overlay.
fn overlay_profiles(
    installed: &BTreeMap<String, crate::software_compatibility::CompatibilityProfile>,
    target: &BTreeMap<String, crate::software_compatibility::CompatibilityProfile>,
    pending: &[(&str, Action)],
) -> BTreeMap<String, crate::software_compatibility::CompatibilityProfile> {
    let removed: BTreeSet<&str> = pending
        .iter()
        .filter(|(_, action)| matches!(action, Action::Remove))
        .map(|(product, _)| *product)
        .collect();
    let mut profiles = installed.clone();
    for (product, action) in pending {
        if removed.contains(product)
            || (!target.contains_key(*product) && *action != Action::Restart)
        {
            profiles.remove(*product);
        }
    }
    for (product, profile) in target {
        if removed.contains(product.as_str()) {
            continue;
        }
        profiles.insert(product.clone(), profile.clone());
    }
    profiles
}

fn refuse_cross_release_cycle(edges: &[ContractEdge]) -> Result<()> {
    let mut outgoing: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
    let mut nodes = BTreeSet::new();
    for (provider, dependent, contract) in edges {
        nodes.insert(provider.as_str());
        nodes.insert(dependent.as_str());
        outgoing
            .entry(provider.as_str())
            .or_default()
            .push((dependent.as_str(), contract.as_str()));
    }
    let mut visiting = Vec::new();
    let mut visiting_set = BTreeMap::new();
    let mut done = BTreeSet::new();
    for node in nodes {
        visit_plan_contract_edge(node, &outgoing, &mut visiting, &mut visiting_set, &mut done)?;
    }
    Ok(())
}

fn visit_plan_contract_edge<'a>(
    node: &'a str,
    outgoing: &BTreeMap<&'a str, Vec<(&'a str, &'a str)>>,
    visiting: &mut Vec<(&'a str, &'a str)>,
    visiting_set: &mut BTreeMap<&'a str, usize>,
    done: &mut BTreeSet<&'a str>,
) -> Result<()> {
    if done.contains(node) {
        return Ok(());
    }
    if let Some(&index) = visiting_set.get(node) {
        let mut cycle: Vec<&str> = visiting[index..].iter().map(|(name, _)| *name).collect();
        cycle.push(node);
        let contracts: Vec<&str> = visiting[index..]
            .iter()
            .map(|(_, contract)| *contract)
            .collect();
        bail!(
            "plan requirement cycle: {} (contracts: {})",
            cycle.join(" -> "),
            contracts.join(", ")
        );
    }
    visiting_set.insert(node, visiting.len());
    if let Some(next) = outgoing.get(node) {
        for &(dependent, contract) in next {
            visiting.push((node, contract));
            visit_plan_contract_edge(dependent, outgoing, visiting, visiting_set, done)?;
            visiting.pop();
        }
    }
    visiting_set.remove(node);
    done.insert(node);
    Ok(())
}

fn reverse_contract_action(action: Action) -> bool {
    matches!(
        action,
        Action::Remove | Action::Downgrade | Action::Rollback
    )
}

/// Name-ordered topological ranks among `members`. `precede` is (before, after).
fn name_ordered_ranks(members: &BTreeSet<&str>, precede: &[(&str, &str)]) -> BTreeMap<String, u32> {
    let mut incoming: BTreeMap<&str, u32> = members.iter().map(|product| (*product, 0)).collect();
    let mut outgoing: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (from, to) in precede {
        if !members.contains(from) || !members.contains(to) {
            continue;
        }
        if outgoing.entry(*from).or_default().insert(*to) {
            *incoming.entry(*to).or_default() += 1;
        }
    }
    let mut ready: BTreeSet<&str> = incoming
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(product, _)| *product)
        .collect();
    let mut ranks = BTreeMap::new();
    let mut order = 0u32;
    while let Some(next) = ready.pop_first() {
        ranks.insert(next.to_string(), order);
        order += 1;
        if let Some(successors) = outgoing.get(next) {
            for to in successors {
                if let Some(count) = incoming.get_mut(to) {
                    *count -= 1;
                    if *count == 0 {
                        ready.insert(*to);
                    }
                }
            }
        }
    }
    ranks
}

fn refuse_mixed_direction_edges(pending: &[(&str, Action)], edges: &[ContractEdge]) -> Result<()> {
    let actions: BTreeMap<&str, Action> = pending.iter().copied().collect();
    for (provider, dependent, contract) in edges {
        let Some(&provider_action) = actions.get(provider.as_str()) else {
            continue;
        };
        let Some(&dependent_action) = actions.get(dependent.as_str()) else {
            continue;
        };
        if provider_action == Action::Restart || dependent_action == Action::Restart {
            continue;
        }
        if reverse_contract_action(provider_action) != reverse_contract_action(dependent_action) {
            bail!(
                "plan requirement {contract} links {provider} ({provider_action}) and {dependent} ({dependent_action}) in opposite directions; split them into separate plans"
            );
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ContractPlanOrder {
    ranks: BTreeMap<String, u32>,
    target_edges: Vec<ContractEdge>,
    installed_edges: Vec<ContractEdge>,
    overlay_edges: Vec<ContractEdge>,
}

type PendingEntry = PendingChange;

/// Same-version Restart of remaining dependents whose providers change (ADR 0043 §6).
async fn schedule_dependency_rerenders(
    ctx: &mut Ctx,
    env: &str,
    pending: &mut Vec<PendingEntry>,
    installed_profiles: &BTreeMap<String, crate::software_compatibility::CompatibilityProfile>,
    target_profiles: &BTreeMap<String, crate::software_compatibility::CompatibilityProfile>,
    env_obj: &crate::pb::sekai::Object,
    host_products: &std::collections::HashSet<String>,
) -> Result<()> {
    let pending_actions: Vec<(&str, Action)> = pending
        .iter()
        .map(|entry| (entry.product.as_str(), entry.action))
        .collect();
    let remaining = overlay_profiles(installed_profiles, target_profiles, &pending_actions);
    let mut remaining_versions = BTreeMap::new();
    for (key, version) in &env_obj.properties {
        if let Some(product) = key.strip_prefix("deployed.") {
            remaining_versions.insert(product.to_string(), version.clone());
        }
    }
    for entry in pending.iter() {
        if matches!(entry.action, Action::Remove) {
            remaining_versions.remove(&entry.product);
        } else {
            remaining_versions.insert(entry.product.clone(), entry.to.clone());
        }
    }
    let mut current_deployed = BTreeMap::new();
    let mut remaining_deployed = BTreeMap::new();
    for (product, profile) in installed_profiles {
        if let Some(version) = env_obj.properties.get(&format!("deployed.{product}")) {
            current_deployed.insert(product.clone(), (version.clone(), profile.clone()));
        }
    }
    for (product, profile) in &remaining {
        if let Some(version) = remaining_versions.get(product) {
            remaining_deployed.insert(product.clone(), (version.clone(), profile.clone()));
        }
    }
    let pending_products: BTreeSet<String> =
        pending.iter().map(|entry| entry.product.clone()).collect();
    let mut extra = Vec::new();
    for (product, profile) in installed_profiles {
        if pending_products.contains(product) || host_products.contains(product) {
            continue;
        }
        let Some(version) = env_obj.properties.get(&format!("deployed.{product}")) else {
            continue;
        };
        let current =
            crate::dependency_document::document_for(product, profile, &current_deployed)?;
        let result = match remaining.get(product) {
            Some(remaining_profile) => crate::dependency_document::document_for(
                product,
                remaining_profile,
                &remaining_deployed,
            )?,
            None => None,
        };
        let result_digest = match &result {
            Some(document) => document.digest()?,
            None => String::new(),
        };
        let applied = crate::dependency_document::applied_digest(env_obj, product);
        let changed = current != result || (!result_digest.is_empty() && result_digest != applied);
        if !changed {
            continue;
        }
        let Some(manifest) = readable_manifest(ctx, &release_id(product, version)).await? else {
            continue;
        };
        if manifest.deploy.executor == Some(crate::software_executor::SoftwareExecutorKind::Host) {
            continue;
        }
        let target = pin_release(ctx, &release_id(product, version), env).await?;
        extra.push(PendingChange {
            instance: product.clone(),
            product: product.clone(),
            action: Action::Restart,
            from: Some(version.clone()),
            to: version.clone(),
            release: target,
            restore: None,
            kind: manifest.product.kind,
        });
    }
    pending.extend(extra);
    Ok(())
}

fn contract_plan_order(
    pending: &[(&str, Action)],
    target_profiles: &BTreeMap<String, crate::software_compatibility::CompatibilityProfile>,
    installed_profiles: &BTreeMap<String, crate::software_compatibility::CompatibilityProfile>,
) -> Result<ContractPlanOrder> {
    let target_edges = cross_release_contract_edges(target_profiles);
    let installed_edges = cross_release_contract_edges(installed_profiles);
    let remaining = overlay_profiles(installed_profiles, target_profiles, pending);
    crate::software_compatibility::refuse_unsatisfied_dependents(&remaining, installed_profiles)?;
    let overlay_edges = cross_release_contract_edges(&remaining);
    refuse_cross_release_cycle(&overlay_edges)?;
    refuse_mixed_direction_edges(pending, &overlay_edges)?;
    refuse_mixed_direction_edges(pending, &installed_edges)?;
    let actions: BTreeMap<&str, Action> = pending.iter().copied().collect();
    let members: BTreeSet<&str> = actions.keys().copied().collect();
    let mut precede = Vec::new();
    for (provider, dependent, _) in &overlay_edges {
        let Some(&provider_action) = actions.get(provider.as_str()) else {
            continue;
        };
        let Some(&dependent_action) = actions.get(dependent.as_str()) else {
            continue;
        };
        if dependent_action == Action::Restart && !reverse_contract_action(provider_action) {
            precede.push((provider.as_str(), dependent.as_str()));
        }
    }
    for (provider, dependent, _) in &target_edges {
        let Some(&provider_action) = actions.get(provider.as_str()) else {
            continue;
        };
        let Some(&dependent_action) = actions.get(dependent.as_str()) else {
            continue;
        };
        if reverse_contract_action(provider_action) || reverse_contract_action(dependent_action) {
            continue;
        }
        precede.push((provider.as_str(), dependent.as_str()));
    }
    for (provider, dependent, _) in &installed_edges {
        let Some(&provider_action) = actions.get(provider.as_str()) else {
            continue;
        };
        let Some(&dependent_action) = actions.get(dependent.as_str()) else {
            continue;
        };
        if provider_action == Action::Restart || dependent_action == Action::Restart {
            if reverse_contract_action(provider_action) && dependent_action == Action::Restart {
                precede.push((provider.as_str(), dependent.as_str()));
            } else if provider_action == Action::Restart
                && reverse_contract_action(dependent_action)
            {
                precede.push((dependent.as_str(), provider.as_str()));
            } else if dependent_action == Action::Restart
                && !reverse_contract_action(provider_action)
            {
                precede.push((provider.as_str(), dependent.as_str()));
            }
            continue;
        }
        if !reverse_contract_action(provider_action) || !reverse_contract_action(dependent_action) {
            continue;
        }
        precede.push((dependent.as_str(), provider.as_str()));
    }
    Ok(ContractPlanOrder {
        ranks: name_ordered_ranks(&members, &precede),
        target_edges,
        installed_edges,
        overlay_edges,
    })
}

/// Refuse when the sorted plan puts a dependent before its provider (or the
/// reverse on remove/downgrade/rollback). Host, agent, and removal keys can
/// otherwise override contract ranks.
fn refuse_inverted_contract_order(
    ordered: &[(&str, Action)],
    target_edges: &[ContractEdge],
    installed_edges: &[ContractEdge],
    overlay_edges: &[ContractEdge],
) -> Result<()> {
    let index: BTreeMap<&str, usize> = ordered
        .iter()
        .enumerate()
        .map(|(i, (product, _))| (*product, i))
        .collect();
    let actions: BTreeMap<&str, Action> = ordered.iter().copied().collect();
    for (edges, reverse) in [(target_edges, false), (installed_edges, true)] {
        for (provider, dependent, contract) in edges {
            let Some(&provider_index) = index.get(provider.as_str()) else {
                continue;
            };
            let Some(&dependent_index) = index.get(dependent.as_str()) else {
                continue;
            };
            let Some(&provider_action) = actions.get(provider.as_str()) else {
                continue;
            };
            let Some(&dependent_action) = actions.get(dependent.as_str()) else {
                continue;
            };
            if reverse_contract_action(provider_action) != reverse
                || reverse_contract_action(dependent_action) != reverse
            {
                continue;
            }
            if reverse && dependent_index > provider_index {
                bail!(
                    "plan requirement {contract} is inverted: {dependent} must precede {provider} when removing or downgrading"
                );
            }
            if !reverse && provider_index > dependent_index {
                bail!(
                    "plan requirement {contract} is inverted: {provider} must precede {dependent} in this plan"
                );
            }
        }
    }
    for (provider, dependent, contract) in target_edges
        .iter()
        .chain(installed_edges.iter())
        .chain(overlay_edges.iter())
    {
        let Some(&provider_index) = index.get(provider.as_str()) else {
            continue;
        };
        let Some(&dependent_index) = index.get(dependent.as_str()) else {
            continue;
        };
        let Some(&dependent_action) = actions.get(dependent.as_str()) else {
            continue;
        };
        if dependent_action == Action::Restart && provider_index > dependent_index {
            bail!(
                "plan requirement {contract} is inverted: {provider} must precede {dependent} re-render in this plan"
            );
        }
    }
    Ok(())
}

/// Compute the steps that converge the environment on its subscribed channels.
pub(super) async fn compute(ctx: &mut Ctx, env: &str) -> Result<Vec<Step>> {
    let executors = crate::software_executor::SoftwareExecutors::try_from_process()?;
    Ok(compute_snapshot(ctx, env, &executors).await?.1)
}

/// Compute and persist an immutable executable plan before any step is run.
/// Host steps read the applier's records through `executors`.
pub(super) async fn create(
    ctx: &mut Ctx,
    env: &str,
    executors: &crate::software_executor::SoftwareExecutors,
) -> Result<Plan> {
    let (inputs, steps) = compute_snapshot(ctx, env, executors).await?;
    create_with_content(ctx, executors, env, inputs, steps, None).await
}

/// Persist a catalog-only plan only when it includes `product` at `release`.
///
/// Failed-target retry uses this so a moved channel head cannot store a plan
/// for a different release.
pub(super) async fn create_for_held_target(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    release: &str,
) -> Result<Plan> {
    let executors = crate::software_executor::SoftwareExecutors::try_from_process()?;
    let (inputs, steps) = compute_snapshot(ctx, env, &executors).await?;
    if !steps
        .iter()
        .any(|step| step.product == product && step.release_id == release)
    {
        bail!("explicit retry did not include held failed target {product} ({release})");
    }
    create_with_content(ctx, &executors, env, inputs, steps, None).await
}

/// Reconcile planning may emit Restart steps from live observe/health evidence.
///
/// Zero-step output is ephemeral: it is not stored, has no priors annotation,
/// and is not served to a runtime agent. Operator `create` still persists
/// empty Computed plans so durable callers can reload the returned id.
pub(super) async fn create_for_reconcile(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    let executors = crate::software_executor::SoftwareExecutors::try_from_process()?;
    let (inputs, mut steps) =
        compute_snapshot_with_policy(ctx, env, ConvergencePolicy::reconcile(), &executors).await?;
    if steps.is_empty() {
        return assemble_plan(env, inputs, &mut steps, None);
    }
    create_with_content(ctx, &executors, env, inputs, steps, None).await
}

/// Persist a reconcile-policy plan, even with zero steps. Held failed targets
/// stay held, unlike operator `create`, which retries them.
pub(super) async fn create_holding_failed_targets(ctx: &mut Ctx, env: &str) -> Result<Plan> {
    let executors = crate::software_executor::SoftwareExecutors::try_from_process()?;
    let (inputs, steps) =
        compute_snapshot_with_policy(ctx, env, ConvergencePolicy::reconcile(), &executors).await?;
    create_with_content(ctx, &executors, env, inputs, steps, None).await
}

/// Persist an explicitly constructed operation, such as a rollback, as a plan.
pub(super) async fn create_from_steps(ctx: &mut Ctx, env: &str, steps: Vec<Step>) -> Result<Plan> {
    admit_preview_environment(ctx, env).await?;
    let executors = crate::software_executor::SoftwareExecutors::try_from_process()?;
    create_with_content(ctx, &executors, env, Vec::new(), steps, None).await
}

pub(super) async fn create_from_steps_with_recovery(
    ctx: &mut Ctx,
    env: &str,
    steps: Vec<Step>,
    reason: String,
) -> Result<Plan> {
    admit_preview_environment(ctx, env).await?;
    let executors = crate::software_executor::SoftwareExecutors::try_from_process()?;
    create_with_content(ctx, &executors, env, Vec::new(), steps, Some(reason)).await
}

async fn admit_preview_environment(ctx: &mut Ctx, env: &str) -> Result<()> {
    let env_obj = crate::environment::active_environment(ctx, env).await?;
    crate::preview::admit_plan(&env_obj, crate::now_millis())
}

fn assemble_plan(
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
    Ok(Plan {
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
        credential_runway: None,
    })
}

async fn create_with_content(
    ctx: &mut Ctx,
    executors: &crate::software_executor::SoftwareExecutors,
    env: &str,
    inputs: Vec<DesiredStateInput>,
    steps: Vec<Step>,
    recalled_recovery_reason: Option<String>,
) -> Result<Plan> {
    let mut steps = bind_host_steps(ctx, executors, env, steps).await?;
    for step in &steps {
        require_same_executor(ctx, executors, step).await?;
    }
    let mut plan = assemble_plan(env, inputs, &mut steps, recalled_recovery_reason)?;
    // Optional advisory priors (default off). Never hard-block or change steps.
    if let Ok(inspect) = inspect_environment(ctx, env).await {
        let _ = crate::plan_priors::annotate_plan_with_priors(
            &mut plan,
            &inspect,
            &crate::plan_priors::PriorConfig::from_env(),
        );
        plan.credential_runway =
            crate::trust_posture::environment_runway(ctx, inspect.maintenance.as_ref());
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
    let instance = product;
    let product = product_for_instance(&env_obj.properties, instance);
    let current = env_obj
        .properties
        .get(&format!("deployed.{instance}"))
        .cloned();
    let Some(prev) = env_obj
        .properties
        .get(&format!("deployed_prev.{instance}"))
        .cloned()
        .filter(|v| !v.is_empty())
    else {
        bail!("no previous version of {instance} recorded in {env} — nothing to roll back to");
    };
    let prev_id = release_id(&product, &prev);
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
    let mut remaining = BTreeMap::new();
    for (key, value) in &env_obj.properties {
        let Some(name) = key.strip_prefix("deployed.") else {
            continue;
        };
        if name == instance {
            continue;
        }
        let other = product_for_instance(&env_obj.properties, name);
        if let Some(manifest) =
            readable_manifest(ctx, &deployed_release_id(&env_obj.properties, name, value)).await?
            && let Some(profile) = manifest.compatibility
        {
            remaining.insert(other, profile);
        }
    }
    let mut previous = remaining.clone();
    if let Some(version) = current.as_deref()
        && let Some(manifest) = readable_manifest(ctx, &release_id(&product, version)).await?
        && let Some(profile) = manifest.compatibility
    {
        previous.insert(product.clone(), profile);
    }
    if let Some(manifest) = readable_manifest(ctx, &prev_id).await?
        && let Some(profile) = manifest.compatibility
    {
        remaining.insert(product.clone(), profile);
    }
    crate::software_compatibility::refuse_unsatisfied_dependents(&remaining, &previous)?;
    crate::software_compatibility::require_release(ctx, env, &prev_id).await?;
    let restore = match current.as_deref() {
        Some(version) => {
            let current_id = release_id(&product, version);
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
    let step_instance = if instance == product.as_str() {
        String::new()
    } else {
        instance.to_string()
    };
    Ok(Step {
        id: format!("{}:rollback:{instance}", env_id(env)),
        order: 0,
        release_id: target.release_id,
        release_digest: target.digest,
        artifact_digest: target.artifact_digest,
        workdir: target.workdir,
        host: None,
        restore,
        product,
        instance: step_instance,
        action: Action::Rollback,
        from: current,
        to: prev,
    })
}

/// A same-version restart of the currently deployed release.
pub(super) async fn restart_step(ctx: &mut Ctx, env: &str, product: &str) -> Result<Step> {
    validate_identifier("product", product)?;
    let env_obj = crate::environment::environment(ctx, env).await?;
    let instance = product;
    let product = product_for_instance(&env_obj.properties, instance);
    let Some(current) = env_obj
        .properties
        .get(&format!("deployed.{instance}"))
        .cloned()
        .filter(|value| !value.is_empty())
    else {
        bail!("no deployed version of {instance} recorded in {env} — nothing to restart");
    };
    let current_id = release_id(&product, &current);
    if release_is_recalled(ctx, &current_id).await? {
        bail!("cannot restart recalled release {current_id}");
    }
    let target = pin_release(ctx, &current_id, env).await?;
    crate::software_compatibility::require_release(ctx, env, &current_id).await?;
    let step_instance = if instance == product.as_str() {
        String::new()
    } else {
        instance.to_string()
    };
    Ok(Step {
        id: format!("{}:restart:{instance}", env_id(env)),
        order: 0,
        release_id: target.release_id,
        release_digest: target.digest,
        artifact_digest: target.artifact_digest,
        workdir: target.workdir,
        host: None,
        restore: None,
        product,
        instance: step_instance,
        action: Action::Restart,
        from: Some(current.clone()),
        to: current,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile_observes_with_the_release_executor_and_never_a_host_release() {
        use crate::software_executor::{
            FakeSoftwareExecutor, SoftwareExecutor, SoftwareExecutorKind as Kind, SoftwareExecutors,
        };
        let manifest = |executor: &str| {
            crate::manifest::parse_raw(&format!(
                "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\n{executor}\n"
            ))
            .unwrap()
        };
        let in_process: std::sync::Arc<dyn SoftwareExecutor> =
            std::sync::Arc::new(FakeSoftwareExecutor::new());
        let executors = SoftwareExecutors::default()
            .with_adapter(Kind::KubernetesInProcess, in_process.clone())
            .with_adapter(Kind::Host, std::sync::Arc::new(FakeSoftwareExecutor::new()));
        let observed =
            observe_executor(&executors, &manifest("executor = \"kubernetes-inprocess\""))
                .unwrap()
                .unwrap();
        assert!(std::sync::Arc::ptr_eq(&observed, &in_process));
        // The shell default and a host release are never observed.
        for executor in ["", "executor = \"host\""] {
            assert!(
                observe_executor(&executors, &manifest(executor))
                    .unwrap()
                    .is_none(),
                "{executor}"
            );
        }
        // Nor is an unnamed test default, as before.
        let fake_default =
            SoftwareExecutors::with_default(std::sync::Arc::new(FakeSoftwareExecutor::new()));
        assert!(
            observe_executor(&fake_default, &manifest(""))
                .unwrap()
                .is_none()
        );
    }

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

    fn test_profile_optional(
        requires: &[(&str, &str)],
    ) -> crate::software_compatibility::CompatibilityProfile {
        use crate::software_compatibility::{
            CompatibilityProfile, ComponentPin, ComponentRequirement, ContractRequirement,
        };
        CompatibilityProfile {
            version: 2,
            components: BTreeMap::from([(
                "main".into(),
                ComponentRequirement {
                    pin: ComponentPin::Revision("a".repeat(40)),
                    requires: requires
                        .iter()
                        .map(|(contract, minimum)| {
                            (
                                (*contract).into(),
                                ContractRequirement::Detailed {
                                    minimum: (*minimum).into(),
                                    optional: true,
                                },
                            )
                        })
                        .collect(),
                    provides: BTreeMap::new(),
                },
            )]),
            capabilities: Vec::new(),
            facts: BTreeMap::new(),
            schema: None,
            max_evidence_age_ms: 60_000,
        }
    }

    fn test_profile(
        requires: &[(&str, &str)],
        provides: &[(&str, &str)],
    ) -> crate::software_compatibility::CompatibilityProfile {
        use crate::software_compatibility::{
            CompatibilityProfile, ComponentPin, ComponentRequirement, ContractRequirement,
        };
        CompatibilityProfile {
            version: 2,
            components: BTreeMap::from([(
                "main".into(),
                ComponentRequirement {
                    pin: ComponentPin::Revision("a".repeat(40)),
                    requires: requires
                        .iter()
                        .map(|(contract, minimum)| {
                            (
                                (*contract).into(),
                                ContractRequirement::Minimum((*minimum).into()),
                            )
                        })
                        .collect(),
                    provides: provides
                        .iter()
                        .map(|(contract, version)| ((*contract).into(), (*version).into()))
                        .collect(),
                },
            )]),
            capabilities: Vec::new(),
            facts: BTreeMap::new(),
            schema: None,
            max_evidence_age_ms: 60_000,
        }
    }

    #[test]
    fn contract_order_puts_provider_before_dependent_instead_of_name_order() {
        let profiles = BTreeMap::from([
            ("app".into(), test_profile(&[("database", "1.0.0")], &[])),
            ("db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let ranks = contract_plan_order(
            &[("app", Action::Install), ("db", Action::Install)],
            &profiles,
            &profiles,
        )
        .unwrap()
        .ranks;
        assert!(ranks["db"] < ranks["app"], "{ranks:?}");
    }

    #[test]
    fn contract_order_keeps_name_order_without_edges() {
        let profiles = BTreeMap::from([
            ("beta".into(), test_profile(&[], &[])),
            ("alpha".into(), test_profile(&[], &[])),
        ]);
        let ranks = contract_plan_order(
            &[("beta", Action::Install), ("alpha", Action::Install)],
            &profiles,
            &profiles,
        )
        .unwrap()
        .ranks;
        assert!(ranks["alpha"] < ranks["beta"], "{ranks:?}");
    }

    #[test]
    fn contract_order_removes_dependent_before_provider() {
        let profiles = BTreeMap::from([
            ("app".into(), test_profile(&[("database", "1.0.0")], &[])),
            ("db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let ranks = contract_plan_order(
            &[("app", Action::Remove), ("db", Action::Remove)],
            &profiles,
            &profiles,
        )
        .unwrap()
        .ranks;
        assert!(ranks["app"] < ranks["db"], "{ranks:?}");
    }

    #[test]
    fn contract_order_refuses_a_cross_release_cycle() {
        let profiles = BTreeMap::from([
            (
                "app".into(),
                test_profile(&[("database", "1.0.0")], &[("api", "1.0.0")]),
            ),
            (
                "db".into(),
                test_profile(&[("api", "1.0.0")], &[("database", "1.0.0")]),
            ),
        ]);
        let err = contract_plan_order(
            &[("app", Action::Install), ("db", Action::Install)],
            &profiles,
            &profiles,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("plan requirement cycle"), "{err}");
        assert!(err.contains("app"), "{err}");
        assert!(err.contains("db"), "{err}");
        assert!(err.contains("database") || err.contains("api"), "{err}");
    }

    #[test]
    fn contract_order_refuses_mixed_upgrade_and_remove() {
        let profiles = BTreeMap::from([
            ("app".into(), test_profile(&[("database", "1.0.0")], &[])),
            ("db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let err = contract_plan_order(
            &[("app", Action::Remove), ("db", Action::Upgrade)],
            &profiles,
            &profiles,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("opposite directions"), "{err}");
        assert!(err.contains("database"), "{err}");
    }

    #[test]
    fn contract_order_refuses_mixed_direction_from_installed_edge() {
        let target = BTreeMap::from([
            ("z-app".into(), test_profile(&[], &[])),
            ("a-db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let installed = BTreeMap::from([
            ("z-app".into(), test_profile(&[("database", "1.0.0")], &[])),
            ("a-db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let err = contract_plan_order(
            &[("z-app", Action::Downgrade), ("a-db", Action::Upgrade)],
            &target,
            &installed,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("opposite directions"), "{err}");
        assert!(err.contains("database"), "{err}");
    }

    #[test]
    fn contract_order_keeps_name_order_across_forward_and_reverse_without_edges() {
        let profiles = BTreeMap::new();
        let ranks = contract_plan_order(
            &[
                ("a", Action::Upgrade),
                ("b", Action::Upgrade),
                ("z", Action::Downgrade),
            ],
            &profiles,
            &profiles,
        )
        .unwrap()
        .ranks;
        assert!(
            ranks["a"] < ranks["b"] && ranks["b"] < ranks["z"],
            "{ranks:?}"
        );
    }

    #[test]
    fn contract_order_detects_cycle_through_an_unchanged_release() {
        let profiles = BTreeMap::from([
            (
                "app".into(),
                test_profile(&[("database", "1.0.0")], &[("api", "1.0.0")]),
            ),
            (
                "db".into(),
                test_profile(&[("api", "1.0.0")], &[("database", "1.0.0")]),
            ),
        ]);
        let err = contract_plan_order(&[("app", Action::Upgrade)], &profiles, &profiles)
            .unwrap_err()
            .to_string();
        assert!(err.contains("plan requirement cycle"), "{err}");
        assert!(err.contains("app") && err.contains("db"), "{err}");
    }

    #[test]
    fn contract_order_detects_cycle_across_target_and_installed_profiles() {
        let target = BTreeMap::from([(
            "app".into(),
            test_profile(&[("database", "1.0.0")], &[("api", "1.0.0")]),
        )]);
        let installed = BTreeMap::from([(
            "db".into(),
            test_profile(&[("api", "1.0.0")], &[("database", "1.0.0")]),
        )]);
        let err = contract_plan_order(&[("app", Action::Upgrade)], &target, &installed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("plan requirement cycle"), "{err}");
        assert!(err.contains("app") && err.contains("db"), "{err}");
    }

    #[test]
    fn contract_order_allows_upgrade_that_breaks_an_installed_cycle() {
        let target = BTreeMap::from([
            (
                "a".into(),
                test_profile(&[("database", "1.0.0")], &[("api", "1.0.0")]),
            ),
            ("b".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let installed = BTreeMap::from([
            ("a".into(), test_profile(&[], &[("api", "1.0.0")])),
            (
                "b".into(),
                test_profile(&[("api", "1.0.0")], &[("database", "1.0.0")]),
            ),
        ]);
        let ranks = contract_plan_order(
            &[("a", Action::Upgrade), ("b", Action::Upgrade)],
            &target,
            &installed,
        )
        .unwrap()
        .ranks;
        assert!(ranks["b"] < ranks["a"], "{ranks:?}");
    }

    #[test]
    fn contract_order_drops_installed_profile_when_target_has_none() {
        let target = BTreeMap::new();
        let installed = BTreeMap::from([
            (
                "a".into(),
                test_profile(&[("database", "1.0.0")], &[("api", "1.0.0")]),
            ),
            ("b".into(), test_profile(&[], &[])),
        ]);
        let ranks = contract_plan_order(&[("a", Action::Upgrade)], &target, &installed)
            .unwrap()
            .ranks;
        assert!(ranks.contains_key("a"), "{ranks:?}");
    }

    #[test]
    fn contract_order_refuses_remove_that_unsatisfies_a_remaining_dependent() {
        let target = BTreeMap::from([(
            "a".into(),
            test_profile(&[("database", "1.0.0")], &[("api", "1.0.0")]),
        )]);
        let installed = BTreeMap::from([
            (
                "a".into(),
                test_profile(&[("database", "1.0.0")], &[("api", "1.0.0")]),
            ),
            (
                "b".into(),
                test_profile(&[("api", "1.0.0")], &[("database", "1.0.0")]),
            ),
        ]);
        let err = contract_plan_order(&[("a", Action::Remove)], &target, &installed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("installed dependent b"), "{err}");
        assert!(err.contains("api"), "{err}");
    }

    #[test]
    fn contract_order_refuses_upgrade_that_drops_a_required_contract() {
        let target = BTreeMap::from([("db".into(), test_profile(&[], &[]))]);
        let installed = BTreeMap::from([
            ("app".into(), test_profile(&[("database", "1.0.0")], &[])),
            ("db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let err = contract_plan_order(&[("db", Action::Upgrade)], &target, &installed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("installed dependent app"), "{err}");
        assert!(err.contains("database"), "{err}");
    }

    #[test]
    fn contract_order_refuses_rollback_that_drops_a_required_contract() {
        let target = BTreeMap::from([("db".into(), test_profile(&[], &[]))]);
        let installed = BTreeMap::from([
            ("app".into(), test_profile(&[("database", "1.0.0")], &[])),
            ("db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let err = contract_plan_order(&[("db", Action::Rollback)], &target, &installed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("installed dependent app"), "{err}");
        assert!(err.contains("database"), "{err}");
    }

    #[test]
    fn contract_order_allows_remove_of_an_optional_provider() {
        let installed = BTreeMap::from([
            (
                "app".into(),
                test_profile_optional(&[("database", "1.0.0")]),
            ),
            ("db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let ranks = contract_plan_order(&[("db", Action::Remove)], &BTreeMap::new(), &installed)
            .unwrap()
            .ranks;
        assert!(ranks.contains_key("db"), "{ranks:?}");
    }

    #[test]
    fn contract_order_allows_rerender_restart_with_optional_provider_remove() {
        let installed = BTreeMap::from([
            (
                "app".into(),
                test_profile_optional(&[("database", "1.0.0")]),
            ),
            ("db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let ranks = contract_plan_order(
            &[("db", Action::Remove), ("app", Action::Restart)],
            &BTreeMap::new(),
            &installed,
        )
        .unwrap()
        .ranks;
        assert!(ranks["db"] < ranks["app"], "{ranks:?}");
    }

    #[test]
    fn contract_order_orders_provider_install_before_dependent_rerender() {
        let target = BTreeMap::from([("db".into(), test_profile(&[], &[("database", "1.0.0")]))]);
        let installed = BTreeMap::from([(
            "app".into(),
            test_profile_optional(&[("database", "1.0.0")]),
        )]);
        let ranks = contract_plan_order(
            &[("db", Action::Install), ("app", Action::Restart)],
            &target,
            &installed,
        )
        .unwrap()
        .ranks;
        assert!(ranks["db"] < ranks["app"], "{ranks:?}");
    }

    #[test]
    fn contract_order_allows_remove_when_another_provider_still_satisfies() {
        let installed = BTreeMap::from([
            ("app".into(), test_profile(&[("database", "1.0.0")], &[])),
            ("db".into(), test_profile(&[], &[("database", "1.0.0")])),
            ("db2".into(), test_profile(&[], &[("database", "1.1.0")])),
        ]);
        let ranks = contract_plan_order(&[("db", Action::Remove)], &BTreeMap::new(), &installed)
            .unwrap()
            .ranks;
        assert!(ranks.contains_key("db"), "{ranks:?}");
    }

    #[test]
    fn contract_order_reverse_uses_installed_edges_when_target_drops_them() {
        let target = BTreeMap::from([
            ("z-app".into(), test_profile(&[], &[])),
            ("a-db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let installed = BTreeMap::from([
            ("z-app".into(), test_profile(&[("database", "1.0.0")], &[])),
            ("a-db".into(), test_profile(&[], &[("database", "1.0.0")])),
        ]);
        let ranks = contract_plan_order(
            &[("z-app", Action::Downgrade), ("a-db", Action::Downgrade)],
            &target,
            &installed,
        )
        .unwrap()
        .ranks;
        assert!(ranks["z-app"] < ranks["a-db"], "{ranks:?}");
    }

    #[test]
    fn contract_order_refuses_when_agent_last_inverts_a_provider_edge() {
        let agent = crate::runtime_self_upgrade::SELF_PRODUCT;
        let edges = vec![(agent.to_string(), "app".to_string(), "runtime".to_string())];
        let err = refuse_inverted_contract_order(
            &[("app", Action::Upgrade), (agent, Action::Upgrade)],
            &edges,
            &[],
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("inverted"), "{err}");
        assert!(err.contains("runtime"), "{err}");
        assert!(err.contains(agent), "{err}");
        assert!(err.contains("app"), "{err}");
    }

    #[tokio::test]
    async fn plan_orders_provider_before_dependent_instead_of_name_order() {
        use crate::software_compatibility::{
            CompatibilityEvidence, ComponentObservation, ComponentPin, MigrationState,
        };
        let root = std::env::temp_dir().join(format!(
            "tenkai-plan-order-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        let pin = "a".repeat(40);
        let publish = |product: &str, extra: &str| {
            format!(
                "[product]\nname = \"{product}\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n[compatibility]\nversion = 1\nmax_evidence_age_ms = 60000\n[compatibility.components.main.pin]\nkind = \"revision\"\nvalue = \"{pin}\"\n{extra}"
            )
        };
        let db_raw = publish(
            "db",
            "[compatibility.components.main.provides]\ndatabase = \"1.0.0\"\n",
        );
        let app_raw = publish(
            "app",
            "[compatibility.components.main.requires]\ndatabase = \"1.0.0\"\n",
        );
        for (product, raw) in [("db", &db_raw), ("app", &app_raw)] {
            let dir = root.join(product);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("tenkai.toml"), raw).unwrap();
            crate::catalog::publish(
                &mut ctx,
                &dir.join("tenkai.toml"),
                &crate::catalog::PublishOptions {
                    allow_unsigned_development: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        let actor = crate::auth_context::test_management_context("plan-order");
        crate::catalog::promote(&mut ctx, &actor, "db@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "app@1.0.0", "stable")
            .await
            .unwrap();
        subscribe(&mut ctx, "local", "db", "stable").await.unwrap();
        subscribe(&mut ctx, "local", "app", "stable").await.unwrap();
        let evidence = |digest: String, requires, provides, contracts| CompatibilityEvidence {
            version: 1,
            release_digest: digest,
            environment: "local".into(),
            observed_at_ms: crate::now_millis() - 1_000,
            components: BTreeMap::from([(
                "main".into(),
                ComponentObservation {
                    pin: ComponentPin::Revision(pin.clone()),
                    requires,
                    provides,
                },
            )]),
            contracts,
            capabilities: Vec::new(),
            schema_version: None,
            migration: MigrationState::Stable,
        };
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            evidence(
                crate::manifest::digest(&db_raw),
                BTreeMap::new(),
                BTreeMap::from([("database".into(), "1.0.0".into())]),
                BTreeMap::from([("database".into(), "1.0.0".into())]),
            ),
        )
        .await
        .unwrap();
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            evidence(
                crate::manifest::digest(&app_raw),
                BTreeMap::from([("database".into(), "1.0.0".into())]),
                BTreeMap::new(),
                BTreeMap::from([("database".into(), "1.0.0".into())]),
            ),
        )
        .await
        .unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        let products: Vec<_> = plan
            .steps
            .iter()
            .map(|step| step.product.as_str())
            .collect();
        assert_eq!(products, vec!["db", "app"], "{products:?}");
        std::fs::remove_dir_all(root).unwrap();
    }

    async fn publish_compat_release(
        ctx: &mut Ctx,
        root: &std::path::Path,
        product: &str,
        extra: &str,
    ) -> String {
        let pin = "a".repeat(40);
        let raw = format!(
            "[product]\nname = \"{product}\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n[compatibility]\nversion = 1\nmax_evidence_age_ms = 60000\n[compatibility.components.{product}.pin]\nkind = \"revision\"\nvalue = \"{pin}\"\n{extra}"
        );
        let dir = root.join(product);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tenkai.toml"), &raw).unwrap();
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
        raw
    }

    fn compat_evidence(
        digest: String,
        component: &str,
        pin: &str,
        requires: BTreeMap<String, String>,
        provides: BTreeMap<String, String>,
        contracts: BTreeMap<String, String>,
    ) -> crate::software_compatibility::CompatibilityEvidence {
        use crate::software_compatibility::{
            CompatibilityEvidence, ComponentObservation, ComponentPin, MigrationState,
        };
        CompatibilityEvidence {
            version: 1,
            release_digest: digest,
            environment: "local".into(),
            observed_at_ms: crate::now_millis() - 1_000,
            components: BTreeMap::from([(
                component.into(),
                ComponentObservation {
                    pin: ComponentPin::Revision(pin.into()),
                    requires,
                    provides,
                },
            )]),
            contracts,
            capabilities: Vec::new(),
            schema_version: None,
            migration: MigrationState::Stable,
        }
    }

    #[tokio::test]
    async fn reconcile_holds_unmet_required_contract_and_resumes_when_provider_deploys() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-dep-hold-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("state.db");
        let mut ctx = Ctx::embedded(&db_path).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        let pin = "a".repeat(40);
        let db_raw = publish_compat_release(
            &mut ctx,
            &root,
            "db",
            "[compatibility.components.db.provides]\ndatabase = \"1.0.0\"\n",
        )
        .await;
        let app_raw = publish_compat_release(
            &mut ctx,
            &root,
            "app",
            "[compatibility.components.app.requires]\ndatabase = \"1.0.0\"\n",
        )
        .await;
        let side_raw = publish_compat_release(&mut ctx, &root, "side", "").await;
        let actor = crate::auth_context::test_management_context("dep-hold");
        for product in ["db", "app", "side"] {
            crate::catalog::promote(&mut ctx, &actor, &format!("{product}@1.0.0"), "stable")
                .await
                .unwrap();
        }
        subscribe(&mut ctx, "local", "app", "stable").await.unwrap();
        subscribe(&mut ctx, "local", "side", "stable")
            .await
            .unwrap();
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            compat_evidence(
                crate::manifest::digest(&app_raw),
                "app",
                &pin,
                BTreeMap::from([("database".into(), "1.0.0".into())]),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        )
        .await
        .unwrap();
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            compat_evidence(
                crate::manifest::digest(&side_raw),
                "side",
                &pin,
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        )
        .await
        .unwrap();
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            compat_evidence(
                crate::manifest::digest(&db_raw),
                "db",
                &pin,
                BTreeMap::new(),
                BTreeMap::from([("database".into(), "1.0.0".into())]),
                BTreeMap::new(),
            ),
        )
        .await
        .unwrap();

        let err = crate::plan::create(&mut ctx, "local").await.unwrap_err();
        assert!(
            err.downcast_ref::<crate::software_compatibility::CompatibilityBlocked>()
                .is_some(),
            "{err}"
        );

        let held = crate::plan::create_for_reconcile(&mut ctx, "local")
            .await
            .unwrap();
        let products: Vec<_> = held
            .steps
            .iter()
            .map(|step| step.product.as_str())
            .collect();
        assert_eq!(products, vec!["side"], "{products:?}");
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        let hold = crate::environment::dependency_hold(&env.properties, "app").unwrap();
        assert_eq!(hold.release_id, "tenkai:release:app@1.0.0");
        assert_eq!(hold.contracts, vec![("database".into(), "1.0.0".into())]);
        let held_at = hold.held_at;

        let again = crate::plan::create_for_reconcile(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(
            again
                .steps
                .iter()
                .map(|step| step.product.as_str())
                .collect::<Vec<_>>(),
            vec!["side"]
        );
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(
            crate::environment::dependency_hold(&env.properties, "app")
                .unwrap()
                .held_at,
            held_at
        );

        drop(ctx);
        let mut ctx = Ctx::embedded(&db_path).unwrap();
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(
            crate::environment::dependency_hold(&env.properties, "app")
                .unwrap()
                .held_at,
            held_at
        );

        crate::environment::reconcile_deployment(&mut ctx, "local", "db", Some("1.0.0"))
            .await
            .unwrap();
        let resumed = crate::plan::create_for_reconcile(&mut ctx, "local")
            .await
            .unwrap();
        let products: Vec<_> = resumed
            .steps
            .iter()
            .map(|step| step.product.as_str())
            .collect();
        assert!(products.contains(&"app"), "{products:?}");
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(
            crate::environment::dependency_hold(&env.properties, "app"),
            None
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn optional_requirement_does_not_hold_on_reconcile() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-dep-hold-opt-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        let pin = "a".repeat(40);
        let raw = format!(
            "[product]\nname = \"app\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n[compatibility]\nversion = 2\nmax_evidence_age_ms = 60000\n[compatibility.components.app.pin]\nkind = \"revision\"\nvalue = \"{pin}\"\n[compatibility.components.app.requires]\ndatabase = {{ minimum = \"1.0.0\", optional = true }}\n"
        );
        let dir = root.join("app");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tenkai.toml"), &raw).unwrap();
        crate::catalog::publish(
            &mut ctx,
            &dir.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("dep-hold-opt");
        crate::catalog::promote(&mut ctx, &actor, "app@1.0.0", "stable")
            .await
            .unwrap();
        subscribe(&mut ctx, "local", "app", "stable").await.unwrap();
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            compat_evidence(
                crate::manifest::digest(&raw),
                "app",
                &pin,
                BTreeMap::from([("database".into(), "1.0.0".into())]),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        )
        .await
        .unwrap();
        let plan = crate::plan::create_for_reconcile(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(plan.steps[0].product, "app");
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(
            crate::environment::dependency_hold(&env.properties, "app"),
            None
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn optional_provider_arrival_rerenders_installed_dependent() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-dep-doc-arrive-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        let pin = "a".repeat(40);
        let app_raw = format!(
            "[product]\nname = \"app\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n[compatibility]\nversion = 2\nmax_evidence_age_ms = 60000\n[compatibility.components.app.pin]\nkind = \"revision\"\nvalue = \"{pin}\"\n[compatibility.components.app.requires]\ndatabase = {{ minimum = \"1.0.0\", optional = true }}\n"
        );
        let db_raw = format!(
            "[product]\nname = \"db\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n[compatibility]\nversion = 2\nmax_evidence_age_ms = 60000\n[compatibility.components.db.pin]\nkind = \"revision\"\nvalue = \"{pin}\"\n[compatibility.components.db.provides]\ndatabase = \"1.0.0\"\n"
        );
        for (product, raw) in [("app", &app_raw), ("db", &db_raw)] {
            let dir = root.join(product);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("tenkai.toml"), raw).unwrap();
            crate::catalog::publish(
                &mut ctx,
                &dir.join("tenkai.toml"),
                &crate::catalog::PublishOptions {
                    allow_unsigned_development: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        let actor = crate::auth_context::test_management_context("dep-doc-arrive");
        crate::catalog::promote(&mut ctx, &actor, "app@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "db@1.0.0", "stable")
            .await
            .unwrap();
        subscribe(&mut ctx, "local", "app", "stable").await.unwrap();
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            compat_evidence(
                crate::manifest::digest(&app_raw),
                "app",
                &pin,
                BTreeMap::from([("database".into(), "1.0.0".into())]),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        )
        .await
        .unwrap();
        crate::environment::reconcile_deployment(&mut ctx, "local", "app", Some("1.0.0"))
            .await
            .unwrap();
        subscribe(&mut ctx, "local", "db", "stable").await.unwrap();
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            compat_evidence(
                crate::manifest::digest(&db_raw),
                "db",
                &pin,
                BTreeMap::new(),
                BTreeMap::from([("database".into(), "1.0.0".into())]),
                BTreeMap::new(),
            ),
        )
        .await
        .unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        let steps: Vec<_> = plan
            .steps
            .iter()
            .map(|step| (step.product.as_str(), step.action))
            .collect();
        assert_eq!(
            steps,
            vec![("db", Action::Install), ("app", Action::Restart)],
            "{steps:?}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn apply_writes_identical_dependency_document_on_retry() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-dep-doc-apply-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        let pin = "a".repeat(40);
        let db_raw = format!(
            "[product]\nname = \"db\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n[compatibility]\nversion = 2\nmax_evidence_age_ms = 60000\n[compatibility.components.db.pin]\nkind = \"revision\"\nvalue = \"{pin}\"\n[compatibility.components.db.provides]\ndatabase = \"1.3.0\"\n"
        );
        let app_raw = format!(
            "[product]\nname = \"app\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n[compatibility]\nversion = 2\nmax_evidence_age_ms = 60000\n[compatibility.components.app.pin]\nkind = \"revision\"\nvalue = \"{pin}\"\n[compatibility.components.app.requires]\ndatabase = \"1.0.0\"\nconnector = {{ minimum = \"0.1.0\", optional = true }}\n"
        );
        for (product, raw) in [("db", &db_raw), ("app", &app_raw)] {
            let dir = root.join(product);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("tenkai.toml"), raw).unwrap();
            crate::catalog::publish(
                &mut ctx,
                &dir.join("tenkai.toml"),
                &crate::catalog::PublishOptions {
                    allow_unsigned_development: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        let actor = crate::auth_context::test_management_context("dep-doc-apply");
        crate::catalog::promote(&mut ctx, &actor, "db@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "app@1.0.0", "stable")
            .await
            .unwrap();
        subscribe(&mut ctx, "local", "db", "stable").await.unwrap();
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            compat_evidence(
                crate::manifest::digest(&db_raw),
                "db",
                &pin,
                BTreeMap::new(),
                BTreeMap::from([("database".into(), "1.3.0".into())]),
                BTreeMap::new(),
            ),
        )
        .await
        .unwrap();
        crate::environment::reconcile_deployment(&mut ctx, "local", "db", Some("1.0.0"))
            .await
            .unwrap();
        subscribe(&mut ctx, "local", "app", "stable").await.unwrap();
        crate::software_compatibility::record_evidence(
            &mut ctx,
            "local",
            compat_evidence(
                crate::manifest::digest(&app_raw),
                "app",
                &pin,
                BTreeMap::from([
                    ("database".into(), "1.0.0".into()),
                    ("connector".into(), "0.1.0".into()),
                ]),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        )
        .await
        .unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert_eq!(
            plan.steps
                .iter()
                .map(|step| step.product.as_str())
                .collect::<Vec<_>>(),
            vec!["app"]
        );
        let executor = std::sync::Arc::new(crate::software_executor::FakeSoftwareExecutor::new());
        let outcomes = crate::apply::execute_with_options(
            &mut ctx,
            &plan.id,
            crate::apply::ExecutionOptions {
                skip_gates: true,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "dependency document fixture",
                },
                software_executors: crate::software_executor::SoftwareExecutors::with_default(
                    executor.clone(),
                ),
                model_runtime_executor: None,
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        assert!(outcomes.iter().all(|outcome| outcome.status == "succeeded"));
        let documents = executor.applied_documents();
        assert_eq!(documents.len(), 1, "{documents:?}");
        let first = documents[0].clone();
        assert!(first.contains("\"state\":\"present\""), "{first}");
        assert!(first.contains("\"state\":\"absent\""), "{first}");
        assert!(first.contains("\"product\":\"db\""), "{first}");
        assert!(first.contains("\"contract\":\"1.3.0\""), "{first}");
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        let profile = crate::manifest::parse_raw(&app_raw)
            .unwrap()
            .compatibility
            .unwrap();
        let retry = crate::dependency_document::json_for_product(&mut ctx, &env, "app", &profile)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retry, first);
        std::fs::remove_dir_all(root).unwrap();
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

    /// #689: a release declaring a topology plans only while its replicas
    /// sit on distinct hosts; the refusal names the shared fact.
    #[tokio::test]
    async fn plan_refuses_replicas_that_share_a_host() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-topology-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let product = root.join("product");
        std::fs::create_dir_all(&product).unwrap();
        std::fs::write(
            product.join("tenkai.toml"),
            r#"[product]
name = "ledger"
version = "1.0.0"

[deploy]
workdir = "."
install = "true"

[topology]
name = "ledger-ha"
environments = ["ledger-a", "ledger-b"]
anti_affinity = "host"
"#,
        )
        .unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        // Replicas are not `local`, so the release must be signed.
        let keys = root.join("keys");
        crate::dev_sign::init_dev_keys(&keys).unwrap();
        let manifest = product.join("tenkai.toml");
        let signature = product.join("release.sig.json");
        let trust = product.join("release-trust.toml");
        crate::dev_sign::sign_release(&keys, &manifest, &signature, &trust).unwrap();
        let options = crate::catalog::PublishOptions {
            signature: Some(signature),
            trust_roots: Some(trust),
            allow_unsigned_development: false,
            provenance: Vec::new(),
            provenance_trust_roots: None,
            change_set_evidence: None,
            family_release: None,
            artifact_registry: None,
            state_dir: None,
        };
        crate::catalog::publish(&mut ctx, &manifest, &options)
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("topology-promote");
        crate::catalog::promote(&mut ctx, &actor, "ledger@1.0.0", "stable")
            .await
            .unwrap();
        for env in ["ledger-a", "ledger-b"] {
            env_add(&mut ctx, env, "replica").await.unwrap();
            subscribe(&mut ctx, env, "ledger", "stable").await.unwrap();
        }
        set_environment_fact(&mut ctx, "ledger-a", "host", "h1")
            .await
            .unwrap();
        set_environment_fact(&mut ctx, "ledger-b", "host", "h1")
            .await
            .unwrap();

        let err = crate::plan::create(&mut ctx, "ledger-a").await.unwrap_err();
        let err = format!("{err:#}");
        assert!(
            err.contains("replicas ledger-a and ledger-b both have host=h1"),
            "{err}"
        );

        set_environment_fact(&mut ctx, "ledger-b", "host", "h2")
            .await
            .unwrap();
        let plan = crate::plan::create(&mut ctx, "ledger-a").await.unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].product, "ledger");

        // The stored plan is re-checked before mutation: a replica that moved
        // onto the same host after planning blocks it.
        set_environment_fact(&mut ctx, "ledger-b", "host", "h1")
            .await
            .unwrap();
        let err =
            crate::topology::require_placement(&mut ctx, "ledger-a", &plan.steps[0].release_id)
                .await
                .unwrap_err();
        assert!(
            err.downcast_ref::<crate::topology::PlacementRefused>()
                .is_some(),
            "{err:#}"
        );
        let _ = std::fs::remove_dir_all(root);
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
            family_release: None,
            artifact_registry: None,
            state_dir: None,
        };
        crate::catalog::publish(&mut ctx, &q4_dir.join("tenkai.toml"), &options)
            .await
            .unwrap();
        crate::catalog::publish(&mut ctx, &q8_dir.join("tenkai.toml"), &options)
            .await
            .unwrap();
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut ctx,
            "qwen-coder@1.0.0",
        )
        .await
        .unwrap();
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut ctx,
            "qwen-coder@1.1.0",
        )
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

        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].product, "qwen-coder");
        assert_eq!(plan.steps[0].to, "1.0.0");
        assert_eq!(plan.steps[0].release_id, release_id("qwen-coder", "1.0.0"));

        // Infeasible: too little memory for any published variant.
        set_environment_fact(&mut ctx, "local", "memory_gib", "8")
            .await
            .unwrap();
        let err = crate::plan::create(&mut ctx, "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no model_runtime variant") || err.contains("memory_gib"),
            "{err}"
        );

        // High memory selects channel head Q8.
        set_environment_fact(&mut ctx, "local", "memory_gib", "64")
            .await
            .unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
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

    /// Every recorded step outcome leaves one feedback observation with a
    /// typed reason, committed with it, surviving a restart, unchanged by
    /// later outcomes, and holding no detail text (#802).
    #[tokio::test]
    async fn step_outcomes_capture_feedback_observations_without_detail() {
        use crate::feedback_observation::Reason;
        let root = std::env::temp_dir().join(format!("tenkai-feedback-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        for version in ["1.0.0", "1.1.0"] {
            published_software(&mut ctx, &root, version).await;
        }
        let actor = crate::auth_context::test_management_context("feedback-test");
        crate::catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        subscribe(&mut ctx, "local", "api", "stable").await.unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        let lease = crate::apply::claim_environment(&mut ctx, "local", "feedback-test")
            .await
            .unwrap();
        let cases = [
            ("succeeded", "", Reason::None),
            (
                "failed",
                "deployment executor failed: spawn refused",
                Reason::TenkaiFailed,
            ),
            (
                "failed",
                "exit 3: token=secret-value-1",
                Reason::ProductFailed,
            ),
            (
                "failed",
                "deployment command interrupted by SIGINT",
                Reason::Cancelled,
            ),
        ];
        for (status, detail, _) in cases {
            crate::environment::record_deployment_observation(
                &mut ctx,
                &lease,
                crate::environment::DeploymentObservation {
                    environment: "local",
                    plan_id: &plan.id,
                    step: &plan.steps[0],
                    status,
                    detail,
                    transition: crate::environment::DeploymentTransition::Unchanged,
                    started_at_ms: Some(crate::now_millis() - 25),
                },
            )
            .await
            .unwrap();
            // Deployment attempts are keyed by the millisecond.
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        let first = ctx
            .embedded_arc()
            .unwrap()
            .feedback_observations("local")
            .unwrap();
        drop(ctx);
        let ctx = Ctx::embedded(&database).unwrap();
        let stored = ctx
            .embedded_arc()
            .unwrap()
            .feedback_observations("local")
            .unwrap();
        assert_eq!(stored, first, "observations survive a restart unchanged");
        assert_eq!(
            stored.iter().map(|o| o.reason).collect::<Vec<_>>(),
            cases
                .iter()
                .map(|(_, _, reason)| *reason)
                .collect::<Vec<_>>()
        );
        for observation in &stored {
            assert_eq!(observation.plan_id, plan.id);
            assert_eq!(observation.lease_generation, lease.generation);
            assert!(observation.duration_ms.is_some_and(|ms| ms >= 25));
            let encoded = serde_json::to_string(observation).unwrap();
            assert!(!encoded.contains("secret-value"), "{encoded}");
            assert!(!encoded.contains("spawn refused"), "{encoded}");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn rolled_back_target_is_durably_held_but_operator_retry_and_new_head_are_planned() {
        let root =
            std::env::temp_dir().join(format!("tenkai-failed-target-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        for version in ["1.0.0", "1.1.0", "1.2.0"] {
            published_software(&mut ctx, &root, version).await;
        }
        let actor = crate::auth_context::test_management_context("hold-test");
        crate::catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        subscribe(&mut ctx, "local", "api", "stable").await.unwrap();
        let mut environment = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        environment
            .properties
            .insert("deployed.api".into(), "1.0.0".into());
        ctx.put(environment).await.unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        let lease = crate::apply::claim_environment(&mut ctx, "local", "hold-test")
            .await
            .unwrap();
        crate::environment::record_deployment_observation(
            &mut ctx,
            &lease,
            crate::environment::DeploymentObservation {
                environment: "local",
                plan_id: &plan.id,
                step: &plan.steps[0],
                status: "rolled_back",
                detail: "health failed; previous release restored",
                transition: crate::environment::DeploymentTransition::Unchanged,
                started_at_ms: None,
            },
        )
        .await
        .unwrap();
        drop(ctx);
        let mut ctx = Ctx::embedded(&database).unwrap();
        for _ in 0..2 {
            assert!(
                create_for_reconcile(&mut ctx, "local")
                    .await
                    .unwrap()
                    .steps
                    .is_empty()
            );
        }
        assert!(
            crate::environment::status(&mut ctx, "local").await.unwrap()[0]
                .error
                .as_deref()
                .unwrap()
                .contains("held")
        );
        assert_eq!(
            crate::plan::create(&mut ctx, "local").await.unwrap().steps[0].to,
            "1.1.0"
        );
        let mut environment = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        environment
            .properties
            .insert("deployment_health.api".into(), "unknown".into());
        environment.properties.insert(
            "deployment_error.api".into(),
            "restore needs manual recovery".into(),
        );
        ctx.put(environment).await.unwrap();
        assert!(
            create_for_reconcile(&mut ctx, "local")
                .await
                .unwrap_err()
                .to_string()
                .contains("unknown")
        );
        assert_eq!(
            crate::environment::status(&mut ctx, "local").await.unwrap()[0]
                .error
                .as_deref(),
            Some("restore needs manual recovery")
        );
        let mut environment = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        environment
            .properties
            .insert("deployment_health.api".into(), "healthy".into());
        environment.properties.remove("deployment_error.api");
        ctx.put(environment).await.unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@1.2.0", "stable")
            .await
            .unwrap();
        assert_eq!(
            create_for_reconcile(&mut ctx, "local").await.unwrap().steps[0].to,
            "1.2.0"
        );
        crate::environment::record_deployment_observation(
            &mut ctx,
            &lease,
            crate::environment::DeploymentObservation {
                environment: "local",
                plan_id: &plan.id,
                step: &plan.steps[0],
                status: "succeeded",
                detail: "operator retry succeeded",
                transition: crate::environment::DeploymentTransition::Deployed {
                    version: "1.1.0".into(),
                    previous: Some("1.0.0".into()),
                },
                started_at_ms: None,
            },
        )
        .await
        .unwrap();
        // The retry's observation says it retried the held target (#803);
        // the rollback that set the hold did not.
        let observations = ctx
            .embedded_arc()
            .unwrap()
            .feedback_observations("local")
            .unwrap();
        let retried = observations
            .iter()
            .map(|observation| observation.context.failed_target_retry)
            .collect::<Vec<_>>();
        assert_eq!(retried.first(), Some(&false), "{observations:?}");
        assert_eq!(retried.last(), Some(&true), "{observations:?}");
        let environment = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert!(!environment.properties.contains_key("failed_target.api"));
        assert!(
            !environment
                .properties
                .contains_key("failed_target_plan.api")
        );
        drop(ctx);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn failed_target_hold_preserves_model_and_routing_coordination() {
        let root =
            std::env::temp_dir().join(format!("tenkai-coordinated-hold-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = crate::catalog::PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        let mut model = String::new();
        for version in ["1.0.0", "2.0.0"] {
            let dir = root.join(format!("model-{version}"));
            std::fs::create_dir_all(&dir).unwrap();
            write_model_runtime_manifest(&dir, version, 16, "Q4_K_M");
            let path = dir.join("tenkai.toml");
            model = crate::manifest::load(&path).unwrap().manifest.product.name;
            crate::catalog::publish(&mut ctx, &path, &options)
                .await
                .unwrap();
        }
        let routing_dir = root.join("routing");
        std::fs::create_dir_all(&routing_dir).unwrap();
        std::fs::write(
            routing_dir.join("routing.json"),
            include_str!("../../examples/routing-local/routing.json"),
        )
        .unwrap();
        std::fs::write(
            routing_dir.join("tenkai.toml"),
            r#"[product]
name = "routes"
version = "1.0.0"
kind = "routing_config"
[routing]
config = "routing.json"
allowed_providers = ["local"]
"#,
        )
        .unwrap();
        crate::catalog::publish(&mut ctx, &routing_dir.join("tenkai.toml"), &options)
            .await
            .unwrap();
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut ctx,
            &format!("{model}@1.0.0"),
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("coordinated-hold");
        crate::catalog::promote(&mut ctx, &actor, &format!("{model}@1.0.0"), "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "routes@1.0.0", "stable")
            .await
            .unwrap();
        env_add(&mut ctx, "local", "fixture").await.unwrap();
        for product in [&model, "routes"] {
            subscribe(&mut ctx, "local", product, "stable")
                .await
                .unwrap();
        }
        for (key, value) in [
            ("architecture", "arm64"),
            ("accelerator", "apple-metal"),
            ("memory_gib", "64"),
        ] {
            set_environment_fact(&mut ctx, "local", key, value)
                .await
                .unwrap();
        }
        let mut environment = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        environment.properties.insert(
            format!("failed_target.{model}"),
            release_id(&model, "1.0.0"),
        );
        ctx.put(environment).await.unwrap();
        assert!(
            create_for_reconcile(&mut ctx, "local")
                .await
                .unwrap()
                .steps
                .is_empty()
        );

        let mut environment = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        environment
            .properties
            .remove(&format!("failed_target.{model}"));
        environment
            .properties
            .insert("failed_target.routes".into(), release_id("routes", "1.0.0"));
        environment
            .properties
            .insert(format!("deployed.{model}"), "2.0.0".into());
        ctx.put(environment).await.unwrap();
        assert!(
            create_for_reconcile(&mut ctx, "local")
                .await
                .unwrap()
                .steps
                .is_empty()
        );

        let mut environment = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        environment
            .properties
            .insert(format!("deployed.{model}"), "1.0.0".into());
        ctx.put(environment).await.unwrap();
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut ctx,
            &format!("{model}@2.0.0"),
        )
        .await
        .unwrap();
        crate::catalog::promote(&mut ctx, &actor, &format!("{model}@2.0.0"), "stable")
            .await
            .unwrap();
        let forward = create_for_reconcile(&mut ctx, "local").await.unwrap();
        assert_eq!(forward.steps.len(), 1);
        assert_eq!(forward.steps[0].product, model);
        assert_eq!(forward.steps[0].action, Action::Upgrade);
        drop(ctx);
        std::fs::remove_dir_all(root).unwrap();
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

        let idle = create_for_reconcile(&mut ctx, "local").await.unwrap();
        assert!(idle.steps.is_empty(), "{idle:?}");
        assert!(
            list_for_environment(&mut ctx, "local", None)
                .await
                .unwrap()
                .is_empty(),
            "reconcile zero-step plans must not persist"
        );

        set_environment_overlay(&mut ctx, "local", "api", "region", "eu")
            .await
            .unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].action, Action::Restart);
        assert_eq!(plan.steps[0].from.as_deref(), Some("1.0.0"));
        assert_eq!(plan.steps[0].to, "1.0.0");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn operator_zero_step_plan_remains_loadable() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-operator-empty-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        published_software(&mut ctx, &root, "1.0.0").await;
        let actor = crate::auth_context::test_management_context("operator-empty");
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

        let stored = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert!(stored.steps.is_empty(), "{stored:?}");
        let loaded = load(&mut ctx, &stored.id).await.unwrap();
        assert_eq!(loaded.id, stored.id);
        assert_eq!(loaded.state, PlanState::Computed);
        assert!(loaded.steps.is_empty());

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
