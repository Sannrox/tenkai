//! Environment execution ownership, compatibility, and generation fencing.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context as _, Result, bail};

use crate::client::Ctx;
use crate::ontology::{KIND_ENVIRONMENT_EXECUTION, NS, env_id};
use crate::pb::sekai::{Lease, Link, Object};

use super::ReleaseContent;

fn record(id: String, kind: &str, name: String, properties: HashMap<String, String>) -> Object {
    let now = crate::now_millis();
    Object {
        id,
        kind: kind.into(),
        name,
        namespace: NS.into(),
        external_id: String::new(),
        properties,
        created: now,
        updated: now,
    }
}

fn legacy_environment_claim_id(environment: &str) -> String {
    format!("{}:execution", env_id(environment))
}

fn object_environment_claim_id(environment: &str) -> String {
    format!("{}:execution:v2", env_id(environment))
}

const ENVIRONMENT_LEASE_MS: i64 = 2 * 60 * 60 * 1000;
const EXECUTION_LEASE_MS: i64 = 30_000;
const MANUAL_UNLOCK_LEASE_MS: i64 = 5_000;
pub(crate) const ENVIRONMENT_LEASE_NAMESPACE: &str = "tenkai/environment-execution";
const REL_ACTIVE_ENVIRONMENT_EXECUTION: &str = "active_environment_execution";

#[derive(Clone)]
pub(crate) struct EnvironmentLease {
    pub(crate) environment: String,
    owner: String,
    pub(crate) generation: u64,
    pub(crate) fencing_token: String,
    ttl_ms: i64,
    /// The lease was taken over from an expired holder (#803).
    pub(crate) took_over: bool,
}

fn object_environment_claim(environment: &str, owner: &str, expires_at_ms: i64) -> Object {
    record(
        object_environment_claim_id(environment),
        KIND_ENVIRONMENT_EXECUTION,
        format!("apply lease for {environment}"),
        HashMap::from([
            ("environment".into(), environment.into()),
            ("owner".into(), owner.into()),
            ("expires_at".into(), expires_at_ms.to_string()),
        ]),
    )
}

fn object_environment_claim_for_lease(lease: &EnvironmentLease, expires_at_ms: i64) -> Object {
    let mut object = object_environment_claim(&lease.environment, &lease.owner, expires_at_ms);
    object
        .properties
        .insert("generation".into(), lease.generation.to_string());
    object
}

fn object_environment_claim_link(environment: &str) -> Link {
    let environment_id = env_id(environment);
    let lease_id = object_environment_claim_id(environment);
    Link {
        id: format!("{environment_id}--{REL_ACTIVE_ENVIRONMENT_EXECUTION}--{lease_id}"),
        from_id: environment_id,
        to_id: lease_id,
        relation: REL_ACTIVE_ENVIRONMENT_EXECUTION.into(),
        created: crate::now_millis(),
    }
}

async fn release_object_environment_claim(ctx: &mut Ctx, environment: &str) -> Result<()> {
    let claim_id = object_environment_claim_id(environment);
    if let Some(mut existing) = ctx.get(&claim_id).await? {
        existing
            .properties
            .insert("owner".into(), "released".into());
        existing.properties.insert("expires_at".into(), "0".into());
        existing.updated = crate::now_millis();
        ctx.put(existing).await?;
    }
    ctx.unlink(
        &env_id(environment),
        &claim_id,
        REL_ACTIVE_ENVIRONMENT_EXECUTION,
    )
    .await?;
    Ok(())
}

async fn mark_object_environment_claim_released(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
) -> Result<()> {
    let mut claim = ctx
        .get(&object_environment_claim_id(&lease.environment))
        .await?
        .context("object-backed environment apply lease disappeared")?;
    claim.properties.insert("owner".into(), "released".into());
    claim.properties.insert("expires_at".into(), "0".into());
    claim.updated = crate::now_millis();
    ctx.guarded_update(
        claim,
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

pub(crate) async fn claim_environment(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
) -> Result<EnvironmentLease> {
    claim_environment_with_options(ctx, environment, owner, ENVIRONMENT_LEASE_MS, false).await
}

/// Apply lease for a topology drill. An expired holder owned by another
/// drill is taken over so crash recovery does not wait on `env unlock`.
pub(crate) async fn claim_environment_for_drill(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
) -> Result<EnvironmentLease> {
    let now = crate::now_millis();
    let expired_drill = get_environment_lease(ctx, environment)
        .await?
        .is_some_and(|existing| {
            existing.status == "active"
                && existing.expires_at_ms <= now
                && existing.owner.starts_with("drill:")
        });
    claim_environment_with_options(ctx, environment, owner, ENVIRONMENT_LEASE_MS, expired_drill)
        .await
}

/// Owner prefix of [`claim_environment_for_completion`] leases.
const COMPLETION_OWNER: &str = "runtime-completion:";

/// How long a runtime completion may hold the environment lease.
const COMPLETION_LEASE_MS: i64 = 2 * 60 * 1000;

/// Environment lease for applying a runtime completion (#1139): short, and
/// an expired completion lease is taken over, so a server that crashed
/// mid-completion stalls delivery only for minutes and needs no unlock. Safe
/// because a completion writes only through the lease's fence and a replay
/// of an applied one changes nothing. `purpose` names the completion.
pub(crate) async fn claim_environment_for_completion(
    ctx: &mut Ctx,
    environment: &str,
    purpose: &str,
) -> Result<EnvironmentLease> {
    let now = crate::now_millis();
    let expired_completion =
        get_environment_lease(ctx, environment)
            .await?
            .is_some_and(|existing| {
                existing.status == "active"
                    && existing.expires_at_ms <= now
                    && existing.owner.starts_with(COMPLETION_OWNER)
            });
    claim_environment_with_options(
        ctx,
        environment,
        &format!("{COMPLETION_OWNER}{purpose}"),
        COMPLETION_LEASE_MS,
        expired_completion,
    )
    .await
}

/// Release a leftover drill apply lease from its durable fencing token.
pub(crate) async fn release_environment_fence(
    ctx: &mut Ctx,
    environment: &str,
    fencing_token: &str,
) -> Result<()> {
    release_environment(
        ctx,
        &EnvironmentLease {
            environment: environment.into(),
            owner: "released".into(),
            generation: 0,
            fencing_token: fencing_token.into(),
            ttl_ms: 0,
            took_over: false,
        },
    )
    .await
}

pub(super) async fn claim_execution_environment(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
) -> Result<EnvironmentLease> {
    let lease =
        claim_environment_with_options(ctx, environment, owner, EXECUTION_LEASE_MS, true).await?;
    // An environment with an enrolled runtime is run by that runtime only
    // (#630). Checked while this lease is held, and a runtime claims no work
    // while it is, so the two never execute one environment together.
    let delegated = crate::runtime_credentials::runtime_managed(ctx, environment).await;
    if !matches!(delegated, Ok(false)) {
        release_environment(ctx, &lease).await?;
        delegated?;
        bail!("environment {environment} is runtime-managed; its enrolled runtime runs its plans");
    }
    crate::telemetry::record_metric(
        crate::telemetry::METRIC_LEASE_ACQUIRED,
        1.0,
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Apply)
            .environment(environment)
            .fencing_generation(lease.generation),
    );
    Ok(lease)
}

async fn claim_environment_with_options(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
    ttl_ms: i64,
    automatic_takeover: bool,
) -> Result<EnvironmentLease> {
    // Every new environment lease, whether from reconcile, an API apply or
    // a configuration change, needs a trusted clock.
    crate::clock_guard::require_trusted_time("environment lease grant")?;
    let now = crate::now_millis();
    if crate::environment::environment_retirement(ctx, environment)
        .await?
        .is_some()
    {
        anyhow::bail!("retired environment {environment} cannot accept new apply leases");
    }
    reject_foreign_migration_lock(ctx, environment, owner).await?;
    if let Some(existing) = ctx.get(&legacy_environment_claim_id(environment)).await? {
        let expires_at = existing
            .properties
            .get("expires_at")
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(i64::MAX);
        if expires_at <= now {
            bail!(
                "environment {environment} has an expired legacy apply lease; verify no apply is running, then run `tenkaictl env unlock {environment}`"
            );
        }
        bail!("environment {environment} already has a legacy apply in progress");
    }
    let object_claim_id = object_environment_claim_id(environment);
    let has_object_claim = ctx
        .links(&env_id(environment), REL_ACTIVE_ENVIRONMENT_EXECUTION)
        .await?
        .into_iter()
        .any(|link| link.to_id == object_claim_id);
    if has_object_claim {
        match get_environment_lease(ctx, environment).await? {
            Some(existing) if existing.status == "active" => {
                if existing.expires_at_ms > now {
                    bail!(
                        "environment {environment} already has an apply in progress owned by {}",
                        existing.owner
                    );
                }
            }
            _ => {
                let claim = ctx
                    .get(&object_claim_id)
                    .await?
                    .context("object-backed environment apply lease disappeared")?;
                if claim.properties.get("owner").map(String::as_str) != Some("released") {
                    bail!(
                        "environment {environment} has an object-backed apply lease without an active Tenkai lease; finish any older controller, then run `tenkaictl env unlock {environment}`"
                    );
                }
            }
        }
    }
    // An expired active holder replaced by this claim is a takeover (#803),
    // whether the backend replaces it inside AcquireLease (embedded) or
    // through the explicit takeover below.
    let expired_holder = get_environment_lease(ctx, environment)
        .await?
        .is_some_and(|existing| existing.status == "active" && existing.expires_at_ms <= now);
    // Maintenance/canary claims must not silently reclaim an expired active
    // lease via AcquireLease. Embedded (and the mock) treat expired holders as
    // free for acquire, which would otherwise skip the unlock gate and the
    // AlreadyExists → takeover path below.
    if !automatic_takeover
        && let Some(existing) = get_environment_lease(ctx, environment).await?
        && existing.status == "active"
        && existing.expires_at_ms <= now
    {
        bail!(
            "environment {environment} has an expired apply lease; verify no operation is running, then run `tenkaictl env unlock {environment}`"
        );
    }
    let mut took_over = expired_holder;
    let lease = match ctx
        .acquire_lease(ENVIRONMENT_LEASE_NAMESPACE, environment, owner, ttl_ms)
        .await
    {
        Ok(lease) => lease,
        Err(crate::client::LeaseError::AlreadyExists) => {
            if let Some(existing) = get_environment_lease(ctx, environment).await? {
                if existing.status == "active" && existing.expires_at_ms <= now {
                    if !automatic_takeover {
                        bail!(
                            "environment {environment} has an expired apply lease; verify no operation is running, then run `tenkaictl env unlock {environment}`"
                        );
                    }
                    took_over = true;
                    ctx.takeover_expired_lease(
                        ENVIRONMENT_LEASE_NAMESPACE,
                        environment,
                        owner,
                        &existing.fencing_token,
                        existing.expires_at_ms,
                        ttl_ms,
                    )
                    .await?
                } else {
                    bail!(
                        "environment {environment} already has an apply in progress owned by {}",
                        existing.owner
                    );
                }
            } else {
                return Err(crate::client::LeaseError::AlreadyExists.into());
            }
        }
        Err(error) => return Err(error.into()),
    };
    let environment_lease = EnvironmentLease {
        environment: environment.into(),
        owner: owner.into(),
        generation: lease.generation,
        fencing_token: lease.fencing_token,
        ttl_ms,
        took_over,
    };
    let available = object_environment_claim(environment, "released", 0);
    match ctx.create_once(available).await {
        Ok(_) => {}
        Err(status)
            if crate::client::is_unique_conflict(&status) || status.is_retired_identity() => {}
        Err(status) => {
            let _ = release_environment_lease(ctx, &environment_lease).await;
            return Err(status.into());
        }
    }
    if !has_object_claim
        && let Err(status) = ctx
            .create_link_once(object_environment_claim_link(environment))
            .await
    {
        let _ = release_environment_lease(ctx, &environment_lease).await;
        if crate::client::is_unique_conflict(&status) {
            bail!("environment {environment} already has an apply in progress");
        }
        return Err(status.into());
    }
    if let Err(error) = ctx
        .guarded_update(
            object_environment_claim_for_lease(&environment_lease, lease.expires_at_ms),
            ENVIRONMENT_LEASE_NAMESPACE,
            &environment_lease.environment,
            &environment_lease.fencing_token,
        )
        .await
    {
        let _ = release_environment_lease(ctx, &environment_lease).await;
        return Err(error);
    }
    if let Err(error) = reject_foreign_migration_lock(ctx, environment, owner).await {
        let _ = release_environment_lease(ctx, &environment_lease).await;
        return Err(error);
    }
    Ok(environment_lease)
}

async fn reject_foreign_migration_lock(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
) -> Result<()> {
    let Some(lock) = ctx
        .get(&crate::ontology::package_migration_lock_id(environment))
        .await?
    else {
        return Ok(());
    };
    let lock_owner = lock
        .properties
        .get("owner")
        .map(String::as_str)
        .unwrap_or_default();
    let allowed_plan = lock
        .properties
        .get("allowed_plan_id")
        .map(String::as_str)
        .unwrap_or_default();
    let migration_owner = format!("package-migration:{lock_owner}");
    if owner != allowed_plan && owner != migration_owner {
        bail!("environment {environment} has package migration {lock_owner} in progress");
    }
    Ok(())
}

/// Named wave or topology lease the current plan execution lost (#834).
#[derive(Debug)]
pub(crate) struct ExecutionFenceLost {
    namespace: String,
    key: String,
    detail: String,
}

impl std::fmt::Display for ExecutionFenceLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "lost {} lease {}: {}",
            self.namespace, self.key, self.detail
        )
    }
}

impl std::error::Error for ExecutionFenceLost {}

pub(crate) fn is_execution_fence_lost(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<ExecutionFenceLost>())
}

pub(crate) async fn refresh_environment_lease(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
) -> Result<()> {
    Box::pin(refresh_environment_lease_inner(ctx, lease)).await
}

async fn refresh_environment_lease_inner(ctx: &mut Ctx, lease: &EnvironmentLease) -> Result<()> {
    let now = crate::now_millis();
    let mut refreshes = Vec::new();
    let mut held_slots = Vec::new();
    for (idx, held) in ctx.held_execution_leases.iter().enumerate() {
        refreshes.push(crate::storage::LeaseRefresh {
            namespace: held.namespace.clone(),
            key: held.key.clone(),
            fencing_token: held.fencing_token.clone(),
            ttl_ms: held.ttl_ms,
            extend: held.due_for_refresh(now),
        });
        held_slots.push(idx);
    }
    refreshes.push(crate::storage::LeaseRefresh {
        namespace: ENVIRONMENT_LEASE_NAMESPACE.into(),
        key: lease.environment.clone(),
        fencing_token: lease.fencing_token.clone(),
        ttl_ms: lease.ttl_ms,
        extend: true,
    });
    let claim = object_environment_claim_for_lease(lease, now.saturating_add(lease.ttl_ms));
    let (refreshed, _) = ctx
        .refresh_leases_and_guarded_put(
            refreshes,
            claim,
            ENVIRONMENT_LEASE_NAMESPACE,
            &lease.environment,
            &lease.fencing_token,
        )
        .await
        .map_err(|error| map_held_lease_error(ctx, error))?;
    let Some(env) = refreshed.last() else {
        bail!("Tenkai refreshed no environment lease");
    };
    if env.generation != lease.generation || env.owner != lease.owner {
        bail!("Tenkai refreshed a different environment lease generation");
    }
    for (slot, updated) in held_slots.iter().zip(refreshed.iter()) {
        ctx.held_execution_leases[*slot].expires_at_ms = updated.expires_at_ms;
    }
    Ok(())
}

fn map_held_lease_error(ctx: &Ctx, error: anyhow::Error) -> anyhow::Error {
    let Some(first) = ctx.held_execution_leases.first() else {
        return error;
    };
    let detail = error.to_string();
    let held = ctx
        .held_execution_leases
        .iter()
        .find(|held| {
            detail.contains(&format!("{}/{}", held.namespace, held.key))
                || detail.contains(&held.key)
        })
        .unwrap_or(first);
    ExecutionFenceLost {
        namespace: held.namespace.clone(),
        key: held.key.clone(),
        detail,
    }
    .into()
}

/// The environment lease as the fence of a mutation: refreshing renews it.
pub(super) struct ApplyMutationFence<'a> {
    pub(super) ctx: &'a mut Ctx,
    pub(super) lease: &'a EnvironmentLease,
}

impl crate::fenced_mutation::MutationFence for ApplyMutationFence<'_> {
    fn generation(&self) -> u64 {
        self.lease.generation
    }

    fn refresh(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(refresh_environment_lease(self.ctx, self.lease))
    }
}

/// Run an in-process mutation under the executor guard: refresh the
/// environment fence, hold the mutation lock for the whole call, and keep
/// refreshing the fence while the blocking work runs, like
/// [`run_mutation_command`] does for shell commands. Fence and lock failures
/// are outer errors. In-process work cannot be killed when the fence is lost;
/// it keeps the mutation lock until it returns, so no second guarded mutation
/// can start, and the lost fence is reported as soon as it is observed.
pub(super) async fn run_guarded_mutation<T>(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<Result<T, String>>
where
    T: Send + 'static,
{
    refresh_environment_lease(ctx, lease).await?;
    let lock_path = content.mutation_lock.clone();
    let (acquired_tx, mut acquired_rx) = tokio::sync::oneshot::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let mut guarded = tokio::task::spawn_blocking(move || {
        crate::fenced_mutation::with_mutation_lock_authorized(
            &lock_path,
            move || {
                // Ready/go handshake, as in the shell guard: announce the
                // held lock, then start only on explicit authorization.
                let _ = acquired_tx.send(());
                go_rx
                    .recv()
                    .map_err(|_| anyhow::anyhow!("model-runtime mutation was not authorized"))
            },
            work,
        )
    });
    let mut refresh = tokio::time::interval(std::time::Duration::from_secs(10));
    refresh.tick().await;
    // Wait for the lock while keeping the fence fresh. Losing the fence here
    // drops the go channel, so the queued task releases the lock unused.
    loop {
        tokio::select! {
            acquired = &mut acquired_rx => {
                acquired.context("guarded model-runtime mutation ended before acquiring the lock")?;
                break;
            }
            joined = &mut guarded => {
                let finished = joined.context("guarded model-runtime mutation task failed")??;
                refresh_environment_lease(ctx, lease).await?;
                return Ok(finished.map_err(|error| error.to_string()));
            }
            _ = refresh.tick() => refresh_environment_lease(ctx, lease).await?,
        }
    }
    // The lock is held; revalidate the fence before authorizing any mutation.
    refresh_environment_lease(ctx, lease).await?;
    let _ = go_tx.send(());
    let mut refresh = tokio::time::interval(std::time::Duration::from_secs(10));
    refresh.tick().await;
    let guarded = loop {
        tokio::select! {
            joined = &mut guarded => break joined.context("guarded model-runtime mutation task failed")??,
            _ = refresh.tick() => refresh_environment_lease(ctx, lease).await?,
        }
    };
    refresh_environment_lease(ctx, lease).await?;
    Ok(guarded.map_err(|error| error.to_string()))
}

/// Renew at a quarter of the shortest TTL this apply holds, at most every
/// 10 s. A renewal that takes longer than one interval counts as failed, so
/// the work is told to stop with at least half a TTL of the lease left.
fn renewal_interval(ctx: &Ctx, lease: &EnvironmentLease) -> std::time::Duration {
    let shortest = ctx
        .held_execution_leases
        .iter()
        .map(|held| held.ttl_ms)
        .fold(lease.ttl_ms, i64::min);
    let quarter = u64::try_from(shortest / 4).unwrap_or(0).max(10);
    std::time::Duration::from_millis(quarter.min(10_000))
}

/// One renewal, failing as a lost fence when it errs or does not finish
/// within `within`.
async fn renew_within(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    within: std::time::Duration,
) -> Result<()> {
    // Once the work is told to stop, every failed renewal is a lost fence,
    // so the step takes the fence-loss exit instead of recovery.
    let detail = match tokio::time::timeout(within, refresh_environment_lease(ctx, lease)).await {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(error)) if is_execution_fence_lost(&error) => return Err(error),
        Ok(Err(error)) => format!("renewal failed: {error:#}"),
        Err(_) => format!("renewal did not finish within {} ms", within.as_millis()),
    };
    Err(ExecutionFenceLost {
        namespace: ENVIRONMENT_LEASE_NAMESPACE.into(),
        key: lease.environment.clone(),
        detail,
    }
    .into())
}

/// Sets the stop flag when dropped.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Run a blocking software-executor call while renewing the environment lease
/// (#982). A rollout may wait longer than the lease TTL; renewal keeps the
/// lease for as long as the call runs. When a renewal fails or stalls, `work`
/// sees its stop flag set and should return soon after. This waits for
/// `work` to return either way, so no executor call outlives this function.
/// If this future is dropped instead, the stop flag is set as well.
///
/// The inner result is the work's own. A lost fence is the outer error; when
/// the work failed too, the outer error names the work's failure first.
pub(super) async fn run_with_lease_renewal<T>(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    work: impl FnOnce(&AtomicBool) -> Result<T> + Send + 'static,
) -> Result<Result<T>>
where
    T: Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    // Dropping this future (a cancelled apply) also stops the work: renewal
    // ends with the future, so the work must not keep running unfenced.
    let _stop_on_drop = StopOnDrop(stop.clone());
    let mut running = tokio::task::spawn_blocking({
        let stop = stop.clone();
        move || work(&stop)
    });
    let interval = renewal_interval(ctx, lease);
    let mut renew = tokio::time::interval(interval);
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    renew.tick().await;
    let mut lost = None;
    let finished = loop {
        tokio::select! {
            joined = &mut running => break joined,
            _ = renew.tick(), if lost.is_none() => {
                if let Err(error) = renew_within(ctx, lease, interval).await {
                    stop.store(true, Ordering::SeqCst);
                    lost = Some(error);
                }
            }
        }
    };
    let finished = finished.context("software executor task failed")?;
    let fenced = match lost {
        Some(error) => Err(error),
        None => renew_within(ctx, lease, interval).await,
    };
    match (fenced, finished) {
        (Ok(()), finished) => Ok(finished),
        (Err(fence), Ok(_)) => Err(fence),
        (Err(fence), Err(failure)) => {
            let failure =
                crate::software_executor::sanitize_diagnostic_text(&format!("{failure:#}"));
            let message = format!("{failure}; the apply lease was also lost: {fence}");
            Err(fence.context(message))
        }
    }
}

pub(super) async fn run_mutation_command(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    cmd: &str,
) -> Result<Result<(), String>> {
    let mut fence = ApplyMutationFence { ctx, lease };
    crate::fenced_mutation::run(
        &mut fence,
        crate::fenced_mutation::MutationCommand {
            lock_path: &content.mutation_lock,
            workdir: &content.workdir,
            environment: &content.environment,
            product: &content.product,
            instance: &content.instance,
            command: cmd,
        },
    )
    .await
}

async fn release_environment_lease(ctx: &mut Ctx, lease: &EnvironmentLease) -> Result<()> {
    ctx.release_lease(
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

pub(crate) async fn release_environment(ctx: &mut Ctx, lease: &EnvironmentLease) -> Result<()> {
    mark_object_environment_claim_released(ctx, lease).await?;
    release_environment_lease(ctx, lease).await?;
    crate::telemetry::record_metric(
        crate::telemetry::METRIC_LEASE_RELEASED,
        1.0,
        &crate::telemetry::DeliveryAttributes::new(crate::telemetry::Operation::Apply)
            .environment(&lease.environment)
            .fencing_generation(lease.generation),
    );
    Ok(())
}

pub(crate) struct EnvironmentLeaseStatus {
    pub owner: String,
}

/// Operator-facing lease/fence summary. Never includes credentials.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct EnvironmentLeaseInspect {
    /// Whether an active apply/execution lease is held.
    pub held: bool,
    /// Lease owner identity (controller id), never a bearer token.
    pub owner: Option<String>,
    pub generation: Option<u64>,
    pub expires_at_ms: Option<i64>,
    pub status: String,
}

async fn get_environment_lease(ctx: &mut Ctx, environment: &str) -> Result<Option<Lease>> {
    ctx.get_lease(ENVIRONMENT_LEASE_NAMESPACE, environment)
        .await
}

/// Inspect generation-fenced execution lease state for an environment.
pub async fn inspect_environment_lease(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<EnvironmentLeaseInspect> {
    crate::ontology::validate_identifier("environment", environment)?;
    if let Some(active) = get_environment_lease(ctx, environment).await? {
        if active.status == "active" {
            return Ok(EnvironmentLeaseInspect {
                held: true,
                owner: Some(active.owner),
                generation: Some(active.generation),
                expires_at_ms: Some(active.expires_at_ms),
                status: active.status,
            });
        }
        return Ok(EnvironmentLeaseInspect {
            held: false,
            owner: Some(active.owner),
            generation: Some(active.generation),
            expires_at_ms: Some(active.expires_at_ms),
            status: active.status,
        });
    }
    // Compatibility path: object/legacy claim without Tenkai generation lease.
    if let Some(status) = environment_lease_status(ctx, environment).await? {
        return Ok(EnvironmentLeaseInspect {
            held: true,
            owner: Some(status.owner),
            generation: None,
            expires_at_ms: None,
            status: "active".into(),
        });
    }
    Ok(EnvironmentLeaseInspect {
        held: false,
        owner: None,
        generation: None,
        expires_at_ms: None,
        status: "absent".into(),
    })
}

pub(crate) async fn environment_lease_status(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<Option<EnvironmentLeaseStatus>> {
    if let Some(lease) = ctx.get(&legacy_environment_claim_id(environment)).await? {
        let owner = lease
            .properties
            .get("owner")
            .cloned()
            .context("legacy environment apply lease has no owner")?;
        return Ok(Some(EnvironmentLeaseStatus { owner }));
    }
    let object_claim_id = object_environment_claim_id(environment);
    if ctx
        .links(&env_id(environment), REL_ACTIVE_ENVIRONMENT_EXECUTION)
        .await?
        .into_iter()
        .any(|link| link.to_id == object_claim_id)
    {
        let lease = ctx
            .get(&object_claim_id)
            .await?
            .context("object-backed environment apply lease disappeared")?;
        let owner = lease
            .properties
            .get("owner")
            .cloned()
            .context("object-backed environment apply lease has no owner")?;
        if owner != "released" {
            return Ok(Some(EnvironmentLeaseStatus { owner }));
        }
        // New controllers retain the compatibility link so an older binary
        // fails closed. The authoritative Tenkai lease determines whether the
        // released marker is merely idle or a new generation is being adopted.
        if let Some(active) = get_environment_lease(ctx, environment).await?
            && active.status == "active"
        {
            return Ok(Some(EnvironmentLeaseStatus {
                owner: active.owner,
            }));
        }
        return Ok(None);
    }
    let Some(lease) = get_environment_lease(ctx, environment).await? else {
        return Ok(None);
    };
    if lease.status != "active" {
        return Ok(None);
    }
    Ok(Some(EnvironmentLeaseStatus { owner: lease.owner }))
}

/// Whether a runtime may take work in `environment` after it enrolled
/// (#630): no server execution may still be running there. A server lease
/// past its expiry is taken over atomically, as server execution takes one
/// over, and released: its holder can no longer renew it, and its writes fail
/// their generation fence. A live lease, or a claim only an operator may
/// clear, keeps the runtime waiting. Polls write nothing unless a lease is
/// taken over.
pub(crate) async fn runtime_may_take_over(ctx: &mut Ctx, environment: &str) -> Result<bool> {
    if environment_lease_status(ctx, environment).await?.is_none() {
        return Ok(true);
    }
    if ctx
        .get(&legacy_environment_claim_id(environment))
        .await?
        .is_some()
    {
        return Ok(false);
    }
    match get_environment_lease(ctx, environment).await? {
        Some(lease) if lease.status == "active" && lease.expires_at_ms > crate::now_millis() => {
            return Ok(false);
        }
        Some(lease) if lease.status == "active" => {}
        _ => return Ok(false),
    }
    // Renewed meanwhile, the lease refuses this takeover, and the runtime retries.
    let lease = claim_environment_with_options(
        ctx,
        environment,
        "runtime-handoff",
        ENVIRONMENT_LEASE_MS,
        true,
    )
    .await?;
    release_environment(ctx, &lease).await?;
    Ok(true)
}

pub async fn unlock_environment(ctx: &mut Ctx, environment: &str) -> Result<String> {
    crate::ontology::validate_identifier("environment", environment)?;
    let legacy_id = legacy_environment_claim_id(environment);
    if ctx.get(&legacy_id).await?.is_some() {
        ctx.delete(&legacy_id).await?;
        return Ok(format!(
            "removed legacy apply lease for environment {environment}"
        ));
    }
    let object_claim_id = object_environment_claim_id(environment);
    let has_object_claim = ctx.get(&object_claim_id).await?.is_some()
        && ctx
            .links(&env_id(environment), REL_ACTIVE_ENVIRONMENT_EXECUTION)
            .await?
            .into_iter()
            .any(|link| link.to_id == object_claim_id);
    if has_object_claim
        && get_environment_lease(ctx, environment)
            .await?
            .is_none_or(|lease| lease.status != "active")
    {
        release_object_environment_claim(ctx, environment).await?;
        return Ok(format!(
            "removed object-backed apply lease for environment {environment}"
        ));
    }
    let Some(existing) = get_environment_lease(ctx, environment).await? else {
        return Ok(format!("environment {environment} has no apply lease"));
    };
    if existing.status != "active" {
        return Ok(format!("environment {environment} has no apply lease"));
    }
    if existing.expires_at_ms > crate::now_millis() {
        bail!(
            "environment {environment} has an unexpired apply lease owned by {}; stop that controller and retry after lease expiry at {}",
            existing.owner,
            existing.expires_at_ms
        );
    }
    let takeover = ctx
        .takeover_expired_lease(
            ENVIRONMENT_LEASE_NAMESPACE,
            environment,
            &format!("manual-unlock:{}", uuid::Uuid::new_v4()),
            &existing.fencing_token,
            existing.expires_at_ms,
            MANUAL_UNLOCK_LEASE_MS,
        )
        .await?;
    ctx.release_lease(
        ENVIRONMENT_LEASE_NAMESPACE,
        environment,
        &takeover.fencing_token,
    )
    .await?;
    if has_object_claim {
        release_object_environment_claim(ctx, environment).await?;
    }
    Ok(format!("removed apply lease for environment {environment}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;

    fn context(name: &str) -> Ctx {
        let database = std::env::temp_dir().join(format!(
            "tenkai-execution-lease-{name}-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        Ctx::embedded(database).unwrap()
    }

    #[tokio::test]
    async fn claim_environment_requires_unlock_for_expired_lease() {
        let mut ctx = context("expired-unlock");
        ctx.acquire_lease(ENVIRONMENT_LEASE_NAMESPACE, "prod", "owner-a", 1)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let err = match claim_environment(&mut ctx, "prod", "owner-b").await {
            Ok(_) => panic!("expired lease must require unlock"),
            Err(error) => error.to_string(),
        };
        assert!(
            err.contains("expired apply lease") && err.contains("env unlock"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn only_a_lapsed_completion_lease_is_taken_over_by_a_completion() {
        let mut ctx = context("completion-takeover");
        // A server crashed while applying a completion.
        ctx.acquire_lease(
            ENVIRONMENT_LEASE_NAMESPACE,
            "prod",
            "runtime-completion:plan-1",
            1,
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let lease = claim_environment_for_completion(&mut ctx, "prod", "plan-1")
            .await
            .unwrap();
        assert!(lease.took_over);
        release_environment(&mut ctx, &lease).await.unwrap();

        // Any other lapsed holder still needs an operator's unlock.
        ctx.acquire_lease(ENVIRONMENT_LEASE_NAMESPACE, "prod", "plan-2", 1)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let refused = match claim_environment_for_completion(&mut ctx, "prod", "plan-1").await {
            Ok(_) => panic!("a lapsed apply lease must require unlock"),
            Err(error) => error.to_string(),
        };
        assert!(refused.contains("env unlock"), "{refused}");
    }

    #[tokio::test]
    async fn claim_execution_environment_takeovers_expired_lease() {
        let mut ctx = context("expired-takeover");
        ctx.acquire_lease(ENVIRONMENT_LEASE_NAMESPACE, "prod", "owner-a", 1)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let lease = claim_execution_environment(&mut ctx, "prod", "owner-b")
            .await
            .unwrap();
        assert!(lease.generation >= 2);
        // Observations under this lease attribute it to a takeover (#803).
        assert!(lease.took_over);
        release_environment(&mut ctx, &lease).await.unwrap();
        let fresh = claim_execution_environment(&mut ctx, "prod", "owner-c")
            .await
            .unwrap();
        assert!(!fresh.took_over);
        release_environment(&mut ctx, &fresh).await.unwrap();
    }

    #[tokio::test]
    async fn the_server_does_not_execute_an_environment_with_an_enrolled_runtime() {
        let mut ctx = context("enrolled-runtime");
        crate::runtime_credentials::mark_runtime_managed(&mut ctx, "prod")
            .await
            .unwrap();
        let refused = match claim_execution_environment(&mut ctx, "prod", "plan-1").await {
            Ok(_) => panic!("an enrolled environment must not execute on the server"),
            Err(error) => error.to_string(),
        };
        assert!(refused.contains("runtime-managed"), "{refused}");
        // The lease it took to check is released again.
        assert!(
            environment_lease_status(&mut ctx, "prod")
                .await
                .unwrap()
                .is_none()
        );
        // Other environment work, such as a configuration change, still runs.
        let lease = claim_environment(&mut ctx, "prod", "config").await.unwrap();
        release_environment(&mut ctx, &lease).await.unwrap();
    }

    #[tokio::test]
    async fn a_held_execution_lease_is_refreshed_with_the_environment_fence() {
        let mut ctx = context("held-refresh");
        let held = ctx
            .acquire_lease("tenkai/topology-availability", "ledger-ha", "wave", 60_000)
            .await
            .unwrap();
        ctx.held_execution_leases = vec![crate::client::HeldExecutionLease::new(
            "tenkai/topology-availability",
            "ledger-ha",
            held.fencing_token.clone(),
            120_000,
        )];
        let before = ctx
            .get_lease("tenkai/topology-availability", "ledger-ha")
            .await
            .unwrap()
            .unwrap();
        let lease = claim_environment(&mut ctx, "prod", "plan-1").await.unwrap();
        refresh_environment_lease(&mut ctx, &lease).await.unwrap();
        let after = ctx
            .get_lease("tenkai/topology-availability", "ledger-ha")
            .await
            .unwrap()
            .unwrap();
        assert!(
            after.expires_at_ms > before.expires_at_ms,
            "before={} after={}",
            before.expires_at_ms,
            after.expires_at_ms
        );
        let err = ctx
            .acquire_lease("tenkai/topology-availability", "ledger-ha", "other", 1_000)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("already exists") || err.contains("held"),
            "{err}"
        );
        release_environment(&mut ctx, &lease).await.unwrap();
    }

    #[tokio::test]
    async fn a_lost_held_execution_lease_fails_closed_naming_it() {
        let mut ctx = context("held-lost");
        let held = ctx
            .acquire_lease("tenkai/topology-availability", "ledger-ha", "wave", 60_000)
            .await
            .unwrap();
        ctx.release_lease(
            "tenkai/topology-availability",
            "ledger-ha",
            &held.fencing_token,
        )
        .await
        .unwrap();
        ctx.held_execution_leases = vec![crate::client::HeldExecutionLease::new(
            "tenkai/topology-availability",
            "ledger-ha",
            held.fencing_token,
            60_000,
        )];
        let lease = claim_environment(&mut ctx, "prod", "plan-1").await.unwrap();
        let err = refresh_environment_lease(&mut ctx, &lease)
            .await
            .unwrap_err();
        assert!(is_execution_fence_lost(&err), "{err:#}");
        assert!(err.to_string().contains("ledger-ha"), "{err:#}");
        release_environment(&mut ctx, &lease).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_wait_longer_than_the_lease_ttl_keeps_the_lease() {
        let mut ctx = context("renew-slow");
        // 4s TTL → 1s renew_within. A 1s TTL / 250ms bound flakes when a
        // SQLite refresh is delayed under the default cargo test load.
        let lease = claim_environment_with_options(&mut ctx, "prod", "plan-1", 4_000, false)
            .await
            .unwrap();
        let waited = run_with_lease_renewal(&mut ctx, &lease, |stop| {
            std::thread::sleep(std::time::Duration::from_millis(10_000));
            Ok(stop.load(Ordering::SeqCst))
        })
        .await
        .unwrap()
        .unwrap();
        assert!(!waited, "a renewed lease must not stop the work");
        // Releasing proves this apply is still the fenced holder.
        release_environment(&mut ctx, &lease).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lost_lease_stops_the_work_before_reporting_it() {
        let mut ctx = context("renew-lost");
        ctx.held_execution_leases = vec![crate::client::HeldExecutionLease::new(
            "tenkai/topology-availability",
            "ledger-ha",
            "stale",
            60_000,
        )];
        let lease = claim_environment_with_options(&mut ctx, "prod", "plan-1", 300, false)
            .await
            .unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let err = run_with_lease_renewal(&mut ctx, &lease, {
            let stopped = stopped.clone();
            move |stop| -> Result<()> {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while std::time::Instant::now() < deadline {
                    if stop.load(Ordering::SeqCst) {
                        stopped.store(true, Ordering::SeqCst);
                        bail!("Deployment web cannot become Available: CrashLoopBackOff");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Ok(())
            }
        })
        .await
        .unwrap_err();
        assert!(is_execution_fence_lost(&err), "{err:#}");
        assert!(
            stopped.load(Ordering::SeqCst),
            "the work must see the stop before the lost fence is reported"
        );
        // The step's own failure leads; the lost lease follows it.
        assert!(
            err.to_string()
                .starts_with("Deployment web cannot become Available: CrashLoopBackOff; the apply lease was also lost: lost tenkai/topology-availability lease ledger-ha"),
            "{err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_cancelled_apply_stops_the_work() {
        let mut ctx = context("renew-cancel");
        let lease = claim_environment(&mut ctx, "prod", "plan-1").await.unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (stopped_tx, stopped_rx) = std::sync::mpsc::channel();
        let apply = tokio::spawn(async move {
            run_with_lease_renewal(&mut ctx, &lease, move |stop| {
                started_tx.send(()).unwrap();
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                stopped_tx.send(()).unwrap();
                Ok(())
            })
            .await
        });
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();
        apply.abort();
        tokio::task::spawn_blocking(move || {
            stopped_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("dropping the apply must stop the work")
        })
        .await
        .unwrap();
    }

    #[test]
    fn a_held_lease_is_due_when_less_than_a_third_of_ttl_remains() {
        let held = crate::client::HeldExecutionLease::new(
            "tenkai/wave-execution",
            "roll",
            "token",
            120_000,
        );
        assert!(held.due_for_refresh(1_000), "unknown expiry must refresh");
        let held = held.until(1_000 + 80_000);
        assert!(
            !held.due_for_refresh(1_000),
            "two-thirds of TTL remaining must skip"
        );
        let held = held.until(1_000 + 30_000);
        assert!(held.due_for_refresh(1_000), "ttl/4 remaining must refresh");
    }

    #[tokio::test]
    async fn a_held_execution_lease_with_ttl_remaining_is_not_refreshed() {
        let mut ctx = context("held-skip");
        let held = ctx
            .acquire_lease("tenkai/topology-availability", "ledger-ha", "wave", 120_000)
            .await
            .unwrap();
        ctx.held_execution_leases = vec![
            crate::client::HeldExecutionLease::new(
                "tenkai/topology-availability",
                "ledger-ha",
                held.fencing_token.clone(),
                120_000,
            )
            .until(held.expires_at_ms),
        ];
        let before = ctx
            .get_lease("tenkai/topology-availability", "ledger-ha")
            .await
            .unwrap()
            .unwrap();
        let lease = claim_environment(&mut ctx, "prod", "plan-1").await.unwrap();
        refresh_environment_lease(&mut ctx, &lease).await.unwrap();
        let after = ctx
            .get_lease("tenkai/topology-availability", "ledger-ha")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.expires_at_ms, before.expires_at_ms,
            "a 2h-class lease must not refresh on the 10s fence"
        );
        release_environment(&mut ctx, &lease).await.unwrap();
    }

    #[tokio::test]
    async fn environment_execution_heartbeat_does_not_record_catalog_changes() {
        let mut ctx = context("heartbeat-history");
        let lease = claim_environment(&mut ctx, "prod", "plan-1").await.unwrap();
        let claim_id = object_environment_claim_id("prod");
        let before = ctx
            .embedded_arc()
            .expect("embedded store")
            .changes(&claim_id)
            .unwrap()
            .len();
        refresh_environment_lease(&mut ctx, &lease).await.unwrap();
        refresh_environment_lease(&mut ctx, &lease).await.unwrap();
        let after = ctx
            .embedded_arc()
            .expect("embedded store")
            .changes(&claim_id)
            .unwrap()
            .len();
        assert_eq!(
            after, before,
            "expires_at-only heartbeats must not grow catalog_changes"
        );
        release_environment(&mut ctx, &lease).await.unwrap();
    }

    #[test]
    fn a_batch_refresh_failure_while_holding_leases_is_fence_loss() {
        let mut ctx = context("map-held-err");
        ctx.held_execution_leases = vec![crate::client::HeldExecutionLease::new(
            "tenkai/wave-execution",
            "roll",
            "token",
            60_000,
        )];
        let err = map_held_lease_error(&ctx, anyhow::anyhow!("catalog writer unavailable"));
        assert!(is_execution_fence_lost(&err), "{err:#}");
        assert!(err.to_string().contains("roll"), "{err:#}");
    }

    #[test]
    fn fence_loss_is_visible_through_anyhow_context() {
        let err = anyhow::Error::from(ExecutionFenceLost {
            namespace: "tenkai/wave-execution".into(),
            key: "ledger-roll".into(),
            detail: "lease not held".into(),
        })
        .context("refreshing environment apply lease during SLO sampling");
        assert!(is_execution_fence_lost(&err), "{err:#}");
        assert!(format!("{err:#}").contains("ledger-roll"), "{err:#}");
    }
}
