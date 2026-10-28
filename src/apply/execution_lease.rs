//! Environment execution ownership, compatibility, and generation fencing.

use std::collections::HashMap;

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

pub(crate) async fn refresh_environment_lease(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
) -> Result<()> {
    let refreshed = ctx
        .refresh_lease(
            ENVIRONMENT_LEASE_NAMESPACE,
            &lease.environment,
            &lease.fencing_token,
            lease.ttl_ms,
        )
        .await?;
    if refreshed.generation != lease.generation || refreshed.owner != lease.owner {
        bail!("Tenkai refreshed a different environment lease generation");
    }
    ctx.guarded_update(
        object_environment_claim_for_lease(lease, refreshed.expires_at_ms),
        ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

struct ApplyMutationFence<'a> {
    ctx: &'a mut Ctx,
    lease: &'a EnvironmentLease,
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
}
