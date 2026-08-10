//! Environment execution ownership, compatibility, and generation fencing.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};

use crate::client::Ctx;
use crate::ontology::{KIND_ENVIRONMENT_EXECUTION, env_id};
use crate::pb::sekai::{Lease, Link, Object};

use super::{ReleaseContent, record};

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
    claim_environment_with_options(ctx, environment, owner, EXECUTION_LEASE_MS, true).await
}

async fn claim_environment_with_options(
    ctx: &mut Ctx,
    environment: &str,
    owner: &str,
    ttl_ms: i64,
    automatic_takeover: bool,
) -> Result<EnvironmentLease> {
    let now = crate::now_millis();
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
    let lease = match ctx
        .acquire_lease(ENVIRONMENT_LEASE_NAMESPACE, environment, owner, ttl_ms)
        .await
    {
        Ok(lease) => lease,
        Err(error)
            if error
                .downcast_ref::<tonic::Status>()
                .is_some_and(|status| status.code() == tonic::Code::AlreadyExists) =>
        {
            if let Some(existing) = get_environment_lease(ctx, environment).await? {
                if existing.status == "active" && existing.expires_at_ms <= now {
                    if !automatic_takeover {
                        bail!(
                            "environment {environment} has an expired apply lease; verify no operation is running, then run `tenkaictl env unlock {environment}`"
                        );
                    }
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
                return Err(error);
            }
        }
        Err(error) => return Err(error),
    };
    let environment_lease = EnvironmentLease {
        environment: environment.into(),
        owner: owner.into(),
        generation: lease.generation,
        fencing_token: lease.fencing_token,
        ttl_ms,
    };
    let available = object_environment_claim(environment, "released", 0);
    match ctx.create_once(available).await {
        Ok(_) => {}
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && (status.message().contains("UNIQUE")
                        || status.message().contains("object IDs with audit history"))) => {}
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
        if status.code() == tonic::Code::AlreadyExists
            || (status.code() == tonic::Code::Internal && status.message().contains("UNIQUE"))
        {
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
    Ok(environment_lease)
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
    Ok(())
}

pub(crate) struct EnvironmentLeaseStatus {
    pub owner: String,
}

/// Operator-facing lease/fence summary. Never includes credentials.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
