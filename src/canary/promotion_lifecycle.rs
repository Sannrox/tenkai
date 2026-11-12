//! Canary policy persistence, promotion fencing, authorization, and compensation.

use super::*;
use crate::auth_context::{AuthenticatedRequestContext, DeliveryCapability};

pub(crate) fn require_management(actor: &AuthenticatedRequestContext) -> Result<()> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn require_publish(actor: &AuthenticatedRequestContext) -> Result<()> {
    actor
        .require_delivery_capability(DeliveryCapability::Publish)
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn policy_id(product: &str, version: &str, target_channel: &str) -> String {
    format!("tenkai:canary-policy:{product}@{version}:{target_channel}")
}

pub(super) fn policy_record_id(active: &ActiveCanaryPolicy) -> String {
    format!(
        "{}:{}:{}",
        policy_id(
            &active.policy.product,
            &active.policy.version,
            &active.policy.target_channel
        ),
        active.activated_at,
        active.digest
    )
}

fn designation_id(environment: &str) -> String {
    format!("tenkai:canary-designation:{environment}")
}

pub(super) const POLICY_DISCOVERY_LOCK_CHANNEL: &str = "_policy-index";
const REL_ACTIVE_PROMOTION_LOCK: &str = "active_promotion_lock";
/// Generic lease namespace for promotion and policy-update serialization.
const PROMOTION_LEASE_NAMESPACE: &str = "tenkai/promotion";
/// Promotion critical sections are a few catalog round trips, and each
/// write is preceded by a refresh; a crashed holder frees the lock once
/// this lapses.
const PROMOTION_LEASE_TTL_MS: i64 = 120_000;

fn promotion_lease_key(product: &str, target_channel: &str) -> String {
    format!("{product}:{target_channel}")
}

/// Object and self-link a server from before the lease holds the lock with.
fn pre_lease_lock_id(product: &str, target_channel: &str) -> String {
    format!("tenkai:promotion-lock:v2:{product}:{target_channel}")
}

fn legacy_promotion_lock_id(product: &str, target_channel: &str) -> String {
    format!("tenkai:promotion-lock:{product}:{target_channel}")
}

/// Marks the pre-lease lock object as held by a lease holder, so a later
/// lease holder can tell a crashed one apart from a pre-lease server.
const LEASE_OWNER_PREFIX: &str = "lease:";

/// A held promotion lease, plus the pre-lease link it holds alongside.
#[derive(Debug)]
pub(crate) struct PromotionLock {
    key: String,
    link_object: String,
    fencing_token: String,
}

fn pre_lease_lock_link(lock_id: &str) -> Link {
    Link {
        id: format!("{lock_id}--{REL_ACTIVE_PROMOTION_LOCK}--{lock_id}"),
        from_id: lock_id.into(),
        to_id: lock_id.into(),
        relation: REL_ACTIVE_PROMOTION_LOCK.into(),
        created: crate::now_millis(),
    }
}

async fn pre_lease_link_held(ctx: &mut Ctx, id: &str) -> Result<bool> {
    let active = pre_lease_lock_link(id).id;
    Ok(ctx
        .links(id, REL_ACTIVE_PROMOTION_LOCK)
        .await?
        .iter()
        .any(|link| link.id == active))
}

/// Also hold the pre-lease self-link while holding the lease.
///
/// Rolling-deploy window only; the next release drops it. A server from
/// before the lease claims through this link and cannot see the lease, so
/// a lease holder takes the link too, then stamps the lock object with its
/// lease token. A link already present is adopted only when its object
/// names the previous lease's token and the link was created before that
/// lease ended: it was left by that holder, and holding the lease now
/// proves the holder is gone. A pre-lease server stamps its own owner right
/// after linking, so its link never passes both checks. Any other link
/// waits.
///
/// Residual, rolling-deploy window only: a crash between linking and
/// stamping over a pre-lease owner, or a holder that stalls longer than a
/// lease inside [`release_promotion_lock`], needs `canary unlock`.
async fn hold_pre_lease_link(
    ctx: &mut Ctx,
    lock: &PromotionLock,
    previous: Option<&crate::pb::sekai::Lease>,
    product: &str,
    target_channel: &str,
) -> Result<()> {
    let now = crate::now_millis();
    let fresh = Object {
        id: lock.link_object.clone(),
        kind: KIND_PROMOTION_LOCK.into(),
        name: format!("{product}/{target_channel} promotion lock"),
        namespace: NS.into(),
        external_id: String::new(),
        // Born owned, so a crash before the stamp below stays adoptable.
        properties: HashMap::from([(
            "owner".into(),
            format!("{LEASE_OWNER_PREFIX}{}", lock.fencing_token),
        )]),
        created: now,
        updated: now,
    };
    match ctx.create_once(fresh).await {
        Ok(_) => {}
        Err(status) if crate::client::is_unique_conflict(&status) => {}
        Err(status) => return Err(status.into()),
    }
    match ctx
        .create_link_once(pre_lease_lock_link(&lock.link_object))
        .await
    {
        Ok(_) => {}
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let owner = ctx
                .get(&lock.link_object)
                .await?
                .and_then(|object| object.properties.get("owner").cloned());
            let active = pre_lease_lock_link(&lock.link_object).id;
            let links = ctx
                .links(&lock.link_object, REL_ACTIVE_PROMOTION_LOCK)
                .await?;
            let left_by_previous_holder = previous.is_some_and(|previous| {
                let end = if previous.status == "active" {
                    previous.expires_at_ms
                } else {
                    previous.released_at_ms
                };
                owner.as_deref() == Some(&format!("{LEASE_OWNER_PREFIX}{}", previous.fencing_token))
                    && links
                        .iter()
                        .any(|link| link.id == active && link.created < end)
            });
            if !left_by_previous_holder {
                return Err(busy(product, target_channel));
            }
        }
        Err(status) => return Err(status.into()),
    }
    let mut object = ctx
        .get(&lock.link_object)
        .await?
        .with_context(|| format!("promotion lock {} vanished", lock.link_object))?;
    object.properties.insert(
        "owner".into(),
        format!("{LEASE_OWNER_PREFIX}{}", lock.fencing_token),
    );
    object.updated = crate::now_millis().max(object.created);
    fenced_put(ctx, std::slice::from_ref(lock), object).await?;
    Ok(())
}

/// Write `object` only while every lock in `locks` is held.
///
/// The first lock is checked in the write's own transaction; the others
/// are refreshed in the same catalog transaction where the backend can.
/// With no locks (an attempt that names no policy) the write is plain.
pub(crate) async fn fenced_put(
    ctx: &mut Ctx,
    locks: &[PromotionLock],
    object: Object,
) -> Result<Object> {
    let Some((guard, others)) = locks.split_first() else {
        return ctx.put(object).await;
    };
    // A guarded update needs the object to exist; create it fenced first.
    if ctx.get(&object.id).await?.is_none()
        && let Some(created) = fenced_create(ctx, locks, object.clone()).await?
    {
        return Ok(created);
    }
    if others.is_empty() {
        return ctx
            .guarded_update(
                object,
                PROMOTION_LEASE_NAMESPACE,
                &guard.key,
                &guard.fencing_token,
            )
            .await;
    }
    // The guard lease is left out of the refreshes so its expiry is not
    // stamped onto `object`.
    let refreshes = others
        .iter()
        .map(|lock| crate::storage::LeaseRefresh {
            namespace: PROMOTION_LEASE_NAMESPACE.into(),
            key: lock.key.clone(),
            fencing_token: lock.fencing_token.clone(),
            ttl_ms: PROMOTION_LEASE_TTL_MS,
            extend: true,
        })
        .collect();
    let (_, object) = ctx
        .refresh_leases_and_guarded_put(
            refreshes,
            object,
            PROMOTION_LEASE_NAMESPACE,
            &guard.key,
            &guard.fencing_token,
        )
        .await?;
    Ok(object)
}

/// Write every object only while the promotion lock is held, in one store
/// transaction. Used so a channel head and its decision commit cannot split.
pub(crate) async fn fenced_put_objects(
    ctx: &mut Ctx,
    locks: &[PromotionLock],
    objects: Vec<Object>,
) -> Result<()> {
    if objects.is_empty() {
        return Ok(());
    }
    if objects.len() == 1 {
        fenced_put(ctx, locks, objects.into_iter().next().expect("len 1")).await?;
        return Ok(());
    }
    let Some((guard, others)) = locks.split_first() else {
        for object in objects {
            ctx.put(object).await?;
        }
        return Ok(());
    };
    for lock in others {
        confirm_promotion_lock(ctx, lock).await?;
    }
    ctx.guarded_update_objects_with_provider_events(
        &objects,
        PROMOTION_LEASE_NAMESPACE,
        &guard.key,
        &guard.fencing_token,
        &[],
        &[],
    )
    .await
}

/// Create `object` only while every lock in `locks` is held. `None` when
/// an object with that id already exists.
pub(crate) async fn fenced_create(
    ctx: &mut Ctx,
    locks: &[PromotionLock],
    object: Object,
) -> Result<Option<Object>> {
    let Some((guard, others)) = locks.split_first() else {
        return match ctx.create_once(object).await {
            Ok(object) => Ok(Some(object)),
            Err(status) if crate::client::is_unique_conflict(&status) => Ok(None),
            Err(status) => Err(status.into()),
        };
    };
    for lock in others {
        confirm_promotion_lock(ctx, lock).await?;
    }
    let id = object.id.clone();
    match ctx
        .guarded_create(
            object,
            PROMOTION_LEASE_NAMESPACE,
            &guard.key,
            &guard.fencing_token,
        )
        .await
    {
        Ok(object) => Ok(Some(object)),
        Err(error) => {
            confirm_promotion_lock(ctx, guard).await?;
            if ctx.get(&id).await?.is_some() {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }
}

fn busy(product: &str, target_channel: &str) -> anyhow::Error {
    anyhow::anyhow!("promotion or policy update already in progress for {product}/{target_channel}")
}

/// Claim the promotion lease for `product`/`target_channel`.
///
/// An expired holder is taken over, so a crashed promotion frees the lock
/// on its own. Fails with "already in progress" while a live holder exists.
pub(crate) async fn claim_promotion_lock(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
    owner: &str,
) -> Result<PromotionLock> {
    claim_promotion_lock_for(ctx, product, target_channel, owner, PROMOTION_LEASE_TTL_MS).await
}

async fn claim_promotion_lock_for(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
    owner: &str,
    ttl_ms: i64,
) -> Result<PromotionLock> {
    crate::ontology::require_canary_schema(ctx).await?;
    if ctx
        .get(&legacy_promotion_lock_id(product, target_channel))
        .await?
        .is_some()
    {
        return Err(busy(product, target_channel));
    }
    let key = promotion_lease_key(product, target_channel);
    let previous = ctx.get_lease(PROMOTION_LEASE_NAMESPACE, &key).await?;
    let lease = match ctx
        .acquire_lease(PROMOTION_LEASE_NAMESPACE, &key, owner, ttl_ms)
        .await
    {
        Ok(lease) => lease,
        Err(crate::client::LeaseError::AlreadyExists) => {
            let existing = ctx
                .get_lease(PROMOTION_LEASE_NAMESPACE, &key)
                .await?
                .ok_or_else(|| busy(product, target_channel))?;
            if existing.status != "active" || existing.expires_at_ms > crate::now_millis() {
                return Err(busy(product, target_channel));
            }
            ctx.takeover_expired_lease(
                PROMOTION_LEASE_NAMESPACE,
                &key,
                owner,
                &existing.fencing_token,
                existing.expires_at_ms,
                ttl_ms,
            )
            .await
            .map_err(|_| busy(product, target_channel))?
        }
        Err(error) => return Err(error.into()),
    };
    let lock = PromotionLock {
        key,
        link_object: pre_lease_lock_id(product, target_channel),
        fencing_token: lease.fencing_token,
    };
    if let Err(error) =
        hold_pre_lease_link(ctx, &lock, previous.as_ref(), product, target_channel).await
    {
        let _ = ctx
            .release_lease(PROMOTION_LEASE_NAMESPACE, &lock.key, &lock.fencing_token)
            .await;
        return Err(error);
    }
    Ok(lock)
}

pub(super) async fn claim_promotion_lock_with_retry(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
    owner: &str,
) -> Result<PromotionLock> {
    const MAX_ATTEMPTS: usize = 100;
    for attempt in 0..MAX_ATTEMPTS {
        match claim_promotion_lock(ctx, product, target_channel, owner).await {
            Ok(lock) => return Ok(lock),
            Err(error)
                if attempt + 1 < MAX_ATTEMPTS
                    && error.to_string().contains("already in progress") =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded lock retry loop always returns")
}

/// Fail unless `lock` is still the live lease holder, and extend it.
///
/// Call it right before each protected write.
pub(crate) async fn confirm_promotion_lock(ctx: &mut Ctx, lock: &PromotionLock) -> Result<()> {
    ctx.refresh_lease(
        PROMOTION_LEASE_NAMESPACE,
        &lock.key,
        &lock.fencing_token,
        PROMOTION_LEASE_TTL_MS,
    )
    .await
    .with_context(|| {
        format!(
            "promotion lock {} is no longer owned by this operation",
            lock.key
        )
    })?;
    Ok(())
}

/// Operator escape hatch: free a promotion lock without waiting for expiry.
pub async fn unlock_promotion(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    product: &str,
    target_channel: &str,
) -> Result<String> {
    require_management(actor)?;
    validate_identifier("product", product)?;
    if target_channel != POLICY_DISCOVERY_LOCK_CHANNEL {
        validate_identifier("channel", target_channel)?;
    }
    let mut removed = false;
    let key = promotion_lease_key(product, target_channel);
    // An expired lease needs nothing: the next claim takes it over.
    if let Some(lease) = ctx.get_lease(PROMOTION_LEASE_NAMESPACE, &key).await?
        && lease.status == "active"
        && lease.expires_at_ms > crate::now_millis()
    {
        ctx.release_lease(PROMOTION_LEASE_NAMESPACE, &key, &lease.fencing_token)
            .await?;
        removed = true;
    }
    let id = pre_lease_lock_id(product, target_channel);
    if pre_lease_link_held(ctx, &id).await? {
        ctx.unlink(&id, &id, REL_ACTIVE_PROMOTION_LOCK).await?;
        removed = true;
    }
    let legacy_id = legacy_promotion_lock_id(product, target_channel);
    if ctx.get(&legacy_id).await?.is_some() {
        ctx.delete(&legacy_id).await?;
        removed = true;
    }
    Ok(if removed {
        format!("promotion lock removed for {product}/{target_channel}")
    } else {
        format!("no promotion lock exists for {product}/{target_channel}")
    })
}

/// Release `lock`: the pre-lease link while the lease is still ours, then
/// the lease. A lapsed or taken-over lease leaves nothing to release.
pub(crate) async fn release_promotion_lock(ctx: &mut Ctx, lock: &PromotionLock) -> Result<()> {
    // A lapsed holder leaves the link: the next holder adopts it. The
    // owner is read after the refresh, so only a holder that stalls longer
    // than a lease between these two calls and the unlink could remove a
    // successor's link (rolling-deploy window only).
    let ours = format!("{LEASE_OWNER_PREFIX}{}", lock.fencing_token);
    if confirm_promotion_lock(ctx, lock).await.is_ok()
        && ctx
            .get(&lock.link_object)
            .await?
            .is_some_and(|object| object.properties.get("owner") == Some(&ours))
    {
        ctx.unlink(
            &lock.link_object,
            &lock.link_object,
            REL_ACTIVE_PROMOTION_LOCK,
        )
        .await?;
    }
    match ctx
        .release_lease(PROMOTION_LEASE_NAMESPACE, &lock.key, &lock.fencing_token)
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => match ctx.get_lease(PROMOTION_LEASE_NAMESPACE, &lock.key).await? {
            Some(lease)
                if lease.status == "active"
                    && lease.fencing_token == lock.fencing_token
                    && lease.expires_at_ms > crate::now_millis() =>
            {
                Err(error)
            }
            _ => Ok(()),
        },
    }
}

pub(super) async fn claim_policy_locks(
    ctx: &mut Ctx,
    policies: &[ActiveCanaryPolicy],
    owner: &str,
) -> Result<Vec<PromotionLock>> {
    let keys = policies
        .iter()
        .map(|active| {
            (
                active.policy.product.clone(),
                active.policy.target_channel.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut locks = Vec::new();
    for (product, target_channel) in keys {
        match claim_promotion_lock_with_retry(ctx, &product, &target_channel, owner).await {
            Ok(lock) => locks.push(lock),
            Err(error) => {
                for lock in locks.iter().rev() {
                    let _ = release_promotion_lock(ctx, lock).await;
                }
                return Err(error);
            }
        }
    }
    Ok(locks)
}

pub(super) async fn release_policy_locks(ctx: &mut Ctx, locks: &[PromotionLock]) -> Result<()> {
    let mut first_error = None;
    for lock in locks.iter().rev() {
        if let Err(error) = release_promotion_lock(ctx, lock).await {
            first_error.get_or_insert(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(())
}

pub(super) fn object_property<'a>(object: &'a Object, name: &str) -> Result<&'a str> {
    object
        .properties
        .get(name)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .with_context(|| format!("object {} has no {name}", object.id))
}

fn active_from_object(object: &Object) -> Result<ActiveCanaryPolicy> {
    if object.kind != KIND_CANARY_POLICY {
        bail!(
            "object {} is {}, not {KIND_CANARY_POLICY}",
            object.id,
            object.kind
        );
    }
    if object_property(object, "active")? != "true" {
        bail!("canary policy object {} is not active", object.id);
    }
    let policy: CanaryPolicy = serde_json::from_str(object_property(object, "policy")?)
        .with_context(|| format!("canary policy object {} has invalid JSON", object.id))?;
    let active = ActiveCanaryPolicy::new(policy, object.updated)?;
    if object.id != policy_record_id(&active)
        || object_property(object, "policy_digest")? != active.digest
        || object_property(object, "release_id")? != active.policy.release_id
    {
        bail!(
            "canary policy object {} has inconsistent identity",
            object.id
        );
    }
    Ok(active)
}

async fn active_from_pointer(ctx: &mut Ctx, pointer: &Object) -> Result<ActiveCanaryPolicy> {
    if pointer.kind != KIND_CANARY_POLICY_POINTER {
        bail!(
            "object {} is {}, not {KIND_CANARY_POLICY_POINTER}",
            pointer.id,
            pointer.kind
        );
    }
    let policy_object_id = object_property(pointer, "policy_id")?;
    let object = ctx
        .get(policy_object_id)
        .await?
        .with_context(|| format!("active canary policy {policy_object_id} is missing"))?;
    let active = active_from_object(&object)?;
    if pointer.id
        != policy_id(
            &active.policy.product,
            &active.policy.version,
            &active.policy.target_channel,
        )
        || object_property(pointer, "release_id")? != active.policy.release_id
        || object_property(pointer, "target_channel")? != active.policy.target_channel
        || object_property(pointer, "policy_digest")? != active.digest
    {
        bail!(
            "canary policy pointer {} has inconsistent identity",
            pointer.id
        );
    }
    Ok(active)
}

pub async fn set_designated(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    environment: &str,
    designated: bool,
) -> Result<String> {
    require_management(actor)?;
    crate::ontology::require_canary_schema(ctx).await?;
    validate_identifier("environment", environment)?;
    let id = env_id(environment);
    let owner = format!(
        "canary-designation:{}:{}",
        actor.principal_id(),
        crate::now_millis()
    );
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = async {
        let environment_object = ctx
            .get(&id)
            .await?
            .with_context(|| format!("environment {environment} is not registered"))?;
        if environment_object.kind != KIND_ENVIRONMENT {
            bail!(
                "object {id} is {}, not {KIND_ENVIRONMENT}",
                environment_object.kind
            );
        }
        let designation_id = designation_id(environment);
        if designated {
            let now = crate::now_millis();
            ctx.put(Object {
                id: designation_id,
                kind: KIND_CANARY_DESIGNATION.into(),
                name: format!("{environment} canary designation"),
                namespace: NS.into(),
                external_id: String::new(),
                properties: HashMap::from([("environment".into(), environment.into())]),
                created: now,
                updated: now,
            })
            .await?;
        } else if ctx.get(&designation_id).await?.is_some() {
            ctx.delete(&designation_id).await?;
        }
        Ok::<_, anyhow::Error>(format!(
            "environment {environment} {} as canary",
            if designated { "designated" } else { "removed" }
        ))
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing canary designation lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing canary designation lease failed")),
    }
}

async fn is_designated(ctx: &mut Ctx, environment: &str, product: &str) -> Result<bool> {
    let object = ctx
        .get(&env_id(environment))
        .await?
        .with_context(|| format!("environment {environment} is not registered"))?;
    if let Some(designation) = ctx.get(&designation_id(environment)).await? {
        if designation.kind != KIND_CANARY_DESIGNATION
            || designation
                .properties
                .get("environment")
                .map(String::as_str)
                != Some(environment)
        {
            bail!("canary designation for {environment} is inconsistent");
        }
        return Ok(true);
    }
    Ok(ctx
        .linked(&object.id, REL_SUBSCRIBES, "out")
        .await?
        .iter()
        .any(|channel| {
            channel
                .properties
                .get("product")
                .is_some_and(|value| value == product)
                && channel
                    .properties
                    .get("channel")
                    .is_some_and(|value| value == "canary")
        }))
}

pub async fn configure(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    spec: &str,
    target_channel: &str,
    cohort: Vec<String>,
    reactivate: bool,
) -> Result<ActiveCanaryPolicy> {
    require_management(actor)?;
    let product = spec
        .split_once('@')
        .map(|(product, _)| product)
        .unwrap_or(spec);
    validate_identifier("product", product)?;
    validate_identifier("channel", target_channel)?;
    let owner = format!(
        "policy:{}:{spec}:{}",
        actor.principal_id(),
        crate::now_millis()
    );
    let discovery =
        claim_promotion_lock(ctx, product, POLICY_DISCOVERY_LOCK_CHANNEL, &owner).await?;
    let target = match claim_promotion_lock(ctx, product, target_channel, &owner).await {
        Ok(lock) => lock,
        Err(error) => {
            let release = release_promotion_lock(ctx, &discovery).await;
            return match release {
                Ok(()) => Err(error),
                Err(unlock) => Err(error.context(format!(
                    "releasing policy discovery lock also failed: {unlock}"
                ))),
            };
        }
    };
    let locks = [target, discovery];
    let result = configure_locked(ctx, spec, target_channel, cohort, reactivate, &locks).await;
    let mut unlock_error = None;
    for lock in &locks {
        if let Err(error) = release_promotion_lock(ctx, lock).await {
            unlock_error.get_or_insert(error);
        }
    }
    match (result, unlock_error) {
        (Ok(policy), None) => Ok(policy),
        (Err(error), None) => Err(error),
        (Err(error), Some(unlock)) => {
            Err(error.context(format!("releasing policy locks also failed: {unlock}")))
        }
        (Ok(_), Some(error)) => Err(error.context("releasing policy locks failed")),
    }
}

async fn configure_locked(
    ctx: &mut Ctx,
    spec: &str,
    target_channel: &str,
    cohort: Vec<String>,
    reactivate: bool,
    locks: &[PromotionLock],
) -> Result<ActiveCanaryPolicy> {
    let (product, version) = spec
        .split_once('@')
        .with_context(|| format!("expected <product>@<version>, got {spec:?}"))?;
    validate_identifier("product", product)?;
    validate_identifier("version", version)?;
    validate_identifier("channel", target_channel)?;
    let release_id = release_id(product, version);
    let release = ctx
        .get(&release_id)
        .await?
        .with_context(|| format!("release {spec} is not published"))?;
    for environment in &cohort {
        if !is_designated(ctx, environment, product).await? {
            bail!(
                "environment {environment} is not designated as a canary or subscribed to {product}/canary"
            );
        }
    }
    let policy = CanaryPolicy {
        release_id: release_id.clone(),
        release_digest: object_property(&release, "digest")?.into(),
        artifact_digest: object_property(&release, "artifact_digest")?.into(),
        product: product.into(),
        version: version.into(),
        target_channel: target_channel.into(),
        cohort,
        success_policy: SuccessPolicy::All,
    }
    .canonicalized()?;
    let pointer_id = policy_id(product, version, target_channel);
    let existing = ctx.get(&pointer_id).await?;
    if let Some(pointer) = existing.as_ref() {
        let current = active_from_pointer(ctx, pointer).await?;
        if current.policy == policy && !reactivate {
            return Ok(current);
        }
    }
    let now = crate::now_millis();
    let activated_at = existing
        .as_ref()
        .map_or(now, |pointer| now.max(pointer.updated.saturating_add(1)));
    let active = ActiveCanaryPolicy::new(policy, activated_at)?;
    let record_id = policy_record_id(&active);
    let object = Object {
        id: record_id.clone(),
        kind: KIND_CANARY_POLICY.into(),
        name: format!("{spec} promotion to {target_channel}"),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("release_id".into(), active.policy.release_id.clone()),
            (
                "release_digest".into(),
                active.policy.release_digest.clone(),
            ),
            (
                "artifact_digest".into(),
                active.policy.artifact_digest.clone(),
            ),
            ("target_channel".into(), target_channel.into()),
            ("policy_digest".into(), active.digest.clone()),
            ("active".into(), "true".into()),
            ("policy".into(), serde_json::to_string(&active.policy)?),
        ]),
        created: activated_at,
        updated: activated_at,
    };
    if fenced_create(ctx, locks, object).await?.is_none() {
        bail!("canary policy {record_id} already exists");
    }
    ctx.link(&record_id, &release_id, REL_GOVERNS_RELEASE)
        .await?;
    let pointer = Object {
        id: pointer_id,
        kind: KIND_CANARY_POLICY_POINTER.into(),
        name: format!("active {spec} promotion to {target_channel}"),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("release_id".into(), active.policy.release_id.clone()),
            ("target_channel".into(), target_channel.into()),
            ("policy_id".into(), record_id),
            ("policy_digest".into(), active.digest.clone()),
        ]),
        created: existing
            .as_ref()
            .map_or(activated_at, |pointer| pointer.created),
        updated: activated_at,
    };
    fenced_put(ctx, locks, pointer).await?;
    Ok(active)
}

pub async fn active_policy(
    ctx: &mut Ctx,
    product: &str,
    version: &str,
    target_channel: &str,
) -> Result<ActiveCanaryPolicy> {
    let id = policy_id(product, version, target_channel);
    let object = ctx.get(&id).await?.with_context(|| {
        format!("no canary policy configured for {product}@{version} -> {target_channel}")
    })?;
    active_from_pointer(ctx, &object).await
}

pub(super) async fn policies_for_release(
    ctx: &mut Ctx,
    release: &str,
) -> Result<Vec<ActiveCanaryPolicy>> {
    let pointers = ctx
        .find_by_property(KIND_CANARY_POLICY_POINTER, "release_id", release)
        .await?;
    let mut policies = Vec::with_capacity(pointers.len());
    for pointer in &pointers {
        policies.push(active_from_pointer(ctx, pointer).await?);
    }
    Ok(policies)
}

pub(crate) async fn maybe_active_policy(
    ctx: &mut Ctx,
    product: &str,
    version: &str,
    target_channel: &str,
) -> Result<Option<ActiveCanaryPolicy>> {
    let pointer = ctx
        .get(&policy_id(product, version, target_channel))
        .await?;
    match pointer.as_ref() {
        Some(pointer) => Ok(Some(active_from_pointer(ctx, pointer).await?)),
        None => Ok(None),
    }
}

async fn record_promotion_audit(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    active: &ActiveCanaryPolicy,
    evaluation: &PromotionEvaluation,
) -> Result<()> {
    let evaluated_at = crate::now_millis();
    let serialized = serde_json::to_string(evaluation)?;
    let policy_object_id = policy_record_id(active);
    for sequence in 0..1024_u16 {
        let id = format!(
            "{}:promotion-audit:{}:{evaluated_at}:{sequence}",
            active.policy.release_id, active.policy.target_channel
        );
        let object = Object {
            id: id.clone(),
            kind: KIND_PROMOTION_AUDIT.into(),
            name: format!(
                "{} promotion to {}",
                active.policy.release_id, active.policy.target_channel
            ),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("release_id".into(), active.policy.release_id.clone()),
                (
                    "target_channel".into(),
                    active.policy.target_channel.clone(),
                ),
                ("policy_digest".into(), active.digest.clone()),
                (
                    "policy_activated_at".into(),
                    evaluation.policy_activated_at.to_string(),
                ),
                ("allowed".into(), evaluation.allowed.to_string()),
                ("evaluated_at".into(), evaluated_at.to_string()),
                ("evaluation".into(), serialized.clone()),
                ("principal_id".into(), actor.principal_id().into()),
                ("principal_kind".into(), actor.principal_kind_name().into()),
            ]),
            created: evaluated_at,
            updated: evaluated_at,
        };
        match ctx.create_once(object).await {
            Ok(_) => {
                ctx.link(&id, &active.policy.release_id, REL_AUDITS_PROMOTION)
                    .await?;
                ctx.link(&id, &policy_object_id, REL_EVIDENCE_FOR_POLICY)
                    .await?;
                return Ok(());
            }
            Err(status) if crate::client::is_unique_conflict(&status) => {}
            Err(status) => return Err(status.into()),
        }
    }
    bail!(
        "could not allocate promotion audit for {}",
        active.policy.release_id
    )
}

pub async fn authorize_promotion(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    product: &str,
    version: &str,
    target_channel: &str,
) -> Result<Option<ActiveCanaryPolicy>> {
    require_publish(actor)?;
    let Some(active) = maybe_active_policy(ctx, product, version, target_channel).await? else {
        return Ok(None);
    };
    let evaluation = evaluate_active(ctx, &active).await?;
    record_promotion_audit(ctx, actor, &active, &evaluation).await?;
    if !evaluation.allowed {
        let blocked = evaluation
            .cohort
            .iter()
            .filter_map(|(environment, result)| {
                (!matches!(result, CohortResult::Passed { .. })).then_some(environment.as_str())
            })
            .collect::<Vec<_>>();
        bail!(
            "canary promotion blocked for {product}@{version} -> {target_channel}: {}",
            blocked.join(", ")
        );
    }
    Ok(Some(active))
}

pub async fn confirm_policy_active(ctx: &mut Ctx, expected: &ActiveCanaryPolicy) -> Result<()> {
    let current = active_policy(
        ctx,
        &expected.policy.product,
        &expected.policy.version,
        &expected.policy.target_channel,
    )
    .await?;
    if current != *expected {
        bail!("canary policy changed after promotion authorization");
    }
    Ok(())
}

/// Run one complete promotion transaction while the Canary policy and lock
/// remain valid. The caller supplies only the Catalog mutation; lock fencing,
/// authorization freshness, and release compensation stay inside this module.
pub(crate) async fn guarded_promotion<T, F>(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    product: &str,
    version: &str,
    target_channel: &str,
    owner: &str,
    promote: F,
) -> Result<T>
where
    F: for<'a> FnOnce(
        &'a mut Ctx,
        &'a PromotionLock,
    ) -> Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>,
{
    require_publish(actor)?;
    let lock = claim_promotion_lock(ctx, product, target_channel, owner).await?;
    let result = async {
        let authorization =
            authorize_promotion(ctx, actor, product, version, target_channel).await?;
        if let Some(expected) = authorization.as_ref() {
            confirm_policy_active(ctx, expected).await?;
        }
        confirm_promotion_lock(ctx, &lock).await?;
        promote(ctx, &lock).await
    }
    .await;
    let unlock = release_promotion_lock(ctx, &lock).await;
    finish_locked(result, unlock)
}

/// Combine a locked mutation's outcome with releasing its promotion lock.
/// Callers that hold the lock without `guarded_promotion` (channel head
/// removal) report both failures the same way.
pub(crate) fn finish_locked<T>(result: Result<T>, unlock: Result<()>) -> Result<T> {
    match (result, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => {
            Err(error.context(format!("releasing promotion lock also failed: {unlock}")))
        }
        (Ok(_), Err(error)) => Err(error.context("releasing promotion lock failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn canary_ctx(label: &str) -> (Ctx, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "tenkai-promotion-lock-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        (ctx, root)
    }

    /// What a server from before the lease does to claim the lock.
    async fn pre_lease_server_claims(ctx: &mut Ctx) -> bool {
        let id = pre_lease_lock_id("app", "stable");
        ctx.create_link_once(pre_lease_lock_link(&id)).await.is_ok()
    }

    fn channel_head(release: &str) -> Object {
        let now = crate::now_millis();
        Object {
            id: "tenkai:channel:app:stable".into(),
            kind: KIND_CHANNEL.into(),
            name: "app/stable".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([("current_release".into(), release.into())]),
            created: now,
            updated: now,
        }
    }

    #[tokio::test]
    async fn a_crashed_promotion_holder_is_recovered_by_expiry() {
        let (mut ctx, root) = canary_ctx("expiry").await;
        // Holder A "crashes": it never releases.
        let crashed = claim_promotion_lock_for(&mut ctx, "app", "stable", "holder-a", 50)
            .await
            .unwrap();
        let live = claim_promotion_lock(&mut ctx, "app", "stable", "holder-b")
            .await
            .unwrap_err();
        assert!(live.to_string().contains("already in progress"), "{live:#}");

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        // B takes over the lease and adopts the link A left behind.
        let next = claim_promotion_lock(&mut ctx, "app", "stable", "holder-b")
            .await
            .unwrap();
        fenced_put(&mut ctx, std::slice::from_ref(&next), channel_head("b"))
            .await
            .unwrap();

        // A resumes: its writes are refused and its release frees nothing.
        assert!(
            fenced_put(&mut ctx, std::slice::from_ref(&crashed), channel_head("a"))
                .await
                .is_err()
        );
        release_promotion_lock(&mut ctx, &crashed).await.unwrap();
        assert!(!pre_lease_server_claims(&mut ctx).await);
        let head = ctx.get("tenkai:channel:app:stable").await.unwrap().unwrap();
        assert_eq!(head.properties["current_release"], "b");

        release_promotion_lock(&mut ctx, &next).await.unwrap();
        assert!(pre_lease_server_claims(&mut ctx).await);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_lease_holder_also_blocks_a_pre_lease_server() {
        let (mut ctx, root) = canary_ctx("dual").await;
        let lock = claim_promotion_lock(&mut ctx, "app", "stable", "new-server")
            .await
            .unwrap();
        assert!(!pre_lease_server_claims(&mut ctx).await);
        release_promotion_lock(&mut ctx, &lock).await.unwrap();
        assert!(pre_lease_server_claims(&mut ctx).await);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_pre_lease_server_mid_claim_is_not_adopted() {
        let (mut ctx, root) = canary_ctx("mid-claim").await;
        let lock = claim_promotion_lock(&mut ctx, "app", "stable", "new-a")
            .await
            .unwrap();
        release_promotion_lock(&mut ctx, &lock).await.unwrap();
        // A pre-lease server links; its owner is not stamped yet, so the
        // object still names the released lease holder.
        assert!(pre_lease_server_claims(&mut ctx).await);
        let refused = claim_promotion_lock(&mut ctx, "app", "stable", "new-b")
            .await
            .unwrap_err();
        assert!(
            refused.to_string().contains("already in progress"),
            "{refused:#}"
        );
        // The refused claim's own lease does not make the link adoptable.
        assert!(
            claim_promotion_lock(&mut ctx, "app", "stable", "new-c")
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_pre_lease_holder_keeps_the_lock_until_unlocked() {
        let (mut ctx, root) = canary_ctx("rolling").await;
        // A server from before the lease holds the link with no lease token.
        let id = pre_lease_lock_id("app", "stable");
        let now = crate::now_millis();
        ctx.create_once(Object {
            id: id.clone(),
            kind: KIND_PROMOTION_LOCK.into(),
            name: "app/stable promotion lock".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([("owner".into(), "old-server".into())]),
            created: now,
            updated: now,
        })
        .await
        .unwrap();
        ctx.create_link_once(pre_lease_lock_link(&id))
            .await
            .unwrap();

        let refused = claim_promotion_lock(&mut ctx, "app", "stable", "new-server")
            .await
            .unwrap_err();
        assert!(
            refused.to_string().contains("already in progress"),
            "{refused:#}"
        );
        // The refused claim gave its lease back, so it blocks nobody.
        assert!(
            ctx.get_lease(
                PROMOTION_LEASE_NAMESPACE,
                &promotion_lease_key("app", "stable")
            )
            .await
            .unwrap()
            .is_none_or(|lease| lease.status != "active")
        );

        let operator = crate::auth_context::test_management_context("operator");
        unlock_promotion(&mut ctx, &operator, "app", "stable")
            .await
            .unwrap();
        let lock = claim_promotion_lock(&mut ctx, "app", "stable", "new-server")
            .await
            .unwrap();
        release_promotion_lock(&mut ctx, &lock).await.unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }
}
