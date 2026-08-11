//! Canary policy persistence, promotion fencing, authorization, and compensation.

use super::*;

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
const RELEASED_PROMOTION_LOCK_OWNER: &str = "released";
const REL_ACTIVE_PROMOTION_LOCK: &str = "active_promotion_lock";

fn promotion_lock_id(product: &str, target_channel: &str) -> String {
    format!("tenkai:promotion-lock:v2:{product}:{target_channel}")
}

fn legacy_promotion_lock_id(product: &str, target_channel: &str) -> String {
    format!("tenkai:promotion-lock:{product}:{target_channel}")
}

pub(crate) struct PromotionLock {
    id: String,
    owner: String,
}

fn promotion_lock_link(lock_id: &str) -> Link {
    Link {
        id: format!("{lock_id}--{REL_ACTIVE_PROMOTION_LOCK}--{lock_id}"),
        from_id: lock_id.into(),
        to_id: lock_id.into(),
        relation: REL_ACTIVE_PROMOTION_LOCK.into(),
        created: crate::now_millis(),
    }
}

pub(crate) async fn claim_promotion_lock(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
    owner: &str,
) -> Result<PromotionLock> {
    crate::ontology::require_canary_schema(ctx).await?;
    let now = crate::now_millis();
    if ctx
        .get(&legacy_promotion_lock_id(product, target_channel))
        .await?
        .is_some()
    {
        bail!(
            "legacy promotion or policy update already in progress for {product}/{target_channel}"
        );
    }
    let lock = PromotionLock {
        id: promotion_lock_id(product, target_channel),
        owner: owner.into(),
    };
    let mut object = Object {
        id: lock.id.clone(),
        kind: KIND_PROMOTION_LOCK.into(),
        name: format!("{product}/{target_channel} promotion lock"),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([("owner".into(), RELEASED_PROMOTION_LOCK_OWNER.into())]),
        created: now,
        updated: now,
    };
    if ctx.get(&lock.id).await?.is_none() {
        match ctx.create_once(object.clone()).await {
            Ok(_) => {}
            Err(status)
                if status.code() == tonic::Code::AlreadyExists
                    || (status.code() == tonic::Code::Internal
                        && status.message().contains("UNIQUE")) => {}
            Err(status) => return Err(status.into()),
        }
    }
    match ctx.create_link_once(promotion_lock_link(&lock.id)).await {
        Ok(_) => {
            object.properties.insert("owner".into(), lock.owner.clone());
            object.updated = crate::now_millis();
            if let Err(error) = ctx.put(object).await {
                let _ = ctx
                    .unlink(&lock.id, &lock.id, REL_ACTIVE_PROMOTION_LOCK)
                    .await;
                return Err(error);
            }
            Ok(lock)
        }
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE")) =>
        {
            bail!("promotion or policy update already in progress for {product}/{target_channel}")
        }
        Err(status) => Err(status.into()),
    }
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

pub(crate) async fn confirm_promotion_lock(ctx: &mut Ctx, lock: &PromotionLock) -> Result<()> {
    let object = ctx
        .get(&lock.id)
        .await?
        .with_context(|| format!("promotion lock {} was lost", lock.id))?;
    if !ctx
        .links(&lock.id, REL_ACTIVE_PROMOTION_LOCK)
        .await?
        .iter()
        .any(|link| link.to_id == lock.id)
        || object.properties.get("owner") != Some(&lock.owner)
    {
        bail!(
            "promotion lock {} is no longer owned by this operation",
            lock.id
        );
    }
    Ok(())
}

pub async fn unlock_promotion(
    ctx: &mut Ctx,
    product: &str,
    target_channel: &str,
) -> Result<String> {
    validate_identifier("product", product)?;
    if target_channel != POLICY_DISCOVERY_LOCK_CHANNEL {
        validate_identifier("channel", target_channel)?;
    }
    let id = promotion_lock_id(product, target_channel);
    let active_link = promotion_lock_link(&id);
    if !ctx
        .links(&id, REL_ACTIVE_PROMOTION_LOCK)
        .await?
        .iter()
        .any(|link| link.id == active_link.id)
    {
        let legacy_id = legacy_promotion_lock_id(product, target_channel);
        if ctx.get(&legacy_id).await?.is_some() {
            ctx.delete(&legacy_id).await?;
            return Ok(format!(
                "legacy promotion lock removed for {product}/{target_channel}"
            ));
        }
        return Ok(format!(
            "no promotion lock exists for {product}/{target_channel}"
        ));
    }
    if let Some(mut object) = ctx.get(&id).await? {
        object
            .properties
            .insert("owner".into(), RELEASED_PROMOTION_LOCK_OWNER.into());
        object.updated = crate::now_millis();
        ctx.put(object).await?;
    }
    ctx.unlink(&id, &id, REL_ACTIVE_PROMOTION_LOCK).await?;
    Ok(format!(
        "promotion lock removed for {product}/{target_channel}"
    ))
}

pub(crate) async fn release_promotion_lock(ctx: &mut Ctx, lock: &PromotionLock) -> Result<()> {
    if let Some(object) = ctx.get(&lock.id).await?
        && object.properties.get("owner") == Some(&lock.owner)
    {
        let mut object = object;
        object
            .properties
            .insert("owner".into(), RELEASED_PROMOTION_LOCK_OWNER.into());
        object.updated = crate::now_millis();
        ctx.put(object).await?;
        ctx.unlink(&lock.id, &lock.id, REL_ACTIVE_PROMOTION_LOCK)
            .await?;
    }
    Ok(())
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

pub async fn set_designated(ctx: &mut Ctx, environment: &str, designated: bool) -> Result<String> {
    crate::ontology::require_canary_schema(ctx).await?;
    validate_identifier("environment", environment)?;
    let id = env_id(environment);
    let owner = format!("canary-designation:{}", crate::now_millis());
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
    spec: &str,
    target_channel: &str,
    cohort: Vec<String>,
    reactivate: bool,
) -> Result<ActiveCanaryPolicy> {
    let product = spec
        .split_once('@')
        .map(|(product, _)| product)
        .unwrap_or(spec);
    validate_identifier("product", product)?;
    validate_identifier("channel", target_channel)?;
    let owner = format!("policy:{spec}:{}", crate::now_millis());
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
    let result = configure_locked(ctx, spec, target_channel, cohort, reactivate, &target).await;
    let mut unlock_error = release_promotion_lock(ctx, &target).await.err();
    if let Err(error) = release_promotion_lock(ctx, &discovery).await {
        unlock_error.get_or_insert(error);
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
    lock: &PromotionLock,
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
    confirm_promotion_lock(ctx, lock).await?;
    ctx.create_once(object).await?;
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
    confirm_promotion_lock(ctx, lock).await?;
    ctx.put(pointer).await?;
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

async fn maybe_active_policy(
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
            Err(status)
                if status.code() == tonic::Code::AlreadyExists
                    || (status.code() == tonic::Code::Internal
                        && status.message().contains("UNIQUE")) => {}
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
    product: &str,
    version: &str,
    target_channel: &str,
) -> Result<Option<ActiveCanaryPolicy>> {
    let Some(active) = maybe_active_policy(ctx, product, version, target_channel).await? else {
        return Ok(None);
    };
    let evaluation = evaluate_active(ctx, &active).await?;
    record_promotion_audit(ctx, &active, &evaluation).await?;
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
    product: &str,
    version: &str,
    target_channel: &str,
    owner: &str,
    promote: F,
) -> Result<T>
where
    F: for<'a> FnOnce(&'a mut Ctx) -> Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>,
{
    let lock = claim_promotion_lock(ctx, product, target_channel, owner).await?;
    let result = async {
        let authorization = authorize_promotion(ctx, product, version, target_channel).await?;
        if let Some(expected) = authorization.as_ref() {
            confirm_policy_active(ctx, expected).await?;
        }
        confirm_promotion_lock(ctx, &lock).await?;
        promote(ctx).await
    }
    .await;
    let unlock = release_promotion_lock(ctx, &lock).await;
    match (result, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => {
            Err(error.context(format!("releasing promotion lock also failed: {unlock}")))
        }
        (Ok(_), Err(error)) => Err(error.context("releasing promotion lock failed")),
    }
}
