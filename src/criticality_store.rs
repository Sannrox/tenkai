//! Persist, sign, and import declared and derived criticality (#694).
//!
//! Types and property math live in [`crate::criticality`]. This module owns
//! the store writes and envelope signatures.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::client::{Ctx, LeaseError};
use crate::criticality::{
    CRITICALITY_TRUST_ROOTS_ENV, CriticalityLevel, CriticalityTargetKind, DECLARED_LEVEL,
    DECLARED_OWNER, DECLARED_REASON, DECLARED_SET_AT, DERIVED_GENERATED_AT, DERIVED_IMPORTED_AT,
    DERIVED_KEY_ID, DERIVED_LEVEL, DERIVED_MAX_AGE_MS, DERIVED_REASON, DERIVED_SCHEMA,
    DERIVED_SOURCE, DerivedAssignment, DerivedEnvelope, DerivedStatement, EffectiveCriticality,
    ReceivedEnvelope, SIGNING_DOMAIN, SetCriticalityRequest, VerifiedDerived,
    legacy_signed_message, parse_envelope, refuse_generated_after_issued,
    refuse_generated_in_the_future, require_owner_reason,
};
use crate::ontology::{env_id, product_id, validate_identifier};
use crate::pb::sekai::Object;
use crate::release_signing::TrustRoots;

const PRODUCT_MUTATION_LEASE_NAMESPACE: &str = "tenkai/product-mutation";
const PRODUCT_MUTATION_LEASE_MS: i64 = 60_000;

pub(crate) struct ProductMutationLease {
    product: String,
    fencing_token: String,
}

/// Inspect one environment's criticality.
pub async fn inspect_environment(ctx: &mut Ctx, environment: &str) -> Result<EffectiveCriticality> {
    let env = load_environment(ctx, environment).await?;
    crate::criticality::from_properties(&env.properties, crate::now_millis())
}

/// Inspect one product's criticality.
pub async fn inspect_product(ctx: &mut Ctx, product: &str) -> Result<EffectiveCriticality> {
    validate_identifier("product", product)?;
    let Some(object) = ctx.get(&product_id(product)).await? else {
        return Ok(EffectiveCriticality {
            effective: None,
            declared: None,
            derived: None,
        });
    };
    crate::criticality::from_properties(&object.properties, crate::now_millis())
}

/// Set declared criticality on an environment.
pub async fn set_environment(
    ctx: &mut Ctx,
    environment: &str,
    request: &SetCriticalityRequest,
) -> Result<String> {
    validate_identifier("environment", environment)?;
    require_owner_reason(&request.owner, &request.reason)?;
    let owner = format!("criticality-declared:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = set_environment_locked(ctx, environment, request, &lease).await;
    finish_environment_mutation(ctx, &lease, result).await
}

/// Clear declared criticality on an environment. Derived values stay.
pub async fn clear_environment(ctx: &mut Ctx, environment: &str) -> Result<String> {
    validate_identifier("environment", environment)?;
    let owner = format!("criticality-declared:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = clear_environment_locked(ctx, environment, &lease).await;
    finish_environment_mutation(ctx, &lease, result).await
}

/// Write declared criticality while the caller already holds the apply lease.
pub(crate) async fn set_environment_locked(
    ctx: &mut Ctx,
    environment: &str,
    request: &SetCriticalityRequest,
    lease: &crate::apply::EnvironmentLease,
) -> Result<String> {
    require_owner_reason(&request.owner, &request.reason)?;
    let mut object = load_environment(ctx, environment).await?;
    write_declared(&mut object, request, crate::now_millis());
    persist_environment(ctx, object, lease).await?;
    Ok(format!(
        "set {environment} criticality {}",
        request.level.as_str()
    ))
}

/// Clear declared criticality while the caller already holds the apply lease.
pub(crate) async fn clear_environment_locked(
    ctx: &mut Ctx,
    environment: &str,
    lease: &crate::apply::EnvironmentLease,
) -> Result<String> {
    let mut object = load_environment(ctx, environment).await?;
    clear_declared(&mut object);
    persist_environment(ctx, object, lease).await?;
    Ok(format!("cleared {environment} declared criticality"))
}

/// Set declared criticality on a catalog product.
pub async fn set_product(
    ctx: &mut Ctx,
    product: &str,
    request: &SetCriticalityRequest,
) -> Result<String> {
    validate_identifier("product", product)?;
    require_owner_reason(&request.owner, &request.reason)?;
    let lease = claim_product_mutation(ctx, product).await?;
    let result = async {
        let mut object = load_product(ctx, product).await?;
        write_declared(&mut object, request, crate::now_millis());
        persist_product(ctx, object, &lease).await?;
        Ok(format!(
            "set product {product} criticality {}",
            request.level.as_str()
        ))
    }
    .await;
    finish_product_mutation(ctx, &lease, result).await
}

/// Clear declared criticality on a catalog product. Derived values stay.
pub async fn clear_product(ctx: &mut Ctx, product: &str) -> Result<String> {
    validate_identifier("product", product)?;
    let lease = claim_product_mutation(ctx, product).await?;
    let result = async {
        let mut object = load_product(ctx, product).await?;
        clear_declared(&mut object);
        persist_product(ctx, object, &lease).await?;
        Ok(format!("cleared product {product} declared criticality"))
    }
    .await;
    finish_product_mutation(ctx, &lease, result).await
}

/// Effective criticality for a plan or wave: max of the environment and named products.
pub async fn effective_for_targets(
    ctx: &mut Ctx,
    environment: &str,
    products: &[String],
) -> Result<Option<CriticalityLevel>> {
    let now = crate::now_millis();
    let env = load_environment(ctx, environment).await?;
    let mut effective = crate::criticality::effective_level(&env.properties, now)?;
    let mut seen = BTreeSet::new();
    for product in products {
        if product.trim().is_empty() || !seen.insert(product.as_str()) {
            continue;
        }
        let product_level = match ctx.get(&product_id(product)).await? {
            Some(object) => crate::criticality::effective_level(&object.properties, now)?,
            None => None,
        };
        effective = crate::criticality::higher(effective, product_level);
    }
    Ok(effective)
}

async fn load_environment(ctx: &mut Ctx, environment: &str) -> Result<Object> {
    validate_identifier("environment", environment)?;
    ctx.get(&env_id(environment)).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "environment {environment} is not registered (tenkaictl env add {environment})"
        )
    })
}

async fn load_product(ctx: &mut Ctx, product: &str) -> Result<Object> {
    ctx.get(&product_id(product))
        .await?
        .ok_or_else(|| anyhow::anyhow!("product {product} is not in the catalog"))
}

fn write_declared(object: &mut Object, request: &SetCriticalityRequest, now: i64) {
    object
        .properties
        .insert(DECLARED_LEVEL.into(), request.level.as_str().into());
    object
        .properties
        .insert(DECLARED_OWNER.into(), request.owner.trim().into());
    object
        .properties
        .insert(DECLARED_REASON.into(), request.reason.trim().into());
    object
        .properties
        .insert(DECLARED_SET_AT.into(), now.to_string());
    object.updated = now;
}

fn clear_declared(object: &mut Object) {
    for key in [
        DECLARED_LEVEL,
        DECLARED_OWNER,
        DECLARED_REASON,
        DECLARED_SET_AT,
    ] {
        object.properties.remove(key);
    }
    object.updated = crate::now_millis();
}

fn write_derived(
    object: &mut Object,
    assignment: &DerivedAssignment,
    generated_at: i64,
    imported_at: i64,
    max_age_ms: i64,
    key_id: &str,
) {
    object
        .properties
        .insert(DERIVED_LEVEL.into(), assignment.level.as_str().into());
    object
        .properties
        .insert(DERIVED_SOURCE.into(), assignment.source.clone());
    object
        .properties
        .insert(DERIVED_REASON.into(), assignment.reason.clone());
    object
        .properties
        .insert(DERIVED_GENERATED_AT.into(), generated_at.to_string());
    object
        .properties
        .insert(DERIVED_IMPORTED_AT.into(), imported_at.to_string());
    object
        .properties
        .insert(DERIVED_MAX_AGE_MS.into(), max_age_ms.to_string());
    object
        .properties
        .insert(DERIVED_KEY_ID.into(), key_id.into());
    object.updated = imported_at;
}

/// Sign a derived-criticality statement with `signer`: serialize it once
/// and sign those bytes.
pub fn sign(
    statement: &DerivedStatement,
    signer: &dyn crate::signer::ContentSigner,
) -> Result<DerivedEnvelope> {
    statement.validate()?;
    let signed = crate::signed_bytes::sign(SIGNING_DOMAIN, statement, |message| {
        Ok(signer.sign(message)?.to_vec())
    })?;
    Ok(DerivedEnvelope {
        schema: DERIVED_SCHEMA.into(),
        key_id: signer.key_id().to_string(),
        statement: signed.statement,
        signature: STANDARD.encode(signed.signature),
    })
}

/// Check the signature against the criticality authorities, then parse and
/// validate the statement. A v2 statement is parsed only from the bytes the
/// signature covers.
pub fn verify_envelope(
    envelope: &ReceivedEnvelope,
    authorities: &TrustRoots,
) -> Result<VerifiedDerived> {
    const LABEL: &str = "derived criticality signature";
    let signer = authorities.resolve(envelope.key_id())?;
    let statement = match envelope {
        ReceivedEnvelope::Current(envelope) => {
            let signature =
                crate::signature_verification::decode_exact::<64>(LABEL, &envelope.signature)?;
            let verified = crate::signed_bytes::verify::<DerivedStatement>(
                SIGNING_DOMAIN,
                &envelope.statement,
                |message| {
                    crate::signature_verification::verify_strict_bytes(
                        &signer.verifying_key,
                        LABEL,
                        &signature,
                        message,
                    )
                    .is_ok()
                },
            )
            .map_err(|refusal| anyhow::anyhow!("derived criticality refused: {refusal}"))?;
            verified.statement.validate()?;
            verified.statement
        }
        ReceivedEnvelope::Legacy(envelope) => {
            crate::signature_verification::verify_strict(
                &signer.verifying_key,
                LABEL,
                &envelope.signature,
                &legacy_signed_message(&envelope.statement)?,
            )?;
            let statement = DerivedStatement::from(envelope.statement.clone());
            statement.validate()?;
            statement
        }
    };
    Ok(VerifiedDerived {
        key_id: envelope.key_id().into(),
        statement,
    })
}

/// Trust roots configured for derived criticality, if any.
pub fn configured_trust_roots() -> Result<Option<TrustRoots>> {
    let Some(path) = std::env::var_os(CRITICALITY_TRUST_ROOTS_ENV).map(std::path::PathBuf::from)
    else {
        return Ok(None);
    };
    Ok(Some(TrustRoots::load(
        &path,
        crate::signature_verification::TrustRootKind::Release,
    )?))
}

/// Verify `criticality/derived.json` from a verified bundle and check it
/// against the bundle's issued-at and bound environment.
fn verify_bundle_payload(
    bytes: &[u8],
    issued_at: i64,
    bound_environment: &str,
) -> Result<VerifiedDerived> {
    let envelope = parse_envelope(bytes)?;
    let Some(roots) = configured_trust_roots()? else {
        bail!(
            "offline bundle carries derived criticality, but {CRITICALITY_TRUST_ROOTS_ENV} is not set"
        );
    };
    let verified = verify_envelope(&envelope, &roots)?;
    refuse_generated_after_issued(verified.statement.generated_at, issued_at)?;
    refuse_bundle_scope(&verified.statement, bound_environment)?;
    Ok(verified)
}

/// Check `criticality/derived.json` before any catalog mutation.
pub fn preflight_derived_payload(
    bytes: &[u8],
    issued_at: i64,
    bound_environment: &str,
) -> Result<()> {
    verify_bundle_payload(bytes, issued_at, bound_environment).map(|_| ())
}

/// Import `criticality/derived.json` from a verified bundle payload.
pub async fn import_derived_payload(
    ctx: &mut Ctx,
    bytes: &[u8],
    issued_at: i64,
    bound_environment: &str,
) -> Result<usize> {
    let verified = verify_bundle_payload(bytes, issued_at, bound_environment)?;
    apply_verified(ctx, &verified, crate::now_millis()).await
}

/// A bundle bound to one environment may only assign that environment.
pub(crate) fn refuse_bundle_scope(
    statement: &DerivedStatement,
    bound_environment: &str,
) -> Result<()> {
    for assignment in &statement.assignments {
        match assignment.kind {
            CriticalityTargetKind::Environment if assignment.name == bound_environment => {}
            CriticalityTargetKind::Environment => bail!(
                "offline bundle for {bound_environment} cannot assign environment {}",
                assignment.name
            ),
            CriticalityTargetKind::Product => bail!(
                "offline bundle for {bound_environment} cannot assign product {}; import product derived criticality with fleet management",
                assignment.name
            ),
        }
    }
    Ok(())
}

/// Verify and apply a signed derived envelope. A bad signature changes nothing.
pub async fn import_envelope(
    ctx: &mut Ctx,
    envelope: &ReceivedEnvelope,
    authorities: &TrustRoots,
    now: i64,
) -> Result<usize> {
    let verified = verify_envelope(envelope, authorities)?;
    apply_verified(ctx, &verified, now).await
}

/// Apply a verified statement, newest generation wins per target.
pub async fn apply_verified(ctx: &mut Ctx, verified: &VerifiedDerived, now: i64) -> Result<usize> {
    refuse_generated_in_the_future(verified.statement.generated_at, now)?;
    apply_assignments(ctx, verified, now).await
}

async fn apply_assignments(ctx: &mut Ctx, verified: &VerifiedDerived, now: i64) -> Result<usize> {
    let mut applied = 0usize;
    for assignment in &verified.statement.assignments {
        let wrote = match assignment.kind {
            CriticalityTargetKind::Environment => {
                apply_environment_assignment(ctx, verified, assignment, now).await?
            }
            CriticalityTargetKind::Product => {
                apply_product_assignment(ctx, verified, assignment, now).await?
            }
        };
        if wrote {
            applied += 1;
        }
    }
    Ok(applied)
}

async fn apply_product_assignment(
    ctx: &mut Ctx,
    verified: &VerifiedDerived,
    assignment: &DerivedAssignment,
    now: i64,
) -> Result<bool> {
    let lease = claim_product_mutation(ctx, &assignment.name).await?;
    let result = async {
        let mut object = load_product(ctx, &assignment.name).await?;
        let wrote = apply_derived_if_newer(
            &mut object,
            assignment,
            verified.statement.generated_at,
            now,
            verified.statement.max_age_ms,
            &verified.key_id,
        )?;
        if wrote {
            persist_product(ctx, object, &lease).await?;
        }
        Ok(wrote)
    }
    .await;
    finish_product_mutation(ctx, &lease, result).await
}

pub(crate) async fn claim_product_mutation(
    ctx: &mut Ctx,
    product: &str,
) -> Result<ProductMutationLease> {
    validate_identifier("product", product)?;
    let owner = format!("product-mutation:{product}:{}", crate::now_millis());
    match ctx
        .acquire_lease(
            PRODUCT_MUTATION_LEASE_NAMESPACE,
            product,
            &owner,
            PRODUCT_MUTATION_LEASE_MS,
        )
        .await
    {
        Ok(lease) => Ok(ProductMutationLease {
            product: product.into(),
            fencing_token: lease.fencing_token,
        }),
        Err(LeaseError::AlreadyExists) => {
            bail!("product {product} is already being mutated; retry after that lease expires")
        }
        Err(LeaseError::Failed(error)) => {
            Err(error).context(format!("claiming the product mutation lease for {product}"))
        }
    }
}

async fn release_product_mutation(ctx: &mut Ctx, lease: &ProductMutationLease) -> Result<()> {
    ctx.release_lease(
        PRODUCT_MUTATION_LEASE_NAMESPACE,
        &lease.product,
        &lease.fencing_token,
    )
    .await
    .map(|_| ())
    .with_context(|| {
        format!(
            "releasing the product mutation lease for {} failed",
            lease.product
        )
    })
}

pub(crate) async fn finish_product_mutation<T>(
    ctx: &mut Ctx,
    lease: &ProductMutationLease,
    result: Result<T>,
) -> Result<T> {
    match (result, release_product_mutation(ctx, lease).await) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("releasing the product mutation lease")),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing the product mutation lease also failed: {unlock}"
        ))),
    }
}

async fn apply_environment_assignment(
    ctx: &mut Ctx,
    verified: &VerifiedDerived,
    assignment: &DerivedAssignment,
    now: i64,
) -> Result<bool> {
    let owner = format!("criticality-derived:{now}");
    let lease = crate::apply::claim_environment(ctx, &assignment.name, &owner).await?;
    let result = async {
        let mut object = load_environment(ctx, &assignment.name).await?;
        let wrote = apply_derived_if_newer(
            &mut object,
            assignment,
            verified.statement.generated_at,
            now,
            verified.statement.max_age_ms,
            &verified.key_id,
        )?;
        if wrote {
            persist_environment(ctx, object, &lease).await?;
        }
        Ok(wrote)
    }
    .await;
    finish_environment_mutation(ctx, &lease, result).await
}

async fn persist_environment(
    ctx: &mut Ctx,
    object: Object,
    lease: &crate::apply::EnvironmentLease,
) -> Result<()> {
    ctx.guarded_update(
        object,
        crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

async fn persist_product(
    ctx: &mut Ctx,
    object: Object,
    lease: &ProductMutationLease,
) -> Result<()> {
    persist_product_object(ctx, object, lease, false).await
}

pub(crate) async fn persist_product_object(
    ctx: &mut Ctx,
    object: Object,
    lease: &ProductMutationLease,
    create: bool,
) -> Result<()> {
    if create {
        ctx.guarded_create(
            object,
            PRODUCT_MUTATION_LEASE_NAMESPACE,
            &lease.product,
            &lease.fencing_token,
        )
        .await?;
    } else {
        ctx.guarded_update(
            object,
            PRODUCT_MUTATION_LEASE_NAMESPACE,
            &lease.product,
            &lease.fencing_token,
        )
        .await?;
    }
    Ok(())
}

async fn finish_environment_mutation<T>(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    result: Result<T>,
) -> Result<T> {
    match (result, crate::apply::release_environment(ctx, lease).await) {
        (Ok(wrote), Ok(())) => Ok(wrote),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("releasing the environment criticality lease")),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing the environment criticality lease also failed: {unlock}"
        ))),
    }
}

fn apply_derived_if_newer(
    object: &mut Object,
    assignment: &DerivedAssignment,
    generated_at: i64,
    imported_at: i64,
    max_age_ms: i64,
    key_id: &str,
) -> Result<bool> {
    if let Some(existing) = object
        .properties
        .get(DERIVED_GENERATED_AT)
        .and_then(|value| value.parse::<i64>().ok())
    {
        if generated_at < existing {
            return Ok(false);
        }
        if generated_at == existing {
            let same = object.properties.get(DERIVED_LEVEL).map(String::as_str)
                == Some(assignment.level.as_str())
                && object.properties.get(DERIVED_SOURCE).map(String::as_str)
                    == Some(assignment.source.as_str());
            if !same {
                bail!(
                    "derived criticality generation {generated_at} already assigned with a different value"
                );
            }
            return Ok(false);
        }
    }
    write_derived(
        object,
        assignment,
        generated_at,
        imported_at,
        max_age_ms,
        key_id,
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::criticality::{CriticalityLevel, CriticalityTargetKind, DerivedAssignment};
    use crate::ontology::{KIND_ENVIRONMENT, NS};
    use crate::release_signing::TrustedSigner;
    use ed25519_dalek::Signer as _;
    use ed25519_dalek::SigningKey;
    use std::path::Path;

    const AUTHORITY: [u8; 32] = [211; 32];

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-criticality-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn seed_file(dir: &Path, seed: &[u8; 32]) -> std::path::PathBuf {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let path = dir.join(format!("{}.ed25519", seed[0]));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(seed).unwrap();
        path
    }

    fn signer(seed: &[u8; 32], identity: &str) -> TrustedSigner {
        let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        TrustedSigner::new(
            crate::signature_verification::key_id(&public),
            identity,
            STANDARD.encode(public),
        )
    }

    fn roots(signers: Vec<TrustedSigner>) -> TrustRoots {
        TrustRoots {
            version: 1,
            signers,
        }
    }

    async fn seeded_env(root: &Path, name: &str) -> Ctx {
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        ctx.put(Object {
            id: env_id(name),
            kind: KIND_ENVIRONMENT.into(),
            name: name.into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([(
                "description".into(),
                "production".into(),
            )]),
            created: 1,
            updated: 1,
        })
        .await
        .unwrap();
        ctx
    }

    fn statement(level: CriticalityLevel) -> DerivedStatement {
        DerivedStatement {
            generated_at: crate::now_millis(),
            max_age_ms: 86_400_000,
            assignments: vec![DerivedAssignment {
                kind: CriticalityTargetKind::Environment,
                name: "prod".into(),
                level,
                source: "governance-catalog".into(),
                reason: "reaches marked data".into(),
            }],
        }
    }

    #[tokio::test]
    async fn set_and_clear_declared_on_environment() {
        let root = temp_dir("set-clear");
        let mut ctx = seeded_env(&root, "prod").await;
        set_environment(
            &mut ctx,
            "prod",
            &SetCriticalityRequest {
                level: CriticalityLevel::Critical,
                owner: "alice".into(),
                reason: "pci".into(),
            },
        )
        .await
        .unwrap();
        let view = inspect_environment(&mut ctx, "prod").await.unwrap();
        assert_eq!(view.effective, Some(CriticalityLevel::Critical));
        assert_eq!(view.declared.as_ref().unwrap().owner, "alice");
        clear_environment(&mut ctx, "prod").await.unwrap();
        let view = inspect_environment(&mut ctx, "prod").await.unwrap();
        assert!(view.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    fn current(envelope: DerivedEnvelope) -> ReceivedEnvelope {
        ReceivedEnvelope::Current(envelope)
    }

    /// An envelope over `bytes` exactly as given, as a non-Rust producer would sign it.
    fn sign_bytes(seed: &[u8; 32], bytes: &[u8]) -> ReceivedEnvelope {
        let key = SigningKey::from_bytes(seed);
        let envelope = serde_json::json!({
            "schema": DERIVED_SCHEMA,
            "key_id": crate::signature_verification::key_id(&key.verifying_key().to_bytes()),
            "statement": STANDARD.encode(bytes),
            "signature": STANDARD.encode(key.sign(&[SIGNING_DOMAIN, bytes].concat()).to_bytes()),
        });
        parse_envelope(&serde_json::to_vec(&envelope).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn derived_import_refuses_a_bad_signature_without_writes() {
        let root = temp_dir("bad-sig");
        let seed = seed_file(&root, &AUTHORITY);
        let mut envelope = sign(
            &statement(CriticalityLevel::Critical),
            &crate::signer::FileSigner::open(&seed).unwrap(),
        )
        .unwrap();
        envelope.signature = STANDARD.encode([0u8; 64]);
        let mut ctx = seeded_env(&root, "prod").await;
        set_environment(
            &mut ctx,
            "prod",
            &SetCriticalityRequest {
                level: CriticalityLevel::High,
                owner: "alice".into(),
                reason: "pci".into(),
            },
        )
        .await
        .unwrap();
        let authorities = roots(vec![signer(&AUTHORITY, "governance")]);
        let error = import_envelope(
            &mut ctx,
            &current(envelope),
            &authorities,
            1_700_000_000_050,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("signature"), "{error}");
        let view = inspect_environment(&mut ctx, "prod").await.unwrap();
        assert_eq!(view.effective, Some(CriticalityLevel::High));
        assert!(view.derived.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn derived_import_applies_a_verified_envelope() {
        let root = temp_dir("good-sig");
        let seed = seed_file(&root, &AUTHORITY);
        let first = statement(CriticalityLevel::Critical);
        let envelope = sign(&first, &crate::signer::FileSigner::open(&seed).unwrap()).unwrap();
        let mut ctx = seeded_env(&root, "prod").await;
        let authorities = roots(vec![signer(&AUTHORITY, "governance")]);
        import_envelope(
            &mut ctx,
            &current(envelope),
            &authorities,
            crate::now_millis(),
        )
        .await
        .unwrap();
        let view = inspect_environment(&mut ctx, "prod").await.unwrap();
        assert_eq!(view.effective, Some(CriticalityLevel::Critical));
        assert_eq!(view.derived.as_ref().unwrap().source, "governance-catalog");
        let mut older = statement(CriticalityLevel::Low);
        older.generated_at = first.generated_at - 1;
        let older = sign(&older, &crate::signer::FileSigner::open(&seed).unwrap()).unwrap();
        import_envelope(&mut ctx, &current(older), &authorities, crate::now_millis())
            .await
            .unwrap();
        let view = inspect_environment(&mut ctx, "prod").await.unwrap();
        assert_eq!(view.effective, Some(CriticalityLevel::Critical));
        let _ = std::fs::remove_dir_all(root);
    }

    /// A producer signs its own bytes: any key order and spacing, no
    /// `reason`, and a field this release does not know. The signature
    /// covers those bytes, so the same statement re-encoded no longer
    /// verifies with it.
    #[test]
    fn the_signature_covers_the_statement_bytes_the_producer_sent() {
        let bytes = br#"{ "assignments": [ { "source": "risk-feed", "level": "high",
            "name": "prod", "kind": "environment", "expires_at": 1 } ],
            "max_age_ms": 60000, "generated_at": 1700000000000, "note": "x" }"#;
        let authorities = roots(vec![signer(&AUTHORITY, "governance")]);
        let sent = sign_bytes(&AUTHORITY, bytes);
        let verified = verify_envelope(&sent, &authorities).unwrap();
        let assignment = &verified.statement.assignments[0];
        assert_eq!(assignment.level, CriticalityLevel::High);
        assert_eq!(assignment.reason, "");
        assert_eq!(verified.key_id, sent.key_id());

        let ReceivedEnvelope::Current(mut reencoded) = sent else {
            panic!("expected a current envelope");
        };
        reencoded.statement = STANDARD.encode(serde_json::to_vec(&verified.statement).unwrap());
        let error = verify_envelope(&current(reencoded), &authorities)
            .unwrap_err()
            .to_string();
        assert!(error.contains("signature does not verify"), "{error}");
    }

    /// Bytes that verify are still validated before anything is applied.
    #[test]
    fn verified_bytes_that_are_not_a_valid_statement_are_refused() {
        let authorities = roots(vec![signer(&AUTHORITY, "governance")]);
        for (bytes, expected) in [
            (&b"not json"[..], "does not parse"),
            (
                br#"{"generated_at":1,"generated_at":2,"max_age_ms":1,"assignments":[]}"#,
                "duplicate field",
            ),
            (
                br#"{"generated_at":1,"max_age_ms":1,"assignments":[]}"#,
                "at least one assignment",
            ),
        ] {
            let error = verify_envelope(&sign_bytes(&AUTHORITY, bytes), &authorities)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    /// Envelopes made before #866 still verify during the upgrade window, by
    /// their frozen re-encoding, and refuse fields the signature cannot cover.
    #[test]
    fn a_legacy_v1_envelope_verifies_and_stays_strict() {
        let key = SigningKey::from_bytes(&AUTHORITY);
        let legacy = crate::criticality::LegacyStatement {
            generated_at: 1_700_000_000_000,
            max_age_ms: 60_000,
            assignments: vec![crate::criticality::LegacyAssignment {
                kind: CriticalityTargetKind::Environment,
                name: "prod".into(),
                level: CriticalityLevel::Critical,
                source: "governance-catalog".into(),
                reason: String::new(),
            }],
        };
        let message = legacy_signed_message(&legacy).unwrap();
        let mut document = serde_json::json!({
            "schema": crate::criticality::LEGACY_DERIVED_SCHEMA,
            "key_id": crate::signature_verification::key_id(&key.verifying_key().to_bytes()),
            "statement": legacy,
            "signature": STANDARD.encode(key.sign(&message).to_bytes()),
        });
        let authorities = roots(vec![signer(&AUTHORITY, "governance")]);
        let envelope = parse_envelope(&serde_json::to_vec(&document).unwrap()).unwrap();
        let verified = verify_envelope(&envelope, &authorities).unwrap();
        assert_eq!(verified.statement, DerivedStatement::from(legacy.clone()));

        document["statement"]["note"] = "unsigned".into();
        let error = parse_envelope(&serde_json::to_vec(&document).unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("envelope is not valid"), "{error}");
    }

    #[test]
    fn an_unknown_schema_is_refused_by_name() {
        let error = parse_envelope(br#"{"schema":"tenkai.derived-criticality.v3"}"#)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unsupported derived criticality schema")
                && error.contains(DERIVED_SCHEMA),
            "{error}"
        );
    }

    #[tokio::test]
    async fn derived_import_refuses_a_future_generation() {
        let root = temp_dir("future-gen");
        let seed = seed_file(&root, &AUTHORITY);
        let now = crate::now_millis();
        let mut future = statement(CriticalityLevel::Low);
        future.generated_at = now + 86_400_000;
        let envelope = sign(&future, &crate::signer::FileSigner::open(&seed).unwrap()).unwrap();
        let mut ctx = seeded_env(&root, "prod").await;
        let authorities = roots(vec![signer(&AUTHORITY, "governance")]);
        let error = import_envelope(&mut ctx, &current(envelope), &authorities, now)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("after import clock"), "{error}");
        let view = inspect_environment(&mut ctx, "prod").await.unwrap();
        assert!(view.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn bundle_scope_refuses_other_environments_and_products() {
        refuse_bundle_scope(&statement(CriticalityLevel::High), "prod").unwrap();
        let mut other_env = statement(CriticalityLevel::High);
        other_env.assignments[0].name = "lab".into();
        let error = refuse_bundle_scope(&other_env, "prod")
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot assign environment lab"), "{error}");
        let mut product = statement(CriticalityLevel::High);
        product.assignments[0].kind = CriticalityTargetKind::Product;
        product.assignments[0].name = "api".into();
        let error = refuse_bundle_scope(&product, "prod")
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot assign product api"), "{error}");
    }
}
