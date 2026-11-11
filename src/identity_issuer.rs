//! The environment's workload identity issuer (ADR 0046 §2).
//!
//! Each environment has at most one issuing key. Its private half exists
//! unsealed only inside the environment's runtimes; the server stores the
//! issuer's CA certificate and the key sealed to recipient keys, exactly
//! like a sealed value (ADR 0045 §1).
//!
//! Creating or rotating the issuer has two phases:
//!
//! 1. `prepare` records a request for the next generation. A runtime that
//!    names the `workload_identity` capability generates a candidate key,
//!    seals it to its own sealing key only, and uploads the fingerprint,
//!    certificate and sealed key. It never seals to a key the server names:
//!    a server that listed its own key would read the issuer. The first
//!    candidate for a generation is kept; a retry after a crash gets the
//!    same answer.
//! 2. A plan step carries the candidate, so the plan digest and its
//!    approval cover the exact fingerprint. The runtime that claims the step
//!    verifies the plan itself (ADR 0045 §4), opens the key, and refuses it
//!    unless its public half has the approved fingerprint. The server then
//!    records the issuer with a compare-and-set on the previous generation.
//!
//! Rotating an issuer that already exists (ADR 0046 §7) takes approved
//! steps, so no valid peer ever fails: **add** records the activated key
//! as the next issuer, which every trust bundle then carries beside the
//! current one, and **issue** makes it the current issuer, keeping the old
//! one as the previous issuer in the bundles. Each records with a
//! compare-and-set on the generations, so a replay changes nothing.
//!
//! A key the server substitutes is therefore useless: it cannot get its
//! fingerprint approved without the approvers' keys. Every other runtime,
//! and the recovery key, receives the issuer only through an approved
//! re-wrap step, whose approval names the recipient (ADR 0045 §5).

use anyhow::{Context as _, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::pb::sekai::Object;
use crate::sealed_secret::{RecipientWrap, SealedOpener, SealedTarget, SealedValue};
use crate::sealing_key::SealingPublicKey;

/// Environment property with the recorded issuer, as [`IssuerKey`] JSON.
/// None of these properties start with `sealed.`, so instance scans skip
/// them.
const ISSUER_PROPERTY: &str = "identity_issuer";
/// Environment property with the uploaded candidate for the requested
/// generation.
const CANDIDATE_PROPERTY: &str = "identity_issuer_candidate";
/// Environment property with the generation `prepare` asked a candidate for.
const REQUEST_PROPERTY: &str = "identity_issuer_request";
/// Environment property with the next issuer an add step recorded: trusted
/// in every bundle, not issuing yet.
const NEXT_PROPERTY: &str = "identity_issuer_next";
/// Environment property with the issuer an issue step replaced: still
/// trusted in every bundle, no longer issuing.
const PREVIOUS_PROPERTY: &str = "identity_issuer_previous";
/// Environment property with the id of the plan whose add step recorded
/// the next issuer: its approvals prove the next issuer to every runtime.
const NEXT_PLAN_PROPERTY: &str = "identity_issuer_next_plan";
/// Environment property with the id of the plan whose issue step replaced
/// the previous issuer: its approvals prove the previous issuer to a
/// runtime that joins later, and the current one to a runtime that missed
/// the promotion. Kept after the remove step, until the next issue step.
const PREVIOUS_PLAN_PROPERTY: &str = "identity_issuer_previous_plan";
/// Environment property with the id of the plan whose remove step stopped
/// trusting the previous issuer: its approvals tell every runtime to drop
/// it from its bundles. Kept until the next issue step.
const REMOVED_PLAN_PROPERTY: &str = "identity_issuer_removed_plan";

/// Which rotation step an issuer activation is (ADR 0046 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationPhase {
    /// Record the key as the next issuer, trusted beside the current one.
    Add,
    /// Make the next issuer the current one; the current one stays trusted
    /// as the previous issuer.
    Issue,
    /// Stop trusting the previous issuer, once no certificate it signed is
    /// live: no bundle carries it any more.
    Remove,
}

/// How long an issuer certificate is valid. The issuer is replaced by an
/// approved rotation, not by expiry; the bound only keeps a forgotten key
/// from being trusted forever.
const ISSUER_CERTIFICATE_TTL_SECS: i64 = 10 * 365 * 24 * 60 * 60;

/// Sealed-value slot of the issuer key in a re-wrap receipt. The issuer is
/// environment-level, so its re-wrap step names no instance.
pub const WRAP_SECRET: &str = "identity-issuer";

/// An issuing key: its CA certificate, the fingerprint of its public key,
/// and the private key sealed to the environment's recipients. The same
/// shape is the uploaded candidate, the approved step, and the recorded
/// issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IssuerKey {
    /// 1 for the first issuer, then one more per rotation.
    pub generation: u64,
    /// `sha256:<hex>` of the issuer's DER SubjectPublicKeyInfo.
    pub fingerprint: String,
    /// The self-signed CA certificate, PEM.
    pub certificate: String,
    /// The PKCS#8 DER private key, sealed for
    /// [`SealedTarget::identity_issuer`].
    pub sealed_key: SealedValue,
}

/// The generation a runtime generates a candidate for. Sent on runtime work
/// only to runtimes that name the `workload_identity` capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRequest {
    pub generation: u64,
}

/// The issuer as `env inspect` and `status` show it. Never a key. A view:
/// clients ignore fields they do not know (#1172).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IssuerSummary {
    pub generation: u64,
    pub fingerprint: String,
    /// Recipients the key is wrapped for; empty means it is lost.
    pub recipients: Vec<String>,
}

impl From<&IssuerKey> for IssuerSummary {
    fn from(key: &IssuerKey) -> Self {
        Self {
            generation: key.generation,
            fingerprint: key.fingerprint.clone(),
            recipients: key
                .sealed_key
                .wraps
                .iter()
                .map(|wrap| wrap.fingerprint.clone())
                .collect(),
        }
    }
}

/// The issuer state of an environment for inspection. A view: clients
/// ignore fields they do not know (#1172).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IssuerStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<IssuerSummary>,
    /// The generation `prepare` asked a candidate for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<u64>,
    /// The uploaded candidate, waiting for an approved step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<IssuerSummary>,
    /// The next issuer an add step recorded, waiting for the issue step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<IssuerSummary>,
    /// The issuer the last issue step replaced, still trusted until its
    /// remove step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<IssuerSummary>,
}

impl IssuerStatus {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl IssuerKey {
    /// The slot a re-wrap receipt names for this key.
    pub fn wrap_key(&self) -> String {
        format!("generation-{}", self.generation)
    }

    /// Digest of the sealed key, as a re-wrap receipt names it.
    pub fn digest(&self, environment: &str) -> Result<String> {
        crate::sealed_secret::digest(
            &SealedTarget::identity_issuer(environment, self.generation)?,
            &self.sealed_key,
        )
    }

    /// Refuse a key whose public parts do not hang together: the
    /// certificate must be a self-signed CA over the key the fingerprint
    /// names, and the sealed key well formed. Needs no private key, so the
    /// server checks this on upload and the runtime again before opening.
    pub fn check_public(&self) -> Result<()> {
        use x509_parser::prelude::*;
        ensure!(self.generation >= 1, "issuer generations start at 1");
        crate::sealing_key::normalize_fingerprint(&self.fingerprint)
            .ok()
            .filter(|normalized| normalized == &self.fingerprint)
            .context("the issuer fingerprint must be sha256:<64 lowercase hex>")?;
        crate::sealed_secret::check_form(&self.sealed_key)?;
        let (_, pem) = parse_x509_pem(self.certificate.as_bytes())
            .map_err(|error| anyhow::anyhow!("reading the issuer certificate: {error}"))?;
        let certificate = pem
            .parse_x509()
            .map_err(|error| anyhow::anyhow!("parsing the issuer certificate: {error}"))?;
        ensure!(
            certificate.is_ca(),
            "the issuer certificate is not a CA certificate"
        );
        certificate.verify_signature(None).map_err(|error| {
            anyhow::anyhow!("the issuer certificate is not self-signed: {error}")
        })?;
        ensure!(
            spki_fingerprint(certificate.public_key().raw) == self.fingerprint,
            "the issuer certificate does not carry the key {}",
            self.fingerprint
        );
        Ok(())
    }

    /// Open the issuing key with this runtime's `opener` and refuse it
    /// unless its public half is the one the fingerprint names. Errors name
    /// the generation and fingerprint, never the key.
    pub fn open(&self, environment: &str, opener: &SealedOpener) -> Result<rcgen::KeyPair> {
        self.check_public()?;
        let target = SealedTarget::identity_issuer(environment, self.generation)?;
        let der = opener.open(&target, &self.sealed_key).with_context(|| {
            format!(
                "opening the issuer key of generation {} with {}",
                self.generation,
                opener.fingerprint()
            )
        })?;
        let key = rcgen::KeyPair::try_from(der.as_slice())
            .map_err(|_| anyhow::anyhow!("the sealed issuer key is not a PKCS#8 private key"))?;
        let actual = spki_fingerprint(&rcgen::PublicKeyData::subject_public_key_info(&key));
        ensure!(
            actual == self.fingerprint,
            "the sealed issuer key is {actual}, not the approved {}",
            self.fingerprint
        );
        Ok(key)
    }
}

/// `sha256:<hex>` of a DER SubjectPublicKeyInfo.
fn spki_fingerprint(spki: &[u8]) -> String {
    crate::sealing_key::fingerprint(spki)
}

/// Generate a candidate issuing key for `generation`, sealed to
/// `recipient` only: the generating runtime's own key. Runs in a runtime:
/// the private key leaves it only sealed.
pub fn generate(
    environment: &str,
    generation: u64,
    recipient: &SealingPublicKey,
    now_secs: i64,
) -> Result<IssuerKey> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("tenkai identity issuer {environment} {generation}"),
    );
    params.not_before = time::OffsetDateTime::from_unix_timestamp(now_secs - 60)?;
    params.not_after =
        time::OffsetDateTime::from_unix_timestamp(now_secs + ISSUER_CERTIFICATE_TTL_SECS)?;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(
        &uuid::Uuid::new_v4().into_bytes(),
    ));
    let certificate = params.self_signed(&key)?;
    let der = zeroize::Zeroizing::new(key.serialize_der());
    let sealed_key = crate::sealed_secret::seal(
        &SealedTarget::identity_issuer(environment, generation)?,
        &der,
        std::slice::from_ref(recipient),
    )?;
    Ok(IssuerKey {
        generation,
        fingerprint: spki_fingerprint(&rcgen::PublicKeyData::subject_public_key_info(&key)),
        certificate: certificate.pem(),
        sealed_key,
    })
}

fn read(env_obj: &Object, property: &str) -> Result<Option<IssuerKey>> {
    env_obj
        .properties
        .get(property)
        .map(|raw| serde_json::from_str(raw))
        .transpose()
        .with_context(|| format!("the stored {property} is not valid"))
}

fn write(env_obj: &mut Object, property: &str, key: &IssuerKey) {
    env_obj.properties.insert(
        property.into(),
        serde_json::to_string(key).expect("issuer keys are JSON-serializable"),
    );
}

/// The recorded issuer.
pub fn current(env_obj: &Object) -> Result<Option<IssuerKey>> {
    read(env_obj, ISSUER_PROPERTY)
}

/// The uploaded candidate.
pub fn candidate(env_obj: &Object) -> Result<Option<IssuerKey>> {
    read(env_obj, CANDIDATE_PROPERTY)
}

/// The next issuer an add step recorded.
pub fn next(env_obj: &Object) -> Result<Option<IssuerKey>> {
    read(env_obj, NEXT_PROPERTY)
}

/// The id of the plan whose add step recorded the next issuer.
pub fn next_plan(env_obj: &Object) -> Option<&str> {
    env_obj
        .properties
        .get(NEXT_PLAN_PROPERTY)
        .map(String::as_str)
}

/// The id of the plan whose issue step replaced the previous issuer.
pub fn previous_plan(env_obj: &Object) -> Option<&str> {
    env_obj
        .properties
        .get(PREVIOUS_PLAN_PROPERTY)
        .map(String::as_str)
}

/// The id of the plan whose remove step dropped the previous issuer.
pub fn removed_plan(env_obj: &Object) -> Option<&str> {
    env_obj
        .properties
        .get(REMOVED_PLAN_PROPERTY)
        .map(String::as_str)
}

/// The issuer the last issue step replaced.
pub fn previous(env_obj: &Object) -> Result<Option<IssuerKey>> {
    read(env_obj, PREVIOUS_PROPERTY)
}

/// The generation `prepare` asked a candidate for.
pub fn requested(env_obj: &Object) -> Result<Option<u64>> {
    env_obj
        .properties
        .get(REQUEST_PROPERTY)
        .map(|raw| raw.parse())
        .transpose()
        .context("the stored issuer request is not a generation")
}

/// The issuer state for inspection.
pub fn status(env_obj: &Object) -> Result<IssuerStatus> {
    Ok(IssuerStatus {
        current: current(env_obj)?.as_ref().map(IssuerSummary::from),
        requested: requested(env_obj)?,
        candidate: candidate(env_obj)?.as_ref().map(IssuerSummary::from),
        next: next(env_obj)?.as_ref().map(IssuerSummary::from),
        previous: previous(env_obj)?.as_ref().map(IssuerSummary::from),
    })
}

/// The candidate for `generation` that a runtime can still open: one whose
/// wraps a revocation dropped is lost, and a new one is wanted.
fn usable_candidate(env_obj: &Object, generation: u64) -> Result<Option<IssuerKey>> {
    Ok(candidate(env_obj)?.filter(|candidate| {
        candidate.generation == generation && !candidate.sealed_key.wraps.is_empty()
    }))
}

/// The generation a candidate is still wanted for: requested, and no usable
/// one uploaded for it yet.
pub fn wanted_generation(env_obj: &Object) -> Result<Option<u64>> {
    let Some(generation) = requested(env_obj)? else {
        return Ok(None);
    };
    Ok(usable_candidate(env_obj, generation)?
        .is_none()
        .then_some(generation))
}

/// Run `change` on `environment` under a short environment lease and write
/// the result through its fence. An expired lease of a crashed holder is
/// taken over, as for a runtime completion: the write is fenced and every
/// change here is safe to repeat.
async fn under_lease<T>(
    ctx: &mut Ctx,
    environment: &str,
    purpose: &str,
    change: impl FnOnce(&mut Object) -> Result<T>,
) -> Result<T> {
    let lease = crate::apply::claim_environment_for_completion(ctx, environment, purpose).await?;
    let changed = async {
        let mut env_obj = crate::environment::environment(ctx, environment).await?;
        let value = change(&mut env_obj)?;
        env_obj.updated = crate::now_millis();
        crate::sealed_secret::put_fenced(ctx, env_obj, &lease).await?;
        anyhow::Ok(value)
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (changed, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("releasing the environment lease")),
    }
}

/// Ask the environment's runtimes for a candidate key for the next issuer
/// generation. Asking again returns the same generation and keeps a usable
/// candidate; one for an older request, or one no runtime can open any
/// more, is dropped.
pub async fn request_candidate(ctx: &mut Ctx, environment: &str) -> Result<u64> {
    let owner = format!("identity-issuer-prepare:{}", crate::now_millis());
    under_lease(ctx, environment, &owner, |env_obj| {
        let generation = current(env_obj)?.map_or(0, |key| key.generation) + 1;
        if usable_candidate(env_obj, generation)?.is_none() {
            env_obj.properties.remove(CANDIDATE_PROPERTY);
        }
        env_obj
            .properties
            .insert(REQUEST_PROPERTY.into(), generation.to_string());
        Ok(generation)
    })
    .await
}

/// Store a runtime's candidate. The first candidate for the requested
/// generation wins; the same one again is accepted, so a runtime that
/// crashed after uploading retries safely, and any other is refused, so its
/// runtime discards its key. A candidate no runtime can open any more is
/// replaced. Its one wrap must be for the uploader's unrevoked key, which
/// `own` reads inside the lease, so an upload never undoes a revocation
/// that finished before it.
pub async fn store_candidate(
    ctx: &mut Ctx,
    environment: &str,
    key: IssuerKey,
    own: impl FnOnce() -> Result<Option<String>>,
) -> Result<IssuerKey> {
    key.check_public()?;
    let owner = format!("identity-issuer-candidate:{}", crate::now_millis());
    under_lease(ctx, environment, &owner, |env_obj| {
        if let Some(existing) = usable_candidate(env_obj, key.generation)? {
            ensure!(
                existing.fingerprint == key.fingerprint,
                "{environment} already has issuer candidate {} for generation {}",
                existing.fingerprint,
                key.generation
            );
            return Ok(existing);
        }
        ensure!(
            requested(env_obj)? == Some(key.generation),
            "{environment} asked for no issuer candidate of generation {}",
            key.generation
        );
        let own = own()?.with_context(|| {
            format!("the uploader has no unrevoked sealing key in {environment}")
        })?;
        match key.sealed_key.wraps.as_slice() {
            [wrap] if wrap.fingerprint == own => {}
            _ => bail!("an issuer candidate must be wrapped for its uploader's key {own} only"),
        }
        write(env_obj, CANDIDATE_PROPERTY, &key);
        Ok(key)
    })
    .await
}

/// Refuse an issuer step that no longer applies: one that creates a
/// generation other than the next, or re-wraps a key that is no longer the
/// issuer. A step whose issuer is already recorded is a replay and applies.
pub fn require_current(env_obj: &Object, step: &crate::plan::Step) -> Result<()> {
    let Some(issuer) = &step.issuer else {
        return Ok(());
    };
    let recorded = current(env_obj)?;
    let key = &issuer.key;
    if step.rewrap.is_some() {
        ensure!(
            recorded
                .as_ref()
                .is_some_and(|recorded| recorded.fingerprint == key.fingerprint),
            "step {} re-wraps issuer {}, which is no longer the issuer",
            step.id,
            key.fingerprint
        );
        return Ok(());
    }
    if let Some(phase) = issuer.phase {
        return require_rotation(env_obj, step, phase);
    }
    match recorded {
        Some(recorded) if recorded.generation == key.generation => ensure!(
            recorded.fingerprint == key.fingerprint,
            "step {} is stale: issuer generation {} is already {}",
            step.id,
            key.generation,
            recorded.fingerprint
        ),
        recorded => {
            let previous = recorded.map_or(0, |recorded| recorded.generation);
            ensure!(
                previous + 1 == key.generation,
                "step {} is stale: it creates issuer generation {}, and the issuer is at generation {previous}",
                step.id,
                key.generation
            );
        }
    }
    Ok(())
}

/// Refuse a rotation step that no longer applies. An add needs the next
/// generation after the current issuer and no other next issuer; an issue
/// needs exactly its key recorded as the next issuer. A step whose key is
/// already where it puts it is a replay and applies.
fn require_rotation(
    env_obj: &Object,
    step: &crate::plan::Step,
    phase: RotationPhase,
) -> Result<()> {
    let key = &step
        .issuer
        .as_ref()
        .expect("rotation steps carry a key")
        .key;
    let current = current(env_obj)?;
    let next = next(env_obj)?;
    let is = |recorded: &Option<IssuerKey>| {
        recorded
            .as_ref()
            .is_some_and(|recorded| recorded.fingerprint == key.fingerprint)
    };
    let current_generation = current.as_ref().map_or(0, |current| current.generation);
    match phase {
        RotationPhase::Add => {
            if is(&next) || is(&current) {
                return Ok(());
            }
            ensure!(
                current.is_some() && current_generation + 1 == key.generation,
                "step {} is stale: it adds issuer generation {}, and the issuer is at generation {current_generation}",
                step.id,
                key.generation
            );
            ensure!(
                next.is_none(),
                "step {} is stale: issuer generation {} is already the next issuer",
                step.id,
                key.generation
            );
        }
        RotationPhase::Issue => {
            if is(&current) {
                return Ok(());
            }
            let replaces = step
                .issuer
                .as_ref()
                .and_then(|issuer| issuer.replaces.as_ref());
            ensure!(
                replaces.is_some_and(|replaces| current
                    .as_ref()
                    .is_some_and(|current| current.fingerprint == replaces.fingerprint)),
                "step {} is stale: it does not replace the current issuer",
                step.id
            );
            ensure!(
                is(&next) && current_generation + 1 == key.generation,
                "step {} is stale: issuer generation {} ({}) is not the next issuer",
                step.id,
                key.generation,
                key.fingerprint
            );
        }
        RotationPhase::Remove => {
            // A replay finds the generation below the current one removed.
            let removed = previous(env_obj)?.is_none()
                && removed_plan(env_obj).is_some()
                && key.generation + 1 == current_generation;
            ensure!(
                is(&previous(env_obj)?) || removed,
                "step {} is stale: issuer generation {} ({}) is not the previous issuer",
                step.id,
                key.generation,
                key.fingerprint
            );
        }
    }
    Ok(())
}

/// Record the issuers that succeeded steps of `plan` activated, each as a
/// compare-and-set on the previous generation, under the environment lease.
/// The candidate's current wraps are recorded, not the step's: a recipient
/// revoked since the plan was made keeps no wrap. A replay changes nothing.
pub async fn record_activated(
    ctx: &mut Ctx,
    environment: &str,
    plan_id: &str,
    steps: &[&crate::plan::Step],
) -> Result<()> {
    if steps.is_empty() {
        return Ok(());
    }
    let purpose = format!("identity-issuer-record:{}", crate::now_millis());
    let lease = crate::apply::claim_environment_for_completion(ctx, environment, &purpose).await?;
    let recorded = async {
        let mut env_obj = crate::environment::environment(ctx, environment).await?;
        let mut changed = false;
        for step in steps {
            require_current(&env_obj, step)?;
            let key = &step
                .issuer
                .as_ref()
                .expect("activation steps carry a key")
                .key;
            match step.issuer.as_ref().and_then(|issuer| issuer.phase) {
                Some(RotationPhase::Issue) => {
                    // Checked again under the lease: an instance deployed
                    // or renewed without the bundle since the plan was made
                    // keeps the next issuer from issuing.
                    if next(&env_obj)?.is_some_and(|next| next.fingerprint == key.fingerprint) {
                        let waiting =
                            waiting_for_take_up(ctx, &env_obj, key, crate::now_millis() / 1000)
                                .await?;
                        ensure!(
                            waiting.is_empty(),
                            "the next identity issuer is not taken up yet by {}",
                            waiting.join(", ")
                        );
                    }
                    changed |= record_issued(&mut env_obj, key, plan_id)?;
                    continue;
                }
                Some(RotationPhase::Remove) => {
                    if previous(&env_obj)?.is_some_and(|kept| kept.fingerprint == key.fingerprint) {
                        // Checked again under the lease: a certificate the
                        // previous issuer signed must not lose its trust.
                        let waiting =
                            waiting_for_removal(ctx, &env_obj, crate::now_millis() / 1000).await?;
                        ensure!(
                            waiting.is_empty(),
                            "the previous identity issuer still has live certificates at {}",
                            waiting.join(", ")
                        );
                        // The issue plan stays: a runtime that missed the
                        // promotion learns the current issuer from it before
                        // the remove plan drops the old one.
                        env_obj.properties.remove(PREVIOUS_PROPERTY);
                        env_obj
                            .properties
                            .insert(REMOVED_PLAN_PROPERTY.into(), plan_id.into());
                        changed = true;
                    }
                    continue;
                }
                Some(RotationPhase::Add) => {
                    if next(&env_obj)?.is_some_and(|next| next.generation == key.generation)
                        || current(&env_obj)?
                            .is_some_and(|recorded| recorded.generation >= key.generation)
                    {
                        continue;
                    }
                }
                None => {
                    if current(&env_obj)?
                        .is_some_and(|recorded| recorded.generation == key.generation)
                    {
                        continue;
                    }
                }
            }
            // The candidate carries the wraps revocations left. A candidate
            // is replaced only once revocations dropped every wrap, so when
            // the approved one is gone the generation is recorded as lost
            // (no wraps): a durable completion always has an outcome, and
            // the issuer is rotated in at the next generation.
            let activated = candidate(&env_obj)?
                .filter(|candidate| candidate.fingerprint == key.fingerprint)
                .unwrap_or_else(|| {
                    let mut lost = key.clone();
                    lost.sealed_key.wraps.clear();
                    lost
                });
            let property = match step.issuer.as_ref().and_then(|issuer| issuer.phase) {
                Some(RotationPhase::Add) => NEXT_PROPERTY,
                _ => ISSUER_PROPERTY,
            };
            write(&mut env_obj, property, &activated);
            if property == NEXT_PROPERTY {
                env_obj
                    .properties
                    .insert(NEXT_PLAN_PROPERTY.into(), plan_id.into());
            }
            if candidate(&env_obj)?.is_some_and(|stale| stale.generation <= key.generation) {
                env_obj.properties.remove(CANDIDATE_PROPERTY);
            }
            if requested(&env_obj)?.is_some_and(|wanted| wanted <= key.generation) {
                env_obj.properties.remove(REQUEST_PROPERTY);
            }
            changed = true;
        }
        if changed {
            env_obj.updated = crate::now_millis();
            crate::sealed_secret::put_fenced(ctx, env_obj, &lease).await?;
        }
        anyhow::Ok(())
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (recorded, unlock) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error.context("releasing the environment lease")),
    }
}

/// Make the next issuer `key` the current one, keeping the current one as
/// the previous issuer, proven by `plan_id`. Returns whether anything
/// changed: a replay finds `key` already current.
fn record_issued(env_obj: &mut Object, key: &IssuerKey, plan_id: &str) -> Result<bool> {
    if current(env_obj)?.is_some_and(|current| current.fingerprint == key.fingerprint) {
        return Ok(false);
    }
    let next = next(env_obj)?
        .filter(|next| next.fingerprint == key.fingerprint)
        .context("the issued key is no longer the next issuer")?;
    if let Some(replaced) = current(env_obj)? {
        write(env_obj, PREVIOUS_PROPERTY, &replaced);
    }
    write(env_obj, ISSUER_PROPERTY, &next);
    env_obj.properties.remove(NEXT_PROPERTY);
    env_obj.properties.remove(NEXT_PLAN_PROPERTY);
    env_obj.properties.remove(REMOVED_PLAN_PROPERTY);
    env_obj
        .properties
        .insert(PREVIOUS_PLAN_PROPERTY.into(), plan_id.into());
    Ok(true)
}

/// Add re-wrap `wraps` to the recorded issuer. A wrap for another
/// generation or digest is skipped: the issuer changed since.
pub(crate) fn add_wraps(
    env_obj: &mut Object,
    environment: &str,
    wraps: &[RecipientWrap],
) -> Result<()> {
    let Some(mut issuer) = current(env_obj)? else {
        return Ok(());
    };
    let digest = issuer.digest(environment)?;
    let mut changed = false;
    for wrap in wraps {
        if wrap.secret != WRAP_SECRET || wrap.key != issuer.wrap_key() || wrap.digest != digest {
            continue;
        }
        let known = issuer
            .sealed_key
            .wraps
            .iter()
            .any(|existing| existing.fingerprint == wrap.wrap.fingerprint);
        if !known && issuer.sealed_key.wraps.len() >= crate::sealed_secret::MAX_WRAPS {
            continue;
        }
        issuer
            .sealed_key
            .wraps
            .retain(|existing| existing.fingerprint != wrap.wrap.fingerprint);
        issuer.sealed_key.wraps.push(wrap.wrap.clone());
        changed = true;
    }
    if changed {
        crate::sealed_secret::check_form(&issuer.sealed_key)
            .context("refusing a wrap for the identity issuer")?;
        write(env_obj, ISSUER_PROPERTY, &issuer);
    }
    Ok(())
}

/// Drop every wrap for `fingerprint` from the issuer and its candidate, as
/// for sealed values (ADR 0045 §5). Returns whether anything changed and
/// the keys no wrap is left on.
pub(crate) fn drop_wraps(env_obj: &mut Object, fingerprint: &str) -> Result<(bool, Vec<String>)> {
    let mut changed = false;
    let mut lost = Vec::new();
    for (property, label) in [
        (ISSUER_PROPERTY, "identity issuer"),
        (CANDIDATE_PROPERTY, "identity issuer candidate"),
        (NEXT_PROPERTY, "next identity issuer"),
        (PREVIOUS_PROPERTY, "previous identity issuer"),
    ] {
        let Some(mut key) = read(env_obj, property)? else {
            continue;
        };
        let before = key.sealed_key.wraps.len();
        key.sealed_key
            .wraps
            .retain(|wrap| wrap.fingerprint != fingerprint);
        if key.sealed_key.wraps.len() != before {
            changed = true;
            write(env_obj, property, &key);
        }
        if key.sealed_key.wraps.is_empty() {
            lost.push(format!("{label} generation {}", key.generation));
        }
    }
    Ok((changed, lost))
}

/// An environment-level plan step for `key`: it names no product,
/// instance or release. Without `rewrap` it activates the key.
fn issuer_step(
    key: IssuerKey,
    rewrap: Option<crate::plan::RewrapStep>,
    recipient: Option<String>,
    phase: Option<RotationPhase>,
) -> crate::plan::Step {
    crate::plan::Step {
        id: String::new(),
        order: 0,
        product: String::new(),
        instance: String::new(),
        action: if rewrap.is_some() {
            crate::plan::Action::Restart
        } else {
            crate::plan::Action::Install
        },
        from: None,
        to: String::new(),
        release_id: String::new(),
        release_digest: String::new(),
        artifact_digest: String::new(),
        workdir: String::new(),
        restore: None,
        host: None,
        sealed: Vec::new(),
        rewrap,
        issuer: Some(crate::plan::IssuerStep {
            key,
            recipient,
            phase,
            replaces: None,
        }),
        identity: None,
        restore_identity: None,
    }
}

/// The step that activates `environment`'s uploaded candidate: as the
/// first issuer, or, when one exists, as the next issuer (the add step of
/// ADR 0046 §7). Refused while there is no candidate, once it no longer is
/// the next generation, or while an earlier rotation waits for its issue or
/// remove step.
pub fn activation_step(env_obj: &Object, environment: &str) -> Result<crate::plan::Step> {
    if let Some(next) = next(env_obj)? {
        bail!(
            "{environment} already trusts the next identity issuer generation {} ({}); plan its issue step first",
            next.generation,
            next.fingerprint
        );
    }
    if let Some(previous) = previous(env_obj)? {
        bail!(
            "{environment} still trusts the previous identity issuer generation {} ({}); plan its remove step first",
            previous.generation,
            previous.fingerprint
        );
    }
    let candidate = candidate(env_obj)?.with_context(|| {
        match requested(env_obj).ok().flatten() {
            Some(generation) => format!(
                "{environment} has no issuer candidate for generation {generation} yet; a runtime that names workload_identity uploads one on its next poll"
            ),
            None => format!(
                "{environment} has no issuer candidate; prepare one first"
            ),
        }
    })?;
    let phase = current(env_obj)?.map(|_| RotationPhase::Add);
    let step = issuer_step(candidate, None, None, phase);
    require_current(env_obj, &step)?;
    Ok(step)
}

/// The issue step for `environment`'s next issuer, once every instance
/// with a workload certificate has taken up the bundle that carries it
/// (ADR 0046 §7). The refusal names the instances still waiting.
pub async fn issue_step(
    ctx: &mut Ctx,
    env_obj: &Object,
    now_secs: i64,
) -> Result<crate::plan::Step> {
    let next = next(env_obj)?.context("no next identity issuer")?;
    let waiting = waiting_for_take_up(ctx, env_obj, &next, now_secs).await?;
    if !waiting.is_empty() {
        bail!(
            "the next identity issuer generation {} is not taken up yet by {}; plan the issue step again once they have",
            next.generation,
            waiting.join(", ")
        );
    }
    let mut step = issuer_step(next, None, None, Some(RotationPhase::Issue));
    if let Some(issuer) = &mut step.issuer {
        issuer.replaces = current(env_obj)?;
    }
    require_current(env_obj, &step)?;
    Ok(step)
}

/// The remove step for `environment`'s previous issuer, once no instance
/// may still hold a live certificate it signed (ADR 0046 §7). The refusal
/// names the instances that may.
pub async fn remove_step(
    ctx: &mut Ctx,
    env_obj: &Object,
    now_secs: i64,
) -> Result<crate::plan::Step> {
    let previous = previous(env_obj)?.context("no previous identity issuer")?;
    let waiting = waiting_for_removal(ctx, env_obj, now_secs).await?;
    if !waiting.is_empty() {
        bail!(
            "the previous identity issuer generation {} may still sign a live certificate at {}; plan the remove step again once they renewed",
            previous.generation,
            waiting.join(", ")
        );
    }
    let step = issuer_step(previous, None, None, Some(RotationPhase::Remove));
    require_current(env_obj, &step)?;
    Ok(step)
}

/// The next step of `environment`'s issuer lifecycle, read from what the
/// server recorded, so a rotation interrupted anywhere resumes at the step
/// after the last one recorded: the issue step while a next issuer waits,
/// the remove step while a previous one is kept, and otherwise the
/// activation of the uploaded candidate.
pub async fn rotation_step(
    ctx: &mut Ctx,
    env_obj: &Object,
    now_secs: i64,
) -> Result<crate::plan::Step> {
    if next(env_obj)?.is_some() {
        return issue_step(ctx, env_obj, now_secs).await;
    }
    if previous(env_obj)?.is_some() {
        return remove_step(ctx, env_obj, now_secs).await;
    }
    activation_step(env_obj, &env_obj.name)
}

/// What keeps the next rotation step from being planned: the instances
/// that have not taken up the next issuer, or that may still hold a live
/// certificate of the previous one. Empty when nothing waits.
pub async fn rotation_waiting(
    ctx: &mut Ctx,
    env_obj: &Object,
    now_secs: i64,
) -> Result<Vec<String>> {
    if let Some(next) = next(env_obj)? {
        return waiting_for_take_up(ctx, env_obj, &next, now_secs).await;
    }
    if previous(env_obj)?.is_some() {
        return waiting_for_removal(ctx, env_obj, now_secs).await;
    }
    Ok(Vec::new())
}

/// How long after a renewed bundle is written a workload that reloads it
/// itself is taken to have read it: the refresh of mounted Secrets and a
/// product's reload interval (ADR 0046 §7).
pub const TAKE_UP_SECS: i64 = 600;

/// The instances of `env_obj` whose deployed release asks for a workload
/// certificate and that have not yet taken up a bundle with `next`, each
/// with why. Taken up means the runtime reported a certificate whose bundle
/// holds `next`, with no restart pending (a restart-reload workload has
/// rolled out on it), written at least [`TAKE_UP_SECS`] ago.
pub async fn waiting_for_take_up(
    ctx: &mut Ctx,
    env_obj: &Object,
    next: &IssuerKey,
    now_secs: i64,
) -> Result<Vec<String>> {
    waiting_instances(ctx, env_obj, |report| {
        if !report.trust.contains(&next.fingerprint) {
            Some("bundle without the next issuer".into())
        } else if report.restart_pending {
            Some("restart pending".into())
        } else if report.not_before + 60 + TAKE_UP_SECS > now_secs {
            Some("bundle written too recently".into())
        } else {
            None
        }
    })
    .await
}

/// The instances of `env_obj` whose deployed release asks for a workload
/// certificate and that may still hold a live one from an issuer other
/// than the current one, each with why. Only a report of a certificate
/// from the current issuer clears an instance, taken up as for
/// the issue step: no restart pending, written at least [`TAKE_UP_SECS`]
/// ago, so no running replica still presents the old one.
pub async fn waiting_for_removal(
    ctx: &mut Ctx,
    env_obj: &Object,
    now_secs: i64,
) -> Result<Vec<String>> {
    let current = current(env_obj)?.context("no identity issuer")?;
    // An expired report proves nothing: a runtime offline since may have
    // renewed from the old issuer. Only a report of the current one counts.
    waiting_instances(ctx, env_obj, |report| match report.trust.first() {
        None => Some("issuer not reported".into()),
        Some(issuer) if *issuer != current.fingerprint => Some(format!(
            "certificate from an earlier issuer valid until {}",
            report.not_after
        )),
        Some(_) if report.restart_pending => Some("restart pending".into()),
        Some(_) if report.not_before + 60 + TAKE_UP_SECS > now_secs => {
            Some("certificate written too recently".into())
        }
        Some(_) => None,
    })
    .await
}

/// The instances of `env_obj` whose deployed release asks for a workload
/// certificate and whose latest report `why` refuses, each with why. Every
/// deployed release counts until its removal completes, subscribed or not.
/// An instance whose deployment state is unknown, whose manifest cannot be
/// read, that the runtime never reported, or that it has not reported since
/// its last deployment waits too.
async fn waiting_instances(
    ctx: &mut Ctx,
    env_obj: &Object,
    why: impl Fn(&crate::certificate_reports::CertificateReport) -> Option<String>,
) -> Result<Vec<String>> {
    let reports = crate::certificate_reports::reported(ctx, &env_obj.name).await?;
    let deployed: std::collections::BTreeMap<&str, &str> = env_obj
        .properties
        .iter()
        .filter_map(|(key, release)| {
            Some((key.strip_prefix("deployed_release.")?, release.as_str()))
        })
        .collect();
    let mut waiting = Vec::new();
    // An instance whose deployment is unknown may still run on an old
    // certificate; it waits until reconciliation settles it.
    for (key, health) in &env_obj.properties {
        if let Some(instance) = key.strip_prefix("deployment_health.")
            && health == "unknown"
            && !deployed.contains_key(instance)
        {
            waiting.push(format!("{instance} (deployment state unknown)"));
        }
    }
    for (instance, release) in deployed {
        // Only a manifest read and found without an identity is skipped;
        // one that cannot be read waits.
        let manifest = crate::plan::readable_manifest(ctx, release).await?;
        if manifest
            .as_ref()
            .is_some_and(|manifest| manifest.deploy.identity.is_none())
        {
            continue;
        }
        // Evidence from before the instance's last deployment describes a
        // certificate it may no longer hold. An observation in the same
        // second may precede it, so only a later second counts.
        let deployed_at = env_obj
            .properties
            .get(&format!("{}{instance}", crate::environment::DEPLOYMENT_AT))
            .and_then(|at| at.parse::<i64>().ok())
            .unwrap_or(0);
        let refused = match reports.get(instance) {
            _ if manifest.is_none() => Some("release manifest unreadable".into()),
            None => Some("no certificate reported".into()),
            Some(report) if deployed_at > 0 && report.observed_at <= deployed_at / 1000 => {
                Some("not reported since its last deployment".into())
            }
            Some(report) => why(report),
        };
        if let Some(refused) = refused {
            waiting.push(format!("{instance} ({refused})"));
        }
    }
    Ok(waiting)
}

/// An approved rotation step (ADR 0046 §7), as the server hands it to
/// every runtime of the environment: the add step proves the next issuer,
/// the issue step the issuer it replaced. Each runtime trusts them without
/// the server naming them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerProof {
    pub plan: crate::plan::Plan,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<crate::plan_approval::ApprovalEnvelope>,
    /// On an issue plan: the issuer as the server holds it now, with the
    /// wraps re-wraps added since the plan. Not trusted on its own: a
    /// runtime uses only its wraps, and only when it is the approved key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<IssuerKey>,
}

/// The issuers `proof` shows, once this runtime's local approval policy
/// accepts the plan: an add step's next issuer, or the issuer an issue step
/// replaced and the one it made issuing. The plan must be of `environment`
/// with that one step. A proof stays valid after its approvals expire, as
/// long as their signers are still valid now.
pub fn verify_proof(
    policy: Option<&crate::host_apply::HostApprovalPolicy>,
    environment: &str,
    proof: &IssuerProof,
    now_ms: i64,
) -> Result<Proven> {
    ensure!(
        proof.plan.environment == environment,
        "the issuer proof is a plan of {}, not {environment}",
        proof.plan.environment
    );
    let [step] = proof.plan.steps.as_slice() else {
        bail!("the issuer proof is not a plan with one step");
    };
    let issuer = step
        .issuer
        .as_ref()
        .filter(|_| step.rewrap.is_none())
        .context("the issuer proof is not a rotation step")?;
    let proven = match (issuer.phase, &issuer.replaces) {
        (Some(RotationPhase::Add), None) => Proven::Next(issuer.key.clone()),
        (Some(RotationPhase::Remove), None) => Proven::Removed(issuer.key.clone()),
        (Some(RotationPhase::Issue), Some(replaced)) => {
            check_replaced(&issuer.key, replaced)?;
            // The latest wraps of the approved key, if the server sent it.
            let issuing = proof
                .current
                .as_ref()
                .filter(|current| {
                    current.generation == issuer.key.generation
                        && current.fingerprint == issuer.key.fingerprint
                        && current.certificate == issuer.key.certificate
                })
                .unwrap_or(&issuer.key);
            Proven::Issued {
                replaced: replaced.clone(),
                issuing: issuing.clone(),
            }
        }
        _ => bail!("the issuer proof is not an add, issue or remove step"),
    };
    // Trust evidence outlives the approvals' own expiry, so a runtime that
    // joins after them still learns a rotated issuer: the approvals of
    // signers this policy still holds valid must have met the quorum at
    // some time up to now, at the latest one's issue or now.
    let signed: Vec<_> = proof
        .approvals
        .iter()
        .filter(|envelope| policy.is_some_and(|policy| policy.signer_valid(envelope, now_ms)))
        .cloned()
        .collect();
    let approved_at = |at: i64| {
        crate::runtime_local_approval::require_step(policy, &proof.plan, step, &signed, at)
    };
    let earlier = signed
        .iter()
        .map(|envelope| envelope.statement.issued_at)
        .filter(|at| *at < now_ms);
    if !earlier.into_iter().any(|at| approved_at(at).is_ok()) {
        approved_at(now_ms)?;
    }
    match &proven {
        Proven::Next(key) | Proven::Removed(key) => key.check_public()?,
        Proven::Issued { replaced, issuing } => {
            replaced.check_public()?;
            issuing.check_public()?;
        }
    }
    Ok(proven)
}

/// What a verified [`IssuerProof`] shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proven {
    /// An add plan: the next issuer, kept in every bundle.
    Next(IssuerKey),
    /// An issue plan: the issuer it replaced, kept in every bundle, and the
    /// one the server recorded as issuing, which a runtime that can open it
    /// renews from.
    Issued {
        replaced: IssuerKey,
        issuing: IssuerKey,
    },
    /// A remove plan: the issuer no bundle carries any more.
    Removed(IssuerKey),
}

impl Proven {
    /// The issuer bundles keep beside the issuing one, if the plan keeps one.
    pub fn trusted(&self) -> Option<&IssuerKey> {
        match self {
            Self::Next(key) | Self::Issued { replaced: key, .. } => Some(key),
            Self::Removed(_) => None,
        }
    }

    /// The issuer an issue plan made issuing.
    pub fn issuing(&self) -> Option<&IssuerKey> {
        match self {
            Self::Issued { issuing, .. } => Some(issuing),
            _ => None,
        }
    }
}

/// Refuse an issue step whose `replaced` issuer is not one generation
/// below `key`.
pub fn check_replaced(key: &IssuerKey, replaced: &IssuerKey) -> Result<()> {
    ensure!(
        replaced.generation.checked_add(1) == Some(key.generation),
        "the issue step replaces issuer generation {}, not the one below {}",
        replaced.generation,
        key.generation
    );
    replaced.check_public()
}

/// The step that wraps the recorded issuer key for `recipient` (ADR 0045
/// §5), if `environment` has an issuer.
pub fn rewrap_step(
    env_obj: &Object,
    recipient: &SealingPublicKey,
) -> Result<Option<crate::plan::Step>> {
    Ok(current(env_obj)?.map(|key| {
        issuer_step(
            key,
            Some(crate::plan::RewrapStep {
                fingerprint: recipient.fingerprint(),
                recovered: Vec::new(),
            }),
            Some(recipient.to_wire()),
            None,
        )
    }))
}

/// The issuer a runtime last verified for an environment, kept beside its
/// sealing key (ADR 0046 §3) so it can renew certificates while the server
/// is unreachable. The key inside stays sealed to that runtime.
fn cached_issuer_path(
    sealing_dir: &std::path::Path,
    environment: &str,
) -> Result<std::path::PathBuf> {
    crate::ontology::validate_identifier("environment", environment)?;
    Ok(sealing_dir.join(format!("identity-issuer-{environment}.json")))
}

/// Keep `issuer`, which an approved step just verified, for renewal. A
/// later generation replaces an earlier one, never the reverse, also when
/// two runtime processes share the sealing directory during a restart. An
/// issuer a remove plan dropped is never kept, so a replayed older proof
/// cannot resume issuance from it.
pub fn cache_verified(
    sealing_dir: &std::path::Path,
    environment: &str,
    issuer: &IssuerKey,
) -> Result<()> {
    issuer.check_public()?;
    cache_trusted(sealing_dir, environment, issuer)?;
    let path = cached_issuer_path(sealing_dir, environment)?;
    let lock = path.with_extension("lock");
    crate::fenced_mutation::with_mutation_lock(&lock, || {
        if cached_removed(sealing_dir, environment)?.drops(issuer) {
            return Ok(());
        }
        if let Some(cached) = cached_verified(sealing_dir, environment)?
            && (cached.generation > issuer.generation || &cached == issuer)
        {
            return Ok(());
        }
        crate::atomic_state::write_file(&path, &serde_json::to_vec_pretty(issuer)?, Some(0o600))
            .with_context(|| format!("writing {}", path.display()))
    })?
}

/// The issuer [`cache_verified`] kept for `environment`, if any. None once
/// a remove plan dropped it, which a removal racing [`cache_verified`] can
/// leave on disk: renewal then fails visibly instead of issuing from it.
pub fn cached_verified(
    sealing_dir: &std::path::Path,
    environment: &str,
) -> Result<Option<IssuerKey>> {
    let path = cached_issuer_path(sealing_dir, environment)?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let issuer: IssuerKey =
        serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))?;
    issuer.check_public()?;
    if cached_removed(sealing_dir, environment)?.drops(&issuer) {
        return Ok(None);
    }
    Ok(Some(issuer))
}

/// How many generations the trusted issuer cache keeps below its newest.
const TRUSTED_GENERATIONS: u64 = 2;

fn trusted_path(sealing_dir: &std::path::Path, environment: &str) -> Result<std::path::PathBuf> {
    crate::ontology::validate_identifier("environment", environment)?;
    Ok(sealing_dir.join(format!("identity-issuer-trusted-{environment}.json")))
}

fn removed_path(sealing_dir: &std::path::Path, environment: &str) -> Result<std::path::PathBuf> {
    crate::ontology::validate_identifier("environment", environment)?;
    Ok(sealing_dir.join(format!("identity-issuer-removed-{environment}.json")))
}

/// What approved remove plans dropped for `environment` (ADR 0046 §7).
/// Generations only rise, so `through` is the removal boundary: no issuer
/// at or below it is trusted again, whatever older proofs replay.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    /// The highest removed generation.
    pub through: u64,
    /// The newest removed fingerprints, so a bundle that still carries one
    /// is re-issued.
    pub fingerprints: Vec<String>,
}

impl Removed {
    /// Whether `issuer` is at or below the boundary.
    pub fn drops(&self, issuer: &IssuerKey) -> bool {
        !self.fingerprints.is_empty() && issuer.generation <= self.through
    }
}

/// The issuers approved remove plans dropped for `environment`.
pub fn cached_removed(sealing_dir: &std::path::Path, environment: &str) -> Result<Removed> {
    let path = removed_path(sealing_dir, environment)?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Removed::default()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// Stop trusting `issuer`, which an approved remove plan dropped (ADR 0046
/// §7), and every generation below it: they leave the trusted issuers and
/// their proofs, and are never kept again. Refused at or above the issuer
/// this runtime issues from. Idempotent, and a replayed older plan changes
/// nothing.
pub fn cache_removed(
    sealing_dir: &std::path::Path,
    environment: &str,
    issuer: &IssuerKey,
) -> Result<()> {
    ensure!(
        cached_verified(sealing_dir, environment)?
            .is_none_or(|issuing| issuer.generation < issuing.generation),
        "the remove plan names issuer generation {}, which this runtime still issues from",
        issuer.generation
    );
    let path = trusted_path(sealing_dir, environment)?;
    let lock = path.with_extension("lock");
    crate::fenced_mutation::with_mutation_lock(&lock, || {
        let mut removed = cached_removed(sealing_dir, environment)?;
        if !removed.drops(issuer) {
            removed.through = issuer.generation;
            removed.fingerprints.push(issuer.fingerprint.clone());
            // Only the newest few matter: older bundles have long expired.
            let excess = removed.fingerprints.len().saturating_sub(MAX_REMOVED);
            removed.fingerprints.drain(..excess);
            let removed_path = removed_path(sealing_dir, environment)?;
            crate::atomic_state::write_file(
                &removed_path,
                &serde_json::to_vec_pretty(&removed)?,
                Some(0o600),
            )
            .with_context(|| format!("writing {}", removed_path.display()))?;
        }
        let mut trusted = stored_trusted(sealing_dir, environment)?;
        if trusted.iter().any(|kept| removed.drops(kept)) {
            trusted.retain(|kept| !removed.drops(kept));
            crate::atomic_state::write_file(
                &path,
                &serde_json::to_vec_pretty(&trusted)?,
                Some(0o600),
            )
            .with_context(|| format!("writing {}", path.display()))?;
        }
        anyhow::Ok(())
    })??;
    prune_proofs(sealing_dir, environment)
}

/// How many removed fingerprints a runtime remembers.
const MAX_REMOVED: usize = 8;

/// Keep `issuer`, which an approved step or issuance just verified, as one
/// the trust bundles of `environment` may carry (ADR 0046 §7). Only the
/// newest few generations are kept, and never one a remove plan dropped.
pub fn cache_trusted(
    sealing_dir: &std::path::Path,
    environment: &str,
    issuer: &IssuerKey,
) -> Result<()> {
    issuer.check_public()?;
    let path = trusted_path(sealing_dir, environment)?;
    let lock = path.with_extension("lock");
    crate::fenced_mutation::with_mutation_lock(&lock, || {
        let mut trusted = cached_trusted(sealing_dir, environment)?;
        if trusted
            .iter()
            .any(|kept| kept.fingerprint == issuer.fingerprint)
            || cached_removed(sealing_dir, environment)?.drops(issuer)
        {
            return Ok(());
        }
        trusted.retain(|kept| kept.generation != issuer.generation);
        trusted.push(issuer.clone());
        let newest = trusted
            .iter()
            .map(|kept| kept.generation)
            .max()
            .unwrap_or(0);
        trusted.retain(|kept| kept.generation + TRUSTED_GENERATIONS >= newest);
        trusted.sort_by_key(|kept| kept.generation);
        crate::atomic_state::write_file(&path, &serde_json::to_vec_pretty(&trusted)?, Some(0o600))
            .with_context(|| format!("writing {}", path.display()))
    })?
}

/// The issuers [`cache_trusted`] kept for `environment`, oldest first,
/// without any a remove plan dropped: a crash inside [`cache_removed`] can
/// leave one in the file, and the durable removal still wins.
fn cached_trusted(sealing_dir: &std::path::Path, environment: &str) -> Result<Vec<IssuerKey>> {
    let removed = cached_removed(sealing_dir, environment)?;
    let mut trusted = stored_trusted(sealing_dir, environment)?;
    trusted.retain(|kept| !removed.drops(kept));
    Ok(trusted)
}

/// The trusted-issuer file of `environment` as written.
fn stored_trusted(sealing_dir: &std::path::Path, environment: &str) -> Result<Vec<IssuerKey>> {
    let path = trusted_path(sealing_dir, environment)?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let trusted: Vec<IssuerKey> =
        serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))?;
    for issuer in &trusted {
        issuer.check_public()?;
    }
    Ok(trusted)
}

/// Whether this runtime already trusts the issuer `fingerprint` for
/// `environment`.
pub fn trusts(sealing_dir: &std::path::Path, environment: &str, fingerprint: &str) -> Result<bool> {
    Ok(cached_trusted(sealing_dir, environment)?
        .iter()
        .any(|kept| kept.fingerprint == fingerprint))
}

/// The certificates a bundle issued by `issuing` carries after it: each
/// verified issuer one generation before or after it, so the previous and
/// the next issuer of a rotation.
pub fn trust_bundle(
    sealing_dir: &std::path::Path,
    environment: &str,
    issuing: &IssuerKey,
) -> Result<Vec<IssuerKey>> {
    Ok(cached_trusted(sealing_dir, environment)?
        .into_iter()
        .filter(|kept| {
            kept.fingerprint != issuing.fingerprint
                && kept.generation.abs_diff(issuing.generation) == 1
        })
        .collect())
}

fn proofs_path(sealing_dir: &std::path::Path, environment: &str) -> Result<std::path::PathBuf> {
    crate::ontology::validate_identifier("environment", environment)?;
    Ok(sealing_dir.join(format!("identity-issuer-proofs-{environment}.json")))
}

/// The issuer `proof`'s plan has bundles trust: the key an add step adds,
/// or the key an issue step replaces.
fn proof_trusts(proof: &IssuerProof) -> Option<&IssuerKey> {
    let [step] = proof.plan.steps.as_slice() else {
        return None;
    };
    let issuer = step.issuer.as_ref()?;
    match (issuer.phase, &issuer.replaces) {
        (Some(RotationPhase::Add), None) => Some(&issuer.key),
        (Some(RotationPhase::Issue), Some(replaced)) => Some(replaced),
        _ => None,
    }
}

/// Keep `proof`, which this runtime verified, for the host applier, which
/// checks it itself before a host certificate's bundle may carry the issuer
/// it proves (ADR 0046 §7). Call after [`cache_trusted`]: a proof is kept
/// only while the issuer it proves is trusted. A later delivery of the same
/// plan replaces the kept one; an identical one writes nothing.
pub fn cache_proof(
    sealing_dir: &std::path::Path,
    environment: &str,
    proof: &IssuerProof,
) -> Result<()> {
    // The applier needs no wraps; the issuing key's fingerprint is the plan's.
    let proof = IssuerProof {
        current: None,
        ..proof.clone()
    };
    let path = proofs_path(sealing_dir, environment)?;
    let lock = path.with_extension("lock");
    crate::fenced_mutation::with_mutation_lock(&lock, || {
        let mut proofs = cached_proofs(sealing_dir, environment)?;
        let bytes = serde_json::to_vec(&proof)?;
        if proofs
            .iter()
            .map(serde_json::to_vec)
            .any(|kept| kept.is_ok_and(|kept| kept == bytes))
        {
            return Ok(());
        }
        proofs.retain(|kept| kept.plan.id != proof.plan.id);
        proofs.push(proof);
        let trusted = cached_trusted(sealing_dir, environment)?;
        proofs.retain(|kept| {
            proof_trusts(kept).is_some_and(|key| {
                trusted
                    .iter()
                    .any(|trusted| trusted.fingerprint == key.fingerprint)
            })
        });
        crate::atomic_state::write_file(&path, &serde_json::to_vec_pretty(&proofs)?, Some(0o600))
            .with_context(|| format!("writing {}", path.display()))
    })?
}

/// Drop the kept proofs whose issuer is no longer trusted.
fn prune_proofs(sealing_dir: &std::path::Path, environment: &str) -> Result<()> {
    let path = proofs_path(sealing_dir, environment)?;
    let lock = path.with_extension("lock");
    crate::fenced_mutation::with_mutation_lock(&lock, || {
        let mut proofs = cached_proofs(sealing_dir, environment)?;
        let before = proofs.len();
        let trusted = cached_trusted(sealing_dir, environment)?;
        proofs.retain(|kept| {
            proof_trusts(kept).is_some_and(|key| {
                trusted
                    .iter()
                    .any(|trusted| trusted.fingerprint == key.fingerprint)
            })
        });
        if proofs.len() == before {
            return Ok(());
        }
        crate::atomic_state::write_file(&path, &serde_json::to_vec_pretty(&proofs)?, Some(0o600))
            .with_context(|| format!("writing {}", path.display()))
    })?
}

/// The proofs [`cache_proof`] kept for `environment`.
fn cached_proofs(sealing_dir: &std::path::Path, environment: &str) -> Result<Vec<IssuerProof>> {
    let path = proofs_path(sealing_dir, environment)?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// [`trust_bundle`] for a host certificate: only the issuers a kept proof
/// proves, since the host applier admits no other.
pub fn host_trust_bundle(
    sealing_dir: &std::path::Path,
    environment: &str,
    issuing: &IssuerKey,
) -> Result<Vec<IssuerKey>> {
    let proofs = cached_proofs(sealing_dir, environment)?;
    Ok(trust_bundle(sealing_dir, environment, issuing)?
        .into_iter()
        .filter(|kept| {
            proofs
                .iter()
                .filter_map(proof_trusts)
                .any(|proven| proven.fingerprint == kept.fingerprint)
        })
        .collect())
}

/// The kept proofs of the issuers the bundle `ca` carries after its first,
/// which the host applier needs to admit them.
pub fn host_proofs(
    sealing_dir: &std::path::Path,
    environment: &str,
    ca: &str,
) -> Result<Vec<IssuerProof>> {
    let further: Vec<String> = crate::workload_identity::bundle_fingerprints(ca)?
        .into_iter()
        .skip(1)
        .collect();
    if further.is_empty() {
        return Ok(Vec::new());
    }
    Ok(cached_proofs(sealing_dir, environment)?
        .into_iter()
        .filter(|proof| proof_trusts(proof).is_some_and(|key| further.contains(&key.fingerprint)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runtime's sealing key in its own temp dir, and its opener.
    struct Runtime {
        dir: std::path::PathBuf,
        public: SealingPublicKey,
    }

    impl Runtime {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tenkai-issuer-{label}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let public = crate::sealing_key::SealingKey::open_or_generate(&dir)
                .unwrap()
                .public()
                .clone();
            Self { dir, public }
        }

        fn opener(&self) -> SealedOpener {
            SealedOpener::load(&self.dir).unwrap()
        }

        /// The uploader check `store_candidate` runs inside the lease.
        fn own(&self) -> impl FnOnce() -> Result<Option<String>> + use<> {
            let fingerprint = self.public.fingerprint();
            move || Ok(Some(fingerprint))
        }

        fn candidate(&self, generation: u64) -> IssuerKey {
            generate("prod", generation, &self.public, now()).unwrap()
        }
    }

    impl Drop for Runtime {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn store(label: &str) -> Ctx {
        let database = std::env::temp_dir().join(format!(
            "tenkai-issuer-{label}-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "issuer")
            .await
            .unwrap();
        ctx
    }

    fn now() -> i64 {
        crate::now_millis() / 1000
    }

    async fn env_obj(ctx: &mut Ctx) -> Object {
        crate::environment::environment(ctx, "prod").await.unwrap()
    }

    fn activation(key: &IssuerKey) -> crate::plan::Step {
        let mut step = issuer_step(key.clone(), None, None, None);
        step.id = format!("plan:step:{}", key.generation);
        step
    }

    /// Prepare, upload and activate a first issuer from `runtime`.
    async fn activate_first(ctx: &mut Ctx, runtime: &Runtime) -> IssuerKey {
        request_candidate(ctx, "prod").await.unwrap();
        let key = runtime.candidate(1);
        store_candidate(ctx, "prod", key.clone(), runtime.own())
            .await
            .unwrap();
        let step = activation_step(&env_obj(ctx).await, "prod").unwrap();
        record_activated(ctx, "prod", "plan-test", &[&step])
            .await
            .unwrap();
        key
    }

    /// An approved step pins the key: a step whose fingerprint differs from
    /// the sealed key is refused, and so is a key the server substitutes
    /// under the approved fingerprint.
    #[test]
    fn a_key_other_than_the_approved_fingerprint_is_refused() {
        let runtime = Runtime::new("mismatch");
        let approved = runtime.candidate(1);
        approved.open("prod", &runtime.opener()).unwrap();

        let substituted = runtime.candidate(1);
        let swapped = IssuerKey {
            sealed_key: substituted.sealed_key,
            ..approved.clone()
        };
        let error = format!("{:#}", swapped.open("prod", &runtime.opener()).unwrap_err());
        assert!(error.contains("not the approved"), "{error}");

        let renamed = IssuerKey {
            fingerprint: substituted.fingerprint,
            ..approved.clone()
        };
        let error = format!("{:#}", renamed.check_public().unwrap_err());
        assert!(error.contains("does not carry the key"), "{error}");

        // Sealed for another environment, it does not open here.
        let foreign = generate("staging", 1, &runtime.public, now()).unwrap();
        assert!(foreign.open("prod", &runtime.opener()).is_err());
    }

    /// A step for a generation other than the next is refused, and the
    /// issuer stays as recorded.
    #[tokio::test]
    async fn a_stale_generation_is_refused_and_keeps_the_issuer() {
        let mut ctx = store("stale").await;
        let runtime = Runtime::new("stale");
        let first = activate_first(&mut ctx, &runtime).await;
        assert_eq!(
            current(&env_obj(&mut ctx).await).unwrap(),
            Some(first.clone())
        );

        // A second plan made for generation 1 before the first applied.
        let error = format!(
            "{:#}",
            record_activated(
                &mut ctx,
                "prod",
                "plan-test",
                &[&activation(&runtime.candidate(1))]
            )
            .await
            .unwrap_err()
        );
        assert!(error.contains("stale"), "{error}");
        // One that skips a generation.
        let skipping = activation(&runtime.candidate(3));
        assert!(require_current(&env_obj(&mut ctx).await, &skipping).is_err());
        assert_eq!(current(&env_obj(&mut ctx).await).unwrap(), Some(first));
    }

    /// Rotating an existing issuer takes an add step, which records the
    /// next issuer beside the current one, then an issue step, which makes
    /// it current and keeps the old one as the previous issuer. Each is a
    /// compare-and-set: a replay changes nothing, and a stale step is
    /// refused.
    #[tokio::test]
    async fn a_rotation_adds_the_next_issuer_before_it_issues() {
        let mut ctx = store("rotation").await;
        let runtime = Runtime::new("rotation");
        let first = activate_first(&mut ctx, &runtime).await;

        request_candidate(&mut ctx, "prod").await.unwrap();
        let second = runtime.candidate(2);
        store_candidate(&mut ctx, "prod", second.clone(), runtime.own())
            .await
            .unwrap();
        let add = activation_step(&env_obj(&mut ctx).await, "prod").unwrap();
        assert_eq!(add.issuer.as_ref().unwrap().phase, Some(RotationPhase::Add));
        record_activated(&mut ctx, "prod", "plan-test", &[&add])
            .await
            .unwrap();
        record_activated(&mut ctx, "prod", "plan-test", &[&add])
            .await
            .unwrap();
        let object = env_obj(&mut ctx).await;
        assert_eq!(current(&object).unwrap(), Some(first.clone()));
        assert_eq!(next(&object).unwrap(), Some(second.clone()));
        assert_eq!(candidate(&object).unwrap(), None);
        // No second next issuer while one waits.
        request_candidate(&mut ctx, "prod").await.unwrap();
        let mut other = activation(&runtime.candidate(2));
        other.issuer.as_mut().unwrap().phase = Some(RotationPhase::Add);
        assert!(require_current(&env_obj(&mut ctx).await, &other).is_err());

        let error = format!(
            "{:#}",
            activation_step(&env_obj(&mut ctx).await, "prod").unwrap_err()
        );
        assert!(error.contains("already trusts the next"), "{error}");
        let object = env_obj(&mut ctx).await;
        let issue = issue_step(&mut ctx, &object, now()).await.unwrap();
        assert_eq!(
            issue.issuer.as_ref().unwrap().phase,
            Some(RotationPhase::Issue)
        );
        record_activated(&mut ctx, "prod", "plan-test", &[&issue])
            .await
            .unwrap();
        record_activated(&mut ctx, "prod", "plan-test", &[&issue])
            .await
            .unwrap();
        let object = env_obj(&mut ctx).await;
        assert_eq!(current(&object).unwrap(), Some(second));
        assert_eq!(previous(&object).unwrap(), Some(first.clone()));
        assert_eq!(previous_plan(&object), Some("plan-test"));
        let named = issue.issuer.as_ref().unwrap().replaces.as_ref().unwrap();
        assert_eq!(named.fingerprint, first.fingerprint);
        assert_eq!(next(&object).unwrap(), None);
        let status = status(&object).unwrap();
        assert!(status.next.is_none() && status.previous.is_some());
        // The add step applied after the issue step changes nothing.
        record_activated(&mut ctx, "prod", "plan-test", &[&add])
            .await
            .unwrap();
        assert_eq!(next(&env_obj(&mut ctx).await).unwrap(), None);
    }

    /// A runtime trusts a next issuer only through an add plan its own
    /// local policy approves, and a replaced one only through an approved
    /// issue plan: a key swapped into the approved plan, a plan of another
    /// environment, another kind of step or missing approvals are refused.
    /// A host approval policy where one approval of `alice` (ops) runs a plan.
    fn ops_fixture() -> crate::host_apply::fixture::HostFixture {
        use crate::approval_policy::{QuorumPurpose, QuorumRule};
        crate::host_apply::fixture::HostFixture::new(
            &[("alice", &["ops"])],
            vec![QuorumRule {
                purpose: QuorumPurpose::ExecutePlan,
                n: 1,
                groups: vec!["ops".into()],
                exclude_requester: false,
                min_criticality: None,
            }],
        )
    }

    /// A succeeded plan of `environment` whose one step rotates to `key`.
    fn rotation_plan(
        environment: &str,
        key: &IssuerKey,
        phase: Option<RotationPhase>,
        replaces: Option<&IssuerKey>,
        now_ms: i64,
    ) -> crate::plan::Plan {
        let mut step = issuer_step(key.clone(), None, None, phase);
        step.id = format!("plan:{environment}:step:0");
        step.issuer.as_mut().unwrap().replaces = replaces.cloned();
        crate::plan::Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: format!("plan:{environment}:{phase:?}:{}", key.generation),
            content_id: "content".into(),
            environment: environment.into(),
            created_at: now_ms,
            inputs: Vec::new(),
            steps: vec![step],
            state: crate::plan::PlanState::Succeeded,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        }
    }

    /// `plan` with alice's approval.
    fn approved(
        fixture: &crate::host_apply::fixture::HostFixture,
        plan: crate::plan::Plan,
        now_ms: i64,
    ) -> IssuerProof {
        IssuerProof {
            approvals: vec![fixture.approve(&plan, 0, now_ms)],
            plan,
            current: None,
        }
    }

    #[test]
    fn a_runtime_trusts_rotated_issuers_only_through_approved_plans() {
        let fixture = ops_fixture();
        let runtime = Runtime::new("proof");
        let now_ms = crate::now_millis();
        let next = runtime.candidate(2);
        let plan = |environment: &str, phase: Option<RotationPhase>| {
            rotation_plan(environment, &next, phase, None, now_ms)
        };
        let proof = |plan: crate::plan::Plan| approved(&fixture, plan, now_ms);
        let policy = Some(&fixture.trust.policy);
        let approved = proof(plan("prod", Some(RotationPhase::Add)));
        assert_eq!(
            verify_proof(policy, "prod", &approved, now_ms).unwrap(),
            Proven::Next(next.clone())
        );

        let mut swapped = approved.clone();
        swapped.plan.steps[0].issuer.as_mut().unwrap().key = runtime.candidate(2);
        assert!(verify_proof(policy, "prod", &swapped, now_ms).is_err());
        assert!(verify_proof(policy, "staging", &approved, now_ms).is_err());
        let first = proof(plan("prod", None));
        assert!(verify_proof(policy, "prod", &first, now_ms).is_err());
        let unapproved = IssuerProof {
            approvals: Vec::new(),
            ..approved.clone()
        };
        assert!(verify_proof(policy, "prod", &unapproved, now_ms).is_err());
        assert!(verify_proof(None, "prod", &approved, now_ms).is_err());
        // Past the approvals' expiry the proof still holds, but not once the
        // signer has left the policy.
        let year_later = now_ms + 365 * 24 * 3600 * 1000;
        verify_proof(policy, "prod", &approved, year_later).unwrap();
        let mut revoked = fixture.trust.policy.clone();
        revoked.signers.clear();
        assert!(verify_proof(Some(&revoked), "prod", &approved, year_later).is_err());

        // An approved issue step proves the issuer it replaced, and only one
        // generation back; a swapped one breaks the approval.
        let replaced = runtime.candidate(1);
        let issue = |replaces: IssuerKey| {
            rotation_plan(
                "prod",
                &next,
                Some(RotationPhase::Issue),
                Some(&replaces),
                now_ms,
            )
        };
        let approved_issue = proof(issue(replaced.clone()));
        assert_eq!(
            verify_proof(policy, "prod", &approved_issue, now_ms).unwrap(),
            Proven::Issued {
                replaced: replaced.clone(),
                issuing: next.clone()
            }
        );
        // The server's current copy lends only its wraps, and only when it
        // is the approved key.
        let mut rewrapped = next.clone();
        rewrapped
            .sealed_key
            .wraps
            .extend(Runtime::new("rewrapped").candidate(2).sealed_key.wraps);
        let with_current = |current: IssuerKey| IssuerProof {
            current: Some(current),
            ..approved_issue.clone()
        };
        assert_eq!(
            verify_proof(policy, "prod", &with_current(rewrapped.clone()), now_ms)
                .unwrap()
                .issuing(),
            Some(&rewrapped)
        );
        assert_eq!(
            verify_proof(policy, "prod", &with_current(runtime.candidate(2)), now_ms)
                .unwrap()
                .issuing(),
            Some(&next)
        );
        let mut swapped = approved_issue.clone();
        swapped.plan.steps[0].issuer.as_mut().unwrap().replaces = Some(runtime.candidate(1));
        assert!(verify_proof(policy, "prod", &swapped, now_ms).is_err());
        let skipped = proof(issue(runtime.candidate(3)));
        assert!(verify_proof(policy, "prod", &skipped, now_ms).is_err());
        let bare_issue = proof(plan("prod", Some(RotationPhase::Issue)));
        assert!(verify_proof(policy, "prod", &bare_issue, now_ms).is_err());
    }

    /// A host certificate's bundle carries a further issuer only with a
    /// kept approved plan proving it, and the host applier admits it, or a
    /// renewal moved to the next issuer, only when that plan passes its own
    /// approval policy.
    #[test]
    fn the_host_applier_admits_only_issuers_an_approved_plan_proves() {
        use crate::host_apply::sealed::{HostSealedValues, IssuerTrust};
        use crate::workload_identity::{CertificateRole, IdentityGrant, IssuedIdentity, Reload};
        let fixture = ops_fixture();
        let runtime = Runtime::new("host-bundle");
        let dir = runtime.dir.as_path();
        let now_ms = crate::now_millis();
        let (first, second) = (runtime.candidate(1), runtime.candidate(2));
        cache_verified(dir, "prod", &first).unwrap();
        // Trusted from the add step it ran, with no proof yet: workload
        // bundles carry it, host bundles do not.
        cache_trusted(dir, "prod", &second).unwrap();
        assert_eq!(
            trust_bundle(dir, "prod", &first).unwrap(),
            std::slice::from_ref(&second)
        );
        assert!(host_trust_bundle(dir, "prod", &first).unwrap().is_empty());
        let add = approved(
            &fixture,
            rotation_plan("prod", &second, Some(RotationPhase::Add), None, now_ms),
            now_ms,
        );
        cache_proof(dir, "prod", &add).unwrap();
        cache_proof(dir, "prod", &add).unwrap();
        assert_eq!(cached_proofs(dir, "prod").unwrap().len(), 1);
        assert_eq!(
            host_trust_bundle(dir, "prod", &first).unwrap(),
            std::slice::from_ref(&second)
        );

        let grant = |issuer: &IssuerKey| IdentityGrant {
            uri: "tenkai://prod/api".into(),
            dns_names: vec!["api.internal".into()],
            certificate: CertificateRole::Server,
            reload: Reload::Runtime,
            issuer_generation: issuer.generation,
            issuer_fingerprint: issuer.fingerprint.clone(),
            peers: Default::default(),
        };
        let issue = |from: &IssuerKey, beside: &IssuerKey| {
            let key = from.open("prod", &runtime.opener()).unwrap();
            crate::workload_identity::issue_trusting(
                &grant(from),
                from,
                key,
                &[beside.certificate.as_str()],
                now_ms / 1000,
            )
            .unwrap()
        };
        let spooled = |issued: &IssuedIdentity, proofs: Vec<IssuerProof>| {
            HostSealedValues::new(Vec::new(), Some(issued.into()), proofs)
        };
        let host_policy = || Ok(fixture.trust.policy.clone());
        let trust = IssuerTrust {
            policy: &host_policy,
            environment: "prod",
            now_ms,
        };
        let mut stricter = fixture.trust.policy.clone();
        stricter.signers.clear();
        let stricter_policy = || Ok(stricter.clone());
        let strict = IssuerTrust {
            policy: &stricter_policy,
            ..trust
        };

        // Before promotion: the next issuer beside the granted one.
        let issued = issue(&first, &second);
        let proofs = host_proofs(dir, "prod", &issued.ca).unwrap();
        assert_eq!(proofs.len(), 1);
        spooled(&issued, proofs.clone())
            .bind_identity(Some(&grant(&first)), &trust)
            .unwrap();
        for (values, trust) in [
            (spooled(&issued, Vec::new()), &trust),
            (spooled(&issued, proofs), &strict),
        ] {
            let error = format!(
                "{:#}",
                values
                    .bind_identity(Some(&grant(&first)), trust)
                    .unwrap_err()
            );
            assert!(error.contains("no approved rotation plan"), "{error}");
        }

        // After promotion: a renewal moves the recorded grant to the issuer
        // an approved issue plan put in place of its own, and only then.
        let promoted = approved(
            &fixture,
            rotation_plan(
                "prod",
                &second,
                Some(RotationPhase::Issue),
                Some(&first),
                now_ms,
            ),
            now_ms,
        );
        cache_proof(dir, "prod", &promoted).unwrap();
        let renewed = issue(&second, &first);
        let proofs = host_proofs(dir, "prod", &renewed.ca).unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(
            spooled(&renewed, proofs.clone())
                .bind_renewal(&grant(&first), &trust)
                .unwrap()
                .grant,
            grant(&second)
        );
        for (values, trust) in [
            (spooled(&renewed, vec![add.clone()]), &trust),
            (spooled(&renewed, proofs), &strict),
        ] {
            assert!(values.bind_renewal(&grant(&first), trust).is_err());
        }
        // A renewal from the recorded issuer still binds the recorded grant.
        let proofs = host_proofs(dir, "prod", &issued.ca).unwrap();
        assert_eq!(
            spooled(&issued, proofs)
                .bind_renewal(&grant(&first), &trust)
                .unwrap()
                .grant,
            grant(&first)
        );
    }

    /// An approved remove plan drops its issuer from this runtime's bundles
    /// and kept proofs for good, and never the issuer it issues from.
    #[test]
    fn a_removed_issuer_leaves_the_bundles_for_good() {
        let fixture = ops_fixture();
        let runtime = Runtime::new("removed");
        let dir = runtime.dir.as_path();
        let now_ms = crate::now_millis();
        let (first, second) = (runtime.candidate(1), runtime.candidate(2));
        cache_verified(dir, "prod", &second).unwrap();
        cache_trusted(dir, "prod", &first).unwrap();
        let promoted = approved(
            &fixture,
            rotation_plan(
                "prod",
                &second,
                Some(RotationPhase::Issue),
                Some(&first),
                now_ms,
            ),
            now_ms,
        );
        cache_proof(dir, "prod", &promoted).unwrap();
        assert_eq!(
            host_trust_bundle(dir, "prod", &second).unwrap(),
            std::slice::from_ref(&first)
        );
        let removal = approved(
            &fixture,
            rotation_plan("prod", &first, Some(RotationPhase::Remove), None, now_ms),
            now_ms,
        );
        let policy = Some(&fixture.trust.policy);
        assert_eq!(
            verify_proof(policy, "prod", &removal, now_ms).unwrap(),
            Proven::Removed(first.clone())
        );
        let mut swapped = removal.clone();
        swapped.plan.steps[0].issuer.as_mut().unwrap().key = runtime.candidate(1);
        assert!(verify_proof(policy, "prod", &swapped, now_ms).is_err());

        // A crash after only the removal was written: no bundle carries it.
        std::fs::write(
            removed_path(dir, "prod").unwrap(),
            serde_json::to_vec(&Removed {
                through: first.generation,
                fingerprints: vec![first.fingerprint.clone()],
            })
            .unwrap(),
        )
        .unwrap();
        assert!(host_trust_bundle(dir, "prod", &second).unwrap().is_empty());
        assert!(stored_trusted(dir, "prod").unwrap().contains(&first));

        cache_removed(dir, "prod", &first).unwrap();
        assert!(!stored_trusted(dir, "prod").unwrap().contains(&first));
        cache_removed(dir, "prod", &first).unwrap();
        assert!(trust_bundle(dir, "prod", &second).unwrap().is_empty());
        assert!(cached_proofs(dir, "prod").unwrap().is_empty());
        // A late copy of the issue plan does not bring it back.
        cache_trusted(dir, "prod", &first).unwrap();
        assert!(!trusts(dir, "prod", &first.fingerprint).unwrap());
        assert_eq!(
            cached_removed(dir, "prod").unwrap().fingerprints,
            std::slice::from_ref(&first.fingerprint)
        );
        assert!(cache_removed(dir, "prod", &second).is_err());
        // Replayed older removals neither move the boundary nor evict the
        // newest removal, so the removed issuer stays out for good.
        for generation in [0, 1].repeat(MAX_REMOVED) {
            cache_removed(dir, "prod", &runtime.candidate(generation)).unwrap();
        }
        let removed = cached_removed(dir, "prod").unwrap();
        assert_eq!(removed.through, first.generation);
        assert_eq!(
            removed.fingerprints,
            std::slice::from_ref(&first.fingerprint)
        );
        cache_trusted(dir, "prod", &runtime.candidate(1)).unwrap();
        assert!(trust_bundle(dir, "prod", &second).unwrap().is_empty());

        // A runtime that recorded the removal before any issuer never
        // issues from the removed one, even when an older proof replays.
        let fresh = Runtime::new("removed-fresh");
        cache_removed(&fresh.dir, "prod", &first).unwrap();
        cache_verified(&fresh.dir, "prod", &first).unwrap();
        assert_eq!(cached_verified(&fresh.dir, "prod").unwrap(), None);
        // Nor does one whose removal raced a write of the issuing key.
        let raced = Runtime::new("removed-raced");
        cache_verified(&raced.dir, "prod", &first).unwrap();
        std::fs::write(
            removed_path(&raced.dir, "prod").unwrap(),
            serde_json::to_vec(&Removed {
                through: first.generation,
                fingerprints: vec![first.fingerprint.clone()],
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(cached_verified(&raced.dir, "prod").unwrap(), None);
    }

    /// A runtime keeps each issuer an approved step verified, and a bundle
    /// carries only the generations next to the issuing one.
    #[test]
    fn the_trust_bundle_holds_the_neighbouring_generations() {
        let runtime = Runtime::new("bundle");
        let keys: Vec<IssuerKey> = (1..=4)
            .map(|generation| runtime.candidate(generation))
            .collect();
        for key in &keys {
            cache_trusted(&runtime.dir, "prod", key).unwrap();
        }
        cache_trusted(&runtime.dir, "prod", &keys[1]).unwrap();
        let bundle = |issuing: &IssuerKey| -> Vec<u64> {
            trust_bundle(&runtime.dir, "prod", issuing)
                .unwrap()
                .iter()
                .map(|key| key.generation)
                .collect()
        };
        // Generation 1 fell out of the cache.
        assert_eq!(bundle(&keys[1]), [3]);
        assert_eq!(bundle(&keys[2]), [2, 4]);
        assert!(
            trust_bundle(&runtime.dir, "staging", &keys[2])
                .unwrap()
                .is_empty()
        );
    }

    /// A runtime enrolled after the issuer was created cannot open it until
    /// an approved re-wrap step wraps it for its key; a wrap for an older
    /// generation is ignored.
    #[tokio::test]
    async fn a_later_runtime_gets_the_issuer_only_through_a_rewrap() {
        let mut ctx = store("rewrap").await;
        let first = Runtime::new("rewrap-first");
        let later = Runtime::new("rewrap-later");
        let key = activate_first(&mut ctx, &first).await;
        assert!(key.open("prod", &later.opener()).is_err());

        let step = rewrap_step(&env_obj(&mut ctx).await, &later.public)
            .unwrap()
            .unwrap();
        let issuer = step.issuer.as_ref().unwrap();
        let recipient = SealingPublicKey::from_wire(issuer.recipient.as_deref().unwrap()).unwrap();
        let target = SealedTarget::identity_issuer("prod", 1).unwrap();
        let wrap = RecipientWrap {
            secret: WRAP_SECRET.into(),
            key: issuer.key.wrap_key(),
            digest: issuer.key.digest("prod").unwrap(),
            wrap: first
                .opener()
                .rewrap(&target, &issuer.key.sealed_key, &recipient)
                .unwrap(),
        };
        let stale = RecipientWrap {
            key: "generation-0".into(),
            ..wrap.clone()
        };
        let mut object = env_obj(&mut ctx).await;
        add_wraps(&mut object, "prod", &[stale]).unwrap();
        assert!(
            current(&object)
                .unwrap()
                .unwrap()
                .open("prod", &later.opener())
                .is_err()
        );
        add_wraps(&mut object, "prod", &[wrap]).unwrap();
        current(&object)
            .unwrap()
            .unwrap()
            .open("prod", &later.opener())
            .unwrap();

        // Revoking the first runtime leaves the later one's wrap.
        let (changed, lost) = drop_wraps(&mut object, &first.public.fingerprint()).unwrap();
        assert!(changed && lost.is_empty(), "{lost:?}");
    }

    /// A runtime that crashes after generating a key, or after uploading
    /// it, retries without a second issuer: the first candidate is kept,
    /// the same upload again is accepted, another is refused, and a
    /// replayed activation records nothing new.
    #[tokio::test]
    async fn a_retry_after_a_crash_creates_no_second_issuer() {
        let mut ctx = store("crash").await;
        let a = Runtime::new("crash-a");
        let b = Runtime::new("crash-b");
        // Before `prepare`, a candidate is refused.
        assert!(
            store_candidate(&mut ctx, "prod", a.candidate(1), a.own())
                .await
                .is_err()
        );
        assert_eq!(request_candidate(&mut ctx, "prod").await.unwrap(), 1);
        assert_eq!(request_candidate(&mut ctx, "prod").await.unwrap(), 1);

        let kept = a.candidate(1);
        store_candidate(&mut ctx, "prod", kept.clone(), a.own())
            .await
            .unwrap();
        assert_eq!(
            store_candidate(&mut ctx, "prod", kept.clone(), a.own())
                .await
                .unwrap(),
            kept
        );
        assert!(
            store_candidate(&mut ctx, "prod", b.candidate(1), b.own())
                .await
                .is_err()
        );
        // Preparing again keeps the usable candidate.
        request_candidate(&mut ctx, "prod").await.unwrap();
        assert_eq!(wanted_generation(&env_obj(&mut ctx).await).unwrap(), None);

        let step = activation_step(&env_obj(&mut ctx).await, "prod").unwrap();
        record_activated(&mut ctx, "prod", "plan-test", &[&step])
            .await
            .unwrap();
        record_activated(&mut ctx, "prod", "plan-test", &[&step])
            .await
            .unwrap();
        let object = env_obj(&mut ctx).await;
        assert_eq!(current(&object).unwrap(), Some(kept));
        assert_eq!(candidate(&object).unwrap(), None);
        assert_eq!(requested(&object).unwrap(), None);
    }

    /// A candidate is sealed only to its uploader's own unrevoked key: one
    /// wrapped for any other key, or also for one the server named, is
    /// refused, so a server cannot have itself added as a recipient.
    #[tokio::test]
    async fn a_candidate_wrapped_for_another_key_is_refused() {
        let mut ctx = store("stranger").await;
        let runtime = Runtime::new("stranger-runtime");
        let server = Runtime::new("stranger-server");
        request_candidate(&mut ctx, "prod").await.unwrap();
        for (label, key) in [
            ("another key", server.candidate(1)),
            ("an added key", {
                let mut key = runtime.candidate(1);
                key.sealed_key
                    .wraps
                    .extend(server.candidate(1).sealed_key.wraps);
                key
            }),
        ] {
            assert!(
                store_candidate(&mut ctx, "prod", key, runtime.own())
                    .await
                    .is_err(),
                "{label}"
            );
        }
        // A revoked uploader uploads nothing.
        assert!(
            store_candidate(&mut ctx, "prod", runtime.candidate(1), || Ok(None))
                .await
                .is_err()
        );
    }

    /// A durable activation replayed after its candidate was lost and
    /// replaced records that generation as lost instead of failing forever,
    /// and drops the replacement, so the next generation is prepared.
    #[tokio::test]
    async fn an_activation_whose_candidate_was_replaced_records_a_lost_issuer() {
        let mut ctx = store("replaced").await;
        let revoked = Runtime::new("replaced-revoked");
        let replacement = Runtime::new("replaced-replacement");
        request_candidate(&mut ctx, "prod").await.unwrap();
        let approved = revoked.candidate(1);
        store_candidate(&mut ctx, "prod", approved.clone(), revoked.own())
            .await
            .unwrap();
        let step = activation_step(&env_obj(&mut ctx).await, "prod").unwrap();
        let mut object = env_obj(&mut ctx).await;
        drop_wraps(&mut object, &revoked.public.fingerprint()).unwrap();
        ctx.put(object).await.unwrap();
        store_candidate(
            &mut ctx,
            "prod",
            replacement.candidate(1),
            replacement.own(),
        )
        .await
        .unwrap();

        record_activated(&mut ctx, "prod", "plan-test", &[&step])
            .await
            .unwrap();
        let object = env_obj(&mut ctx).await;
        let recorded = current(&object).unwrap().unwrap();
        assert_eq!(recorded.fingerprint, approved.fingerprint);
        assert!(recorded.sealed_key.wraps.is_empty());
        assert_eq!(candidate(&object).unwrap(), None);
        assert_eq!(requested(&object).unwrap(), None);
    }

    /// A candidate whose only wrap a revocation dropped is lost: it is
    /// wanted again and replaced, so issuer creation never gets stuck.
    #[tokio::test]
    async fn a_lost_candidate_is_replaced() {
        let mut ctx = store("lost").await;
        let revoked = Runtime::new("lost-revoked");
        let replacement = Runtime::new("lost-replacement");
        request_candidate(&mut ctx, "prod").await.unwrap();
        store_candidate(&mut ctx, "prod", revoked.candidate(1), revoked.own())
            .await
            .unwrap();
        let mut object = env_obj(&mut ctx).await;
        let (changed, lost) = drop_wraps(&mut object, &revoked.public.fingerprint()).unwrap();
        assert!(changed && lost.len() == 1, "{lost:?}");
        assert_eq!(wanted_generation(&object).unwrap(), Some(1));
        ctx.put(object).await.unwrap();

        let fresh = replacement.candidate(1);
        store_candidate(&mut ctx, "prod", fresh.clone(), replacement.own())
            .await
            .unwrap();
        assert_eq!(candidate(&env_obj(&mut ctx).await).unwrap(), Some(fresh));
    }

    /// The runtime keeps the newest issuer it verified: a step that still
    /// carries an older generation does not replace it.
    #[test]
    fn the_cached_issuer_never_goes_back_a_generation() {
        let runtime = Runtime::new("cache");
        let (first, second) = (runtime.candidate(1), runtime.candidate(2));
        assert_eq!(cached_verified(&runtime.dir, "prod").unwrap(), None);
        cache_verified(&runtime.dir, "prod", &second).unwrap();
        cache_verified(&runtime.dir, "prod", &first).unwrap();
        assert_eq!(cached_verified(&runtime.dir, "prod").unwrap(), Some(second));
        assert_eq!(cached_verified(&runtime.dir, "staging").unwrap(), None);
    }
}
