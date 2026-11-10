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

/// The issuer as `env inspect` and `status` show it. Never a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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

/// The issuer state of an environment for inspection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IssuerStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<IssuerSummary>,
    /// The generation `prepare` asked a candidate for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<u64>,
    /// The uploaded candidate, waiting for an approved step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<IssuerSummary>,
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

/// Record the issuers that succeeded steps of `plan` activated, each as a
/// compare-and-set on the previous generation, under the environment lease.
/// The candidate's current wraps are recorded, not the step's: a recipient
/// revoked since the plan was made keeps no wrap. A replay changes nothing.
pub async fn record_activated(
    ctx: &mut Ctx,
    environment: &str,
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
            if current(&env_obj)?.is_some_and(|recorded| recorded.generation == key.generation) {
                continue;
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
            write(&mut env_obj, ISSUER_PROPERTY, &activated);
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
        issuer: Some(crate::plan::IssuerStep { key, recipient }),
        identity: None,
        restore_identity: None,
    }
}

/// The step that activates `environment`'s uploaded candidate. Refused
/// while there is none, or once it no longer is the next generation.
pub fn activation_step(env_obj: &Object, environment: &str) -> Result<crate::plan::Step> {
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
    let step = issuer_step(candidate, None, None);
    require_current(env_obj, &step)?;
    Ok(step)
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
        )
    }))
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
        let mut step = issuer_step(key.clone(), None, None);
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
        record_activated(ctx, "prod", &[&step]).await.unwrap();
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
            record_activated(&mut ctx, "prod", &[&activation(&runtime.candidate(1))])
                .await
                .unwrap_err()
        );
        assert!(error.contains("stale"), "{error}");
        // One that skips a generation.
        let skipping = activation(&runtime.candidate(3));
        assert!(require_current(&env_obj(&mut ctx).await, &skipping).is_err());
        assert_eq!(current(&env_obj(&mut ctx).await).unwrap(), Some(first));
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
        record_activated(&mut ctx, "prod", &[&step]).await.unwrap();
        record_activated(&mut ctx, "prod", &[&step]).await.unwrap();
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

        record_activated(&mut ctx, "prod", &[&step]).await.unwrap();
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
}
