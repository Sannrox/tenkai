//! Versioned two-way model-release evidence schema (ADR 0032).
//!
//! Tenkai emits runtime health and canary evidence for a model identity.
//! Chisei emits evaluation results for that same identity. Promotion refuses
//! when either side is missing, stale, or invalid. Completed `model_runtime`
//! canary and smoke results are signed and exported through the integration
//! outbox. Channel promotion consumes stored evaluation records; operators
//! install evaluation trust roots and record signed Chisei results through
//! the library, `tenkaictl eval-evidence`, or the HTTP ingest routes.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::auth_context::{AuthenticatedRequestContext, DeliveryCapability};
use crate::client::{Ctx, block_embedded};
use crate::manifest::ProductKind;
use crate::model_runtime::ModelRuntimeDescriptor;
use crate::ontology::validate_identifier;
use crate::pb::sekai::Object;
use crate::providers::{
    EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderEvent, enqueue_optional_event,
};
use crate::signature_verification::{
    decode_exact, key_id, push_len_prefixed, validate_key_id, validate_prefixed_digest,
};

pub const RUNTIME_EVIDENCE_SCHEMA: &str = "tenkai.model_runtime_evidence.v1";
pub const EVALUATION_EVIDENCE_SCHEMA: &str = "chisei.model_evaluation_evidence.v1";
pub const MODEL_RUNTIME_EVIDENCE_KIND: &str = "model_runtime_evidence";
pub const MODEL_RUNTIME_EVIDENCE_SIGNING_KEY_ENV: &str = "TENKAI_MODEL_EVIDENCE_KEY";
pub const CLOCK_SKEW_ALLOWANCE_MS: i64 = 60_000;
pub const RUNTIME_EVIDENCE_TTL_MS: i64 = 3_600_000;
const RUNTIME_EVIDENCE_DOMAIN: &[u8] = b"TENKAI-MODEL-RUNTIME-EVIDENCE-V1\0";
pub(crate) const EVALUATION_EVIDENCE_KIND: &str = "tenkai.model_evaluation_evidence";
pub(crate) const EVALUATION_TRUST_KIND: &str = "tenkai.model_evaluation_trust";
const EVALUATION_DOMAIN: &[u8] = b"TENKAI-MODEL-EVALUATION-V1\0";
const EVALUATION_TRUST_ID: &str = "tenkai:model-evaluation-trust";
const EVALUATION_TRUST_VERSION: u32 = 1;
const MAX_ENDPOINT_BYTES: usize = 512;
#[cfg(test)]
const FIXTURE_SEED: [u8; 32] = [17; 32];

/// Shared model identity for both evidence directions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelReleaseIdentity {
    pub provider: String,
    pub model: String,
    pub profile_version: String,
    pub artifact_digest: String,
    pub endpoint: String,
}

/// Tenkai → Chisei runtime health and canary evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRuntimeEvidence {
    pub schema: String,
    pub identity: ModelReleaseIdentity,
    pub release_id: String,
    pub release_digest: String,
    pub health: RuntimeHealth,
    pub canary: RuntimeCanary,
    pub observed_at: i64,
    pub expires_at: i64,
    pub signer: EvidenceSigner,
}

/// Chisei → Tenkai evaluation result for the same identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelEvaluationEvidence {
    pub schema: String,
    pub identity: ModelReleaseIdentity,
    pub eval_suite_id: String,
    pub eval_run_id: String,
    pub outcome: EvaluationOutcome,
    pub observed_at: i64,
    pub expires_at: i64,
    pub signer: EvidenceSigner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCanary {
    Passed,
    Failed,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationOutcome {
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSigner {
    pub key_id: String,
    pub signature: String,
}

/// Closed promotion-refusal vocabulary from ADR 0032.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModelReleaseEvidenceFailure {
    #[error("missing")]
    Missing,
    #[error("stale")]
    Stale,
    #[error("invalid")]
    Invalid,
}

impl ModelRuntimeEvidence {
    pub fn parse_json(value: &str) -> std::result::Result<Self, ModelReleaseEvidenceFailure> {
        let parsed: Self =
            serde_json::from_str(value).map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        parsed
            .validate()
            .map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != RUNTIME_EVIDENCE_SCHEMA {
            bail!("unsupported model runtime evidence schema {}", self.schema);
        }
        self.identity.validate()?;
        if self.release_id.is_empty() {
            bail!("runtime evidence release_id must not be empty");
        }
        validate_prefixed_digest("release_digest", &self.release_digest)?;
        validate_timestamps(self.observed_at, self.expires_at)?;
        self.signer.validate()?;
        Ok(())
    }

    fn promotion_refusal(
        &self,
        expected: &ModelReleaseIdentity,
        now_ms: i64,
    ) -> Option<ModelReleaseEvidenceFailure> {
        if self.validate().is_err() || &self.identity != expected {
            return Some(ModelReleaseEvidenceFailure::Invalid);
        }
        if is_stale(self.observed_at, self.expires_at, now_ms) {
            return Some(ModelReleaseEvidenceFailure::Stale);
        }
        if self.health != RuntimeHealth::Healthy || self.canary != RuntimeCanary::Passed {
            return Some(ModelReleaseEvidenceFailure::Invalid);
        }
        None
    }
}

impl ModelEvaluationEvidence {
    pub fn parse_json(value: &str) -> std::result::Result<Self, ModelReleaseEvidenceFailure> {
        let parsed: Self =
            serde_json::from_str(value).map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        parsed
            .validate()
            .map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        Ok(parsed)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading model evaluation evidence {}", path.display()))?;
        let evidence: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parsing model evaluation evidence {}", path.display()))?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_statement()?;
        self.signer.validate()
    }

    fn validate_statement(&self) -> Result<()> {
        if self.schema != EVALUATION_EVIDENCE_SCHEMA {
            bail!(
                "unsupported model evaluation evidence schema {}",
                self.schema
            );
        }
        self.identity.validate()?;
        validate_identifier("eval_suite_id", &self.eval_suite_id)?;
        validate_identifier("eval_run_id", &self.eval_run_id)?;
        validate_timestamps(self.observed_at, self.expires_at)?;
        validate_key_id("signer.key_id", &self.signer.key_id)?;
        Ok(())
    }

    fn promotion_refusal(
        &self,
        expected: &ModelReleaseIdentity,
        now_ms: i64,
    ) -> Option<ModelReleaseEvidenceFailure> {
        if self.validate().is_err() || &self.identity != expected {
            return Some(ModelReleaseEvidenceFailure::Invalid);
        }
        if is_stale(self.observed_at, self.expires_at, now_ms) {
            return Some(ModelReleaseEvidenceFailure::Stale);
        }
        if self.outcome != EvaluationOutcome::Passed {
            return Some(ModelReleaseEvidenceFailure::Invalid);
        }
        None
    }
}

impl ModelReleaseIdentity {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("provider", &self.provider)?;
        validate_identifier("model", &self.model)?;
        validate_identifier("profile_version", &self.profile_version)?;
        validate_prefixed_digest("artifact_digest", &self.artifact_digest)?;
        validate_endpoint(&self.endpoint)?;
        Ok(())
    }
}

impl EvidenceSigner {
    pub fn validate(&self) -> Result<()> {
        validate_key_id("signer.key_id", &self.key_id)?;
        decode_exact::<64>("signer.signature", &self.signature)
            .context("signer.signature must be a 64-byte Ed25519 signature")?;
        Ok(())
    }
}

/// Unsigned runtime observation signed before outbox enqueue.
pub struct RuntimeEvidenceDraft {
    pub identity: ModelReleaseIdentity,
    pub release_id: String,
    pub release_digest: String,
    pub health: RuntimeHealth,
    pub canary: RuntimeCanary,
    pub observed_at: i64,
    pub expires_at: i64,
}

/// Map a `model_runtime` descriptor to the public identity (no host inventory).
pub fn identity_from_descriptor(
    descriptor: &ModelRuntimeDescriptor,
) -> Result<ModelReleaseIdentity> {
    let identity = ModelReleaseIdentity {
        provider: provider_from_source(&descriptor.model.source)?,
        model: descriptor.product_name.clone(),
        profile_version: descriptor.product_version.clone(),
        artifact_digest: descriptor.model.artifact_digest.clone(),
        endpoint: format!("served://{}", descriptor.product_name),
    };
    identity.validate()?;
    Ok(identity)
}

/// Sign a runtime evidence record over the domain-separated canonical bytes.
fn identity_digest(identity: &ModelReleaseIdentity) -> Result<String> {
    identity.validate()?;
    let canonical = serde_json::to_vec(identity).context("serializing model identity")?;
    Ok(format!("{:x}", Sha256::digest(&canonical)))
}

fn evaluation_record_id(
    identity: &ModelReleaseIdentity,
    observed_at: i64,
    eval_run_id: &str,
) -> Result<String> {
    Ok(format!(
        "tenkai:model-evaluation:{}:{:020}:{eval_run_id}",
        identity_digest(identity)?,
        observed_at
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluationTrustRoots {
    pub version: u32,
    pub signers: Vec<EvaluationTrustedSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluationTrustedSigner {
    pub key_id: String,
    pub public_key: String,
}

impl EvaluationTrustRoots {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading model evaluation trust roots {}", path.display()))?;
        let roots: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing model evaluation trust roots {}", path.display()))?;
        roots.validate()?;
        Ok(roots)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != EVALUATION_TRUST_VERSION {
            bail!(
                "unsupported model evaluation trust-root version {}; expected {EVALUATION_TRUST_VERSION}",
                self.version
            );
        }
        if self.signers.is_empty() {
            bail!("model evaluation trust roots contain no signers");
        }
        let mut key_ids = std::collections::BTreeSet::new();
        for signer in &self.signers {
            crate::signature_verification::validate_key_id(
                "model evaluation signer key id",
                &signer.key_id,
            )?;
            if !key_ids.insert(&signer.key_id) {
                bail!(
                    "model evaluation trust roots contain duplicate key id {}",
                    signer.key_id
                );
            }
            crate::signature_verification::trusted_key(
                "model evaluation public key",
                &signer.public_key,
                &signer.key_id,
            )?;
        }
        Ok(())
    }
}

fn canonical_evaluation_bytes(evidence: &ModelEvaluationEvidence) -> Result<Vec<u8>> {
    evidence.validate_statement()?;
    let mut bytes = EVALUATION_DOMAIN.to_vec();
    for value in [
        evidence.schema.as_bytes(),
        evidence.identity.provider.as_bytes(),
        evidence.identity.model.as_bytes(),
        evidence.identity.profile_version.as_bytes(),
        evidence.identity.artifact_digest.as_bytes(),
        evidence.identity.endpoint.as_bytes(),
        evidence.eval_suite_id.as_bytes(),
        evidence.eval_run_id.as_bytes(),
        match evidence.outcome {
            EvaluationOutcome::Passed => b"passed".as_slice(),
            EvaluationOutcome::Failed => b"failed".as_slice(),
        },
        evidence.signer.key_id.as_bytes(),
    ] {
        push_len_prefixed(&mut bytes, value);
    }
    bytes.extend_from_slice(&evidence.observed_at.to_be_bytes());
    bytes.extend_from_slice(&evidence.expires_at.to_be_bytes());
    Ok(bytes)
}

#[cfg(test)]
fn sign_evaluation(evidence: &mut ModelEvaluationEvidence, signing_key: &SigningKey) -> Result<()> {
    let public = signing_key.verifying_key().to_bytes();
    evidence.signer.key_id = key_id(&public);
    let signature = signing_key.sign(&canonical_evaluation_bytes(evidence)?);
    evidence.signer.signature = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes(),
    );
    Ok(())
}

fn verify_evaluation_signature(
    evidence: &ModelEvaluationEvidence,
    roots: &EvaluationTrustRoots,
) -> Result<()> {
    roots.validate()?;
    let signer = roots
        .signers
        .iter()
        .find(|signer| signer.key_id == evidence.signer.key_id)
        .context("model evaluation signer is not currently trusted")?;
    let key = crate::signature_verification::trusted_key(
        "model evaluation public key",
        &signer.public_key,
        &signer.key_id,
    )?;
    crate::signature_verification::verify_strict(
        &key,
        "model evaluation signature",
        &evidence.signer.signature,
        &canonical_evaluation_bytes(evidence)?,
    )
}

async fn load_evaluation_trust_roots(ctx: &mut Ctx) -> Result<Option<EvaluationTrustRoots>> {
    let Some(record) = ctx.get(EVALUATION_TRUST_ID).await? else {
        return Ok(None);
    };
    if record.kind != EVALUATION_TRUST_KIND {
        bail!("model evaluation trust object has the wrong kind");
    }
    let raw = record
        .properties
        .get("roots")
        .context("model evaluation trust object is missing roots")?;
    let roots: EvaluationTrustRoots = serde_json::from_str(raw)?;
    roots.validate()?;
    Ok(Some(roots))
}

/// Install or replace the trusted Ed25519 signers for evaluation records.
pub async fn install_evaluation_trust_roots(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    roots: &EvaluationTrustRoots,
) -> Result<()> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    roots.validate()?;
    let now = crate::now_millis();
    let record = Object {
        id: EVALUATION_TRUST_ID.into(),
        kind: EVALUATION_TRUST_KIND.into(),
        namespace: crate::ontology::NS.into(),
        name: EVALUATION_TRUST_ID.into(),
        properties: HashMap::from([("roots".into(), serde_json::to_string(roots)?)]),
        created: now,
        updated: now,
        ..Default::default()
    };
    match ctx.create_once(record.clone()).await {
        Ok(_) => Ok(()),
        Err(status) if crate::client::is_unique_conflict(&status) => {
            ctx.put(record).await?;
            Ok(())
        }
        Err(status) => Err(status.into()),
    }
}

#[cfg(test)]
async fn ensure_fixture_evaluation_trust(ctx: &mut Ctx) -> Result<SigningKey> {
    let signing_key = SigningKey::from_bytes(&FIXTURE_SEED);
    let public = signing_key.verifying_key().to_bytes();
    let roots = EvaluationTrustRoots {
        version: EVALUATION_TRUST_VERSION,
        signers: vec![EvaluationTrustedSigner {
            key_id: key_id(&public),
            public_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public),
        }],
    };
    let actor = crate::auth_context::test_management_context("eval-trust-fixture");
    install_evaluation_trust_roots(ctx, &actor, &roots).await?;
    Ok(signing_key)
}

#[cfg(test)]
fn signed_fixture_evaluation(
    identity: ModelReleaseIdentity,
    outcome: EvaluationOutcome,
    observed_at: i64,
    expires_at: i64,
    signing_key: &SigningKey,
) -> Result<ModelEvaluationEvidence> {
    let mut evidence = ModelEvaluationEvidence {
        schema: EVALUATION_EVIDENCE_SCHEMA.into(),
        identity,
        eval_suite_id: "model-quality".into(),
        eval_run_id: "fixture-run".into(),
        outcome,
        observed_at,
        expires_at,
        signer: EvidenceSigner {
            key_id: String::new(),
            signature: String::new(),
        },
    };
    sign_evaluation(&mut evidence, signing_key)?;
    Ok(evidence)
}

/// Persist an immutable evaluation record for one model identity.
pub async fn record_evaluation_evidence(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    evidence: ModelEvaluationEvidence,
) -> Result<()> {
    actor
        .require_delivery_capability(DeliveryCapability::Publish)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if !actor.product_bindings().is_empty()
        && !actor.product_bindings().contains(&evidence.identity.model)
    {
        bail!("product is outside the publication grant");
    }
    evidence.validate()?;
    let roots = load_evaluation_trust_roots(ctx)
        .await?
        .context("model evaluation trust roots are not installed")?;
    verify_evaluation_signature(&evidence, &roots)?;
    let raw = serde_json::to_string(&evidence)?;
    if raw.len() > 64 * 1024 {
        bail!("model evaluation evidence exceeds 64 KiB");
    }
    let digest = identity_digest(&evidence.identity)?;
    let id = evaluation_record_id(
        &evidence.identity,
        evidence.observed_at,
        &evidence.eval_run_id,
    )?;
    let now = crate::now_millis();
    let record = Object {
        id: id.clone(),
        kind: EVALUATION_EVIDENCE_KIND.into(),
        namespace: crate::ontology::NS.into(),
        name: id.clone(),
        properties: HashMap::from([
            ("identity_digest".into(), digest),
            (
                "observed_at_order".into(),
                format!("{:020}", evidence.observed_at),
            ),
            ("evidence".into(), raw.clone()),
        ]),
        created: now,
        updated: now,
        ..Default::default()
    };
    match ctx.create_once(record).await {
        Ok(_) => Ok(()),
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let existing = ctx
                .get(&id)
                .await?
                .context("conflicting model evaluation evidence disappeared")?;
            if existing.properties.get("evidence") == Some(&raw) {
                Ok(())
            } else {
                bail!("conflicting model evaluation evidence at the same observation time");
            }
        }
        Err(status) => Err(status.into()),
    }
}

enum LoadedEvaluation {
    Missing,
    Invalid,
    Record(Box<ModelEvaluationEvidence>),
}

async fn load_evaluation_for_promotion(
    ctx: &mut Ctx,
    identity: &ModelReleaseIdentity,
) -> Result<LoadedEvaluation> {
    let digest = identity_digest(identity)?;
    let records = ctx
        .find_by_property(EVALUATION_EVIDENCE_KIND, "identity_digest", &digest)
        .await?;
    if records.is_empty() {
        return Ok(LoadedEvaluation::Missing);
    }
    let mut newest: Vec<ModelEvaluationEvidence> = Vec::new();
    let mut newest_at = i64::MIN;
    for record in records {
        if record.kind != EVALUATION_EVIDENCE_KIND {
            return Ok(LoadedEvaluation::Invalid);
        }
        let Some(raw) = record.properties.get("evidence") else {
            return Ok(LoadedEvaluation::Invalid);
        };
        let Ok(evidence) = ModelEvaluationEvidence::parse_json(raw) else {
            return Ok(LoadedEvaluation::Invalid);
        };
        if evidence.identity != *identity {
            return Ok(LoadedEvaluation::Invalid);
        }
        match evidence.observed_at.cmp(&newest_at) {
            std::cmp::Ordering::Greater => {
                newest_at = evidence.observed_at;
                newest = vec![evidence];
            }
            std::cmp::Ordering::Equal => newest.push(evidence),
            std::cmp::Ordering::Less => {}
        }
    }
    match newest.as_slice() {
        [only] => Ok(LoadedEvaluation::Record(Box::new(only.clone()))),
        [] => Ok(LoadedEvaluation::Missing),
        _ => Ok(LoadedEvaluation::Invalid),
    }
}

/// Admit a model-runtime channel promotion from the Chisei evaluation half.
pub fn admit_model_evaluation_evidence(
    evaluation: Option<&ModelEvaluationEvidence>,
    expected: &ModelReleaseIdentity,
    now_ms: i64,
) -> std::result::Result<(), ModelReleaseEvidenceFailure> {
    let Some(evaluation) = evaluation else {
        return Err(ModelReleaseEvidenceFailure::Missing);
    };
    match evaluation.promotion_refusal(expected, now_ms) {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

/// Channel promotion of `model_runtime` requires a passing, fresh eval record.
pub async fn require_published_model_evaluation(ctx: &mut Ctx, release: &Object) -> Result<()> {
    let Some(raw) = release.properties.get("manifest") else {
        return Ok(());
    };
    let manifest = crate::manifest::parse_raw(raw)?;
    if manifest.product.kind != ProductKind::ModelRuntime {
        return Ok(());
    }
    let descriptor = ModelRuntimeDescriptor::from_manifest(&manifest)?;
    let expected = identity_from_descriptor(&descriptor)?;
    let blocked = |failure: ModelReleaseEvidenceFailure| {
        anyhow::anyhow!("model evaluation promotion blocked: {failure}")
    };
    let evidence = match load_evaluation_for_promotion(ctx, &expected).await? {
        LoadedEvaluation::Missing => return Err(blocked(ModelReleaseEvidenceFailure::Missing)),
        LoadedEvaluation::Invalid => return Err(blocked(ModelReleaseEvidenceFailure::Invalid)),
        LoadedEvaluation::Record(evidence) => *evidence,
    };
    let Some(roots) = load_evaluation_trust_roots(ctx).await? else {
        return Err(blocked(ModelReleaseEvidenceFailure::Invalid));
    };
    if verify_evaluation_signature(&evidence, &roots).is_err() {
        return Err(blocked(ModelReleaseEvidenceFailure::Invalid));
    }
    admit_model_evaluation_evidence(Some(&evidence), &expected, crate::now_millis())
        .map_err(blocked)
}

/// Test helper: store a passing, fresh eval for a published release.
#[cfg(test)]
pub async fn record_passing_evaluation_for_release(ctx: &mut Ctx, spec: &str) -> Result<()> {
    let Some((product, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    let release = ctx
        .get(&crate::ontology::release_id(product, version))
        .await?
        .with_context(|| format!("release {spec} is not published"))?;
    let raw = release
        .properties
        .get("manifest")
        .context("published release is missing its manifest")?;
    let descriptor = ModelRuntimeDescriptor::from_manifest(&crate::manifest::parse_raw(raw)?)?;
    let identity = identity_from_descriptor(&descriptor)?;
    let signing_key = ensure_fixture_evaluation_trust(ctx).await?;
    let now = crate::now_millis();
    let actor = crate::auth_context::test_management_context("eval-record-fixture");
    record_evaluation_evidence(
        ctx,
        &actor,
        signed_fixture_evaluation(
            identity,
            EvaluationOutcome::Passed,
            now,
            now.saturating_add(3_600_000),
            &signing_key,
        )?,
    )
    .await
}

pub fn sign_runtime_evidence(
    draft: RuntimeEvidenceDraft,
    key: &SigningKey,
) -> Result<ModelRuntimeEvidence> {
    let release_digest = prefixed_digest("release_digest", &draft.release_digest)?;
    let mut evidence = ModelRuntimeEvidence {
        schema: RUNTIME_EVIDENCE_SCHEMA.into(),
        identity: draft.identity,
        release_id: draft.release_id,
        release_digest,
        health: draft.health,
        canary: draft.canary,
        observed_at: draft.observed_at,
        expires_at: draft.expires_at,
        signer: EvidenceSigner {
            key_id: key_id(&key.verifying_key().to_bytes()),
            signature: String::new(),
        },
    };
    evidence.identity.validate()?;
    if evidence.release_id.is_empty() {
        bail!("runtime evidence release_id must not be empty");
    }
    validate_timestamps(evidence.observed_at, evidence.expires_at)?;
    let canonical = canonical_runtime_evidence_bytes(&evidence)?;
    evidence.signer.signature = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        key.sign(&canonical).to_bytes(),
    );
    evidence.validate()?;
    Ok(evidence)
}

/// Build a provider outbox event whose payload is the part-1 runtime record.
pub fn runtime_evidence_event(
    evidence: &ModelRuntimeEvidence,
    environment_id: &str,
    plan_digest: &str,
    configuration_digest: &str,
) -> Result<ProviderEvent> {
    evidence.validate()?;
    let payload_json = serde_json::to_string(evidence)?;
    let binding = EvidenceBinding {
        contract_version: PROVIDER_CONTRACT_VERSION,
        release_digest: evidence.release_digest.clone(),
        plan_digest: plan_digest.into(),
        configuration_digest: configuration_digest.into(),
        environment_id: environment_id.into(),
    };
    binding.validate().map_err(anyhow::Error::from)?;
    let event = ProviderEvent {
        id: runtime_evidence_event_id(&binding, &payload_json),
        binding,
        payload_json,
        collected_at_ms: None,
        source_sequence: None,
    };
    event.validate().map_err(anyhow::Error::from)?;
    Ok(event)
}

/// Enqueue a signed runtime evidence record into the integration outbox.
pub fn enqueue_runtime_evidence(
    store: &impl crate::provider_event::ProviderEventStore,
    evidence: &ModelRuntimeEvidence,
    environment_id: &str,
    plan_digest: &str,
    configuration_digest: &str,
    now: i64,
) -> Result<()> {
    let event =
        runtime_evidence_event(evidence, environment_id, plan_digest, configuration_digest)?;
    enqueue_optional_event(store, MODEL_RUNTIME_EVIDENCE_KIND, &event, now)
        .map_err(anyhow::Error::from)
}

/// Inputs for exporting one completed canary or smoke observation.
pub(crate) struct CompletedRuntimeExport<'a> {
    pub descriptor: &'a ModelRuntimeDescriptor,
    pub release_id: &'a str,
    pub release_digest: &'a str,
    pub environment: &'a str,
    pub plan_digest: &'a str,
    pub health: RuntimeHealth,
    pub canary: RuntimeCanary,
    pub observed_at: i64,
}

/// Export a completed canary or smoke observation when outcome export is armed.
pub(crate) async fn export_completed_runtime_evidence(
    ctx: &mut Ctx,
    export: CompletedRuntimeExport<'_>,
) -> Result<()> {
    if !ctx.outcome_export_enabled() {
        return Ok(());
    }
    let Some(key) = signing_key_from_env()? else {
        return Ok(());
    };
    let Some(store) = ctx.embedded_arc() else {
        return Ok(());
    };
    let environment_object = ctx
        .get(&crate::ontology::env_id(export.environment))
        .await?
        .with_context(|| {
            format!(
                "environment {} disappeared during model runtime evidence export",
                export.environment
            )
        })?;
    let identity = identity_from_descriptor(export.descriptor)?;
    let evidence = sign_runtime_evidence(
        RuntimeEvidenceDraft {
            identity,
            release_id: export.release_id.into(),
            release_digest: export.release_digest.into(),
            health: export.health,
            canary: export.canary,
            observed_at: export.observed_at,
            expires_at: export.observed_at.saturating_add(RUNTIME_EVIDENCE_TTL_MS),
        },
        &key,
    )?;
    let configuration_digest =
        crate::providers::environment_configuration_digest(&environment_object);
    let environment_id = environment_object.id.clone();
    let plan_digest = export.plan_digest.to_string();
    let observed_at = export.observed_at;
    block_embedded(store, move |store| {
        enqueue_runtime_evidence(
            store,
            &evidence,
            &environment_id,
            &plan_digest,
            &configuration_digest,
            observed_at.max(1),
        )
    })
    .await
}

pub(crate) fn descriptor_from_release_object(
    release: &Object,
) -> Result<Option<ModelRuntimeDescriptor>> {
    let Some(raw) = release
        .properties
        .get("manifest")
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let manifest = crate::manifest::parse_raw(raw)?;
    if manifest.product.kind != crate::manifest::ProductKind::ModelRuntime {
        return Ok(None);
    }
    Ok(Some(ModelRuntimeDescriptor::from_manifest(&manifest)?))
}

pub(crate) fn signing_key_from_env() -> Result<Option<SigningKey>> {
    let Some(path) = std::env::var_os(MODEL_RUNTIME_EVIDENCE_SIGNING_KEY_ENV) else {
        return Ok(None);
    };
    Ok(Some(signing_key_from_path(Path::new(&path))?))
}

pub(crate) fn signing_key_from_path(path: &Path) -> Result<SigningKey> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting model evidence key {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "model evidence key {} must not be a symlink",
            path.display()
        );
    }
    if !meta.file_type().is_file() {
        bail!(
            "model evidence key {} must be a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "model evidence key {} must be owner-only; found {:o}",
                path.display(),
                mode
            );
        }
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading model evidence key {}", path.display()))?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "model evidence key {} must be exactly 32 bytes (got {})",
            path.display(),
            bytes.len()
        )
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Refuse promotion unless both directions are present, fresh, and passing.
pub fn evaluate_model_release_promotion(
    runtime: Option<&ModelRuntimeEvidence>,
    evaluation: Option<&ModelEvaluationEvidence>,
    expected: &ModelReleaseIdentity,
    now_ms: i64,
) -> std::result::Result<(), ModelReleaseEvidenceFailure> {
    let Some(runtime) = runtime else {
        return Err(ModelReleaseEvidenceFailure::Missing);
    };
    let Some(evaluation) = evaluation else {
        return Err(ModelReleaseEvidenceFailure::Missing);
    };
    if let Some(failure) = runtime.promotion_refusal(expected, now_ms) {
        return Err(failure);
    }
    if let Some(failure) = evaluation.promotion_refusal(expected, now_ms) {
        return Err(failure);
    }
    Ok(())
}

fn validate_endpoint(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES || value.chars().any(char::is_control) {
        bail!("endpoint is empty, oversized, or contains control characters");
    }
    let parsed = url::Url::parse(value).context("endpoint must be an absolute URI")?;
    if parsed.cannot_be_a_base() {
        bail!("endpoint must be an absolute URI");
    }
    Ok(())
}

fn validate_timestamps(observed_at: i64, expires_at: i64) -> Result<()> {
    if observed_at <= 0 || expires_at <= observed_at {
        bail!("evidence timestamps must be positive and expire after observation");
    }
    Ok(())
}

fn is_stale(observed_at: i64, expires_at: i64, now_ms: i64) -> bool {
    observed_at > now_ms.saturating_add(CLOCK_SKEW_ALLOWANCE_MS) || expires_at <= now_ms
}

fn provider_from_source(source: &str) -> Result<String> {
    let provider = if source.starts_with("hf://") {
        "huggingface"
    } else if source.starts_with("oci://") {
        "oci"
    } else if source.starts_with("file://") {
        "file"
    } else if source.starts_with("http://") || source.starts_with("https://") {
        "http"
    } else {
        bail!("unsupported model.source scheme for runtime evidence identity");
    };
    Ok(provider.into())
}

fn prefixed_digest(label: &str, value: &str) -> Result<String> {
    let prefixed = if value.starts_with("sha256:") {
        value.to_string()
    } else {
        format!("sha256:{value}")
    };
    validate_prefixed_digest(label, &prefixed)?;
    Ok(prefixed)
}

fn health_label(health: RuntimeHealth) -> &'static str {
    match health {
        RuntimeHealth::Healthy => "healthy",
        RuntimeHealth::Unhealthy => "unhealthy",
        RuntimeHealth::Unknown => "unknown",
    }
}

fn canary_label(canary: RuntimeCanary) -> &'static str {
    match canary {
        RuntimeCanary::Passed => "passed",
        RuntimeCanary::Failed => "failed",
        RuntimeCanary::Incomplete => "incomplete",
    }
}

fn canonical_runtime_evidence_bytes(evidence: &ModelRuntimeEvidence) -> Result<Vec<u8>> {
    let mut bytes = RUNTIME_EVIDENCE_DOMAIN.to_vec();
    for value in [
        evidence.schema.as_bytes(),
        evidence.identity.provider.as_bytes(),
        evidence.identity.model.as_bytes(),
        evidence.identity.profile_version.as_bytes(),
        evidence.identity.artifact_digest.as_bytes(),
        evidence.identity.endpoint.as_bytes(),
        evidence.release_id.as_bytes(),
        evidence.release_digest.as_bytes(),
        health_label(evidence.health).as_bytes(),
        canary_label(evidence.canary).as_bytes(),
        evidence.signer.key_id.as_bytes(),
    ] {
        push_len_prefixed(&mut bytes, value);
    }
    bytes.extend_from_slice(&evidence.observed_at.to_be_bytes());
    bytes.extend_from_slice(&evidence.expires_at.to_be_bytes());
    Ok(bytes)
}

pub(crate) fn smoke_plan_digest(environment: &str, release_id: &str) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(format!("tenkai.model_runtime.smoke:{environment}:{release_id}").as_bytes())
    )
}

fn runtime_evidence_event_id(binding: &EvidenceBinding, payload_json: &str) -> String {
    let binding_digest = binding.digest();
    let mut identity = Sha256::new();
    for value in [binding_digest.as_str(), payload_json] {
        identity.update((value.len() as u64).to_le_bytes());
        identity.update(value.as_bytes());
    }
    format!("tenkai:model-runtime-evidence:v1:{:x}", identity.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::OperationalStore;

    const RUNTIME_EXAMPLE: &str =
        include_str!("../docs/examples/model-release-evidence/runtime-health.json");
    const EVALUATION_EXAMPLE: &str =
        include_str!("../docs/examples/model-release-evidence/evaluation-result.json");
    const NOW_MS: i64 = 1_700_000_100_000;

    fn expected_identity() -> ModelReleaseIdentity {
        ModelRuntimeEvidence::parse_json(RUNTIME_EXAMPLE)
            .expect("runtime example")
            .identity
    }

    #[test]
    fn example_records_validate_and_admit_promotion() {
        let runtime = ModelRuntimeEvidence::parse_json(RUNTIME_EXAMPLE).expect("runtime example");
        let evaluation =
            ModelEvaluationEvidence::parse_json(EVALUATION_EXAMPLE).expect("evaluation example");
        assert_eq!(runtime.schema, RUNTIME_EVIDENCE_SCHEMA);
        assert_eq!(evaluation.schema, EVALUATION_EVIDENCE_SCHEMA);
        assert_eq!(runtime.identity, evaluation.identity);
        evaluate_model_release_promotion(
            Some(&runtime),
            Some(&evaluation),
            &runtime.identity,
            NOW_MS,
        )
        .expect("fresh passing examples admit promotion");
        let runtime_again: ModelRuntimeEvidence =
            serde_json::from_str(&serde_json::to_string(&runtime).unwrap()).unwrap();
        let evaluation_again: ModelEvaluationEvidence =
            serde_json::from_str(&serde_json::to_string(&evaluation).unwrap()).unwrap();
        assert_eq!(runtime, runtime_again);
        assert_eq!(evaluation, evaluation_again);
    }

    #[test]
    fn unknown_fields_and_unknown_schema_are_invalid() {
        let mutated = RUNTIME_EXAMPLE.replacen(
            r#""schema": "tenkai.model_runtime_evidence.v1""#,
            r#""schema": "tenkai.model_runtime_evidence.v1", "extra": true"#,
            1,
        );
        assert_eq!(
            ModelRuntimeEvidence::parse_json(&mutated).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
        let unknown_schema =
            RUNTIME_EXAMPLE.replace(RUNTIME_EVIDENCE_SCHEMA, "tenkai.model_runtime_evidence.v0");
        assert_eq!(
            ModelRuntimeEvidence::parse_json(&unknown_schema).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
        let mutated_eval = EVALUATION_EXAMPLE.replacen(
            r#""outcome": "passed""#,
            r#""outcome": "passed", "score": 1"#,
            1,
        );
        assert_eq!(
            ModelEvaluationEvidence::parse_json(&mutated_eval).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }

    #[test]
    fn promotion_refuses_missing_stale_and_invalid_evidence() {
        let runtime = ModelRuntimeEvidence::parse_json(RUNTIME_EXAMPLE).unwrap();
        let evaluation = ModelEvaluationEvidence::parse_json(EVALUATION_EXAMPLE).unwrap();
        let expected = expected_identity();

        assert_eq!(
            evaluate_model_release_promotion(None, Some(&evaluation), &expected, NOW_MS)
                .unwrap_err(),
            ModelReleaseEvidenceFailure::Missing
        );
        assert_eq!(
            evaluate_model_release_promotion(Some(&runtime), None, &expected, NOW_MS).unwrap_err(),
            ModelReleaseEvidenceFailure::Missing
        );

        let mut stale = runtime.clone();
        stale.expires_at = NOW_MS;
        assert_eq!(
            evaluate_model_release_promotion(Some(&stale), Some(&evaluation), &expected, NOW_MS)
                .unwrap_err(),
            ModelReleaseEvidenceFailure::Stale
        );

        let mut failed = runtime.clone();
        failed.canary = RuntimeCanary::Failed;
        assert_eq!(
            evaluate_model_release_promotion(Some(&failed), Some(&evaluation), &expected, NOW_MS)
                .unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );

        let mut mismatched = expected.clone();
        mismatched.model = "other-model".into();
        assert_eq!(
            evaluate_model_release_promotion(
                Some(&runtime),
                Some(&evaluation),
                &mismatched,
                NOW_MS
            )
            .unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }

    #[test]
    fn identity_rejects_unschemed_endpoints() {
        let mut identity = expected_identity();
        identity.endpoint = "gpu-node-3".into();
        assert!(identity.validate().is_err());
        identity.endpoint = "served://qwen-coder".into();
        identity.validate().unwrap();
    }

    fn sample_descriptor() -> ModelRuntimeDescriptor {
        let manifest = crate::manifest::parse_raw(
            r#"
[product]
name = "qwen-coder"
version = "v1"
kind = "model_runtime"
description = "export fixture"

[model]
source = "hf://example/qwen-coder/qwen-coder.gguf"
revision = "0123456789abcdef0123456789abcdef01234567"
format = "gguf"
quantization = "Q4_K_M"
artifact_digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
license = "apache-2.0"

[runtime]
engine = "llama.cpp"
port = 18080
context_length = 4096

[requirements]
architecture = ["arm64"]
memory_gib = 8

[health]
endpoint = "http://127.0.0.1:18080/v1/models"
smoke_prompt = "OK"
max_startup_seconds = 30
"#,
        )
        .expect("fixture manifest");
        ModelRuntimeDescriptor::from_manifest(&manifest).expect("fixture descriptor")
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[23; 32])
    }

    fn signed_outcome(health: RuntimeHealth, canary: RuntimeCanary) -> ModelRuntimeEvidence {
        let identity = identity_from_descriptor(&sample_descriptor()).unwrap();
        sign_runtime_evidence(
            RuntimeEvidenceDraft {
                identity,
                release_id: "tenkai:release:qwen-coder@v1".into(),
                release_digest: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .into(),
                health,
                canary,
                observed_at: NOW_MS,
                expires_at: NOW_MS + RUNTIME_EVIDENCE_TTL_MS,
            },
            &test_signing_key(),
        )
        .unwrap()
    }

    fn assert_no_host_inventory_or_secrets(json: &str) {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        fn walk(value: &serde_json::Value) {
            match value {
                serde_json::Value::String(text) => {
                    assert!(
                        !text.contains("127.0.0.1")
                            && !text.contains("localhost")
                            && !text.contains("0.0.0.0")
                            && !text.contains("gpu-node")
                            && !text.contains("password")
                            && !text.contains("credential")
                            && !text.contains("huggingface.co"),
                        "runtime evidence leaked inventory or secret material: {text}"
                    );
                }
                serde_json::Value::Array(values) => values.iter().for_each(walk),
                serde_json::Value::Object(fields) => {
                    for (key, nested) in fields {
                        assert!(
                            !key.contains("password")
                                && !key.contains("token")
                                && !key.contains("secret")
                                && !key.contains("credential"),
                            "runtime evidence leaked secret field {key}"
                        );
                        walk(nested);
                    }
                }
                _ => {}
            }
        }
        walk(&value);
    }

    #[test]
    fn identity_from_descriptor_is_opaque_serving_uri() {
        let identity = identity_from_descriptor(&sample_descriptor()).unwrap();
        assert_eq!(identity.provider, "huggingface");
        assert_eq!(identity.model, "qwen-coder");
        assert_eq!(identity.profile_version, "v1");
        assert_eq!(identity.endpoint, "served://qwen-coder");
        assert!(!identity.endpoint.contains("127.0.0.1"));
    }

    #[test]
    fn outbox_exports_passing_and_failed_runtime_evidence() {
        let store = crate::storage::SqliteStore::open_in_memory().unwrap();
        let passing = signed_outcome(RuntimeHealth::Healthy, RuntimeCanary::Passed);
        let failed = signed_outcome(RuntimeHealth::Unhealthy, RuntimeCanary::Failed);
        enqueue_runtime_evidence(
            &store,
            &passing,
            "tenkai:env:local",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            NOW_MS,
        )
        .unwrap();
        enqueue_runtime_evidence(
            &store,
            &failed,
            "tenkai:env:local",
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            NOW_MS,
        )
        .unwrap();
        let records = store
            .list_provider_events(MODEL_RUNTIME_EVIDENCE_KIND, "tenkai:env:local", 16)
            .unwrap();
        assert_eq!(records.len(), 2);
        let mut parsed = records
            .iter()
            .map(|record| {
                let event: ProviderEvent = serde_json::from_str(&record.payload_json).unwrap();
                assert_no_host_inventory_or_secrets(&event.payload_json);
                ModelRuntimeEvidence::parse_json(&event.payload_json).expect("part-1 schema")
            })
            .collect::<Vec<_>>();
        parsed.sort_by_key(|evidence| match evidence.canary {
            RuntimeCanary::Passed => 0,
            RuntimeCanary::Incomplete => 1,
            RuntimeCanary::Failed => 2,
        });
        assert_eq!(parsed[0].health, RuntimeHealth::Healthy);
        assert_eq!(parsed[0].canary, RuntimeCanary::Passed);
        assert_eq!(parsed[1].health, RuntimeHealth::Unhealthy);
        assert_eq!(parsed[1].canary, RuntimeCanary::Failed);
        assert_eq!(parsed[0].schema, RUNTIME_EVIDENCE_SCHEMA);
        assert_eq!(parsed[1].identity, parsed[0].identity);
    }
    fn write_model(dir: &std::path::Path, product: &str, version: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"[product]
name = "{product}"
version = "{version}"
kind = "model_runtime"
description = "eval-gate fixture"
[model]
source = "hf://example/{product}/{product}.gguf"
revision = "0123456789abcdef0123456789abcdef01234567"
format = "gguf"
quantization = "Q4_K_M"
artifact_digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
license = "apache-2.0"
[runtime]
engine = "llama.cpp"
port = 18080
context_length = 4096
[requirements]
architecture = ["arm64"]
memory_gib = 8
accelerator = ["cpu"]
[health]
endpoint = "http://127.0.0.1:18080/v1/models"
max_startup_seconds = 30
"#
            ),
        )
        .unwrap();
    }

    fn write_software(dir: &std::path::Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            r#"[product]
name = "edge-app"
version = "1.0.0"
kind = "software"
[deploy]
workdir = "."
install = "true"
uninstall = "true"
"#,
        )
        .unwrap();
    }

    async fn published_ctx(root: &std::path::Path, product: &str, version: &str) -> Ctx {
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        write_model(&root.join("model"), product, version);
        let options = crate::catalog::PublishOptions {
            signature: None,
            trust_roots: None,
            allow_unsigned_development: true,
            provenance: Vec::new(),
            provenance_trust_roots: None,
            change_set_evidence: None,
            artifact_registry: None,
        };
        crate::catalog::publish(&mut ctx, &root.join("model/tenkai.toml"), &options)
            .await
            .unwrap();
        ctx
    }

    #[tokio::test]
    async fn model_runtime_promote_requires_fresh_passing_eval() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-model-eval-gate-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let mut ctx = published_ctx(&root, "qwen-eval", "1.0.0").await;
        let actor = crate::auth_context::test_management_context("model-eval-gate");
        let missing = crate::catalog::promote(&mut ctx, &actor, "qwen-eval@1.0.0", "stable")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("model evaluation promotion blocked: missing"),
            "{missing}"
        );

        let release = ctx
            .get(&crate::ontology::release_id("qwen-eval", "1.0.0"))
            .await
            .unwrap()
            .unwrap();
        let descriptor = ModelRuntimeDescriptor::from_manifest(
            &crate::manifest::parse_raw(release.properties.get("manifest").unwrap()).unwrap(),
        )
        .unwrap();
        let identity = identity_from_descriptor(&descriptor).unwrap();
        let signing_key = ensure_fixture_evaluation_trust(&mut ctx).await.unwrap();
        let now = crate::now_millis();
        record_evaluation_evidence(
            &mut ctx,
            &actor,
            signed_fixture_evaluation(
                identity.clone(),
                EvaluationOutcome::Passed,
                now.saturating_sub(1_000),
                now,
                &signing_key,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let stale = crate::catalog::promote(&mut ctx, &actor, "qwen-eval@1.0.0", "stable")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            stale.contains("model evaluation promotion blocked: stale"),
            "{stale}"
        );

        record_evaluation_evidence(
            &mut ctx,
            &actor,
            signed_fixture_evaluation(
                identity.clone(),
                EvaluationOutcome::Failed,
                now,
                now + 3_600_000,
                &signing_key,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let failed = crate::catalog::promote(&mut ctx, &actor, "qwen-eval@1.0.0", "stable")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            failed.contains("model evaluation promotion blocked: invalid"),
            "{failed}"
        );

        let mut forged = signed_fixture_evaluation(
            identity.clone(),
            EvaluationOutcome::Passed,
            now + 1,
            now + 3_600_000,
            &signing_key,
        )
        .unwrap();
        forged.signer.signature =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
        assert!(
            record_evaluation_evidence(&mut ctx, &actor, forged)
                .await
                .unwrap_err()
                .to_string()
                .contains("model evaluation signature"),
        );

        record_passing_evaluation_for_release(&mut ctx, "qwen-eval@1.0.0")
            .await
            .unwrap();
        let admitted = crate::catalog::promote(&mut ctx, &actor, "qwen-eval@1.0.0", "stable")
            .await
            .unwrap();
        assert!(
            admitted.contains("promoted") && admitted.contains("stable"),
            "{admitted}"
        );

        write_software(&root.join("software"));
        let options = crate::catalog::PublishOptions {
            signature: None,
            trust_roots: None,
            allow_unsigned_development: true,
            provenance: Vec::new(),
            provenance_trust_roots: None,
            change_set_evidence: None,
            artifact_registry: None,
        };
        crate::catalog::publish(&mut ctx, &root.join("software/tenkai.toml"), &options)
            .await
            .unwrap();
        let software = crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        assert!(software.contains("promoted"), "{software}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn production_eval_ingest_admits_model_runtime_promote() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-model-eval-ingest-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let mut ctx = published_ctx(&root, "qwen-ingest", "1.0.0").await;
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let public = signing_key.verifying_key().to_bytes();
        let roots = EvaluationTrustRoots {
            version: EVALUATION_TRUST_VERSION,
            signers: vec![EvaluationTrustedSigner {
                key_id: crate::signature_verification::key_id(&public),
                public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    public,
                ),
            }],
        };
        let trust_path = root.join("eval-trust.toml");
        std::fs::write(&trust_path, toml::to_string(&roots).unwrap()).unwrap();
        let loaded_roots = EvaluationTrustRoots::load(&trust_path).unwrap();
        let actor = crate::auth_context::test_management_context("model-eval-ingest");
        install_evaluation_trust_roots(&mut ctx, &actor, &loaded_roots)
            .await
            .unwrap();

        let release = ctx
            .get(&crate::ontology::release_id("qwen-ingest", "1.0.0"))
            .await
            .unwrap()
            .unwrap();
        let descriptor = ModelRuntimeDescriptor::from_manifest(
            &crate::manifest::parse_raw(release.properties.get("manifest").unwrap()).unwrap(),
        )
        .unwrap();
        let identity = identity_from_descriptor(&descriptor).unwrap();
        let now = crate::now_millis();
        let evidence = signed_fixture_evaluation(
            identity,
            EvaluationOutcome::Passed,
            now,
            now.saturating_add(3_600_000),
            &signing_key,
        )
        .unwrap();
        let evidence_path = root.join("evaluation-result.json");
        std::fs::write(
            &evidence_path,
            serde_json::to_string_pretty(&evidence).unwrap(),
        )
        .unwrap();
        record_evaluation_evidence(
            &mut ctx,
            &actor,
            ModelEvaluationEvidence::load(&evidence_path).unwrap(),
        )
        .await
        .unwrap();

        let admitted = crate::catalog::promote(&mut ctx, &actor, "qwen-ingest@1.0.0", "stable")
            .await
            .unwrap();
        assert!(admitted.contains("promoted"), "{admitted}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn evaluation_trust_install_requires_management() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-model-eval-trust-auth-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let public = signing_key.verifying_key().to_bytes();
        let roots = EvaluationTrustRoots {
            version: EVALUATION_TRUST_VERSION,
            signers: vec![EvaluationTrustedSigner {
                key_id: crate::signature_verification::key_id(&public),
                public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    public,
                ),
            }],
        };
        let publisher = crate::auth_context::AuthenticatedRequestContextBuilder::new(
            "eval-trust-publish-only",
            crate::auth_context::PrincipalIdentity {
                id: "publisher".into(),
                kind: crate::auth_context::PrincipalKind::Human,
            },
            "test-auth",
        )
        .with_delivery_capabilities([DeliveryCapability::Publish])
        .build()
        .unwrap();
        let err = install_evaluation_trust_roots(&mut ctx, &publisher, &roots)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("insufficient delivery capability"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn evaluation_record_requires_product_grant() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-model-eval-product-grant-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let mut ctx = published_ctx(&root, "qwen-grant", "1.0.0").await;
        let signing_key = ensure_fixture_evaluation_trust(&mut ctx).await.unwrap();
        let release = ctx
            .get(&crate::ontology::release_id("qwen-grant", "1.0.0"))
            .await
            .unwrap()
            .unwrap();
        let descriptor = ModelRuntimeDescriptor::from_manifest(
            &crate::manifest::parse_raw(release.properties.get("manifest").unwrap()).unwrap(),
        )
        .unwrap();
        let identity = identity_from_descriptor(&descriptor).unwrap();
        let now = crate::now_millis();
        let evidence = signed_fixture_evaluation(
            identity,
            EvaluationOutcome::Passed,
            now,
            now.saturating_add(3_600_000),
            &signing_key,
        )
        .unwrap();
        let publisher = crate::auth_context::AuthenticatedRequestContextBuilder::new(
            "eval-record-other-product",
            crate::auth_context::PrincipalIdentity {
                id: "publisher".into(),
                kind: crate::auth_context::PrincipalKind::Human,
            },
            "test-auth",
        )
        .with_delivery_capabilities([DeliveryCapability::Publish])
        .with_product_bindings(["other-product".into()])
        .build()
        .unwrap();
        let err = record_evaluation_evidence(&mut ctx, &publisher, evidence)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("product is outside the publication grant"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
