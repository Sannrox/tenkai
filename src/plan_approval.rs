//! Signed, provider-independent authorization for immutable plan execution.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::pb::sekai::Object;
use crate::plan::Plan;

pub const APPROVAL_SCHEMA: &str = "tenkai.plan-approval.v1";
const APPROVAL_DOMAIN: &[u8] = b"TENKAI-PLAN-APPROVAL-V1\0";
const TRUST_ROOT_VERSION: u32 = 1;
const PURPOSE: &str = "execute_plan";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalStatement {
    pub plan_digest: String,
    pub environment: String,
    pub purpose: String,
    pub skip_gates: bool,
    pub issued_at: i64,
    pub expires_at: i64,
    pub policy_provider: String,
    pub policy_evidence_id: String,
    pub policy_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnvelope {
    pub schema: String,
    pub key_id: String,
    pub statement: ApprovalStatement,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "PlanApprovalTrustRoots")]
pub struct TrustRoots {
    pub version: u32,
    pub signers: Vec<TrustedSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "PlanApprovalTrustedSigner")]
pub struct TrustedSigner {
    pub key_id: String,
    pub identity: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environments: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationEvidence {
    pub schema: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub environment: String,
    pub signer_identity: String,
    pub key_id: String,
    pub policy_provider: String,
    pub policy_evidence_id: String,
    pub policy_digest: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub verified_at: i64,
    pub bypass_reason: Option<String>,
}

pub fn canonical_bytes(statement: &ApprovalStatement) -> Result<Vec<u8>> {
    validate_statement(statement)?;
    let mut bytes = APPROVAL_DOMAIN.to_vec();
    for value in [
        statement.plan_digest.as_bytes(),
        statement.environment.as_bytes(),
        statement.purpose.as_bytes(),
    ] {
        crate::signature_verification::push_len_prefixed(&mut bytes, value);
    }
    bytes.extend_from_slice(&statement.issued_at.to_be_bytes());
    bytes.extend_from_slice(&statement.expires_at.to_be_bytes());
    bytes.push(u8::from(statement.skip_gates));
    for value in [
        statement.policy_provider.as_bytes(),
        statement.policy_evidence_id.as_bytes(),
        statement.policy_digest.as_bytes(),
    ] {
        crate::signature_verification::push_len_prefixed(&mut bytes, value);
    }
    Ok(bytes)
}

fn validate_text(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value != value.trim() || value.len() > 512 || value.contains('\0')
    {
        bail!("{name} is empty, non-canonical, or too long");
    }
    Ok(())
}

fn validate_statement(statement: &ApprovalStatement) -> Result<()> {
    crate::signature_verification::validate_prefixed_digest("plan digest", &statement.plan_digest)?;
    validate_text("environment", &statement.environment)?;
    if statement.purpose != PURPOSE {
        bail!("approval purpose must be {PURPOSE}");
    }
    if statement.expires_at <= statement.issued_at {
        bail!("approval expiry must be after its issue time");
    }
    validate_text("policy provider", &statement.policy_provider)?;
    validate_text("policy evidence id", &statement.policy_evidence_id)?;
    crate::signature_verification::validate_prefixed_digest(
        "policy digest",
        &statement.policy_digest,
    )?;
    Ok(())
}

impl TrustRoots {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading plan approval trust roots {}", path.display()))?;
        let roots: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing plan approval trust roots {}", path.display()))?;
        if roots.version != TRUST_ROOT_VERSION || roots.signers.is_empty() {
            bail!("plan approval trust roots must use version 1 and contain at least one signer");
        }
        let mut keys = BTreeMap::new();
        let mut identities = std::collections::BTreeSet::new();
        for signer in &roots.signers {
            for scope in signer.environments.iter().chain(&signer.providers) {
                validate_text("trusted signer scope", scope)?;
            }
            if signer
                .providers
                .iter()
                .any(|provider| provider == "builtin-auto")
                && (signer.environments.is_empty() || signer.providers.len() != 1)
            {
                bail!(
                    "automatic approval signers require explicit environments and only the builtin-auto provider"
                );
            }
            validate_text("trusted signer identity", &signer.identity)?;
            crate::signature_verification::trusted_key(
                "plan approval public key",
                &signer.public_key,
                &signer.key_id,
            )?;
            if keys.insert(&signer.key_id, ()).is_some() || !identities.insert(&signer.identity) {
                bail!("plan approval trust roots contain duplicate keys or identities");
            }
        }
        Ok(roots)
    }

    fn signer(&self, key_id: &str) -> Result<&TrustedSigner> {
        self.signers
            .iter()
            .find(|signer| signer.key_id == key_id)
            .with_context(|| format!("plan approval signer {key_id} is not currently trusted"))
    }
}

/// Check host-configured automatic keys as well as the envelope's root scopes.
pub async fn verify_for_execution(
    ctx: &mut Ctx,
    plan: &Plan,
    envelope_path: &Path,
    trust_roots_path: &Path,
    now: i64,
    skip_gates: bool,
) -> Result<VerificationEvidence> {
    let evidence = verify(plan, envelope_path, trust_roots_path, now, skip_gates)?;
    if evidence.policy_provider == "builtin-auto" {
        let environment = crate::environment::environment(ctx, &plan.environment).await?;
        let policy = crate::approval_policy::load_live_policy(&environment.properties)?
            .ok_or_else(|| {
                anyhow::anyhow!("automatic approval requires a live environment policy")
            })?;
        if policy.mode != crate::approval_policy::PolicyMode::Auto
            || crate::approval_policy::signer_key_id(&policy)?.as_deref()
                != Some(evidence.key_id.as_str())
        {
            bail!("automatic approval signer is not authorized by this environment's live policy");
        }
        let signals = crate::approval_policy::delivery_signals_for_plan(ctx, plan).await?;
        if !matches!(
            crate::approval_policy::evaluate(&policy, plan, skip_gates, signals),
            crate::approval_policy::Decision::Auto { .. }
        ) {
            bail!("live environment policy requires human approval");
        }
    }
    let roots = TrustRoots::load(trust_roots_path)?;
    let signer = roots.signer(&evidence.key_id)?;
    if signer.environments.is_empty() || signer.providers != ["builtin-auto"] {
        for environment in ctx.list_kind(crate::ontology::KIND_ENVIRONMENT).await? {
            let known_keys: std::collections::BTreeSet<String> = environment
                .properties
                .get(crate::approval_policy::AUTO_SIGNER_KEYS_PROPERTY)
                .map(|raw| serde_json::from_str(raw))
                .transpose()?
                .unwrap_or_default();
            // Legacy policies may predate retained public key identities. A
            // missing unrelated policy/key must not revoke human authority.
            let live_key = crate::approval_policy::load_live_policy(&environment.properties)
                .ok()
                .flatten()
                .and_then(|policy| {
                    crate::approval_policy::signer_key_id(&policy)
                        .ok()
                        .flatten()
                });
            if known_keys.contains(&evidence.key_id)
                || live_key.as_deref() == Some(evidence.key_id.as_str())
            {
                bail!(
                    "host-configured automatic key requires explicit environment and builtin-auto scopes"
                );
            }
        }
    }
    Ok(evidence)
}

pub fn verify(
    plan: &Plan,
    envelope_path: &Path,
    trust_roots_path: &Path,
    now: i64,
    skip_gates: bool,
) -> Result<VerificationEvidence> {
    let raw = std::fs::read(envelope_path)
        .with_context(|| format!("reading plan approval {}", envelope_path.display()))?;
    let envelope: ApprovalEnvelope =
        serde_json::from_slice(&raw).context("parsing plan approval envelope")?;
    if envelope.schema != APPROVAL_SCHEMA {
        bail!("unsupported plan approval schema {}", envelope.schema);
    }
    let expected_digest = format!("sha256:{}", plan.executable_digest()?);
    if envelope.statement.plan_digest != expected_digest
        || envelope.statement.environment != plan.environment
        || envelope.statement.skip_gates != skip_gates
    {
        bail!(
            "plan approval is bound to different executable content, environment, or gate policy"
        );
    }
    if now < envelope.statement.issued_at {
        bail!("plan approval is not valid yet");
    }
    if now >= envelope.statement.expires_at {
        bail!("plan approval expired at {}", envelope.statement.expires_at);
    }
    let roots = TrustRoots::load(trust_roots_path)?;
    let signer = roots.signer(&envelope.key_id)?;
    if !signer.environments.is_empty() && !signer.environments.contains(&plan.environment) {
        bail!("plan approval signer is outside its environment scope");
    }
    if !signer.providers.is_empty()
        && !signer
            .providers
            .contains(&envelope.statement.policy_provider)
    {
        bail!("plan approval signer is outside its provider scope");
    }
    if envelope.statement.policy_provider == "builtin-auto"
        && (signer.environments.is_empty() || signer.providers != ["builtin-auto"])
    {
        bail!("automatic approval requires an environment-scoped builtin-auto signer");
    }
    let public_key = crate::signature_verification::trusted_key(
        "trusted signer public key",
        &signer.public_key,
        &signer.key_id,
    )?;
    crate::signature_verification::verify_strict(
        &public_key,
        "plan approval signature",
        &envelope.signature,
        &canonical_bytes(&envelope.statement)?,
    )?;
    Ok(VerificationEvidence {
        schema: APPROVAL_SCHEMA.into(),
        plan_id: plan.id.clone(),
        plan_digest: expected_digest,
        environment: plan.environment.clone(),
        signer_identity: signer.identity.clone(),
        key_id: envelope.key_id,
        policy_provider: envelope.statement.policy_provider,
        policy_evidence_id: envelope.statement.policy_evidence_id,
        policy_digest: envelope.statement.policy_digest,
        issued_at: envelope.statement.issued_at,
        expires_at: envelope.statement.expires_at,
        verified_at: now,
        bypass_reason: None,
    })
}

pub fn local_bypass(plan: &Plan, reason: &str, now: i64) -> Result<VerificationEvidence> {
    if plan.environment != "local" {
        bail!("unapproved development execution is restricted to the built-in local environment");
    }
    validate_text("development bypass reason", reason)?;
    Ok(VerificationEvidence {
        schema: APPROVAL_SCHEMA.into(),
        plan_id: plan.id.clone(),
        plan_digest: format!("sha256:{}", plan.executable_digest()?),
        environment: plan.environment.clone(),
        signer_identity: "unsigned-development".into(),
        key_id: String::new(),
        policy_provider: "builtin-local-development".into(),
        policy_evidence_id: format!("local-bypass:{}", plan.id),
        policy_digest: format!("sha256:{:x}", Sha256::digest(reason.as_bytes())),
        issued_at: now,
        expires_at: now,
        verified_at: now,
        bypass_reason: Some(reason.into()),
    })
}

pub async fn record(ctx: &mut Ctx, evidence: &VerificationEvidence) -> Result<()> {
    let id = format!(
        "{}:approval:{}:{}",
        evidence.plan_id,
        evidence.key_id_or_bypass(),
        evidence.verified_at
    );
    let properties = HashMap::from([
        ("evidence".into(), serde_json::to_string(evidence)?),
        ("plan_id".into(), evidence.plan_id.clone()),
        ("plan_digest".into(), evidence.plan_digest.clone()),
        ("environment".into(), evidence.environment.clone()),
        ("signer_identity".into(), evidence.signer_identity.clone()),
        ("policy_provider".into(), evidence.policy_provider.clone()),
        (
            "policy_evidence_id".into(),
            evidence.policy_evidence_id.clone(),
        ),
        ("policy_digest".into(), evidence.policy_digest.clone()),
        ("verified_at".into(), evidence.verified_at.to_string()),
    ]);
    ctx.create_once(Object {
        id,
        kind: crate::ontology::KIND_PLAN_APPROVAL_VERIFICATION.into(),
        name: format!("plan approval {}", evidence.plan_id),
        namespace: "tenkai".into(),
        external_id: String::new(),
        properties,
        created: evidence.verified_at,
        updated: evidence.verified_at,
    })
    .await
    .map_err(anyhow::Error::from)?;
    Ok(())
}

impl VerificationEvidence {
    fn key_id_or_bypass(&self) -> &str {
        if self.key_id.is_empty() {
            "development-bypass"
        } else {
            &self.key_id
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

    fn statement() -> ApprovalStatement {
        ApprovalStatement {
            plan_digest: format!("sha256:{}", "a".repeat(64)),
            environment: "prod".into(),
            purpose: PURPOSE.into(),
            skip_gates: false,
            issued_at: 10,
            expires_at: 20,
            policy_provider: "builtin".into(),
            policy_evidence_id: "decision-1".into(),
            policy_digest: format!("sha256:{}", "b".repeat(64)),
        }
    }

    #[test]
    fn canonical_approval_is_stable_and_content_bound() {
        let original = canonical_bytes(&statement()).unwrap();
        let mut altered = statement();
        altered.environment = "staging".into();
        assert_ne!(original, canonical_bytes(&altered).unwrap());
        let mut altered = statement();
        altered.plan_digest = format!("sha256:{}", "c".repeat(64));
        assert_ne!(original, canonical_bytes(&altered).unwrap());
    }

    #[test]
    fn signature_rejects_changed_statement() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(&canonical_bytes(&statement()).unwrap());
        let mut changed = statement();
        changed.expires_at += 1;
        assert!(
            key.verifying_key()
                .verify(&canonical_bytes(&changed).unwrap(), &signature)
                .is_err()
        );
    }

    #[test]
    fn malformed_scope_and_expiry_are_rejected() {
        let mut invalid = statement();
        invalid.purpose = "anything".into();
        assert!(canonical_bytes(&invalid).is_err());
        let mut invalid = statement();
        invalid.expires_at = invalid.issued_at;
        assert!(canonical_bytes(&invalid).is_err());
    }
}
