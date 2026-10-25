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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
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
    #[serde(default)]
    pub skip_gates: bool,
    pub bypass_reason: Option<String>,
}

/// One collected, still-detached envelope for a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CollectedApproval {
    pub key_id: String,
    pub signer_identity: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub expires_at: i64,
}

/// Collected versus missing approvals for one plan and purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanApprovalsView {
    pub plan_id: String,
    pub plan_digest: String,
    pub purpose: String,
    pub required: u32,
    #[serde(default)]
    pub groups: Vec<String>,
    pub exclude_requester: bool,
    #[serde(default)]
    pub collected: Vec<CollectedApproval>,
    pub missing: u32,
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
            for scope in signer
                .environments
                .iter()
                .chain(&signer.providers)
                .chain(&signer.groups)
            {
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
            if signer
                .providers
                .iter()
                .any(|provider| provider == crate::host_preflight::PREFLIGHT_PROVIDER)
                && (signer.environments.is_empty() || signer.providers.len() != 1)
            {
                bail!(
                    "preflight signers require explicit environments and only the preflight provider"
                );
            }
            validate_text("trusted signer identity", &signer.identity)?;
            crate::signature_verification::well_formed_key(
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

    pub(crate) fn signer(&self, key_id: &str) -> Result<&TrustedSigner> {
        self.signers
            .iter()
            .find(|signer| signer.key_id == key_id)
            .with_context(|| format!("plan approval signer {key_id} is not currently trusted"))
    }
}

/// Load one envelope, a JSON array, or every `*.json` file in a directory.
pub fn load_envelopes(path: &Path) -> Result<Vec<ApprovalEnvelope>> {
    if path.is_dir() {
        let mut files: Vec<_> = std::fs::read_dir(path)
            .with_context(|| format!("reading plan approval directory {}", path.display()))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|candidate| candidate.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect();
        files.sort();
        let mut envelopes = Vec::new();
        for file in files {
            envelopes.extend(load_envelopes(&file)?);
        }
        if envelopes.is_empty() {
            bail!(
                "plan approval directory {} contains no envelopes",
                path.display()
            );
        }
        return Ok(envelopes);
    }
    let raw =
        std::fs::read(path).with_context(|| format!("reading plan approval {}", path.display()))?;
    if let Ok(envelope) = serde_json::from_slice::<ApprovalEnvelope>(&raw) {
        return Ok(vec![envelope]);
    }
    serde_json::from_slice(&raw).context("parsing plan approval envelope set")
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
    verify_for_execution_named(
        ctx,
        plan,
        envelope_path,
        trust_roots_path,
        now,
        skip_gates,
        None,
    )
    .await
}

/// Like [`verify_for_execution`], naming the apply requester for exclude-requester quorums.
pub async fn verify_for_execution_named(
    ctx: &mut Ctx,
    plan: &Plan,
    envelope_path: &Path,
    trust_roots_path: &Path,
    now: i64,
    skip_gates: bool,
    requester: Option<&str>,
) -> Result<VerificationEvidence> {
    let roots = TrustRoots::load(trust_roots_path)?;
    let mut envelopes = load_envelopes(envelope_path)?;
    envelopes.extend(list_collected_envelopes(ctx, &plan.id).await?);
    if envelopes.is_empty() {
        bail!("plan approval is missing");
    }
    // Verify each envelope before unique-by-key so an expired or unusable
    // request file cannot hide a collected renewal for the same signer.
    let mut verified = Vec::new();
    let mut last_error = None;
    for envelope in envelopes {
        match verify_envelope(plan, &envelope, &roots, now, skip_gates) {
            Ok(evidence) => verified.push((envelope, evidence)),
            Err(error) => last_error = Some(error),
        }
    }
    if verified.is_empty() {
        return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("plan approval is missing")));
    }
    let mut unique = Vec::new();
    let mut seen_keys = std::collections::BTreeSet::new();
    for item in verified {
        if seen_keys.insert(item.0.key_id.clone()) {
            unique.push(item);
        }
    }
    let environment = crate::environment::environment(ctx, &plan.environment).await?;
    let policy = crate::approval_policy::load_live_policy(&environment.properties)?;
    let purpose = crate::approval_policy::quorum_purpose(plan, skip_gates);
    let rule = match &policy {
        Some(policy) => crate::approval_policy::quorum_rule(policy, purpose),
        None => crate::approval_policy::default_quorum(purpose),
    };
    if rule.exclude_requester && requester.is_none() {
        bail!(
            "this approval policy excludes the apply requester, but no authenticated requester identity was supplied"
        );
    }
    let candidates: Vec<CountedApproval> = unique
        .iter()
        .filter_map(|(envelope, _)| {
            let signer = roots.signer(&envelope.key_id).ok()?;
            Some(CountedApproval {
                key_id: envelope.key_id.clone(),
                identity: signer.identity.clone(),
                groups: signer.groups.clone(),
                auto: envelope.statement.policy_provider == "builtin-auto",
            })
        })
        .collect();
    let tally = count_quorum(&rule, &candidates, requester);
    if tally.missing > 0 {
        bail!("{}", quorum_refusal(&rule, &tally));
    }
    let counted_keys: std::collections::BTreeSet<&str> = tally
        .counted
        .iter()
        .map(|item| item.key_id.as_str())
        .collect();
    let evidence = unique
        .iter()
        .find(|(envelope, _)| counted_keys.contains(envelope.key_id.as_str()))
        .map(|(_, evidence)| evidence.clone())
        .context("plan approval is missing")?;
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
        if evidence.policy_digest != policy.digest()? {
            bail!(
                "automatic approval policy digest no longer matches the current environment policy"
            );
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
    for counted in &tally.counted {
        let signer = roots.signer(&counted.key_id)?;
        refuse_unscoped_host_automatic_key(ctx, &counted.key_id, signer).await?;
    }
    let environment = crate::environment::environment(ctx, &plan.environment).await?;
    let policy = crate::approval_policy::load_live_policy(&environment.properties)?;
    if policy.is_none()
        && let Some(path) =
            crate::approval_policy::policy_path_from_properties(&environment.properties)?
    {
        // The missing file may have required a preflight; fail closed.
        bail!(
            "approval policy {} is configured but unavailable; cannot check its preflight requirement",
            path.display()
        );
    }
    if let Some(required) = policy.and_then(|policy| policy.require_preflight) {
        crate::host_preflight::require_passing(
            &environment.properties,
            &plan.environment,
            &roots,
            now,
            required.max_age_ms,
        )?;
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
    let roots = TrustRoots::load(trust_roots_path)?;
    verify_envelope(plan, &envelope, &roots, now, skip_gates)
}

pub fn verify_envelope(
    plan: &Plan,
    envelope: &ApprovalEnvelope,
    roots: &TrustRoots,
    now: i64,
    skip_gates: bool,
) -> Result<VerificationEvidence> {
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
    if envelope.statement.policy_provider == crate::host_preflight::PREFLIGHT_PROVIDER {
        bail!("a preflight signer cannot approve plans");
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
        key_id: envelope.key_id.clone(),
        policy_provider: envelope.statement.policy_provider.clone(),
        policy_evidence_id: envelope.statement.policy_evidence_id.clone(),
        policy_digest: envelope.statement.policy_digest.clone(),
        issued_at: envelope.statement.issued_at,
        expires_at: envelope.statement.expires_at,
        verified_at: now,
        skip_gates: envelope.statement.skip_gates,
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
        skip_gates: false,
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

/// Newest recorded verification for `plan_id`, if any.
pub async fn latest_for_plan(ctx: &mut Ctx, plan_id: &str) -> Result<Option<VerificationEvidence>> {
    let mut objects = ctx
        .find_by_property(
            crate::ontology::KIND_PLAN_APPROVAL_VERIFICATION,
            "plan_id",
            plan_id,
        )
        .await?;
    objects.sort_by_key(|object| {
        object
            .properties
            .get("verified_at")
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0)
    });
    let Some(object) = objects.pop() else {
        return Ok(None);
    };
    let raw = object
        .properties
        .get("evidence")
        .context("plan approval verification is missing evidence")?;
    Ok(Some(serde_json::from_str(raw).context(
        "plan approval verification evidence is not valid JSON",
    )?))
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CountedApproval {
    key_id: String,
    identity: String,
    groups: Vec<String>,
    auto: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuorumTally {
    counted: Vec<CountedApproval>,
    missing: u32,
}

fn count_quorum(
    rule: &crate::approval_policy::QuorumRule,
    candidates: &[CountedApproval],
    requester: Option<&str>,
) -> QuorumTally {
    let mut counted = Vec::new();
    let mut seen_keys = std::collections::BTreeSet::new();
    let mut seen_identities = std::collections::BTreeSet::new();
    for candidate in candidates {
        if rule.n > 1 && candidate.auto {
            continue;
        }
        // Execution refuses when this rule is set and requester is None.
        if rule.exclude_requester && requester.is_some_and(|id| id == candidate.identity) {
            continue;
        }
        if !rule.groups.is_empty()
            && !candidate
                .groups
                .iter()
                .any(|group| rule.groups.iter().any(|needed| needed == group))
        {
            continue;
        }
        if seen_keys.contains(&candidate.key_id) || seen_identities.contains(&candidate.identity) {
            continue;
        }
        seen_keys.insert(candidate.key_id.clone());
        seen_identities.insert(candidate.identity.clone());
        counted.push(candidate.clone());
        if counted.len() as u32 >= rule.n {
            break;
        }
    }
    let missing = rule.n.saturating_sub(counted.len() as u32);
    QuorumTally { counted, missing }
}

fn quorum_refusal(rule: &crate::approval_policy::QuorumRule, tally: &QuorumTally) -> String {
    let groups = if rule.groups.is_empty() {
        String::new()
    } else {
        format!(" from groups [{}]", rule.groups.join(", "))
    };
    let have = if tally.counted.is_empty() {
        "none".into()
    } else {
        tally
            .counted
            .iter()
            .map(|item| item.identity.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "need {} {} approvals{}; have {} ({}); missing {}",
        rule.n,
        rule.purpose.as_str(),
        groups,
        tally.counted.len(),
        have,
        tally.missing
    )
}

fn collected_id(plan_id: &str, key_id: &str, skip_gates: bool) -> String {
    format!("{plan_id}:envelope:{key_id}:skip_gates={skip_gates}")
}

async fn refuse_unscoped_host_automatic_key(
    ctx: &mut Ctx,
    key_id: &str,
    signer: &TrustedSigner,
) -> Result<()> {
    if !signer.environments.is_empty() && signer.providers == ["builtin-auto"] {
        return Ok(());
    }
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
        if known_keys.contains(key_id) || live_key.as_deref() == Some(key_id) {
            bail!(
                "host-configured automatic key requires explicit environment and builtin-auto scopes"
            );
        }
    }
    Ok(())
}

/// Persist one verified envelope so later apply or GET can see it.
pub async fn collect_envelope(
    ctx: &mut Ctx,
    plan: &Plan,
    envelope: &ApprovalEnvelope,
    roots: &TrustRoots,
    now: i64,
) -> Result<CollectedApproval> {
    let evidence = verify_envelope(plan, envelope, roots, now, envelope.statement.skip_gates)?;
    let signer = roots.signer(&envelope.key_id)?;
    let object = Object {
        id: collected_id(&plan.id, &envelope.key_id, envelope.statement.skip_gates),
        kind: crate::ontology::KIND_PLAN_APPROVAL_ENVELOPE.into(),
        name: format!("plan approval envelope {}", envelope.key_id),
        namespace: "tenkai".into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("plan_id".into(), plan.id.clone()),
            ("plan_digest".into(), evidence.plan_digest),
            ("key_id".into(), envelope.key_id.clone()),
            ("signer_identity".into(), signer.identity.clone()),
            ("groups".into(), serde_json::to_string(&signer.groups)?),
            (
                "expires_at".into(),
                envelope.statement.expires_at.to_string(),
            ),
            ("envelope".into(), serde_json::to_string(envelope)?),
            ("collected_at".into(), now.to_string()),
        ]),
        created: now,
        updated: now,
    };
    if let Some(existing) = ctx.get(&object.id).await? {
        let still_valid = existing
            .properties
            .get("expires_at")
            .and_then(|value| value.parse::<i64>().ok())
            .is_some_and(|expires_at| now < expires_at);
        if still_valid {
            let expires_at = existing
                .properties
                .get("expires_at")
                .and_then(|value| value.parse().ok())
                .unwrap_or(envelope.statement.expires_at);
            return Ok(CollectedApproval {
                key_id: envelope.key_id.clone(),
                signer_identity: existing
                    .properties
                    .get("signer_identity")
                    .cloned()
                    .unwrap_or_else(|| signer.identity.clone()),
                groups: existing
                    .properties
                    .get("groups")
                    .and_then(|raw| serde_json::from_str(raw).ok())
                    .unwrap_or_else(|| signer.groups.clone()),
                expires_at,
            });
        }
    }
    ctx.put(object).await?;
    Ok(CollectedApproval {
        key_id: envelope.key_id.clone(),
        signer_identity: signer.identity.clone(),
        groups: signer.groups.clone(),
        expires_at: envelope.statement.expires_at,
    })
}

async fn list_collected_envelopes(ctx: &mut Ctx, plan_id: &str) -> Result<Vec<ApprovalEnvelope>> {
    let objects = ctx
        .find_by_property(
            crate::ontology::KIND_PLAN_APPROVAL_ENVELOPE,
            "plan_id",
            plan_id,
        )
        .await?;
    let mut envelopes = Vec::new();
    for object in objects {
        let Some(raw) = object.properties.get("envelope") else {
            continue;
        };
        envelopes.push(serde_json::from_str(raw).context("collected plan approval is not JSON")?);
    }
    Ok(envelopes)
}

/// Operator view of collected versus missing approvals for a live plan.
pub async fn approvals_view(
    ctx: &mut Ctx,
    plan: &Plan,
    roots: Option<&TrustRoots>,
    now: i64,
    skip_gates: bool,
    requester: Option<&str>,
) -> Result<PlanApprovalsView> {
    let environment = crate::environment::environment(ctx, &plan.environment).await?;
    let policy = crate::approval_policy::load_live_policy(&environment.properties)?;
    let purpose = crate::approval_policy::quorum_purpose(plan, skip_gates);
    let rule = match &policy {
        Some(policy) => crate::approval_policy::quorum_rule(policy, purpose),
        None => crate::approval_policy::default_quorum(purpose),
    };
    let expected_digest = format!("sha256:{}", plan.executable_digest()?);
    let objects = ctx
        .find_by_property(
            crate::ontology::KIND_PLAN_APPROVAL_ENVELOPE,
            "plan_id",
            &plan.id,
        )
        .await?;
    let mut collected = Vec::new();
    let mut candidates = Vec::new();
    for object in objects {
        let Some(key_id) = object.properties.get("key_id").cloned() else {
            continue;
        };
        let expires_at = object
            .properties
            .get("expires_at")
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        if now >= expires_at {
            continue;
        }
        let Some(envelope) = object
            .properties
            .get("envelope")
            .and_then(|raw| serde_json::from_str::<ApprovalEnvelope>(raw).ok())
        else {
            continue;
        };
        if envelope.statement.skip_gates != skip_gates
            || envelope.statement.environment != plan.environment
            || envelope.statement.plan_digest != expected_digest
        {
            continue;
        }
        let mut identity = object
            .properties
            .get("signer_identity")
            .cloned()
            .unwrap_or_default();
        let mut groups: Vec<String> = object
            .properties
            .get("groups")
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default();
        if let Some(roots) = roots {
            if verify_envelope(plan, &envelope, roots, now, skip_gates).is_err() {
                continue;
            }
            let Ok(signer) = roots.signer(&key_id) else {
                continue;
            };
            identity = signer.identity.clone();
            groups = signer.groups.clone();
        }
        if !identity.is_empty() {
            let auto = envelope.statement.policy_provider == "builtin-auto";
            candidates.push(CountedApproval {
                key_id: key_id.clone(),
                identity: identity.clone(),
                groups: groups.clone(),
                auto,
            });
        }
        collected.push(CollectedApproval {
            key_id,
            signer_identity: identity,
            groups,
            expires_at,
        });
    }
    let tally = count_quorum(&rule, &candidates, requester);
    Ok(PlanApprovalsView {
        plan_id: plan.id.clone(),
        plan_digest: format!("sha256:{}", plan.executable_digest()?),
        purpose: rule.purpose.as_str().into(),
        required: rule.n,
        groups: rule.groups,
        exclude_requester: rule.exclude_requester,
        collected,
        missing: tally.missing,
    })
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

    fn counted(key: &str, identity: &str, groups: &[&str]) -> CountedApproval {
        CountedApproval {
            key_id: key.into(),
            identity: identity.into(),
            groups: groups.iter().map(|group| (*group).to_string()).collect(),
            auto: false,
        }
    }

    fn rule(
        n: u32,
        groups: &[&str],
        exclude_requester: bool,
    ) -> crate::approval_policy::QuorumRule {
        crate::approval_policy::QuorumRule {
            purpose: crate::approval_policy::QuorumPurpose::ExecutePlan,
            n,
            groups: groups.iter().map(|group| (*group).to_string()).collect(),
            exclude_requester,
        }
    }

    #[test]
    fn same_key_or_principal_counts_once() {
        let need = rule(2, &[], false);
        assert_eq!(
            count_quorum(
                &need,
                &[counted("k1", "alice", &[]), counted("k1", "alice", &[])],
                None
            )
            .missing,
            1
        );
        assert_eq!(
            count_quorum(
                &need,
                &[counted("k1", "alice", &[]), counted("k2", "alice", &[])],
                None
            )
            .missing,
            1
        );
        assert_eq!(
            count_quorum(
                &need,
                &[counted("k1", "alice", &[]), counted("k2", "bob", &[])],
                None
            )
            .missing,
            0
        );
    }

    #[test]
    fn refusal_lists_what_is_missing() {
        let need = rule(2, &["release", "sre"], false);
        let tally = count_quorum(&need, &[counted("k1", "alice", &["release"])], None);
        let message = quorum_refusal(&need, &tally);
        assert!(message.contains("need 2 execute_plan approvals from groups [release, sre]"));
        assert!(message.contains("have 1 (alice)"));
        assert!(message.contains("missing 1"), "{message}");
    }

    #[test]
    fn requester_does_not_count_when_excluded() {
        let need = rule(1, &[], true);
        assert_eq!(
            count_quorum(&need, &[counted("k1", "alice", &[])], Some("alice")).missing,
            1
        );
        assert_eq!(
            count_quorum(&need, &[counted("k1", "alice", &[])], Some("bob")).missing,
            0
        );
    }

    #[test]
    fn named_groups_filter_eligible_signers() {
        let need = rule(1, &["release"], false);
        assert_eq!(
            count_quorum(&need, &[counted("k1", "alice", &["sre"])], None).missing,
            1
        );
        assert_eq!(
            count_quorum(&need, &[counted("k1", "alice", &["release"])], None).missing,
            0
        );
    }

    #[test]
    fn automatic_approval_cannot_satisfy_n_greater_than_one() {
        let need = rule(2, &[], false);
        let mut auto = counted("k-auto", "lab-auto", &[]);
        auto.auto = true;
        assert_eq!(
            count_quorum(&need, &[auto.clone(), counted("k1", "alice", &[])], None).missing,
            1
        );
        assert_eq!(count_quorum(&rule(1, &[], false), &[auto], None).missing, 0);
    }

    #[test]
    fn load_envelopes_reads_a_json_array() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-approval-set-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let first = ApprovalEnvelope {
            schema: APPROVAL_SCHEMA.into(),
            key_id: "k1".into(),
            statement: statement(),
            signature: "c2ln".into(),
        };
        let mut second = first.clone();
        second.key_id = "k2".into();
        let path = dir.join("set.json");
        std::fs::write(&path, serde_json::to_vec(&[&first, &second]).unwrap()).unwrap();
        let loaded = load_envelopes(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        let nested = dir.join("set");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("a.json"), serde_json::to_vec(&first).unwrap()).unwrap();
        std::fs::write(nested.join("b.json"), serde_json::to_vec(&second).unwrap()).unwrap();
        assert_eq!(load_envelopes(&nested).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}
