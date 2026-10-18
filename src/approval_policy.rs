//! Environment-scoped plan approval policy for unattended execution (#544).
//!
//! Auto-approval is opt-in per environment. It signs the same
//! `tenkai.plan-approval.v1` envelope a human would, then the reconciler
//! re-checks the live policy immediately before execute so removing the
//! policy or the signer key revokes pending automatic approvals.

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::plan::{Action, Plan, PlanState};
use crate::plan_approval::{
    APPROVAL_SCHEMA, ApprovalEnvelope, ApprovalStatement, VerificationEvidence, canonical_bytes,
};

/// Environment property storing the canonical path of the policy TOML file.
pub const PLAN_APPROVAL_POLICY_PROPERTY: &str = "plan_approval_policy";
pub(crate) const AUTO_SIGNER_KEYS_PROPERTY: &str = "plan_approval_auto_keys";
/// `policy_provider` written into envelopes signed by this policy.
pub const POLICY_PROVIDER: &str = "builtin-auto";
const POLICY_VERSION: u32 = 1;
const PURPOSE: &str = "execute_plan";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Auto,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequireHumanRule {
    pub product: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPolicy {
    pub version: u32,
    pub mode: PolicyMode,
    pub ttl_ms: i64,
    #[serde(default)]
    pub auto_signer_key: Option<PathBuf>,
    #[serde(default)]
    pub require_human: Vec<RequireHumanRule>,
    /// SHA-256 of the TOML file bytes when loaded from disk.
    #[serde(skip)]
    source_digest: Option<String>,
}

/// Signed release metadata (`[delivery]`) that forces a human approval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliverySignals {
    /// A target release declares a schema migration.
    pub has_migration: bool,
    /// A target release changes identity-provider configuration.
    pub changes_identity_config: bool,
    /// A downgrade or rollback leaves a release that declared a migration.
    pub reverses_migration: bool,
}

impl DeliverySignals {
    /// Signals of a release a plan moves to.
    pub fn target(properties: &HashMap<String, String>) -> Self {
        Self {
            has_migration: flag(properties, "has_migration"),
            changes_identity_config: flag(properties, "changes_identity_config"),
            reverses_migration: false,
        }
    }

    /// Signals of a release a downgrade or rollback moves away from.
    pub fn departed(properties: &HashMap<String, String>) -> Self {
        Self {
            reverses_migration: flag(properties, "has_migration"),
            ..Self::default()
        }
    }

    pub fn merge(self, other: Self) -> Self {
        Self {
            has_migration: self.has_migration || other.has_migration,
            changes_identity_config: self.changes_identity_config || other.changes_identity_config,
            reverses_migration: self.reverses_migration || other.reverses_migration,
        }
    }
}

fn flag(properties: &HashMap<String, String>, key: &str) -> bool {
    properties.get(key).is_some_and(|value| value == "true")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Auto { evidence_id: String },
    RequireHuman { reason: String },
}

/// Outcome of looking for a live automatic envelope at execute time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoEnvelope {
    Signed(PathBuf),
    NeedsHuman,
}

impl ApprovalPolicy {
    pub fn load(path: &Path) -> Result<Self> {
        validate_policy_file_path(path)?;
        let raw = fs::read(path)
            .with_context(|| format!("reading plan approval policy {}", path.display()))?;
        let text = std::str::from_utf8(&raw)
            .with_context(|| format!("plan approval policy {} is not UTF-8", path.display()))?;
        let mut policy: Self = toml::from_str(text)
            .with_context(|| format!("parsing plan approval policy {}", path.display()))?;
        policy.source_digest = Some(format!("sha256:{:x}", Sha256::digest(&raw)));
        policy.validate().with_context(|| {
            format!("plan approval policy {} failed validation", path.display())
        })?;
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        if self.version != POLICY_VERSION {
            bail!("plan approval policy version must be {POLICY_VERSION}");
        }
        if self.ttl_ms <= 0 {
            bail!("plan approval policy ttl_ms must be positive");
        }
        if self.mode == PolicyMode::Auto {
            let Some(key) = &self.auto_signer_key else {
                bail!("auto plan approval policy requires auto_signer_key");
            };
            validate_policy_file_path(key)?;
        }
        for rule in &self.require_human {
            crate::ontology::validate_identifier("require_human product", &rule.product)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        if let Some(digest) = &self.source_digest {
            return Ok(digest.clone());
        }
        let bytes = serde_json::to_vec(self).context("serializing plan approval policy")?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
}

/// Refuse credential material disguised as a policy file path.
pub fn validate_policy_file_path(path: &Path) -> Result<()> {
    let raw = path.to_string_lossy();
    if raw.is_empty() || raw.contains('\0') || raw.contains('\n') {
        bail!("plan_approval_policy must be a single filesystem path");
    }
    let lower = raw.to_ascii_lowercase();
    for needle in ["-----begin ", "bearer ", "token=", "password=", "secret="] {
        if lower.contains(needle) {
            bail!("plan_approval_policy must be a file path, not credential material");
        }
    }
    Ok(())
}

/// Read and admit `plan_approval_policy` from Environment properties.
pub fn policy_path_from_properties(
    properties: &HashMap<String, String>,
) -> Result<Option<PathBuf>> {
    match properties.get(PLAN_APPROVAL_POLICY_PROPERTY) {
        None => Ok(None),
        Some(value) => {
            let path = PathBuf::from(value);
            validate_policy_file_path(&path)?;
            Ok(Some(path))
        }
    }
}

pub fn evaluate(
    policy: &ApprovalPolicy,
    plan: &Plan,
    skip_gates: bool,
    signals: DeliverySignals,
) -> Decision {
    if policy.mode != PolicyMode::Auto {
        return Decision::RequireHuman {
            reason: "policy mode is manual".into(),
        };
    }
    if skip_gates {
        return Decision::RequireHuman {
            reason: "skip_gates requires a human-signed envelope".into(),
        };
    }
    if plan
        .steps
        .iter()
        .any(|step| matches!(step.action, Action::Downgrade | Action::Rollback))
    {
        return Decision::RequireHuman {
            reason: "downgrade or rollback requires a human-signed envelope".into(),
        };
    }
    if signals.has_migration {
        return Decision::RequireHuman {
            reason: "has_migration requires a human-signed envelope".into(),
        };
    }
    if signals.changes_identity_config {
        return Decision::RequireHuman {
            reason: "changes_identity_config requires a human-signed envelope".into(),
        };
    }
    if signals.reverses_migration {
        return Decision::RequireHuman {
            reason: "downgrade across a migration boundary requires a human-signed envelope".into(),
        };
    }
    for rule in &policy.require_human {
        if plan_mentions_product(plan, &rule.product) {
            return Decision::RequireHuman {
                reason: format!("product {} requires a human-signed envelope", rule.product),
            };
        }
    }
    Decision::Auto {
        evidence_id: "auto".into(),
    }
}

fn plan_mentions_product(plan: &Plan, product: &str) -> bool {
    plan.steps.iter().any(|step| step.product == product)
        || plan.inputs.iter().any(|input| input.product == product)
}

pub fn is_auto_envelope(path: &Path) -> Result<bool> {
    let raw =
        fs::read(path).with_context(|| format!("reading plan approval {}", path.display()))?;
    let envelope: ApprovalEnvelope =
        serde_json::from_slice(&raw).context("parsing plan approval envelope")?;
    Ok(envelope.statement.policy_provider == POLICY_PROVIDER)
}

fn auto_envelope_current(path: &Path, policy: &ApprovalPolicy, now: i64) -> Result<bool> {
    let raw =
        fs::read(path).with_context(|| format!("reading plan approval {}", path.display()))?;
    let envelope: ApprovalEnvelope =
        serde_json::from_slice(&raw).context("parsing plan approval envelope")?;
    Ok(now < envelope.statement.expires_at
        && envelope.statement.policy_digest == policy.digest()?
        && signer_key_id(policy)?.as_deref() == Some(envelope.key_id.as_str()))
}

/// Decide whether the live environment policy still authorizes automatic
/// execution, and write or reuse `$DIR/<plan-id>.json` when it does.
pub fn resolve_auto_envelope(
    properties: &HashMap<String, String>,
    plan: &Plan,
    skip_gates: bool,
    signals: DeliverySignals,
    directory: &Path,
    now: i64,
) -> Result<AutoEnvelope> {
    let envelope = directory.join(format!("{}.json", plan.id));
    let policy = load_live_policy(properties)?;
    let live = match &policy {
        None => Decision::RequireHuman {
            reason: "no plan approval policy".into(),
        },
        Some(policy) => evaluate(policy, plan, skip_gates, signals),
    };
    if envelope.is_file() {
        if is_auto_envelope(&envelope)? {
            match &live {
                Decision::RequireHuman { .. } => return Ok(AutoEnvelope::NeedsHuman),
                Decision::Auto { .. } => {
                    let Some(policy) = &policy else {
                        return Ok(AutoEnvelope::NeedsHuman);
                    };
                    if !auto_signer_present(policy) {
                        return Ok(AutoEnvelope::NeedsHuman);
                    }
                    if auto_envelope_current(&envelope, policy, now)? {
                        return Ok(AutoEnvelope::Signed(envelope));
                    }
                }
            }
        } else {
            return Ok(AutoEnvelope::Signed(envelope));
        }
    }
    let Decision::Auto { evidence_id } = live else {
        return Ok(AutoEnvelope::NeedsHuman);
    };
    let Some(policy) = policy else {
        return Ok(AutoEnvelope::NeedsHuman);
    };
    match sign_auto_approval(&policy, plan, skip_gates, now, evidence_id, &envelope) {
        Ok(()) => Ok(AutoEnvelope::Signed(envelope)),
        Err(error) if signer_unavailable(&error) => Ok(AutoEnvelope::NeedsHuman),
        Err(error) => Err(error),
    }
}

pub(crate) fn load_live_policy(
    properties: &HashMap<String, String>,
) -> Result<Option<ApprovalPolicy>> {
    let Some(path) = policy_path_from_properties(properties)? else {
        return Ok(None);
    };
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(ApprovalPolicy::load(&path)?))
}

pub(crate) fn signer_key_id(policy: &ApprovalPolicy) -> Result<Option<String>> {
    let Some(path) = &policy.auto_signer_key else {
        return Ok(None);
    };
    let seed = load_auto_signer_seed(path)?;
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    Ok(Some(crate::signature_verification::key_id(&public)))
}

/// Operator-facing policy: automatic signer key ids, human rules, and TTL.
/// Never includes seed bytes or file contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EffectiveApprovalPolicy {
    pub configured: bool,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub ttl_ms: Option<i64>,
    #[serde(default)]
    pub auto_signers: Vec<String>,
    #[serde(default)]
    pub require_human: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub digest: Option<String>,
}

/// Whether a plan was approved by policy or still needs a human, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanApprovalView {
    /// `policy`, `human`, `development`, or `required`.
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub policy_provider: Option<String>,
}

const BUILTIN_HUMAN_RULES: &[&str] = &[
    "downgrade or rollback",
    "skip_gates",
    "has_migration",
    "changes_identity_config",
];

/// Effective policy for `properties`, omitting missing files as unconfigured.
pub fn effective_policy(properties: &HashMap<String, String>) -> Result<EffectiveApprovalPolicy> {
    let Some(policy) = load_live_policy(properties)? else {
        return Ok(EffectiveApprovalPolicy {
            configured: false,
            mode: "manual".into(),
            ttl_ms: None,
            auto_signers: Vec::new(),
            require_human: vec!["all plans require a human-signed envelope".into()],
            digest: None,
        });
    };
    let require_human = match policy.mode {
        PolicyMode::Manual => vec!["all plans require a human-signed envelope".into()],
        PolicyMode::Auto => {
            let mut rules: Vec<String> = BUILTIN_HUMAN_RULES
                .iter()
                .map(|rule| (*rule).to_string())
                .collect();
            for rule in &policy.require_human {
                rules.push(format!("product {}", rule.product));
            }
            rules
        }
    };
    let auto_signers = match policy.mode {
        PolicyMode::Manual => Vec::new(),
        PolicyMode::Auto => signer_key_id(&policy)
            .ok()
            .flatten()
            .map(|key_id| vec![key_id])
            .unwrap_or_default(),
    };
    Ok(EffectiveApprovalPolicy {
        configured: true,
        mode: match policy.mode {
            PolicyMode::Auto => "auto".into(),
            PolicyMode::Manual => "manual".into(),
        },
        ttl_ms: Some(policy.ttl_ms),
        auto_signers,
        require_human,
        digest: Some(policy.digest()?),
    })
}

pub(crate) fn plan_awaiting_execution(plan: &Plan) -> bool {
    matches!(plan.state, PlanState::Computed | PlanState::Blocked)
}

/// Host execution settings that decide whether a pending plan can auto-approve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPolicy {
    pub skip_gates: bool,
    pub auto_signing: bool,
    pub trust_roots: Option<PathBuf>,
    pub approval_directory: Option<PathBuf>,
    /// Reason this host currently authorizes unsigned local execution.
    pub local_development_reason: Option<String>,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            skip_gates: false,
            auto_signing: true,
            trust_roots: None,
            approval_directory: None,
            local_development_reason: None,
        }
    }
}

impl ExecutionPolicy {
    /// Embedded host settings from `TENKAI_PLAN_APPROVAL_DIR` and trust roots.
    pub fn from_host_env() -> Self {
        let approval_directory = std::env::var_os("TENKAI_PLAN_APPROVAL_DIR").map(PathBuf::from);
        let trust_roots = std::env::var_os("TENKAI_PLAN_APPROVAL_TRUST_ROOTS").map(PathBuf::from);
        Self {
            skip_gates: false,
            auto_signing: approval_directory.is_some() && trust_roots.is_some(),
            trust_roots,
            approval_directory,
            local_development_reason: None,
        }
    }
}

/// `Ok` is a verified human envelope. `Err` is a human envelope that cannot
/// authorize execution. `None` means no human envelope is present.
pub(crate) async fn pending_human_evidence(
    ctx: &mut crate::client::Ctx,
    plan: &Plan,
    execution: &ExecutionPolicy,
    now: i64,
) -> Option<Result<VerificationEvidence, ()>> {
    let directory = execution.approval_directory.as_ref()?;
    let path = directory.join(format!("{}.json", plan.id));
    if !path.is_file() {
        return None;
    }
    match is_auto_envelope(&path) {
        Ok(true) => return None,
        Ok(false) => {}
        Err(_) => return Some(Err(())),
    }
    let Some(trust_roots) = execution.trust_roots.as_ref() else {
        return Some(Err(()));
    };
    match crate::plan_approval::verify_for_execution(
        ctx,
        plan,
        &path,
        trust_roots,
        now,
        execution.skip_gates,
    )
    .await
    {
        Ok(evidence) => Some(Ok(evidence)),
        Err(_) => Some(Err(())),
    }
}

/// True when reconcile would reuse `$DIR/<plan-id>.json` as automatic approval
/// and execution verification would reject it instead of refreshing.
pub(crate) async fn reused_auto_envelope_is_unexecutable(
    ctx: &mut crate::client::Ctx,
    policy: Option<&ApprovalPolicy>,
    plan: &Plan,
    signals: DeliverySignals,
    execution: &ExecutionPolicy,
    now: i64,
) -> bool {
    let Some(directory) = execution.approval_directory.as_ref() else {
        return false;
    };
    let Some(trust_roots) = execution.trust_roots.as_ref() else {
        return false;
    };
    let path = directory.join(format!("{}.json", plan.id));
    if !path.is_file() {
        return false;
    }
    match is_auto_envelope(&path) {
        Ok(true) => {}
        _ => return false,
    }
    let Some(policy) = policy else {
        return false;
    };
    if !matches!(
        evaluate(policy, plan, execution.skip_gates, signals),
        Decision::Auto { .. }
    ) || !auto_signer_present(policy)
        || !auto_envelope_current(&path, policy, now)
            .ok()
            .unwrap_or(false)
    {
        return false;
    }
    crate::plan_approval::verify_for_execution(
        ctx,
        plan,
        &path,
        trust_roots,
        now,
        execution.skip_gates,
    )
    .await
    .is_err()
}

pub(crate) fn development_bypass_current(plan: &Plan, execution: &ExecutionPolicy) -> bool {
    execution.local_development_reason.is_some() && plan.environment == "local"
}

fn recorded_survives_missing_envelope(
    evidence: &VerificationEvidence,
    plan: &Plan,
    execution: &ExecutionPolicy,
) -> bool {
    if evidence.policy_provider == POLICY_PROVIDER {
        return true;
    }
    evidence.policy_provider == "builtin-local-development"
        && development_bypass_current(plan, execution)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InspectedApproval {
    pub evidence: Option<VerificationEvidence>,
    pub blocked_human: bool,
}

/// Current human envelope for pending plans; recorded auto or development if
/// the envelope is absent; historical recorded evidence after execution starts.
/// Computed and blocked plans without a verified current envelope do not keep
/// recorded human evidence.
pub(crate) async fn inspect_approval_evidence(
    ctx: &mut crate::client::Ctx,
    plan: &Plan,
    recorded: Option<VerificationEvidence>,
    execution: &ExecutionPolicy,
    now: i64,
) -> InspectedApproval {
    let consult_envelope = plan_awaiting_execution(plan);
    if recorded.is_none() || consult_envelope {
        match pending_human_evidence(ctx, plan, execution, now).await {
            Some(Ok(pending)) => {
                return InspectedApproval {
                    evidence: Some(pending),
                    blocked_human: false,
                };
            }
            Some(Err(())) => {
                return InspectedApproval {
                    evidence: None,
                    blocked_human: true,
                };
            }
            None => {
                if consult_envelope {
                    return InspectedApproval {
                        evidence: recorded.filter(|evidence| {
                            recorded_survives_missing_envelope(evidence, plan, execution)
                        }),
                        blocked_human: false,
                    };
                }
            }
        }
    }
    InspectedApproval {
        evidence: recorded,
        blocked_human: false,
    }
}

pub(crate) fn blocked_pending_human_view() -> PlanApprovalView {
    PlanApprovalView {
        source: "required".into(),
        reason: Some("pending human approval is not executable".into()),
        policy_provider: None,
    }
}

/// Explain a plan's approval against the live policy and any recorded envelope.
pub fn explain_plan_approval(
    policy: Option<&ApprovalPolicy>,
    plan: &Plan,
    signals: DeliverySignals,
    recorded: Option<&VerificationEvidence>,
    now: i64,
    execution: ExecutionPolicy,
) -> PlanApprovalView {
    let recorded_provider = recorded.map(|evidence| evidence.policy_provider.as_str());
    let expired = recorded.is_some_and(|evidence| now > evidence.expires_at);
    if plan_awaiting_execution(plan) && development_bypass_current(plan, &execution) {
        return PlanApprovalView {
            source: "development".into(),
            reason: recorded
                .and_then(|evidence| evidence.bypass_reason.clone())
                .or_else(|| execution.local_development_reason.clone()),
            policy_provider: Some("builtin-local-development".into()),
        };
    }
    if recorded_provider == Some("builtin-local-development") && !plan_awaiting_execution(plan) {
        return PlanApprovalView {
            source: "development".into(),
            reason: recorded.and_then(|evidence| evidence.bypass_reason.clone()),
            policy_provider: Some("builtin-local-development".into()),
        };
    }
    if let Some(provider) = recorded_provider
        .filter(|provider| *provider != POLICY_PROVIDER && *provider != "builtin-local-development")
    {
        if plan_awaiting_execution(plan) && expired {
            return PlanApprovalView {
                source: "required".into(),
                reason: Some("recorded human approval has expired".into()),
                policy_provider: Some(provider.into()),
            };
        }
        if plan_awaiting_execution(plan)
            && recorded.is_some_and(|evidence| evidence.skip_gates != execution.skip_gates)
        {
            return PlanApprovalView {
                source: "required".into(),
                reason: Some("recorded human approval is bound to a different gate policy".into()),
                policy_provider: Some(provider.into()),
            };
        }
        return PlanApprovalView {
            source: "human".into(),
            reason: None,
            policy_provider: Some(provider.into()),
        };
    }
    if recorded_provider == Some(POLICY_PROVIDER) && !plan_awaiting_execution(plan) {
        return PlanApprovalView {
            source: "policy".into(),
            reason: None,
            policy_provider: Some(POLICY_PROVIDER.into()),
        };
    }
    let Some(policy) = policy else {
        return PlanApprovalView {
            source: "required".into(),
            reason: Some("no environment approval policy".into()),
            policy_provider: recorded_provider.map(str::to_string),
        };
    };
    match evaluate(policy, plan, execution.skip_gates, signals) {
        Decision::RequireHuman { reason } => PlanApprovalView {
            source: "required".into(),
            reason: Some(reason),
            policy_provider: recorded_provider.map(str::to_string),
        },
        Decision::Auto { .. } if !auto_signer_present(policy) => PlanApprovalView {
            source: "required".into(),
            reason: Some("automatic signer key is unavailable".into()),
            policy_provider: recorded_provider.map(str::to_string),
        },
        Decision::Auto { .. } if !execution.auto_signing => PlanApprovalView {
            source: "required".into(),
            reason: Some("automatic approval is not configured on this host".into()),
            policy_provider: recorded_provider.map(str::to_string),
        },
        Decision::Auto { .. }
            if execution
                .trust_roots
                .as_deref()
                .is_some_and(|path| !auto_signer_trusted(policy, plan, path)) =>
        {
            PlanApprovalView {
                source: "required".into(),
                reason: Some("automatic signer is not trusted by this host".into()),
                policy_provider: recorded_provider.map(str::to_string),
            }
        }
        Decision::Auto { .. } => {
            let stale = recorded_provider == Some(POLICY_PROVIDER)
                && (expired
                    || recorded.is_some_and(|evidence| {
                        policy.digest().ok().as_deref() != Some(evidence.policy_digest.as_str())
                            || signer_key_id(policy).ok().flatten().as_deref()
                                != Some(evidence.key_id.as_str())
                    }));
            PlanApprovalView {
                source: "policy".into(),
                reason: stale.then(|| "stale automatic approval will refresh".into()),
                policy_provider: Some(POLICY_PROVIDER.into()),
            }
        }
    }
}

fn auto_signer_present(policy: &ApprovalPolicy) -> bool {
    policy
        .auto_signer_key
        .as_deref()
        .is_some_and(|path| load_auto_signer_seed(path).is_ok())
}

fn auto_signer_trusted(policy: &ApprovalPolicy, plan: &Plan, roots_path: &Path) -> bool {
    let Ok(Some(key_id)) = signer_key_id(policy) else {
        return false;
    };
    let Ok(roots) = crate::plan_approval::TrustRoots::load(roots_path) else {
        return false;
    };
    let Ok(signer) = roots.signer(&key_id) else {
        return false;
    };
    !signer.environments.is_empty()
        && signer
            .environments
            .iter()
            .any(|env| env == &plan.environment)
        && signer.providers == [POLICY_PROVIDER]
}

fn signer_unavailable(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text.contains("auto signer key") && (text.contains("not found") || text.contains("missing"))
}

fn sign_auto_approval(
    policy: &ApprovalPolicy,
    plan: &Plan,
    skip_gates: bool,
    now: i64,
    evidence_id: String,
    approval_out: &Path,
) -> Result<()> {
    let key_path = policy
        .auto_signer_key
        .as_deref()
        .context("auto plan approval policy requires auto_signer_key")?;
    let seed = load_auto_signer_seed(key_path)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let expires_at = now
        .checked_add(policy.ttl_ms)
        .ok_or_else(|| anyhow::anyhow!("plan approval policy ttl_ms overflowed expiry"))?;
    let statement = ApprovalStatement {
        plan_digest: format!("sha256:{}", plan.executable_digest()?),
        environment: plan.environment.clone(),
        purpose: PURPOSE.into(),
        skip_gates,
        issued_at: now,
        expires_at,
        policy_provider: POLICY_PROVIDER.into(),
        policy_evidence_id: evidence_id,
        policy_digest: policy.digest()?,
    };
    let bytes = canonical_bytes(&statement)?;
    let signature = signing_key.sign(&bytes);
    let public = signing_key.verifying_key().to_bytes();
    let envelope = ApprovalEnvelope {
        schema: APPROVAL_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&public),
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    };
    write_text_owner_only(approval_out, &serde_json::to_string_pretty(&envelope)?)?;
    Ok(())
}

fn load_auto_signer_seed(path: &Path) -> Result<[u8; 32]> {
    let meta = fs::symlink_metadata(path).with_context(|| {
        if path.exists() {
            format!("inspecting auto signer key {}", path.display())
        } else {
            format!("auto signer key {} is missing", path.display())
        }
    })?;
    if meta.file_type().is_symlink() {
        bail!("auto signer key {} must not be a symlink", path.display());
    }
    if !meta.file_type().is_file() {
        bail!("auto signer key {} must be a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "auto signer key {} must be mode 0600 (or owner-only); found {:o}",
                path.display(),
                mode
            );
        }
    }
    if meta.len() != 32 {
        bail!(
            "auto signer key {} must be exactly 32 bytes (got {})",
            path.display(),
            meta.len()
        );
    }
    let bytes =
        fs::read(path).with_context(|| format!("reading auto signer key {}", path.display()))?;
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn write_text_owner_only(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent for {}", path.display()))?;
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            bail!(
                "refusing to write through symlink {} (remove it or choose another path)",
                path.display()
            );
        }
        if !meta.file_type().is_file() {
            bail!("refusing to write {}: not a regular file", path.display());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        opts.custom_flags(libc::O_NOFOLLOW);
        opts.mode(0o600);
        match opts.open(path) {
            Ok(mut file) => {
                file.write_all(contents.as_bytes())
                    .with_context(|| format!("writing {}", path.display()))?;
                let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
            }
            Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
                bail!(
                    "refusing to write through symlink {} (remove it or choose another path)",
                    path.display()
                );
            }
            Err(err) => {
                return Err(err).with_context(|| format!("writing {}", path.display()));
            }
        }
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

/// Merge the signed `[delivery]` signals of every release a plan crosses.
/// An upgrade crosses each published version in `(from, to]`, so skipping an
/// intermediate migration still counts; a downgrade or rollback reverses each
/// version in `(to, from]`. A restart re-activates the deployed release and
/// contributes nothing.
pub(crate) async fn delivery_signals_for_plan(
    ctx: &mut crate::client::Ctx,
    plan: &Plan,
) -> Result<crate::approval_policy::DeliverySignals> {
    use crate::approval_policy::DeliverySignals;
    use crate::plan::Action;
    let mut signals = DeliverySignals::default();
    let mut releases = None;
    for step in &plan.steps {
        if step.action == Action::Restart {
            continue;
        }
        if let Some(release) = ctx.get(&step.release_id).await? {
            signals = signals.merge(DeliverySignals::target(&release.properties));
        }
        let reverse = matches!(step.action, Action::Downgrade | Action::Rollback);
        let Some(from) = &step.from else {
            continue;
        };
        let range = semver::Version::parse(from)
            .and_then(|from| Ok((from, semver::Version::parse(&step.to)?)));
        let Ok((from, to)) = range else {
            // Without ordered versions, only the departed release is known.
            if reverse
                && let Some(release) = ctx
                    .get(&crate::ontology::release_id(&step.product, from))
                    .await?
            {
                signals = signals.merge(DeliverySignals::departed(&release.properties));
            }
            continue;
        };
        let (low, high) = if reverse { (&to, &from) } else { (&from, &to) };
        if releases.is_none() {
            releases = Some(ctx.list_kind(crate::ontology::KIND_RELEASE).await?);
        }
        for release in releases.iter().flatten() {
            let crossed = release.properties.get("product") == Some(&step.product)
                && release
                    .properties
                    .get("version")
                    .and_then(|version| semver::Version::parse(version).ok())
                    .is_some_and(|version| *low < version && version <= *high);
            if !crossed {
                continue;
            }
            signals = signals.merge(if reverse {
                DeliverySignals::departed(&release.properties)
            } else {
                DeliverySignals::target(&release.properties)
            });
        }
    }
    Ok(signals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{DesiredStateInput, PLAN_FORMAT_VERSION, PlanState, ReleasePin, Step};
    use crate::plan_approval::verify;

    fn sample_plan(action: Action, product: &str) -> Plan {
        let created_at = 1_700_000_000_000;
        let content_id = "digest-a".to_string();
        let environment = "lab";
        let id = crate::ontology::plan_id(environment, created_at, &content_id);
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            id,
            content_id,
            environment: environment.into(),
            created_at,
            inputs: vec![DesiredStateInput {
                product: product.into(),
                channel: "stable".into(),
                channel_id: "tenkai:channel:api/stable".into(),
                desired_version: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                deployed_version: None,
            }],
            steps: vec![Step {
                id: "step-0".into(),
                order: 0,
                product: product.into(),
                action,
                from: None,
                to: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                workdir: ".".into(),
                restore: match action {
                    Action::Rollback => Some(ReleasePin {
                        release_id: "tenkai:release:api@0.9.0".into(),
                        digest: "abc".into(),
                        artifact_digest: "abc".into(),
                        workdir: ".".into(),
                    }),
                    _ => None,
                },
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
        }
    }

    fn auto_policy(key: &Path, product: Option<&str>) -> ApprovalPolicy {
        ApprovalPolicy {
            version: 1,
            mode: PolicyMode::Auto,
            ttl_ms: 60_000,
            auto_signer_key: Some(key.to_path_buf()),
            require_human: product
                .map(|name| {
                    vec![RequireHumanRule {
                        product: name.into(),
                    }]
                })
                .unwrap_or_default(),
            source_digest: None,
        }
    }

    fn write_seed(dir: &Path) -> PathBuf {
        let path = dir.join("auto-approver.ed25519");
        let seed = [7_u8; 32];
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(&seed).unwrap();
        }
        #[cfg(not(unix))]
        {
            fs::write(&path, seed).unwrap();
        }
        path
    }

    fn write_policy(dir: &Path, policy: &ApprovalPolicy) -> PathBuf {
        let path = dir.join("policy.toml");
        fs::write(&path, toml::to_string(policy).unwrap()).unwrap();
        path
    }

    fn write_trust_roots(dir: &Path, seed: &[u8; 32]) -> PathBuf {
        let signing_key = SigningKey::from_bytes(seed);
        let public = signing_key.verifying_key().to_bytes();
        let kid = crate::signature_verification::key_id(&public);
        let path = dir.join("trust.toml");
        fs::write(
            &path,
            format!(
                "version = 1\n\n[[signers]]\nkey_id = \"{kid}\"\nidentity = \"auto-approver@lab\"\npublic_key = \"{}\"\nenvironments = [\"lab\"]\nproviders = [\"builtin-auto\"]\n",
                STANDARD.encode(public)
            ),
        )
        .unwrap();
        path
    }

    fn recorded(
        provider: &str,
        digest: Option<&str>,
        expires_at: i64,
        bypass: Option<&str>,
        key_id: &str,
    ) -> VerificationEvidence {
        VerificationEvidence {
            schema: APPROVAL_SCHEMA.into(),
            plan_id: "plan".into(),
            plan_digest: "sha256:aa".into(),
            environment: "lab".into(),
            signer_identity: provider.into(),
            key_id: key_id.into(),
            policy_provider: provider.into(),
            policy_evidence_id: "auto".into(),
            policy_digest: digest.unwrap_or("sha256:bb").into(),
            issued_at: 1,
            expires_at,
            verified_at: 1,
            skip_gates: false,
            bypass_reason: bypass.map(str::to_string),
        }
    }

    fn unique_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tenkai-approval-policy-{}-{}-{}",
            label,
            std::process::id(),
            crate::now_millis()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn automatic_keys_cannot_impersonate_humans_and_revocation_preserves_human_approval() {
        let dir = unique_dir("signer-scope");
        fs::create_dir_all(&dir).unwrap();
        let key = write_seed(&dir);
        let policy = auto_policy(&key, None);
        let policy_path = dir.join("policy.toml");
        fs::write(&policy_path, toml::to_string(&policy).unwrap()).unwrap();
        let mut ctx = crate::client::Ctx::embedded(dir.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "lab", "Lab").await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "Production")
            .await
            .unwrap();
        crate::environment::set_plan_approval_policy(&mut ctx, "lab", &policy_path)
            .await
            .unwrap();
        let mut plan = sample_plan(Action::Install, "api");
        plan.environment = "prod".into();
        let now = crate::now_millis();
        let envelope_path = dir.join("forged.json");
        sign_auto_approval(&policy, &plan, false, now, "auto".into(), &envelope_path).unwrap();
        let mut forged: ApprovalEnvelope =
            serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
        forged.statement.policy_provider = "human".into();
        forged.signature = STANDARD.encode(
            SigningKey::from_bytes(&[7_u8; 32])
                .sign(&canonical_bytes(&forged.statement).unwrap())
                .to_bytes(),
        );
        fs::write(&envelope_path, serde_json::to_vec(&forged).unwrap()).unwrap();
        let trust = write_trust_roots(&dir, &[7_u8; 32]);
        let mut legacy = crate::plan_approval::TrustRoots::load(&trust).unwrap();
        legacy.signers[0].environments.clear();
        legacy.signers[0].providers.clear();
        fs::write(&trust, toml::to_string(&legacy).unwrap()).unwrap();
        assert!(
            crate::plan_approval::verify_for_execution(
                &mut ctx,
                &plan,
                &envelope_path,
                &trust,
                now + 1,
                false
            )
            .await
            .is_err()
        );
        legacy.signers[0].environments = vec!["prod".into()];
        legacy.signers[0].providers = vec!["human".into()];
        fs::write(&trust, toml::to_string(&legacy).unwrap()).unwrap();
        assert!(
            crate::plan_approval::verify_for_execution(
                &mut ctx,
                &plan,
                &envelope_path,
                &trust,
                now + 1,
                false
            )
            .await
            .is_err()
        );
        fs::remove_file(&key).unwrap();
        assert!(
            crate::plan_approval::verify_for_execution(
                &mut ctx,
                &plan,
                &envelope_path,
                &trust,
                now + 1,
                false
            )
            .await
            .is_err()
        );
        crate::dev_sign::sign_plan_approval_for_digest(
            &dir.join("human-keys"),
            &format!("sha256:{}", plan.executable_digest().unwrap()),
            "prod",
            &envelope_path,
            &trust,
            3600,
        )
        .unwrap();
        crate::plan_approval::verify_for_execution(
            &mut ctx,
            &plan,
            &envelope_path,
            &trust,
            crate::now_millis(),
            false,
        )
        .await
        .unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn policy_changes_revoke_pending_auto_approvals_and_reconcile_refreshes_them() {
        let dir = unique_dir("policy-digest");
        let key = write_seed(&dir);
        let mut policy = auto_policy(&key, None);
        let policy_path = write_policy(&dir, &policy);
        let mut ctx = crate::client::Ctx::embedded(dir.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "lab", "fixture")
            .await
            .unwrap();
        crate::environment::set_plan_approval_policy(&mut ctx, "lab", &policy_path)
            .await
            .unwrap();
        let plan = sample_plan(Action::Install, "api");
        let now = crate::now_millis();
        let approvals = dir.join("approvals");
        let properties = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap()
            .properties;
        let AutoEnvelope::Signed(envelope) = resolve_auto_envelope(
            &properties,
            &plan,
            false,
            DeliverySignals::default(),
            &approvals,
            now,
        )
        .unwrap() else {
            panic!("expected initial automatic approval")
        };
        let roots = write_trust_roots(&dir, &[7_u8; 32]);
        crate::plan_approval::verify_for_execution(&mut ctx, &plan, &envelope, &roots, now, false)
            .await
            .unwrap();

        policy.ttl_ms /= 2;
        fs::write(&policy_path, toml::to_string(&policy).unwrap()).unwrap();
        let properties = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap()
            .properties;
        let error = crate::plan_approval::verify_for_execution(
            &mut ctx,
            &plan,
            &envelope,
            &roots,
            now + 1,
            false,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("policy digest"), "{error}");
        assert!(matches!(
            resolve_auto_envelope(
                &properties,
                &plan,
                false,
                DeliverySignals::default(),
                &approvals,
                now + 1,
            )
            .unwrap(),
            AutoEnvelope::Signed(_)
        ));
        let refreshed = crate::plan_approval::verify_for_execution(
            &mut ctx,
            &plan,
            &envelope,
            &roots,
            now + 1,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            refreshed.policy_digest,
            ApprovalPolicy::load(&policy_path)
                .unwrap()
                .digest()
                .unwrap()
        );

        let mut environment = crate::environment::environment(&mut ctx, "lab")
            .await
            .unwrap();
        environment.properties.remove(PLAN_APPROVAL_POLICY_PROPERTY);
        ctx.put(environment).await.unwrap();
        assert!(
            crate::plan_approval::verify_for_execution(
                &mut ctx,
                &plan,
                &envelope,
                &roots,
                now + 2,
                false
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("live environment policy")
        );
        crate::dev_sign::sign_plan_approval_for_digest(
            &dir.join("human-keys"),
            &format!("sha256:{}", plan.executable_digest().unwrap()),
            "lab",
            &envelope,
            &roots,
            3600,
        )
        .unwrap();
        crate::plan_approval::verify_for_execution(
            &mut ctx,
            &plan,
            &envelope,
            &roots,
            crate::now_millis(),
            false,
        )
        .await
        .unwrap();
        drop(ctx);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn evaluate_allows_matching_install_and_requires_human_for_defaults() {
        let policy = auto_policy(Path::new("/tmp/key"), None);
        let install = sample_plan(Action::Install, "api");
        assert!(matches!(
            evaluate(&policy, &install, false, DeliverySignals::default()),
            Decision::Auto { .. }
        ));
        assert!(matches!(
            evaluate(&policy, &install, true, DeliverySignals::default()),
            Decision::RequireHuman { reason } if reason.contains("skip_gates")
        ));
        let rollback = sample_plan(Action::Rollback, "api");
        assert!(matches!(
            evaluate(&policy, &rollback, false, DeliverySignals::default()),
            Decision::RequireHuman { reason } if reason.contains("rollback")
        ));
        let downgrade = sample_plan(Action::Downgrade, "api");
        assert!(matches!(
            evaluate(&policy, &downgrade, false, DeliverySignals::default()),
            Decision::RequireHuman { reason } if reason.contains("downgrade")
        ));
        let payments = auto_policy(Path::new("/tmp/key"), Some("payments"));
        assert!(matches!(
            evaluate(
                &payments,
                &sample_plan(Action::Install, "payments"),
                false,
                DeliverySignals::default()
            ),
            Decision::RequireHuman { reason } if reason.contains("payments")
        ));
        let mut manual = policy.clone();
        manual.mode = PolicyMode::Manual;
        assert!(matches!(
            evaluate(&manual, &install, false, DeliverySignals::default()),
            Decision::RequireHuman { reason } if reason.contains("manual")
        ));
    }

    #[test]
    fn explain_covers_policy_approved_downgrade_and_stale_refresh() {
        let dir = unique_dir("explain");
        let key = write_seed(&dir);
        let policy = auto_policy(&key, None);
        let live_key = signer_key_id(&policy).unwrap().unwrap();
        let install = sample_plan(Action::Install, "api");
        let approved = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            Some(&recorded(
                POLICY_PROVIDER,
                policy.digest().ok().as_deref(),
                20,
                None,
                &live_key,
            )),
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(approved.source, "policy");
        assert_eq!(approved.reason, None);

        let missing_signer = auto_policy(Path::new("/tmp/missing-auto-signer"), None);
        let unavailable = explain_plan_approval(
            Some(&missing_signer),
            &install,
            DeliverySignals::default(),
            None,
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(unavailable.source, "required");
        assert_eq!(
            unavailable.reason.as_deref(),
            Some("automatic signer key is unavailable")
        );

        let downgrade = sample_plan(Action::Downgrade, "api");
        let human = explain_plan_approval(
            Some(&policy),
            &downgrade,
            DeliverySignals::default(),
            None,
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(human.source, "required");
        assert!(
            human.reason.as_deref().unwrap().contains("downgrade"),
            "{human:?}"
        );

        let stale = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            Some(&recorded(
                POLICY_PROVIDER,
                Some("sha256:old"),
                20,
                None,
                &live_key,
            )),
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(stale.source, "policy");
        assert_eq!(
            stale.reason.as_deref(),
            Some("stale automatic approval will refresh")
        );

        let rotated = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            Some(&recorded(
                POLICY_PROVIDER,
                policy.digest().ok().as_deref(),
                20,
                None,
                "sha256:rotated-signer",
            )),
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(rotated.source, "policy");
        assert_eq!(
            rotated.reason.as_deref(),
            Some("stale automatic approval will refresh")
        );

        let expired = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            Some(&recorded("alice", None, 5, None, "kid")),
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(expired.source, "required");
        assert_eq!(
            expired.reason.as_deref(),
            Some("recorded human approval has expired")
        );

        let mut succeeded = install.clone();
        succeeded.state = PlanState::Succeeded;
        let completed = explain_plan_approval(
            None,
            &succeeded,
            DeliverySignals::default(),
            Some(&recorded(
                POLICY_PROVIDER,
                Some("sha256:old"),
                5,
                None,
                "kid",
            )),
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(completed.source, "policy");
        assert_eq!(completed.reason, None);
        let preserved = explain_plan_approval(
            None,
            &install,
            DeliverySignals::default(),
            Some(&recorded("alice", None, 20, None, "kid")),
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(preserved.source, "human");
        let mut running = install.clone();
        running.state = PlanState::Running;
        let in_flight = explain_plan_approval(
            None,
            &running,
            DeliverySignals::default(),
            Some(&recorded("alice", None, 5, None, "kid")),
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(in_flight.source, "human");
        let development = explain_plan_approval(
            None,
            &succeeded,
            DeliverySignals::default(),
            Some(&recorded(
                "builtin-local-development",
                None,
                5,
                Some("exercise local executor"),
                "kid",
            )),
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(development.source, "development");
        assert_eq!(
            development.reason.as_deref(),
            Some("exercise local executor")
        );
        let skip_gates = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            None,
            10,
            ExecutionPolicy {
                skip_gates: true,
                ..ExecutionPolicy::default()
            },
        );
        assert_eq!(skip_gates.source, "required");
        assert!(
            skip_gates.reason.as_deref().unwrap().contains("skip_gates"),
            "{skip_gates:?}"
        );
        let mut human_envelope = recorded("alice", None, 20, None, "kid");
        let mismatched_gates = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            Some(&human_envelope),
            10,
            ExecutionPolicy {
                skip_gates: true,
                ..ExecutionPolicy::default()
            },
        );
        assert_eq!(mismatched_gates.source, "required");
        assert_eq!(
            mismatched_gates.reason.as_deref(),
            Some("recorded human approval is bound to a different gate policy")
        );
        human_envelope.skip_gates = true;
        let matching_gates = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            Some(&human_envelope),
            10,
            ExecutionPolicy {
                skip_gates: true,
                ..ExecutionPolicy::default()
            },
        );
        assert_eq!(matching_gates.source, "human");
        let unsigned_host = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            None,
            10,
            ExecutionPolicy {
                auto_signing: false,
                ..ExecutionPolicy::default()
            },
        );
        assert_eq!(unsigned_host.source, "required");
        assert_eq!(
            unsigned_host.reason.as_deref(),
            Some("automatic approval is not configured on this host")
        );
        let untrusted = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            None,
            10,
            ExecutionPolicy {
                trust_roots: Some(write_trust_roots(&dir, &[8_u8; 32])),
                ..ExecutionPolicy::default()
            },
        );
        assert_eq!(untrusted.source, "required");
        assert_eq!(
            untrusted.reason.as_deref(),
            Some("automatic signer is not trusted by this host")
        );
        let trusted = explain_plan_approval(
            Some(&policy),
            &install,
            DeliverySignals::default(),
            None,
            10,
            ExecutionPolicy {
                trust_roots: Some(write_trust_roots(&dir, &[7_u8; 32])),
                ..ExecutionPolicy::default()
            },
        );
        assert_eq!(trusted.source, "policy");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_development_bypass_follows_host_authorization() {
        let install = sample_plan(Action::Install, "api");
        let evidence = recorded(
            "builtin-local-development",
            None,
            5,
            Some("exercise local executor"),
            "",
        );
        let stale = explain_plan_approval(
            None,
            &install,
            DeliverySignals::default(),
            Some(&evidence),
            10,
            ExecutionPolicy::default(),
        );
        assert_eq!(stale.source, "required");
        assert_eq!(
            stale.reason.as_deref(),
            Some("no environment approval policy")
        );

        let mut local = install.clone();
        local.environment = "local".into();
        let host = ExecutionPolicy {
            local_development_reason: Some("exercise local executor".into()),
            ..ExecutionPolicy::default()
        };
        let current = explain_plan_approval(
            None,
            &local,
            DeliverySignals::default(),
            Some(&evidence),
            10,
            host.clone(),
        );
        assert_eq!(current.source, "development");
        assert_eq!(current.reason.as_deref(), Some("exercise local executor"));

        let before_record = explain_plan_approval(
            None,
            &local,
            DeliverySignals::default(),
            None,
            10,
            host.clone(),
        );
        assert_eq!(before_record.source, "development");
        assert_eq!(
            before_record.reason.as_deref(),
            Some("exercise local executor")
        );

        let other_env = explain_plan_approval(
            None,
            &install,
            DeliverySignals::default(),
            Some(&evidence),
            10,
            host,
        );
        assert_eq!(other_env.source, "required");
        assert_eq!(
            other_env.reason.as_deref(),
            Some("no environment approval policy")
        );
    }

    #[tokio::test]
    async fn pending_development_evidence_is_dropped_when_host_disables_bypass() {
        let dir = unique_dir("pending-dev");
        let mut ctx = crate::client::Ctx::embedded(dir.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "lab", "Lab").await.unwrap();
        let plan = sample_plan(Action::Install, "api");
        let evidence = recorded(
            "builtin-local-development",
            None,
            crate::now_millis() + 60_000,
            Some("exercise local executor"),
            "",
        );
        let dropped = inspect_approval_evidence(
            &mut ctx,
            &plan,
            Some(evidence.clone()),
            &ExecutionPolicy::default(),
            crate::now_millis(),
        )
        .await;
        assert!(dropped.evidence.is_none());
        assert!(!dropped.blocked_human);

        let mut local = plan.clone();
        local.environment = "local".into();
        let kept = inspect_approval_evidence(
            &mut ctx,
            &local,
            Some(evidence),
            &ExecutionPolicy {
                local_development_reason: Some("exercise local executor".into()),
                ..ExecutionPolicy::default()
            },
            crate::now_millis(),
        )
        .await;
        assert_eq!(
            kept.evidence
                .as_ref()
                .map(|evidence| evidence.policy_provider.as_str()),
            Some("builtin-local-development")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pending_human_envelope_is_verified_and_auto_envelopes_are_ignored() {
        let dir = unique_dir("pending-human");
        let mut ctx = crate::client::Ctx::embedded(dir.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "lab", "Lab").await.unwrap();
        let plan = sample_plan(Action::Install, "api");
        let approvals = dir.join("approvals");
        fs::create_dir_all(&approvals).unwrap();
        let envelope = approvals.join(format!("{}.json", plan.id));
        let roots = dir.join("human-trust.toml");
        crate::dev_sign::sign_plan_approval_for_digest(
            &dir.join("human-keys"),
            &format!("sha256:{}", plan.executable_digest().unwrap()),
            "lab",
            &envelope,
            &roots,
            3600,
        )
        .unwrap();
        let execution = ExecutionPolicy {
            trust_roots: Some(roots.clone()),
            approval_directory: Some(approvals.clone()),
            ..ExecutionPolicy::default()
        };
        let now = crate::now_millis();
        let human = pending_human_evidence(&mut ctx, &plan, &execution, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(human.policy_provider, "builtin");
        assert_eq!(human.plan_id, plan.id);
        let expired_now = now + 4_000_000;
        assert!(matches!(
            pending_human_evidence(&mut ctx, &plan, &execution, expired_now).await,
            Some(Err(()))
        ));
        let blocked =
            inspect_approval_evidence(&mut ctx, &plan, None, &execution, expired_now).await;
        assert!(blocked.blocked_human);
        let expired_human = recorded("alice", None, 5, None, "kid");
        let renewed = inspect_approval_evidence(
            &mut ctx,
            &plan,
            Some(expired_human.clone()),
            &execution,
            now,
        )
        .await
        .evidence
        .unwrap();
        assert_eq!(renewed.policy_provider, "builtin");
        fs::remove_file(&envelope).unwrap();
        let missing = inspect_approval_evidence(
            &mut ctx,
            &plan,
            Some(expired_human.clone()),
            &execution,
            now,
        )
        .await;
        assert!(!missing.blocked_human);
        assert!(missing.evidence.is_none());
        let no_host = inspect_approval_evidence(
            &mut ctx,
            &plan,
            Some(expired_human.clone()),
            &ExecutionPolicy::default(),
            now,
        )
        .await;
        assert!(!no_host.blocked_human);
        assert!(no_host.evidence.is_none());
        let mut running = plan.clone();
        running.state = PlanState::Running;
        let in_flight =
            inspect_approval_evidence(&mut ctx, &running, Some(expired_human), &execution, now)
                .await
                .evidence
                .unwrap();
        assert_eq!(in_flight.policy_provider, "alice");
        crate::dev_sign::sign_plan_approval_for_digest(
            &dir.join("human-keys"),
            &format!("sha256:{}", plan.executable_digest().unwrap()),
            "lab",
            &envelope,
            &roots,
            3600,
        )
        .unwrap();

        let key = write_seed(&dir);
        let policy = auto_policy(&key, None);
        crate::environment::set_plan_approval_policy(&mut ctx, "lab", &write_policy(&dir, &policy))
            .await
            .unwrap();
        sign_auto_approval(&policy, &plan, false, now, "auto".into(), &envelope).unwrap();
        assert!(
            pending_human_evidence(&mut ctx, &plan, &execution, now)
                .await
                .is_none()
        );

        let mut forged: ApprovalEnvelope =
            serde_json::from_slice(&fs::read(&envelope).unwrap()).unwrap();
        forged.statement.policy_provider = "human".into();
        forged.signature = STANDARD.encode(
            SigningKey::from_bytes(&[7_u8; 32])
                .sign(&canonical_bytes(&forged.statement).unwrap())
                .to_bytes(),
        );
        fs::write(&envelope, serde_json::to_vec(&forged).unwrap()).unwrap();
        let public = SigningKey::from_bytes(&[7_u8; 32])
            .verifying_key()
            .to_bytes();
        let kid = crate::signature_verification::key_id(&public);
        let impersonation_roots = dir.join("impersonation-trust.toml");
        fs::write(
            &impersonation_roots,
            format!(
                "version = 1\n\n[[signers]]\nkey_id = \"{kid}\"\nidentity = \"auto-approver@lab\"\npublic_key = \"{}\"\n",
                STANDARD.encode(public)
            ),
        )
        .unwrap();
        let impersonating = ExecutionPolicy {
            trust_roots: Some(impersonation_roots),
            approval_directory: Some(approvals.clone()),
            ..ExecutionPolicy::default()
        };
        assert!(matches!(
            pending_human_evidence(&mut ctx, &plan, &impersonating, now).await,
            Some(Err(()))
        ));
        assert!(
            inspect_approval_evidence(&mut ctx, &plan, None, &impersonating, now)
                .await
                .blocked_human
        );

        fs::write(
            &envelope,
            format!(
                r#"{{"schema":"{APPROVAL_SCHEMA}","key_id":"sha256:dead","statement":{{"plan_digest":"sha256:{}","environment":"lab","purpose":"execute_plan","skip_gates":false,"issued_at":1,"expires_at":9999999999999,"policy_provider":"alice","policy_evidence_id":"x","policy_digest":"sha256:bb"}},"signature":"AAAA"}}"#,
                plan.executable_digest().unwrap()
            ),
        )
        .unwrap();
        assert!(matches!(
            pending_human_evidence(&mut ctx, &plan, &execution, now).await,
            Some(Err(()))
        ));
        assert!(
            pending_human_evidence(&mut ctx, &plan, &ExecutionPolicy::default(), now)
                .await
                .is_none()
        );
        drop(ctx);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reused_auto_envelope_with_bad_signature_is_unexecutable() {
        let dir = unique_dir("reused-auto");
        let mut ctx = crate::client::Ctx::embedded(dir.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "lab", "Lab").await.unwrap();
        let key = write_seed(&dir);
        let policy_path = write_policy(&dir, &auto_policy(&key, None));
        crate::environment::set_plan_approval_policy(&mut ctx, "lab", &policy_path)
            .await
            .unwrap();
        let policy = ApprovalPolicy::load(&policy_path).unwrap();
        let plan = sample_plan(Action::Install, "api");
        let approvals = dir.join("approvals");
        fs::create_dir_all(&approvals).unwrap();
        let envelope = approvals.join(format!("{}.json", plan.id));
        let now = crate::now_millis();
        sign_auto_approval(&policy, &plan, false, now, "auto".into(), &envelope).unwrap();
        let execution = ExecutionPolicy {
            trust_roots: Some(write_trust_roots(&dir, &[7_u8; 32])),
            approval_directory: Some(approvals),
            ..ExecutionPolicy::default()
        };
        assert!(
            !reused_auto_envelope_is_unexecutable(
                &mut ctx,
                Some(&policy),
                &plan,
                DeliverySignals::default(),
                &execution,
                now,
            )
            .await
        );
        let mut tampered: ApprovalEnvelope =
            serde_json::from_slice(&fs::read(&envelope).unwrap()).unwrap();
        tampered.signature = STANDARD.encode([0_u8; 64]);
        fs::write(&envelope, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(
            reused_auto_envelope_is_unexecutable(
                &mut ctx,
                Some(&policy),
                &plan,
                DeliverySignals::default(),
                &execution,
                now,
            )
            .await
        );
        drop(ctx);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn effective_policy_omits_key_material_and_lists_human_rules() {
        let unconfigured = effective_policy(&HashMap::new()).unwrap();
        assert!(!unconfigured.configured);
        assert_eq!(unconfigured.mode, "manual");
        assert_eq!(unconfigured.auto_signers.len(), 0);
        assert_eq!(
            unconfigured.require_human,
            vec!["all plans require a human-signed envelope"]
        );

        let dir = unique_dir("effective");
        let key = write_seed(&dir);
        let policy_path = write_policy(&dir, &auto_policy(&key, Some("payments")));
        let mut properties = HashMap::new();
        properties.insert(
            PLAN_APPROVAL_POLICY_PROPERTY.into(),
            policy_path.to_string_lossy().into_owned(),
        );
        let view = effective_policy(&properties).unwrap();
        assert!(view.configured);
        assert_eq!(view.mode, "auto");
        assert_eq!(view.ttl_ms, Some(60_000));
        assert_eq!(view.auto_signers.len(), 1);
        assert!(
            view.require_human
                .iter()
                .any(|rule| rule == "downgrade or rollback")
        );
        assert!(
            view.require_human
                .iter()
                .any(|rule| rule == "product payments")
        );
        let encoded = serde_json::to_string(&view).unwrap();
        assert!(!encoded.contains(&key.display().to_string()), "{encoded}");
        assert!(!encoded.contains("7".repeat(32).as_str()), "{encoded}");

        fs::remove_file(&key).unwrap();
        let revoked = effective_policy(&properties).unwrap();
        assert!(revoked.configured);
        assert_eq!(revoked.mode, "auto");
        assert!(revoked.auto_signers.is_empty());
        assert!(
            revoked
                .require_human
                .iter()
                .any(|rule| rule == "product payments")
        );

        let key = write_seed(&dir);
        let mut manual = auto_policy(&key, Some("payments"));
        manual.mode = PolicyMode::Manual;
        write_policy(&dir, &manual);
        let manual_view = effective_policy(&properties).unwrap();
        assert!(manual_view.configured);
        assert_eq!(manual_view.mode, "manual");
        assert!(manual_view.auto_signers.is_empty());
        assert_eq!(
            manual_view.require_human,
            vec!["all plans require a human-signed envelope"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn evaluate_requires_human_for_signed_delivery_metadata() {
        let policy = auto_policy(Path::new("/tmp/key"), None);
        let install = sample_plan(Action::Install, "api");
        assert!(matches!(
            evaluate(&policy, &install, false, DeliverySignals::default()),
            Decision::Auto { .. }
        ));
        assert!(matches!(
            evaluate(
                &policy,
                &install,
                false,
                DeliverySignals {
                    has_migration: true,
                    ..DeliverySignals::default()
                }
            ),
            Decision::RequireHuman { reason } if reason.contains("has_migration")
        ));
        assert!(matches!(
            evaluate(
                &policy,
                &install,
                false,
                DeliverySignals {
                    changes_identity_config: true,
                    ..DeliverySignals::default()
                }
            ),
            Decision::RequireHuman { reason } if reason.contains("changes_identity_config")
        ));
        assert!(matches!(
            evaluate(
                &policy,
                &sample_plan(Action::Downgrade, "api"),
                false,
                DeliverySignals {
                    reverses_migration: true,
                    ..DeliverySignals::default()
                }
            ),
            Decision::RequireHuman { .. }
        ));
    }

    #[test]
    fn downgrade_needs_human_without_creating_or_reusing_auto_approval() {
        let dir = unique_dir("downgrade");
        let key = write_seed(&dir);
        let policy = auto_policy(&key, None);
        let policy_path = write_policy(&dir, &policy);
        let plan = sample_plan(Action::Downgrade, "api");
        let now = 1_800_000_000_000;
        let approvals = dir.join("approvals");
        let properties = HashMap::from([(
            PLAN_APPROVAL_POLICY_PROPERTY.into(),
            policy_path.to_string_lossy().into_owned(),
        )]);
        let envelope = approvals.join(format!("{}.json", plan.id));
        assert_eq!(
            resolve_auto_envelope(
                &properties,
                &plan,
                false,
                DeliverySignals::default(),
                &approvals,
                now,
            )
            .unwrap(),
            AutoEnvelope::NeedsHuman
        );
        assert!(!envelope.exists());

        // Simulate a pending approval issued before downgrades required a human.
        sign_auto_approval(&policy, &plan, false, now, "auto".into(), &envelope).unwrap();
        assert_eq!(
            resolve_auto_envelope(
                &properties,
                &plan,
                false,
                DeliverySignals::default(),
                &approvals,
                now + 1,
            )
            .unwrap(),
            AutoEnvelope::NeedsHuman
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_delivery_signals_revoke_an_existing_auto_envelope() {
        let dir = unique_dir("signals-revoke");
        let key = write_seed(&dir);
        let policy = auto_policy(&key, None);
        let policy_path = write_policy(&dir, &policy);
        let plan = sample_plan(Action::Install, "api");
        let now = 1_800_000_000_000;
        let approvals = dir.join("approvals");
        fs::create_dir_all(&approvals).unwrap();
        let mut properties = HashMap::new();
        properties.insert(
            PLAN_APPROVAL_POLICY_PROPERTY.into(),
            policy_path.to_string_lossy().into_owned(),
        );
        assert!(matches!(
            resolve_auto_envelope(
                &properties,
                &plan,
                false,
                DeliverySignals::default(),
                &approvals,
                now
            )
            .unwrap(),
            AutoEnvelope::Signed(_)
        ));
        assert_eq!(
            resolve_auto_envelope(
                &properties,
                &plan,
                false,
                DeliverySignals {
                    has_migration: true,
                    ..DeliverySignals::default()
                },
                &approvals,
                now
            )
            .unwrap(),
            AutoEnvelope::NeedsHuman
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_sign_verifies_and_revoking_policy_or_expiry_needs_human() {
        let dir = unique_dir("sign");
        let key = write_seed(&dir);
        let policy = auto_policy(&key, None);
        let policy_path = write_policy(&dir, &policy);
        let plan = sample_plan(Action::Install, "api");
        let now = 1_800_000_000_000;
        let approvals = dir.join("approvals");
        fs::create_dir_all(&approvals).unwrap();
        let mut properties = HashMap::new();
        properties.insert(
            PLAN_APPROVAL_POLICY_PROPERTY.into(),
            policy_path.to_string_lossy().into_owned(),
        );

        let AutoEnvelope::Signed(envelope) = resolve_auto_envelope(
            &properties,
            &plan,
            false,
            DeliverySignals::default(),
            &approvals,
            now,
        )
        .unwrap() else {
            panic!("expected auto envelope");
        };
        let trust = write_trust_roots(&dir, &[7_u8; 32]);
        let evidence = verify(&plan, &envelope, &trust, now + 1, false).unwrap();
        assert_eq!(evidence.policy_provider, POLICY_PROVIDER);
        assert_eq!(evidence.policy_evidence_id, "auto");
        let loaded = ApprovalPolicy::load(&policy_path).unwrap();
        assert_eq!(evidence.policy_digest, loaded.digest().unwrap());
        let mut foreign_plan = plan.clone();
        foreign_plan.environment = "prod".into();
        let foreign_envelope = dir.join("foreign.json");
        sign_auto_approval(
            &loaded,
            &foreign_plan,
            false,
            now,
            "auto".into(),
            &foreign_envelope,
        )
        .unwrap();
        assert!(
            verify(&foreign_plan, &foreign_envelope, &trust, now + 1, false)
                .unwrap_err()
                .to_string()
                .contains("environment scope")
        );
        let mut forged: ApprovalEnvelope =
            serde_json::from_slice(&fs::read(&envelope).unwrap()).unwrap();
        forged.statement.policy_provider = "human".into();
        forged.signature = STANDARD.encode(
            SigningKey::from_bytes(&[7_u8; 32])
                .sign(&canonical_bytes(&forged.statement).unwrap())
                .to_bytes(),
        );
        fs::write(&foreign_envelope, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(
            verify(&plan, &foreign_envelope, &trust, now + 1, false)
                .unwrap_err()
                .to_string()
                .contains("provider scope")
        );

        properties.remove(PLAN_APPROVAL_POLICY_PROPERTY);
        assert_eq!(
            resolve_auto_envelope(
                &properties,
                &plan,
                false,
                DeliverySignals::default(),
                &approvals,
                now
            )
            .unwrap(),
            AutoEnvelope::NeedsHuman
        );

        properties.insert(
            PLAN_APPROVAL_POLICY_PROPERTY.into(),
            policy_path.to_string_lossy().into_owned(),
        );
        fs::remove_file(&key).unwrap();
        assert_eq!(
            resolve_auto_envelope(
                &properties,
                &plan,
                false,
                DeliverySignals::default(),
                &approvals,
                now
            )
            .unwrap(),
            AutoEnvelope::NeedsHuman
        );
        write_seed(&dir);

        let AutoEnvelope::Signed(path) = resolve_auto_envelope(
            &properties,
            &plan,
            false,
            DeliverySignals::default(),
            &approvals,
            now + 120_000,
        )
        .unwrap() else {
            panic!("expected re-sign after expiry");
        };
        assert_eq!(path, envelope);
        let resigned: ApprovalEnvelope = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(resigned.statement.issued_at, now + 120_000);
        verify(&plan, &path, &trust, now + 120_001, false).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_signer_key_needs_human_and_credential_paths_are_refused() {
        let dir = unique_dir("missing-key");
        let missing = dir.join("gone.ed25519");
        let policy = auto_policy(&missing, None);
        let policy_path = write_policy(&dir, &policy);
        let plan = sample_plan(Action::Install, "api");
        let mut properties = HashMap::new();
        properties.insert(
            PLAN_APPROVAL_POLICY_PROPERTY.into(),
            policy_path.to_string_lossy().into_owned(),
        );
        let approvals = dir.join("approvals");
        assert_eq!(
            resolve_auto_envelope(
                &properties,
                &plan,
                false,
                DeliverySignals::default(),
                &approvals,
                1
            )
            .unwrap(),
            AutoEnvelope::NeedsHuman
        );
        let err = validate_policy_file_path(Path::new("password=s3cret"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("file path"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
