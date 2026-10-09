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

use crate::plan::{Action, Plan};
use crate::plan_approval::{APPROVAL_SCHEMA, ApprovalEnvelope, ApprovalStatement, canonical_bytes};

/// Environment property storing the canonical path of the policy TOML file.
pub const PLAN_APPROVAL_POLICY_PROPERTY: &str = "plan_approval_policy";
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
        .any(|step| step.action == Action::Rollback)
    {
        return Decision::RequireHuman {
            reason: "rollback requires a human-signed envelope".into(),
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

fn envelope_expired(path: &Path, now: i64) -> Result<bool> {
    let raw =
        fs::read(path).with_context(|| format!("reading plan approval {}", path.display()))?;
    let envelope: ApprovalEnvelope =
        serde_json::from_slice(&raw).context("parsing plan approval envelope")?;
    Ok(now >= envelope.statement.expires_at)
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
                    if !envelope_expired(&envelope, now)? {
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

fn load_live_policy(properties: &HashMap<String, String>) -> Result<Option<ApprovalPolicy>> {
    let Some(path) = policy_path_from_properties(properties)? else {
        return Ok(None);
    };
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(ApprovalPolicy::load(&path)?))
}

fn auto_signer_present(policy: &ApprovalPolicy) -> bool {
    policy
        .auto_signer_key
        .as_deref()
        .is_some_and(|path| load_auto_signer_seed(path).is_ok())
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
                "version = 1\n\n[[signers]]\nkey_id = \"{kid}\"\nidentity = \"auto-approver@lab\"\npublic_key = \"{}\"\n",
                STANDARD.encode(public)
            ),
        )
        .unwrap();
        path
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
            Decision::RequireHuman { reason } if reason.contains("migration boundary")
        ));
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
