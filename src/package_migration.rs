//! Tenkai-owned package migration plans (ADR 0024).
//!
//! Package definitions and compatibility classification stay with their
//! external authorities. Tenkai binds source, target, evidence, and ordered
//! checkpoints into one immutable plan, then executes, resumes, rolls back,
//! or records recovery-required state under the environment fence.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::apply::{self, ExecutionAuthorization, ExecutionOptions};
use crate::catalog::{self, CatalogReader as _};
use crate::client::Ctx;
use crate::ontology::{
    KIND_PACKAGE_MIGRATION, KIND_PACKAGE_MIGRATION_LOCK, NS, package_migration_id,
    package_migration_lock_id, require_package_migration_schema, validate_identifier,
};
use crate::pb::sekai::Object;
use crate::plan::{self, Action, PlanState, ReleasePin as PlanReleasePin, Step};
use crate::signature_verification;

pub const MIGRATION_PROFILE: &str = "tenkai.package_migration.v1";
pub const MIGRATION_DOCUMENT_VERSION: u32 = 1;
pub const COMPATIBILITY_VERSION: u32 = 1;
pub const APPROVAL_SCHEMA: &str = "tenkai.package-migration-approval.v1";
const APPROVAL_DOMAIN: &[u8] = b"TENKAI-PACKAGE-MIGRATION-APPROVAL-V1\0";
const APPROVAL_PURPOSE: &str = "execute_package_migration";
const TRUST_ROOT_VERSION: u32 = 1;
const MIGRATION_EXEC_NAMESPACE: &str = "tenkai.package-migration";
const MIGRATION_EXEC_TTL_MS: i64 = 2 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointClass {
    Reversible,
    Compensating,
    Irreversible,
}

impl CheckpointClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::Compensating => "compensating",
            Self::Irreversible => "irreversible",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Compatible,
    Incompatible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    Admitted,
    Running,
    Succeeded,
    Failed,
    RolledBack,
    RecoveryRequired,
}

impl MigrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePin {
    pub product: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointDecl {
    pub id: String,
    pub class: CheckpointClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_admission: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidence {
    pub version: u32,
    pub status: CompatibilityStatus,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationDeclaration {
    pub version: u32,
    pub profile: String,
    pub source: PackagePin,
    pub target: PackagePin,
    pub compatibility: CompatibilityEvidence,
    pub checkpoints: Vec<CheckpointDecl>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReceipt {
    pub checkpoint_id: String,
    pub class: CheckpointClass,
    pub effect: String,
    pub result: String,
    pub fence_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRecord {
    pub name: String,
    pub environment: String,
    pub identity_digest: String,
    pub declaration: MigrationDeclaration,
    pub approval_digest: String,
    pub fence_generation: u64,
    pub status: MigrationStatus,
    pub receipts: Vec<CheckpointReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_receipt_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_plan_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_rollback_plan_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationAuthorization<'a> {
    LocalDevelopment {
        reason: &'a str,
    },
    Signed {
        approval: &'a Path,
        trust_roots: &'a Path,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationApprovalStatement {
    pub identity_digest: String,
    pub environment: String,
    pub purpose: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationApprovalEnvelope {
    pub schema: String,
    pub key_id: String,
    pub statement: MigrationApprovalStatement,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalTrustRoots {
    version: u32,
    signers: Vec<ApprovalTrustedSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalTrustedSigner {
    key_id: String,
    identity: String,
    public_key: String,
}

fn checkpoint_effect(class: CheckpointClass) -> &'static str {
    match class {
        CheckpointClass::Compensating => "apply_target",
        CheckpointClass::Reversible | CheckpointClass::Irreversible => "revalidate",
    }
}

impl PackagePin {
    fn validate(&self, label: &str) -> Result<()> {
        validate_identifier(&format!("{label} product"), &self.product)?;
        validate_identifier(&format!("{label} version"), &self.version)?;
        signature_verification::validate_prefixed_digest(&format!("{label} digest"), &self.digest)?;
        Ok(())
    }
}

impl MigrationDeclaration {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading package migration {}", path.display()))?;
        let doc: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing package migration {}", path.display()))?;
        doc.validate()?;
        Ok(doc)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != MIGRATION_DOCUMENT_VERSION {
            bail!(
                "unsupported package migration version {}; expected {MIGRATION_DOCUMENT_VERSION}",
                self.version
            );
        }
        if self.profile != MIGRATION_PROFILE {
            bail!(
                "unknown package migration profile {:?}; expected {MIGRATION_PROFILE}",
                self.profile
            );
        }
        self.source.validate("source")?;
        self.target.validate("target")?;
        if self.source == self.target {
            bail!("package migration source and target must differ");
        }
        if self.source.product != self.target.product {
            bail!("package migration source and target must name the same product");
        }
        if self.compatibility.version != COMPATIBILITY_VERSION {
            bail!(
                "unsupported compatibility evidence version {}; expected {COMPATIBILITY_VERSION}",
                self.compatibility.version
            );
        }
        signature_verification::validate_prefixed_digest(
            "compatibility evidence digest",
            &self.compatibility.evidence_digest,
        )?;
        if self.checkpoints.is_empty() {
            bail!("package migration must declare at least one checkpoint");
        }
        let mut seen = BTreeSet::new();
        for checkpoint in &self.checkpoints {
            validate_identifier("checkpoint id", &checkpoint.id)?;
            if !seen.insert(checkpoint.id.as_str()) {
                bail!("duplicate checkpoint id {}", checkpoint.id);
            }
            match checkpoint.class {
                CheckpointClass::Irreversible => {
                    let Some(handling) = checkpoint.pre_admission.as_deref() else {
                        bail!(
                            "irreversible checkpoint {} requires explicit pre-admission handling",
                            checkpoint.id
                        );
                    };
                    if handling != "require_backup_receipt" {
                        bail!(
                            "unknown irreversible pre-admission {handling:?} on checkpoint {}",
                            checkpoint.id
                        );
                    }
                }
                CheckpointClass::Reversible | CheckpointClass::Compensating => {
                    if checkpoint.pre_admission.is_some() {
                        bail!(
                            "checkpoint {} is not irreversible and cannot declare pre-admission handling",
                            checkpoint.id
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub fn identity_digest(
        &self,
        environment: &str,
        backup_receipt_digest: Option<&str>,
    ) -> Result<String> {
        self.validate()?;
        if let Some(digest) = backup_receipt_digest {
            signature_verification::validate_prefixed_digest("backup receipt digest", digest)?;
        }
        let canonical = serde_json::to_vec(self)?;
        let mut output = b"TENKAI-PACKAGE-MIGRATION-V1\0".to_vec();
        signature_verification::push_len_prefixed(&mut output, environment.as_bytes());
        signature_verification::push_len_prefixed(&mut output, &canonical);
        signature_verification::push_len_prefixed(
            &mut output,
            backup_receipt_digest.unwrap_or_default().as_bytes(),
        );
        Ok(format!("sha256:{:x}", Sha256::digest(output)))
    }
}

pub async fn preview(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
) -> Result<MigrationRecord> {
    admit(
        ctx,
        name,
        environment,
        declaration,
        backup_receipt_digest,
        true,
    )
    .await
}

pub async fn create(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
) -> Result<MigrationRecord> {
    admit(
        ctx,
        name,
        environment,
        declaration,
        backup_receipt_digest,
        false,
    )
    .await
}

/// Admit (if needed), approve, and execute until the migration is terminal or stuck.
pub async fn run_until_blocked(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
    authorization: MigrationAuthorization<'_>,
) -> Result<MigrationRecord> {
    require_package_migration_schema(ctx).await?;
    let existing = ctx.get(&package_migration_id(name)).await?;
    let record = if existing.is_some() {
        let stored = load(ctx, name).await?;
        let expected = declaration.identity_digest(environment, backup_receipt_digest)?;
        if stored.identity_digest != expected || stored.environment != environment {
            bail!("package migration {name} already exists with a different identity");
        }
        stored
    } else {
        create(ctx, name, environment, declaration, backup_receipt_digest).await?
    };
    match record.status {
        MigrationStatus::Succeeded
        | MigrationStatus::Failed
        | MigrationStatus::RolledBack
        | MigrationStatus::RecoveryRequired => return Ok(record),
        MigrationStatus::Admitted if record.approval_digest.is_empty() => {
            approve(ctx, name, authorization).await?;
        }
        MigrationStatus::Admitted | MigrationStatus::Running => {
            require_approval(&record, authorization)?;
        }
    }
    let mut last_receipts = record.receipts.len();
    loop {
        let next = execute(ctx, name, authorization, None).await?;
        if matches!(
            next.status,
            MigrationStatus::Succeeded
                | MigrationStatus::Failed
                | MigrationStatus::RolledBack
                | MigrationStatus::RecoveryRequired
        ) {
            return Ok(next);
        }
        if next.receipts.len() == last_receipts {
            return Ok(next);
        }
        last_receipts = next.receipts.len();
    }
}

pub fn format_migration(record: &MigrationRecord) -> String {
    let mut lines = vec![format!(
        "package-migration name={} status={} identity={} env={} fence={} approval={}",
        record.name,
        record.status.as_str(),
        record.identity_digest,
        record.environment,
        record.fence_generation,
        if record.approval_digest.is_empty() {
            "-"
        } else {
            &record.approval_digest
        }
    )];
    lines.push(format!(
        "source {}@{} {}",
        record.declaration.source.product,
        record.declaration.source.version,
        record.declaration.source.digest
    ));
    lines.push(format!(
        "target {}@{} {}",
        record.declaration.target.product,
        record.declaration.target.version,
        record.declaration.target.digest
    ));
    if let Some(backup) = &record.backup_receipt_digest {
        lines.push(format!("backup {backup}"));
    }
    lines.push(format!(
        "{:<16} {:<14} {:<12} fence",
        "checkpoint", "class", "result"
    ));
    for checkpoint in &record.declaration.checkpoints {
        let receipt = record
            .receipts
            .iter()
            .find(|receipt| receipt.checkpoint_id == checkpoint.id);
        match receipt {
            Some(receipt) => lines.push(format!(
                "{:<16} {:<14} {:<12} {}",
                checkpoint.id,
                checkpoint.class.as_str(),
                receipt.result,
                receipt.fence_generation
            )),
            None => lines.push(format!(
                "{:<16} {:<14} {:<12} -",
                checkpoint.id,
                checkpoint.class.as_str(),
                "-"
            )),
        }
    }
    lines.push(
        "note: accepted irreversible work cannot report rollback success; recover from Tenkai receipts"
            .into(),
    );
    lines.join("\n")
}

async fn admit(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
    preview_only: bool,
) -> Result<MigrationRecord> {
    validate_identifier("migration name", name)?;
    validate_identifier("environment", environment)?;
    declaration.validate()?;
    if declaration.compatibility.status != CompatibilityStatus::Compatible {
        bail!("package migration compatibility evidence is not compatible");
    }
    crate::environment::environment(ctx, environment).await?;
    require_package_pin(ctx, &declaration.source).await?;
    require_package_pin(ctx, &declaration.target).await?;
    if catalog::release_is_recalled(
        ctx,
        &crate::ontology::release_id(&declaration.source.product, &declaration.source.version),
    )
    .await?
        || catalog::release_is_recalled(
            ctx,
            &crate::ontology::release_id(&declaration.target.product, &declaration.target.version),
        )
        .await?
    {
        bail!("package migration cannot use a recalled source or target release");
    }
    let needs_backup = declaration
        .checkpoints
        .iter()
        .any(|checkpoint| checkpoint.class == CheckpointClass::Irreversible);
    let backup = match backup_receipt_digest {
        Some(digest) => {
            signature_verification::validate_prefixed_digest("backup receipt digest", digest)?;
            Some(digest.to_string())
        }
        None if needs_backup => {
            bail!(
                "irreversible package migration requires a backup receipt digest before admission"
            )
        }
        None => None,
    };
    let record = MigrationRecord {
        name: name.into(),
        environment: environment.into(),
        identity_digest: declaration.identity_digest(environment, backup.as_deref())?,
        declaration,
        approval_digest: String::new(),
        fence_generation: 0,
        status: MigrationStatus::Admitted,
        receipts: Vec::new(),
        backup_receipt_digest: backup,
        pending_plan_id: None,
        pending_rollback_plan_id: None,
    };
    if preview_only {
        return Ok(record);
    }
    persist_new(ctx, &record).await?;
    Ok(record)
}

async fn require_package_pin(ctx: &mut Ctx, pin: &PackagePin) -> Result<()> {
    let release_id = crate::ontology::release_id(&pin.product, &pin.version);
    let object = ctx
        .get(&release_id)
        .await?
        .with_context(|| format!("release {}@{} is not published", pin.product, pin.version))?;
    let digest = catalog_digest(
        object
            .properties
            .get("digest")
            .map(String::as_str)
            .unwrap_or_default(),
    )?;
    if digest != pin.digest {
        bail!(
            "release {}@{} digest {digest} does not match migration pin {}",
            pin.product,
            pin.version,
            pin.digest
        );
    }
    Ok(())
}

fn catalog_digest(stored: &str) -> Result<String> {
    let prefixed = if stored.starts_with("sha256:") {
        stored.to_string()
    } else {
        format!("sha256:{stored}")
    };
    signature_verification::validate_prefixed_digest("catalog release digest", &prefixed)?;
    Ok(prefixed)
}

pub async fn approve(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
) -> Result<MigrationRecord> {
    let mut record = load(ctx, name).await?;
    if record.status != MigrationStatus::Admitted {
        bail!(
            "package migration {name} is {}, not admitted",
            record.status.as_str()
        );
    }
    record.approval_digest = approval_digest(&record, authorization)?;
    persist(ctx, &record).await?;
    Ok(record)
}

pub async fn execute(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
) -> Result<MigrationRecord> {
    step(ctx, name, authorization, expected_generation, false).await
}

pub async fn resume(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
) -> Result<MigrationRecord> {
    step(ctx, name, authorization, expected_generation, true).await
}

async fn step(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
    resume: bool,
) -> Result<MigrationRecord> {
    require_package_migration_schema(ctx).await?;
    let record = load(ctx, name).await?;
    require_approval(&record, authorization)?;
    if let Some(expected) = expected_generation
        && expected != record.fence_generation
    {
        bail!(
            "stale fencing generation {expected} for package migration {name}; current is {}",
            record.fence_generation
        );
    }
    let exec_lease = acquire_execution_lease(ctx, name).await?;
    let result = step_locked(ctx, record, authorization, resume, &exec_lease).await;
    release_execution_lease(ctx, name, &exec_lease).await;
    result
}

async fn step_locked(
    ctx: &mut Ctx,
    mut record: MigrationRecord,
    authorization: MigrationAuthorization<'_>,
    resume: bool,
    exec_lease: &str,
) -> Result<MigrationRecord> {
    match record.status {
        MigrationStatus::Admitted if !resume => {
            record.fence_generation += 1;
            record.status = MigrationStatus::Running;
        }
        MigrationStatus::Running if resume || !record.receipts.is_empty() => {}
        MigrationStatus::Succeeded if resume => return Ok(record),
        other => bail!(
            "package migration {} cannot execute from {}",
            record.name,
            other.as_str()
        ),
    }
    acquire_environment_lock(ctx, &record).await?;
    let next = record.declaration.checkpoints.get(record.receipts.len());
    let Some(checkpoint) = next.cloned() else {
        record.status = MigrationStatus::Succeeded;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record.environment, &record.name).await?;
        return Ok(record);
    };
    if checkpoint.class == CheckpointClass::Irreversible && record.backup_receipt_digest.is_none() {
        record.status = MigrationStatus::Failed;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record.environment, &record.name).await?;
        bail!(
            "irreversible checkpoint {} has no backup receipt; refusing the first effect",
            checkpoint.id
        );
    }
    if record
        .receipts
        .iter()
        .any(|receipt| receipt.checkpoint_id == checkpoint.id)
    {
        persist(ctx, &record).await?;
        return Ok(record);
    }
    match execute_checkpoint(ctx, &mut record, &checkpoint, authorization, exec_lease).await {
        Ok(CheckpointProgress::Accepted { plan_id }) => {
            record.pending_plan_id = None;
            record.pending_rollback_plan_id = None;
            record.receipts.push(CheckpointReceipt {
                checkpoint_id: checkpoint.id.clone(),
                class: checkpoint.class,
                effect: checkpoint_effect(checkpoint.class).into(),
                result: "accepted".into(),
                fence_generation: record.fence_generation,
                plan_id,
            });
            if record.receipts.len() == record.declaration.checkpoints.len() {
                record.status = MigrationStatus::Succeeded;
            } else {
                record.status = MigrationStatus::Running;
            }
            persist(ctx, &record).await?;
            if record.status == MigrationStatus::Succeeded {
                release_environment_lock(ctx, &record.environment, &record.name).await?;
            }
            Ok(record)
        }
        Ok(CheckpointProgress::AwaitingPlanApproval { plan_id }) => {
            record.pending_plan_id = Some(plan_id);
            persist(ctx, &record).await?;
            Ok(record)
        }
        Err(error) => {
            if let Some(plan_id) = record.pending_plan_id.clone()
                && let Ok(plan) = plan::load(ctx, &plan_id).await
            {
                if plan.state == PlanState::Succeeded {
                    record.pending_plan_id = None;
                    record.receipts.push(CheckpointReceipt {
                        checkpoint_id: checkpoint.id.clone(),
                        class: checkpoint.class,
                        effect: checkpoint_effect(checkpoint.class).into(),
                        result: "accepted".into(),
                        fence_generation: record.fence_generation,
                        plan_id: Some(plan_id),
                    });
                    record.status = if record.receipts.len() == record.declaration.checkpoints.len()
                    {
                        MigrationStatus::Succeeded
                    } else {
                        MigrationStatus::Running
                    };
                    persist(ctx, &record).await?;
                    if record.status == MigrationStatus::Succeeded {
                        release_environment_lock(ctx, &record.environment, &record.name).await?;
                    }
                    return Ok(record);
                }
                if plan.state != PlanState::Computed {
                    record.status = MigrationStatus::RecoveryRequired;
                    persist(ctx, &record).await?;
                    return Err(error);
                }
            }
            record.status = MigrationStatus::Failed;
            persist(ctx, &record).await?;
            release_environment_lock(ctx, &record.environment, &record.name).await?;
            Err(error)
        }
    }
}

pub async fn rollback(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
) -> Result<MigrationRecord> {
    require_package_migration_schema(ctx).await?;
    let record = load(ctx, name).await?;
    require_approval(&record, authorization)?;
    if let Some(expected) = expected_generation
        && expected != record.fence_generation
    {
        bail!(
            "stale fencing generation {expected} for package migration rollback {name}; current is {}",
            record.fence_generation
        );
    }
    let exec_lease = acquire_execution_lease(ctx, name).await?;
    let result = rollback_locked(ctx, record, authorization, &exec_lease).await;
    release_execution_lease(ctx, name, &exec_lease).await;
    result
}

async fn rollback_locked(
    ctx: &mut Ctx,
    mut record: MigrationRecord,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<MigrationRecord> {
    if matches!(
        record.status,
        MigrationStatus::Admitted | MigrationStatus::RolledBack
    ) {
        record.status = MigrationStatus::RolledBack;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record.environment, &record.name).await?;
        return Ok(record);
    }
    acquire_environment_lock(ctx, &record).await?;
    if let Err(error) = require_rollback_target(ctx, &record).await {
        record.status = MigrationStatus::RecoveryRequired;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record.environment, &record.name).await?;
        return Err(error);
    }
    record.fence_generation += 1;
    for receipt in record.receipts.iter().rev() {
        if receipt.class == CheckpointClass::Irreversible && receipt.result == "accepted" {
            record.status = MigrationStatus::RecoveryRequired;
            persist(ctx, &record).await?;
            release_environment_lock(ctx, &record.environment, &record.name).await?;
            bail!(
                "package migration {} crossed irreversible checkpoint {}; rollback cannot claim success",
                record.name,
                receipt.checkpoint_id
            );
        }
        if receipt.result == "accepted"
            && !matches!(
                receipt.class,
                CheckpointClass::Reversible | CheckpointClass::Compensating
            )
        {
            record.status = MigrationStatus::RecoveryRequired;
            persist(ctx, &record).await?;
            release_environment_lock(ctx, &record.environment, &record.name).await?;
            bail!(
                "package migration {} cannot compensate checkpoint {}",
                record.name,
                receipt.checkpoint_id
            );
        }
    }
    if let Err(error) = compensate_accepted(ctx, &mut record, authorization, exec_lease).await {
        record.status = MigrationStatus::RecoveryRequired;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record.environment, &record.name).await?;
        return Err(error);
    }
    for receipt in &mut record.receipts {
        if receipt.result == "accepted" {
            receipt.result = "rolled_back".into();
            receipt.fence_generation = record.fence_generation;
        }
    }
    record.status = MigrationStatus::RolledBack;
    record.pending_plan_id = None;
    record.pending_rollback_plan_id = None;
    persist(ctx, &record).await?;
    release_environment_lock(ctx, &record.environment, &record.name).await?;
    Ok(record)
}

pub async fn load(ctx: &mut Ctx, name: &str) -> Result<MigrationRecord> {
    validate_identifier("migration name", name)?;
    require_package_migration_schema(ctx).await?;
    let object = ctx
        .get(&package_migration_id(name))
        .await?
        .with_context(|| format!("package migration {name} is not stored"))?;
    let raw = object
        .properties
        .get("record")
        .context("package migration record is missing")?;
    let record: MigrationRecord = serde_json::from_str(raw)?;
    if record.name != name {
        bail!("stored package migration name does not match {name}");
    }
    Ok(record)
}

fn approval_digest(
    record: &MigrationRecord,
    authorization: MigrationAuthorization<'_>,
) -> Result<String> {
    if let MigrationAuthorization::LocalDevelopment { .. } = authorization
        && record.environment != "local"
    {
        bail!("unapproved development execution is restricted to the built-in local environment");
    }
    match authorization {
        MigrationAuthorization::LocalDevelopment { reason } => {
            if reason.trim().is_empty() {
                bail!("package migration development approval requires a non-empty reason");
            }
            let mut output = b"TENKAI-PACKAGE-MIGRATION-DEV-APPROVAL-V1\0".to_vec();
            signature_verification::push_len_prefixed(
                &mut output,
                record.identity_digest.as_bytes(),
            );
            signature_verification::push_len_prefixed(&mut output, reason.as_bytes());
            Ok(format!("sha256:{:x}", Sha256::digest(output)))
        }
        MigrationAuthorization::Signed {
            approval,
            trust_roots,
        } => {
            verify_signed_approval(record, approval, trust_roots, crate::now_millis())?;
            Ok(identity_approval_binding(record))
        }
    }
}

fn require_approval(
    record: &MigrationRecord,
    authorization: MigrationAuthorization<'_>,
) -> Result<()> {
    if record.approval_digest.is_empty() {
        bail!("package migration {} is not approved", record.name);
    }
    let expected = approval_digest(record, authorization)?;
    if expected != record.approval_digest {
        bail!(
            "package migration {} approval does not match the stored digest",
            record.name
        );
    }
    Ok(())
}

enum CheckpointProgress {
    Accepted { plan_id: Option<String> },
    AwaitingPlanApproval { plan_id: String },
}

fn canonical_approval_bytes(statement: &MigrationApprovalStatement) -> Result<Vec<u8>> {
    if statement.purpose != APPROVAL_PURPOSE {
        bail!("package migration approval purpose must be {APPROVAL_PURPOSE}");
    }
    signature_verification::validate_prefixed_digest(
        "migration identity digest",
        &statement.identity_digest,
    )?;
    validate_identifier("approval environment", &statement.environment)?;
    if statement.expires_at <= statement.issued_at {
        bail!("package migration approval expiry must be after its issue time");
    }
    let mut bytes = APPROVAL_DOMAIN.to_vec();
    for value in [
        statement.identity_digest.as_bytes(),
        statement.environment.as_bytes(),
        statement.purpose.as_bytes(),
    ] {
        signature_verification::push_len_prefixed(&mut bytes, value);
    }
    bytes.extend_from_slice(&statement.issued_at.to_be_bytes());
    bytes.extend_from_slice(&statement.expires_at.to_be_bytes());
    Ok(bytes)
}

fn verify_signed_approval(
    record: &MigrationRecord,
    approval: &Path,
    trust_roots: &Path,
    now: i64,
) -> Result<String> {
    let raw = std::fs::read(approval)
        .with_context(|| format!("reading package migration approval {}", approval.display()))?;
    let envelope: MigrationApprovalEnvelope =
        serde_json::from_slice(&raw).context("parsing package migration approval envelope")?;
    if envelope.schema != APPROVAL_SCHEMA {
        bail!(
            "unsupported package migration approval schema {}",
            envelope.schema
        );
    }
    if envelope.statement.identity_digest != record.identity_digest
        || envelope.statement.environment != record.environment
    {
        bail!("package migration approval is bound to a different identity or environment");
    }
    if now < envelope.statement.issued_at {
        bail!("package migration approval is not valid yet");
    }
    if now >= envelope.statement.expires_at {
        bail!(
            "package migration approval expired at {}",
            envelope.statement.expires_at
        );
    }
    let roots_raw = std::fs::read_to_string(trust_roots).with_context(|| {
        format!(
            "reading package migration approval trust roots {}",
            trust_roots.display()
        )
    })?;
    let roots: ApprovalTrustRoots = toml::from_str(&roots_raw).with_context(|| {
        format!(
            "parsing package migration approval trust roots {}",
            trust_roots.display()
        )
    })?;
    if roots.version != TRUST_ROOT_VERSION || roots.signers.is_empty() {
        bail!(
            "package migration approval trust roots must use version {TRUST_ROOT_VERSION} and contain at least one signer"
        );
    }
    let signer = roots
        .signers
        .iter()
        .find(|signer| signer.key_id == envelope.key_id)
        .with_context(|| {
            format!(
                "package migration approval signer {} is not currently trusted",
                envelope.key_id
            )
        })?;
    let public_key = signature_verification::trusted_key(
        "package migration approval public key",
        &signer.public_key,
        &signer.key_id,
    )?;
    signature_verification::verify_strict(
        &public_key,
        "package migration approval signature",
        &envelope.signature,
        &canonical_approval_bytes(&envelope.statement)?,
    )?;
    Ok(identity_approval_binding(record))
}

fn identity_approval_binding(record: &MigrationRecord) -> String {
    let mut output = b"TENKAI-PACKAGE-MIGRATION-APPROVED-V1\0".to_vec();
    signature_verification::push_len_prefixed(&mut output, record.identity_digest.as_bytes());
    signature_verification::push_len_prefixed(&mut output, record.environment.as_bytes());
    format!("sha256:{:x}", Sha256::digest(output))
}

async fn acquire_execution_lease(ctx: &mut Ctx, name: &str) -> Result<String> {
    match ctx
        .acquire_lease(
            MIGRATION_EXEC_NAMESPACE,
            name,
            "execute",
            MIGRATION_EXEC_TTL_MS,
        )
        .await
    {
        Ok(lease) => Ok(lease.fencing_token),
        Err(error)
            if error
                .downcast_ref::<tonic::Status>()
                .is_some_and(|status| status.code() == tonic::Code::AlreadyExists) =>
        {
            bail!("package migration {name} already has an execution in progress")
        }
        Err(error) => Err(error),
    }
}

async fn release_execution_lease(ctx: &mut Ctx, name: &str, fencing_token: &str) {
    let _ = ctx
        .release_lease(MIGRATION_EXEC_NAMESPACE, name, fencing_token)
        .await;
}

async fn refresh_execution_lease(ctx: &mut Ctx, name: &str, fencing_token: &str) -> Result<()> {
    ctx.refresh_lease(
        MIGRATION_EXEC_NAMESPACE,
        name,
        fencing_token,
        MIGRATION_EXEC_TTL_MS,
    )
    .await?;
    Ok(())
}

async fn authorize_plan_on_lock(ctx: &mut Ctx, environment: &str, plan_id: &str) -> Result<()> {
    let id = package_migration_lock_id(environment);
    let mut object = ctx
        .get(&id)
        .await?
        .with_context(|| format!("package migration lock for {environment} is missing"))?;
    object
        .properties
        .insert("allowed_plan_id".into(), plan_id.into());
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(())
}

async fn clear_authorized_plan(ctx: &mut Ctx, environment: &str) -> Result<()> {
    let id = package_migration_lock_id(environment);
    let Some(mut object) = ctx.get(&id).await? else {
        return Ok(());
    };
    object.properties.remove("allowed_plan_id");
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(())
}

async fn acquire_environment_lock(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    let owner = format!("package-migration:{}", record.name);
    let lease = apply::claim_environment(ctx, &record.environment, &owner).await?;
    let id = package_migration_lock_id(&record.environment);
    let result = async {
        if let Some(existing) = ctx.get(&id).await? {
            let lock_owner = existing
                .properties
                .get("owner")
                .map(String::as_str)
                .unwrap_or_default();
            if lock_owner != record.name {
                bail!(
                    "environment {} already has package migration {lock_owner} in progress",
                    record.environment
                );
            }
            return Ok(());
        }
        ctx.create_once(Object {
            id,
            kind: KIND_PACKAGE_MIGRATION_LOCK.into(),
            name: format!("lock-{}", record.environment),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("environment".into(), record.environment.clone()),
                ("owner".into(), record.name.clone()),
            ]),
            created: crate::now_millis(),
            updated: crate::now_millis(),
        })
        .await?;
        Ok(())
    }
    .await;
    apply::release_environment(ctx, &lease).await?;
    result
}

async fn release_environment_lock(ctx: &mut Ctx, environment: &str, owner: &str) -> Result<()> {
    let id = package_migration_lock_id(environment);
    let Some(existing) = ctx.get(&id).await? else {
        return Ok(());
    };
    if existing.properties.get("owner").map(String::as_str) != Some(owner) {
        return Ok(());
    }
    ctx.delete(&id).await?;
    Ok(())
}

async fn execute_checkpoint(
    ctx: &mut Ctx,
    record: &mut MigrationRecord,
    checkpoint: &CheckpointDecl,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<CheckpointProgress> {
    refresh_execution_lease(ctx, &record.name, exec_lease).await?;
    match checkpoint_effect(checkpoint.class) {
        "revalidate" => {
            let owner = format!("package-migration:{}", record.name);
            let lease = apply::claim_environment(ctx, &record.environment, &owner).await?;
            let result = revalidate_pins(ctx, record).await;
            apply::release_environment(ctx, &lease).await?;
            result?;
            Ok(CheckpointProgress::Accepted { plan_id: None })
        }
        "apply_target" => {
            let pin = record.declaration.target.clone();
            apply_pin(ctx, record, &pin, authorization, exec_lease).await
        }
        other => bail!("unknown package migration checkpoint effect {other}"),
    }
}

async fn revalidate_pins(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    if record.declaration.compatibility.status != CompatibilityStatus::Compatible {
        bail!("package migration compatibility evidence is not compatible");
    }
    require_package_pin(ctx, &record.declaration.source).await?;
    require_package_pin(ctx, &record.declaration.target).await?;
    let env = crate::environment::environment(ctx, &record.environment).await?;
    let deployed = env
        .properties
        .get(&format!("deployed.{}", record.declaration.source.product))
        .map(String::as_str);
    if deployed != Some(record.declaration.source.version.as_str())
        && deployed != Some(record.declaration.target.version.as_str())
    {
        bail!(
            "package migration {} requires {} to be at source {} or target {}",
            record.name,
            record.declaration.source.product,
            record.declaration.source.version,
            record.declaration.target.version
        );
    }
    if catalog::release_is_recalled(
        ctx,
        &crate::ontology::release_id(
            &record.declaration.source.product,
            &record.declaration.source.version,
        ),
    )
    .await?
        || catalog::release_is_recalled(
            ctx,
            &crate::ontology::release_id(
                &record.declaration.target.product,
                &record.declaration.target.version,
            ),
        )
        .await?
    {
        bail!("package migration cannot use a recalled source or target release");
    }
    Ok(())
}

async fn apply_pin(
    ctx: &mut Ctx,
    record: &mut MigrationRecord,
    pin: &PackagePin,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<CheckpointProgress> {
    revalidate_pins(ctx, record).await?;
    let plan_id = match record.pending_plan_id.clone() {
        Some(id) => id,
        None => {
            let plan_id = create_pin_plan(ctx, record, pin).await?.id;
            record.pending_plan_id = Some(plan_id.clone());
            persist(ctx, record).await?;
            plan_id
        }
    };
    refresh_execution_lease(ctx, &record.name, exec_lease).await?;
    let approval_path;
    let exec = match authorization {
        MigrationAuthorization::LocalDevelopment { reason } => {
            ExecutionAuthorization::LocalDevelopment { reason }
        }
        MigrationAuthorization::Signed {
            approval,
            trust_roots,
        } => {
            let dir = approval
                .parent()
                .context("package migration approval path has no parent")?;
            approval_path = dir.join(format!("{plan_id}.json"));
            if !approval_path.is_file() {
                return Ok(CheckpointProgress::AwaitingPlanApproval { plan_id });
            }
            ExecutionAuthorization::Signed {
                approval: &approval_path,
                trust_roots,
            }
        }
    };
    authorize_plan_on_lock(ctx, &record.environment, &plan_id).await?;
    let applied = apply::execute_with_options(
        ctx,
        &plan_id,
        ExecutionOptions {
            skip_gates: false,
            emergency_reason: None,
            authorization: exec,
            software_executor: crate::software_executor::selected_software_executor()
                .map(std::sync::Arc::from),
            delivery_adapter: None,
            delivery_fence: None,
        },
    )
    .await;
    clear_authorized_plan(ctx, &record.environment).await?;
    refresh_execution_lease(ctx, &record.name, exec_lease).await?;
    applied?;
    let plan = plan::load(ctx, &plan_id).await?;
    if plan.state != PlanState::Succeeded {
        bail!("package migration plan {plan_id} ended in {}", plan.state);
    }
    Ok(CheckpointProgress::Accepted {
        plan_id: Some(plan_id),
    })
}

async fn create_pin_plan(
    ctx: &mut Ctx,
    record: &MigrationRecord,
    pin: &PackagePin,
) -> Result<plan::Plan> {
    let release_id = crate::ontology::release_id(&pin.product, &pin.version);
    let descriptor = catalog::EmbeddedCatalog::new(ctx)
        .lookup_release(&release_id, &record.environment)
        .await
        .map_err(anyhow::Error::from)?;
    let stored = catalog_digest(&descriptor.manifest_digest)?;
    if stored != pin.digest {
        bail!(
            "release {release_id} digest {stored} does not match migration pin {}",
            pin.digest
        );
    }
    let env = crate::environment::environment(ctx, &record.environment).await?;
    let deployed = env
        .properties
        .get(&format!("deployed.{}", pin.product))
        .cloned()
        .filter(|value| !value.is_empty());
    let restore = match deployed.as_deref() {
        Some(version) => {
            let current_id = crate::ontology::release_id(&pin.product, version);
            let current = catalog::EmbeddedCatalog::new(ctx)
                .lookup_release(&current_id, &record.environment)
                .await
                .map_err(anyhow::Error::from)?;
            Some(PlanReleasePin {
                release_id: current.release_id,
                digest: current.manifest_digest,
                artifact_digest: current.artifact_digest,
                workdir: current.content_path,
            })
        }
        None => {
            let source_id = crate::ontology::release_id(
                &record.declaration.source.product,
                &record.declaration.source.version,
            );
            let source = catalog::EmbeddedCatalog::new(ctx)
                .lookup_release(&source_id, &record.environment)
                .await
                .map_err(anyhow::Error::from)?;
            Some(PlanReleasePin {
                release_id: source.release_id,
                digest: source.manifest_digest,
                artifact_digest: source.artifact_digest,
                workdir: source.content_path,
            })
        }
    };
    let action = match deployed.as_deref() {
        None => Action::Install,
        Some(version) if version == pin.version => Action::Restart,
        Some(_) => Action::Upgrade,
    };
    let step = Step {
        id: String::new(),
        order: 0,
        product: pin.product.clone(),
        action,
        from: deployed,
        to: pin.version.clone(),
        release_id: descriptor.release_id,
        release_digest: descriptor.manifest_digest,
        artifact_digest: descriptor.artifact_digest,
        workdir: descriptor.content_path,
        restore,
    };
    plan::create_from_steps(ctx, &record.environment, vec![step]).await
}

async fn pending_plan_started(ctx: &mut Ctx, record: &MigrationRecord) -> Result<bool> {
    let Some(plan_id) = &record.pending_plan_id else {
        return Ok(false);
    };
    let plan = plan::load(ctx, plan_id).await?;
    Ok(plan.state != PlanState::Computed)
}

async fn require_rollback_target(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    if !record
        .receipts
        .iter()
        .any(|receipt| receipt.result == "accepted" && receipt.effect == "apply_target")
        && !pending_plan_started(ctx, record).await?
    {
        return Ok(());
    }
    let env = crate::environment::environment(ctx, &record.environment).await?;
    let deployed = env
        .properties
        .get(&format!("deployed.{}", record.declaration.target.product))
        .map(String::as_str);
    if deployed != Some(record.declaration.target.version.as_str()) {
        bail!(
            "package migration {} cannot roll back because {} is no longer at target {}",
            record.name,
            record.declaration.target.product,
            record.declaration.target.version
        );
    }
    Ok(())
}

async fn compensate_accepted(
    ctx: &mut Ctx,
    record: &mut MigrationRecord,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<()> {
    let attempted_apply = pending_plan_started(ctx, record).await?
        || record
            .receipts
            .iter()
            .any(|receipt| receipt.result == "accepted" && receipt.effect == "apply_target");
    if attempted_apply {
        restore_source(ctx, record, authorization, exec_lease).await?;
    }
    Ok(())
}

async fn restore_source(
    ctx: &mut Ctx,
    record: &mut MigrationRecord,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<()> {
    refresh_execution_lease(ctx, &record.name, exec_lease).await?;
    let pin = record.declaration.source.clone();
    let plan_id = match record.pending_rollback_plan_id.clone() {
        Some(id) => id,
        None => {
            let plan_id = create_pin_plan(ctx, record, &pin).await?.id;
            record.pending_rollback_plan_id = Some(plan_id.clone());
            persist(ctx, record).await?;
            plan_id
        }
    };
    apply_pin_plan(
        ctx,
        &record.name,
        &record.environment,
        &plan_id,
        authorization,
        exec_lease,
    )
    .await
}

async fn apply_pin_plan(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    plan_id: &str,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<()> {
    let approval_path;
    let exec = match authorization {
        MigrationAuthorization::LocalDevelopment { reason } => {
            ExecutionAuthorization::LocalDevelopment { reason }
        }
        MigrationAuthorization::Signed {
            approval,
            trust_roots,
        } => {
            let dir = approval
                .parent()
                .context("package migration approval path has no parent")?;
            approval_path = dir.join(format!("{plan_id}.json"));
            if !approval_path.is_file() {
                bail!(
                    "package migration rollback plan {plan_id} is waiting for a signed plan approval at {}",
                    approval_path.display()
                );
            }
            ExecutionAuthorization::Signed {
                approval: &approval_path,
                trust_roots,
            }
        }
    };
    refresh_execution_lease(ctx, name, exec_lease).await?;
    authorize_plan_on_lock(ctx, environment, plan_id).await?;
    let applied = apply::execute_with_options(
        ctx,
        plan_id,
        ExecutionOptions {
            skip_gates: false,
            emergency_reason: None,
            authorization: exec,
            software_executor: crate::software_executor::selected_software_executor()
                .map(std::sync::Arc::from),
            delivery_adapter: None,
            delivery_fence: None,
        },
    )
    .await;
    clear_authorized_plan(ctx, environment).await?;
    applied?;
    let plan = plan::load(ctx, plan_id).await?;
    if plan.state != PlanState::Succeeded {
        bail!("package migration plan {plan_id} ended in {}", plan.state);
    }
    Ok(())
}

async fn persist_new(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    require_package_migration_schema(ctx).await?;
    let id = package_migration_id(&record.name);
    if let Some(existing) = ctx.get(&id).await? {
        let stored: MigrationRecord = serde_json::from_str(
            existing
                .properties
                .get("record")
                .context("stored package migration has no record")?,
        )?;
        if stored.identity_digest == record.identity_digest
            && stored.declaration == record.declaration
        {
            return Ok(());
        }
        bail!(
            "package migration {} already exists with a different identity",
            record.name
        );
    }
    ctx.create_once(record_object(record, crate::now_millis())?)
        .await?;
    Ok(())
}

async fn persist(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    require_package_migration_schema(ctx).await?;
    ctx.put(record_object(record, crate::now_millis())?).await?;
    Ok(())
}

fn record_object(record: &MigrationRecord, now: i64) -> Result<Object> {
    Ok(Object {
        id: package_migration_id(&record.name),
        kind: KIND_PACKAGE_MIGRATION.into(),
        name: record.name.clone(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("name".into(), record.name.clone()),
            ("identity_digest".into(), record.identity_digest.clone()),
            ("environment".into(), record.environment.clone()),
            ("status".into(), record.status.as_str().into()),
            ("record".into(), serde_json::to_string(record)?),
        ]),
        created: now,
        updated: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{self, PublishOptions};
    use crate::client::Ctx;
    use base64::Engine as _;

    fn digest(nibble: char) -> String {
        format!("sha256:{}", nibble.to_string().repeat(64))
    }

    fn declaration(irreversible: bool) -> MigrationDeclaration {
        let mut checkpoints = vec![
            CheckpointDecl {
                id: "preflight".into(),
                class: CheckpointClass::Reversible,
                pre_admission: None,
            },
            CheckpointDecl {
                id: "switch".into(),
                class: CheckpointClass::Compensating,
                pre_admission: None,
            },
        ];
        if irreversible {
            checkpoints.push(CheckpointDecl {
                id: "drop-old".into(),
                class: CheckpointClass::Irreversible,
                pre_admission: Some("require_backup_receipt".into()),
            });
        }
        MigrationDeclaration {
            version: 1,
            profile: MIGRATION_PROFILE.into(),
            source: PackagePin {
                product: "pkg".into(),
                version: "1.0.0".into(),
                digest: String::new(),
            },
            target: PackagePin {
                product: "pkg".into(),
                version: "1.1.0".into(),
                digest: String::new(),
            },
            compatibility: CompatibilityEvidence {
                version: 1,
                status: CompatibilityStatus::Compatible,
                evidence_digest: digest('e'),
            },
            checkpoints,
        }
    }

    async fn publish_pins(ctx: &mut Ctx, root: &Path) -> MigrationDeclaration {
        let mut doc = declaration(false);
        for (version, body) in [("1.0.0", "one"), ("1.1.0", "two")] {
            let dir = root.join(version);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("payload.txt"), body).unwrap();
            std::fs::write(
                dir.join("tenkai.toml"),
                format!(
                    r#"
[product]
name = "pkg"
version = "{version}"
[deploy]
install = "true"
inputs = ["payload.txt"]
"#
                ),
            )
            .unwrap();
            catalog::publish(
                ctx,
                &dir.join("tenkai.toml"),
                &PublishOptions {
                    signature: None,
                    trust_roots: None,
                    allow_unsigned_development: true,
                    provenance: Vec::new(),
                    provenance_trust_roots: None,
                    change_set_evidence: None,
                },
            )
            .await
            .unwrap();
        }
        let source = ctx
            .get(&crate::ontology::release_id("pkg", "1.0.0"))
            .await
            .unwrap()
            .unwrap();
        let target = ctx
            .get(&crate::ontology::release_id("pkg", "1.1.0"))
            .await
            .unwrap()
            .unwrap();
        doc.source.digest = catalog_digest(source.properties.get("digest").unwrap()).unwrap();
        doc.target.digest = catalog_digest(target.properties.get("digest").unwrap()).unwrap();
        doc
    }

    async fn deploy_source(ctx: &mut Ctx) {
        let actor = crate::auth_context::test_management_context("package-migration");
        catalog::promote(ctx, &actor, "pkg@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(ctx, "local", "pkg", "stable")
            .await
            .unwrap();
        let plan = crate::plan::create(ctx, "local").await.unwrap();
        crate::apply::execute_with_options(
            ctx,
            &plan.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "seed source package",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        let env = crate::environment::environment(ctx, "local").await.unwrap();
        assert_eq!(
            env.properties.get("deployed.pkg").map(String::as_str),
            Some("1.0.0")
        );
    }

    #[tokio::test]
    async fn compatible_migration_approves_executes_resumes_and_rolls_back() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-migration-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        let declaration = publish_pins(&mut ctx, &root).await;
        deploy_source(&mut ctx).await;
        let auth = MigrationAuthorization::LocalDevelopment {
            reason: "package migration e2e",
        };
        let previewed = preview(&mut ctx, "cutover", "local", declaration.clone(), None)
            .await
            .unwrap();
        let created = create(&mut ctx, "cutover", "local", declaration.clone(), None)
            .await
            .unwrap();
        assert_eq!(previewed.identity_digest, created.identity_digest);
        approve(&mut ctx, "cutover", auth).await.unwrap();
        let first = execute(&mut ctx, "cutover", auth, None).await.unwrap();
        assert_eq!(first.receipts.len(), 1);
        assert_eq!(first.status, MigrationStatus::Running);
        let sneak = crate::plan::create_from_steps(
            &mut ctx,
            "local",
            vec![crate::plan::Step {
                id: String::new(),
                order: 0,
                product: "pkg".into(),
                action: crate::plan::Action::Upgrade,
                from: Some("1.0.0".into()),
                to: "1.1.0".into(),
                release_id: crate::ontology::release_id("pkg", "1.1.0"),
                release_digest: declaration.target.digest.clone(),
                artifact_digest: declaration.target.digest.clone(),
                workdir: root.join("1.1.0").to_string_lossy().into(),
                restore: None,
            }],
        )
        .await
        .unwrap();
        let err = crate::apply::execute_with_options(
            &mut ctx,
            &sneak.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "sneak apply during migration",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("package migration"), "{err}");
        let held = ctx
            .acquire_lease(MIGRATION_EXEC_NAMESPACE, "cutover", "tester", 60_000)
            .await
            .unwrap();
        let err = resume(&mut ctx, "cutover", auth, Some(first.fence_generation))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("already has an execution"), "{err}");
        ctx.release_lease(MIGRATION_EXEC_NAMESPACE, "cutover", &held.fencing_token)
            .await
            .unwrap();
        let resumed = resume(&mut ctx, "cutover", auth, Some(first.fence_generation))
            .await
            .unwrap();
        assert_eq!(resumed.receipts.len(), 2);
        assert_eq!(resumed.status, MigrationStatus::Succeeded);
        assert_eq!(resumed.receipts[1].effect, "apply_target");
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(
            env.properties.get("deployed.pkg").map(String::as_str),
            Some("1.1.0")
        );
        let again = resume(&mut ctx, "cutover", auth, Some(resumed.fence_generation))
            .await
            .unwrap();
        assert_eq!(again.receipts, resumed.receipts);
        let rolled = rollback(&mut ctx, "cutover", auth, Some(again.fence_generation))
            .await
            .unwrap();
        assert_eq!(rolled.status, MigrationStatus::RolledBack);
        assert!(
            rolled
                .receipts
                .iter()
                .all(|receipt| receipt.result == "rolled_back")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn denial_stale_fence_conflict_and_irreversible_recovery() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-migration-deny-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        let mut declaration = publish_pins(&mut ctx, &root).await;
        deploy_source(&mut ctx).await;
        declaration.compatibility.status = CompatibilityStatus::Incompatible;
        let err = create(&mut ctx, "bad", "local", declaration.clone(), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not compatible"), "{err}");
        let mut cross = declaration.clone();
        cross.compatibility.status = CompatibilityStatus::Compatible;
        cross.target.product = "other".into();
        let err = create(&mut ctx, "cross", "local", cross, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("same product"), "{err}");

        declaration.compatibility.status = CompatibilityStatus::Compatible;
        create(&mut ctx, "cutover", "local", declaration.clone(), None)
            .await
            .unwrap();
        let err = execute(
            &mut ctx,
            "cutover",
            MigrationAuthorization::LocalDevelopment { reason: "nope" },
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("not approved"), "{err}");

        let auth = MigrationAuthorization::LocalDevelopment {
            reason: "package migration deny",
        };
        approve(&mut ctx, "cutover", auth).await.unwrap();
        execute(&mut ctx, "cutover", auth, None).await.unwrap();
        create(&mut ctx, "other", "local", declaration.clone(), None)
            .await
            .unwrap();
        approve(
            &mut ctx,
            "other",
            MigrationAuthorization::LocalDevelopment {
                reason: "concurrent",
            },
        )
        .await
        .unwrap();
        let err = execute(
            &mut ctx,
            "other",
            MigrationAuthorization::LocalDevelopment {
                reason: "concurrent",
            },
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("already has package migration")
                || err.contains("has package migration cutover"),
            "{err}"
        );
        let err = resume(&mut ctx, "cutover", auth, Some(99))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("stale fencing"), "{err}");
        rollback(&mut ctx, "cutover", auth, None).await.unwrap();

        let mut changed = declaration.clone();
        changed.checkpoints.pop();
        let err = create(&mut ctx, "cutover", "local", changed, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("different identity"), "{err}");

        let mut irreversible = declaration.clone();
        irreversible.checkpoints.push(CheckpointDecl {
            id: "drop-old".into(),
            class: CheckpointClass::Irreversible,
            pre_admission: Some("require_backup_receipt".into()),
        });
        let err = create(&mut ctx, "drop", "local", irreversible.clone(), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("backup receipt"), "{err}");
        create(&mut ctx, "drop", "local", irreversible, Some(&digest('b')))
            .await
            .unwrap();
        let drop_auth = MigrationAuthorization::LocalDevelopment {
            reason: "irreversible",
        };
        approve(&mut ctx, "drop", drop_auth).await.unwrap();
        execute(&mut ctx, "drop", drop_auth, None).await.unwrap();
        execute(&mut ctx, "drop", drop_auth, None).await.unwrap();
        let finished = execute(&mut ctx, "drop", drop_auth, None).await.unwrap();
        assert_eq!(finished.status, MigrationStatus::Succeeded);
        let err = rollback(&mut ctx, "drop", drop_auth, Some(finished.fence_generation))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("irreversible"), "{err}");
        let stored = load(&mut ctx, "drop").await.unwrap();
        assert_eq!(stored.status, MigrationStatus::RecoveryRequired);
        assert_eq!(
            stored.backup_receipt_digest.as_deref(),
            Some(digest('b').as_str())
        );

        let signed = create(&mut ctx, "signed", "local", declaration.clone(), None)
            .await
            .unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let public = key.verifying_key();
        let key_id = signature_verification::key_id(&public.to_bytes());
        let mut statement = MigrationApprovalStatement {
            identity_digest: signed.identity_digest.clone(),
            environment: signed.environment.clone(),
            purpose: APPROVAL_PURPOSE.into(),
            issued_at: 1,
            expires_at: i64::MAX / 4,
        };
        statement.identity_digest = digest('a');
        let bad_sig = {
            use ed25519_dalek::Signer as _;
            base64::engine::general_purpose::STANDARD.encode(
                key.sign(&canonical_approval_bytes(&statement).unwrap())
                    .to_bytes(),
            )
        };
        let bad = root.join("bad-approval.json");
        std::fs::write(
            &bad,
            serde_json::to_vec(&MigrationApprovalEnvelope {
                schema: APPROVAL_SCHEMA.into(),
                key_id: key_id.clone(),
                statement,
                signature: bad_sig,
            })
            .unwrap(),
        )
        .unwrap();
        let roots = root.join("migration-trust.toml");
        std::fs::write(
            &roots,
            format!(
                "version = 1\n[[signers]]\nkey_id = \"{key_id}\"\nidentity = \"approver\"\npublic_key = \"{}\"\n",
                base64::engine::general_purpose::STANDARD.encode(public.to_bytes())
            ),
        )
        .unwrap();
        let err = approve(
            &mut ctx,
            "signed",
            MigrationAuthorization::Signed {
                approval: &bad,
                trust_roots: &roots,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("different identity"), "{err}");
        let statement = MigrationApprovalStatement {
            identity_digest: signed.identity_digest.clone(),
            environment: signed.environment.clone(),
            purpose: APPROVAL_PURPOSE.into(),
            issued_at: 1,
            expires_at: i64::MAX / 4,
        };
        let signature = {
            use ed25519_dalek::Signer as _;
            base64::engine::general_purpose::STANDARD.encode(
                key.sign(&canonical_approval_bytes(&statement).unwrap())
                    .to_bytes(),
            )
        };
        let good = root.join("good-approval.json");
        std::fs::write(
            &good,
            serde_json::to_vec(&MigrationApprovalEnvelope {
                schema: APPROVAL_SCHEMA.into(),
                key_id,
                statement,
                signature,
            })
            .unwrap(),
        )
        .unwrap();
        approve(
            &mut ctx,
            "signed",
            MigrationAuthorization::Signed {
                approval: &good,
                trust_roots: &roots,
            },
        )
        .await
        .unwrap();

        crate::plan::env_add(&mut ctx, "stage", "fixture")
            .await
            .unwrap();
        create(&mut ctx, "remote", "stage", declaration, None)
            .await
            .unwrap();
        let err = approve(
            &mut ctx,
            "remote",
            MigrationAuthorization::LocalDevelopment { reason: "stage" },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("built-in local"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }
}
