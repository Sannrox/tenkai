//! Self-verifying delivery bundles and signed receipts for disconnected runtimes.
//!
//! The JSON envelope is the transport archive. Integrity and signatures bind a
//! canonical binary statement, so JSON field order never affects identity.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::reconciler::{RuntimeCompletion, RuntimeStepReceipt};
use crate::release_signing::TrustRoots;

pub const BUNDLE_SCHEMA: &str = "tenkai.offline-bundle.v1";
pub const RECEIPT_SCHEMA: &str = "tenkai.offline-receipt.v1";
pub const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 1024;

const BUNDLE_DOMAIN: &[u8] = b"TENKAI-OFFLINE-BUNDLE-V1\0";
const RECEIPT_DOMAIN: &[u8] = b"TENKAI-OFFLINE-RECEIPT-V1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEnvelope {
    pub schema: String,
    pub key_id: String,
    pub statement: BundleStatement,
    pub entries: Vec<BundleEntry>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleStatement {
    pub tenant_id: String,
    pub environment_id: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub approval_digest: String,
    pub release_ids: Vec<String>,
    pub exporter_identity: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub entries: Vec<EntryDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryDescriptor {
    pub path: String,
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEntry {
    pub path: String,
    pub content_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEnvelope {
    pub schema: String,
    pub key_id: String,
    pub statement: ReceiptStatement,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptStatement {
    pub bundle_digest: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub runtime_id: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub generation: u64,
    pub succeeded: bool,
    pub detail: String,
    pub completed_at_unix_ms: i64,
    pub receipts: Vec<OfflineStepReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineStepReceipt {
    pub receipt_id: String,
    pub step_id: String,
    pub attempt: u32,
    pub succeeded: bool,
    pub result_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundle {
    digest: String,
    signer_identity: String,
    statement: BundleStatement,
    entries: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    signer_identity: String,
    statement: ReceiptStatement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptTrustScope {
    pub tenant_id: String,
    pub environment_id: String,
    pub runtime_id: String,
    pub key_id: String,
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn validate_text(name: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > max
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        bail!("{name} is empty, non-canonical, contains control characters, or is too long");
    }
    Ok(())
}

fn validate_digest(name: &str, value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{name} must use sha256:<hex>");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{name} must contain 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    validate_text("bundle entry path", path, 512)?;
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || path.contains('\\')
        || candidate
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        bail!("bundle entry path {path:?} is not a canonical relative path");
    }
    Ok(())
}

fn signing_key_id(key: &SigningKey) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(key.verifying_key().to_bytes())
    )
}

fn signature_bytes(value: &str) -> Result<Signature> {
    let decoded = STANDARD
        .decode(value)
        .context("decoding Ed25519 signature")?;
    let bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signature must decode to exactly 64 bytes"))?;
    Ok(Signature::from_bytes(&bytes))
}

fn verifying_key(
    roots: &TrustRoots,
    key_id: &str,
) -> Result<(String, ed25519_dalek::VerifyingKey)> {
    roots.validate()?;
    let signer = roots
        .signers
        .iter()
        .find(|signer| signer.key_id == key_id)
        .with_context(|| format!("offline signer {key_id} is not currently trusted"))?;
    let decoded = STANDARD
        .decode(&signer.public_key)
        .context("decoding offline signer public key")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("offline signer public key must be exactly 32 bytes"))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .context("offline signer public key is invalid")?;
    Ok((signer.identity.clone(), key))
}

impl BundleStatement {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut output = BUNDLE_DOMAIN.to_vec();
        for value in [
            self.tenant_id.as_bytes(),
            self.environment_id.as_bytes(),
            self.plan_id.as_bytes(),
            self.plan_digest.as_bytes(),
            self.approval_digest.as_bytes(),
            self.exporter_identity.as_bytes(),
        ] {
            push_bytes(&mut output, value);
        }
        output.extend_from_slice(&self.issued_at_unix_ms.to_be_bytes());
        output.extend_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        output.extend_from_slice(&(self.release_ids.len() as u64).to_be_bytes());
        for release in &self.release_ids {
            push_bytes(&mut output, release.as_bytes());
        }
        output.extend_from_slice(&(self.entries.len() as u64).to_be_bytes());
        for entry in &self.entries {
            for value in [
                entry.path.as_bytes(),
                entry.media_type.as_bytes(),
                entry.digest.as_bytes(),
            ] {
                push_bytes(&mut output, value);
            }
            output.extend_from_slice(&entry.size.to_be_bytes());
        }
        Ok(output)
    }

    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("tenant identity", self.tenant_id.as_str()),
            ("environment identity", self.environment_id.as_str()),
            ("plan identity", self.plan_id.as_str()),
            ("exporter identity", self.exporter_identity.as_str()),
        ] {
            validate_text(name, value, 256)?;
        }
        validate_digest("plan digest", &self.plan_digest)?;
        validate_digest("approval digest", &self.approval_digest)?;
        if self.issued_at_unix_ms <= 0 || self.expires_at_unix_ms <= self.issued_at_unix_ms {
            bail!("bundle validity interval is invalid");
        }
        if self.release_ids.is_empty() || self.entries.is_empty() {
            bail!("bundle must contain releases and entries");
        }
        if self.entries.len() > MAX_ENTRIES {
            bail!("bundle exceeds the {MAX_ENTRIES} entry limit");
        }
        let mut releases = BTreeSet::new();
        for release in &self.release_ids {
            validate_text("release identity", release, 256)?;
            if release.contains('/') || release.contains('\\') {
                bail!("release identity cannot contain path separators");
            }
            if !releases.insert(release) {
                bail!("bundle contains duplicate release identity {release}");
            }
        }
        let mut paths = BTreeSet::new();
        let mut previous = None;
        let mut total = 0_u64;
        for entry in &self.entries {
            validate_path(&entry.path)?;
            validate_text("entry media type", &entry.media_type, 128)?;
            validate_digest("entry digest", &entry.digest)?;
            if entry.size > MAX_ENTRY_BYTES {
                bail!("bundle entry {} exceeds the byte limit", entry.path);
            }
            total = total
                .checked_add(entry.size)
                .ok_or_else(|| anyhow::anyhow!("bundle size overflow"))?;
            if total > MAX_ARCHIVE_BYTES {
                bail!("bundle payloads exceed the archive byte limit");
            }
            if !paths.insert(&entry.path) {
                bail!("bundle contains duplicate entry path {}", entry.path);
            }
            if previous.is_some_and(|path: &str| path >= entry.path.as_str()) {
                bail!("bundle entry descriptors must be sorted by path");
            }
            previous = Some(&entry.path);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(self.canonical_bytes()?)
        ))
    }
}

impl BundleEnvelope {
    pub fn create(
        mut statement: BundleStatement,
        payloads: BTreeMap<String, (String, Vec<u8>)>,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        statement.entries = payloads
            .iter()
            .map(|(path, (media_type, content))| EntryDescriptor {
                path: path.clone(),
                media_type: media_type.clone(),
                digest: format!("sha256:{:x}", Sha256::digest(content)),
                size: content.len() as u64,
            })
            .collect();
        let signature = signing_key.sign(&statement.canonical_bytes()?);
        Ok(Self {
            schema: BUNDLE_SCHEMA.into(),
            key_id: signing_key_id(signing_key),
            statement,
            entries: payloads
                .into_iter()
                .map(|(path, (_, content))| BundleEntry {
                    path,
                    content_base64: STANDARD.encode(content),
                })
                .collect(),
            signature: STANDARD.encode(signature.to_bytes()),
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let size = std::fs::metadata(path)
            .with_context(|| format!("reading bundle metadata {}", path.display()))?
            .len();
        let encoded_limit = MAX_ARCHIVE_BYTES.saturating_mul(4) / 3 + 4 * 1024 * 1024;
        if size > encoded_limit {
            bail!("offline bundle exceeds the encoded archive byte limit");
        }
        let raw = std::fs::read(path)
            .with_context(|| format!("reading offline bundle {}", path.display()))?;
        serde_json::from_slice(&raw).context("parsing offline bundle")
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("offline bundle destination must have a UTF-8 file name")?;
        let temporary = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .with_context(|| format!("creating temporary bundle {}", temporary.display()))?;
            file.write_all(&bytes)
                .with_context(|| format!("writing temporary bundle {}", temporary.display()))?;
            file.sync_all()
                .with_context(|| format!("syncing temporary bundle {}", temporary.display()))?;
            std::fs::rename(&temporary, path).with_context(|| {
                format!("atomically replacing offline bundle {}", path.display())
            })?;
            std::fs::File::open(parent)
                .with_context(|| format!("opening bundle directory {}", parent.display()))?
                .sync_all()
                .with_context(|| format!("syncing bundle directory {}", parent.display()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    pub fn verify(
        &self,
        roots: &TrustRoots,
        tenant_id: &str,
        environment_id: &str,
        now_unix_ms: i64,
    ) -> Result<VerifiedBundle> {
        if self.schema != BUNDLE_SCHEMA {
            bail!("unsupported offline bundle schema {}", self.schema);
        }
        if self.statement.tenant_id != tenant_id || self.statement.environment_id != environment_id
        {
            bail!("offline bundle is outside the configured tenant or environment scope");
        }
        if now_unix_ms < self.statement.issued_at_unix_ms
            || now_unix_ms >= self.statement.expires_at_unix_ms
        {
            bail!("offline bundle is outside its validity interval");
        }
        let (identity, key) = verifying_key(roots, &self.key_id)?;
        if self.statement.exporter_identity != identity {
            bail!("bundle exporter identity does not match its trusted signing identity");
        }
        key.verify_strict(
            &self.statement.canonical_bytes()?,
            &signature_bytes(&self.signature)?,
        )
        .context("offline bundle signature verification failed")?;
        let expected = self
            .statement
            .entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        if self.entries.len() != expected.len() {
            bail!("offline bundle entry set does not match its signed index");
        }
        let mut entries = BTreeMap::new();
        for entry in &self.entries {
            validate_path(&entry.path)?;
            let descriptor = expected
                .get(entry.path.as_str())
                .with_context(|| format!("unsigned or unexpected bundle entry {}", entry.path))?;
            if entries.contains_key(&entry.path) {
                bail!("offline bundle contains duplicate entry {}", entry.path);
            }
            let content = STANDARD
                .decode(&entry.content_base64)
                .with_context(|| format!("decoding bundle entry {}", entry.path))?;
            if content.len() as u64 != descriptor.size
                || format!("sha256:{:x}", Sha256::digest(&content)) != descriptor.digest
            {
                bail!(
                    "bundle entry {} does not match its signed digest and size",
                    entry.path
                );
            }
            entries.insert(entry.path.clone(), content);
        }
        let plan_path = format!("plans/{}.json", self.statement.plan_id);
        let plan = entries
            .get(&plan_path)
            .with_context(|| format!("bundle is missing canonical plan entry {plan_path}"))?;
        if format!("sha256:{:x}", Sha256::digest(plan)) != self.statement.plan_digest {
            bail!("canonical plan entry does not match the signed plan digest");
        }
        let approval_path = format!("approvals/{}.json", self.statement.plan_id);
        let approval = entries.get(&approval_path).with_context(|| {
            format!("bundle is missing canonical approval entry {approval_path}")
        })?;
        if format!("sha256:{:x}", Sha256::digest(approval)) != self.statement.approval_digest {
            bail!("canonical approval entry does not match the signed approval digest");
        }
        for release in &self.statement.release_ids {
            let prefix = format!("releases/{release}/");
            if !entries.keys().any(|path| path.starts_with(&prefix)) {
                bail!("bundle is missing content for signed release identity {release}");
            }
        }
        Ok(VerifiedBundle {
            digest: self.statement.digest()?,
            signer_identity: identity,
            statement: self.statement.clone(),
            entries,
        })
    }
}

impl VerifiedBundle {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn signer_identity(&self) -> &str {
        &self.signer_identity
    }

    pub fn statement(&self) -> &BundleStatement {
        &self.statement
    }

    pub fn entry(&self, path: &str) -> Option<&[u8]> {
        self.entries.get(path).map(Vec::as_slice)
    }
}

impl ReceiptStatement {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut output = RECEIPT_DOMAIN.to_vec();
        for value in [
            self.bundle_digest.as_bytes(),
            self.tenant_id.as_bytes(),
            self.environment_id.as_bytes(),
            self.runtime_id.as_bytes(),
            self.plan_id.as_bytes(),
            self.plan_digest.as_bytes(),
        ] {
            push_bytes(&mut output, value);
        }
        output.extend_from_slice(&self.generation.to_be_bytes());
        output.push(u8::from(self.succeeded));
        push_bytes(&mut output, self.detail.as_bytes());
        output.extend_from_slice(&self.completed_at_unix_ms.to_be_bytes());
        output.extend_from_slice(&(self.receipts.len() as u64).to_be_bytes());
        for receipt in &self.receipts {
            for value in [
                receipt.receipt_id.as_bytes(),
                receipt.step_id.as_bytes(),
                receipt.result_digest.as_bytes(),
            ] {
                push_bytes(&mut output, value);
            }
            output.extend_from_slice(&receipt.attempt.to_be_bytes());
            output.push(u8::from(receipt.succeeded));
        }
        Ok(output)
    }

    fn validate(&self) -> Result<()> {
        validate_digest("bundle digest", &self.bundle_digest)?;
        validate_digest("plan digest", &self.plan_digest)?;
        for (name, value) in [
            ("tenant identity", self.tenant_id.as_str()),
            ("environment identity", self.environment_id.as_str()),
            ("runtime identity", self.runtime_id.as_str()),
            ("plan identity", self.plan_id.as_str()),
        ] {
            validate_text(name, value, 256)?;
        }
        validate_text("receipt detail", &self.detail, 2048)?;
        if self.generation == 0 || self.completed_at_unix_ms <= 0 || self.receipts.is_empty() {
            bail!("offline receipt has invalid generation, completion time, or step set");
        }
        let mut ids = BTreeSet::new();
        let mut steps = BTreeSet::new();
        for receipt in &self.receipts {
            validate_text("receipt identity", &receipt.receipt_id, 256)?;
            validate_text("receipt step identity", &receipt.step_id, 256)?;
            validate_digest("receipt result digest", &receipt.result_digest)?;
            if receipt.attempt == 0
                || receipt.receipt_id
                    != offline_receipt_id(
                        &self.environment_id,
                        &self.plan_id,
                        &receipt.step_id,
                        receipt.attempt,
                    )
            {
                bail!("offline receipt identity does not match its step mutation identity");
            }
            if !ids.insert(&receipt.receipt_id) || !steps.insert(&receipt.step_id) {
                bail!("offline receipt contains duplicate receipt or step identity");
            }
        }
        if self.succeeded && self.receipts.iter().any(|receipt| !receipt.succeeded) {
            bail!("successful offline completion contains a failed step receipt");
        }
        Ok(())
    }
}

impl ReceiptEnvelope {
    pub fn create(statement: ReceiptStatement, signing_key: &SigningKey) -> Result<Self> {
        let signature = signing_key.sign(&statement.canonical_bytes()?);
        Ok(Self {
            schema: RECEIPT_SCHEMA.into(),
            key_id: signing_key_id(signing_key),
            statement,
            signature: STANDARD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(
        &self,
        roots: &TrustRoots,
        scope: &ReceiptTrustScope,
        bundle: &VerifiedBundle,
        now_unix_ms: i64,
    ) -> Result<VerifiedReceipt> {
        if self.schema != RECEIPT_SCHEMA {
            bail!("unsupported offline receipt schema {}", self.schema);
        }
        if self.statement.tenant_id != scope.tenant_id
            || self.statement.environment_id != scope.environment_id
            || self.statement.runtime_id != scope.runtime_id
            || self.key_id != scope.key_id
        {
            bail!("offline receipt signer is outside its configured runtime trust scope");
        }
        if self.statement.bundle_digest != bundle.digest
            || self.statement.tenant_id != bundle.statement.tenant_id
            || self.statement.environment_id != bundle.statement.environment_id
            || self.statement.plan_id != bundle.statement.plan_id
            || self.statement.plan_digest != bundle.statement.plan_digest
        {
            bail!("offline receipt does not bind to the verified bundle");
        }
        if self.statement.completed_at_unix_ms < bundle.statement.issued_at_unix_ms
            || self.statement.completed_at_unix_ms >= bundle.statement.expires_at_unix_ms
            || self.statement.completed_at_unix_ms > now_unix_ms
        {
            bail!("offline receipt completion time is invalid");
        }
        let (identity, key) = verifying_key(roots, &self.key_id)?;
        key.verify_strict(
            &self.statement.canonical_bytes()?,
            &signature_bytes(&self.signature)?,
        )
        .context("offline receipt signature verification failed")?;
        Ok(VerifiedReceipt {
            signer_identity: identity,
            statement: self.statement.clone(),
        })
    }
}

impl VerifiedReceipt {
    pub fn signer_identity(&self) -> &str {
        &self.signer_identity
    }

    pub fn statement(&self) -> &ReceiptStatement {
        &self.statement
    }

    /// Adapt a verified offline receipt to the same application completion
    /// contract used by connected runtimes.
    pub fn runtime_completion(&self) -> RuntimeCompletion {
        RuntimeCompletion {
            plan_id: self.statement.plan_id.clone(),
            generation: self.statement.generation,
            succeeded: self.statement.succeeded,
            detail: self.statement.detail.clone(),
            receipts: self
                .statement
                .receipts
                .iter()
                .map(|receipt| RuntimeStepReceipt {
                    step_id: receipt.step_id.clone(),
                    succeeded: receipt.succeeded,
                    detail: format!(
                        "offline receipt {} result {}",
                        receipt.receipt_id, receipt.result_digest
                    ),
                })
                .collect(),
        }
    }
}

/// Match the connected runtime's stable mutation identity.
pub fn offline_receipt_id(
    environment_id: &str,
    plan_id: &str,
    step_id: &str,
    attempt: u32,
) -> String {
    let mut digest = Sha256::new();
    for value in [
        environment_id.as_bytes(),
        plan_id.as_bytes(),
        step_id.as_bytes(),
        &attempt.to_be_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    format!("{:x}", digest.finalize())
}

/// Import through the same lifecycle operation as connected runtime completion.
/// Replaying the same terminal result is idempotent; a conflicting result fails.
pub async fn import_receipt(
    store: &impl crate::storage::OperationalStore,
    reconciler: &crate::reconciler::Reconciler,
    receipt: &VerifiedReceipt,
) -> Result<()> {
    use crate::storage::{OfflineImportRecord, OfflineStepImportRecord};

    let completion = receipt.runtime_completion();
    reconciler
        .validate_runtime_completion(&receipt.statement.environment_id, &completion)
        .await?;
    let record = OfflineImportRecord {
        bundle_digest: receipt.statement.bundle_digest.clone(),
        environment_id: receipt.statement.environment_id.clone(),
        plan_id: receipt.statement.plan_id.clone(),
        receipt_json: serde_json::to_string(&receipt.statement)?,
    };
    let steps = receipt
        .statement
        .receipts
        .iter()
        .map(|step| OfflineStepImportRecord {
            receipt_id: step.receipt_id.clone(),
            environment_id: receipt.statement.environment_id.clone(),
            plan_id: receipt.statement.plan_id.clone(),
            step_id: step.step_id.clone(),
            attempt: step.attempt,
            result_digest: step.result_digest.clone(),
            succeeded: step.succeeded,
        })
        .collect::<Vec<_>>();
    store.record_offline_import(&record, &steps)?;
    reconciler
        .complete_runtime_work(&receipt.statement.environment_id, &completion)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_signing::TrustedSigner;

    fn digest(value: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(value))
    }

    fn roots(key: &SigningKey, identity: &str) -> TrustRoots {
        TrustRoots {
            version: 1,
            signers: vec![TrustedSigner {
                key_id: signing_key_id(key),
                identity: identity.into(),
                public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            }],
        }
    }

    fn bundle(key: &SigningKey) -> BundleEnvelope {
        let mut payloads = BTreeMap::new();
        let approval = br#"{"approval":"plan-1"}"#.to_vec();
        payloads.insert(
            "approvals/plan-1.json".into(),
            ("application/json".into(), approval.clone()),
        );
        let plan = br#"{"plan":"plan-1"}"#.to_vec();
        payloads.insert(
            "plans/plan-1.json".into(),
            ("application/json".into(), plan.clone()),
        );
        payloads.insert(
            "releases/app@1.0.0/payload.bin".into(),
            (
                "application/octet-stream".into(),
                b"immutable payload".to_vec(),
            ),
        );
        BundleEnvelope::create(
            BundleStatement {
                tenant_id: "tenant-1".into(),
                environment_id: "airgap-1".into(),
                plan_id: "plan-1".into(),
                plan_digest: digest(&plan),
                approval_digest: digest(&approval),
                release_ids: vec!["app@1.0.0".into()],
                exporter_identity: "exporter".into(),
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 10_000,
                entries: Vec::new(),
            },
            payloads,
            key,
        )
        .unwrap()
    }

    #[test]
    fn network_isolated_bundle_execution_and_receipt_round_trip() {
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let runtime = SigningKey::from_bytes(&[9; 32]);
        let verified = bundle(&exporter)
            .verify(&roots(&exporter, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap();
        assert_eq!(
            verified.entries["releases/app@1.0.0/payload.bin"],
            b"immutable payload"
        );

        let receipt = ReceiptEnvelope::create(
            ReceiptStatement {
                bundle_digest: verified.digest.clone(),
                tenant_id: "tenant-1".into(),
                environment_id: "airgap-1".into(),
                runtime_id: "runtime-1".into(),
                plan_id: "plan-1".into(),
                plan_digest: verified.statement.plan_digest.clone(),
                generation: 1,
                succeeded: true,
                detail: "offline execution completed".into(),
                completed_at_unix_ms: 3_000,
                receipts: vec![OfflineStepReceipt {
                    receipt_id: offline_receipt_id("airgap-1", "plan-1", "step-1", 1),
                    step_id: "step-1".into(),
                    attempt: 1,
                    succeeded: true,
                    result_digest: digest(b"installed"),
                }],
            },
            &runtime,
        )
        .unwrap();
        let scope = ReceiptTrustScope {
            tenant_id: "tenant-1".into(),
            environment_id: "airgap-1".into(),
            runtime_id: "runtime-1".into(),
            key_id: signing_key_id(&runtime),
        };
        let imported = receipt
            .verify(&roots(&runtime, "airgap runtime"), &scope, &verified, 4_000)
            .unwrap();
        assert!(imported.runtime_completion().succeeded);
    }

    #[test]
    fn every_changed_signed_input_fails_verification() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let roots = roots(&key, "exporter");
        let original = bundle(&key);
        for mutate in [
            |bundle: &mut BundleEnvelope| bundle.statement.plan_digest = digest(b"changed plan"),
            |bundle: &mut BundleEnvelope| {
                bundle.statement.approval_digest = digest(b"changed approval")
            },
            |bundle: &mut BundleEnvelope| bundle.statement.release_ids[0] = "app@2.0.0".into(),
            |bundle: &mut BundleEnvelope| {
                bundle.entries[0].content_base64 = STANDARD.encode(b"changed artifact")
            },
        ] {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert!(
                changed
                    .verify(&roots, "tenant-1", "airgap-1", 2_000)
                    .is_err()
            );
        }
    }

    #[test]
    fn signed_root_cannot_claim_different_plan_or_approval_payloads() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let roots = roots(&key, "exporter");
        for change in [
            |statement: &mut BundleStatement| statement.plan_digest = digest(b"other plan"),
            |statement: &mut BundleStatement| statement.approval_digest = digest(b"other approval"),
        ] {
            let mut archive = bundle(&key);
            change(&mut archive.statement);
            archive.signature = STANDARD.encode(
                key.sign(&archive.statement.canonical_bytes().unwrap())
                    .to_bytes(),
            );
            assert!(
                archive
                    .verify(&roots, "tenant-1", "airgap-1", 2_000)
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_scope_replay_expiry_and_unsafe_paths() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let roots = roots(&key, "exporter");
        let archive = bundle(&key);
        assert!(
            archive
                .verify(&roots, "other-tenant", "airgap-1", 2_000)
                .is_err()
        );
        assert!(
            archive
                .verify(&roots, "tenant-1", "airgap-1", 10_000)
                .is_err()
        );

        let mut unsafe_archive = archive;
        unsafe_archive.statement.entries[0].path = "../escape".into();
        assert!(
            unsafe_archive
                .verify(&roots, "tenant-1", "airgap-1", 2_000)
                .is_err()
        );
    }

    #[test]
    fn binds_claimed_identities_to_explicit_signer_scopes() {
        let exporter = SigningKey::from_bytes(&[7; 32]);
        let mut archive = bundle(&exporter);
        archive.statement.exporter_identity = "impersonated exporter".into();
        archive.signature = STANDARD.encode(
            exporter
                .sign(&archive.statement.canonical_bytes().unwrap())
                .to_bytes(),
        );
        assert!(
            archive
                .verify(&roots(&exporter, "exporter"), "tenant-1", "airgap-1", 2_000)
                .is_err()
        );

        let verified = bundle(&exporter)
            .verify(&roots(&exporter, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap();
        let runtime = SigningKey::from_bytes(&[9; 32]);
        let receipt = ReceiptEnvelope::create(
            ReceiptStatement {
                bundle_digest: verified.digest.clone(),
                tenant_id: "tenant-1".into(),
                environment_id: "airgap-1".into(),
                runtime_id: "runtime-1".into(),
                plan_id: "plan-1".into(),
                plan_digest: verified.statement.plan_digest.clone(),
                generation: 1,
                succeeded: true,
                detail: "completed".into(),
                completed_at_unix_ms: 3_000,
                receipts: vec![OfflineStepReceipt {
                    receipt_id: offline_receipt_id("airgap-1", "plan-1", "step-1", 1),
                    step_id: "step-1".into(),
                    attempt: 1,
                    succeeded: true,
                    result_digest: digest(b"installed"),
                }],
            },
            &runtime,
        )
        .unwrap();
        let wrong_scope = ReceiptTrustScope {
            tenant_id: "tenant-1".into(),
            environment_id: "other-environment".into(),
            runtime_id: "runtime-1".into(),
            key_id: signing_key_id(&runtime),
        };
        assert!(
            receipt
                .verify(&roots(&runtime, "runtime"), &wrong_scope, &verified, 4_000)
                .is_err()
        );
    }

    #[test]
    fn save_replaces_an_archive_without_leaving_temporary_files() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let directory =
            std::env::temp_dir().join(format!("tenkai-bundle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("delivery.json");
        std::fs::write(&path, b"old archive").unwrap();
        let archive = bundle(&key);
        archive.save(&path).unwrap();
        assert_eq!(BundleEnvelope::load(&path).unwrap(), archive);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
