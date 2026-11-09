//! Signed recall notices and advisory-driven fix-forward proposals (#693).
//!
//! A notice is a small `tenkai.recall-notice.v2` artifact: recalled release
//! digests, a reason, and an advisory id, signed over the bytes sent under
//! the same Ed25519 trust rules as
//! [ADR 0036](../docs/decisions/0036-offline-key-revocation.md). Import
//! verifies, refuses a revoked key, then stamps [`crate::catalog::recall`].
//! Named releases that are not in the catalog still get a recall claim so a
//! later publish of that identity is not deployable. `propose` validates the
//! signing key, notice, and wave cohort, reserves the wave name, then promotes
//! and recalls. The admitted wave does not apply until plan approval.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::auth_context::{AuthenticatedRequestContext, DeliveryCapability};
use crate::client::Ctx;
use crate::ontology::{KIND_ENVIRONMENT, KIND_RELEASE, NS, release_id};
use crate::pb::sekai::Object;
use crate::provider_event::{ProviderEventStore, enqueue_optional_event};
use crate::providers::{EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderEvent};
use crate::release_signing::TrustRoots;
use crate::wave::{self, ExecutableWaveSpec, WaveRecord};

/// Portable signed recall-notice schema. Its signature covers the statement
/// bytes the signer sent (#931); see `docs/recall-notices.md#wire-format`.
pub const NOTICE_SCHEMA: &str = "tenkai.recall-notice.v2";
/// Deprecated (#931): signed over Tenkai's re-encoding of the parsed
/// statement. Verified for notices made by earlier releases, never
/// produced, and removed in a later release.
pub const LEGACY_NOTICE_SCHEMA: &str = "tenkai.recall-notice.v1";
/// Stored imported-notice object kind.
pub const KIND_RECALL_NOTICE: &str = "tenkai.recall_notice";
/// First-writer claim that binds a wave name to one proposal identity.
pub const KIND_RECALL_PROPOSAL: &str = "tenkai.recall_proposal";
/// Optional outbox kind for imported notices. Off unless [`export_notice`] runs.
pub const RECALL_NOTICE_PROVIDER_KIND: &str = "recall_notice";
/// Prefix of every [`NOTICE_SCHEMA`] signed message.
pub const SIGNING_DOMAIN: &[u8] = b"TENKAI-RECALL-NOTICE-V2\0";
const LEGACY_SIGNING_DOMAIN: &[u8] = b"TENKAI-RECALL-NOTICE-V1\0";
const SIGNATURE_LABEL: &str = "recall notice signature";
const MAX_RECALLED: usize = 4_096;

/// One release named by a notice. A verifier ignores fields it does not
/// know; the signature still covers them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecalledRelease {
    pub release: String,
    pub digest: String,
}

/// What a recall authority signs ([`NOTICE_SCHEMA`]). A verifier ignores
/// fields it does not know; the signature still covers them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallNoticeStatement {
    pub issued_at: i64,
    pub advisory_id: String,
    pub reason: String,
    pub recalled: Vec<RecalledRelease>,
}

/// Signed recall notice as sent (#931). Every field is a string, so the
/// stored JSON of this envelope keeps the signed statement bytes exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeEnvelope {
    /// `tenkai.recall-notice.v2`.
    pub schema: String,
    /// `sha256:` and the lowercase hex SHA-256 of the signer's Ed25519 public key.
    pub key_id: String,
    /// Standard padded base64 of the statement JSON bytes the signer signed.
    pub statement: String,
    /// Standard padded base64 Ed25519 signature over
    /// `TENKAI-RECALL-NOTICE-V2`, one NUL byte, and the statement bytes.
    pub signature: String,
}

/// Frozen [`LEGACY_NOTICE_SCHEMA`] types. The signature covers the
/// serde_json encoding of [`legacy::Statement`], and a stored notice's
/// object id hashes the encoding of [`legacy::Notice`], so neither changes.
pub mod legacy {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Notice {
        pub schema: String,
        pub key_id: String,
        pub statement: Statement,
        pub signature: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Statement {
        pub issued_at: i64,
        pub advisory_id: String,
        pub reason: String,
        pub recalled: Vec<Recalled>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Recalled {
        pub release: String,
        pub digest: String,
    }
}

impl From<legacy::Statement> for RecallNoticeStatement {
    fn from(legacy: legacy::Statement) -> Self {
        Self {
            issued_at: legacy.issued_at,
            advisory_id: legacy.advisory_id,
            reason: legacy.reason,
            recalled: legacy
                .recalled
                .into_iter()
                .map(|entry| RecalledRelease {
                    release: entry.release,
                    digest: entry.digest,
                })
                .collect(),
        }
    }
}

/// A recall notice as received, before its signature is checked. It
/// serializes to the JSON Tenkai stores and hashes into the object id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum RecallNotice {
    Current(NoticeEnvelope),
    Legacy(legacy::Notice),
}

/// A recall notice whose signature verified, with its signer valid at
/// `issued_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNotice {
    pub key_id: String,
    pub statement: RecallNoticeStatement,
}

/// Inputs for [`propose`].
#[derive(Debug, Clone)]
pub struct ProposeRequest {
    pub exposure: String,
    pub fix: String,
    pub channel: String,
    pub environments: Vec<String>,
    pub wave_name: String,
    pub signing_key: PathBuf,
    pub notice_out: PathBuf,
}

/// Reviewable recall plus admitted fix-forward wave. Nothing has applied yet.
#[derive(Debug, Clone)]
pub struct Proposal {
    pub advisory_id: String,
    pub recalled: Vec<String>,
    pub notice: NoticeEnvelope,
    pub wave: WaveRecord,
    pub environments: Vec<RunningEnvironment>,
}

/// Result of importing a notice: catalog stamps and environments still running
/// the recalled releases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub advisory_id: String,
    pub recalled: Vec<String>,
    pub already_recalled: Vec<String>,
    pub missing: Vec<String>,
    pub environments: Vec<RunningEnvironment>,
}

/// An environment whose deployed pin still names a recalled release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningEnvironment {
    pub environment: String,
    pub deployed_release: String,
}

/// The message a [`LEGACY_NOTICE_SCHEMA`] signature covers.
fn legacy_signed_message(statement: &legacy::Statement) -> Result<Vec<u8>> {
    let mut bytes = LEGACY_SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, statement)?;
    Ok(bytes)
}

/// Stored identity of a notice: the SHA-256 of its stored JSON. A v1
/// notice keeps the id earlier releases gave it.
fn notice_id(notice: &RecallNotice) -> Result<String> {
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(notice)?));
    Ok(format!("tenkai:recall-notice:{digest}"))
}

fn notice_object(notice: &RecallNotice, verified: &VerifiedNotice) -> Result<Object> {
    let now = crate::now_millis();
    let document = serde_json::to_string(notice)?;
    let digest = format!("{:x}", Sha256::digest(document.as_bytes()));
    Ok(Object {
        id: notice_id(notice)?,
        kind: KIND_RECALL_NOTICE.into(),
        name: format!("recall-notice {}", verified.statement.advisory_id),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("document".into(), document),
            ("digest".into(), digest),
            ("imported_at".into(), now.to_string()),
            ("advisory_id".into(), verified.statement.advisory_id.clone()),
            ("key_id".into(), verified.key_id.clone()),
        ]),
        created: now,
        updated: now,
    })
}

/// Sign a notice with `signer`, the recall authority's key: serialize the
/// statement once and sign those bytes.
pub fn sign(
    statement: &RecallNoticeStatement,
    signer: &dyn crate::signer::ContentSigner,
) -> Result<NoticeEnvelope> {
    statement.validate()?;
    let signed = crate::signed_bytes::sign(SIGNING_DOMAIN, statement, |message| {
        Ok(signer.sign(message)?.to_vec())
    })?;
    Ok(NoticeEnvelope {
        schema: NOTICE_SCHEMA.into(),
        key_id: signer.key_id().to_string(),
        statement: signed.statement,
        signature: STANDARD.encode(signed.signature),
    })
}

impl RecallNoticeStatement {
    fn validate(&self) -> Result<()> {
        if self.advisory_id.trim().is_empty() || self.advisory_id.chars().any(char::is_control) {
            bail!("recall notice needs an advisory id");
        }
        if self.reason.trim().is_empty() || self.reason.chars().any(char::is_control) {
            bail!("recall notice needs a reason");
        }
        if self.recalled.is_empty() {
            bail!("recall notice must name at least one release");
        }
        if self.recalled.len() > MAX_RECALLED {
            bail!("recall notice exceeds {MAX_RECALLED} releases");
        }
        let mut seen = BTreeSet::new();
        for recalled in &self.recalled {
            let (product, version) = parse_release_spec(&recalled.release)?;
            validate_release_digest(&recalled.digest)?;
            if !seen.insert(format!("{product}@{version}")) {
                bail!("recall notice names {} twice", recalled.release);
            }
        }
        Ok(())
    }
}

impl RecallNotice {
    /// Read and parse a notice file. The signature is not checked here.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)
            .with_context(|| format!("reading recall notice {}", path.display()))?;
        Self::parse(&raw).with_context(|| format!("parsing recall notice {}", path.display()))
    }

    /// Parse a notice by its `schema`, without checking the signature. A
    /// schema this release does not verify is refused by name.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Schema {
            schema: String,
        }
        let Schema { schema } = serde_json::from_slice(bytes)
            .context("recall notice is not a JSON object with a schema")?;
        let notice = match schema.as_str() {
            NOTICE_SCHEMA => Self::Current(
                serde_json::from_slice(bytes).context("recall notice envelope is not valid")?,
            ),
            LEGACY_NOTICE_SCHEMA => Self::Legacy(
                serde_json::from_slice(bytes).context("recall notice envelope is not valid")?,
            ),
            other => bail!(
                "unsupported recall notice schema {other:?}; this release verifies {NOTICE_SCHEMA} and the deprecated {LEGACY_NOTICE_SCHEMA}"
            ),
        };
        crate::signature_verification::validate_key_id("recall notice key id", notice.key_id())?;
        Ok(notice)
    }

    pub fn key_id(&self) -> &str {
        match self {
            Self::Current(envelope) => &envelope.key_id,
            Self::Legacy(notice) => &notice.key_id,
        }
    }

    /// Check the signature against the notice authorities, then parse and
    /// validate the statement. A v2 statement is parsed only from the bytes
    /// the signature covers.
    ///
    /// The key is looked up with revocation checked, so a notice signed by a
    /// revoked authority never reaches catalog mutation. Once the signed
    /// `issued_at` is known, the authority must have been valid then (ADR 0042).
    pub fn verify(&self, authorities: &TrustRoots) -> Result<VerifiedNotice> {
        let key = authorities.resolve_unwindowed(self.key_id())?.verifying_key;
        let statement = match self {
            Self::Current(envelope) => {
                let signature = crate::signature_verification::decode_exact::<64>(
                    SIGNATURE_LABEL,
                    &envelope.signature,
                )?;
                crate::signed_bytes::verify::<RecallNoticeStatement>(
                    SIGNING_DOMAIN,
                    &envelope.statement,
                    |message| {
                        crate::signature_verification::verify_strict_bytes(
                            &key,
                            SIGNATURE_LABEL,
                            &signature,
                            message,
                        )
                        .is_ok()
                    },
                )
                .map_err(|refusal| anyhow::anyhow!("recall notice refused: {refusal}"))?
                .statement
            }
            Self::Legacy(notice) => {
                crate::signature_verification::verify_strict(
                    &key,
                    SIGNATURE_LABEL,
                    &notice.signature,
                    &legacy_signed_message(&notice.statement)?,
                )?;
                RecallNoticeStatement::from(notice.statement.clone())
            }
        };
        statement.validate()?;
        authorities.resolve_signed_at(self.key_id(), statement.issued_at, crate::now_millis())?;
        Ok(VerifiedNotice {
            key_id: self.key_id().into(),
            statement,
        })
    }
}

fn digest_hex(value: &str) -> &str {
    value.strip_prefix("sha256:").unwrap_or(value)
}

fn validate_release_digest(value: &str) -> Result<()> {
    crate::signature_verification::validate_hex_digest("recalled release digest", digest_hex(value))
}

fn parse_release_spec(spec: &str) -> Result<(&str, &str)> {
    let Some((product, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    crate::ontology::validate_identifier("product", product)?;
    crate::ontology::validate_identifier("version", version)?;
    Ok((product, version))
}

async fn persist_notice(
    ctx: &mut Ctx,
    notice: &RecallNotice,
    verified: &VerifiedNotice,
) -> Result<()> {
    let proposed = notice_object(notice, verified)?;
    match ctx.create_once(proposed.clone()).await {
        Ok(_) => Ok(()),
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let stored = ctx.get(&proposed.id).await?.ok_or_else(|| {
                anyhow::anyhow!("recall notice {} appeared then vanished", proposed.id)
            })?;
            if stored.kind != KIND_RECALL_NOTICE
                || stored.properties.get("document") != proposed.properties.get("document")
            {
                bail!(
                    "recall notice {} has conflicting stored evidence",
                    proposed.id
                );
            }
            Ok(())
        }
        Err(status) => Err(status.into()),
    }
}

async fn release_digest(ctx: &mut Ctx, spec: &str) -> Result<Option<(String, String)>> {
    let (product, version) = parse_release_spec(spec)?;
    let id = release_id(product, version);
    let Some(release) = ctx.get(&id).await? else {
        return Ok(None);
    };
    if release.kind != KIND_RELEASE {
        bail!("{id} is not a release");
    }
    let digest = release
        .properties
        .get("digest")
        .cloned()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("release {spec} is missing its manifest digest"))?;
    Ok(Some((id, digest)))
}

async fn environments_running(
    ctx: &mut Ctx,
    recalled: &[RecalledRelease],
) -> Result<Vec<RunningEnvironment>> {
    let environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    let mut running = Vec::new();
    for entry in recalled {
        let (product, version) = parse_release_spec(&entry.release)?;
        let id = release_id(product, version);
        let spec = format!("{product}@{version}");
        for environment in &environments {
            let deployed = environment
                .properties
                .get(&format!("deployed_release.{product}"))
                .map(String::as_str);
            if deployed == Some(id.as_str()) {
                running.push(RunningEnvironment {
                    environment: environment.name.clone(),
                    deployed_release: spec.clone(),
                });
            }
        }
    }
    running.sort_by(|left, right| {
        left.environment
            .cmp(&right.environment)
            .then(left.deployed_release.cmp(&right.deployed_release))
    });
    running.dedup();
    Ok(running)
}

async fn preflight_wave_cohort(ctx: &mut Ctx, spec: &ExecutableWaveSpec) -> Result<()> {
    let fix_id = release_id(&spec.product, &spec.version);
    if ctx
        .get(&crate::ontology::wave_id(&spec.name))
        .await?
        .is_some()
    {
        let loaded = wave::load_wave(ctx, &spec.name).await?;
        if loaded.product != spec.product
            || loaded.version != spec.version
            || loaded.channel != spec.channel
            || loaded.fail_policy != spec.fail_policy
            || loaded
                .environments
                .iter()
                .map(|entry| entry.environment.as_str())
                .ne(spec.environments.iter().map(String::as_str))
        {
            bail!(
                "wave {} already exists with a conflicting identity (cohort, release, channel, or policy changed)",
                spec.name
            );
        }
    }
    let fix_release = ctx.get(&fix_id).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "patched release {}@{} is not published",
            spec.product,
            spec.version
        )
    })?;
    for environment in &spec.environments {
        crate::environment::environment(ctx, environment).await?;
        crate::catalog::require_deployable_trust(ctx, &fix_release, environment).await?;
        let inspect = crate::plan::inspect_environment(ctx, environment).await?;
        let subscription = inspect
            .subscriptions
            .iter()
            .find(|row| row.product == spec.product);
        let Some(subscription) = subscription else {
            bail!(
                "environment {environment} is not subscribed to {}/{}",
                spec.product,
                spec.channel
            );
        };
        if subscription.channel != spec.channel {
            bail!(
                "environment {environment} subscribes {} to {}, wave pins {}",
                spec.product,
                subscription.channel,
                spec.channel
            );
        }
        let lease = crate::apply::inspect_environment_lease(ctx, environment).await?;
        if lease.held {
            bail!(
                "environment {environment} has an active apply lease owned by {}; stale controllers cannot admit wave {}",
                lease.owner.as_deref().unwrap_or("unknown"),
                spec.name
            );
        }
    }
    Ok(())
}

async fn require_replaceable_or_matching_head(
    ctx: &mut Ctx,
    spec: &ExecutableWaveSpec,
    replaceable_heads: &[String],
) -> Result<()> {
    let fix_id = release_id(&spec.product, &spec.version);
    let current = match ctx
        .get(&crate::ontology::channel_id(&spec.product, &spec.channel))
        .await?
    {
        Some(channel) => channel
            .properties
            .get("current_release")
            .cloned()
            .unwrap_or_default(),
        None => String::new(),
    };
    if current.is_empty() || current == fix_id || replaceable_heads.iter().any(|id| id == &current)
    {
        return Ok(());
    }
    bail!(
        "channel {}/{} currently names {current}; refusing to replace it with {fix_id}",
        spec.product,
        spec.channel
    )
}

fn proposal_id(wave_name: &str) -> String {
    format!("tenkai:recall-proposal:{wave_name}")
}

fn proposal_identity(spec: &ExecutableWaveSpec) -> Result<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "product": spec.product,
        "version": spec.version,
        "channel": spec.channel,
        "environments": spec.environments,
        "fail_policy": spec.fail_policy,
    }))?)
}

/// Bind `spec.name` to this proposal before channel or recall writes.
async fn reserve_proposal(ctx: &mut Ctx, spec: &ExecutableWaveSpec) -> Result<()> {
    let id = proposal_id(&spec.name);
    let identity = proposal_identity(spec)?;
    let now = crate::now_millis();
    let proposed = Object {
        id: id.clone(),
        kind: KIND_RECALL_PROPOSAL.into(),
        name: format!("recall-proposal {}", spec.name),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([("identity".into(), identity.clone())]),
        created: now,
        updated: now,
    };
    match ctx.create_once(proposed).await {
        Ok(_) => Ok(()),
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let stored = ctx
                .get(&id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("recall proposal {id} appeared then vanished"))?;
            if stored.kind != KIND_RECALL_PROPOSAL
                || stored.properties.get("identity").map(String::as_str) != Some(identity.as_str())
            {
                bail!(
                    "wave {} already exists with a conflicting identity (cohort, release, channel, or policy changed)",
                    spec.name
                );
            }
            Ok(())
        }
        Err(status) => Err(status.into()),
    }
}

/// Verify `notice` and stamp catalog recalls. Signature, revoked-key, and
/// authorization failures return before any write.
pub async fn import(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    notice: &RecallNotice,
    authorities: &TrustRoots,
) -> Result<ImportReport> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let verified = notice.verify(authorities)?;
    let mut missing = Vec::new();
    for entry in &verified.statement.recalled {
        match release_digest(ctx, &entry.release).await? {
            Some((_, digest)) if digest_hex(&digest) == digest_hex(&entry.digest) => {}
            Some((_, digest)) => bail!(
                "recall notice digest for {} is {}, catalog has {digest}; refusing import",
                entry.release,
                entry.digest
            ),
            None => missing.push(entry.release.clone()),
        }
    }
    persist_notice(ctx, notice, &verified).await?;
    let mut recalled = Vec::new();
    let mut already_recalled = Vec::new();
    for entry in &verified.statement.recalled {
        let (product, version) = parse_release_spec(&entry.release)?;
        let rid = release_id(product, version);
        if missing.iter().any(|spec| spec == &entry.release) {
            crate::catalog::persist_recall_claim(ctx, actor, &rid).await?;
            continue;
        }
        let message = crate::catalog::recall(ctx, actor, &entry.release).await?;
        if message.contains("already recalled") {
            already_recalled.push(entry.release.clone());
        } else {
            recalled.push(entry.release.clone());
        }
    }
    let environments = environments_running(ctx, &verified.statement.recalled).await?;
    Ok(ImportReport {
        advisory_id: verified.statement.advisory_id.clone(),
        recalled,
        already_recalled,
        missing,
        environments,
    })
}

/// Enqueue an imported notice on the optional integration outbox. The
/// payload is the notice as stored, so a consumer can verify it again.
pub fn export_notice(
    store: &impl ProviderEventStore,
    notice: &RecallNotice,
    verified: &VerifiedNotice,
    now: i64,
) -> Result<()> {
    let payload = serde_json::to_string(notice)?;
    let payload_digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
    let event = ProviderEvent {
        id: notice_id(notice)?,
        binding: EvidenceBinding {
            contract_version: PROVIDER_CONTRACT_VERSION,
            release_digest: verified
                .statement
                .recalled
                .first()
                .map(|entry| entry.digest.clone())
                .unwrap_or_else(|| payload_digest.clone()),
            plan_digest: payload_digest.clone(),
            configuration_digest: payload_digest,
            environment_id: "catalog".into(),
        },
        payload_json: payload,
        collected_at_ms: None,
        source_sequence: None,
    };
    enqueue_optional_event(store, RECALL_NOTICE_PROVIDER_KIND, &event, now)
        .map_err(anyhow::Error::from)?;
    Ok(())
}

/// Recall every catalog release that matches `request.exposure`, sign a notice,
/// promote `request.fix`, and admit a stop-on-failure wave. The wave does not
/// apply until an operator supplies plan approval (or the local-development
/// bypass) and runs `wave resume` / `wave execute`.
pub async fn propose(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    request: ProposeRequest,
) -> Result<Proposal> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let advisory = crate::exposure::advisory(ctx, &request.exposure).await?;
    let matched = crate::exposure::match_advisories(ctx).await?;
    let hits: Vec<_> = matched
        .into_iter()
        .filter(|entry| entry.advisory_id == advisory.id)
        .collect();
    if hits.is_empty() {
        bail!(
            "advisory {} matches no published inventory",
            request.exposure
        );
    }
    let (fix_product, fix_version) = parse_release_spec(&request.fix)?;
    if crate::catalog::release_is_recalled(ctx, &release_id(fix_product, fix_version)).await? {
        bail!("patched release {} is recalled", request.fix);
    }
    if hits.iter().any(|hit| hit.release == request.fix) {
        bail!(
            "patched release {} still matches advisory {}",
            request.fix,
            advisory.id
        );
    }
    if !hits
        .iter()
        .any(|hit| hit.release.starts_with(&format!("{fix_product}@")))
    {
        bail!(
            "advisory {} does not match any release of {fix_product}",
            advisory.id
        );
    }
    let fix_release = ctx
        .get(&release_id(fix_product, fix_version))
        .await?
        .ok_or_else(|| anyhow::anyhow!("patched release {} is not published", request.fix))?;
    crate::exposure::require_stored_inventory(&fix_release)?;
    let mut recalled_entries = Vec::new();
    let mut seen = BTreeSet::new();
    for hit in &hits {
        if !seen.insert(hit.release.clone()) {
            continue;
        }
        let Some((_, digest)) = release_digest(ctx, &hit.release).await? else {
            bail!("matched release {} disappeared", hit.release);
        };
        recalled_entries.push(RecalledRelease {
            release: hit.release.clone(),
            digest,
        });
    }
    let spec = ExecutableWaveSpec::new(
        request.wave_name,
        fix_product,
        fix_version,
        request.channel,
        request.environments,
        true,
    )?;
    preflight_wave_cohort(ctx, &spec).await?;
    let reason = format!(
        "advisory {} {} matches {} {}",
        advisory.id,
        advisory.severity.as_str(),
        advisory.component,
        advisory.range
    );
    let statement = RecallNoticeStatement {
        issued_at: crate::now_millis(),
        advisory_id: advisory.id.clone(),
        reason,
        recalled: recalled_entries.clone(),
    };
    let notice = sign(&statement, &crate::signer::open_key(&request.signing_key)?)?;
    if crate::key_revocation::is_revoked(&notice.key_id) {
        bail!("recall notice signer {} is revoked", notice.key_id);
    }
    crate::atomic_state::write_json_verified::<NoticeEnvelope, NoticeEnvelope, _>(
        &request.notice_out,
        &notice,
        |_| Ok(()),
    )
    .with_context(|| format!("writing {}", request.notice_out.display()))?;
    let replaceable_heads: Vec<String> = recalled_entries
        .iter()
        .filter_map(|entry| {
            parse_release_spec(&entry.release)
                .ok()
                .map(|(product, version)| release_id(product, version))
        })
        .collect();
    require_replaceable_or_matching_head(ctx, &spec, &replaceable_heads).await?;
    // First-writer claim on the wave name, before channel or recall writes.
    reserve_proposal(ctx, &spec).await?;
    crate::catalog::promote_over_replaceable_heads(
        ctx,
        actor,
        &request.fix,
        &spec.channel,
        &replaceable_heads,
    )
    .await?;
    let mut recalled = Vec::new();
    for entry in &recalled_entries {
        let message = crate::catalog::recall(ctx, actor, &entry.release).await?;
        if !message.contains("already recalled") {
            recalled.push(entry.release.clone());
        }
    }
    let verified = VerifiedNotice {
        key_id: notice.key_id.clone(),
        statement,
    };
    persist_notice(ctx, &RecallNotice::Current(notice.clone()), &verified).await?;
    let wave = wave::start_or_resume(ctx, &spec).await?;
    let environments = environments_running(ctx, &recalled_entries).await?;
    Ok(Proposal {
        advisory_id: advisory.id,
        recalled,
        notice,
        wave,
        environments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{CatalogReader, PublishOptions};
    use crate::exposure::{
        ADVISORY_FEED_SCHEMA, Advisory, AdvisoryFeed, INVENTORY_SCHEMA, Severity,
    };
    use crate::key_revocation::{self, RevocationStatement, RevokedKey};
    use crate::ontology::release_id;
    use crate::plan;
    use crate::release_signing::TrustedSigner;
    use crate::wave::{WaveAuthorization, WaveEnvironmentStatus, WaveStatus};
    use ed25519_dalek::Signer as _;
    use ed25519_dalek::SigningKey;

    const NOTICE: [u8; 32] = [211; 32];
    const AUTHORITY: [u8; 32] = [213; 32];
    const REVOKED_SIGNER: [u8; 32] = [215; 32];

    fn sample_feed() -> AdvisoryFeed {
        AdvisoryFeed {
            schema: ADVISORY_FEED_SCHEMA.into(),
            generated_at: 1,
            advisories: vec![Advisory {
                id: "TENKAI-2026-1".into(),
                component: "openssl".into(),
                range: ">=1.0.0,<1.2.0".into(),
                severity: Severity::High,
                issued_at: 1,
            }],
        }
    }

    fn native_inventory(name: &str, version: &str) -> String {
        serde_json::json!({
            "schema": INVENTORY_SCHEMA,
            "components": [{"name": name, "version": version}]
        })
        .to_string()
    }

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tenkai-recall-notice-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn seed_file(dir: &Path, seed: &[u8; 32]) -> PathBuf {
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

    fn write_product(root: &Path, version: &str, inventory: &str) -> PathBuf {
        let product = root.join(format!("product-{version}"));
        std::fs::create_dir_all(&product).unwrap();
        std::fs::write(product.join("sbom.json"), inventory).unwrap();
        std::fs::write(
            product.join("suite.json"),
            r#"{"version":1,"suite_id":"recall-suite","cases":["health"]}"#,
        )
        .unwrap();
        std::fs::write(
            product.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "api"
version = "{version}"
kind = "eval_suite"

[eval_suite_product]
document = "suite.json"

[inventory]
document = "sbom.json"
"#
            ),
        )
        .unwrap();
        product
    }

    fn write_bare_product(root: &Path, version: &str) -> PathBuf {
        let product = root.join(format!("product-bare-{version}"));
        std::fs::create_dir_all(&product).unwrap();
        std::fs::write(
            product.join("suite.json"),
            r#"{"version":1,"suite_id":"recall-suite","cases":["health"]}"#,
        )
        .unwrap();
        std::fs::write(
            product.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "api"
version = "{version}"
kind = "eval_suite"

[eval_suite_product]
document = "suite.json"
"#
            ),
        )
        .unwrap();
        product
    }

    async fn signed_publish(ctx: &mut Ctx, root: &Path, version: &str, inventory: &str) {
        let product = write_product(root, version, inventory);
        let keys = root.join("release-keys");
        let signature = root.join(format!("signature-{version}.json"));
        let trust = root.join("release-trust.toml");
        crate::dev_sign::sign_release(&keys, &product.join("tenkai.toml"), &signature, &trust)
            .unwrap();
        crate::catalog::publish(
            ctx,
            &product.join("tenkai.toml"),
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                state_dir: Some(root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    async fn mark_deployed(ctx: &mut Ctx, env: &str, spec: &str) {
        let (product, version) = parse_release_spec(spec).unwrap();
        let mut object = crate::environment::environment(ctx, env).await.unwrap();
        object
            .properties
            .insert(format!("deployed.{product}"), version.into());
        object.properties.insert(
            format!("deployed_release.{product}"),
            release_id(product, version),
        );
        ctx.put(object).await.unwrap();
    }

    fn sample_notice(dir: &Path, spec: &str, digest: &str) -> RecallNotice {
        RecallNotice::Current(
            sign(
                &RecallNoticeStatement {
                    issued_at: 1,
                    advisory_id: "TENKAI-2026-1".into(),
                    reason: "openssl range matches".into(),
                    recalled: vec![RecalledRelease {
                        release: spec.into(),
                        digest: digest.into(),
                    }],
                },
                &crate::signer::FileSigner::open(&seed_file(dir, &NOTICE)).unwrap(),
            )
            .unwrap(),
        )
    }

    /// A notice over `bytes` exactly as given, as a non-Rust signer would make it.
    fn sign_bytes(seed: &[u8; 32], bytes: &[u8]) -> RecallNotice {
        let key = SigningKey::from_bytes(seed);
        let envelope = serde_json::json!({
            "schema": NOTICE_SCHEMA,
            "key_id": crate::signature_verification::key_id(&key.verifying_key().to_bytes()),
            "statement": STANDARD.encode(bytes),
            "signature": STANDARD.encode(key.sign(&[SIGNING_DOMAIN, bytes].concat()).to_bytes()),
        });
        RecallNotice::parse(&serde_json::to_vec(&envelope).unwrap()).unwrap()
    }

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    /// A signer's own bytes verify: any key order and spacing, and fields
    /// this release does not know. The same statement re-encoded no longer
    /// verifies, and the signer's window is checked at the signed `issued_at`.
    #[test]
    fn the_signature_covers_the_statement_bytes_the_signer_sent() {
        let bytes = format!(
            r#"{{ "recalled": [ {{ "digest": "{DIGEST}", "release": "api@1.0.0", "cve": "x" }} ],
            "reason": "openssl", "advisory_id": "TENKAI-2026-1", "issued_at": 5, "note": "y" }}"#
        );
        let authorities = roots(vec![signer(&NOTICE, "recall-authority")]);
        let sent = sign_bytes(&NOTICE, bytes.as_bytes());
        let verified = sent.verify(&authorities).unwrap();
        assert_eq!(verified.statement.issued_at, 5);
        assert_eq!(verified.statement.recalled[0].release, "api@1.0.0");
        assert_eq!(verified.key_id, sent.key_id());

        let RecallNotice::Current(mut reencoded) = sent.clone() else {
            panic!("expected a current notice");
        };
        reencoded.statement = STANDARD.encode(serde_json::to_vec(&verified.statement).unwrap());
        let error = RecallNotice::Current(reencoded)
            .verify(&authorities)
            .unwrap_err()
            .to_string();
        assert!(error.contains("signature does not verify"), "{error}");

        let mut expired = signer(&NOTICE, "recall-authority");
        expired.not_after = Some(4);
        let error = sent.verify(&roots(vec![expired])).unwrap_err().to_string();
        assert!(error.contains("not_after"), "{error}");
    }

    /// Bytes that verify are still validated before anything is imported.
    #[test]
    fn verified_bytes_that_are_not_a_valid_notice_are_refused() {
        let authorities = roots(vec![signer(&NOTICE, "recall-authority")]);
        for (bytes, expected) in [
            ("not json".to_string(), "does not parse"),
            (
                r#"{"issued_at":1,"issued_at":2,"advisory_id":"a","reason":"r","recalled":[]}"#
                    .into(),
                "duplicate field",
            ),
            (
                r#"{"issued_at":1,"advisory_id":"a","reason":"r","recalled":[]}"#.into(),
                "at least one release",
            ),
        ] {
            let error = sign_bytes(&NOTICE, bytes.as_bytes())
                .verify(&authorities)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    /// A notice made before #931 still verifies, keeps the stored JSON and
    /// object id earlier releases gave it, and refuses fields its signature
    /// cannot cover.
    #[test]
    fn a_legacy_v1_notice_verifies_and_keeps_its_stored_identity() {
        let key = SigningKey::from_bytes(&NOTICE);
        let key_id = crate::signature_verification::key_id(&key.verifying_key().to_bytes());
        let statement = legacy::Statement {
            issued_at: 1,
            advisory_id: "TENKAI-2026-1".into(),
            reason: "openssl range matches".into(),
            recalled: vec![legacy::Recalled {
                release: "api@1.0.0".into(),
                digest: DIGEST.into(),
            }],
        };
        let signature = STANDARD.encode(
            key.sign(&legacy_signed_message(&statement).unwrap())
                .to_bytes(),
        );
        // The stored document of an earlier release, byte for byte.
        let stored = format!(
            r#"{{"schema":"tenkai.recall-notice.v1","key_id":"{key_id}","statement":{{"issued_at":1,"advisory_id":"TENKAI-2026-1","reason":"openssl range matches","recalled":[{{"release":"api@1.0.0","digest":"{DIGEST}"}}]}},"signature":"{signature}"}}"#
        );
        let notice = RecallNotice::parse(stored.as_bytes()).unwrap();
        assert_eq!(serde_json::to_string(&notice).unwrap(), stored);
        assert_eq!(
            notice_id(&notice).unwrap(),
            format!(
                "tenkai:recall-notice:{:x}",
                Sha256::digest(stored.as_bytes())
            )
        );
        let authorities = roots(vec![signer(&NOTICE, "recall-authority")]);
        let verified = notice.verify(&authorities).unwrap();
        assert_eq!(verified.statement, RecallNoticeStatement::from(statement));

        let mut document: serde_json::Value = serde_json::from_str(&stored).unwrap();
        document["statement"]["note"] = "unsigned".into();
        let error = RecallNotice::parse(&serde_json::to_vec(&document).unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("envelope is not valid"), "{error}");
    }

    #[test]
    fn an_unknown_schema_is_refused_by_name() {
        let error = RecallNotice::parse(br#"{"schema":"tenkai.recall-notice.v3"}"#)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unsupported recall notice schema") && error.contains(NOTICE_SCHEMA),
            "{error}"
        );
    }

    #[tokio::test]
    async fn import_refuses_plan_before_fix_bundle() {
        let root = temp_root("import-plan");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        let actor = crate::auth_context::test_management_context("notice-import");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "spoke", "isolated")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "spoke", "api", "stable")
            .await
            .unwrap();
        mark_deployed(&mut ctx, "spoke", "api@1.0.0").await;
        let rid = release_id("api", "1.0.0");
        let digest = ctx
            .get(&rid)
            .await
            .unwrap()
            .unwrap()
            .properties
            .get("digest")
            .cloned()
            .unwrap();
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let notice = sample_notice(&keys, "api@1.0.0", &digest);
        let authorities = roots(vec![signer(&NOTICE, "recall-authority")]);
        let report = import(&mut ctx, &actor, &notice, &authorities)
            .await
            .unwrap();
        assert_eq!(report.recalled, vec!["api@1.0.0".to_string()]);
        assert_eq!(report.environments[0].environment, "spoke");
        let denied = plan::compute(&mut ctx, "spoke")
            .await
            .unwrap_err()
            .to_string();
        assert!(denied.contains("recalled"), "{denied}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn bad_signature_and_revoked_key_leave_state_unchanged() {
        let root = temp_root("refuse");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        let actor = crate::auth_context::test_management_context("notice-refuse");
        let rid = release_id("api", "1.0.0");
        let digest = ctx
            .get(&rid)
            .await
            .unwrap()
            .unwrap()
            .properties
            .get("digest")
            .cloned()
            .unwrap();
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let RecallNotice::Current(mut notice) = sample_notice(&keys, "api@1.0.0", &digest) else {
            panic!("expected a current notice");
        };
        let authorities = roots(vec![signer(&NOTICE, "recall-authority")]);
        notice.signature = STANDARD.encode([0u8; 64]);
        let notice = RecallNotice::Current(notice);
        let bad_sig = import(&mut ctx, &actor, &notice, &authorities)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            bad_sig.contains("signature") || bad_sig.contains("verify"),
            "{bad_sig}"
        );
        assert!(
            ctx.get(&crate::ontology::release_recall_id(&rid))
                .await
                .unwrap()
                .is_none()
        );

        let revoked_seed: [u8; 32] = [214; 32];
        let revoked_notice = sign(
            &RecallNoticeStatement {
                issued_at: 1,
                advisory_id: "TENKAI-2026-1".into(),
                reason: "openssl range matches".into(),
                recalled: vec![RecalledRelease {
                    release: "api@1.0.0".into(),
                    digest: digest.clone(),
                }],
            },
            &crate::signer::FileSigner::open(&seed_file(&keys, &revoked_seed)).unwrap(),
        )
        .unwrap();
        seed_file(&keys, &AUTHORITY);
        let revocation_authorities = roots(vec![signer(&AUTHORITY, "revocation-authority")]);
        let list = key_revocation::sign(
            RevocationStatement {
                sequence: 1,
                issued_at: 1,
                revoked: vec![RevokedKey {
                    key_id: revoked_notice.key_id.clone(),
                    reason: "compromised".into(),
                }],
            },
            &crate::signer::FileSigner::open(&keys.join(format!("{}.ed25519", AUTHORITY[0])))
                .unwrap(),
        )
        .unwrap();
        key_revocation::install(
            &list,
            &revocation_authorities,
            &root.join("revocations.json"),
        )
        .unwrap();
        let notice_authorities = roots(vec![signer(&revoked_seed, "revoked-recall")]);
        let revoked = import(
            &mut ctx,
            &actor,
            &RecallNotice::Current(revoked_notice),
            &notice_authorities,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(revoked.contains("revoked"), "{revoked}");
        assert!(
            ctx.get(&crate::ontology::release_recall_id(&rid))
                .await
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn propose_waits_for_approval_and_blocks_recalled_rollback() {
        let root = temp_root("propose");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        signed_publish(
            &mut ctx,
            &root,
            "1.1.0",
            &native_inventory("openssl", "3.0.0"),
        )
        .await;
        let actor = crate::auth_context::test_management_context("notice-propose");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        mark_deployed(&mut ctx, "local", "api@1.0.0").await;
        crate::exposure::import_advisory_feed(&mut ctx, sample_feed(), crate::now_millis())
            .await
            .unwrap();
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let proposal = propose(
            &mut ctx,
            &actor,
            ProposeRequest {
                exposure: "TENKAI-2026-1".into(),
                fix: "api@1.1.0".into(),
                channel: "stable".into(),
                environments: vec!["local".into()],
                wave_name: "recall-TENKAI-2026-1".into(),
                signing_key: seed_file(&keys, &NOTICE),
                notice_out: root.join("notice.json"),
            },
        )
        .await
        .unwrap();
        assert_eq!(proposal.wave.status, WaveStatus::Admitted);
        assert_eq!(proposal.recalled, vec!["api@1.0.0".to_string()]);
        assert!(
            crate::catalog::release_is_recalled(&mut ctx, &release_id("api", "1.0.0"))
                .await
                .unwrap()
        );
        let executed = wave::advance(
            &mut ctx,
            "recall-TENKAI-2026-1",
            WaveAuthorization::LocalDevelopment {
                reason: "remediate e2e",
            },
        )
        .await
        .unwrap();
        assert_eq!(
            executed.status,
            WaveStatus::Succeeded,
            "{:?} {}",
            executed.status,
            executed.environments[0].detail
        );
        assert_eq!(
            executed.environments[0].status,
            WaveEnvironmentStatus::Succeeded
        );
        let rollback = plan::rollback_step(&mut ctx, "local", "api")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            rollback.contains("recalled") && rollback.contains("recovery-reason"),
            "{rollback}"
        );
        let plan_id = executed.environments[0].plan_id.clone().unwrap();
        let replay = wave::start_or_resume(
            &mut ctx,
            &ExecutableWaveSpec::new(
                "recall-TENKAI-2026-1",
                "api",
                "1.1.0",
                "stable",
                ["local".to_string()],
                true,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let again = wave::advance(
            &mut ctx,
            &replay.name,
            WaveAuthorization::LocalDevelopment {
                reason: "remediate e2e",
            },
        )
        .await
        .unwrap();
        assert_eq!(
            again.environments[0].plan_id.as_deref(),
            Some(plan_id.as_str())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn import_without_management_leaves_state_unchanged() {
        let root = temp_root("import-auth");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        let rid = release_id("api", "1.0.0");
        let digest = ctx
            .get(&rid)
            .await
            .unwrap()
            .unwrap()
            .properties
            .get("digest")
            .cloned()
            .unwrap();
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let notice = sample_notice(&keys, "api@1.0.0", &digest);
        let authorities = roots(vec![signer(&NOTICE, "recall-authority")]);
        let actor = crate::auth_context::test_human_context("notice-unauth");
        let denied = import(&mut ctx, &actor, &notice, &authorities)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            denied.contains("management") || denied.contains("capability"),
            "{denied}"
        );
        assert!(
            ctx.get(&notice_id(&notice).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.get(&crate::ontology::release_recall_id(&rid))
                .await
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn import_pending_recall_blocks_later_publish() {
        let root = temp_root("pending-recall");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let actor = crate::auth_context::test_management_context("notice-pending");
        let digest = "ab".repeat(32);
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let notice = sample_notice(&keys, "api@1.0.0", &digest);
        let authorities = roots(vec![signer(&NOTICE, "recall-authority")]);
        let report = import(&mut ctx, &actor, &notice, &authorities)
            .await
            .unwrap();
        assert_eq!(report.missing, vec!["api@1.0.0".to_string()]);
        assert!(
            crate::catalog::release_is_recalled(&mut ctx, &release_id("api", "1.0.0"))
                .await
                .unwrap()
        );
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        let denied = crate::catalog::EmbeddedCatalog::new(&mut ctx)
            .lookup_release(&release_id("api", "1.0.0"), "spoke")
            .await
            .unwrap_err()
            .to_string();
        assert!(denied.contains("recalled"), "{denied}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn propose_validates_before_promote_and_recall() {
        let root = temp_root("propose-preflight");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        signed_publish(
            &mut ctx,
            &root,
            "1.1.0",
            &native_inventory("openssl", "3.0.0"),
        )
        .await;
        let actor = crate::auth_context::test_management_context("notice-preflight");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let signing_key = seed_file(&keys, &NOTICE);
        crate::exposure::import_advisory_feed(&mut ctx, sample_feed(), crate::now_millis())
            .await
            .unwrap();
        let unsubscribed = propose(
            &mut ctx,
            &actor,
            ProposeRequest {
                exposure: "TENKAI-2026-1".into(),
                fix: "api@1.1.0".into(),
                channel: "stable".into(),
                environments: vec!["local".into()],
                wave_name: "recall-TENKAI-2026-1".into(),
                signing_key: signing_key.clone(),
                notice_out: root.join("notice.json"),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(unsubscribed.contains("not subscribed"), "{unsubscribed}");
        plan::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        let missing_key = propose(
            &mut ctx,
            &actor,
            ProposeRequest {
                exposure: "TENKAI-2026-1".into(),
                fix: "api@1.1.0".into(),
                channel: "stable".into(),
                environments: vec!["local".into()],
                wave_name: "recall-TENKAI-2026-1".into(),
                signing_key: root.join("missing.ed25519"),
                notice_out: root.join("notice.json"),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            missing_key.contains("missing.ed25519") || missing_key.contains("signing"),
            "{missing_key}"
        );
        let empty_cohort = propose(
            &mut ctx,
            &actor,
            ProposeRequest {
                exposure: "TENKAI-2026-1".into(),
                fix: "api@1.1.0".into(),
                channel: "stable".into(),
                environments: Vec::new(),
                wave_name: "recall-TENKAI-2026-1".into(),
                signing_key,
                notice_out: root.join("notice.json"),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(empty_cohort.contains("empty"), "{empty_cohort}");
        let channel = ctx
            .get(&crate::ontology::channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            channel
                .properties
                .get("current_release")
                .map(String::as_str),
            Some(release_id("api", "1.0.0").as_str())
        );
        assert!(
            !crate::catalog::release_is_recalled(&mut ctx, &release_id("api", "1.0.0"))
                .await
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn propose_refuses_revoked_signer_before_mutations() {
        let root = temp_root("propose-revoked");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        signed_publish(
            &mut ctx,
            &root,
            "1.1.0",
            &native_inventory("openssl", "3.0.0"),
        )
        .await;
        let actor = crate::auth_context::test_management_context("notice-revoked-propose");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        crate::exposure::import_advisory_feed(&mut ctx, sample_feed(), crate::now_millis())
            .await
            .unwrap();
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let signing_key = seed_file(&keys, &REVOKED_SIGNER);
        seed_file(&keys, &AUTHORITY);
        let revoked_id = crate::signature_verification::key_id(
            &SigningKey::from_bytes(&REVOKED_SIGNER)
                .verifying_key()
                .to_bytes(),
        );
        let list = key_revocation::sign(
            RevocationStatement {
                sequence: 1,
                issued_at: 1,
                revoked: vec![RevokedKey {
                    key_id: revoked_id,
                    reason: "compromised".into(),
                }],
            },
            &crate::signer::FileSigner::open(&keys.join(format!("{}.ed25519", AUTHORITY[0])))
                .unwrap(),
        )
        .unwrap();
        key_revocation::install(
            &list,
            &roots(vec![signer(&AUTHORITY, "revocation-authority")]),
            &root.join("revocations.json"),
        )
        .unwrap();
        let denied = propose(
            &mut ctx,
            &actor,
            ProposeRequest {
                exposure: "TENKAI-2026-1".into(),
                fix: "api@1.1.0".into(),
                channel: "stable".into(),
                environments: vec!["local".into()],
                wave_name: "recall-TENKAI-2026-1".into(),
                signing_key,
                notice_out: root.join("notice.json"),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(denied.contains("revoked"), "{denied}");
        let channel = ctx
            .get(&crate::ontology::channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            channel
                .properties
                .get("current_release")
                .map(String::as_str),
            Some(release_id("api", "1.0.0").as_str())
        );
        assert!(
            !crate::catalog::release_is_recalled(&mut ctx, &release_id("api", "1.0.0"))
                .await
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn propose_refuses_fix_without_inventory() {
        let root = temp_root("propose-no-inventory");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        let product = write_bare_product(&root, "1.1.0");
        let keys = root.join("bare-keys");
        let signature = root.join("signature-bare-1.1.0.json");
        let trust = root.join("bare-trust.toml");
        crate::dev_sign::sign_release(&keys, &product.join("tenkai.toml"), &signature, &trust)
            .unwrap();
        crate::catalog::publish(
            &mut ctx,
            &product.join("tenkai.toml"),
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                state_dir: Some(root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("notice-no-inventory");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        crate::exposure::import_advisory_feed(&mut ctx, sample_feed(), crate::now_millis())
            .await
            .unwrap();
        let notice_keys = root.join("notice-keys");
        std::fs::create_dir_all(&notice_keys).unwrap();
        let denied = propose(
            &mut ctx,
            &actor,
            ProposeRequest {
                exposure: "TENKAI-2026-1".into(),
                fix: "api@1.1.0".into(),
                channel: "stable".into(),
                environments: vec!["local".into()],
                wave_name: "recall-TENKAI-2026-1".into(),
                signing_key: seed_file(&notice_keys, &NOTICE),
                notice_out: root.join("notice.json"),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(denied.contains("inventory"), "{denied}");
        assert!(
            !crate::catalog::release_is_recalled(&mut ctx, &release_id("api", "1.0.0"))
                .await
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn propose_replay_refuses_to_restore_stale_channel() {
        let root = temp_root("propose-stale");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        signed_publish(
            &mut ctx,
            &root,
            "1.1.0",
            &native_inventory("openssl", "3.0.0"),
        )
        .await;
        signed_publish(
            &mut ctx,
            &root,
            "1.2.0",
            &native_inventory("openssl", "3.0.0"),
        )
        .await;
        let actor = crate::auth_context::test_management_context("notice-stale");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        crate::exposure::import_advisory_feed(&mut ctx, sample_feed(), crate::now_millis())
            .await
            .unwrap();
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let signing_key = seed_file(&keys, &NOTICE);
        let request = ProposeRequest {
            exposure: "TENKAI-2026-1".into(),
            fix: "api@1.1.0".into(),
            channel: "stable".into(),
            environments: vec!["local".into()],
            wave_name: "recall-TENKAI-2026-1".into(),
            signing_key: signing_key.clone(),
            notice_out: root.join("notice.json"),
        };
        propose(&mut ctx, &actor, request.clone()).await.unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@1.2.0", "stable")
            .await
            .unwrap();
        let denied = propose(&mut ctx, &actor, request)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            denied.contains("refusing to restore")
                || denied.contains("refusing to replace")
                || denied.contains("already exists"),
            "{denied}"
        );
        let channel = ctx
            .get(&crate::ontology::channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            channel
                .properties
                .get("current_release")
                .map(String::as_str),
            Some(release_id("api", "1.2.0").as_str())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn propose_refuses_to_replace_unrelated_channel_head() {
        let root = temp_root("propose-unrelated-head");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        signed_publish(
            &mut ctx,
            &root,
            "1.1.0",
            &native_inventory("openssl", "3.0.0"),
        )
        .await;
        signed_publish(
            &mut ctx,
            &root,
            "1.2.0",
            &native_inventory("openssl", "3.0.0"),
        )
        .await;
        let actor = crate::auth_context::test_management_context("notice-unrelated");
        crate::catalog::promote(&mut ctx, &actor, "api@1.2.0", "stable")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        crate::exposure::import_advisory_feed(&mut ctx, sample_feed(), crate::now_millis())
            .await
            .unwrap();
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let denied = propose(
            &mut ctx,
            &actor,
            ProposeRequest {
                exposure: "TENKAI-2026-1".into(),
                fix: "api@1.1.0".into(),
                channel: "stable".into(),
                environments: vec!["local".into()],
                wave_name: "recall-TENKAI-2026-1".into(),
                signing_key: seed_file(&keys, &NOTICE),
                notice_out: root.join("notice.json"),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(denied.contains("refusing to replace"), "{denied}");
        let channel = ctx
            .get(&crate::ontology::channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            channel
                .properties
                .get("current_release")
                .map(String::as_str),
            Some(release_id("api", "1.2.0").as_str())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn conflicting_wave_identity_does_not_promote_the_other_channel() {
        let root = temp_root("propose-conflict-wave");
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        signed_publish(
            &mut ctx,
            &root,
            "1.1.0",
            &native_inventory("openssl", "3.0.0"),
        )
        .await;
        let actor = crate::auth_context::test_management_context("notice-conflict-wave");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "beta")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "stable-env", "fixture")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "beta-env", "fixture")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "stable-env", "api", "stable")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "beta-env", "api", "beta")
            .await
            .unwrap();
        crate::exposure::import_advisory_feed(&mut ctx, sample_feed(), crate::now_millis())
            .await
            .unwrap();
        let keys = root.join("notice-keys");
        std::fs::create_dir_all(&keys).unwrap();
        let signing_key = seed_file(&keys, &NOTICE);
        propose(
            &mut ctx,
            &actor,
            ProposeRequest {
                exposure: "TENKAI-2026-1".into(),
                fix: "api@1.1.0".into(),
                channel: "stable".into(),
                environments: vec!["stable-env".into()],
                wave_name: "recall-TENKAI-2026-1".into(),
                signing_key: signing_key.clone(),
                notice_out: root.join("notice-stable.json"),
            },
        )
        .await
        .unwrap();
        let denied = propose(
            &mut ctx,
            &actor,
            ProposeRequest {
                exposure: "TENKAI-2026-1".into(),
                fix: "api@1.1.0".into(),
                channel: "beta".into(),
                environments: vec!["beta-env".into()],
                wave_name: "recall-TENKAI-2026-1".into(),
                signing_key,
                notice_out: root.join("notice-beta.json"),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(denied.contains("conflicting identity"), "{denied}");
        let beta = ctx
            .get(&crate::ontology::channel_id("api", "beta"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            beta.properties.get("current_release").map(String::as_str),
            Some(release_id("api", "1.0.0").as_str())
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
