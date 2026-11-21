//! Small-footprint dark-site spoke profile (#695).
//!
//! One or two SQLite spokes. The active writer holds the environment lease in
//! its own SQLite operational store, and its role is a
//! [`crate::writer_fence::WriterFence`]. A warm standby restores shipped
//! backups (#672); promotion takes over the restored lease, so the new writer
//! runs at the next generation. Applied steps are operational-store receipts
//! stamped with that generation: the store refuses a stale one, and a receipt
//! restored from the backup is not executed again. Site runtimes refuse an
//! older generation, so a demoted spoke that returns cannot act. Promotion is
//! a signed operator action by default. Automatic promotion is refused for two members without a
//! witness vote or an exclusive lock (agent-kit ADR 0001). Deployed workloads
//! keep the last good release while the spoke is down; new plans, applies and
//! rollbacks pause. Product `high_availability` is not claimed.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::VerifyingKey;
use fencing_lease::{Fence, FencingToken, refuse_older, require_auto_promote};
use serde::{Deserialize, Serialize};

use crate::storage::{
    CopyStoreFile, EnvironmentRecord, LeaseRecord, OperationalStore, PlanRecord, PlanStatus,
    ReceiptRecord, StoreBackup,
};
use crate::writer_fence::{WriterFence, WriterRole};

pub const PROFILE_VERSION: u32 = 1;
/// Signed drill evidence. Its signature covers the statement bytes as
/// signed (#953); see `docs/spoke-standby.md#evidence-format`.
pub const DRILL_SCHEMA: &str = "tenkai.spoke-standby-drill.v2";
/// Signed promotion evidence, signed like [`DRILL_SCHEMA`].
pub const PROMOTION_SCHEMA: &str = "tenkai.spoke-standby-promotion.v2";
/// Deprecated (#953): signed over Tenkai's re-encoding of the parsed
/// statement. Verified for evidence written by earlier releases, never
/// produced.
pub const LEGACY_DRILL_SCHEMA: &str = "tenkai.spoke-standby-drill.v1";
/// Deprecated like [`LEGACY_DRILL_SCHEMA`].
pub const LEGACY_PROMOTION_SCHEMA: &str = "tenkai.spoke-standby-promotion.v1";
/// Default writer-lease lifetime. Matches the hub writer lease.
pub const LEASE_TTL: Duration = Duration::from_secs(15);
const DRILL_DOMAIN: &[u8] = b"TENKAI-SPOKE-STANDBY-DRILL-V2\0";
const PROMOTION_DOMAIN: &[u8] = b"TENKAI-SPOKE-STANDBY-PROMOTION-V2\0";
const LEGACY_DRILL_DOMAIN: &[u8] = b"TENKAI-SPOKE-STANDBY-DRILL-V1\0";
const LEGACY_PROMOTION_DOMAIN: &[u8] = b"TENKAI-SPOKE-STANDBY-PROMOTION-V1\0";

/// How a standby becomes the writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionMode {
    Manual,
    Auto,
}

/// Version 1 small-footprint spoke profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpokeStandbyProfile {
    pub version: u32,
    /// One writer, or a writer plus one warm standby. Not a majority.
    pub members: u32,
    /// How often the active spoke ships a backup to the standby.
    pub backup_interval_ms: u64,
    pub promotion: PromotionMode,
    /// Shared lock store every member mounts (file lock, PostgreSQL row, or
    /// Kubernetes Lease). Required together with a witness for `auto`.
    #[serde(default)]
    pub exclusive_lock: bool,
    /// A third-party vote is in hand. The library does not run a witness.
    #[serde(default)]
    pub witness: bool,
}

impl SpokeStandbyProfile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading spoke-standby profile {}", path.display()))?;
        let profile: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing spoke-standby profile {}", path.display()))?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != PROFILE_VERSION {
            bail!("spoke-standby profile version must be {PROFILE_VERSION}");
        }
        if self.members != 1 && self.members != 2 {
            bail!("spoke-standby members must be 1 or 2, got {}", self.members);
        }
        if self.backup_interval_ms == 0 {
            bail!("backup_interval_ms must be greater than zero");
        }
        if self.promotion == PromotionMode::Auto {
            require_auto_promote(self.members, self.exclusive_lock, self.witness)
                .map_err(|err| anyhow::anyhow!("{err}"))?;
        }
        Ok(())
    }

    /// Bound on acknowledged writes that a failover may drop: the last shipped
    /// backup, which is at most one interval old.
    pub fn acknowledged_loss_bound_ms(&self) -> u64 {
        self.backup_interval_ms
    }

    pub fn remaining_spofs(&self) -> Vec<&'static str> {
        if self.members == 1 {
            vec![
                "the single spoke node",
                "the SQLite file",
                "the backup set",
                "the promotion signing key",
            ]
        } else {
            vec![
                "the surviving spoke node",
                "the SQLite file on that node",
                "the backup set",
                "the promotion signing key",
            ]
        }
    }
}

/// What one apply did on a spoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied {
        generation: u64,
    },
    /// A receipt for this step already exists, recorded at `generation`.
    AlreadyApplied {
        generation: u64,
    },
    /// No writer here. Deployed workloads keep the last good release.
    Paused,
}

/// One step a spoke applies, recorded as an operational-store receipt.
#[derive(Debug, Clone)]
pub struct SpokeStep<'a> {
    pub receipt_id: &'a str,
    pub plan_id: &'a str,
    pub step_id: &'a str,
    pub release: &'a str,
}

/// One spoke process over its own SQLite operational store: the writer's
/// live store, or a standby's restored backup.
pub struct SpokeNode {
    holder: String,
    environment: String,
    store: Arc<dyn OperationalStore>,
    files: Arc<dyn StoreBackup>,
    ttl: Duration,
    role: WriterFence,
    /// Site runtimes share one fence so a promoted generation fences the old.
    runtime: Arc<Mutex<Fence>>,
}

impl SpokeNode {
    pub fn new(
        holder: &str,
        environment: &str,
        store: Arc<dyn OperationalStore>,
        files: Arc<dyn StoreBackup>,
        ttl: Duration,
        runtime: Arc<Mutex<Fence>>,
    ) -> Result<Self> {
        if holder.trim().is_empty() || environment.trim().is_empty() {
            bail!("spoke holder and environment must not be empty");
        }
        Ok(Self {
            holder: holder.into(),
            environment: environment.into(),
            store,
            files,
            ttl,
            role: WriterFence::default(),
            runtime,
        })
    }

    pub fn holder(&self) -> &str {
        &self.holder
    }

    pub fn store(&self) -> &dyn OperationalStore {
        &*self.store
    }

    pub fn backup_store(&self, destination: &Path) -> Result<()> {
        self.files.backup(destination)
    }

    pub fn role(&self) -> WriterRole {
        self.role.role()
    }

    /// Generation of the lease recorded in this node's store, 0 when none.
    pub fn recorded_generation(&self) -> Result<u64> {
        Ok(self
            .store
            .current_lease(&self.environment)?
            .map_or(0, |lease| lease.generation))
    }

    /// Become the writer. Fails while another holder's lease is unexpired.
    pub fn acquire(&mut self) -> Result<u64> {
        let requested = Instant::now();
        let lease = self
            .store
            .acquire_lease(&self.environment, &self.holder, self.expires_at())?;
        self.lead(&lease, requested)
    }

    fn expires_at(&self) -> i64 {
        let ttl_ms = i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX);
        crate::now_millis().saturating_add(ttl_ms)
    }

    /// Admit the lease generation to the runtime fence and act as writer
    /// until the lease would lapse.
    fn lead(&mut self, lease: &LeaseRecord, requested: Instant) -> Result<u64> {
        {
            let mut fence = self.runtime.lock().unwrap_or_else(|err| err.into_inner());
            fence
                .admit(FencingToken::from_raw(lease.generation))
                .map_err(|err| anyhow::anyhow!("{err}"))?;
        }
        self.role.set_until(
            WriterRole::Leader {
                holder: self.holder.clone(),
                generation: lease.generation,
            },
            requested + self.ttl,
        );
        Ok(lease.generation)
    }

    /// Signed operator promotion on a restored store: sign, then take over
    /// its expired lease at a generation of at least `min_generation`.
    pub fn promote(&mut self, seed_path: &Path, min_generation: u64) -> Result<SignedPromotion> {
        let evidence = self.prepare_promotion(seed_path, min_generation)?;
        self.commit_promotion(&evidence)?;
        Ok(evidence)
    }

    /// Read-only half of a promotion: refuse a live lease (any holder) and
    /// sign the statement for the next generation. Nothing changes yet.
    pub fn prepare_promotion(
        &self,
        seed_path: &Path,
        min_generation: u64,
    ) -> Result<SignedPromotion> {
        let signer = crate::signer::open_key("the spoke promotion key", seed_path)?;
        let fenced = self.lapsed_generation()?;
        sign(
            PromotionStatement {
                holder: self.holder.clone(),
                fenced_generation: fenced,
                generation: (fenced + 1).max(min_generation),
                at_ms: crate::now_millis(),
            },
            &signer,
        )
    }

    /// Generation of the recorded lease once it has lapsed (0 when none).
    /// A live lease, any holder's, refuses promotion.
    pub fn lapsed_generation(&self) -> Result<u64> {
        let current = self.store.current_lease(&self.environment)?;
        if let Some(lease) = &current
            && lease.expires_at > crate::now_millis()
        {
            bail!(
                "spoke lease for {} is held by {} until {}; promotion waits for it to lapse",
                self.environment,
                lease.owner,
                lease.expires_at
            );
        }
        Ok(current.map_or(0, |lease| lease.generation))
    }

    /// Take over the lease at exactly the signed generation, storing the
    /// signed statement in the same transaction, and lead.
    pub fn commit_promotion(&mut self, evidence: &SignedPromotion) -> Result<()> {
        let requested = Instant::now();
        let lease = self.store.takeover_expired_lease(
            &self.environment,
            &self.holder,
            evidence.statement.generation,
            self.expires_at(),
            &serde_json::to_string(&evidence.evidence)?,
        )?;
        self.lead(&lease, requested)?;
        Ok(())
    }

    /// Apply `step`. Pauses when this process is not the writer. A receipt
    /// already in the (restored) store is not a second execution.
    pub fn apply(&mut self, step: &SpokeStep<'_>) -> Result<ApplyOutcome> {
        let WriterRole::Leader { generation, .. } = self.role.role() else {
            return Ok(ApplyOutcome::Paused);
        };
        self.admit_runtime(generation)?;
        let receipt = ReceiptRecord {
            id: step.receipt_id.into(),
            environment_id: self.environment.clone(),
            plan_id: step.plan_id.into(),
            step_id: step.step_id.into(),
            lease_generation: generation,
            payload_json: serde_json::json!({ "release": step.release }).to_string(),
        };
        if let Some(existing) = self.store.get_receipt(step.receipt_id)? {
            // The same operation at an older generation was already applied;
            // anything else reusing the id is a conflict, not a success.
            if (
                &existing.environment_id,
                &existing.plan_id,
                &existing.step_id,
                &existing.payload_json,
            ) != (
                &receipt.environment_id,
                &receipt.plan_id,
                &receipt.step_id,
                &receipt.payload_json,
            ) {
                bail!(
                    "receipt {} already records a different operation",
                    step.receipt_id
                );
            }
            return Ok(ApplyOutcome::AlreadyApplied {
                generation: existing.lease_generation,
            });
        }
        self.store.record_receipt(&self.holder, &receipt)?;
        Ok(ApplyOutcome::Applied { generation })
    }

    pub fn plan_or_rollback(&self) -> Result<()> {
        if self.role.is_leader() {
            Ok(())
        } else {
            bail!("spoke writer is down; new plans, applies and rollbacks pause")
        }
    }

    /// Kill this process: drop the role without releasing the store lease.
    pub fn kill(&mut self) {
        self.role.set(WriterRole::Standby);
    }

    /// A returning process presenting its old generation to site runtimes.
    pub fn admit_runtime(&self, generation: u64) -> Result<()> {
        let fence = self.runtime.lock().unwrap_or_else(|err| err.into_inner());
        refuse_older(FencingToken::from_raw(generation), fence.highest())
            .map_err(|err| anyhow::anyhow!("{err}"))
    }
}

/// What a promotion signs ([`PROMOTION_SCHEMA`]). A verifier ignores fields
/// it does not know; the signature still covers them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionStatement {
    pub holder: String,
    pub fenced_generation: u64,
    pub generation: u64,
    pub at_ms: i64,
}

/// What a drill signs ([`DRILL_SCHEMA`]). A verifier ignores fields it does
/// not know; the signature still covers them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillStatement {
    pub members: u32,
    pub promotion: PromotionMode,
    pub exclusive_lock: bool,
    pub witness: bool,
    pub passed: bool,
    pub killed: String,
    pub promoted: String,
    pub fenced_generation: u64,
    pub generation: u64,
    pub interruption_window_ms: u64,
    pub acknowledged_loss_bound_ms: u64,
    pub remaining_spofs: Vec<String>,
    pub duplicate_apply: bool,
    pub old_spoke_refused: bool,
    pub workloads_held: bool,
}

/// Signed spoke-standby evidence as stored with the lease takeover and
/// written to disk (#953). Every field is a string, so the stored JSON keeps
/// the signed statement bytes exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// [`PROMOTION_SCHEMA`] or [`DRILL_SCHEMA`].
    pub schema: String,
    /// `sha256:` and the lowercase hex SHA-256 of the signer's Ed25519 public key.
    pub key_id: String,
    /// Standard padded base64 of the statement JSON bytes that were signed.
    pub statement: String,
    /// Standard padded base64 Ed25519 signature over the schema's signing
    /// domain, one NUL byte, and the statement bytes.
    pub signature: String,
}

/// Evidence this process signed, and the statement it signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed<T> {
    pub evidence: Evidence,
    pub statement: T,
}

pub type SignedPromotion = Signed<PromotionStatement>;
pub type SignedDrill = Signed<DrillStatement>;

/// One kind of spoke-standby evidence: its schema and signing domain, and
/// the deprecated v1 it still verifies.
pub trait EvidenceKind: Serialize + serde::de::DeserializeOwned {
    const SCHEMA: &'static str;
    const DOMAIN: &'static [u8];
    const LEGACY_SCHEMA: &'static str;
    const LEGACY_DOMAIN: &'static [u8];
    /// Names the evidence in errors.
    const NAME: &'static str;
    /// The frozen v1 statement, whose re-encoding the v1 signature covers.
    type Legacy: Serialize + serde::de::DeserializeOwned + Into<Self>;
}

impl EvidenceKind for PromotionStatement {
    const SCHEMA: &'static str = PROMOTION_SCHEMA;
    const DOMAIN: &'static [u8] = PROMOTION_DOMAIN;
    const LEGACY_SCHEMA: &'static str = LEGACY_PROMOTION_SCHEMA;
    const LEGACY_DOMAIN: &'static [u8] = LEGACY_PROMOTION_DOMAIN;
    const NAME: &'static str = "spoke-standby promotion";
    type Legacy = legacy::PromotionStatement;
}

impl EvidenceKind for DrillStatement {
    const SCHEMA: &'static str = DRILL_SCHEMA;
    const DOMAIN: &'static [u8] = DRILL_DOMAIN;
    const LEGACY_SCHEMA: &'static str = LEGACY_DRILL_SCHEMA;
    const LEGACY_DOMAIN: &'static [u8] = LEGACY_DRILL_DOMAIN;
    const NAME: &'static str = "spoke-standby drill";
    type Legacy = legacy::DrillStatement;
}

/// Frozen v1 types (#953). The v1 signature covers the serde_json encoding
/// of these statements, so none of them change.
pub mod legacy {
    use serde::{Deserialize, Serialize};

    use super::PromotionMode;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Evidence<S> {
        pub schema: String,
        pub key_id: String,
        pub statement: S,
        pub signature: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PromotionStatement {
        pub holder: String,
        pub fenced_generation: u64,
        pub generation: u64,
        pub at_ms: i64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DrillStatement {
        pub members: u32,
        pub promotion: PromotionMode,
        pub exclusive_lock: bool,
        pub witness: bool,
        pub passed: bool,
        pub killed: String,
        pub promoted: String,
        pub fenced_generation: u64,
        pub generation: u64,
        pub interruption_window_ms: u64,
        pub acknowledged_loss_bound_ms: u64,
        pub remaining_spofs: Vec<String>,
        pub duplicate_apply: bool,
        pub old_spoke_refused: bool,
        pub workloads_held: bool,
    }
}

impl From<legacy::PromotionStatement> for PromotionStatement {
    fn from(legacy: legacy::PromotionStatement) -> Self {
        Self {
            holder: legacy.holder,
            fenced_generation: legacy.fenced_generation,
            generation: legacy.generation,
            at_ms: legacy.at_ms,
        }
    }
}

impl From<legacy::DrillStatement> for DrillStatement {
    fn from(legacy: legacy::DrillStatement) -> Self {
        Self {
            members: legacy.members,
            promotion: legacy.promotion,
            exclusive_lock: legacy.exclusive_lock,
            witness: legacy.witness,
            passed: legacy.passed,
            killed: legacy.killed,
            promoted: legacy.promoted,
            fenced_generation: legacy.fenced_generation,
            generation: legacy.generation,
            interruption_window_ms: legacy.interruption_window_ms,
            acknowledged_loss_bound_ms: legacy.acknowledged_loss_bound_ms,
            remaining_spofs: legacy.remaining_spofs,
            duplicate_apply: legacy.duplicate_apply,
            old_spoke_refused: legacy.old_spoke_refused,
            workloads_held: legacy.workloads_held,
        }
    }
}

/// Serialize `statement` once and sign those bytes.
fn sign<T: EvidenceKind>(statement: T, signer: &crate::signer::KeySigner) -> Result<Signed<T>> {
    let signed = crate::signed_bytes::sign(T::DOMAIN, &statement, |message| {
        Ok(crate::signer::ContentSigner::sign(signer, message)?.to_vec())
    })?;
    Ok(Signed {
        evidence: Evidence {
            schema: T::SCHEMA.into(),
            key_id: crate::signer::ContentSigner::key_id(signer).to_string(),
            statement: signed.statement,
            signature: STANDARD.encode(signed.signature),
        },
        statement,
    })
}

/// Verify stored or written evidence of kind `T` against the signer's
/// public key and return its statement. The evidence is read by `schema`:
/// v2 is parsed only from the bytes its signature covers, the deprecated v1
/// by its frozen re-encoding, and any other schema is refused by name.
pub fn verify_evidence<T: EvidenceKind>(bytes: &[u8], public_key: &[u8; 32]) -> Result<T> {
    #[derive(Deserialize)]
    struct Schema {
        schema: String,
    }
    let name = T::NAME;
    let Schema { schema } = serde_json::from_slice(bytes)
        .with_context(|| format!("{name} evidence is not a JSON object with a schema"))?;
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("{name} public key is invalid"))?;
    let key_id = crate::signature_verification::key_id(public_key);
    let label = format!("{name} signature");
    if schema == T::SCHEMA {
        let evidence: Evidence = serde_json::from_slice(bytes)
            .with_context(|| format!("{name} evidence is not valid"))?;
        anyhow::ensure!(
            evidence.key_id == key_id,
            "{name} key_id does not match the signer"
        );
        let signature =
            crate::signature_verification::decode_exact::<64>(&label, &evidence.signature)?;
        let verified =
            crate::signed_bytes::verify::<T>(T::DOMAIN, &evidence.statement, |message| {
                crate::signature_verification::verify_strict_bytes(
                    &key, &label, &signature, message,
                )
                .is_ok()
            })
            .map_err(|refusal| anyhow::anyhow!("{name} refused: {refusal}"))?;
        Ok(verified.statement)
    } else if schema == T::LEGACY_SCHEMA {
        let evidence: legacy::Evidence<T::Legacy> = serde_json::from_slice(bytes)
            .with_context(|| format!("{name} evidence is not valid"))?;
        anyhow::ensure!(
            evidence.key_id == key_id,
            "{name} key_id does not match the signer"
        );
        let mut message = T::LEGACY_DOMAIN.to_vec();
        serde_json::to_writer(&mut message, &evidence.statement)?;
        crate::signature_verification::verify_strict(&key, &label, &evidence.signature, &message)?;
        Ok(evidence.statement.into())
    } else {
        bail!(
            "unsupported {name} schema {schema:?}; this release verifies {} and the deprecated {}",
            T::SCHEMA,
            T::LEGACY_SCHEMA
        )
    }
}

fn sign_drill(statement: DrillStatement, seed_path: &Path) -> Result<SignedDrill> {
    let signer = crate::signer::open_key("the spoke drill key", seed_path)?;
    sign(statement, &signer)
}

/// Lease lifetime the drill's writer renews to just before it is killed, so
/// the takeover happens quickly. Until then it leads on `LEASE_TTL`, so a
/// slow first apply cannot lapse its leadership.
const DRILL_LEASE_TTL: Duration = Duration::from_millis(500);
/// The drill only asserts that a live lease blocks promotion while at least
/// this much of the writer's lease is left, so a slow disk cannot fail it.
const DRILL_LIVE_MARGIN: Duration = Duration::from_millis(200);
const DRILL_ENVIRONMENT: &str = "site";
const DRILL_PLAN: &str = "spoke-drill-plan";

type OpenPorts = (Arc<dyn OperationalStore>, Arc<dyn StoreBackup>);

fn drill_store(path: &Path, open: &dyn Fn(&Path) -> Result<OpenPorts>) -> Result<OpenPorts> {
    let (store, files) = open(path)?;
    store.put_environment(&EnvironmentRecord {
        id: DRILL_ENVIRONMENT.into(),
        revision: 0,
        configuration_json: "{}".into(),
    })?;
    store.create_plan(&PlanRecord {
        id: DRILL_PLAN.into(),
        environment_id: DRILL_ENVIRONMENT.into(),
        format_version: 1,
        content_digest: "sha256:spoke-drill".into(),
        plan_json: "{}".into(),
        status: PlanStatus::Computed,
        status_detail: String::new(),
    })?;
    Ok((store, files))
}

fn drill_step<'a>(receipt_id: &'a str, release: &'a str) -> SpokeStep<'a> {
    SpokeStep {
        receipt_id,
        plan_id: DRILL_PLAN,
        step_id: receipt_id,
        release,
    }
}

/// Scratch directory for one drill run, removed when the drill ends.
struct DrillDir(std::path::PathBuf);

impl DrillDir {
    fn create() -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "tenkai-spoke-drill-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&path)
            .with_context(|| format!("creating drill directory {}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for DrillDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Two-node drill with egress blocked: kill the writer, restore its shipped
/// backup on the standby, promote it, prove no duplicate apply, and refuse
/// the old generation when it returns.
pub fn drill(
    profile: &SpokeStandbyProfile,
    seed_path: &Path,
    open: impl Fn(&Path) -> Result<OpenPorts>,
    restore: CopyStoreFile,
) -> Result<SignedDrill> {
    drill_after(profile, seed_path, Duration::ZERO, &open, restore)
}

/// The drill, waiting `before_first_apply` between acquiring and the first
/// apply so a test can stand in for a loaded machine.
fn drill_after(
    profile: &SpokeStandbyProfile,
    seed_path: &Path,
    before_first_apply: Duration,
    open: &dyn Fn(&Path) -> Result<OpenPorts>,
    restore: CopyStoreFile,
) -> Result<SignedDrill> {
    profile.validate()?;
    if profile.members != 2 {
        bail!("the spoke-standby drill is the two-node procedure");
    }
    if profile.promotion != PromotionMode::Manual {
        bail!("the two-node drill promotes through a signed operator action");
    }
    let dir = DrillDir::create()?;
    let runtime = Arc::new(Mutex::new(Fence::empty()));
    let (writer_store, writer_files) = drill_store(&dir.0.join("spoke-a.db"), open)?;
    let mut writer = SpokeNode::new(
        "spoke-a",
        DRILL_ENVIRONMENT,
        writer_store,
        writer_files,
        LEASE_TTL,
        Arc::clone(&runtime),
    )?;
    writer.acquire()?;
    std::thread::sleep(before_first_apply);
    match writer.apply(&drill_step("apply-1", "edge@1.0.0"))? {
        ApplyOutcome::Applied { generation: 1 } => {}
        other => bail!("expected first apply at generation 1, got {other:?}"),
    }
    writer.plan_or_rollback()?;
    // Renew the still-live lease (same holder, same generation) to the short
    // drill lifetime; every wait below is timed from this renewal.
    writer.ttl = DRILL_LEASE_TTL;
    let renewed = Instant::now();
    if writer.acquire()? != 1 {
        bail!("renewing the writer's lease must keep generation 1");
    }
    let backup = dir.0.join("shipped.db");
    writer.backup_store(&backup)?;

    // Egress blocked: neither spoke can reach the hub. Workloads hold.
    writer.kill();
    let killed_at = Instant::now();
    let workloads_held = writer.apply(&drill_step("apply-2", "edge@1.1.0"))?
        == ApplyOutcome::Paused
        && writer.store().get_receipt("apply-2")?.is_none();
    if !workloads_held {
        bail!("a killed writer must pause and keep the last good release");
    }
    if writer.plan_or_rollback().is_ok() {
        bail!("plans must pause while the writer is down");
    }

    let restored = dir.0.join("spoke-b.db");
    restore(&backup, &restored)?;
    let (standby_store, standby_files) = open(&restored)?;
    let mut standby = SpokeNode::new(
        "spoke-b",
        DRILL_ENVIRONMENT,
        standby_store,
        standby_files,
        LEASE_TTL,
        Arc::clone(&runtime),
    )?;
    if renewed.elapsed() + DRILL_LIVE_MARGIN < DRILL_LEASE_TTL
        && standby.prepare_promotion(seed_path, 0).is_ok()
    {
        bail!("promotion must wait for the old writer's lease to lapse");
    }
    std::thread::sleep(
        DRILL_LEASE_TTL.saturating_sub(renewed.elapsed()) + Duration::from_millis(20),
    );
    let promotion = standby.promote(seed_path, 0)?;
    let interruption_window_ms = u64::try_from(killed_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    if promotion.statement.fenced_generation != 1 || promotion.statement.generation != 2 {
        bail!(
            "promotion must fence generation 1 and issue 2, got {} -> {}",
            promotion.statement.fenced_generation,
            promotion.statement.generation
        );
    }
    match standby.apply(&drill_step("apply-1", "edge@1.0.0"))? {
        ApplyOutcome::AlreadyApplied { generation: 1 } => {}
        other => bail!("restored receipt must not re-execute apply-1, got {other:?}"),
    }
    match standby.apply(&drill_step("apply-2", "edge@1.1.0"))? {
        ApplyOutcome::Applied { generation: 2 } => {}
        other => bail!("standby apply-2 should run at generation 2, got {other:?}"),
    }

    // The old spoke returns and presents generation 1.
    let old_spoke_refused = writer.admit_runtime(1).is_err();
    if !old_spoke_refused {
        bail!("runtimes must refuse the old spoke generation after promotion");
    }
    writer.admit_runtime(2)?;

    let statement = DrillStatement {
        members: profile.members,
        promotion: profile.promotion,
        exclusive_lock: profile.exclusive_lock,
        witness: profile.witness,
        passed: old_spoke_refused && workloads_held,
        killed: writer.holder().to_string(),
        promoted: standby.holder().to_string(),
        fenced_generation: promotion.statement.fenced_generation,
        generation: promotion.statement.generation,
        interruption_window_ms,
        acknowledged_loss_bound_ms: profile.acknowledged_loss_bound_ms(),
        remaining_spofs: profile
            .remaining_spofs()
            .into_iter()
            .map(str::to_string)
            .collect(),
        duplicate_apply: false,
        old_spoke_refused,
        workloads_held,
    };
    if !statement.passed {
        bail!("spoke-standby drill did not pass");
    }
    sign_drill(statement, seed_path)
}

/// Promotion generations are `epoch << EPOCH_SHIFT` or above: the high bits are the shared lock's fencing token, the low bits
/// count plain takeovers on one restored copy within that epoch.
const EPOCH_SHIFT: u32 = 32;

/// Claim the shared spoke lock and return the generation floor it grants.
/// Every invocation is its own holder, so a live claim by anyone refuses
/// this one, and each new claim gets a strictly higher token. A promotion
/// in a later epoch therefore always fences one in an earlier epoch, even
/// when both start from copies of the same backup or one process stalls.
fn claim_promotion_generation(
    lock_dir: &Path,
    holder: &str,
    recorded: u64,
) -> Result<(SharedClaim, u64)> {
    use fencing_lease::LeaseStore as _;
    let locks = fencing_lease::FileStore::new(lock_dir).map_err(|err| anyhow::anyhow!("{err}"))?;
    let claimant = format!("{holder}:{}:{}", std::process::id(), uuid::Uuid::new_v4());
    let lease = locks
        .acquire(
            &fencing_lease::LeaseName::new("spoke").map_err(|err| anyhow::anyhow!("{err}"))?,
            &fencing_lease::HolderId::new(claimant).map_err(|err| anyhow::anyhow!("{err}"))?,
            LEASE_TTL,
            u64::try_from(crate::now_millis()).unwrap_or_default(),
        )
        .map_err(|err| anyhow::anyhow!("shared spoke lock: {err}"))?;
    let epoch = lease.token.get();
    let floor = epoch
        .checked_shl(EPOCH_SHIFT)
        .filter(|floor| floor >> EPOCH_SHIFT == epoch)
        .context("shared spoke lock token is out of range")?;
    let ceiling = epoch
        .checked_add(1)
        .and_then(|next| next.checked_shl(EPOCH_SHIFT))
        .filter(|ceiling| ceiling >> EPOCH_SHIFT == epoch + 1)
        .unwrap_or(u64::MAX);
    anyhow::ensure!(
        recorded.saturating_add(1) < ceiling,
        "restored spoke store generation {recorded} is past shared lock epoch {epoch}"
    );
    Ok((SharedClaim { locks, lease }, floor.max(recorded + 1)))
}

/// `<store>.promotion.json`, appended to the full file name so the evidence
/// can never alias the store itself.
fn promotion_path(store_path: &Path) -> std::path::PathBuf {
    let mut path = store_path.as_os_str().to_owned();
    path.push(".promotion.json");
    path.into()
}

/// A held claim on the shared spoke lock.
struct SharedClaim {
    locks: fencing_lease::FileStore,
    lease: fencing_lease::Lease,
}

impl SharedClaim {
    /// Fail closed unless this claim is still the live one. Renewing checks
    /// holder and token, so a lapsed or superseded claim is refused.
    fn confirm(&mut self) -> Result<()> {
        use fencing_lease::LeaseStore as _;
        self.lease = self
            .locks
            .renew(
                &self.lease,
                LEASE_TTL,
                u64::try_from(crate::now_millis()).unwrap_or_default(),
            )
            .map_err(|err| anyhow::anyhow!("shared spoke lock lapsed or was superseded: {err}"))?;
        Ok(())
    }

    /// Give the claim up. Its token stays spent, so epochs keep rising.
    fn release(self) {
        use fencing_lease::LeaseStore as _;
        let _ = self.locks.release(&self.lease);
    }
}

/// Promote `holder` on the restored operational store at `store_path` by
/// taking over `environment`'s lease, and write the signed statement next
/// to it. Fails while the old writer's lease is unexpired.
///
/// Each restored copy has its own lease row, and restoring a backup rewinds
/// it, so the lock in `lock_dir` (outside the backup; the same directory for
/// every member, or generations can repeat) serializes promotions and issues
/// each one's epoch. Its fencing token keeps the generation rising across
/// restores and copies, so site runtimes refuse every earlier writer.
pub fn promote_on_disk(
    profile: &SpokeStandbyProfile,
    holder: &str,
    environment: &str,
    store_path: &Path,
    lock_dir: &Path,
    seed_path: &Path,
    open: impl Fn(&Path) -> Result<OpenPorts>,
) -> Result<SignedPromotion> {
    profile.validate()?;
    anyhow::ensure!(
        store_path.is_file(),
        "restored spoke store {} does not exist",
        store_path.display()
    );
    let (store, files) = open(store_path)?;
    let runtime = Arc::new(Mutex::new(Fence::empty()));
    let mut node = SpokeNode::new(holder, environment, store, files, LEASE_TTL, runtime)?;
    // Refuse a live lease before claiming, so a refused attempt does not
    // spend an epoch. A rerun after a crash is refused the same way until
    // the lease lapses, then promotes afresh at a later epoch.
    let recorded = node.lapsed_generation()?;
    let (mut claim, min_generation) = claim_promotion_generation(lock_dir, holder, recorded)?;
    let evidence = node.prepare_promotion(seed_path, min_generation)?;
    // A stalled promotion must not commit, or report success, once a later
    // epoch may have promoted another copy. Runtimes fence it either way:
    // the later epoch's generation is higher.
    claim.confirm()?;
    node.commit_promotion(&evidence)?;
    claim.confirm()?;
    // The claim only orders promotions; site runtimes are the fence. Free it
    // so a rollback can promote again at the next epoch.
    claim.release();
    // The store holds the signed statement with the takeover; this file is
    // a convenience copy.
    write_evidence_verified(&promotion_path(store_path), &evidence.evidence)?;
    Ok(evidence)
}

fn write_evidence_verified(path: &Path, evidence: &Evidence) -> Result<()> {
    crate::atomic_state::write_json_verified::<_, Evidence, _>(path, evidence, |observed| {
        if observed != evidence {
            bail!("spoke-standby promotion post-mutation verification failed");
        }
        Ok(())
    })
}

/// Write a profile next to the example.
pub fn example_profile() -> SpokeStandbyProfile {
    SpokeStandbyProfile {
        version: PROFILE_VERSION,
        members: 2,
        backup_interval_ms: 300_000,
        promotion: PromotionMode::Manual,
        exclusive_lock: false,
        witness: false,
    }
}

pub fn write_evidence(path: &Path, evidence: &Evidence) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let encoded = serde_json::to_vec_pretty(evidence)?;
    std::fs::write(path, encoded)
        .with_context(|| format!("writing spoke-standby drill evidence {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryCatalogGraph;
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    fn open_memory(path: &Path) -> Result<(Arc<dyn OperationalStore>, Arc<dyn StoreBackup>)> {
        MemoryCatalogGraph::open_ports(path)
    }

    fn seeded(path: &Path) -> Result<(Arc<dyn OperationalStore>, Arc<dyn StoreBackup>)> {
        drill_store(path, &open_memory)
    }

    fn node(holder: &str, path: &Path, ttl: Duration, runtime: Arc<Mutex<Fence>>) -> SpokeNode {
        let (store, files) = seeded(path).unwrap();
        SpokeNode::new(holder, "site", store, files, ttl, runtime).unwrap()
    }

    fn tmp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tenkai-spoke-standby-{name}-{}-{}-{}",
            std::process::id(),
            crate::now_millis(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_seed(dir: &Path) -> PathBuf {
        let path = dir.join("seed");
        std::fs::write(&path, [9u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn public_key() -> [u8; 32] {
        SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes()
    }

    fn profile() -> SpokeStandbyProfile {
        example_profile()
    }

    #[test]
    fn auto_promote_two_nodes_without_lock_or_witness_is_refused() {
        let err = SpokeStandbyProfile {
            promotion: PromotionMode::Auto,
            ..profile()
        }
        .validate()
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("automatic promotion refused for 2 members"),
            "{err}"
        );
        SpokeStandbyProfile {
            promotion: PromotionMode::Auto,
            exclusive_lock: true,
            ..profile()
        }
        .validate()
        .unwrap();
        SpokeStandbyProfile {
            promotion: PromotionMode::Auto,
            witness: true,
            ..profile()
        }
        .validate()
        .unwrap();
        SpokeStandbyProfile {
            members: 1,
            promotion: PromotionMode::Auto,
            ..profile()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn two_node_drill_promotes_fences_and_holds_workloads() {
        let root = tmp_root("drill");
        let seed = write_seed(&root);
        let evidence = drill(
            &profile(),
            &seed,
            open_memory,
            MemoryCatalogGraph::copy_store_file,
        )
        .unwrap();
        assert_eq!(
            verify_evidence::<DrillStatement>(
                &serde_json::to_vec(&evidence.evidence).unwrap(),
                &public_key()
            )
            .unwrap(),
            evidence.statement
        );
        let s = &evidence.statement;
        assert!(s.passed);
        assert_eq!(s.killed, "spoke-a");
        assert_eq!(s.promoted, "spoke-b");
        assert_eq!(s.fenced_generation, 1);
        assert_eq!(s.generation, 2);
        assert!(!s.duplicate_apply);
        assert!(s.old_spoke_refused);
        assert!(s.workloads_held);
        assert_eq!(s.acknowledged_loss_bound_ms, 300_000);
        assert!(s.interruption_window_ms > 0);
        assert!(
            s.remaining_spofs
                .iter()
                .any(|item| item.contains("surviving")),
            "{:?}",
            s.remaining_spofs
        );
        assert!(!serde_json::to_string(s).unwrap().contains("available"));
    }

    /// A first apply slower than the drill's short lease still runs as the
    /// writer, and the takeover still waits out the renewed lease.
    #[test]
    fn a_slow_first_apply_does_not_lapse_the_drill_writer() {
        let root = tmp_root("drill-slow");
        let seed = write_seed(&root);
        let evidence = drill_after(
            &profile(),
            &seed,
            DRILL_LEASE_TTL + Duration::from_millis(100),
            &open_memory,
            MemoryCatalogGraph::copy_store_file,
        )
        .unwrap();
        assert_eq!(evidence.statement.fenced_generation, 1);
        assert_eq!(evidence.statement.generation, 2);
        assert!(evidence.statement.passed);
    }

    #[test]
    fn load_rejects_three_members_and_zero_interval() {
        let dir = tmp_root("profile");
        let path = dir.join("profile.toml");
        std::fs::write(
            &path,
            r#"
version = 1
members = 3
backup_interval_ms = 1000
promotion = "manual"
"#,
        )
        .unwrap();
        let err = SpokeStandbyProfile::load(&path).unwrap_err();
        assert!(err.to_string().contains("members must be 1 or 2"), "{err}");
        std::fs::write(
            &path,
            r#"
version = 1
members = 2
backup_interval_ms = 0
promotion = "manual"
"#,
        )
        .unwrap();
        let err = SpokeStandbyProfile::load(&path).unwrap_err();
        assert!(err.to_string().contains("backup_interval_ms"), "{err}");
    }

    #[test]
    fn a_demoted_spoke_cannot_record_a_receipt_after_takeover() {
        let root = tmp_root("takeover");
        let path = root.join("spoke.db");
        let runtime = Arc::new(Mutex::new(Fence::empty()));
        let ttl = DRILL_LEASE_TTL;
        let mut a = node("a", &path, ttl, Arc::clone(&runtime));
        let (store, files) = open_memory(&path).unwrap();
        let mut b = SpokeNode::new("b", "site", store, files, ttl, runtime).unwrap();
        let acquired = Instant::now();
        a.acquire().unwrap();
        if acquired.elapsed() + DRILL_LIVE_MARGIN < ttl {
            assert!(b.acquire().is_err(), "a live lease is not taken over");
        }
        std::thread::sleep(ttl.saturating_sub(acquired.elapsed()) + Duration::from_millis(20));
        assert_eq!(b.acquire().unwrap(), 2);
        // A stalled past its lease: its role lapsed, and a write that slips
        // through with the old generation is refused by the store.
        assert_eq!(
            a.apply(&drill_step("late", "app@2")).unwrap(),
            ApplyOutcome::Paused
        );
        let stale = a.store().record_receipt(
            "a",
            &ReceiptRecord {
                id: "late".into(),
                environment_id: "site".into(),
                plan_id: DRILL_PLAN.into(),
                step_id: "late".into(),
                lease_generation: 1,
                payload_json: "{}".into(),
            },
        );
        assert!(stale.is_err(), "{stale:?}");
        assert!(a.admit_runtime(1).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_reused_receipt_id_for_another_step_is_a_conflict() {
        let root = tmp_root("receipt-id");
        let runtime = Arc::new(Mutex::new(Fence::empty()));
        let mut a = node(
            "a",
            &root.join("spoke.db"),
            Duration::from_secs(60),
            runtime,
        );
        a.acquire().unwrap();
        a.apply(&drill_step("apply-1", "edge@1.0.0")).unwrap();
        assert!(a.apply(&drill_step("apply-1", "edge@9.9.9")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn promote_refuses_the_holders_own_live_lease_and_a_missing_key() {
        let root = tmp_root("own-lease");
        let seed = write_seed(&root);
        let store = root.join("spoke.db");
        let runtime = Arc::new(Mutex::new(Fence::empty()));
        let mut a = node("a", &store, DRILL_LEASE_TTL, runtime);
        let acquired = Instant::now();
        a.acquire().unwrap();
        if acquired.elapsed() + DRILL_LIVE_MARGIN < DRILL_LEASE_TTL {
            assert!(a.promote(&seed, 0).is_err(), "renewal is not a promotion");
        }
        std::thread::sleep(
            DRILL_LEASE_TTL.saturating_sub(acquired.elapsed()) + Duration::from_millis(20),
        );
        assert!(a.promote(&root.join("missing-seed"), 0).is_err());
        assert_eq!(a.recorded_generation().unwrap(), 1, "no key, no takeover");
        assert_eq!(a.promote(&seed, 0).unwrap().statement.generation, 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_later_epoch_outranks_any_takeover_in_an_earlier_one() {
        let root = tmp_root("epoch");
        let locks = root.join("locks");
        std::fs::create_dir_all(&locks).unwrap();
        let (mut claim, first) = claim_promotion_generation(&locks, "spoke-b", 1).unwrap();
        assert_eq!(first, 1 << EPOCH_SHIFT);
        claim.confirm().unwrap();
        assert!(
            claim_promotion_generation(&locks, "spoke-b", 1).is_err(),
            "a live claim refuses even the same holder"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_crash_after_takeover_keeps_the_signed_statement_in_the_store() {
        let root = tmp_root("interrupted");
        let seed = write_seed(&root);
        let restored = root.join("spoke-b.db");
        let mut node = node(
            "spoke-b",
            &restored,
            LEASE_TTL,
            Arc::new(Mutex::new(Fence::empty())),
        );
        // Crash after the takeover committed, before the file was written.
        let evidence = node.prepare_promotion(&seed, 0).unwrap();
        node.commit_promotion(&evidence).unwrap();
        let (owner, stored) = MemoryCatalogGraph::open(&restored)
            .unwrap()
            .lease_takeover("site", evidence.statement.generation)
            .unwrap()
            .unwrap();
        assert_eq!(owner, "spoke-b");
        assert_eq!(
            serde_json::from_str::<Evidence>(&stored).unwrap(),
            evidence.evidence
        );
        let locks = root.join("locks");
        for holder in ["spoke-b", "spoke-c"] {
            let rerun = promote_on_disk(
                &profile(),
                holder,
                "site",
                &restored,
                &locks,
                &seed,
                open_memory,
            );
            assert!(rerun.is_err(), "the live lease refuses {holder}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_expired_promotion_is_not_republished_but_taken_over_again() {
        let root = tmp_root("expired-promotion");
        let seed = write_seed(&root);
        let restored = root.join("spoke-b.db");
        let mut node = node(
            "spoke-b",
            &restored,
            Duration::from_millis(50),
            Arc::new(Mutex::new(Fence::empty())),
        );
        node.promote(&seed, 0).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        let again = promote_on_disk(
            &profile(),
            "spoke-b",
            "site",
            &restored,
            &root.join("locks"),
            &seed,
            open_memory,
        )
        .unwrap();
        assert_eq!(
            (
                again.statement.fenced_generation,
                again.statement.generation
            ),
            (1, 1 << EPOCH_SHIFT)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn evidence_never_aliases_the_store() {
        let store = Path::new("site.promotion.json");
        assert_ne!(promotion_path(store), store);
    }

    #[test]
    fn a_later_copy_promotion_outranks_the_first_so_runtimes_fence_it() {
        let root = tmp_root("exclusive");
        let seed = write_seed(&root);
        let backup = root.join("shipped.db");
        seeded(&backup).unwrap();
        let (b, c) = (root.join("spoke-b.db"), root.join("spoke-c.db"));
        MemoryCatalogGraph::restore(&backup, &b).unwrap();
        MemoryCatalogGraph::restore(&backup, &c).unwrap();
        let profile = SpokeStandbyProfile {
            exclusive_lock: true,
            ..profile()
        };
        let locks = root.join("locks");
        let first =
            promote_on_disk(&profile, "spoke-b", "site", &b, &locks, &seed, open_memory).unwrap();
        let second =
            promote_on_disk(&profile, "spoke-c", "site", &c, &locks, &seed, open_memory).unwrap();
        assert!(second.statement.generation > first.statement.generation);
        let mut runtime = Fence::empty();
        runtime
            .admit(FencingToken::from_raw(second.statement.generation))
            .unwrap();
        assert!(
            runtime
                .admit(FencingToken::from_raw(first.statement.generation))
                .is_err(),
            "the runtime refuses the earlier copy"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn on_disk_promote_takes_over_the_restored_lease_and_rolls_back_cleanly() {
        let root = tmp_root("promote");
        let seed = write_seed(&root);
        let live = root.join("spoke-a.db");
        let runtime = Arc::new(Mutex::new(Fence::empty()));
        let mut writer = node("spoke-a", &live, Duration::from_millis(50), runtime);
        writer.acquire().unwrap();
        writer.apply(&drill_step("apply-1", "edge@1.0.0")).unwrap();
        let backup = root.join("shipped.db");
        MemoryCatalogGraph::open(&live)
            .unwrap()
            .backup(&backup)
            .unwrap();
        writer.kill();

        // Restart: restore the backup and promote once the lease lapsed.
        let restored = root.join("spoke-b.db");
        MemoryCatalogGraph::restore(&backup, &restored).unwrap();
        std::thread::sleep(Duration::from_millis(70));
        let evidence = promote_on_disk(
            &profile(),
            "spoke-b",
            "site",
            &restored,
            &root.join("locks"),
            &seed,
            open_memory,
        )
        .unwrap();
        // The convenience copy verifies to the statement that was signed.
        let written = std::fs::read(promotion_path(&restored)).unwrap();
        assert_eq!(
            verify_evidence::<PromotionStatement>(&written, &public_key()).unwrap(),
            evidence.statement
        );
        assert_eq!(evidence.statement.fenced_generation, 1);
        assert_eq!(evidence.statement.generation, 1 << EPOCH_SHIFT);
        let store = MemoryCatalogGraph::open(&restored).unwrap();
        assert_eq!(
            store.current_lease("site").unwrap().unwrap().owner,
            "spoke-b"
        );
        assert_eq!(
            store
                .get_receipt("apply-1")
                .unwrap()
                .unwrap()
                .lease_generation,
            1
        );
        // Rollback: the untouched backup restores the pre-promotion state.
        let rolled_back = root.join("rolled-back.db");
        MemoryCatalogGraph::restore(&backup, &rolled_back).unwrap();
        assert_eq!(
            MemoryCatalogGraph::open(&rolled_back)
                .unwrap()
                .current_lease("site")
                .unwrap()
                .unwrap()
                .generation,
            1
        );
        // Promoting the rolled-back copy again issues a higher generation.
        let repromoted = promote_on_disk(
            &profile(),
            "spoke-b",
            "site",
            &rolled_back,
            &root.join("locks"),
            &seed,
            open_memory,
        )
        .unwrap();
        assert!(repromoted.statement.generation > evidence.statement.generation);
        // Promoting while the lease is still live is refused.
        let live_err = promote_on_disk(
            &profile(),
            "spoke-c",
            "site",
            &restored,
            &root.join("locks"),
            &seed,
            open_memory,
        );
        assert!(live_err.is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    const PROMOTION_JSON: &str =
        r#"{"holder":"spoke-b","fenced_generation":1,"generation":2,"at_ms":5}"#;

    fn signed(domain: &[u8], bytes: &[u8]) -> String {
        use ed25519_dalek::Signer as _;
        STANDARD.encode(
            SigningKey::from_bytes(&[9u8; 32])
                .sign(&[domain, bytes].concat())
                .to_bytes(),
        )
    }

    /// The signature covers the statement bytes as signed (#953): a field
    /// this release does not know still verifies, the same statement
    /// re-encoded does not, and drill evidence is not a promotion.
    #[test]
    fn evidence_verifies_over_the_statement_bytes_as_signed() {
        let bytes = PROMOTION_JSON.replacen('{', r#"{"note":"newer","#, 1);
        let evidence = Evidence {
            schema: PROMOTION_SCHEMA.into(),
            key_id: crate::signature_verification::key_id(&public_key()),
            statement: STANDARD.encode(&bytes),
            signature: signed(PROMOTION_DOMAIN, bytes.as_bytes()),
        };
        let verify = |evidence: &Evidence| {
            verify_evidence::<PromotionStatement>(
                &serde_json::to_vec(evidence).unwrap(),
                &public_key(),
            )
        };
        let statement = verify(&evidence).unwrap();
        assert_eq!(statement.generation, 2);

        let reencoded = Evidence {
            statement: STANDARD.encode(serde_json::to_vec(&statement).unwrap()),
            ..evidence.clone()
        };
        let error = verify(&reencoded).unwrap_err().to_string();
        assert!(error.contains("signature does not verify"), "{error}");

        let as_drill = Evidence {
            schema: DRILL_SCHEMA.into(),
            ..evidence
        };
        let error = verify(&as_drill).unwrap_err().to_string();
        assert!(
            error.contains("unsupported spoke-standby promotion schema"),
            "{error}"
        );
    }

    /// Evidence written before #953 still verifies by its frozen
    /// re-encoding and refuses fields its signature cannot cover.
    #[test]
    fn legacy_v1_evidence_verifies_and_stays_strict() {
        let statement: legacy::PromotionStatement = serde_json::from_str(PROMOTION_JSON).unwrap();
        let mut stored = serde_json::json!({
            "schema": LEGACY_PROMOTION_SCHEMA,
            "key_id": crate::signature_verification::key_id(&public_key()),
            "statement": statement,
            "signature": signed(LEGACY_PROMOTION_DOMAIN, &serde_json::to_vec(&statement).unwrap()),
        });
        let verify = |stored: &serde_json::Value| {
            verify_evidence::<PromotionStatement>(
                &serde_json::to_vec(stored).unwrap(),
                &public_key(),
            )
        };
        assert_eq!(
            verify(&stored).unwrap(),
            PromotionStatement::from(statement)
        );

        stored["statement"]["note"] = "unsigned".into();
        let error = verify(&stored).unwrap_err().to_string();
        assert!(error.contains("evidence is not valid"), "{error}");
    }
}
