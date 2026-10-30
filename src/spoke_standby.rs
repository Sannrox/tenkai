//! Small-footprint dark-site spoke profile (#695).
//!
//! One or two SQLite spokes. The active writer holds a `fencing-lease`. A warm
//! standby restores shipped backups (#672). Promotion is a signed operator
//! action by default. Automatic promotion is refused for two members without a
//! witness vote or an exclusive lock (agent-kit ADR 0001). Deployed workloads
//! keep the last good release while the spoke is down; new plans, applies and
//! rollbacks pause. Product `high_availability` is not claimed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use fencing_lease::{
    Fence, FencingToken, HolderId, Lease, LeaseName, LeaseStore, MemoryStore, refuse_older,
    require_auto_promote,
};
use serde::{Deserialize, Serialize};

pub const PROFILE_VERSION: u32 = 1;
pub const LEASE_NAME: &str = "spoke";
pub const DRILL_SCHEMA: &str = "tenkai.spoke-standby-drill.v1";
pub const PROMOTION_SCHEMA: &str = "tenkai.spoke-standby-promotion.v1";
pub const STATE_SCHEMA: &str = "tenkai.spoke-standby-state.v1";
pub const STATE_FILE: &str = "spoke-standby.json";
/// Default writer-lease lifetime. Matches the hub writer lease.
pub const LEASE_TTL: Duration = Duration::from_secs(15);
const DRILL_DOMAIN: &[u8] = b"TENKAI-SPOKE-STANDBY-DRILL-V1\0";
const PROMOTION_DOMAIN: &[u8] = b"TENKAI-SPOKE-STANDBY-PROMOTION-V1\0";

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

/// Durable generation and receipts restored onto a standby.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpokeState {
    pub schema: String,
    pub generation: u64,
    pub deployed: Option<String>,
    pub applied: BTreeSet<String>,
    pub receipts: BTreeMap<String, u64>,
}

impl SpokeState {
    pub fn empty() -> Self {
        Self {
            schema: STATE_SCHEMA.into(),
            generation: 0,
            deployed: None,
            applied: BTreeSet::new(),
            receipts: BTreeMap::new(),
        }
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(STATE_FILE);
        if !path.is_file() {
            return Ok(Self::empty());
        }
        let raw = std::fs::read(&path)
            .with_context(|| format!("reading spoke-standby state {}", path.display()))?;
        let state: Self = serde_json::from_slice(&raw)
            .with_context(|| format!("parsing spoke-standby state {}", path.display()))?;
        if state.schema != STATE_SCHEMA {
            bail!("spoke-standby state schema is not {STATE_SCHEMA}");
        }
        Ok(state)
    }

    pub fn store(&self, dir: &Path) -> Result<()> {
        let path = dir.join(STATE_FILE);
        crate::atomic_state::write_json_verified::<_, SpokeState, _>(&path, self, |observed| {
            if observed != self {
                bail!("spoke-standby state post-mutation verification failed");
            }
            Ok(())
        })
    }
}

/// Why a control-plane mutation did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlPlane {
    /// This process holds the writer lease.
    Active { generation: u64 },
    /// No writer here. Deployed workloads keep the last good release.
    Paused { deployed: Option<String> },
}

/// One spoke process: a lease holder or a standby restoring backups.
pub struct SpokeNode<S> {
    holder: HolderId,
    store: Arc<S>,
    lease: Option<Lease>,
    state: SpokeState,
    /// Site runtimes share one fence so a promoted generation fences the old.
    runtime: Arc<std::sync::Mutex<Fence>>,
}

impl<S: LeaseStore> SpokeNode<S> {
    pub fn new(holder: &str, store: Arc<S>, runtime: Arc<std::sync::Mutex<Fence>>) -> Result<Self> {
        Ok(Self {
            holder: HolderId::new(holder).map_err(|err| anyhow::anyhow!("{err}"))?,
            store,
            lease: None,
            state: SpokeState::empty(),
            runtime,
        })
    }

    pub fn holder(&self) -> &str {
        self.holder.as_str()
    }

    pub fn generation(&self) -> u64 {
        self.state.generation
    }

    pub fn deployed(&self) -> Option<&str> {
        self.state.deployed.as_deref()
    }

    pub fn applied(&self) -> &BTreeSet<String> {
        &self.state.applied
    }

    pub fn restore_backup(&mut self, backup: &SpokeState) {
        self.state = backup.clone();
    }

    pub fn snapshot(&self) -> SpokeState {
        self.state.clone()
    }

    fn name() -> Result<LeaseName> {
        LeaseName::new(LEASE_NAME).map_err(|err| anyhow::anyhow!("{err}"))
    }

    /// Become the writer. Fails when another holder still owns an unexpired lease.
    pub fn acquire(&mut self, now_ms: u64) -> Result<Lease> {
        let name = Self::name()?;
        let lease = self
            .store
            .acquire(&name, &self.holder, LEASE_TTL, now_ms)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        self.admit_generation(lease.token.get())?;
        self.lease = Some(lease.clone());
        Ok(lease)
    }

    /// Signed operator promotion: restore from `backup`, then acquire.
    ///
    /// A shared lock store raises the token on takeover. Two local stores
    /// start at 1; the restored generation is then incremented so runtimes
    /// fence the old writer.
    pub fn promote(
        &mut self,
        backup: &SpokeState,
        now_ms: u64,
        seed_path: &Path,
    ) -> Result<PromotionEvidence> {
        self.restore_backup(backup);
        let fenced = self.state.generation;
        let lease = self.acquire(now_ms)?;
        let generation = lease.token.get().max(fenced.saturating_add(1));
        self.admit_generation(generation)?;
        sign_promotion(
            PromotionStatement {
                holder: self.holder.as_str().to_string(),
                fenced_generation: fenced,
                generation,
                at_ms: now_ms as i64,
            },
            seed_path,
        )
    }

    fn admit_generation(&mut self, generation: u64) -> Result<()> {
        let token = FencingToken::from_raw(generation);
        let mut fence = self.runtime.lock().unwrap_or_else(|err| err.into_inner());
        fence.admit(token).map_err(|err| anyhow::anyhow!("{err}"))?;
        self.state.generation = generation;
        Ok(())
    }

    pub fn control_plane(&self, now_ms: u64) -> ControlPlane {
        match &self.lease {
            Some(lease) if !lease.expired(now_ms) => ControlPlane::Active {
                // The admitted generation, which may be higher than a
                // local-store token when two nodes do not share a lock.
                generation: self.state.generation,
            },
            _ => ControlPlane::Paused {
                deployed: self.state.deployed.clone(),
            },
        }
    }

    /// Apply `id` of `release`. Pauses when this process is not the writer.
    /// A receipt already in the restored store is not a second execution.
    pub fn apply(&mut self, id: &str, release: &str, now_ms: u64) -> Result<ApplyOutcome> {
        match self.control_plane(now_ms) {
            ControlPlane::Paused { deployed } => Ok(ApplyOutcome::Paused { deployed }),
            ControlPlane::Active { generation } => {
                self.admit_runtime(generation)?;
                if let Some(&previous) = self.state.receipts.get(id) {
                    return Ok(ApplyOutcome::AlreadyApplied {
                        generation: previous,
                    });
                }
                self.state.applied.insert(id.to_string());
                self.state.receipts.insert(id.to_string(), generation);
                self.state.deployed = Some(release.to_string());
                Ok(ApplyOutcome::Applied { generation })
            }
        }
    }

    pub fn plan_or_rollback(&self, now_ms: u64) -> Result<()> {
        match self.control_plane(now_ms) {
            ControlPlane::Active { .. } => Ok(()),
            ControlPlane::Paused { .. } => {
                bail!("spoke writer is down; new plans, applies and rollbacks pause")
            }
        }
    }

    /// Kill this process: drop the in-memory lease without releasing the store.
    pub fn kill(&mut self) {
        self.lease = None;
    }

    /// A returning process presenting its old generation to site runtimes.
    pub fn admit_runtime(&self, generation: u64) -> Result<()> {
        let fence = self.runtime.lock().unwrap_or_else(|err| err.into_inner());
        refuse_older(FencingToken::from_raw(generation), fence.highest())
            .map_err(|err| anyhow::anyhow!("{err}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied { generation: u64 },
    AlreadyApplied { generation: u64 },
    Paused { deployed: Option<String> },
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
pub struct PromotionEvidence {
    pub schema: String,
    pub key_id: String,
    pub statement: PromotionStatement,
    pub signature: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrillEvidence {
    pub schema: String,
    pub key_id: String,
    pub statement: DrillStatement,
    pub signature: String,
}

fn canonical(domain: &[u8], value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    serde_json::to_writer(&mut bytes, value)?;
    Ok(bytes)
}

fn sign_promotion(statement: PromotionStatement, seed_path: &Path) -> Result<PromotionEvidence> {
    let signing_key = SigningKey::from_bytes(&crate::approval_policy::load_signer_seed(seed_path)?);
    let signature = signing_key.sign(&canonical(PROMOTION_DOMAIN, &statement)?);
    Ok(PromotionEvidence {
        schema: PROMOTION_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&signing_key.verifying_key().to_bytes()),
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

impl PromotionEvidence {
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<()> {
        if self.schema != PROMOTION_SCHEMA {
            bail!("spoke-standby promotion schema is not {PROMOTION_SCHEMA}");
        }
        if self.key_id != crate::signature_verification::key_id(public_key) {
            bail!("spoke-standby promotion key_id does not match the signer");
        }
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| anyhow::anyhow!("spoke-standby promotion public key is invalid"))?;
        crate::signature_verification::verify_strict(
            &key,
            "spoke-standby promotion signature",
            &self.signature,
            &canonical(PROMOTION_DOMAIN, &self.statement)?,
        )
    }
}

impl DrillEvidence {
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<()> {
        if self.schema != DRILL_SCHEMA {
            bail!("spoke-standby drill schema is not {DRILL_SCHEMA}");
        }
        if self.key_id != crate::signature_verification::key_id(public_key) {
            bail!("spoke-standby drill key_id does not match the signer");
        }
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| anyhow::anyhow!("spoke-standby drill public key is invalid"))?;
        crate::signature_verification::verify_strict(
            &key,
            "spoke-standby drill signature",
            &self.signature,
            &canonical(DRILL_DOMAIN, &self.statement)?,
        )
    }
}

fn sign_drill(statement: DrillStatement, seed_path: &Path) -> Result<DrillEvidence> {
    let signing_key = SigningKey::from_bytes(&crate::approval_policy::load_signer_seed(seed_path)?);
    let signature = signing_key.sign(&canonical(DRILL_DOMAIN, &statement)?);
    Ok(DrillEvidence {
        schema: DRILL_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&signing_key.verifying_key().to_bytes()),
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

/// Two-node drill with egress blocked: kill the writer, promote the standby,
/// prove no duplicate apply, and refuse the old generation when it returns.
pub fn drill(profile: &SpokeStandbyProfile, seed_path: &Path) -> Result<DrillEvidence> {
    profile.validate()?;
    if profile.members != 2 {
        bail!("the spoke-standby drill is the two-node procedure");
    }
    if profile.promotion != PromotionMode::Manual {
        bail!("the two-node drill promotes through a signed operator action");
    }

    let writer_store = Arc::new(MemoryStore::new());
    let standby_store = Arc::new(MemoryStore::new());
    let runtime = Arc::new(std::sync::Mutex::new(Fence::empty()));
    let mut writer = SpokeNode::new("spoke-a", writer_store, Arc::clone(&runtime))?;
    let mut standby = SpokeNode::new("spoke-b", standby_store, runtime)?;

    let mut now = 1_000u64;
    writer.acquire(now)?;
    match writer.apply("apply-1", "edge@1.0.0", now)? {
        ApplyOutcome::Applied { generation: 1 } => {}
        other => bail!("expected first apply at generation 1, got {other:?}"),
    }
    writer.plan_or_rollback(now)?;
    let backup = writer.snapshot();
    standby.restore_backup(&backup);

    // Egress blocked: neither spoke can reach the hub. Workloads hold.
    now += 50;
    writer.kill();
    let killed_at = now;
    if !matches!(writer.control_plane(now), ControlPlane::Paused { .. }) {
        bail!("killed writer must pause the control plane");
    }
    let paused = writer.apply("apply-2", "edge@1.1.0", now)?;
    match &paused {
        ApplyOutcome::Paused {
            deployed: Some(release),
        } if release == "edge@1.0.0" => {}
        other => bail!("expected workloads to hold edge@1.0.0, got {other:?}"),
    }
    let workloads_held = matches!(
        paused,
        ApplyOutcome::Paused {
            deployed: Some(ref release)
        } if release == "edge@1.0.0"
    );
    let pause_err = writer.plan_or_rollback(now);
    if pause_err.is_ok() {
        bail!("plans must pause while the writer is down");
    }

    now += 25;
    let promotion = standby.promote(&backup, now, seed_path)?;
    let interruption_window_ms = now.saturating_sub(killed_at);
    if promotion.statement.fenced_generation != 1 || promotion.statement.generation != 2 {
        bail!(
            "promotion must fence generation 1 and issue 2, got {} -> {}",
            promotion.statement.fenced_generation,
            promotion.statement.generation
        );
    }

    match standby.apply("apply-1", "edge@1.0.0", now)? {
        ApplyOutcome::AlreadyApplied { generation: 1 } => {}
        other => bail!("restored receipt must not re-execute apply-1, got {other:?}"),
    }
    match standby.apply("apply-2", "edge@1.1.0", now)? {
        ApplyOutcome::Applied { generation: 2 } => {}
        other => bail!("standby apply-2 should run at generation 2, got {other:?}"),
    }

    // Old spoke returns and presents generation 1.
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

/// Promote `--holder` using the lock files in `lease_dir` and persist state.
pub fn promote_on_disk(
    profile: &SpokeStandbyProfile,
    holder: &str,
    lease_dir: &Path,
    state_dir: &Path,
    seed_path: &Path,
    now_ms: u64,
) -> Result<PromotionEvidence> {
    profile.validate()?;
    if profile.promotion == PromotionMode::Auto {
        require_auto_promote(profile.members, profile.exclusive_lock, profile.witness)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
    }
    let store = fencing_lease::FileStore::new(lease_dir).map_err(|err| anyhow::anyhow!("{err}"))?;
    let runtime = Arc::new(std::sync::Mutex::new(Fence::new(FencingToken::from_raw(
        SpokeState::load(state_dir)?.generation,
    ))));
    let mut node = SpokeNode::new(holder, Arc::new(store), runtime)?;
    node.restore_backup(&SpokeState::load(state_dir)?);
    let evidence = node.promote(&node.snapshot(), now_ms, seed_path)?;
    node.snapshot().store(state_dir)?;
    let promotion_path = state_dir.join("spoke-standby-promotion.json");
    crate::atomic_state::write_json_verified::<_, PromotionEvidence, _>(
        &promotion_path,
        &evidence,
        |observed| {
            if observed != &evidence {
                bail!("spoke-standby promotion post-mutation verification failed");
            }
            Ok(())
        },
    )?;
    Ok(evidence)
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

pub fn write_evidence(path: &Path, evidence: &DrillEvidence) -> Result<()> {
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
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

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
        let evidence = drill(&profile(), &seed).unwrap();
        evidence.verify(&public_key()).unwrap();
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
    fn exclusive_lock_takeover_raises_the_token() {
        let store = Arc::new(MemoryStore::new());
        let runtime = Arc::new(std::sync::Mutex::new(Fence::empty()));
        let mut a = SpokeNode::new("a", Arc::clone(&store), Arc::clone(&runtime)).unwrap();
        let mut b = SpokeNode::new("b", store, runtime).unwrap();
        a.acquire(10).unwrap();
        a.apply("step", "app@1", 10).unwrap();
        a.kill();
        let err = b.acquire(11).unwrap_err();
        assert!(err.to_string().contains("contended"), "{err}");
        b.restore_backup(&a.snapshot());
        let lease = b.acquire(10 + LEASE_TTL.as_millis() as u64 + 1).unwrap();
        assert_eq!(lease.token.get(), 2);
        assert!(a.admit_runtime(1).is_err());
    }

    #[test]
    fn signed_promotion_verifies_and_on_disk_promote_persists() {
        let root = tmp_root("promote");
        let seed = write_seed(&root);
        let lease_dir = root.join("leases");
        let state_dir = root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        SpokeState {
            schema: STATE_SCHEMA.into(),
            generation: 1,
            deployed: Some("edge@1.0.0".into()),
            applied: BTreeSet::from(["apply-1".into()]),
            receipts: BTreeMap::from([("apply-1".into(), 1)]),
        }
        .store(&state_dir)
        .unwrap();
        let evidence =
            promote_on_disk(&profile(), "spoke-b", &lease_dir, &state_dir, &seed, 5_000).unwrap();
        evidence.verify(&public_key()).unwrap();
        assert_eq!(evidence.statement.fenced_generation, 1);
        assert_eq!(evidence.statement.generation, 2);
        let stored = SpokeState::load(&state_dir).unwrap();
        assert_eq!(stored.generation, 2);
        assert_eq!(stored.deployed.as_deref(), Some("edge@1.0.0"));
    }
}
