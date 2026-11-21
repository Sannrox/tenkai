//! [`OperationalStore`] and path-keyed open for [`MemoryCatalogGraph`].

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use super::{CatalogGraph, MemoryCatalogGraph, Partition, enqueue_memory_provider_event};
use crate::change_stream::{ChangeEvent, ChangeEventKind};
use crate::environment::retirement_from_configuration_json;
use crate::grant_rules::{
    GrantRuleStore, GrantRuleWrite, MAX_STORED_RULES, StoredGrantRule, StoredGrantRules, encode,
};
use crate::ontology::env_id;
use crate::runtime_capabilities::sqlite_store_capabilities;
use crate::storage::{
    AuditRecord, ChannelRecord, EnvironmentRecord, LeaseRecord, OfflineImportRecord,
    OfflineStepImportRecord, OperationalStore, PlanRecord, PlanStatus, ProviderEventPosition,
    ProviderEventRecord, ReceiptRecord, ReleaseRecord, Result, RollbackRecord, RollbackStatus,
    RuntimeActivityRecord, RuntimeAttestationRecord, RuntimeClaim, RuntimeCredentialRecord,
    RuntimeEnrollmentRecord, RuntimeRevocation, RuntimeRunnerRecord, RuntimeSealingKeyRecord,
    StoreBackup, StoreError, provider_event_environment_id, provider_event_observed_at,
    provider_event_payloads_match,
};

static STORES: OnceLock<Mutex<BTreeMap<String, MemoryCatalogGraph>>> = OnceLock::new();

fn registry() -> &'static Mutex<BTreeMap<String, MemoryCatalogGraph>> {
    STORES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

impl MemoryCatalogGraph {
    /// Open a path-keyed in-memory store. Reopening the same path returns the
    /// same maps, so tests that drop and reopen a session keep state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.as_os_str() == ":memory:" {
            return Ok(Self::new());
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                StoreError::AdapterUnavailable(format!(
                    "creating embedded state directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        if !path.exists() {
            write_placeholder(path)?;
        }
        let key = path.to_string_lossy().into_owned();
        let mut stores = registry().lock().map_err(|_| StoreError::Poisoned)?;
        Ok(stores.entry(key).or_insert_with(Self::new).clone())
    }

    pub fn open_in_memory() -> Result<Self> {
        Ok(Self::new())
    }

    /// Copy one path-keyed store onto another, including the placeholder file
    /// so callers that inspect the destination as a file see a store header.
    pub fn restore(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> Result<()> {
        let source = source.as_ref();
        let destination = destination.as_ref();
        if source.is_file() {
            crate::storage::sqlite_user_version(source).map_err(|error| {
                StoreError::AdapterUnavailable(format!(
                    "backup {} is not a store: {error}",
                    source.display()
                ))
            })?;
            if let Some(parent) = destination.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|error| {
                    StoreError::AdapterUnavailable(format!(
                        "creating restored store directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
            copy_placeholder(source, destination)?;
        } else {
            write_placeholder(destination)?;
        }
        let source_store = Self::open(source)?;
        let destination_store = Self::open(destination)?;
        *destination_store.store_lock()? = source_store.store_lock()?.clone();
        Ok(())
    }

    /// [`crate::storage::CopyStoreFile`] adapter for in-process tests.
    pub fn copy_store_file(source: &Path, destination: &Path) -> anyhow::Result<()> {
        Self::restore(source, destination).map_err(anyhow::Error::from)
    }

    /// Open one path as both operational and backup ports.
    pub fn open_ports(
        path: impl AsRef<Path>,
    ) -> anyhow::Result<(Arc<dyn OperationalStore>, Arc<dyn StoreBackup>)> {
        let store = Arc::new(Self::open(path)?);
        Ok((
            Arc::clone(&store) as Arc<dyn OperationalStore>,
            store as Arc<dyn StoreBackup>,
        ))
    }

    /// Insert a raw grant-rule row, including ones this release cannot read.
    pub fn put_grant_rule_row(&self, value: &str, row: &str) -> Result<()> {
        self.ops_mut(|partition| {
            partition
                .grant_rules
                .insert(value.to_owned(), row.to_owned());
            partition.grant_rule_generation += 1;
            Ok(())
        })
    }

    pub fn lease_takeover(
        &self,
        environment: &str,
        generation: u64,
    ) -> Result<Option<(String, String)>> {
        self.ops_mut(|partition| {
            Ok(partition
                .lease_takeovers
                .get(&(environment.into(), generation))
                .cloned())
        })
    }

    pub fn inspect_counts(&self) -> Result<(u64, u64, u64)> {
        self.ops_mut(|partition| {
            Ok((
                partition.environments.len() as u64,
                partition.releases.len() as u64,
                partition.plans.len() as u64,
            ))
        })
    }

    /// Set `$.recorded_at` on every claim that has progress (host-applier tests).
    pub fn set_runtime_progress_recorded_at(&self, recorded_at: i64) -> Result<usize> {
        self.ops_mut(|partition| {
            let mut aged = 0;
            for claim in partition.runtime_claims.values_mut() {
                let Some(json) = claim.progress_json.as_mut() else {
                    continue;
                };
                let mut value: serde_json::Value =
                    serde_json::from_str(json).map_err(|error| StoreError::InvalidData {
                        kind: "runtime progress",
                        detail: error.to_string(),
                    })?;
                value["recorded_at"] = recorded_at.into();
                *json = value.to_string();
                aged += 1;
            }
            Ok(aged)
        })
    }

    /// Lapse every runtime claim's expiry (host-applier tests).
    pub fn lapse_runtime_claims(&self, expires_at: i64) -> Result<()> {
        self.ops_mut(|partition| {
            for claim in partition.runtime_claims.values_mut() {
                claim.expires_at = expires_at;
            }
            Ok(())
        })
    }

    pub fn release_namespaced_lease(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> anyhow::Result<crate::pb::sekai::Lease> {
        self.release_lease(None, namespace, key, fencing_token)
    }

    fn store_lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, Partition>>> {
        self.partitions.lock().map_err(|_| StoreError::Poisoned)
    }

    fn ops_mut<T>(&self, f: impl FnOnce(&mut Partition) -> Result<T>) -> Result<T> {
        let mut partitions = self.store_lock()?;
        let partition = partitions.entry(String::new()).or_default();
        f(partition)
    }
}

impl StoreBackup for MemoryCatalogGraph {
    fn backup(&self, destination: &Path) -> anyhow::Result<()> {
        let destination_store = Self::open(destination)?;
        *destination_store.store_lock()? = self.store_lock()?.clone();
        write_placeholder(destination).map_err(anyhow::Error::from)?;
        Ok(())
    }
}

/// 8 KiB SQLite header so `sqlite_user_version` and file-tamper tests work
/// without linking rusqlite into `tenkai`.
const MEMORY_STORE_BYTES: usize = 8192;

fn write_placeholder(path: &Path) -> Result<()> {
    let mut bytes = vec![0_u8; MEMORY_STORE_BYTES];
    bytes[..16].copy_from_slice(b"SQLite format 3\0");
    bytes[60..64].copy_from_slice(&crate::storage::SCHEMA_VERSION.to_be_bytes());
    write_placeholder_bytes(path, &bytes)
}

fn copy_placeholder(source: &Path, destination: &Path) -> Result<()> {
    let bytes = std::fs::read(source).map_err(|error| {
        StoreError::AdapterUnavailable(format!("reading {}: {error}", source.display()))
    })?;
    write_placeholder_bytes(destination, &bytes)
}

/// Write store bytes into `path`. An existing dest keeps its inode and mode
/// so a 0o600 backup created before the copy stays 0o600.
fn write_placeholder_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            StoreError::AdapterUnavailable(format!(
                "creating embedded state directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    if path.exists() {
        std::fs::write(path, bytes).map_err(|error| {
            StoreError::AdapterUnavailable(format!(
                "writing memory store placeholder {}: {error}",
                path.display()
            ))
        })?;
        return Ok(());
    }
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            StoreError::AdapterUnavailable(format!(
                "creating memory store placeholder {}: {error}",
                path.display()
            ))
        })?;
    file.write_all(bytes).map_err(|error| {
        StoreError::AdapterUnavailable(format!(
            "writing memory store placeholder {}: {error}",
            path.display()
        ))
    })?;
    Ok(())
}

fn fixture_kind(partition: &Partition, kind: &str, id: &str) -> bool {
    partition
        .fixture_objects
        .contains_key(&(kind.to_owned(), id.to_owned()))
}

fn environment_key(environment: &str) -> String {
    if environment.starts_with("tenkai:env:") {
        environment.to_owned()
    } else {
        env_id(environment)
    }
}

fn ensure_active(partition: &Partition, environment: &str, operation: &str) -> Result<()> {
    let id = environment_key(environment);
    let configuration = partition
        .environments
        .get(&id)
        .or_else(|| partition.environments.get(environment))
        .map(|environment| environment.configuration_json.as_str());
    if configuration
        .and_then(retirement_from_configuration_json)
        .is_some()
    {
        return Err(StoreError::InvalidData {
            kind: "environment",
            detail: format!("retired environment {environment} cannot accept {operation}"),
        });
    }
    Ok(())
}

fn require_apply_lease(
    partition: &Partition,
    environment: &str,
    owner: &str,
    generation: u64,
    now: i64,
) -> Result<()> {
    let lease = partition
        .apply_leases
        .get(environment)
        .or_else(|| partition.apply_leases.get(&environment_key(environment)))
        .ok_or_else(|| StoreError::StaleLease {
            environment: environment.into(),
            expected: 0,
            actual: generation,
        })?;
    if lease.generation != generation {
        return Err(StoreError::StaleLease {
            environment: environment.into(),
            expected: lease.generation,
            actual: generation,
        });
    }
    if lease.owner != owner {
        return Err(StoreError::LeaseOwnerMismatch {
            environment: environment.into(),
            expected: lease.owner.clone(),
            actual: owner.into(),
        });
    }
    if lease.expires_at <= now {
        return Err(StoreError::LeaseExpired {
            environment: environment.into(),
            generation,
        });
    }
    Ok(())
}

fn event_position(event: &ProviderEventRecord) -> ProviderEventPosition {
    ProviderEventPosition {
        observed_at: provider_event_observed_at(&event.payload_json, event.next_attempt_at),
        provider_kind: event.provider_kind.clone(),
        id: event.id.clone(),
    }
}

fn claimed_undelivered<'a>(
    partition: &'a mut Partition,
    provider_kind: &str,
    id: &str,
    claim_token: &str,
) -> Result<&'a mut ProviderEventRecord> {
    let event = partition
        .events
        .get_mut(&(provider_kind.to_owned(), id.to_owned()))
        .ok_or_else(|| StoreError::NotFound {
            kind: "claimed provider event",
            id: id.into(),
        })?;
    if event.delivered_at.is_some() || event.claim_token.as_deref() != Some(claim_token) {
        return Err(StoreError::NotFound {
            kind: "claimed provider event",
            id: id.into(),
        });
    }
    Ok(event)
}

impl OperationalStore for MemoryCatalogGraph {
    fn publish_release(&self, release: &ReleaseRecord) -> Result<()> {
        self.ops_mut(|partition| {
            if let Some(existing) = partition.releases.get(&release.id) {
                if existing != release {
                    return Err(StoreError::ImmutableConflict {
                        kind: "release",
                        id: release.id.clone(),
                    });
                }
                return Ok(());
            }
            partition
                .releases
                .insert(release.id.clone(), release.clone());
            Ok(())
        })
    }

    fn get_release(&self, id: &str) -> Result<Option<ReleaseRecord>> {
        self.ops_mut(|partition| Ok(partition.releases.get(id).cloned()))
    }

    fn promote_channel(&self, channel: &ChannelRecord) -> Result<ChannelRecord> {
        self.ops_mut(|partition| {
            if fixture_kind(partition, "release", &channel.release_id)
                || fixture_kind(partition, "channel", &channel.id)
            {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture releases and channels cannot be promoted".into(),
                });
            }
            let release = partition.releases.get(&channel.release_id).ok_or_else(|| {
                StoreError::NotFound {
                    kind: "release",
                    id: channel.release_id.clone(),
                }
            })?;
            if release.product != channel.product {
                return Err(StoreError::InvalidData {
                    kind: "channel",
                    detail: format!(
                        "release {} belongs to product {}, not {}",
                        channel.release_id, release.product, channel.product
                    ),
                });
            }
            let next = match partition.channels.get(&channel.id) {
                Some(existing) => {
                    if existing.product != channel.product || existing.name != channel.name {
                        return Err(StoreError::ImmutableConflict {
                            kind: "channel",
                            id: channel.id.clone(),
                        });
                    }
                    if existing.revision != channel.revision {
                        return Err(StoreError::RevisionConflict {
                            kind: "channel",
                            id: channel.id.clone(),
                            expected: channel.revision,
                            actual: existing.revision,
                        });
                    }
                    existing.revision + 1
                }
                None if channel.revision == 0 => 1,
                None => {
                    return Err(StoreError::RevisionConflict {
                        kind: "channel",
                        id: channel.id.clone(),
                        expected: channel.revision,
                        actual: 0,
                    });
                }
            };
            let stored = ChannelRecord {
                revision: next,
                ..channel.clone()
            };
            partition
                .channels
                .insert(channel.id.clone(), stored.clone());
            Ok(stored)
        })
    }

    fn put_environment(&self, environment: &EnvironmentRecord) -> Result<EnvironmentRecord> {
        self.ops_mut(|partition| {
            if fixture_kind(partition, "environment", &environment.id) {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture environments are immutable".into(),
                });
            }
            if partition
                .environments
                .get(&environment.id)
                .is_some_and(|stored| {
                    retirement_from_configuration_json(&stored.configuration_json).is_some()
                })
            {
                return Err(StoreError::InvalidData {
                    kind: "environment",
                    detail: format!(
                        "environment {} is retired; registering it again requires a new environment name",
                        environment.id
                    ),
                });
            }
            if retirement_from_configuration_json(&environment.configuration_json).is_some() {
                let now = crate::now_millis();
                let active_claim = partition.runtime_claims.values().any(|claim| {
                    claim.environment_id == environment.id
                        && claim.expires_at > now
                        && claim.completion_json.is_none()
                });
                let active_apply = partition
                    .apply_leases
                    .get(&environment.id)
                    .is_some_and(|lease| lease.expires_at > now);
                if active_claim || active_apply {
                    return Err(StoreError::InvalidData {
                        kind: "environment",
                        detail: format!(
                            "environment {} has active delivery work",
                            environment.id
                        ),
                    });
                }
            }
            let next = match partition.environments.get(&environment.id) {
                Some(existing) if existing.revision == environment.revision => {
                    existing.revision + 1
                }
                Some(existing) => {
                    return Err(StoreError::RevisionConflict {
                        kind: "environment",
                        id: environment.id.clone(),
                        expected: environment.revision,
                        actual: existing.revision,
                    });
                }
                None if environment.revision == 0 => 1,
                None => {
                    return Err(StoreError::RevisionConflict {
                        kind: "environment",
                        id: environment.id.clone(),
                        expected: environment.revision,
                        actual: 0,
                    });
                }
            };
            let stored = EnvironmentRecord {
                revision: next,
                ..environment.clone()
            };
            partition
                .environments
                .insert(environment.id.clone(), stored.clone());
            Ok(stored)
        })
    }

    fn get_environment(&self, id: &str) -> Result<Option<EnvironmentRecord>> {
        self.ops_mut(|partition| {
            Ok(partition
                .environments
                .get(id)
                .cloned()
                .or_else(|| partition.environments.get(&environment_key(id)).cloned()))
        })
    }

    fn list_environment_ids(&self) -> Result<Vec<String>> {
        self.ops_mut(|partition| {
            let mut ids: Vec<String> = partition.environments.keys().cloned().collect();
            ids.sort();
            Ok(ids)
        })
    }

    fn list_active_environment_ids(&self) -> Result<Vec<String>> {
        self.ops_mut(|partition| {
            let mut ids: Vec<String> = partition
                .environments
                .values()
                .filter(|environment| {
                    retirement_from_configuration_json(&environment.configuration_json).is_none()
                })
                .map(|environment| environment.id.clone())
                .collect();
            ids.sort();
            Ok(ids)
        })
    }

    fn create_plan(&self, plan: &PlanRecord) -> Result<()> {
        self.ops_mut(|partition| {
            ensure_active(partition, &plan.environment_id, "new plans")?;
            if fixture_kind(partition, "environment", &plan.environment_id) {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture environments cannot accept executable plans".into(),
                });
            }
            if let Some(existing) = partition.plans.get(&plan.id) {
                if existing.environment_id != plan.environment_id
                    || existing.format_version != plan.format_version
                    || existing.content_digest != plan.content_digest
                    || existing.plan_json != plan.plan_json
                {
                    return Err(StoreError::ImmutableConflict {
                        kind: "plan",
                        id: plan.id.clone(),
                    });
                }
                return Ok(());
            }
            if plan.status != PlanStatus::Computed {
                return Err(StoreError::InvalidPlanTransition {
                    id: plan.id.clone(),
                    from: PlanStatus::Computed,
                    to: plan.status,
                });
            }
            partition.plans.insert(plan.id.clone(), plan.clone());
            Ok(())
        })
    }

    fn get_plan(&self, id: &str) -> Result<Option<PlanRecord>> {
        self.ops_mut(|partition| Ok(partition.plans.get(id).cloned()))
    }

    fn transition_plan(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord> {
        self.ops_mut(|partition| {
            if fixture_kind(partition, "plan", id) {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture plans are non-executable".into(),
                });
            }
            let current = partition
                .plans
                .get(id)
                .cloned()
                .ok_or_else(|| StoreError::NotFound {
                    kind: "plan",
                    id: id.into(),
                })?;
            require_apply_lease(
                partition,
                &current.environment_id,
                owner,
                generation,
                crate::now_millis(),
            )?;
            if !current.status.allows(status) {
                return Err(StoreError::InvalidPlanTransition {
                    id: id.into(),
                    from: current.status,
                    to: status,
                });
            }
            let mut stored = current;
            stored.status = status;
            stored.status_detail = detail.into();
            partition.plans.insert(id.into(), stored.clone());
            Ok(stored)
        })
    }

    fn acquire_lease(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<LeaseRecord> {
        self.grant_lease(environment, owner, expires_at, None)
    }

    fn current_lease(&self, environment: &str) -> Result<Option<LeaseRecord>> {
        self.ops_mut(|partition| {
            Ok(partition
                .apply_leases
                .get(environment)
                .cloned()
                .or_else(|| {
                    partition
                        .apply_leases
                        .get(&environment_key(environment))
                        .cloned()
                }))
        })
    }

    fn takeover_expired_lease(
        &self,
        environment: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
        evidence_json: &str,
    ) -> Result<LeaseRecord> {
        self.grant_lease(
            environment,
            owner,
            expires_at,
            Some((generation, evidence_json)),
        )
    }

    fn record_receipt(&self, owner: &str, receipt: &ReceiptRecord) -> Result<()> {
        self.ops_mut(|partition| {
            if let Some(existing) = partition.receipts.get(&receipt.id) {
                if existing != receipt {
                    return Err(StoreError::ImmutableConflict {
                        kind: "receipt",
                        id: receipt.id.clone(),
                    });
                }
                return Ok(());
            }
            let plan =
                partition
                    .plans
                    .get(&receipt.plan_id)
                    .ok_or_else(|| StoreError::NotFound {
                        kind: "plan",
                        id: receipt.plan_id.clone(),
                    })?;
            if plan.environment_id != receipt.environment_id {
                return Err(StoreError::EnvironmentMismatch {
                    kind: "receipt",
                    id: receipt.id.clone(),
                    expected: plan.environment_id.clone(),
                    actual: receipt.environment_id.clone(),
                });
            }
            require_apply_lease(
                partition,
                &receipt.environment_id,
                owner,
                receipt.lease_generation,
                crate::now_millis(),
            )?;
            partition
                .receipts
                .insert(receipt.id.clone(), receipt.clone());
            Ok(())
        })
    }

    fn get_receipt(&self, id: &str) -> Result<Option<ReceiptRecord>> {
        self.ops_mut(|partition| Ok(partition.receipts.get(id).cloned()))
    }

    fn record_offline_import(
        &self,
        receipt: &OfflineImportRecord,
        steps: &[OfflineStepImportRecord],
    ) -> Result<()> {
        self.ops_mut(|partition| {
            if let Some(existing) = partition.offline_imports.get(&receipt.bundle_digest) {
                if existing != receipt {
                    return Err(StoreError::ImmutableConflict {
                        kind: "offline import",
                        id: receipt.bundle_digest.clone(),
                    });
                }
                return Ok(());
            }
            partition
                .offline_imports
                .insert(receipt.bundle_digest.clone(), receipt.clone());
            partition.offline_steps.extend(steps.iter().cloned());
            Ok(())
        })
    }

    fn get_offline_import(&self, bundle_digest: &str) -> Result<Option<OfflineImportRecord>> {
        self.ops_mut(|partition| Ok(partition.offline_imports.get(bundle_digest).cloned()))
    }

    fn create_rollback(&self, owner: &str, rollback: &RollbackRecord) -> Result<()> {
        self.ops_mut(|partition| {
            ensure_active(partition, &rollback.environment_id, "new rollbacks")?;
            if let Some(existing) = partition.rollbacks.get(&rollback.id) {
                if existing != rollback {
                    return Err(StoreError::ImmutableConflict {
                        kind: "rollback",
                        id: rollback.id.clone(),
                    });
                }
                return Ok(());
            }
            require_apply_lease(
                partition,
                &rollback.environment_id,
                owner,
                rollback.lease_generation,
                crate::now_millis(),
            )?;
            if rollback.status != RollbackStatus::Pending {
                return Err(StoreError::InvalidRollbackTransition {
                    id: rollback.id.clone(),
                    from: RollbackStatus::Pending,
                    to: rollback.status,
                });
            }
            partition
                .rollbacks
                .insert(rollback.id.clone(), rollback.clone());
            Ok(())
        })
    }

    fn transition_rollback(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: RollbackStatus,
        checkpoint_json: &str,
        detail: &str,
    ) -> Result<RollbackRecord> {
        self.ops_mut(|partition| {
            let current =
                partition
                    .rollbacks
                    .get(id)
                    .cloned()
                    .ok_or_else(|| StoreError::NotFound {
                        kind: "rollback",
                        id: id.into(),
                    })?;
            require_apply_lease(
                partition,
                &current.environment_id,
                owner,
                generation,
                crate::now_millis(),
            )?;
            if !current.status.allows(status) {
                return Err(StoreError::InvalidRollbackTransition {
                    id: id.into(),
                    from: current.status,
                    to: status,
                });
            }
            let mut stored = current;
            stored.status = status;
            stored.checkpoint_json = checkpoint_json.into();
            stored.status_detail = detail.into();
            partition.rollbacks.insert(id.into(), stored.clone());
            Ok(stored)
        })
    }

    fn pending_rollbacks(&self) -> Result<Vec<RollbackRecord>> {
        self.ops_mut(|partition| {
            Ok(partition
                .rollbacks
                .values()
                .filter(|rollback| rollback.status == RollbackStatus::Pending)
                .cloned()
                .collect())
        })
    }

    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> Result<()> {
        self.ops_mut(|partition| {
            enqueue_memory_provider_event(partition, event).map_err(|error| {
                error
                    .downcast::<StoreError>()
                    .unwrap_or_else(|error| StoreError::Database(error.to_string()))
            })
        })
    }

    fn list_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.ops_mut(|partition| {
            let mut events: Vec<_> = partition
                .events
                .values()
                .filter(|event| {
                    event.provider_kind == provider_kind
                        && provider_event_environment_id(&event.payload_json).as_deref()
                            == Some(environment_id)
                })
                .cloned()
                .collect();
            events.sort_by_key(|event| std::cmp::Reverse(event_position(event)));
            events.truncate(limit);
            Ok(events)
        })
    }

    fn list_provider_events_after(
        &self,
        provider_kind: &str,
        environment_id: &str,
        after: Option<&ProviderEventPosition>,
        limit: usize,
    ) -> Result<Vec<(ProviderEventPosition, ProviderEventRecord)>> {
        self.ops_mut(|partition| {
            let mut events: Vec<_> = partition
                .events
                .values()
                .filter(|event| {
                    event.provider_kind == provider_kind
                        && provider_event_environment_id(&event.payload_json).as_deref()
                            == Some(environment_id)
                })
                .map(|event| (event_position(event), event.clone()))
                .collect();
            events.sort_by(|left, right| right.0.cmp(&left.0));
            if let Some(after) = after {
                events.retain(|(position, _)| position < after);
            }
            events.truncate(limit);
            Ok(events)
        })
    }

    fn list_failing_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.ops_mut(|partition| {
            let mut events: Vec<_> = partition
                .events
                .values()
                .filter(|event| {
                    event.provider_kind == provider_kind
                        && event.delivered_at.is_none()
                        && event.attempts > 0
                        && provider_event_environment_id(&event.payload_json).as_deref()
                            == Some(environment_id)
                })
                .cloned()
                .collect();
            events.sort_by(|left, right| {
                right
                    .attempts
                    .cmp(&left.attempts)
                    .then_with(|| left.id.cmp(&right.id))
            });
            events.truncate(limit);
            Ok(events)
        })
    }

    fn claim_provider_events(
        &self,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.claim_events(None, now, limit, claim_token, claim_until)
    }

    fn claim_provider_events_for_kind(
        &self,
        provider_kind: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.claim_events(Some(provider_kind), now, limit, claim_token, claim_until)
    }

    fn require_claimed_undelivered_provider_event(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
    ) -> Result<()> {
        self.ops_mut(|partition| {
            claimed_undelivered(partition, provider_kind, id, claim_token).map(|_| ())
        })
    }

    fn reserve_provider_event_sequence(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
    ) -> Result<i64> {
        self.ops_mut(|partition| {
            claimed_undelivered(partition, provider_kind, id, claim_token)?;
            let next = partition
                .producer_sequences
                .entry(provider_kind.to_owned())
                .or_insert(0);
            *next += 1;
            Ok(*next)
        })
    }

    fn bind_provider_event_collection_time(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        payload_json: &str,
    ) -> Result<()> {
        self.ops_mut(|partition| {
            let event = claimed_undelivered(partition, provider_kind, id, claim_token)?;
            if !provider_event_payloads_match(&event.payload_json, payload_json) {
                return Err(StoreError::ImmutableConflict {
                    kind: "provider event",
                    id: id.into(),
                });
            }
            event.payload_json = payload_json.into();
            Ok(())
        })
    }

    fn record_provider_failure(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        next_attempt_at: i64,
        error: &str,
    ) -> Result<()> {
        self.ops_mut(|partition| {
            let event = claimed_undelivered(partition, provider_kind, id, claim_token)?;
            event.attempts = event.attempts.saturating_add(1);
            event.next_attempt_at = next_attempt_at;
            event.last_error = error.into();
            event.claim_token = None;
            event.claim_until = None;
            Ok(())
        })
    }

    fn mark_provider_event_delivered(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> Result<()> {
        self.ops_mut(|partition| {
            let event = claimed_undelivered(partition, provider_kind, id, claim_token)?;
            event.delivered_at = Some(delivered_at);
            event.claim_token = None;
            event.claim_until = None;
            Ok(())
        })
    }

    fn append_audit(&self, event: &AuditRecord) -> Result<()> {
        self.ops_mut(|partition| {
            partition.audit.push(event.clone());
            Ok(())
        })
    }

    fn audit_events(&self) -> Result<Vec<AuditRecord>> {
        self.ops_mut(|partition| Ok(partition.audit.clone()))
    }

    fn audit_events_after(&self, cursor: i64, limit: usize) -> Result<Vec<(i64, AuditRecord)>> {
        self.ops_mut(|partition| {
            let start = usize::try_from(cursor.max(0)).unwrap_or(0);
            Ok(partition
                .audit
                .iter()
                .enumerate()
                .skip(start)
                .take(limit)
                .map(|(index, event)| ((index + 1) as i64, event.clone()))
                .collect())
        })
    }

    fn append_change_event(
        &self,
        occurred_at: i64,
        kind: &str,
        resource: &str,
        environment_id: &str,
    ) -> Result<ChangeEvent> {
        self.ops_mut(|partition| {
            let kind = ChangeEventKind::parse(kind).map_err(|error| StoreError::InvalidData {
                kind: "change event",
                detail: error.to_string(),
            })?;
            if resource.is_empty() {
                return Err(StoreError::InvalidData {
                    kind: "change event",
                    detail: "resource must be non-empty".into(),
                });
            }
            partition.change_seq += 1;
            let event = ChangeEvent::new(
                partition.change_seq,
                occurred_at,
                kind,
                resource,
                environment_id,
            );
            partition.change_events.push(event.clone());
            Ok(event)
        })
    }

    fn append_change_event_once(
        &self,
        occurred_at: i64,
        kind: ChangeEventKind,
        resource: &str,
        since: i64,
        only_after_another: bool,
    ) -> Result<Option<ChangeEvent>> {
        self.ops_mut(|partition| {
            if resource.is_empty() {
                return Err(StoreError::InvalidData {
                    kind: "change event",
                    detail: "resource must be non-empty".into(),
                });
            }
            let latest = partition
                .change_events
                .iter()
                .rev()
                .find(|event| event.kind == kind);
            if let Some(latest) = latest
                && latest.resource == resource
                && latest.occurred_at >= since
            {
                return Ok(None);
            }
            if only_after_another && latest.is_none() {
                return Ok(None);
            }
            partition.change_seq += 1;
            let event = ChangeEvent::new(partition.change_seq, occurred_at, kind, resource, "");
            partition.change_events.push(event.clone());
            Ok(Some(event))
        })
    }

    fn list_change_events_after(&self, cursor: i64, limit: usize) -> Result<Vec<ChangeEvent>> {
        self.ops_mut(|partition| {
            Ok(partition
                .change_events
                .iter()
                .filter(|event| {
                    event
                        .cursor
                        .parse::<i64>()
                        .ok()
                        .is_some_and(|seq| seq > cursor)
                })
                .take(limit)
                .cloned()
                .collect())
        })
    }

    fn check_health(&self) -> Result<()> {
        self.store_lock().map(|_| ())
    }

    fn runtime_capabilities(&self) -> crate::runtime_capabilities::ComponentCapabilities {
        sqlite_store_capabilities()
    }

    fn import_development_fixture(
        &self,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureMap> {
        self.ops_mut(|partition| {
            let existing: Vec<_> = partition
                .fixture_objects
                .iter()
                .filter(|(_, (fixture_id, _, _))| fixture_id == &fixture.map.fixture_id)
                .collect();
            let expected = fixture.releases.len()
                + fixture.channels.len()
                + fixture.environments.len()
                + fixture.plans.len();
            if !existing.is_empty() {
                let digest = existing[0].1.1.clone();
                if existing.len() != expected || digest != fixture.map.fixture_digest {
                    return Err(StoreError::ImmutableConflict {
                        kind: "development_fixture",
                        id: fixture.map.fixture_id.clone(),
                    });
                }
                return Ok(fixture.map.clone());
            }
            for release in &fixture.releases {
                partition
                    .releases
                    .insert(release.id.clone(), release.clone());
            }
            for channel in &fixture.channels {
                partition
                    .channels
                    .insert(channel.id.clone(), channel.clone());
            }
            for environment in &fixture.environments {
                partition
                    .environments
                    .insert(environment.id.clone(), environment.clone());
            }
            for plan in &fixture.plans {
                let mut stored = plan.clone();
                stored.status = PlanStatus::Blocked;
                partition.plans.insert(plan.id.clone(), stored);
            }
            for (kind, ids) in [
                ("release", &fixture.map.releases),
                ("channel", &fixture.map.channels),
                ("environment", &fixture.map.environments),
                ("plan", &fixture.map.plans),
            ] {
                for (order, id) in ids.iter().enumerate() {
                    partition.fixture_objects.insert(
                        (kind.into(), id.clone()),
                        (
                            fixture.map.fixture_id.clone(),
                            fixture.map.fixture_digest.clone(),
                            order as i64,
                        ),
                    );
                }
            }
            partition.audit.push(AuditRecord {
                id: request_id.into(),
                occurred_at: crate::now_millis(),
                principal: actor.into(),
                operation: "development_fixture.imported".into(),
                resource: fixture.map.fixture_digest.clone(),
                outcome: "imported".into(),
            });
            Ok(fixture.map.clone())
        })
    }

    fn reset_development_fixture(
        &self,
        fixture_id: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureResetResult> {
        self.ops_mut(|partition| {
            let env_ids: Vec<String> = partition
                .fixture_objects
                .iter()
                .filter(|((kind, _), (id, _, _))| kind == "environment" && id == fixture_id)
                .map(|((_, object_id), _)| object_id.clone())
                .collect();
            let plan_ids: Vec<String> = partition
                .fixture_objects
                .iter()
                .filter(|((kind, _), (id, _, _))| kind == "plan" && id == fixture_id)
                .map(|((_, object_id), _)| object_id.clone())
                .collect();
            let dependent = partition.apply_leases.keys().any(|id| env_ids.contains(id))
                || partition.receipts.values().any(|receipt| {
                    env_ids.contains(&receipt.environment_id) || plan_ids.contains(&receipt.plan_id)
                })
                || partition.rollbacks.values().any(|rollback| {
                    env_ids.contains(&rollback.environment_id)
                        || plan_ids.contains(&rollback.plan_id)
                })
                || partition.offline_imports.values().any(|receipt| {
                    env_ids.contains(&receipt.environment_id) || plan_ids.contains(&receipt.plan_id)
                })
                || partition.runtime_claims.values().any(|claim| {
                    env_ids.contains(&claim.environment_id) || plan_ids.contains(&claim.plan_id)
                });
            if dependent {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture reset refused because operational state depends on it".into(),
                });
            }
            let mut removed = 0_usize;
            for ((kind, object_id), (id, _, _)) in partition.fixture_objects.clone() {
                if id != fixture_id {
                    continue;
                }
                removed += match kind.as_str() {
                    "plan" => partition.plans.remove(&object_id).is_some() as usize,
                    "channel" => partition.channels.remove(&object_id).is_some() as usize,
                    "environment" => partition.environments.remove(&object_id).is_some() as usize,
                    "release" => partition.releases.remove(&object_id).is_some() as usize,
                    _ => 0,
                };
            }
            partition
                .fixture_objects
                .retain(|_, (id, _, _)| id != fixture_id);
            partition.audit.push(AuditRecord {
                id: request_id.into(),
                occurred_at: crate::now_millis(),
                principal: actor.into(),
                operation: "development_fixture.reset".into(),
                resource: fixture_id.into(),
                outcome: "reset".into(),
            });
            Ok(crate::development_fixtures::FixtureResetResult {
                contract_version: crate::development_fixtures::DEVELOPMENT_FIXTURE_CONTRACT_VERSION,
                fixture_id: fixture_id.into(),
                removed,
            })
        })
    }

    fn development_fixture_environment(
        &self,
        environment_id: &str,
    ) -> Result<Option<crate::development_fixtures::FixtureEnvironmentProjection>> {
        self.ops_mut(|partition| {
            let Some((fixture_id, _, _)) = partition
                .fixture_objects
                .get(&("environment".into(), environment_id.into()))
                .cloned()
            else {
                return Ok(None);
            };
            let Some(environment) = partition.environments.get(environment_id).cloned() else {
                return Ok(None);
            };
            let mut owned_channels: Vec<(i64, ChannelRecord)> = partition
                .fixture_objects
                .iter()
                .filter(|((kind, _), (id, _, _))| kind == "channel" && *id == fixture_id)
                .filter_map(|((_, object_id), (_, _, order))| {
                    partition
                        .channels
                        .get(object_id)
                        .cloned()
                        .map(|channel| (*order, channel))
                })
                .collect();
            owned_channels.sort_by(|left, right| {
                right
                    .0
                    .cmp(&left.0)
                    .then_with(|| left.1.id.cmp(&right.1.id))
            });
            let channels = owned_channels
                .into_iter()
                .filter_map(|(_, channel)| {
                    let head = partition.releases.get(&channel.release_id)?.version.clone();
                    Some(crate::development_fixtures::FixtureChannelProjection {
                        product: channel.product,
                        channel: channel.name,
                        head,
                    })
                })
                .collect();
            let mut owned_plans: Vec<(i64, PlanRecord)> = partition
                .fixture_objects
                .iter()
                .filter(|((kind, _), (id, _, _))| kind == "plan" && *id == fixture_id)
                .filter_map(|((_, object_id), (_, _, order))| {
                    partition.plans.get(object_id).cloned().and_then(|plan| {
                        (plan.environment_id == environment_id).then_some((*order, plan))
                    })
                })
                .collect();
            owned_plans.sort_by(|left, right| {
                right
                    .0
                    .cmp(&left.0)
                    .then_with(|| right.1.id.cmp(&left.1.id))
            });
            let latest_plan = owned_plans.into_iter().next().map(|(_, plan)| plan);
            crate::development_fixtures::parse_environment_projection(
                environment,
                channels,
                latest_plan,
            )
            .map(Some)
        })
    }

    fn claim_runtime_plan(
        &self,
        environment: &str,
        plan_id: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.ops_mut(|partition| {
            let now = crate::now_millis();
            if environment.is_empty() || plan_id.is_empty() || owner.is_empty() || expires_at <= now
            {
                return Err(StoreError::InvalidData {
                    kind: "runtime claim",
                    detail: "environment, plan, owner, and future expiry are required".into(),
                });
            }
            ensure_active(partition, environment, "runtime work claims")?;
            if fixture_kind(partition, "plan", plan_id) {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture plans are non-executable".into(),
                });
            }
            let (generation, progress_json) = match partition.runtime_claims.get(plan_id).cloned() {
                Some(current) if current.environment_id != environment => {
                    return Err(StoreError::EnvironmentMismatch {
                        kind: "runtime claim",
                        id: plan_id.into(),
                        expected: current.environment_id,
                        actual: environment.into(),
                    });
                }
                Some(current) if current.owner == owner && current.completion_json.is_some() => {
                    return Ok(Some(current));
                }
                Some(current) if current.completion_json.is_some() => return Ok(None),
                Some(mut current) if current.expires_at > now && current.owner == owner => {
                    current.expires_at = expires_at;
                    let stored = current.clone();
                    partition.runtime_claims.insert(plan_id.into(), current);
                    return Ok(Some(stored));
                }
                Some(current) if current.expires_at > now => return Ok(None),
                // SQLite's ON CONFLICT update leaves progress_json; a later
                // claim must still see the boot resume point (ADR 0051 §3).
                Some(current) => (current.generation.saturating_add(1), current.progress_json),
                None => (1, None),
            };
            let claim = RuntimeClaim {
                plan_id: plan_id.into(),
                environment_id: environment.into(),
                owner: owner.into(),
                generation,
                expires_at,
                completion_json: None,
                progress_json,
            };
            partition
                .runtime_claims
                .insert(plan_id.into(), claim.clone());
            // Match the SQLite claim row: progress is read via runtime_progress.
            Ok(Some(RuntimeClaim {
                progress_json: None,
                ..claim
            }))
        })
    }

    fn durable_runtime_completion(
        &self,
        plan_id: &str,
        owner: &str,
    ) -> Result<Option<RuntimeClaim>> {
        self.ops_mut(|partition| {
            Ok(partition
                .runtime_claims
                .get(plan_id)
                .cloned()
                .filter(|claim| claim.owner == owner && claim.completion_json.is_some()))
        })
    }

    fn renew_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.ops_mut(|partition| {
            let Some(current) = partition.runtime_claims.get_mut(plan_id) else {
                return Ok(None);
            };
            if current.owner != owner
                || current.generation != generation
                || current.completion_json.is_some()
            {
                return Ok(None);
            }
            current.expires_at = expires_at;
            Ok(Some(current.clone()))
        })
    }

    fn complete_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        completion_json: &str,
    ) -> Result<()> {
        self.ops_mut(|partition| {
            let current =
                partition
                    .runtime_claims
                    .get_mut(plan_id)
                    .ok_or_else(|| StoreError::NotFound {
                        kind: "runtime claim",
                        id: plan_id.into(),
                    })?;
            if current.owner != owner || current.generation != generation {
                return Err(StoreError::StaleLease {
                    environment: current.environment_id.clone(),
                    expected: current.generation,
                    actual: generation,
                });
            }
            current.completion_json = Some(completion_json.into());
            Ok(())
        })
    }

    fn lapsed_runtime_completion(
        &self,
        environment: &str,
        plan_id: &str,
        now: i64,
    ) -> Result<Option<String>> {
        self.ops_mut(|partition| {
            Ok(partition.runtime_claims.get(plan_id).and_then(|claim| {
                if claim.environment_id == environment
                    && claim.expires_at <= now
                    && claim.completion_json.is_some()
                {
                    claim.completion_json.clone()
                } else {
                    None
                }
            }))
        })
    }

    fn record_runtime_progress(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        progress_json: &str,
    ) -> Result<bool> {
        self.ops_mut(|partition| {
            let Some(current) = partition.runtime_claims.get_mut(plan_id) else {
                return Ok(false);
            };
            if current.owner != owner
                || current.generation != generation
                || current.completion_json.is_some()
            {
                return Ok(false);
            }
            current.progress_json = Some(progress_json.into());
            Ok(true)
        })
    }

    fn runtime_progress(&self, plan_id: &str) -> Result<Option<String>> {
        self.ops_mut(|partition| {
            Ok(partition
                .runtime_claims
                .get(plan_id)
                .and_then(|claim| claim.progress_json.clone()))
        })
    }

    fn create_runtime_enrollment(&self, enrollment: &RuntimeEnrollmentRecord) -> Result<()> {
        self.ops_mut(|partition| {
            if partition.enrollments.contains_key(&enrollment.token_digest) {
                return Err(StoreError::already_exists(
                    "runtime enrollment",
                    enrollment.token_digest.clone(),
                ));
            }
            partition
                .enrollments
                .insert(enrollment.token_digest.clone(), enrollment.clone());
            Ok(())
        })
    }

    fn redeem_runtime_enrollment(
        &self,
        environment: &str,
        token_digest: &str,
        credential_digest: &str,
        now: i64,
        attestation: Option<&RuntimeAttestationRecord>,
        sealing: Option<&RuntimeSealingKeyRecord>,
    ) -> Result<RuntimeCredentialRecord> {
        self.ops_mut(|partition| {
            let enrollment = partition.enrollments.remove(token_digest).ok_or_else(|| {
                StoreError::InvalidData {
                    kind: "runtime enrollment",
                    detail: "unknown, spent or expired enrollment".into(),
                }
            })?;
            if enrollment.environment_id != environment || enrollment.expires_at <= now {
                partition
                    .enrollments
                    .insert(token_digest.into(), enrollment);
                return Err(StoreError::InvalidData {
                    kind: "runtime enrollment",
                    detail: "unknown, spent or expired enrollment".into(),
                });
            }
            let credential = RuntimeCredentialRecord {
                credential_digest: credential_digest.into(),
                environment_id: environment.into(),
                enrollment_digest: token_digest.into(),
                created_at: now,
                revoked_at: None,
            };
            partition
                .credentials
                .insert(credential_digest.into(), credential.clone());
            if let Some(attestation) = attestation {
                partition
                    .attestations
                    .insert(attestation.runner_id.clone(), attestation.clone());
            }
            if let Some(sealing) = sealing {
                partition
                    .sealing_keys
                    .insert(sealing.runner_id.clone(), sealing.clone());
            }
            Ok(credential)
        })
    }

    fn runtime_enrollment_usable(
        &self,
        environment: &str,
        token_digest: &str,
        now: i64,
    ) -> Result<bool> {
        self.ops_mut(|partition| {
            Ok(partition
                .enrollments
                .get(token_digest)
                .is_some_and(|enrollment| {
                    enrollment.environment_id == environment && enrollment.expires_at > now
                }))
        })
    }

    fn runtime_credential(
        &self,
        credential_digest: &str,
    ) -> Result<Option<RuntimeCredentialRecord>> {
        self.ops_mut(|partition| Ok(partition.credentials.get(credential_digest).cloned()))
    }

    fn revoke_runtime_credential(
        &self,
        credential_digest: &str,
        now: i64,
        revocation: &RuntimeRevocation,
    ) -> Result<()> {
        self.ops_mut(|partition| {
            let credential = partition
                .credentials
                .get_mut(credential_digest)
                .ok_or_else(|| StoreError::NotFound {
                    kind: "runtime credential",
                    id: credential_digest.into(),
                })?;
            if credential.revoked_at.is_none() {
                credential.revoked_at = Some(now);
                partition
                    .credential_revocations
                    .insert(credential_digest.into(), revocation.clone());
            }
            Ok(())
        })
    }

    fn runtime_runners(&self) -> Result<Vec<RuntimeRunnerRecord>> {
        self.ops_mut(|partition| {
            Ok(partition
                .credentials
                .values()
                .map(|credential| RuntimeRunnerRecord {
                    created_by: partition
                        .enrollments
                        .values()
                        .find(|enrollment| enrollment.token_digest == credential.enrollment_digest)
                        .map(|enrollment| enrollment.created_by.clone())
                        .unwrap_or_default(),
                    revocation: partition
                        .credential_revocations
                        .get(&credential.credential_digest)
                        .cloned(),
                    credential: credential.clone(),
                })
                .collect())
        })
    }

    fn record_runtime_activity(&self, activity: &RuntimeActivityRecord) -> Result<()> {
        self.ops_mut(|partition| {
            let key = (activity.runner_id.clone(), activity.instance_id.clone());
            let stored = partition
                .activity
                .entry(key)
                .or_insert_with(|| activity.clone());
            stored.last_work_at = stored.last_work_at.max(activity.last_work_at);
            stored.last_heartbeat_at = stored.last_heartbeat_at.max(activity.last_heartbeat_at);
            stored.last_inventory_at = stored.last_inventory_at.max(activity.last_inventory_at);
            if stored.runtime_version.is_none() {
                stored.runtime_version = activity.runtime_version.clone();
            }
            if activity.executors.is_some() {
                stored.executors = activity.executors.clone();
            }
            if activity.engines.is_some() {
                stored.engines = activity.engines.clone();
            }
            Ok(())
        })
    }

    fn runtime_activity(&self) -> Result<Vec<RuntimeActivityRecord>> {
        self.ops_mut(|partition| Ok(partition.activity.values().cloned().collect()))
    }

    fn record_runtime_certificate(
        &self,
        runner_id: &str,
        environment_id: &str,
        issued_at: i64,
    ) -> Result<()> {
        self.ops_mut(|partition| {
            partition
                .certificates
                .entry(runner_id.into())
                .or_insert((environment_id.into(), issued_at));
            Ok(())
        })
    }

    fn certified_runtime_runners(&self) -> Result<Vec<String>> {
        self.ops_mut(|partition| {
            let mut ids: Vec<String> = partition.certificates.keys().cloned().collect();
            ids.sort();
            Ok(ids)
        })
    }

    fn record_runtime_attestation(&self, record: &RuntimeAttestationRecord) -> Result<()> {
        self.ops_mut(|partition| {
            let stored = partition
                .attestations
                .entry(record.runner_id.clone())
                .or_insert_with(|| record.clone());
            if record.evidence_digest.is_some() {
                *stored = record.clone();
                stored.refusal_reason = None;
                stored.refused_at = None;
            } else {
                stored.refusal_reason = record.refusal_reason.clone();
                stored.refused_at = record.refused_at;
            }
            Ok(())
        })
    }

    fn runtime_attestations(&self) -> Result<Vec<RuntimeAttestationRecord>> {
        self.ops_mut(|partition| Ok(partition.attestations.values().cloned().collect()))
    }

    fn record_runtime_sealing_key(&self, record: &RuntimeSealingKeyRecord) -> Result<()> {
        self.ops_mut(|partition| {
            partition
                .sealing_keys
                .insert(record.runner_id.clone(), record.clone());
            Ok(())
        })
    }

    fn runtime_sealing_keys(&self, environment: &str) -> Result<Vec<RuntimeSealingKeyRecord>> {
        self.ops_mut(|partition| {
            Ok(partition
                .sealing_keys
                .values()
                .filter(|record| record.environment_id == environment)
                .filter(|record| {
                    partition
                        .credentials
                        .get(&record.runner_id)
                        .is_none_or(|credential| credential.revoked_at.is_none())
                })
                .cloned()
                .collect())
        })
    }

    fn runtime_sealing_key(&self, runner_id: &str) -> Result<Option<RuntimeSealingKeyRecord>> {
        self.ops_mut(|partition| Ok(partition.sealing_keys.get(runner_id).cloned()))
    }

    fn live_runtime_claim_owners(&self, now: i64) -> Result<Vec<String>> {
        self.ops_mut(|partition| {
            let mut owners: Vec<String> = partition
                .runtime_claims
                .values()
                .filter(|claim| claim.expires_at > now)
                .map(|claim| claim.owner.clone())
                .collect();
            owners.sort();
            owners.dedup();
            Ok(owners)
        })
    }
}

impl MemoryCatalogGraph {
    fn grant_lease(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
        takeover: Option<(u64, &str)>,
    ) -> Result<LeaseRecord> {
        self.ops_mut(|partition| {
            let now = crate::now_millis();
            if expires_at <= now {
                return Err(StoreError::LeaseExpired {
                    environment: environment.into(),
                    generation: 0,
                });
            }
            ensure_active(partition, environment, "new apply leases")?;
            if fixture_kind(partition, "environment", environment) {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture environments are non-executable".into(),
                });
            }
            let wanted = takeover.map(|(generation, _)| generation);
            let current = partition
                .apply_leases
                .get(environment)
                .cloned()
                .or_else(|| {
                    partition
                        .apply_leases
                        .get(&environment_key(environment))
                        .cloned()
                });
            let generation = match current {
                Some(current)
                    if current.expires_at > now && (current.owner != owner || wanted.is_some()) =>
                {
                    return Err(StoreError::LeaseHeld {
                        environment: environment.into(),
                        owner: current.owner,
                        expires_at: current.expires_at,
                    });
                }
                Some(current) if current.expires_at > now => current.generation,
                Some(current) if wanted.is_some_and(|wanted| wanted <= current.generation) => {
                    return Err(StoreError::InvalidData {
                        kind: "lease",
                        detail: format!(
                            "takeover generation must exceed {} for {environment}",
                            current.generation
                        ),
                    });
                }
                Some(current) => wanted.unwrap_or(current.generation + 1),
                None => wanted.unwrap_or(1).max(1),
            };
            let lease = LeaseRecord {
                environment_id: environment.into(),
                owner: owner.into(),
                generation,
                expires_at,
            };
            partition
                .apply_leases
                .insert(environment.into(), lease.clone());
            if let Some((_, evidence_json)) = takeover {
                partition.lease_takeovers.insert(
                    (environment.into(), generation),
                    (owner.into(), evidence_json.into()),
                );
            }
            Ok(lease)
        })
    }

    fn claim_events(
        &self,
        provider_kind: Option<&str>,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        if claim_token.is_empty() || claim_until <= now {
            return Err(StoreError::InvalidData {
                kind: "provider event claim",
                detail: "claim token must be non-empty and expiry must be in the future".into(),
            });
        }
        if provider_kind.is_some_and(str::is_empty) {
            return Err(StoreError::InvalidData {
                kind: "provider event claim",
                detail: "provider kind must be non-empty".into(),
            });
        }
        self.ops_mut(|partition| {
            for event in partition.events.values_mut() {
                if event.delivered_at.is_none()
                    && event.claim_until.is_some_and(|until| until <= now)
                {
                    event.claim_token = None;
                    event.claim_until = None;
                }
            }
            if partition.events.values().any(|event| {
                event.delivered_at.is_none() && event.claim_token.as_deref() == Some(claim_token)
            }) {
                return Err(StoreError::InvalidData {
                    kind: "provider event claim",
                    detail:
                        "claim token is already active; every claim operation requires a fresh token"
                            .into(),
                });
            }
            let mut due: Vec<(String, String)> = partition
                .events
                .values()
                .filter(|event| {
                    event.delivered_at.is_none()
                        && event.next_attempt_at <= now
                        && event.claim_until.map(|until| until <= now).unwrap_or(true)
                        && provider_kind
                            .is_none_or(|kind| event.provider_kind == kind)
                })
                .map(|event| (event.provider_kind.clone(), event.id.clone()))
                .collect();
            due.sort();
            due.truncate(limit);
            let mut claimed = Vec::new();
            for key in due {
                if let Some(event) = partition.events.get_mut(&key) {
                    event.claim_token = Some(claim_token.into());
                    event.claim_until = Some(claim_until);
                    claimed.push(event.clone());
                }
            }
            Ok(claimed)
        })
    }
}

impl GrantRuleStore for MemoryCatalogGraph {
    fn grant_rule_generation(&self) -> Result<i64> {
        self.ops_mut(|partition| Ok(partition.grant_rule_generation))
    }

    fn grant_rules(&self) -> Result<StoredGrantRules> {
        self.ops_mut(|partition| Ok(decoded_grant_rules(partition)))
    }

    fn insert_grant_rule(
        &self,
        rule: &StoredGrantRule,
        expected: Option<i64>,
    ) -> Result<GrantRuleWrite> {
        let json = encode(rule)?;
        self.ops_mut(|partition| {
            if let Some(stale) =
                GrantRuleWrite::check_expected(expected, partition.grant_rule_generation)
            {
                return Ok(stale);
            }
            if partition.grant_rules.len() >= MAX_STORED_RULES
                || partition.grant_rules.contains_key(&rule.rule.value)
            {
                return Ok(GrantRuleWrite::Refused);
            }
            partition.grant_rules.insert(rule.rule.value.clone(), json);
            partition.grant_rule_generation += 1;
            Ok(GrantRuleWrite::Applied(decoded_grant_rules(partition)))
        })
    }

    fn delete_grant_rule(&self, value: &str, expected: Option<i64>) -> Result<GrantRuleWrite> {
        self.ops_mut(|partition| {
            if let Some(stale) =
                GrantRuleWrite::check_expected(expected, partition.grant_rule_generation)
            {
                return Ok(stale);
            }
            if partition.grant_rules.remove(value).is_none() {
                return Ok(GrantRuleWrite::Refused);
            }
            partition.grant_rule_generation += 1;
            Ok(GrantRuleWrite::Applied(decoded_grant_rules(partition)))
        })
    }
}

fn decoded_grant_rules(partition: &Partition) -> StoredGrantRules {
    StoredGrantRules::decode(
        partition.grant_rule_generation,
        partition
            .grant_rules
            .iter()
            .map(|(value, row)| (value.clone(), row.clone())),
    )
}
