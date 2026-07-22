//! Tenkai-owned durable operational state.
//!
//! Domain code depends on [`OperationalStore`], not SQLite rows. The SQLite
//! adapter is the complete solo-mode implementation; a production database
//! adapter must preserve the same transaction and fencing semantics.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("operational store failure: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("{kind} {id} is immutable and already has different content")]
    ImmutableConflict { kind: &'static str, id: String },
    #[error("{kind} {id} was not found")]
    NotFound { kind: &'static str, id: String },
    #[error("plan {id} cannot transition from {from:?} to {to:?}")]
    InvalidPlanTransition {
        id: String,
        from: PlanStatus,
        to: PlanStatus,
    },
    #[error("rollback {id} cannot transition from {from:?} to {to:?}")]
    InvalidRollbackTransition {
        id: String,
        from: RollbackStatus,
        to: RollbackStatus,
    },
    #[error(
        "stale lease for environment {environment}: expected generation {expected}, got {actual}"
    )]
    StaleLease {
        environment: String,
        expected: u64,
        actual: u64,
    },
    #[error("database schema version {found} is newer than supported version {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("invalid stored {kind} payload: {detail}")]
    InvalidData { kind: &'static str, detail: String },
    #[error("{kind} {id} revision conflict: expected {expected}, found {actual}")]
    RevisionConflict {
        kind: &'static str,
        id: String,
        expected: u64,
        actual: u64,
    },
    #[error("environment {environment} lease is held by {owner} until {expires_at}")]
    LeaseHeld {
        environment: String,
        owner: String,
        expires_at: i64,
    },
    #[error("environment {environment} lease generation {generation} is expired")]
    LeaseExpired {
        environment: String,
        generation: u64,
    },
    #[error(
        "lease owner mismatch for environment {environment}: expected {expected}, got {actual}"
    )]
    LeaseOwnerMismatch {
        environment: String,
        expected: String,
        actual: String,
    },
    #[error("{kind} {id} belongs to environment {expected}, not {actual}")]
    EnvironmentMismatch {
        kind: &'static str,
        id: String,
        expected: String,
        actual: String,
    },
    #[error("operational store mutex was poisoned")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    pub id: String,
    pub product: String,
    pub version: String,
    pub content_digest: String,
    pub descriptor_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRecord {
    pub id: String,
    pub product: String,
    pub name: String,
    pub release_id: String,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    pub id: String,
    pub revision: u64,
    pub configuration_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Computed,
    Running,
    Blocked,
    Succeeded,
    Failed,
}

impl PlanStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Computed => "computed",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "computed" => Ok(Self::Computed),
            "running" => Ok(Self::Running),
            "blocked" => Ok(Self::Blocked),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::InvalidData {
                kind: "plan",
                detail: format!("unknown status {other:?}"),
            }),
        }
    }

    fn allows(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Computed, Self::Running)
                    | (Self::Computed, Self::Blocked)
                    | (Self::Blocked, Self::Running)
                    | (Self::Running, Self::Blocked)
                    | (Self::Running, Self::Succeeded)
                    | (Self::Running, Self::Failed)
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRecord {
    pub id: String,
    pub environment_id: String,
    pub format_version: u32,
    pub content_digest: String,
    pub plan_json: String,
    pub status: PlanStatus,
    pub status_detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub environment_id: String,
    pub owner: String,
    pub generation: u64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub id: String,
    pub environment_id: String,
    pub plan_id: String,
    pub step_id: String,
    pub lease_generation: u64,
    pub payload_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
}

impl RollbackStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::InvalidData {
                kind: "rollback",
                detail: format!("unknown status {other:?}"),
            }),
        }
    }

    fn allows(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Pending, Self::Running)
                    | (Self::Pending, Self::Failed)
                    | (Self::Running, Self::Succeeded)
                    | (Self::Running, Self::Failed)
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    pub id: String,
    pub environment_id: String,
    pub plan_id: String,
    pub lease_generation: u64,
    pub checkpoint_json: String,
    pub status: RollbackStatus,
    pub status_detail: String,
}

/// Transactional authority used by embedded and future server hosts.
pub trait OperationalStore: Send + Sync {
    fn publish_release(&self, release: &ReleaseRecord) -> Result<()>;
    fn get_release(&self, id: &str) -> Result<Option<ReleaseRecord>>;
    fn promote_channel(&self, channel: &ChannelRecord) -> Result<ChannelRecord>;
    fn put_environment(&self, environment: &EnvironmentRecord) -> Result<EnvironmentRecord>;
    fn create_plan(&self, plan: &PlanRecord) -> Result<()>;
    fn get_plan(&self, id: &str) -> Result<Option<PlanRecord>>;
    fn transition_plan(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord>;
    fn acquire_lease(&self, environment: &str, owner: &str, expires_at: i64)
    -> Result<LeaseRecord>;
    fn current_lease(&self, environment: &str) -> Result<Option<LeaseRecord>>;
    fn record_receipt(&self, owner: &str, receipt: &ReceiptRecord) -> Result<()>;
    fn get_receipt(&self, id: &str) -> Result<Option<ReceiptRecord>>;
    fn create_rollback(&self, owner: &str, rollback: &RollbackRecord) -> Result<()>;
    fn transition_rollback(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: RollbackStatus,
        checkpoint_json: &str,
        detail: &str,
    ) -> Result<RollbackRecord>;
    fn pending_rollbacks(&self) -> Result<Vec<RollbackRecord>>;
}

pub struct SqliteStore {
    connection: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn schema_version(&self) -> Result<u32> {
        let connection = self.connection()?;
        Ok(connection.query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StoreError::Poisoned)
    }
}

fn migrate(connection: &mut Connection) -> Result<()> {
    let found: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    if found == 0 {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "CREATE TABLE releases (
                id TEXT PRIMARY KEY, product TEXT NOT NULL, version TEXT NOT NULL,
                content_digest TEXT NOT NULL, descriptor_json TEXT NOT NULL,
                UNIQUE(product, version)
             );
             CREATE TABLE channels (
                id TEXT PRIMARY KEY, product TEXT NOT NULL, name TEXT NOT NULL,
                release_id TEXT NOT NULL REFERENCES releases(id), revision INTEGER NOT NULL,
                UNIQUE(product, name)
             );
             CREATE TABLE environments (
                id TEXT PRIMARY KEY, revision INTEGER NOT NULL, configuration_json TEXT NOT NULL
             );
             CREATE TABLE plans (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL REFERENCES environments(id),
                format_version INTEGER NOT NULL, content_digest TEXT NOT NULL,
                plan_json TEXT NOT NULL, status TEXT NOT NULL, status_detail TEXT NOT NULL
             );
             CREATE TABLE leases (
                environment_id TEXT PRIMARY KEY REFERENCES environments(id),
                owner TEXT NOT NULL, generation INTEGER NOT NULL, expires_at INTEGER NOT NULL
             );
             CREATE TABLE receipts (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL REFERENCES environments(id),
                plan_id TEXT NOT NULL REFERENCES plans(id), step_id TEXT NOT NULL,
                lease_generation INTEGER NOT NULL, payload_json TEXT NOT NULL
             );
             CREATE TABLE rollbacks (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL REFERENCES environments(id),
                plan_id TEXT NOT NULL REFERENCES plans(id), lease_generation INTEGER NOT NULL,
                intent_digest TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL, status TEXT NOT NULL, status_detail TEXT NOT NULL
             );
             CREATE INDEX rollbacks_recovery ON rollbacks(status, environment_id);
             PRAGMA user_version = 1;",
        )?;
        tx.commit()?;
    }
    Ok(())
}

fn lease_in(tx: &Transaction<'_>, environment: &str) -> Result<Option<LeaseRecord>> {
    Ok(tx
        .query_row(
            "SELECT environment_id, owner, generation, expires_at FROM leases WHERE environment_id=?1",
            [environment],
            |row| {
                Ok(LeaseRecord {
                    environment_id: row.get(0)?,
                    owner: row.get(1)?,
                    generation: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            },
        )
        .optional()?)
}

fn require_lease(
    tx: &Transaction<'_>,
    environment: &str,
    owner: &str,
    generation: u64,
    now: i64,
) -> Result<()> {
    let lease = lease_in(tx, environment)?.ok_or_else(|| StoreError::StaleLease {
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
            expected: lease.owner,
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

fn plan_environment(tx: &Transaction<'_>, plan_id: &str) -> Result<String> {
    tx.query_row(
        "SELECT environment_id FROM plans WHERE id=?1",
        [plan_id],
        |row| row.get(0),
    )
    .optional()?
    .ok_or_else(|| StoreError::NotFound {
        kind: "plan",
        id: plan_id.into(),
    })
}

fn require_plan_environment(
    tx: &Transaction<'_>,
    plan_id: &str,
    environment: &str,
    kind: &'static str,
) -> Result<()> {
    let expected = plan_environment(tx, plan_id)?;
    if expected != environment {
        return Err(StoreError::EnvironmentMismatch {
            kind,
            id: plan_id.into(),
            expected,
            actual: environment.into(),
        });
    }
    Ok(())
}

fn rollback_intent_digest(rollback: &RollbackRecord) -> String {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    for value in [
        rollback.environment_id.as_bytes(),
        rollback.plan_id.as_bytes(),
        &rollback.lease_generation.to_le_bytes(),
        rollback.checkpoint_json.as_bytes(),
        rollback.status_detail.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    }
    format!("{:x}", digest.finalize())
}

impl OperationalStore for SqliteStore {
    fn publish_release(&self, release: &ReleaseRecord) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT product, version, content_digest, descriptor_json FROM releases WHERE id=?1",
                [&release.id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing
                != (
                    release.product.clone(),
                    release.version.clone(),
                    release.content_digest.clone(),
                    release.descriptor_json.clone(),
                )
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "release",
                    id: release.id.clone(),
                });
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO releases(id,product,version,content_digest,descriptor_json) VALUES(?1,?2,?3,?4,?5)",
            params![release.id, release.product, release.version, release.content_digest, release.descriptor_json],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn get_release(&self, id: &str) -> Result<Option<ReleaseRecord>> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT id,product,version,content_digest,descriptor_json FROM releases WHERE id=?1", [id],
            |row| Ok(ReleaseRecord { id: row.get(0)?, product: row.get(1)?, version: row.get(2)?, content_digest: row.get(3)?, descriptor_json: row.get(4)? }),
        ).optional()?)
    }

    fn promote_channel(&self, channel: &ChannelRecord) -> Result<ChannelRecord> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let release_product: String = tx
            .query_row(
                "SELECT product FROM releases WHERE id=?1",
                [&channel.release_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound {
                kind: "release",
                id: channel.release_id.clone(),
            })?;
        if release_product != channel.product {
            return Err(StoreError::InvalidData {
                kind: "channel",
                detail: format!(
                    "release {} belongs to product {release_product}, not {}",
                    channel.release_id, channel.product
                ),
            });
        }
        let existing: Option<(String, String, u64)> = tx
            .query_row(
                "SELECT product,name,revision FROM channels WHERE id=?1",
                [&channel.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let next = match existing {
            Some((product, name, revision)) => {
                if product != channel.product || name != channel.name {
                    return Err(StoreError::ImmutableConflict {
                        kind: "channel",
                        id: channel.id.clone(),
                    });
                }
                if revision != channel.revision {
                    return Err(StoreError::RevisionConflict {
                        kind: "channel",
                        id: channel.id.clone(),
                        expected: channel.revision,
                        actual: revision,
                    });
                }
                revision + 1
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
        tx.execute(
            "INSERT INTO channels(id,product,name,release_id,revision) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(id) DO UPDATE SET release_id=excluded.release_id, revision=excluded.revision",
            params![channel.id, channel.product, channel.name, channel.release_id, next],
        )?;
        tx.commit()?;
        Ok(ChannelRecord {
            revision: next,
            ..channel.clone()
        })
    }

    fn put_environment(&self, environment: &EnvironmentRecord) -> Result<EnvironmentRecord> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let revision: Option<u64> = tx
            .query_row(
                "SELECT revision FROM environments WHERE id=?1",
                [&environment.id],
                |row| row.get(0),
            )
            .optional()?;
        let next = match revision {
            Some(revision) if revision == environment.revision => revision + 1,
            Some(revision) => {
                return Err(StoreError::RevisionConflict {
                    kind: "environment",
                    id: environment.id.clone(),
                    expected: environment.revision,
                    actual: revision,
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
        tx.execute(
            "INSERT INTO environments(id,revision,configuration_json) VALUES(?1,?2,?3)
             ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, configuration_json=excluded.configuration_json",
            params![environment.id, next, environment.configuration_json],
        )?;
        tx.commit()?;
        Ok(EnvironmentRecord {
            revision: next,
            ..environment.clone()
        })
    }

    fn create_plan(&self, plan: &PlanRecord) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing: Option<(String, u32, String, String)> = tx.query_row(
            "SELECT environment_id,format_version,content_digest,plan_json FROM plans WHERE id=?1", [&plan.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        if let Some(existing) = existing {
            if existing
                != (
                    plan.environment_id.clone(),
                    plan.format_version,
                    plan.content_digest.clone(),
                    plan.plan_json.clone(),
                )
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
        tx.execute(
            "INSERT INTO plans(id,environment_id,format_version,content_digest,plan_json,status,status_detail) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![plan.id, plan.environment_id, plan.format_version, plan.content_digest, plan.plan_json, plan.status.as_str(), plan.status_detail],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn get_plan(&self, id: &str) -> Result<Option<PlanRecord>> {
        let connection = self.connection()?;
        connection.query_row(
            "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail FROM plans WHERE id=?1", [id],
            |row| {
                let status: String = row.get(5)?;
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, status, row.get(6)?))
            },
        ).optional()?.map(|(id, environment_id, format_version, content_digest, plan_json, status, status_detail)| {
            Ok::<PlanRecord, StoreError>(PlanRecord { id, environment_id, format_version, content_digest, plan_json, status: PlanStatus::parse(&status)?, status_detail })
        }).transpose()
    }

    fn transition_plan(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let current: String = tx
            .query_row("SELECT status FROM plans WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or_else(|| StoreError::NotFound {
                kind: "plan",
                id: id.into(),
            })?;
        let current = PlanStatus::parse(&current)?;
        let environment = plan_environment(&tx, id)?;
        require_lease(&tx, &environment, owner, generation, crate::now_millis())?;
        if !current.allows(status) {
            return Err(StoreError::InvalidPlanTransition {
                id: id.into(),
                from: current,
                to: status,
            });
        }
        tx.execute(
            "UPDATE plans SET status=?2,status_detail=?3 WHERE id=?1",
            params![id, status.as_str(), detail],
        )?;
        tx.commit()?;
        drop(connection);
        self.get_plan(id)?.ok_or_else(|| StoreError::NotFound {
            kind: "plan",
            id: id.into(),
        })
    }

    fn acquire_lease(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<LeaseRecord> {
        let now = crate::now_millis();
        if expires_at <= now {
            return Err(StoreError::LeaseExpired {
                environment: environment.into(),
                generation: 0,
            });
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let current = lease_in(&tx, environment)?;
        let generation = match current {
            Some(current) if current.expires_at > now && current.owner != owner => {
                return Err(StoreError::LeaseHeld {
                    environment: environment.into(),
                    owner: current.owner,
                    expires_at: current.expires_at,
                });
            }
            Some(current) if current.expires_at > now => current.generation,
            Some(current) => current.generation + 1,
            None => 1,
        };
        tx.execute(
            "INSERT INTO leases(environment_id,owner,generation,expires_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(environment_id) DO UPDATE SET owner=excluded.owner,generation=excluded.generation,expires_at=excluded.expires_at",
            params![environment, owner, generation, expires_at],
        )?;
        tx.commit()?;
        Ok(LeaseRecord {
            environment_id: environment.into(),
            owner: owner.into(),
            generation,
            expires_at,
        })
    }

    fn current_lease(&self, environment: &str) -> Result<Option<LeaseRecord>> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let lease = lease_in(&tx, environment)?;
        tx.commit()?;
        Ok(lease)
    }

    fn record_receipt(&self, owner: &str, receipt: &ReceiptRecord) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing: Option<(String, String, String, u64, String)> = tx.query_row(
            "SELECT environment_id,plan_id,step_id,lease_generation,payload_json FROM receipts WHERE id=?1", [&receipt.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?;
        if let Some(existing) = existing {
            if existing
                != (
                    receipt.environment_id.clone(),
                    receipt.plan_id.clone(),
                    receipt.step_id.clone(),
                    receipt.lease_generation,
                    receipt.payload_json.clone(),
                )
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "receipt",
                    id: receipt.id.clone(),
                });
            }
            return Ok(());
        }
        require_plan_environment(&tx, &receipt.plan_id, &receipt.environment_id, "receipt")?;
        require_lease(
            &tx,
            &receipt.environment_id,
            owner,
            receipt.lease_generation,
            crate::now_millis(),
        )?;
        tx.execute(
            "INSERT INTO receipts(id,environment_id,plan_id,step_id,lease_generation,payload_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![receipt.id, receipt.environment_id, receipt.plan_id, receipt.step_id, receipt.lease_generation, receipt.payload_json],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn get_receipt(&self, id: &str) -> Result<Option<ReceiptRecord>> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT id,environment_id,plan_id,step_id,lease_generation,payload_json FROM receipts WHERE id=?1", [id],
            |row| Ok(ReceiptRecord { id: row.get(0)?, environment_id: row.get(1)?, plan_id: row.get(2)?, step_id: row.get(3)?, lease_generation: row.get(4)?, payload_json: row.get(5)? }),
        ).optional()?)
    }

    fn create_rollback(&self, owner: &str, rollback: &RollbackRecord) -> Result<()> {
        if rollback.status != RollbackStatus::Pending {
            return Err(StoreError::InvalidRollbackTransition {
                id: rollback.id.clone(),
                from: RollbackStatus::Pending,
                to: rollback.status,
            });
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if rollback_in(&tx, &rollback.id)?.is_some() {
            let stored_digest: String = tx.query_row(
                "SELECT intent_digest FROM rollbacks WHERE id=?1",
                [&rollback.id],
                |row| row.get(0),
            )?;
            if rollback_intent_digest(rollback) != stored_digest {
                return Err(StoreError::ImmutableConflict {
                    kind: "rollback",
                    id: rollback.id.clone(),
                });
            }
            return Ok(());
        }
        require_plan_environment(&tx, &rollback.plan_id, &rollback.environment_id, "rollback")?;
        require_lease(
            &tx,
            &rollback.environment_id,
            owner,
            rollback.lease_generation,
            crate::now_millis(),
        )?;
        tx.execute(
            "INSERT INTO rollbacks(id,environment_id,plan_id,lease_generation,intent_digest,checkpoint_json,status,status_detail) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![rollback.id, rollback.environment_id, rollback.plan_id, rollback.lease_generation, rollback_intent_digest(rollback), rollback.checkpoint_json, rollback.status.as_str(), rollback.status_detail],
        )?;
        tx.commit()?;
        Ok(())
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
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let current = rollback_in(&tx, id)?.ok_or_else(|| StoreError::NotFound {
            kind: "rollback",
            id: id.into(),
        })?;
        require_plan_environment(&tx, &current.plan_id, &current.environment_id, "rollback")?;
        require_lease(
            &tx,
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
        tx.execute(
            "UPDATE rollbacks SET lease_generation=?2,checkpoint_json=?3,status=?4,status_detail=?5 WHERE id=?1",
            params![id, generation, checkpoint_json, status.as_str(), detail],
        )?;
        let updated = rollback_in(&tx, id)?.expect("updated rollback exists");
        tx.commit()?;
        Ok(updated)
    }

    fn pending_rollbacks(&self) -> Result<Vec<RollbackRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id,environment_id,plan_id,lease_generation,checkpoint_json,status,status_detail FROM rollbacks WHERE status IN ('pending','running') ORDER BY id"
        )?;
        let rows = statement.query_map([], rollback_from_row)?;
        rows.map(|row| row.map_err(StoreError::from))
            .collect::<Result<Vec<_>>>()
    }
}

fn rollback_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RollbackRecord> {
    let status: String = row.get(5)?;
    let status = RollbackStatus::parse(&status).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(RollbackRecord {
        id: row.get(0)?,
        environment_id: row.get(1)?,
        plan_id: row.get(2)?,
        lease_generation: row.get(3)?,
        checkpoint_json: row.get(4)?,
        status,
        status_detail: row.get(6)?,
    })
}

fn rollback_in(tx: &Transaction<'_>, id: &str) -> Result<Option<RollbackRecord>> {
    Ok(tx.query_row(
        "SELECT id,environment_id,plan_id,lease_generation,checkpoint_json,status,status_detail FROM rollbacks WHERE id=?1",
        [id], rollback_from_row,
    ).optional()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(store: &SqliteStore) {
        store
            .put_environment(&EnvironmentRecord {
                id: "prod".into(),
                revision: 0,
                configuration_json: "{}".into(),
            })
            .unwrap();
    }

    fn plan(store: &SqliteStore) -> PlanRecord {
        let plan = PlanRecord {
            id: "plan-1".into(),
            environment_id: "prod".into(),
            format_version: 1,
            content_digest: "sha256:plan".into(),
            plan_json: "{}".into(),
            status: PlanStatus::Computed,
            status_detail: String::new(),
        };
        store.create_plan(&plan).unwrap();
        plan
    }

    #[test]
    fn schema_is_created_and_reopened_without_optional_provider() {
        let path = std::env::temp_dir().join(format!("tenkai-storage-{}.db", uuid::Uuid::new_v4()));
        {
            let store = SqliteStore::open(&path).unwrap();
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
            store
                .publish_release(&ReleaseRecord {
                    id: "release-1".into(),
                    product: "api".into(),
                    version: "1.0.0".into(),
                    content_digest: "sha256:a".into(),
                    descriptor_json: "{}".into(),
                })
                .unwrap();
        }
        let reopened = SqliteStore::open(&path).unwrap();
        assert_eq!(
            reopened.get_release("release-1").unwrap().unwrap().version,
            "1.0.0"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn release_content_and_plan_content_are_immutable() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut release = ReleaseRecord {
            id: "release-1".into(),
            product: "api".into(),
            version: "1.0.0".into(),
            content_digest: "sha256:a".into(),
            descriptor_json: "{}".into(),
        };
        store.publish_release(&release).unwrap();
        store.publish_release(&release).unwrap();
        release.content_digest = "sha256:b".into();
        assert!(matches!(
            store.publish_release(&release),
            Err(StoreError::ImmutableConflict { .. })
        ));
        environment(&store);
        let mut created = plan(&store);
        created.plan_json = "{\"changed\":true}".into();
        assert!(matches!(
            store.create_plan(&created),
            Err(StoreError::ImmutableConflict { .. })
        ));
    }

    #[test]
    fn plan_lifecycle_is_transactionally_constrained() {
        let store = SqliteStore::open_in_memory().unwrap();
        environment(&store);
        plan(&store);
        let now = crate::now_millis();
        let lease = store.acquire_lease("prod", "worker", now + 10_000).unwrap();
        store
            .transition_plan(
                "plan-1",
                "worker",
                lease.generation,
                PlanStatus::Running,
                "started",
            )
            .unwrap();
        store
            .transition_plan(
                "plan-1",
                "worker",
                lease.generation,
                PlanStatus::Succeeded,
                "done",
            )
            .unwrap();
        assert!(matches!(
            store.transition_plan(
                "plan-1",
                "worker",
                lease.generation,
                PlanStatus::Running,
                "retry"
            ),
            Err(StoreError::InvalidPlanTransition { .. })
        ));
    }

    #[test]
    fn generations_fence_receipts_and_rollback_updates() {
        let store = SqliteStore::open_in_memory().unwrap();
        environment(&store);
        plan(&store);
        let now = crate::now_millis();
        let first = store.acquire_lease("prod", "worker-a", now + 50).unwrap();
        let rollback = RollbackRecord {
            id: "rollback-1".into(),
            environment_id: "prod".into(),
            plan_id: "plan-1".into(),
            lease_generation: first.generation,
            checkpoint_json: "{}".into(),
            status: RollbackStatus::Pending,
            status_detail: String::new(),
        };
        store.create_rollback("worker-a", &rollback).unwrap();
        assert!(matches!(
            store.acquire_lease("prod", "worker-b", now + 10_000),
            Err(StoreError::LeaseHeld { .. })
        ));
        std::thread::sleep(std::time::Duration::from_millis(60));
        let second = store
            .acquire_lease("prod", "worker-b", now + 10_000)
            .unwrap();
        assert!(matches!(
            store.record_receipt(
                "worker-a",
                &ReceiptRecord {
                    id: "receipt-1".into(),
                    environment_id: "prod".into(),
                    plan_id: "plan-1".into(),
                    step_id: "step-1".into(),
                    lease_generation: first.generation,
                    payload_json: "{}".into()
                }
            ),
            Err(StoreError::StaleLease { .. })
        ));
        assert!(matches!(
            store.transition_rollback(
                "rollback-1",
                "worker-a",
                first.generation,
                RollbackStatus::Running,
                "{}",
                "retry"
            ),
            Err(StoreError::StaleLease { .. })
        ));
        let resumed = store
            .transition_rollback(
                "rollback-1",
                "worker-b",
                second.generation,
                RollbackStatus::Running,
                "{\"resumed\":true}",
                "recovered after takeover",
            )
            .unwrap();
        assert_eq!(resumed.lease_generation, second.generation);
        store.create_rollback("worker-a", &rollback).unwrap();
        let mut collision = rollback.clone();
        collision.checkpoint_json = "{\"different\":true}".into();
        assert!(matches!(
            store.create_rollback("worker-a", &collision),
            Err(StoreError::ImmutableConflict { .. })
        ));
        let mut detail_collision = rollback.clone();
        detail_collision.status_detail = "different intent".into();
        assert!(matches!(
            store.create_rollback("worker-a", &detail_collision),
            Err(StoreError::ImmutableConflict { .. })
        ));
    }

    #[test]
    fn pending_rollback_survives_restart_and_receipts_are_idempotent() {
        let path =
            std::env::temp_dir().join(format!("tenkai-recovery-{}.db", uuid::Uuid::new_v4()));
        let receipt = ReceiptRecord {
            id: "receipt-1".into(),
            environment_id: "prod".into(),
            plan_id: "plan-1".into(),
            step_id: "step-1".into(),
            lease_generation: 1,
            payload_json: "{\"ok\":true}".into(),
        };
        {
            let store = SqliteStore::open(&path).unwrap();
            environment(&store);
            plan(&store);
            let now = crate::now_millis();
            let lease = store.acquire_lease("prod", "worker", now + 10_000).unwrap();
            assert_eq!(lease.generation, receipt.lease_generation);
            store.record_receipt("worker", &receipt).unwrap();
            store.record_receipt("worker", &receipt).unwrap();
            store
                .create_rollback(
                    "worker",
                    &RollbackRecord {
                        id: "rollback-1".into(),
                        environment_id: "prod".into(),
                        plan_id: "plan-1".into(),
                        lease_generation: receipt.lease_generation,
                        checkpoint_json: "{\"next\":1}".into(),
                        status: RollbackStatus::Pending,
                        status_detail: String::new(),
                    },
                )
                .unwrap();
        }
        let reopened = SqliteStore::open(&path).unwrap();
        assert_eq!(reopened.get_receipt("receipt-1").unwrap(), Some(receipt));
        assert_eq!(reopened.pending_rollbacks().unwrap().len(), 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn newer_schema_fails_closed() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let mut connection = connection;
        assert!(matches!(
            migrate(&mut connection),
            Err(StoreError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn revisions_prevent_stale_environment_and_channel_writes() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first = store
            .put_environment(&EnvironmentRecord {
                id: "prod".into(),
                revision: 0,
                configuration_json: "{}".into(),
            })
            .unwrap();
        let updated = store
            .put_environment(&EnvironmentRecord {
                configuration_json: "{\"region\":\"eu\"}".into(),
                ..first.clone()
            })
            .unwrap();
        assert_eq!(updated.revision, 2);
        assert!(matches!(
            store.put_environment(&first),
            Err(StoreError::RevisionConflict { .. })
        ));

        store
            .publish_release(&ReleaseRecord {
                id: "release-1".into(),
                product: "api".into(),
                version: "1.0.0".into(),
                content_digest: "sha256:a".into(),
                descriptor_json: "{}".into(),
            })
            .unwrap();
        let channel = store
            .promote_channel(&ChannelRecord {
                id: "api/stable".into(),
                product: "api".into(),
                name: "stable".into(),
                release_id: "release-1".into(),
                revision: 0,
            })
            .unwrap();
        store
            .publish_release(&ReleaseRecord {
                id: "release-other".into(),
                product: "other".into(),
                version: "1.0.0".into(),
                content_digest: "sha256:other".into(),
                descriptor_json: "{}".into(),
            })
            .unwrap();
        assert!(matches!(
            store.promote_channel(&ChannelRecord {
                product: "other".into(),
                release_id: "release-other".into(),
                ..channel
            }),
            Err(StoreError::ImmutableConflict { .. })
        ));
        assert!(matches!(
            store.promote_channel(&ChannelRecord {
                id: "api/dev".into(),
                product: "api".into(),
                name: "dev".into(),
                release_id: "release-other".into(),
                revision: 0,
            }),
            Err(StoreError::InvalidData {
                kind: "channel",
                ..
            })
        ));
    }

    #[test]
    fn execution_records_cannot_cross_environment_boundaries() {
        let store = SqliteStore::open_in_memory().unwrap();
        environment(&store);
        plan(&store);
        store
            .put_environment(&EnvironmentRecord {
                id: "other".into(),
                revision: 0,
                configuration_json: "{}".into(),
            })
            .unwrap();
        let now = crate::now_millis();
        let lease = store
            .acquire_lease("other", "worker", now + 10_000)
            .unwrap();
        assert!(matches!(
            store.record_receipt(
                "worker",
                &ReceiptRecord {
                    id: "receipt-other".into(),
                    environment_id: "other".into(),
                    plan_id: "plan-1".into(),
                    step_id: "step-1".into(),
                    lease_generation: lease.generation,
                    payload_json: "{}".into(),
                }
            ),
            Err(StoreError::EnvironmentMismatch { .. })
        ));
    }
}
