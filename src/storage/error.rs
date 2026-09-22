use super::*;

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
    /// Optional Postgres adapter failures (feature `postgres`). Never used by SQLite path.
    #[error("postgres operational store failure: {0}")]
    Postgres(String),
    /// Feature or configuration required for an optional store adapter is missing.
    #[error("optional store adapter unavailable: {0}")]
    AdapterUnavailable(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;
