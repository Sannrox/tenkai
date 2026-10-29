//! Grant rules stored in the hub's store (#836).
//!
//! OIDC grant rules map an identity-provider claim value to Tenkai
//! capabilities. The configuration file holds some; the hub's store can hold
//! more, so the first administrator can be set up and changed without editing
//! the file and restarting every replica. Effective rules are the file's plus
//! the stored ones. The file stays authoritative for what it declares: a
//! stored rule may not use a claim value the file names, and one that does
//! (because the file gained it later) is ignored.
//!
//! The store keeps one rule per claim value and a generation that grows with
//! every change, shared by every replica (the hub-wide tables on PostgreSQL).
//! Each replica checks the generation every [`REFRESH_INTERVAL`] and reloads
//! the rules when it moved; the replica that made a change reloads at once.
//! A replica that cannot read the store for longer than [`STALE_AFTER`]
//! stops applying stored rules (the file's still apply) until a check
//! succeeds again, so a cut-off replica never keeps honouring a rule removed
//! meanwhile; `/readyz` reports it not ready.
//! Each rule records who created it, when and why. Older replicas ignore the
//! stored rules, so they take effect everywhere only once every replica runs a
//! release with this change.

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::oidc_verifier::{FirstAdministrator, OidcGrantRule};
use crate::storage::{Result, StoreError};

/// How often a replica checks the stored rules' generation.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
/// How long a replica keeps applying stored rules without a successful
/// check of the store; after that it applies none until one succeeds.
pub const STALE_AFTER: Duration = Duration::from_secs(30);
/// Most stored rules a hub keeps; each is matched on every OIDC request.
pub const MAX_STORED_RULES: usize = 256;
const MAX_REASON: usize = 1024;

/// A stored rule: the rule as the configuration file would hold it, and who
/// created it, when and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredGrantRule {
    pub rule: OidcGrantRule,
    /// The principal, or the management token's use, that created it.
    pub created_by: String,
    pub created_at_ms: i64,
    pub reason: String,
}

/// Stored grant rules, shared by every replica of a hub.
pub trait GrantRuleStore: Send + Sync {
    /// The generation: 0 before the first change, then one more per change.
    fn grant_rule_generation(&self) -> Result<i64>;
    /// Every stored rule with the generation they are current at, read
    /// together.
    fn grant_rules(&self) -> Result<(i64, Vec<StoredGrantRule>)>;
    /// Store `rule` unless a rule for its claim value exists or the store
    /// already holds [`MAX_STORED_RULES`]; the new generation, or `None`
    /// when refused.
    fn insert_grant_rule(&self, rule: &StoredGrantRule) -> Result<Option<i64>>;
    /// Remove the rule for `value`; the new generation, or `None` when there
    /// is none.
    fn delete_grant_rule(&self, value: &str) -> Result<Option<i64>>;
}

/// Why a stored rule was refused.
#[derive(Debug, thiserror::Error)]
pub enum GrantRuleError {
    #[error("invalid grant rule: {0}")]
    Invalid(String),
    #[error("the configuration file declares claim value {0:?}; change it there")]
    DeclaredByConfig(String),
    #[error("a stored grant rule for claim value {0:?} already exists, or the store is full")]
    Exists(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

struct Snapshot {
    generation: i64,
    rules: Arc<Vec<OidcGrantRule>>,
    /// When the last check the store answered was asked.
    checked_at: Instant,
}

/// One replica's view of the stored rules, kept current by
/// [`StoredGrants::spawn_refresher`].
pub struct StoredGrants {
    store: Arc<dyn GrantRuleStore>,
    /// Claim values the configuration file declares.
    config_values: BTreeSet<String>,
    snapshot: RwLock<Snapshot>,
    stale_after: Duration,
}

impl StoredGrants {
    /// Load the stored rules; `config_values` are the claim values the
    /// configuration file declares.
    pub fn load(
        store: Arc<dyn GrantRuleStore>,
        config_values: impl IntoIterator<Item = String>,
    ) -> Result<Arc<Self>> {
        Self::load_with_stale_after(store, config_values, STALE_AFTER)
    }

    /// [`StoredGrants::load`] with another stale bound.
    pub fn load_with_stale_after(
        store: Arc<dyn GrantRuleStore>,
        config_values: impl IntoIterator<Item = String>,
        stale_after: Duration,
    ) -> Result<Arc<Self>> {
        let grants = Arc::new(Self {
            store,
            config_values: config_values.into_iter().collect(),
            snapshot: RwLock::new(Snapshot {
                generation: -1,
                rules: Arc::default(),
                checked_at: Instant::now(),
            }),
            stale_after,
        });
        grants.reload()?;
        Ok(grants)
    }

    /// The stored rules in effect: those the configuration file does not
    /// override, and none while the store has not answered a check for
    /// longer than the stale bound.
    pub fn rules(&self) -> Arc<Vec<OidcGrantRule>> {
        let snapshot = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        if snapshot.checked_at.elapsed() > self.stale_after {
            return Arc::default();
        }
        snapshot.rules.clone()
    }

    /// Whether stored rules are suspended because the store has not
    /// answered a check within the stale bound.
    pub fn is_stale(&self) -> bool {
        self.snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .checked_at
            .elapsed()
            > self.stale_after
    }

    pub fn generation(&self) -> i64 {
        self.snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .generation
    }

    /// Whether a stored rule in effect gives fleet management.
    pub fn first_administrator(&self) -> FirstAdministrator {
        if self
            .rules()
            .iter()
            .any(OidcGrantRule::grants_fleet_management)
        {
            FirstAdministrator::Configured
        } else {
            FirstAdministrator::Missing
        }
    }

    /// Reload when the store's generation moved; whether it did.
    pub fn refresh(&self) -> Result<bool> {
        // A check counts from when it was asked, not when the answer came:
        // a slow answer must not extend how long the rules stay in effect.
        let started = Instant::now();
        let generation = self.store.grant_rule_generation()?;
        {
            let mut snapshot = self
                .snapshot
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            if generation == snapshot.generation {
                snapshot.checked_at = snapshot.checked_at.max(started);
                return Ok(false);
            }
        }
        self.reload_from(started)?;
        Ok(true)
    }

    fn reload(&self) -> Result<()> {
        self.reload_from(Instant::now())
    }

    /// Replace the snapshot with a read started at `started`, unless a read
    /// started later, or of a newer generation, already replaced it.
    fn reload_from(&self, started: Instant) -> Result<()> {
        let (generation, stored) = self.store.grant_rules()?;
        let rules = stored
            .into_iter()
            .map(|stored| stored.rule)
            .filter(|rule| !self.config_values.contains(&rule.value) && rule.validate().is_ok())
            .collect();
        let mut snapshot = self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if started >= snapshot.checked_at && generation >= snapshot.generation {
            *snapshot = Snapshot {
                generation,
                rules: Arc::new(rules),
                checked_at: started,
            };
        }
        Ok(())
    }

    /// Store a rule and apply it on this replica at once.
    pub fn create(
        &self,
        rule: OidcGrantRule,
        created_by: &str,
        reason: &str,
        now_ms: i64,
    ) -> std::result::Result<StoredGrantRule, GrantRuleError> {
        rule.validate()
            .map_err(|error| GrantRuleError::Invalid(error.to_string()))?;
        let reason = reason.trim();
        if reason.is_empty() || reason.len() > MAX_REASON {
            return Err(GrantRuleError::Invalid(format!(
                "a reason of 1..={MAX_REASON} bytes is required"
            )));
        }
        if created_by.trim().is_empty() {
            return Err(GrantRuleError::Invalid("the creator is required".into()));
        }
        if self.config_values.contains(&rule.value) {
            return Err(GrantRuleError::DeclaredByConfig(rule.value));
        }
        let stored = StoredGrantRule {
            rule,
            created_by: created_by.into(),
            created_at_ms: now_ms,
            reason: reason.into(),
        };
        if self.store.insert_grant_rule(&stored)?.is_none() {
            return Err(GrantRuleError::Exists(stored.rule.value));
        }
        self.reload()?;
        Ok(stored)
    }

    /// Remove the stored rule for `value` and apply it on this replica at
    /// once; whether there was one.
    pub fn remove(&self, value: &str) -> Result<bool> {
        let removed = self.store.delete_grant_rule(value)?.is_some();
        self.reload()?;
        Ok(removed)
    }

    /// Check the generation every `interval` on a background thread, until
    /// this handle is dropped. A failed check keeps the last rules and is
    /// retried at the next interval.
    pub fn spawn_refresher(self: &Arc<Self>, interval: Duration) {
        let weak: Weak<Self> = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("tenkai-grant-rules".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(interval);
                    let Some(grants) = weak.upgrade() else {
                        return;
                    };
                    if let Err(error) = grants.refresh() {
                        eprintln!(
                            "tenkai.auth stored_grant_rules=stale detail=refresh failed, keeping the last rules: {error}"
                        );
                    }
                }
            })
            .expect("spawning the grant rule refresher");
    }
}

/// Encode and decode a stored rule as the store keeps it.
pub fn encode(rule: &StoredGrantRule) -> Result<String> {
    serde_json::to_string(rule).map_err(|error| StoreError::Database(error.to_string()))
}

pub fn decode(raw: &str) -> Result<StoredGrantRule> {
    serde_json::from_str(raw)
        .map_err(|error| StoreError::Database(format!("stored grant rule: {error}")))
}

/// The contract every [`GrantRuleStore`] meets, for each backend's tests:
/// `store` and `other` are two replicas' connections to one database, which
/// this run uses alone.
#[cfg(any(test, feature = "test-support"))]
pub fn assert_grant_rule_store_contract(
    store: Arc<dyn GrantRuleStore>,
    other: Arc<dyn GrantRuleStore>,
    prefix: &str,
) {
    let rule = |value: &str, capabilities: &[&str]| OidcGrantRule {
        value: value.into(),
        capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
        environment: None,
        channels: Vec::new(),
        products: Vec::new(),
        kind: None,
    };
    let admins = format!("{prefix}-admins");
    let readers = format!("{prefix}-readers");
    let declared = format!("{prefix}-declared");
    let first = StoredGrants::load(store.clone(), [declared.clone()]).unwrap();
    let second = StoredGrants::load(other, [declared.clone()]).unwrap();
    let start = first.generation();
    assert!(first.rules().iter().all(|r| r.value != admins));

    // A value the configuration file declares is refused.
    assert!(matches!(
        first.create(rule(&declared, &["read"]), "token", "setup", 1),
        Err(GrantRuleError::DeclaredByConfig(_))
    ));
    // A rule without a capability, or without a reason, is refused.
    assert!(matches!(
        first.create(rule(&admins, &[]), "token", "setup", 1),
        Err(GrantRuleError::Invalid(_))
    ));
    assert!(matches!(
        first.create(rule(&admins, &["read"]), "token", " ", 1),
        Err(GrantRuleError::Invalid(_))
    ));

    let created = first
        .create(
            rule(&admins, &["read", "management"]),
            "management-token",
            "first administrator",
            10,
        )
        .unwrap();
    assert_eq!(created.created_by, "management-token");
    // The writing replica applies it at once.
    assert!(first.rules().iter().any(|r| r.value == admins));
    assert_eq!(first.first_administrator(), FirstAdministrator::Configured);
    assert_eq!(first.generation(), start + 1);
    // Another replica sees it once it checks the generation.
    assert!(second.rules().iter().all(|r| r.value != admins));
    assert!(second.refresh().unwrap());
    assert!(second.rules().iter().any(|r| r.value == admins));
    assert!(!second.refresh().unwrap(), "unchanged generation");
    let (generation, stored) = store.grant_rules().unwrap();
    assert_eq!(generation, start + 1);
    let stored = stored.into_iter().find(|s| s.rule.value == admins).unwrap();
    assert_eq!(
        (stored.reason.as_str(), stored.created_at_ms),
        ("first administrator", 10)
    );

    // One rule per claim value, also across replicas.
    assert!(matches!(
        second.create(rule(&admins, &["read"]), "someone", "again", 11),
        Err(GrantRuleError::Exists(_))
    ));
    second
        .create(rule(&readers, &["read"]), "admin", "readers", 12)
        .unwrap();
    assert_eq!(store.grant_rule_generation().unwrap(), start + 2);

    assert!(first.remove(&admins).unwrap());
    assert!(!first.remove(&admins).unwrap());
    assert!(first.rules().iter().all(|r| r.value != admins));
    assert!(second.refresh().unwrap());
    assert!(second.rules().iter().all(|r| r.value != admins));
    assert!(second.rules().iter().any(|r| r.value == readers));
    assert!(second.remove(&readers).unwrap());
    assert_eq!(store.grant_rule_generation().unwrap(), start + 4);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// A store that can be cut off.
    struct Flaky {
        inner: Arc<dyn GrantRuleStore>,
        down: AtomicBool,
        /// Reads of the rules sleep this long while set.
        slow: std::sync::Mutex<Option<Duration>>,
    }

    impl Flaky {
        fn new(inner: Arc<dyn GrantRuleStore>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                down: AtomicBool::new(false),
                slow: std::sync::Mutex::new(None),
            })
        }

        fn check(&self) -> Result<()> {
            if self.down.load(Ordering::SeqCst) {
                return Err(StoreError::Database("store unreachable".into()));
            }
            Ok(())
        }
    }

    impl GrantRuleStore for Flaky {
        fn grant_rule_generation(&self) -> Result<i64> {
            self.check()?;
            self.inner.grant_rule_generation()
        }
        fn grant_rules(&self) -> Result<(i64, Vec<StoredGrantRule>)> {
            self.check()?;
            let read = self.inner.grant_rules();
            if let Some(delay) = *self.slow.lock().unwrap() {
                std::thread::sleep(delay);
            }
            read
        }
        fn insert_grant_rule(&self, rule: &StoredGrantRule) -> Result<Option<i64>> {
            self.check()?;
            self.inner.insert_grant_rule(rule)
        }
        fn delete_grant_rule(&self, value: &str) -> Result<Option<i64>> {
            self.check()?;
            self.inner.delete_grant_rule(value)
        }
    }

    /// A replica cut off from the store stops applying stored rules once
    /// the stale bound passes, and applies them again after a check
    /// succeeds.
    #[test]
    fn a_cut_off_replica_stops_applying_stored_rules() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-grant-rules-stale-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Flaky::new(Arc::new(
            crate::storage::SqliteStore::open(dir.join("tenkai.db")).unwrap(),
        ));
        let grants = StoredGrants::load_with_stale_after(
            store.clone(),
            Vec::<String>::new(),
            Duration::from_millis(50),
        )
        .unwrap();
        let rule = OidcGrantRule {
            value: "tenkai-admins".into(),
            capabilities: vec!["read".into(), "management".into()],
            environment: None,
            channels: Vec::new(),
            products: Vec::new(),
            kind: None,
        };
        grants
            .create(rule, "management-token", "first administrator", 1)
            .unwrap();
        assert_eq!(grants.rules().len(), 1);
        store.down.store(true, Ordering::SeqCst);
        assert!(grants.refresh().is_err());
        assert_eq!(grants.rules().len(), 1, "within the stale bound");
        std::thread::sleep(Duration::from_millis(80));
        assert!(grants.refresh().is_err());
        assert!(grants.is_stale());
        assert!(grants.rules().is_empty(), "fails closed");
        assert_eq!(grants.first_administrator(), FirstAdministrator::Missing);
        store.down.store(false, Ordering::SeqCst);
        assert!(!grants.refresh().unwrap());
        assert!(!grants.is_stale());
        assert_eq!(grants.rules().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn rule(value: &str) -> OidcGrantRule {
        OidcGrantRule {
            value: value.into(),
            capabilities: vec!["read".into(), "management".into()],
            environment: None,
            channels: Vec::new(),
            products: Vec::new(),
            kind: None,
        }
    }

    /// A check counts from when it was asked: an answer that took longer
    /// than the stale bound leaves the rules suspended, and an answer to an
    /// earlier read never replaces a later one.
    #[test]
    fn a_slow_answer_neither_extends_nor_overrides_newer_rules() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-grant-rules-slow-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let database = dir.join("tenkai.db");
        let store = Flaky::new(Arc::new(
            crate::storage::SqliteStore::open(&database).unwrap(),
        ));
        let writer = StoredGrants::load(
            Arc::new(crate::storage::SqliteStore::open(&database).unwrap()),
            Vec::<String>::new(),
        )
        .unwrap();
        let grants = StoredGrants::load_with_stale_after(
            store.clone(),
            Vec::<String>::new(),
            Duration::from_millis(100),
        )
        .unwrap();
        writer
            .create(rule("tenkai-admins"), "token", "first", 1)
            .unwrap();
        *store.slow.lock().unwrap() = Some(Duration::from_millis(150));
        assert!(grants.refresh().unwrap());
        assert!(grants.is_stale(), "the read began more than the bound ago");
        assert!(grants.rules().is_empty());

        // A slow read of the old rules, overtaken by a fast read of new ones.
        *store.slow.lock().unwrap() = None;
        assert!(!grants.refresh().unwrap());
        let slow = {
            let grants = grants.clone();
            let store = store.clone();
            *store.slow.lock().unwrap() = Some(Duration::from_millis(60));
            std::thread::spawn(move || grants.reload())
        };
        std::thread::sleep(Duration::from_millis(20));
        *store.slow.lock().unwrap() = None;
        writer.remove("tenkai-admins").unwrap();
        assert!(grants.refresh().unwrap());
        assert!(grants.rules().is_empty());
        slow.join().unwrap().unwrap();
        assert!(
            grants.rules().is_empty(),
            "the earlier read did not bring the removed rule back"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
