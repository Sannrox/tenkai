//! Grant rules stored in the hub's store (#836).
//!
//! OIDC grant rules map an identity-provider claim value to Tenkai
//! capabilities. The configuration file holds some; the hub's store can hold
//! more, so the first administrator can be set up and changed without editing
//! the file and restarting every replica. Effective rules are the file's plus
//! the stored ones. The file stays authoritative for what it declares: a
//! stored rule may not use a claim value the file names, and one that does
//! (because the file gained it later) is ignored. For a token the file
//! grants anything, a stored rule only adds: one that would narrow that
//! grant is skipped (#847, see `OidcAuthExtension::grants`).
//!
//! The store keeps one rule per claim value and a generation that grows with
//! every change, shared by every replica (the hub-wide tables on PostgreSQL).
//! Each replica checks the generation every [`REFRESH_INTERVAL`] and reloads
//! the rules when it moved. A change reads the rules back in its own
//! transaction, so the replica that made it applies it at once and reports
//! it done as soon as it commits, with no second read that could fail
//! after the commit (#848).
//! A replica that cannot read the store for longer than [`STALE_AFTER`]
//! stops applying stored rules (the file's still apply) until a check
//! succeeds again, so a cut-off replica never keeps honouring a rule removed
//! meanwhile; `/readyz` reports it not ready. A change whose write failed
//! may still have committed, so the replica that tried it applies no stored
//! rules, and is not ready, until it reads them again.
//! Each rule records who created it, when and why. Older replicas ignore the
//! stored rules, so they take effect everywhere only once every replica runs a
//! release with this change.
//!
//! Rows are read one at a time (#850): a row this release cannot read (a
//! newer `format`, a rule field it does not know) or a rule that fails
//! [`OidcGrantRule::validate`] (a capability it does not know) is withheld,
//! logged and listed as not applied; the other rows still apply. Withholding
//! only removes grants: a token the file grants nothing that matches a
//! withheld claim value is refused, since the missing rule might have
//! confined what the others give it.

use std::collections::{BTreeMap, BTreeSet};
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

/// The stored row format this release reads and writes. A row without
/// `format` is format 1, the shape every release since #836 writes; a row of
/// another format is withheld.
pub const STORED_FORMAT: u32 = 1;

/// A stored rule: the rule as the configuration file would hold it, and who
/// created it, when and why.
// A stored row decodes leniently around the rule (#850): unknown fields next
// to it are ignored, so they may only ever carry metadata. Anything that
// changes what a rule grants goes in `rule`, which stays strict (an unknown
// field there withholds the row), or needs a new `STORED_FORMAT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StoredGrantRule {
    pub rule: OidcGrantRule,
    /// The principal, or the management token's use, that created it.
    pub created_by: String,
    pub created_at_ms: i64,
    pub reason: String,
}

/// A stored row this release cannot read; it is never applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct UnreadableGrantRule {
    /// The claim value the row is stored under.
    pub value: String,
    /// Why it cannot be read.
    pub reason: String,
}

/// Every stored row, read together with the generation it is current at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredGrantRules {
    pub generation: i64,
    pub rules: Vec<StoredGrantRule>,
    pub unreadable: Vec<UnreadableGrantRule>,
}

impl StoredGrantRules {
    /// Decode `(value, row)` pairs as the store keeps them, one at a time:
    /// a row this release cannot read is set aside and fails nothing else.
    pub fn decode(generation: i64, rows: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut decoded = Self {
            generation,
            ..Self::default()
        };
        for (value, raw) in rows {
            match decode(&value, &raw) {
                Ok(rule) => decoded.rules.push(rule),
                Err(reason) => decoded
                    .unreadable
                    .push(UnreadableGrantRule { value, reason }),
            }
        }
        decoded
    }
}

/// The stored rules a replica applies, and the claim values of the rows it
/// withholds: unreadable, or failing validation.
#[derive(Debug, Default)]
pub struct AppliedGrantRules {
    pub rules: Vec<OidcGrantRule>,
    pub withheld: BTreeSet<String>,
}

/// Stored grant rules, shared by every replica of a hub.
pub trait GrantRuleStore: Send + Sync {
    /// The generation: 0 before the first change, then one more per change.
    fn grant_rule_generation(&self) -> Result<i64>;
    /// Every stored row with the generation they are current at, read
    /// together. A row that does not decode is returned as unreadable, not
    /// as an error.
    fn grant_rules(&self) -> Result<StoredGrantRules>;
    /// Store `rule` unless a rule for its claim value exists, the store
    /// already holds [`MAX_STORED_RULES`], or the generation is not
    /// `expected` (when given). Applied carries every row as of the write,
    /// read in its transaction.
    fn insert_grant_rule(
        &self,
        rule: &StoredGrantRule,
        expected: Option<i64>,
    ) -> Result<GrantRuleWrite>;
    /// Remove the rule for `value`, unless there is none or the generation
    /// is not `expected` (when given). Applied carries every row as of the
    /// write, read in its transaction.
    fn delete_grant_rule(&self, value: &str, expected: Option<i64>) -> Result<GrantRuleWrite>;
}

/// What a conditional write did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRuleWrite {
    /// Written; every row at the new generation, read before the commit.
    Applied(StoredGrantRules),
    /// Nothing written: the value exists (insert) or does not (delete), or
    /// the store is full.
    Refused,
    /// Nothing written: the rules changed since the caller read them.
    Stale { current: i64 },
}

impl GrantRuleWrite {
    /// The outcome of a write at generation `current`: `Stale` unless it is
    /// `expected` (when given).
    pub fn check_expected(expected: Option<i64>, current: i64) -> Option<Self> {
        expected
            .filter(|expected| *expected != current)
            .map(|_| Self::Stale { current })
    }
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
    #[error("the stored grant rules changed (generation {current}); read them again")]
    StaleGeneration { current: i64 },
    /// The generation moved and the rules already hold the change, as when
    /// a retry follows a change that committed.
    #[error(
        "the stored grant rules changed (generation {current}) and already hold this change; an earlier attempt may have written it"
    )]
    AlreadyApplied { current: i64 },
    #[error(transparent)]
    Store(#[from] StoreError),
}

struct Snapshot {
    generation: i64,
    applied: Arc<AppliedGrantRules>,
    /// When the last check the store answered was asked.
    checked_at: Instant,
    /// When a write this replica tried failed, until a read started after
    /// it succeeds: the write may have committed, so the snapshot may hold
    /// a rule it removed.
    unsure_since: Option<Instant>,
}

impl Snapshot {
    /// Whether stored rules are suspended on this replica.
    fn suspended(&self, stale_after: Duration) -> bool {
        self.unsure_since.is_some() || self.checked_at.elapsed() > stale_after
    }
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
                applied: Arc::default(),
                checked_at: Instant::now(),
                unsure_since: None,
            }),
            stale_after,
        });
        grants.reload()?;
        Ok(grants)
    }

    /// The stored rules in effect: those the configuration file does not
    /// override and this release can read and validate, and none while
    /// [`StoredGrants::is_stale`].
    pub fn rules(&self) -> Arc<AppliedGrantRules> {
        let snapshot = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        if snapshot.suspended(self.stale_after) {
            return Arc::default();
        }
        snapshot.applied.clone()
    }

    /// How many stored rows this replica withholds, at the last reload.
    pub fn withheld(&self) -> usize {
        self.snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .applied
            .withheld
            .len()
    }

    /// Why this replica does not apply a readable stored rule, if it does
    /// not.
    pub fn not_applied_reason(&self, rule: &OidcGrantRule) -> Option<String> {
        if self.config_values.contains(&rule.value) {
            return Some("the configuration file declares this claim value".into());
        }
        rule.validate().err().map(|error| error.to_string())
    }

    /// Whether stored rules are suspended: the store has not answered a
    /// check within the stale bound, or a write this replica tried failed
    /// and the rules were not read since.
    pub fn is_stale(&self) -> bool {
        self.snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .suspended(self.stale_after)
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
            .rules
            .iter()
            .any(OidcGrantRule::grants_fleet_management)
        {
            FirstAdministrator::Configured
        } else {
            FirstAdministrator::Missing
        }
    }

    /// Reload when the store's generation moved, or a failed write left
    /// the snapshot unsure; whether it did.
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
            if generation == snapshot.generation && snapshot.unsure_since.is_none() {
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

    fn reload_from(&self, started: Instant) -> Result<()> {
        let stored = self.store.grant_rules()?;
        self.apply(stored, started);
        Ok(())
    }

    /// Replace the snapshot with rules read by a check started at
    /// `started`, unless it already holds a newer generation. A generation
    /// names one set of rows, so an equal one only refreshes when the store
    /// last answered.
    fn apply(&self, stored: StoredGrantRules, started: Instant) {
        let mut applied = AppliedGrantRules::default();
        let mut not_applied = BTreeMap::new();
        for unreadable in stored.unreadable {
            applied.withheld.insert(unreadable.value.clone());
            not_applied.insert(unreadable.value, unreadable.reason);
        }
        for StoredGrantRule { rule, .. } in stored.rules {
            if self.config_values.contains(&rule.value) {
                continue;
            }
            match rule.validate() {
                Ok(()) => applied.rules.push(rule),
                Err(error) => {
                    applied.withheld.insert(rule.value.clone());
                    not_applied.insert(rule.value, error.to_string());
                }
            }
        }
        let mut snapshot = self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if stored.generation < snapshot.generation {
            return;
        }
        if stored.generation != snapshot.generation {
            for (value, reason) in &not_applied {
                eprintln!("tenkai.auth stored_grant_rule={value:?} applied=false detail={reason}");
            }
        }
        *snapshot = Snapshot {
            generation: stored.generation,
            applied: Arc::new(applied),
            checked_at: snapshot.checked_at.max(started),
            unsure_since: snapshot.unsure_since.filter(|since| *since > started),
        };
    }

    /// A write started at `started` failed and may have committed: suspend
    /// stored rules until a read started after it succeeds, and try one now.
    fn write_failed(&self, started: Instant) {
        {
            let mut snapshot = self
                .snapshot
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            snapshot.unsure_since = snapshot.unsure_since.max(Some(started));
        }
        if let Err(error) = self.reload() {
            eprintln!(
                "tenkai.auth stored_grant_rules=stale detail=a grant rule write failed and the rules cannot be read; applying none until they are: {error}"
            );
        }
    }

    /// Store a rule and apply it on this replica at once; every stored row
    /// after it. With `expected`, only while the rules are still at that
    /// generation.
    pub fn create(
        &self,
        rule: OidcGrantRule,
        created_by: &str,
        reason: &str,
        now_ms: i64,
        expected: Option<i64>,
    ) -> std::result::Result<StoredGrantRules, GrantRuleError> {
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
        let written = self.write(
            |store| store.insert_grant_rule(&stored, expected),
            |rules| {
                rules.rules.iter().any(|held| {
                    (&held.rule, &held.created_by, &held.reason)
                        == (&stored.rule, &stored.created_by, &stored.reason)
                })
            },
        )?;
        written.ok_or(GrantRuleError::Exists(stored.rule.value))
    }

    /// Remove the stored rule for `value` and apply it on this replica at
    /// once; every stored row after it, or `None` when there was no rule
    /// for `value`. With `expected`, only while the rules are still at that
    /// generation.
    pub fn remove(
        &self,
        value: &str,
        expected: Option<i64>,
    ) -> std::result::Result<Option<StoredGrantRules>, GrantRuleError> {
        self.write(
            |store| store.delete_grant_rule(value, expected),
            |rules| {
                rules.rules.iter().all(|held| held.rule.value != value)
                    && rules.unreadable.iter().all(|held| held.value != value)
            },
        )
    }

    /// Run one conditional write: apply what it committed on this replica,
    /// `None` when it was refused. On a stale generation, `holds` tells
    /// whether the current rules already hold the change, so a retry of a
    /// change that committed learns it did.
    fn write(
        &self,
        write: impl FnOnce(&dyn GrantRuleStore) -> Result<GrantRuleWrite>,
        holds: impl FnOnce(&StoredGrantRules) -> bool,
    ) -> std::result::Result<Option<StoredGrantRules>, GrantRuleError> {
        let started = Instant::now();
        match write(self.store.as_ref()) {
            Ok(GrantRuleWrite::Applied(after)) => {
                self.apply(after.clone(), started);
                Ok(Some(after))
            }
            Ok(GrantRuleWrite::Refused) => Ok(None),
            Ok(GrantRuleWrite::Stale { current }) => {
                // Best effort: a failed read leaves the plain stale answer.
                let held = self.store.grant_rules().is_ok_and(|rules| holds(&rules));
                Err(if held {
                    GrantRuleError::AlreadyApplied { current }
                } else {
                    GrantRuleError::StaleGeneration { current }
                })
            }
            Err(error) => {
                self.write_failed(started);
                Err(error.into())
            }
        }
    }

    /// Every stored row as the store holds it, with its generation: what
    /// an administrator lists, including rules the file overrides and rows
    /// this release cannot read.
    pub fn stored(&self) -> Result<StoredGrantRules> {
        self.store.grant_rules()
    }

    /// Whether the configuration file declares `value`.
    pub fn declared_by_config(&self, value: &str) -> bool {
        self.config_values.contains(value)
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

/// Encode a stored rule as the store keeps it. Format 1 rows carry no
/// `format` field, so releases before #850, which refuse unknown fields,
/// still read them during a rolling deploy.
pub fn encode(rule: &StoredGrantRule) -> Result<String> {
    serde_json::to_string(rule).map_err(|error| StoreError::Database(error.to_string()))
}

/// The row's format: absent means 1.
#[derive(Deserialize)]
struct RowFormat {
    #[serde(default = "legacy_format")]
    format: u32,
}

fn legacy_format() -> u32 {
    1
}

/// Decode one row stored under `value`; why not, when it cannot be read.
fn decode(value: &str, raw: &str) -> std::result::Result<StoredGrantRule, String> {
    let row: serde_json::Value =
        serde_json::from_str(raw).map_err(|error| format!("not a stored grant rule: {error}"))?;
    let RowFormat { format } = RowFormat::deserialize(&row)
        .map_err(|error| format!("not a stored grant rule: {error}"))?;
    if format != STORED_FORMAT {
        return Err(format!(
            "stored format {format}; this release reads format {STORED_FORMAT}"
        ));
    }
    let stored = StoredGrantRule::deserialize(row)
        .map_err(|error| format!("not readable by this release: {error}"))?;
    if stored.rule.value != value {
        return Err(format!(
            "stored under {value:?} but names claim value {:?}",
            stored.rule.value
        ));
    }
    Ok(stored)
}

/// The contract every [`GrantRuleStore`] meets, for each backend's tests:
/// `store` and `other` are two replicas' connections to one database, which
/// this run uses alone. `put_row(value, row)` stores a raw row and moves the
/// generation, as a newer release would.
#[cfg(any(test, feature = "test-support"))]
pub fn assert_grant_rule_store_contract(
    store: Arc<dyn GrantRuleStore>,
    other: Arc<dyn GrantRuleStore>,
    prefix: &str,
    put_row: &dyn Fn(&str, &str),
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
    assert!(first.rules().rules.iter().all(|r| r.value != admins));

    // A value the configuration file declares is refused.
    assert!(matches!(
        first.create(rule(&declared, &["read"]), "token", "setup", 1, None),
        Err(GrantRuleError::DeclaredByConfig(_))
    ));
    // A rule without a capability, or without a reason, is refused.
    assert!(matches!(
        first.create(rule(&admins, &[]), "token", "setup", 1, None),
        Err(GrantRuleError::Invalid(_))
    ));
    assert!(matches!(
        first.create(rule(&admins, &["read"]), "token", " ", 1, None),
        Err(GrantRuleError::Invalid(_))
    ));

    let created = first
        .create(
            rule(&admins, &["read", "management"]),
            "management-token",
            "first administrator",
            10,
            Some(start),
        )
        .unwrap();
    // The change answers with the rows it committed (#848).
    assert_eq!(created.generation, start + 1);
    let created_rule = created.rules.iter().find(|s| s.rule.value == admins);
    assert_eq!(created_rule.unwrap().created_by, "management-token");
    // A retry of a change that committed learns it did.
    assert!(matches!(
        first.create(
            rule(&admins, &["read", "management"]),
            "management-token",
            "first administrator",
            11,
            Some(start),
        ),
        Err(GrantRuleError::AlreadyApplied { current }) if current == start + 1
    ));
    // A write against a generation that moved is refused, writing nothing.
    assert!(matches!(
        second.create(rule(&readers, &["read"]), "admin", "stale", 11, Some(start)),
        Err(GrantRuleError::StaleGeneration { current }) if current == start + 1
    ));
    assert!(matches!(
        second.remove(&admins, Some(start)),
        Err(GrantRuleError::StaleGeneration { .. })
    ));
    // The writing replica applies it at once.
    assert!(first.rules().rules.iter().any(|r| r.value == admins));
    assert_eq!(first.first_administrator(), FirstAdministrator::Configured);
    assert_eq!(first.generation(), start + 1);
    // Another replica sees it once it checks the generation.
    assert!(second.rules().rules.iter().all(|r| r.value != admins));
    assert!(second.refresh().unwrap());
    assert!(second.rules().rules.iter().any(|r| r.value == admins));
    assert!(!second.refresh().unwrap(), "unchanged generation");
    let stored = store.grant_rules().unwrap();
    assert_eq!(stored.generation, start + 1);
    let stored = stored
        .rules
        .into_iter()
        .find(|s| s.rule.value == admins)
        .unwrap();
    assert_eq!(
        (stored.reason.as_str(), stored.created_at_ms),
        ("first administrator", 10)
    );

    // One rule per claim value, also across replicas.
    assert!(matches!(
        second.create(rule(&admins, &["read"]), "someone", "again", 11, None),
        Err(GrantRuleError::Exists(_))
    ));
    second
        .create(rule(&readers, &["read"]), "admin", "readers", 12, None)
        .unwrap();
    assert_eq!(store.grant_rule_generation().unwrap(), start + 2);

    let before = store.grant_rule_generation().unwrap();
    let after = first.remove(&admins, Some(before)).unwrap().unwrap();
    assert_eq!(after.generation, before + 1);
    assert!(after.rules.iter().all(|r| r.rule.value != admins));
    assert!(first.remove(&admins, None).unwrap().is_none());
    assert!(matches!(
        first.remove(&admins, Some(before)),
        Err(GrantRuleError::AlreadyApplied { .. })
    ));
    assert!(first.rules().rules.iter().all(|r| r.value != admins));
    assert!(second.refresh().unwrap());
    assert!(second.rules().rules.iter().all(|r| r.value != admins));
    assert!(second.rules().rules.iter().any(|r| r.value == readers));
    assert!(second.remove(&readers, None).unwrap().is_some());
    assert_eq!(store.grant_rule_generation().unwrap(), start + 4);

    // Rows a newer release wrote (#850): a newer format and an unknown rule
    // field are unreadable, an unknown capability fails validation, and an
    // unknown field beside the rule is ignored. Each is withheld on its own;
    // the other rules still apply.
    let row = |value: &str, rule: serde_json::Value, extra: serde_json::Value| {
        let mut row = serde_json::json!({
            "rule": rule, "created_by": "admin", "created_at_ms": 20, "reason": "newer",
        });
        row.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        put_row(value, &row.to_string());
    };
    let plain = |value: &str| serde_json::json!({"value": value, "capabilities": ["read"]});
    let (future, field, capability, annotated, garbage) = (
        format!("{prefix}-future"),
        format!("{prefix}-field"),
        format!("{prefix}-capability"),
        format!("{prefix}-annotated"),
        format!("{prefix}-garbage"),
    );
    first
        .create(rule(&readers, &["read"]), "admin", "readers", 21, None)
        .unwrap();
    row(&future, plain(&future), serde_json::json!({"format": 2}));
    let mut confined = plain(&field);
    confined["expires_at_ms"] = 1.into();
    row(&field, confined, serde_json::json!({}));
    row(
        &capability,
        serde_json::json!({"value": capability, "capabilities": ["read", "audit"]}),
        serde_json::json!({}),
    );
    row(
        &annotated,
        plain(&annotated),
        serde_json::json!({"format": 1, "labels": {"team": "ops"}}),
    );
    put_row(&garbage, "not json");
    assert!(second.refresh().unwrap());
    let applied = second.rules();
    let values: BTreeSet<&str> = applied.rules.iter().map(|r| r.value.as_str()).collect();
    assert!(values.contains(readers.as_str()) && values.contains(annotated.as_str()));
    for withheld in [&future, &field, &capability] {
        assert!(!values.contains(withheld.as_str()));
        assert!(applied.withheld.contains(withheld));
    }
    let listed = second.stored().unwrap();
    let unreadable: BTreeSet<&str> = listed.unreadable.iter().map(|u| u.value.as_str()).collect();
    assert_eq!(
        unreadable,
        BTreeSet::from([future.as_str(), field.as_str(), garbage.as_str()])
    );
    let capability_rule = listed
        .rules
        .iter()
        .find(|s| s.rule.value == capability)
        .unwrap();
    assert!(second.not_applied_reason(&capability_rule.rule).is_some());
    // Removing works on any row, readable or not.
    for value in [&readers, &future, &field, &capability, &annotated, &garbage] {
        assert!(second.remove(value, None).unwrap().is_some(), "{value}");
    }
    assert!(second.rules().withheld.is_empty());
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// A store that can be cut off.
    struct Flaky {
        inner: Arc<dyn GrantRuleStore>,
        down: AtomicBool,
        /// Reads fail while set; writes still work.
        reads_down: AtomicBool,
        /// Writes commit, then fail as if the answer was lost, while set.
        lose_write_answers: AtomicBool,
        /// Reads of the rules sleep this long while set.
        slow: std::sync::Mutex<Option<Duration>>,
    }

    impl Flaky {
        fn new(inner: Arc<dyn GrantRuleStore>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                down: AtomicBool::new(false),
                reads_down: AtomicBool::new(false),
                lose_write_answers: AtomicBool::new(false),
                slow: std::sync::Mutex::new(None),
            })
        }

        fn check(&self) -> Result<()> {
            if self.down.load(Ordering::SeqCst) {
                return Err(StoreError::Database("store unreachable".into()));
            }
            Ok(())
        }

        fn check_read(&self) -> Result<()> {
            self.check()?;
            if self.reads_down.load(Ordering::SeqCst) {
                return Err(StoreError::Database("read timed out".into()));
            }
            Ok(())
        }

        fn answer(&self, written: Result<GrantRuleWrite>) -> Result<GrantRuleWrite> {
            if self.lose_write_answers.load(Ordering::SeqCst) {
                written?;
                return Err(StoreError::Database("connection dropped".into()));
            }
            written
        }
    }

    impl GrantRuleStore for Flaky {
        fn grant_rule_generation(&self) -> Result<i64> {
            self.check_read()?;
            self.inner.grant_rule_generation()
        }
        fn grant_rules(&self) -> Result<StoredGrantRules> {
            self.check_read()?;
            let read = self.inner.grant_rules();
            if let Some(delay) = *self.slow.lock().unwrap() {
                std::thread::sleep(delay);
            }
            read
        }
        fn insert_grant_rule(
            &self,
            rule: &StoredGrantRule,
            expected: Option<i64>,
        ) -> Result<GrantRuleWrite> {
            self.check()?;
            self.answer(self.inner.insert_grant_rule(rule, expected))
        }
        fn delete_grant_rule(&self, value: &str, expected: Option<i64>) -> Result<GrantRuleWrite> {
            self.check()?;
            self.answer(self.inner.delete_grant_rule(value, expected))
        }
    }

    fn flaky_store(name: &str) -> (std::path::PathBuf, Arc<Flaky>) {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-grant-rules-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Flaky::new(Arc::new(
            crate::storage::SqliteStore::open(dir.join("tenkai.db")).unwrap(),
        ));
        (dir, store)
    }

    /// A change that commits succeeds and applies on this replica although
    /// every read after the commit fails (#848).
    #[test]
    fn a_committed_change_succeeds_when_reads_fail_after_it() {
        let (dir, store) = flaky_store("commit-reads");
        let grants = StoredGrants::load(store.clone(), Vec::<String>::new()).unwrap();
        store.reads_down.store(true, Ordering::SeqCst);
        let created = grants
            .create(rule("tenkai-admins"), "token", "first", 1, Some(0))
            .unwrap();
        assert_eq!(created.generation, 1);
        assert_eq!(grants.generation(), 1);
        assert_eq!(grants.rules().rules.len(), 1);
        let removed = grants.remove("tenkai-admins", Some(1)).unwrap().unwrap();
        assert_eq!((removed.generation, removed.rules.len()), (2, 0));
        assert!(grants.rules().rules.is_empty());
        assert!(!grants.is_stale());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A remove whose answer is lost may have committed: this replica
    /// applies no stored rule, and is not ready, until it reads them again.
    /// A retry then learns the change landed.
    #[test]
    fn a_write_without_an_answer_suspends_stored_rules_until_a_read() {
        let (dir, store) = flaky_store("lost-answer");
        let grants = StoredGrants::load(store.clone(), Vec::<String>::new()).unwrap();
        grants
            .create(rule("tenkai-admins"), "token", "first", 1, None)
            .unwrap();
        grants
            .create(rule("tenkai-operators"), "token", "second", 1, None)
            .unwrap();
        store.reads_down.store(true, Ordering::SeqCst);
        store.lose_write_answers.store(true, Ordering::SeqCst);
        assert!(matches!(
            grants.remove("tenkai-admins", Some(2)),
            Err(GrantRuleError::Store(_))
        ));
        assert!(grants.rules().rules.is_empty(), "fails closed");
        assert!(grants.is_stale());
        assert!(grants.refresh().is_err());
        assert!(grants.is_stale());

        store.reads_down.store(false, Ordering::SeqCst);
        store.lose_write_answers.store(false, Ordering::SeqCst);
        assert!(grants.refresh().unwrap());
        assert!(!grants.is_stale());
        let values: Vec<_> = grants
            .rules()
            .rules
            .iter()
            .map(|r| r.value.clone())
            .collect();
        assert_eq!(values, ["tenkai-operators"]);
        assert!(matches!(
            grants.remove("tenkai-admins", Some(2)),
            Err(GrantRuleError::AlreadyApplied { current: 3 })
        ));
        // The same holds when the store answers the read the write starts.
        store.lose_write_answers.store(true, Ordering::SeqCst);
        assert!(grants.remove("tenkai-operators", Some(3)).is_err());
        assert!(
            !grants.is_stale(),
            "the read after the failed write cleared it"
        );
        assert!(grants.rules().rules.is_empty());
        let _ = std::fs::remove_dir_all(dir);
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
            .create(rule, "management-token", "first administrator", 1, None)
            .unwrap();
        assert_eq!(grants.rules().rules.len(), 1);
        store.down.store(true, Ordering::SeqCst);
        assert!(grants.refresh().is_err());
        assert_eq!(grants.rules().rules.len(), 1, "within the stale bound");
        std::thread::sleep(Duration::from_millis(80));
        assert!(grants.refresh().is_err());
        assert!(grants.is_stale());
        assert!(grants.rules().rules.is_empty(), "fails closed");
        assert_eq!(grants.first_administrator(), FirstAdministrator::Missing);
        store.down.store(false, Ordering::SeqCst);
        assert!(!grants.refresh().unwrap());
        assert!(!grants.is_stale());
        assert_eq!(grants.rules().rules.len(), 1);
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

    /// Format 1 rows keep the shape releases before #850 read, which refuse
    /// unknown fields, so a rolling deploy can still mix them.
    #[test]
    fn rows_keep_the_shape_older_releases_read() {
        let stored = StoredGrantRule {
            rule: rule("tenkai-admins"),
            created_by: "admin".into(),
            created_at_ms: 1,
            reason: "first".into(),
        };
        let row: serde_json::Value = serde_json::from_str(&encode(&stored).unwrap()).unwrap();
        let keys: BTreeSet<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from(["rule", "created_by", "created_at_ms", "reason"])
        );
        assert_eq!(decode("tenkai-admins", &row.to_string()), Ok(stored));
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
            .create(rule("tenkai-admins"), "token", "first", 1, None)
            .unwrap();
        *store.slow.lock().unwrap() = Some(Duration::from_millis(150));
        assert!(grants.refresh().unwrap());
        assert!(grants.is_stale(), "the read began more than the bound ago");
        assert!(grants.rules().rules.is_empty());

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
        writer.remove("tenkai-admins", None).unwrap();
        assert!(grants.refresh().unwrap());
        assert!(grants.rules().rules.is_empty());
        slow.join().unwrap().unwrap();
        assert!(
            grants.rules().rules.is_empty(),
            "the earlier read did not bring the removed rule back"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
