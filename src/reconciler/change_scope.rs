//! Change-driven tick scope (#1569).
//!
//! A periodic tick evaluates an environment only when one of these holds:
//!
//! - a store write since its last evaluation touched it (the store write log);
//! - its last pass was not `Current`, so open plans, holds, approval waits,
//!   failures and backoff are evaluated every tick, as before;
//! - its staggered recheck is due, which bounds how long a change the log
//!   cannot see (a clock-driven input, or a write by an older version that
//!   does not log) waits.
//!
//! The first tick of a process, or after `reset` (a writer-lease takeover),
//! evaluates everything. The cursor and quiet set are in memory: losing them
//! costs one full tick, never a missed change, because the log is durable.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use anyhow::Result;

use crate::client::Ctx;
use crate::ontology::{KIND_CHANNEL, KIND_ENVIRONMENT, KIND_INSTANCE_HEALTH, REL_SUBSCRIBES};
use crate::storage::{CATALOG_WRITE_RETENTION_MS, CatalogWrite};

/// How long after a tick its cursor stays the re-read floor. A Postgres
/// sequence can commit after a higher one; a write that commits within this
/// window behind the cursor is still read.
const REREAD_WINDOW_MS: i64 = 2 * 60 * 1000;
/// Base interval after which a quiet environment is evaluated again; each
/// environment adds a stable offset below it so rechecks spread out.
pub(super) const RECHECK_MS: i64 = 5 * 60 * 1000;
/// A cursor older than this may have lost rows to pruning: evaluate everything.
const MAX_CURSOR_AGE_MS: i64 = CATALOG_WRITE_RETENTION_MS / 2;
const PRUNE_EVERY_MS: i64 = 60 * 60 * 1000;
const PAGE: usize = 1_000;
/// More rows than this in one tick evaluate everything instead of mapping each.
const MAX_ROWS: usize = 10_000;

/// Which environments the writes since the last tick touched.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Touched {
    All,
    Only(HashSet<String>),
}

impl Touched {
    fn contains(&self, environment: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(environments) => environments.contains(environment),
        }
    }
}

#[derive(Default)]
pub(super) struct ChangeScope {
    /// `(tick time, highest sequence read)` per tick, oldest first. `None`
    /// until the first full tick, and after `reset`.
    cursor: Option<VecDeque<(i64, i64)>>,
    /// Sequences above the floor already mapped, so a re-read row wakes its
    /// environments once, not on every tick of the window.
    seen: BTreeSet<i64>,
    /// Environments whose last pass was `Current`, with when each is due again.
    quiet: HashMap<String, i64>,
    last_prune_ms: i64,
}

impl ChangeScope {
    /// Forget the cursor and quiet set; the next tick evaluates everything.
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }

    /// The sequence to read after, or `None` when this tick must be full.
    fn floor(&self, now: i64) -> Option<i64> {
        let cursor = self.cursor.as_ref()?;
        let (newest_at, _) = *cursor.back()?;
        if now.saturating_sub(newest_at) > MAX_CURSOR_AGE_MS {
            return None;
        }
        let cutoff = now.saturating_sub(REREAD_WINDOW_MS);
        cursor
            .iter()
            .rev()
            .find(|(at, _)| *at <= cutoff)
            .or_else(|| cursor.front())
            .map(|(_, high)| *high)
    }

    /// Keep the rows not mapped before, and remember them as mapped.
    fn unseen(&mut self, floor: i64, rows: Vec<CatalogWrite>) -> Vec<CatalogWrite> {
        self.seen = self.seen.split_off(&floor.saturating_add(1));
        rows.into_iter()
            .filter(|row| self.seen.insert(row.seq))
            .collect()
    }

    fn advance(&mut self, now: i64, high: i64) {
        let cursor = self.cursor.get_or_insert_with(VecDeque::new);
        let high = cursor.back().map_or(high, |(_, last)| high.max(*last));
        cursor.push_back((now, high));
        // Keep the newest entry old enough to be the floor, and everything after.
        let cutoff = now.saturating_sub(REREAD_WINDOW_MS);
        while cursor.len() > 1 && cursor.get(1).is_some_and(|(at, _)| *at <= cutoff) {
            cursor.pop_front();
        }
    }

    /// Whether `environment` is evaluated on this tick.
    pub(super) fn due(&self, environment: &str, touched: &Touched, now: i64) -> bool {
        touched.contains(environment)
            || self
                .quiet
                .get(environment)
                .is_none_or(|recheck_at| *recheck_at <= now)
    }

    /// Record a pass outcome: only `Current` makes an environment quiet.
    pub(super) fn record(&mut self, environment: &str, current: bool, now: i64) {
        if current {
            let recheck_at = now
                .saturating_add(RECHECK_MS)
                .saturating_add(stagger(environment));
            self.quiet.insert(environment.into(), recheck_at);
        } else {
            self.quiet.remove(environment);
        }
    }

    /// Drop quiet entries of environments that left the fleet.
    pub(super) fn retain(&mut self, environments: &[String]) {
        let listed: HashSet<&str> = environments.iter().map(String::as_str).collect();
        self.quiet
            .retain(|environment, _| listed.contains(environment.as_str()));
    }
}

/// A stable offset in `[0, RECHECK_MS)`, so environments made quiet by one
/// full tick do not all come due on the same later tick.
fn stagger(environment: &str) -> i64 {
    let hash = environment
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        });
    i64::try_from(hash % RECHECK_MS.unsigned_abs()).unwrap_or(0)
}

/// Read the write log since the last tick, advance the cursor, and map the
/// rows to environments. Holds `scope` only between store reads.
pub(super) async fn touched(
    ctx: &mut Ctx,
    scope: &std::sync::Mutex<ChangeScope>,
) -> Result<Touched> {
    let now = crate::now_millis();
    prune(ctx, scope, now).await?;
    let floor = scope.lock().expect("change scope lock").floor(now);
    let Some(floor) = floor else {
        // Full tick: start the cursor at the newest write. A context without
        // a write log (remote) leaves it unset, so every tick stays full.
        if let Some(high) = ctx.latest_write().await? {
            scope.lock().expect("change scope lock").advance(now, high);
        }
        return Ok(Touched::All);
    };
    let mut rows = Vec::new();
    let mut after = floor;
    loop {
        let Some(page) = ctx.writes_after(after, PAGE).await? else {
            return Ok(Touched::All);
        };
        let full_page = page.len() == PAGE;
        if let Some(last) = page.last() {
            after = last.seq;
        }
        rows.extend(page);
        if !full_page || rows.len() > MAX_ROWS {
            break;
        }
    }
    let rows = {
        let mut scope = scope.lock().expect("change scope lock");
        scope.advance(now, after);
        if rows.len() > MAX_ROWS {
            return Ok(Touched::All);
        }
        scope.unseen(floor, rows)
    };
    environments_of(ctx, &rows).await
}

async fn prune(ctx: &mut Ctx, scope: &std::sync::Mutex<ChangeScope>, now: i64) -> Result<()> {
    {
        let mut scope = scope.lock().expect("change scope lock");
        if now.saturating_sub(scope.last_prune_ms) < PRUNE_EVERY_MS {
            return Ok(());
        }
        scope.last_prune_ms = now;
    }
    ctx.prune_writes(now.saturating_sub(CATALOG_WRITE_RETENTION_MS))
        .await
}

/// Map write-log rows to the environments they can change. Anything that
/// cannot be placed in one environment touches all of them.
async fn environments_of(ctx: &mut Ctx, rows: &[CatalogWrite]) -> Result<Touched> {
    let mut seen = HashSet::new();
    let mut environments = HashSet::new();
    for row in rows {
        if !seen.insert((row.object_id.as_str(), row.kind.as_str())) {
            continue;
        }
        match row.kind.as_str() {
            // A pass never reads health; a plan its gates read is open, so its
            // environment is evaluated every tick anyway. Each report replaces
            // the previous object, so mapping it would wake the environment
            // on every report.
            KIND_INSTANCE_HEALTH => {}
            KIND_ENVIRONMENT => match row.object_id.strip_prefix("tenkai:env:") {
                Some(name) => {
                    environments.insert(name.to_string());
                }
                None => return Ok(Touched::All),
            },
            KIND_CHANNEL => {
                for subscriber in ctx.linked(&row.object_id, REL_SUBSCRIBES, "in").await? {
                    match environment_of(&subscriber) {
                        Some(name) => environments.insert(name),
                        None => return Ok(Touched::All),
                    };
                }
            }
            _ => match ctx.get(&row.object_id).await? {
                Some(object) => match environment_of(&object) {
                    Some(name) => {
                        environments.insert(name);
                    }
                    None => return Ok(Touched::All),
                },
                // Deleted: what it belonged to is gone with it.
                None => return Ok(Touched::All),
            },
        }
    }
    Ok(Touched::Only(environments))
}

/// The one environment an object belongs to: an environment itself, or an
/// object that names it in its `environment` property.
fn environment_of(object: &crate::pb::record::Object) -> Option<String> {
    if object.kind == KIND_ENVIRONMENT {
        return Some(object.name.clone()).filter(|name| !name.is_empty());
    }
    object
        .properties
        .get("environment")
        .filter(|name| !name.is_empty())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_rereads_a_window_behind_the_cursor() {
        let mut scope = ChangeScope::default();
        assert_eq!(scope.floor(0), None, "the first tick is full");
        scope.advance(0, 10);
        scope.advance(60_000, 20);
        // Less than the window after the first tick: read from its high.
        assert_eq!(scope.floor(90_000), Some(10));
        // Once the second tick is a window old, it becomes the floor.
        assert_eq!(scope.floor(60_000 + REREAD_WINDOW_MS), Some(20));
        scope.reset();
        assert_eq!(scope.floor(60_000 + REREAD_WINDOW_MS), None);
    }

    #[test]
    fn a_reread_row_is_mapped_once() {
        let row = |seq| CatalogWrite {
            seq,
            object_id: format!("tenkai:env:e{seq}"),
            kind: KIND_ENVIRONMENT.into(),
        };
        let seqs = |rows: Vec<CatalogWrite>| rows.iter().map(|row| row.seq).collect::<Vec<_>>();
        let mut scope = ChangeScope::default();
        assert_eq!(seqs(scope.unseen(10, vec![row(11), row(13)])), [11, 13]);
        // 12 committed late, behind 13: only it is new on the re-read.
        assert_eq!(
            seqs(scope.unseen(10, vec![row(11), row(12), row(13)])),
            [12]
        );
        // Once the floor passes a sequence, it is forgotten.
        scope.unseen(12, Vec::new());
        assert_eq!(scope.seen, BTreeSet::from([13]));
    }

    #[test]
    fn a_stale_cursor_makes_the_tick_full() {
        let mut scope = ChangeScope::default();
        scope.advance(0, 10);
        assert_eq!(scope.floor(MAX_CURSOR_AGE_MS + 1), None);
    }

    #[test]
    fn only_a_current_pass_is_quiet_until_its_recheck() {
        let mut scope = ChangeScope::default();
        let none = Touched::Only(HashSet::new());
        assert!(scope.due("prod", &none, 0), "never evaluated");
        scope.record("prod", true, 0);
        assert!(!scope.due("prod", &none, 1));
        assert!(scope.due("prod", &Touched::Only(HashSet::from(["prod".into()])), 1));
        assert!(scope.due("prod", &Touched::All, 1));
        assert!(scope.due("prod", &none, 2 * RECHECK_MS));
        scope.record("prod", false, 1);
        assert!(
            scope.due("prod", &none, 2),
            "a pass that was not Current stays due"
        );
    }

    #[tokio::test]
    async fn writes_map_to_the_environments_they_change() {
        use crate::pb::record::Object;
        let (database, mut ctx) =
            super::super::tests::registered_ctx("change-scope-map", &["stage", "env-b", "env-c"])
                .await;
        let scope = std::sync::Mutex::new(ChangeScope::default());
        let only =
            |names: &[&str]| Touched::Only(names.iter().map(|name| (*name).into()).collect());
        assert_eq!(
            touched(&mut ctx, &scope).await.unwrap(),
            Touched::All,
            "a new scope is full"
        );

        // A health report, and the delete of the one it replaces, touch nothing.
        let health = Object {
            id: "tenkai:health:stage:i-1".into(),
            kind: KIND_INSTANCE_HEALTH.into(),
            properties: [("environment".into(), "stage".into())].into(),
            ..Object::default()
        };
        ctx.put(health.clone()).await.unwrap();
        ctx.delete(&health.id).await.unwrap();
        assert_eq!(touched(&mut ctx, &scope).await.unwrap(), only(&[]));

        // A channel and its head touch exactly its subscribers.
        super::super::tests::put_product_channel(&mut ctx, "api").await;
        ctx.link(
            &crate::ontology::env_id("env-b"),
            "tenkai:channel:api/stable",
            REL_SUBSCRIBES,
        )
        .await
        .unwrap();
        assert_eq!(
            touched(&mut ctx, &scope).await.unwrap(),
            only(&["stage", "env-b"])
        );

        // An object that names no environment touches all of them.
        ctx.put(Object {
            id: "tenkai:conformance:unscoped".into(),
            kind: "tenkai.conformance".into(),
            ..Object::default()
        })
        .await
        .unwrap();
        assert_eq!(touched(&mut ctx, &scope).await.unwrap(), Touched::All);
        let _ = std::fs::remove_file(&database);
    }
}
