# ADR 0063: Change-driven reconcile ticks

- Status: Accepted
- Date: 2026-11-26
- Issue: [#1569](https://github.com/Sannrox/tenkai/issues/1569)
- Owner: Tenkai maintainers
- Builds on: [ADR 0009](0009-multi-replica-reconcile-and-ha-profile.md)

## Context

Every periodic tick evaluated every environment, whether or not anything it
depends on had changed. A steady fleet paid the full cost on every tick, and
that cost grew with fleet size.

## Decision

1. **Every store write is logged in its own transaction.** A create, put,
   delete, link or unlink appends `(seq, object_id, kind)` to
   `catalog_writes`, on SQLite, Postgres and the in-memory store. A link
   logs both endpoints. The log is kept for 24 hours.

2. **A tick maps log rows to environments.** An environment row touches
   that environment. A channel row touches the channel's subscribers, so a
   write never fans out per subscriber. Any other row touches the
   environment its object names in its `environment` property. A deleted
   object, or one that names no environment, touches all of them. Instance
   health is ignored: each report replaces the previous object, and a pass
   never reads it.

3. **A periodic tick evaluates an environment when one of these holds:**
   - a write touched it since its last evaluation;
   - its last pass was not `Current`, so open plans, holds, approval waits,
     failures and backoff are evaluated every tick, as before;
   - its recheck is due: five minutes after its last `Current` pass, plus a
     stable offset below five minutes so rechecks spread out.

   The recheck bounds how long an input that changes with no store write
   waits: a freeze or maintenance boundary, an approval file, or a write by
   an older release that does not log.

4. **No change is lost.** The cursor and the quiet set are in memory. The
   first tick of a process, the first after a writer-lease takeover, and a
   tick whose cursor is older than 12 hours evaluate everything. Each tick
   re-reads two minutes behind its cursor, because a Postgres sequence can
   commit after a higher one; a re-read row is mapped once. A tick with more
   than 10,000 rows evaluates everything.

5. **Bounded ticks are unchanged.** `run_once_for` evaluates every
   environment it names. A remote host has no write log, so its ticks stay
   full.

6. **Fresh reads before writes stay.** Only which environments a tick visits
   changes. The fenced admission and per-step checks still read fresh data,
   so a recall, hold or freeze that lands mid-pass still stops the write.

## Rejected

- A stored mark per environment, cleared after its pass: every writer must
  know which environments it affects, and clearing races a new mark. The
  log keeps the mapping in one place, in the reader.
- Marking from runtime and health handlers only when the state changed: the
  same knowledge spread over every handler.
- A configurable recheck interval: no operator needs one yet.

## Consequences

- A steady fleet evaluates only environments with work and the few whose
  recheck is due.
- `environments_total` in the tick diagnostics counts evaluated
  environments, not the fleet.
- During a rolling deploy, writes by the older release are not logged; the
  recheck and the full first tick of each new process cover them.
- The log adds one row per write and an hourly prune.
