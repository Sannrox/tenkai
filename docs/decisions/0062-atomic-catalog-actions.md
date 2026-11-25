# ADR 0062: Atomic catalog actions

- Status: Accepted
- Date: 2026-11-18
- Issue: [#1304](https://github.com/Sannrox/tenkai/issues/1304)
- Owner: Tenkai maintainers
- Builds on: [ADR 0015](0015-governed-action-remote-migration.md)

## Context

A catalog action sets properties on one target object, creates or deletes
links, and records an allow decision. Each of those was a separate write.
A missing later parameter left earlier links committed with no decision, and
concurrent writers could overwrite each other's object update.

## Decision

1. **Tenkai keeps owning action edits.** Tenkai computes the edit list from
   its own action definition: property patches and link creates or deletes,
   never a whole-object overwrite. No action semantics move into the graph
   provider, so ADR 0015 stands.

2. **Every parameter is checked before any write.** One shared planner
   resolves the action against its parameters and refuses a missing
   parameter or an unknown operation before any store or remote call.

3. **Embedded actions commit in one transaction.** The SQLite store reads
   the target, applies links and properties, records the change history and
   inserts the decision in one immediate transaction. PostgreSQL uses its
   existing action transaction and the in-memory store one lock guard. A
   dry run reads only.

4. **Remote actions move to one atomic provider write.** The remote path
   computes the same edit list, sends it as one atomic graph write bound to
   the admitted action instance with the object revision it read, then
   records the decision. A provider without the write fails closed; there is
   no fallback to separate calls. Remote `put` uses the same write with a
   bounded retry on a failed precondition. This half
   ([#1566](https://github.com/Sannrox/tenkai/issues/1566)) waits for a released
   provider that serves the write by default, and for a rule that gives a
   repeated action with unchanged parameters a fresh instance. Until then
   remote actions keep the separate calls, with parameters checked first.

## Rejected

- Declarative edits on the governed action type: reverses ADR 0015.
- A version field on the whole-object update alone: stops lost updates but
  still leaves partial application.
- Both rule-based and client-computed actions: no caller needs server-side
  rules.

## Consequences

- An embedded action either lands entirely or leaves nothing behind.
- Remote actions still apply in several calls until the remote half lands;
  a failure after a link write can leave that link without the object
  update.
