# ADR 0062: Atomic catalog actions

- Status: Accepted
- Date: 2026-11-18
- Issue: [#1304](https://github.com/Sannrox/tenkai/issues/1304)
- Owner: Tenkai maintainers
- Builds on: [ADR 0015](0015-governed-action-remote-migration.md)
- Amended-by: [ADR 0064](0064-tenkai-stands-alone.md) (§4 obsolete)

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

4. **Remote actions move to one atomic provider write.** Obsolete.
   [ADR 0064](0064-tenkai-stands-alone.md) retires `--provider-mode remote`.
   [#1566](https://github.com/Sannrox/tenkai/issues/1566) is not built.
   Tenkai-owned stores remain the atomic path in §3.

## Rejected

- Declarative edits on the governed action type: reverses ADR 0015.
- A version field on the whole-object update alone: stops lost updates but
  still leaves partial application.
- Both rule-based and client-computed actions: no caller needs server-side
  rules.

## Consequences

- An embedded action either lands entirely or leaves nothing behind.
- There is no remote catalog-provider action path. Operators who used
  `--provider-mode remote` re-initialize a Tenkai-owned store.
