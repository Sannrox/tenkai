# ADR 0015: Governed-action remote migration

- Status: Accepted
- Date: 2026-08-12
- Owner: Tenkai maintainers
- Related: [ADR 0012](0012-legacy-graph-action-compatibility-boundary.md), [ADR 0014](0014-versioned-rust-client-facade.md)
- Supersedes: [ADR 0012](0012-legacy-graph-action-compatibility-boundary.md)
- Dependency: [Sekai-Chisei #587](https://github.com/Sannrox/sekai-chisei/pull/587)

## Context

ADR 0012 preserved Tenkai's remote subscription and maintenance bootstrap on a
transitional `CreateActionType` / `ExecuteAction` compatibility surface. Sekai
Chisei later removed the legacy graph Actions DSL before v1 (#587): field 17 on
`CapabilityEntry` is reserved, and the public contract exposes only the governed
Action Type / ActionInstance / effect / work RPCs.

Keeping Tenkai pinned to a pre-#587 `sekai-client` revision would leave remote
hosts calling removed RPCs. Restoring `CreateActionType` on Sekai Chisei was
rejected upstream.

## Decision

Align Tenkai's remote host with the governed action surface:

1. Vendor `proto/vendor/sekai.proto` (and `chisei.proto`) from Sekai Chisei main
   after #587/#605 and pin `sekai-client` to
   `67157d1fa242ac2f133c88243ef23b56f88042e6`.
2. Remote registration uses `PutGovernedActionType` with a closed parameter
   schema derived from Tenkai's action params (including required target `id`).
3. Remote execution uses `SubmitActionInstance` for admission. On `admitted`,
   Tenkai applies the same mutation plan through ordinary graph RPCs
   (`UpdateObject` / `CreateLink` / `DeleteLink`) and records
   `execute_action` decision evidence via `RecordDecision` so maintenance
   fail-closed evidence remains content-bound.
4. Missing, disabled, denied, unauthorized, or `require_approval` admissions
   fail closed. Deferred deny is not available on the governed path because
   require_approval submissions are already denied at admit time.
5. Embedded Tenkai keeps a local graph-action definition store using
   Tenkai-owned protobuf messages in `proto/tenkai/graph_action.proto` that
   preserve the pre-1.0 `ActionTypeDef` wire layout for existing SQLite
   payloads. Embedded trust and mutation semantics are unchanged.

The graph-action mutation plan remains Tenkai-owned application knowledge. It
is not reintroduced into the Sekai public contract.

## Consequences

- Remote Tenkai compiles and operates against post-#587 Sekai Chisei.
- ADR 0012's transitional compatibility assumption is obsolete.
- Remote preview is a type/policy gate only; faithful admission happens on
  submit. Maintenance and emergency-override callers still fail closed on
  non-allow decisions.
- Custom remote actions registered only in another process are not executable
  unless the local Tenkai process knows the mutation plan (`known_action` or
  same-process registration cache).
- Protocol, client-pin, and action-lifecycle tests must cover governed
  registration, admit-then-mutate execution, and embedded parity.

## Alternatives considered

### Restore CreateActionType on Sekai Chisei

Rejected. The RPC was intentionally removed before v1; reintroducing it would
revive a retired mutation-authority surface.

### Translate graph ops into governed effect payloads only

Rejected for this change. Effect kinds do not replace Tenkai's graph mutation
plan, and `external_mutate` remains skipped at admit time by design.

### Break embedded graph-action storage

Rejected. Embedded hosts must keep working without silently changing local
trust boundaries or invalidating stored action-type payloads.

## Evidence and provenance

- Sekai-Chisei PR [#587](https://github.com/Sannrox/sekai-chisei/pull/587)
  removed the legacy Actions DSL; tip pin includes later main commits through
  [#605](https://github.com/Sannrox/sekai-chisei/pull/605).
- Client boundary: [`src/client/action_lifecycle.rs`](../../src/client/action_lifecycle.rs)
- Bootstrap definitions: [`src/ontology.rs`](../../src/ontology.rs)
- Embedded local store: [`src/embedded.rs`](../../src/embedded.rs)
- Vendored contract: [`proto/vendor/sekai.proto`](../../proto/vendor/sekai.proto)
- Embedded-only wire types: [`proto/tenkai/graph_action.proto`](../../proto/tenkai/graph_action.proto)
