# ADR 0012: Legacy graph-action compatibility boundary

- Status: Accepted
- Date: 2026-08-04
- Issue: [#208](https://github.com/Sannrox/tenkai/issues/208)
- Owner: Tenkai maintainers
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md)
- Dependency: [Sekai-Chisei #522](https://github.com/Sannrox/sekai-chisei/pull/522)

## Context

Tenkai's subscription and maintenance workflows use the legacy graph action
DSL: `ActionTypeDef` definitions are registered and later executed through
`ExecuteAction`. Sekai-Chisei 1.0 also exposes a newer governed action
registry, but `GovernedActionType` admission has different namespace,
authorization, persistence, and execution semantics.

Removing the legacy authoring RPC would leave Tenkai's remote host unable to
bootstrap the action definitions required by those workflows. Translating the
definitions into governed action types would silently change the trust and
execution contract.

## Decision

Preserve the graph-action contract with a dedicated authenticated,
action-admin-gated `CreateActionType` compatibility RPC in Sekai-Chisei. The
RPC persists and activates the exact `ActionTypeDef` used by `ExecuteAction`.
The graph `ActionTypeDef` registry and the governed `GovernedActionType`
registry remain distinct; new integrations should use
`PutGovernedActionType` and the governed action-instance APIs.

Tenkai uses this compatibility RPC only for remote graph-action registration.
Embedded Tenkai continues to register the same definitions in its local
application store. Both hosts retain the same action definitions and
execution semantics at their respective adapter boundaries.

The compatibility implementation must preserve durable creation timestamps,
serialize mutations with deletion, and refresh process-local action registries
from durable storage before action use. Missing, invalid, or unauthorized
definitions fail closed.

## Consequences

- Existing Tenkai remote subscription and maintenance workflows remain
  bootstrappable against Sekai-Chisei 1.0.
- No implicit migration or semantic widening from graph actions to governed
  actions occurs.
- Sekai-Chisei carries a small, explicitly transitional public compatibility
  surface; new clients should not depend on it for governed admission.
- Protocol fixtures, action-registry persistence, multi-instance refresh, and
  embedded/remote tests must continue to cover the boundary.
- A future removal or migration of graph actions requires a separately
  versioned decision, client migration, and failure semantics.

## Alternatives considered

### Map graph definitions into the governed action registry

Rejected because the registries have different authorization scope, durable
identity, admission, and execution semantics. A translation would make an
apparently compatible client depend on a different trust contract.

### Remove remote graph-action registration

Rejected because fresh remote Tenkai instances could not install the action
definitions required by existing subscription and maintenance workflows.

### Keep an unversioned/private server-side workaround

Rejected because it would hide a public protocol dependency, leave clients
without a durable compatibility contract, and make embedded/server equivalence
unverifiable.

## Evidence and provenance

- Tenkai issue [#208](https://github.com/Sannrox/tenkai/issues/208) defines the
  Sekai-Chisei 1.0 client and protocol migration.
- Sekai-Chisei PR
  [#522](https://github.com/Sannrox/sekai-chisei/pull/522) restores the
  compatibility RPC and its registry/persistence tests; it merged as
  `11d1787b331de8af3688aaba2655d107ef9a4ef1`.
- The client boundary is implemented in
  [`src/client.rs`](../../src/client.rs), the bootstrap registration is in
  [`src/ontology.rs`](../../src/ontology.rs), and the vendored public contract
  is pinned in [`proto/vendor/sekai.proto`](../../proto/vendor/sekai.proto).
- The portable Sekai ontology was validated before this decision. It describes
  Tenkai's host and Chisei public API boundaries but does not define these
  action-registry names; this ADR records the project decision rather than
  inferring it from ontology output.
