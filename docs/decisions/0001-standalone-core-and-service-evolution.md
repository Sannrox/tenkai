# ADR 0001: Standalone core and service evolution

- Status: Accepted
- Date: 2026-07-22
- Issue: [#16](https://github.com/Sannrox/tenkai/issues/16)

## Context

Tenkai currently runs as one local CLI process and persists its domain objects in
sekai-chisei. That prototype does not define which system remains authoritative
as Tenkai grows into a networked control plane, which contracts local and remote
execution share, or which dependencies are required for recovery. Treating the
current process layout or the sekai graph representation as the future service
boundary would couple availability, security, and migrations to optional
integrations.

## Decision

Tenkai is one application core with two deployment shapes:

- **Embedded:** `tenkaictl` hosts the core in process for deterministic one-shot
  operation. It uses the same application ports and transaction rules as the
  server shape; the CLI is not a second implementation.
- **Server:** a long-running control-plane host exposes authenticated APIs,
  schedules reconciliation, and connects scoped environment runtimes. Splitting
  processes does not change the core domain contracts.

The core owns decisions and lifecycle state. Infrastructure is reached through
ports whose required or optional status is explicit at startup and at each
operation. Process boundaries may move; ownership does not.

### State ownership

| State | Authoritative owner | Invariant |
| --- | --- | --- |
| Releases and immutable content descriptors | Tenkai Catalog | A product version resolves to one content identity forever. |
| Channel heads and promotion history | Tenkai Catalog | Head changes are ordered, authorized mutations. |
| Environments, subscriptions, facts, and constraints | Tenkai core | Planning reads a consistent environment revision. |
| Plans, approvals, and execution lifecycle | Tenkai core | A plan is immutable after approval; status advances idempotently. |
| Environment leases and fencing generations | Tenkai core | Only the current generation may mutate execution state. |
| Step receipts and observations | Tenkai core | Receipt identity makes retries and imports idempotent. |
| Rollback intent, checkpoints, and terminal outcome | Tenkai core | Recovery can finish from Tenkai-owned state alone. |

The persistence adapter stores this Tenkai-owned operational model. A sekai
projection may represent the same concepts for lineage, audit, policy, and
learning, but is not the operational source of truth. Projection identifiers
and cursors belong to integration metadata; they cannot be required to
reconstruct or recover a deployment.

Release payload bytes are not operational database rows. The Catalog records
content-addressed descriptors (digest, size, media type, locations, signature
and provenance references); payloads live in external OCI registries or blob
stores and are verified when read. Local development may use a filesystem
content store implementing the same contract.

### Application contracts

The core has transport-independent use cases for publishing, promotion,
environment mutation, planning, approval, work acquisition, receipt recording,
reconciliation, and recovery. Each call carries a principal, request identity,
and cancellation/deadline context and returns typed domain failures.

Embedded commands call these contracts directly. Server APIs authenticate and
authorize a request, then call the same contracts. Network DTOs, database rows,
and sekai objects do not enter the domain API. Transactions and idempotency
boundaries therefore remain identical in both shapes.

The **Catalog is an in-process module and application boundary**, not initially
a network service. It owns releases, channel heads, immutable descriptors, and
their authorization rules behind an interface used by planning and publishing.
This prevents callers from depending on its storage schema while avoiding a
premature distributed transaction.

### Providers and failure behavior

Provider requirements are declared by the selected operation and deployment
configuration:

- The operational store and the configured content store are **required**.
  Startup or an operation fails closed if their durable guarantees, schema
  version, or health cannot be established.
- An authorization or approval provider is **required** wherever policy marks
  the decision governed. Timeout, malformed response, stale evidence, or
  unavailability denies the decision; there is no implicit allow.
- sekai audit/lineage projection, chisei eval and learning, notifications, and
  secondary indexes are **optional only when the operation's policy does not
  require their evidence**. Their failure produces visible degraded health,
  durable retry/outbox state, and operator-facing status. It is never reported
  as success or silently dropped.
- A provider becomes required for a specific plan when its evidence is embedded
  in that plan's approval or gate contract. Planning and execution fail closed
  until valid evidence is available.
- A gate bypass is a separate break-glass decision, not absence of a gate. It
  requires an authenticated principal, non-empty reason, explicit authorization,
  and immutable audit evidence bound to the plan. If override authorization is
  unavailable or invalid, execution fails closed. Imported v0 plans retain their
  original version and recorded bypass evidence and cannot be silently upgraded
  into an authorized override.

Rollback selection, checkpoints, leases, receipts, deployed-state observations,
and repair commands use the operational store and content descriptors. No
optional provider is on the recovery path. Recovery may replay pending
projections after the environment reaches a known terminal state.

### Environment runtime scope

An environment runtime is configured for exactly one environment identity and
one trust scope. It receives immutable, authorized plan work; verifies the plan,
fencing generation, content digests, and approvals; executes idempotent steps;
and returns signed or authenticated receipts and observations.

Credentials are runtime configuration, never plan or bundle content. Work
acquisition and receipt APIs enforce environment scope server-side. Runtime
files, locks, and cached content are namespaced by environment and content
identity. A compromised runtime therefore cannot request another environment's
work or authorize a new plan, though it retains the privileges necessary to
change its own target.

### Catalog extraction criteria

Keep Catalog in process until all of the following are true:

1. Independent scaling or availability is demonstrated by measured publish/read
   load, isolation requirements, or a distinct operating team.
2. The application interface has a versioned remote form with compatibility and
   idempotency tests.
3. Cross-boundary promotion and planning consistency has a documented protocol;
   extraction must not introduce an unhandled distributed transaction.
4. Authentication, authorization, rate limits, observability, backup, restore,
   and incident ownership exist for the new service.
5. A dual-read or shadow-validation migration proves parity and has a rollback
   path before authority moves.

Code organization alone, database size, or a desire for symmetric services is
not sufficient reason to extract it.

## Consequences

### Compatibility and migration

- Application ports are the stable compatibility seam. CLI flags and future
  APIs may evolve independently through explicit versioning and translation.
- Existing sekai-backed state requires a one-time, resumable import into the
  Tenkai operational schema. The importer verifies counts and content identities,
  records a high-water mark, supports shadow reads, and leaves the old graph
  unchanged for rollback. Authority changes only after validation and an
  operator-selected cutover; mixed writers are forbidden.
- Plans and receipts created before a schema or protocol change retain their
  original version and deterministic decoder. Unsupported versions fail visibly
  rather than being reinterpreted.
- External artifact locations may change without changing release identity;
  digest and signature verification remains mandatory.

### Security

- The server authenticates transports and authorizes use cases; the core also
  enforces domain scope so alternate transports cannot bypass it.
- Provider credentials remain in host/runtime secret stores and are redacted
  from plans, receipts, logs, bundles, and projections.
- Content is untrusted until digest, size, and required signature/provenance
  checks pass. Cache hits do not skip verification.
- Environment-scoped identity, fencing, replay-resistant receipt identities,
  bounded payloads, and audit events limit environment-runtime and provider
  blast radius.

### Availability and operations

- Embedded mode remains useful with local durable storage and a filesystem
  content store. Server mode can scale hosts only after the operational store
  provides transactional fencing and coordination.
- Required-provider loss blocks affected mutations. Optional-provider loss
  degrades enrichment while durable outbox retries make lag inspectable.
- Backups must cover the operational store plus Catalog descriptors. Artifact
  stores retain payloads by digest under their own durability policy. Restore is
  tested without sekai, chisei, notification, or learning providers.

## Rejected alternatives

- **sekai as the operational source of truth:** couples safe execution and
  recovery to an integration's availability and object model.
- **Separate services immediately:** adds authentication, compatibility, and
  distributed consistency before workload evidence justifies them.
- **Different local and server implementations:** allows semantics, recovery,
  and authorization to drift between deployment shapes.
- **Artifacts in the operational database:** couples large immutable content to
  transactional state backup, scaling, and retention.

## Follow-up boundaries

- Issue #2 hosts reconciliation around the shared application contracts and
  Tenkai-owned leases; one-shot execution remains an embedded host.
- Issue #5 adds the scoped environment runtime and remote transport without
  moving plan, lease, receipt, or rollback ownership out of the core.
- Issue #8 packages content-addressed release inputs and versioned plans for
  offline execution; receipt import targets the same core contract.
