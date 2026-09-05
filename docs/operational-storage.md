# Operational storage

Tenkai owns releases, channel heads, environments, plans, leases, receipts,
rollback recovery state, and durable executable-wave records (ADR 0017). `OperationalStore` is the application boundary for
that authority. `SqliteStore` is the complete solo-mode adapter; future server
database adapters must pass the same immutability, lifecycle, idempotency, and
generation-fencing contract.

The store also owns the provider-event retry queue used for audit and outcome
projection. The shipped SQLite host path uses this queue for terminal outcomes;
audit and planning-event mutations remain unwired. Provider adapters can
acknowledge delivery, but cannot change or reconstruct operational truth. See
[provider contracts](provider-contracts.md) for delivery semantics.

When terminal-outcome export is configured, `EmbeddedStore` updates the
authoritative plan, deployment, or reconciled environment object and inserts
the `provider_events` row through the same SQLite transaction. A failed insert
rolls back the object update; a committed object update therefore cannot lose
its outcome row. The separately opened `SqliteStore` worker claims and
acknowledges that row through the shared database. PostgreSQL retains the same
kind-filtered outbox contract, but the current mixed enterprise composition
cannot claim atomic terminal wiring until PostgreSQL owns the corresponding
authoritative state under ADR 0010.

Server management requests and their terminal outcomes are appended to the
`audit_events` table. Audit identifiers are immutable and survive server
restart. The table contains principals, operation/resource identifiers, and
outcomes only; bearer credentials and request secrets are never persisted.

Remote runtime claims are durable, environment-scoped, expiring, and
generation-fenced. Their completion payload retains per-step receipts and is
immutable after the first accepted completion. Tokens are represented only by
a one-way owner digest bound to a fresh process instance; raw runtime
credentials are not stored. Heartbeats atomically renew only an unexpired claim
with the same owner and generation and never acquire work. If completion
persistence wins before the authoritative plan transition finishes, the same
owner receives the completed claim again and can replay the identical
completion until the plan is terminal.

Offline receipt imports persist the first verified completion under the signed
bundle digest before applying it through the normal plan lifecycle. Repeating
the same canonical receipt is idempotent; different receipt content for that
bundle digest is an immutable conflict. This record survives a restart between
verification and lifecycle completion, so an identical import can safely
finish recovery.

SQLite databases are migrated transactionally when opened. Tenkai refuses to
open a database whose schema is newer than the binary supports. Use
`tenkaictl backup <destination>` for a live, consistent snapshot; do not copy a
database and its WAL files sequentially. Stop every writer before
`tenkaictl restore <source>`. Restore and integrity checks require no provider.

### Embedded object property index

The embedded catalog store (`EmbeddedStore`, schema version **4**) maintains an
`embedded_object_properties` index for kind+key+value lookups and the
Tenkai-owned `provider_events` outbox. Provider outbox rows retain an immutable
observation timestamp for bounded inspection; retry scheduling remains
separate delivery state. Plan work selection (`pending_work`,
reconcile admission, orphan recovery, environment plan summary) queries plans
**by environment** through that index rather than loading every `tenkai.plan`
row and filtering in process. Opening a v1 or v2 embedded database backfills
the required structures and advances the schema version; empty kind/key or
environment arguments fail closed (no unscoped fallback).

Status filters, `created_at` order, and `LIMIT` for newest/oldest reads are
applied in that SQL for the embedded host; remote catalog lookups keep the
same semantics in process. Zero-step Computed plans are not persisted: a
no-op reconcile reports Current without writing history or serving an empty
plan to a runtime agent. Stored empty Computed/Running rows are retired to
Succeeded (`no-op; environment already current`) on the next reconcile so they
leave work selection.

## Tenant isolation adapter

Community SQLite (`SqliteStore`) is tenant-free. Enterprise hosts that require
tenant mode must compose a store that advertises `tenant_isolation` and enforces
tenant-scoped access. The public repository ships an in-memory multi-tenant
adapter for conformance and host wiring:

- Source: `src/tenant_store.rs`
- Capability helper: `tenant_memory_store_capabilities()`
- Isolation outcomes: [tenant-isolation-conformance.md](tenant-isolation-conformance.md)
- Production criteria: [ADR 0008](decisions/0008-production-tenant-operational-store.md)

Do not enable tenant mode against community SQLite. Do not co-locate identity
plane tables with Tenkai operational partitions.

Optional production multi-tenant Postgres for the **control-plane hub** is
available behind Cargo feature `postgres` (`src/postgres_tenant.rs`). See
[postgres-tenant-store.md](postgres-tenant-store.md). Community default remains
SQLite. Multi-replica hub operations:
[multi-replica-hub-runbook.md](multi-replica-hub-runbook.md).

## Embedded-to-server migration

Embedded and server hosts use the same SQLite file and domain contracts. The
cutover is operational rather than a data reinterpretation:

1. Stop embedded reconcile loops and wait for active applies to finish.
2. Run `tenkaictl inspect` and reconcile any environment whose deployment state
   is unknown.
3. Run `tenkaictl backup /secure/tenkai-cutover.db`.
4. Copy that backup to the server host and restore it into the configured
   `TENKAI_DATABASE`.
5. Start `tenkai-server` in its default embedded-provider mode. Verify
   `/readyz`, inspect the first reconciliation result, and only then enable
   environment runtime credentials.
6. Keep the pre-cutover database read-only until rollback testing is complete.

Do not run the embedded CLI and server as concurrent mutation controllers for
the same environments. SQLite prevents database corruption, but it cannot make
two hosts a highly available control plane. Development-only unsigned release
permission is a per-publish CLI choice and is never enabled implicitly by
server startup.

Older sekai-backed v0 installations require an explicit republish and
reconciliation cutover: archive the graph for audit, initialize embedded state,
republish releases, recreate channels and environments, and record each
verified deployed version with `tenkaictl env reconcile` before applying.

Release payloads and runtime files do not belong in this database. The database
stores content descriptors and recovery authority; content remains in a
digest-verifying content store, and runtime state remains environment-scoped.
