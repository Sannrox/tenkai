# ADR 0029: Hub and spoke operational store, one port

- Status: Accepted
- Date: 2026-09-13
- Issue: [#373](https://github.com/Sannrox/tenkai/issues/373)
- Discussion: [#381](https://github.com/Sannrox/tenkai/discussions/381)
- Owner: Tenkai maintainers
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [ADR 0008](0008-production-tenant-operational-store.md),
  [ADR 0010](0010-supported-operating-profiles.md),
  [Operational storage](../operational-storage.md)

> Later record: Context below is the pre-decision world as of 2026-09-13.
> Live hosts now open [`SqliteStore`](../../src/storage.rs) (typed schema 11).
> [`EmbeddedStore`](../../src/embedded.rs) remains a schema-5 import fixture.
> See [operational storage](../operational-storage.md).

## Context

Three persistence designs coexist in one product:

| Design | Schema | Role then |
| --- | --- | --- |
| `SqliteStore` (`OperationalStore`) | 10 | Typed releases, channels, environments, plans, leases, receipts, rollback, outbox, audit, runtime claims |
| `EmbeddedStore` | 5 | Sekai-shaped objects, links, actions, leases, and a property index so embedded planning can speak in "objects" without a live plane |
| `PostgresTenantPartition` (`OperationalStore`) | 10 | Optional feature `postgres` tenant hub; implements the same typed port |

`Ctx::embedded` opens `EmbeddedStore` on `.tenkai-state/tenkai.db`. Tests also
open `SqliteStore` on that same file. The server can open SQLite for host state
while PostgreSQL holds tenant partitions. ADR 0010 already forbids advertising
that mixed composition as a supported recovery model, and requires one
authoritative backend per process. It does not retire the object graph.

The object graph duplicates a model the governance plane already owns. Recovery
semantics, migrations, and tests are triplicated. A graph row is not a typed
plan, and a typed plan is not a graph row. Cached or projected objects must not
become a second system of record.

## Evidence collected

Inspected `origin/main` at `3840838`.

### Feature matrix

| Capability | `EmbeddedStore` | `SqliteStore` | Postgres tenant |
| --- | :---: | :---: | :---: |
| Typed `OperationalStore` verbs |  | ✓ | ✓ |
| Object/link/action/schema graph | ✓ |  |  |
| Plan property index (`has_steps`, environment, status) | ✓ |  |  |
| Transactional terminal-outcome enqueue with object put | ✓ | separate worker on same file | contract retained, atomic wiring gated |
| `tenkaictl backup` / `restore` | ✓ SQLite | ✓ SQLite | PostgreSQL-native, profile gated |
| Tenant isolation |  |  | ✓ when advertised |
| Shared replica / HA product |  |  | component fence only; no complete profile |
| Recovery never requires the governance provider | ✓ | ✓ | ✓ |

### `EmbeddedStore` call sites that must move to typed records

- `Ctx::embedded` (`src/client.rs`) opens the graph as the solo backend.
- Catalog, plan, environment, lease, and action paths in
  `src/client/{object,relation,lease,action}_lifecycle.rs` read and write
  `Object` / `Link` / `Lease`.
- Fleet fairness and embedded CLI inspect go through the same backend.
- `src/embedded.rs` owns schema 5 migration, property index, and backup.

Remote hosts already transfer plane objects and decode plans. Embedded hosts
should use the same typed `PlanRecord` / `EnvironmentRecord` / `ReleaseRecord`
shapes that `OperationalStore` already persists.

### Recovery drills

| Drill | Store in use | Outcome |
| --- | --- | --- |
| Signed stateful upgrade (`tests/stateful_upgrade_drill.rs`) | embedded `tenkai.db` via `tenkaictl` | Survives executor loss; recovery is Tenkai-owned |
| Two-environment closure (`tests/two_environment_closure_drill.rs`) | embedded SQLite | One signed closure, two environments |
| `tenkaictl backup` / `restore` (`src/embedded.rs` tests) | `EmbeddedStore` | Live backup, integrity-checked restore |
| Enterprise PostgreSQL sole-store recovery | not a shipped profile drill | Gated by ADR 0010 until Postgres owns every authoritative surface |

A single-engine-everywhere option fails the same constraints ADR 0010 recorded:
SQLite cannot be the hub HA store; PostgreSQL cannot be the edge single-file
spoke.

## Decision

Select issue option 1. This is the storage consequence of ADR 0001 (one core,
two hosts) and ADR 0010 (one authoritative backend per process).

1. **One application port.** Embedded, spoke, and hub call `OperationalStore`
   (and `TenantOperationalStore` where tenant isolation is selected). Engine
   choice is an adapter, not a domain model.
2. **Hub is PostgreSQL only.** The enterprise server process opens PostgreSQL
   as the sole authoritative operational store. It does not open SQLite for
   runtime truth and does not keep a parallel object graph.
3. **Spoke and embedded `tenkaictl` are SQLite only.** One file, one writer,
   schema 10 typed records. No PostgreSQL configuration is valid on those
   hosts.
4. **Retire `EmbeddedStore`.** Planning inputs become typed records already
   owned by `OperationalStore`. The sekai-shaped graph remains a remote-plane
   projection and a compatibility codec, not a second embedded schema.
5. **Projections are not recovery material.** Governance-plane objects,
   property indexes copied from a remote catalog, and retained files cannot
   authorize apply, rollback, or lease takeover.

Follow-up implementation is [#382](https://github.com/Sannrox/tenkai/issues/382):
migrate `Ctx::embedded` onto `SqliteStore`, keep object codecs at the remote
adapter boundary, and refuse process startup when both engines are configured.

## Consequences

- Issue [#373](https://github.com/Sannrox/tenkai/issues/373) is answered: the
  topology is hub PostgreSQL, spoke/embedded SQLite, one port, no embedded
  object-graph schema.
- Embedded state migration must copy graph-shaped plans and environments into
  typed schema 10 rows and retain the original evidence version.
- The mixed SQLite-plus-PostgreSQL enterprise composition stays test-only until
  removed; it must not become `enterprise-experimental`.
- Remote protocol listing residuals in ADR 0025 stay at the catalog adapter.
  They are not a reason to keep a local object database.

## Alternatives

1. **Keep all three designs and document gaps.** Rejected: operators cannot
   tell which file is recovery truth, and tests must prove three migration
   stories forever.
2. **Single engine everywhere.** Rejected: SQLite hub replication is not a
   supported HA story (ADR 0009); PostgreSQL on every spoke violates the
   single-file edge constraint.
3. **Keep `EmbeddedStore` as a SQLite view over typed tables.** Rejected: that
   preserves a second domain language. Codecs belong at the plane boundary.

## Evidence and provenance

Source audit of `src/embedded.rs`, `src/storage.rs`, `src/postgres_tenant.rs`,
`src/client.rs`, `src/tenant_store.rs`, ADR 0001, ADR 0008, ADR 0010, and the
shipped recovery drills. No new store implementation is in this change.
