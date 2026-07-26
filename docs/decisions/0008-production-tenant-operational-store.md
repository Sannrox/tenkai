# ADR 0008: Production tenant-capable OperationalStore criteria

- Status: Accepted
- Date: 2026-07-25
- Issue: [#98](https://github.com/Sannrox/tenkai/issues/98)
- Related: [#37](https://github.com/Sannrox/tenkai/issues/37) (isolation harness),
  [#69](https://github.com/Sannrox/tenkai/issues/69) (in-memory adapter),
  [#70](https://github.com/Sannrox/tenkai/issues/70) (management isolation),
  ADR 0001, ADR 0005, [tenant isolation](../tenant-isolation-conformance.md),
  [operational storage](../operational-storage.md)

## Context

Community Tenkai uses SQLite (`SqliteStore`) and advertises a **tenant-free**
capability profile. Enterprise hosts may enable tenant mode when a store
advertises `tenant_isolation` and passes the isolation harness.

Issue #69 shipped `InMemoryTenantOperationalStore` (per-tenant SQLite
partitions) for conformance and host wiring tests. It is not a production
multi-tenant database. Without accepted production criteria, implementers risk:

- claiming isolation without harness coverage;
- co-locating identity-plane tables with operational recovery state (forbidden
  by ADR 0005);
- forcing community users onto a commercial database;
- under-specifying HA and migration obligations.

## Decision

### 1. Minimum production requirements (vs community SQLite)

| Requirement | Community SQLite | Production tenant store |
| --- | --- | --- |
| Capability | No `tenant_isolation` | Must advertise `tenant_isolation` + honest migration level |
| Isolation proof | N/A | Pass `#37` harness against the adapter (or registered subset with CI) |
| Recovery authority | Tenkai-owned file | Tenkai-owned DB; never the identity plane DB |
| HA | Single process | Optional; only if `shared_replica_state` is honestly claimed |
| Community default | Unchanged | Must not become the community default |

### 2. Where the adapter lives

**Recommendation: defer in-repo PostgreSQL for now; keep production adapters
as optional / out-of-tree (or a future optional crate) unless a concrete
maintainer commitment lands.**

Rationale:

- ADR 0005 places commercial multi-tenant assembly outside the public core.
- The public repo already provides the port (`OperationalStore` +
  `tenant_memory` conformance path) and management isolation hooks (#70).
- Shipping Postgres in-tree without HA ops, connection pooling policy, and
  migration ownership would over-promise.

**Allowed later paths (pick when implementing):**

1. **Optional crate** in-repo (`tenkai-store-postgres`) behind explicit feature;
2. **Out-of-repo** commercial adapter implementing the same ports + harness;
3. **In-tree** only if maintainers accept migration/HA CI cost.

### 3. Isolation test obligations

Any production tenant store **must**:

- Pass `TenantIsolationHarness` (or successor) continuously in CI for the
  adapter under test;
- Preserve non-disclosing cross-tenant errors (`NON_DISCLOSING_DENY`);
- Keep community SQLite tests green and tenant-free;
- Register new tenant-visible RPCs in the isolation matrix (#37 rule).

### 4. Migration and HA expectations

- Schema migrations remain Tenkai-owned and versioned (`SCHEMA_VERSION` or
  adapter-specific level advertised via capabilities).
- Opening a newer schema than the binary supports fails closed.
- Multi-replica writers require an explicit `shared_replica_state` capability
  and tested fencing; otherwise advertise single-writer only.
- Backups/restores must document tenant boundaries and exclude identity-plane
  secrets.

### 5. Explicit non-goals

- Shared database with the enterprise identity plane.
- Making community installs require Postgres.
- Commercial quotas / noisy-neighbor isolation as core Tenkai features.
- Implementing Postgres in this ADR (decision only).

## Recommendation

| Action | Status |
| --- | --- |
| Use `InMemoryTenantOperationalStore` for conformance and unit wiring | **Keep** |
| Production Postgres (or other) | **Optional in-tree** behind feature `postgres` (`src/postgres_tenant.rs`, #111) — not community default |
| Follow-on | Multi-replica fencing + `shared_replica_state` (ADR 0009); optional out-of-tree commercial packaging remains allowed |

## Consequences

- Enterprise demos can enable tenant mode with the in-memory adapter.
- Commercial deployments supply their own store or wait for an optional crate.
- Capability advertisement remains the startup fail-closed gate for tenant mode.

## Alternatives considered

- **Ship Postgres in core now:** rejected — ops and packaging cost, scope creep
  vs ADR 0005.
- **Drop tenant mode from public repo:** rejected — harness and contracts already
  land enterprise readiness without a commercial DB.
