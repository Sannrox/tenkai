# ADR 0009: Multi-replica reconcile and HA capability profile

- Status: Accepted
- Date: 2026-07-25
- Issue: [#109](https://github.com/Sannrox/tenkai/issues/109)
- Related: [#38](https://github.com/Sannrox/tenkai/issues/38) (runtime
  capabilities), [#59](https://github.com/Sannrox/tenkai/issues/59) (backup /
  restore), ADR 0001, ADR 0008,
  [runtime capabilities](../runtime-capabilities.md),
  [operational storage](../operational-storage.md),
  [backup/restore](../backup-restore.md)

## Context

`RuntimeRequirements` can request `replica_count > 1` and
`require_high_availability`. Startup negotiation already fails closed when the
composed store does not advertise `shared_replica_state` or `high_availability`
respectively (`src/runtime_capabilities.rs`, #38).

Community SQLite is **single-writer**, tenant-free, and does **not** advertise
those capabilities. ADR 0008 deferred a production shared tenant store and
stated that multi-replica writers need an honest `shared_replica_state` claim
plus fencing. Operators still lacked a single written HA profile answering:

1. What “HA” means with one process;
2. What multi-replica reconcile would require;
3. Which capabilities gate which flags;
4. What is explicitly not guaranteed.

Without that profile, documentation or marketing could imply multi-process
reconcile on SQLite — a security and ops defect.

## Decision

### 1. Single-replica profile (community default and current server)

| Guarantee | Scope |
| --- | --- |
| Process restart | Restart the same binary against the same Tenkai-owned DB; recovery uses durable plans, leases, receipts, rollback intent (ADR 0001). |
| Backup / restore | `tenkaictl backup` / `restore` (and server cutover notes) are the durability path (#59). |
| Continuous reconcile | One process runs the reconcile loop; no cross-process tick coordination. |
| Fail-closed multi-replica | `--replica-count > 1` fails startup without `shared_replica_state`. |
| Fail-closed HA flag | `--require-high-availability` fails startup without `high_availability`. |

**Single-replica HA** means: *restart + restore from Tenkai-owned backups*, not
active-active control planes, not automatic multi-AZ failover, not shared-nothing
multi-writer SQLite.

### 2. Capability matrix (authoritative for operators)

| Operator request | Required capability | Community SQLite |
| --- | --- | --- |
| Default (`replica_count=1`, no HA flag) | Migration level only | Supported |
| `replica_count > 1` | `shared_replica_state` | **Rejected at startup** |
| `--require-high-availability` | `high_availability` | **Rejected at startup** |
| Tenant mode | `tenant_isolation` | **Rejected** (separate axis; ADR 0008) |

`shared_replica_state` and `high_availability` are **independent** claims:

- A store may be multi-writer-safe without full product HA (e.g. shared DB with
  documented single active reconciler).
- Advertising `high_availability` without honest multi-process operational
  semantics is forbidden.

### 3. Multi-replica reconcile requirements (before any implementation)

Multi-process reconcile is **not** implemented today. It must not ship until a
store path exists that can honestly advertise `shared_replica_state` (ADR 0008
production store or equivalent). Minimum future design obligations:

| Concern | Requirement |
| --- | --- |
| Shared operational state | One Tenkai-owned store visible to all replicas; not per-process SQLite files. |
| Tick fencing | At most one active reconciler generation per environment (or global lease) may mutate execution state; stale generations fail closed. |
| Leader / lease | Explicit reconcile leadership or per-environment work claims with TTL and fencing tokens (same family as environment apply leases). |
| Idempotent receipts | Existing receipt identity and plan lifecycle rules remain the retry boundary. |
| Capability honesty | Store advertises `shared_replica_state` only after concurrent-writer tests; HA only after documented multi-process recovery drills. |
| Startup gate | Keep fail-closed validation; never soft-warn into multi-replica. |

**Recommendation:** implement multi-replica **only after** a shared store path
exists and is selected by an explicit storage issue (see ADR 0008 follow-on).
Do not invent multi-primary SQLite for community defaults.

### 4. Explicit non-goals

- Claiming HA on tenant-free community SQLite.
- Multi-primary or NFS-shared SQLite as a production HA story.
- Changing community default `replica_count` from `1`.
- Implementing Postgres, etcd, or leader election in this ADR.
- Coupling HA claims to optional sekai-chisei availability (recovery remains
  Tenkai-owned; ADR 0001).

### 5. Follow-on implementation titles only

Do not implement in this decision:

1. `feat(storage): optional shared OperationalStore with shared_replica_state`  
   (depends on ADR 0008 path choice / #111 commitment).
2. `feat(reconciler): multi-replica tick fencing with shared_replica_state store`
3. `docs(ops): multi-replica runbook and failover drill` (after 1–2).

## Consequences

- Operators can treat single-process Tenkai as restart- and backup-resilient,
  not as an active multi-replica control plane.
- Capability flags remain the only gate for multi-replica / HA configuration.
- Future multi-replica work is blocked on an honest shared store, not on
  reconciler inventiveness alone.
- Incorrect HA claims in product copy or defaults are treated as defects.

## Alternatives considered

| Option | Why rejected |
| --- | --- |
| Soft-allow multi-replica on SQLite with “best effort” | Corrupts leases/plans; violates fail-closed policy. |
| Implement multi-replica before shared store | No durable cross-process authority. |
| Equate backup/restore with `high_availability` capability | Misleads operators; HA flag stays distinct and opt-in. |
