# Multi-host reconcile ticks (#129, #1112)

ADR: [0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md).  
Store claim: [shared_replica_state](postgres-tenant-store.md#shared-replica-state-128).

## How ticks stay single

Two guards keep one environment from being reconciled twice at once:

| Layer | Role |
| --- | --- |
| Local `SchedulerState` | Per-process in-flight and backoff for each environment |
| Hub writer lease (#748) | Only the replica holding the lease ticks; standbys skip their ticks |

The writer lease also fences the writes themselves: every authoritative write
checks the lease's holder and generation in its own transaction, so a replica
that lost the lease cannot commit even before it notices. See
[multi-replica-hub-runbook.md](multi-replica-hub-runbook.md#hub-writer-lease-748).

There is no separate per-environment tick claim. Earlier releases kept one
(`tenkai_reconcile_tick_claims`); it duplicated the writer lease and was
removed in #1112.

## Upgrading

Current replicas no longer create or read `tenkai_reconcile_tick_claims`.
An existing table is left in place so older replicas keep working during a
rolling deploy. Drop it once every replica runs this release.

## Relation to store capabilities

`--replica-count > 1` requires `shared_replica_state` (Postgres hub, single-active
writer model). It does **not** advertise product `high_availability` by itself.

## Ops

Operator failover and lab steps:
[multi-replica-hub-runbook.md](multi-replica-hub-runbook.md) (#130).

## Non-goals

- Multi-primary SQLite
- Product `high_availability` flag (still separate)
- Identity-plane co-location

Delivery-effect evidence and the paths that remain outside the HA claim:
[fenced delivery-effect conformance](delivery-effect-conformance.md).
