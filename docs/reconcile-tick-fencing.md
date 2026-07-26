# Multi-host reconcile tick fencing (#129)

ADR: [0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md).  
Store claim: [shared_replica_state](postgres-tenant-store.md#shared-replica-state-128).

## Problem

In-process `SchedulerState` only prevents concurrent reconcile of the same
environment **inside one process**. With multiple hub hosts sharing operational
state, two ticks can race on the same environment without an inter-host fence.

## Design

| Layer | Role |
| --- | --- |
| Local `SchedulerState` | Per-process in-flight + backoff (unchanged) |
| `ReconcileTickFence` | Optional multi-host claim: owner + generation + TTL |
| `SharedReconcileFence` | Process-shared fence (`Arc`) for tests and co-located hosts |

On each environment, after local admission `Started`:

1. If a shared fence is configured, `try_begin(env, instance_id, now, ttl)`.
2. `Busy` / `Stale` → report `EnvironmentStatus::Busy` (clear local in-flight).
3. `Started { generation }` → hold `FenceGuard` for the duration of the tick job.
4. Guard releases the claim on drop (or explicit release).

Stale generations must not steal another host's live claim.

## Wiring

```rust
use std::sync::Arc;
use tenkai::reconcile_fence::SharedReconcileFence;
use tenkai::reconciler::{Config, Reconciler};

let fence = SharedReconcileFence::new().into_arc();
let reconciler = Reconciler::new(ctx, Config {
    instance_id: "hub-1".into(),
    fence_ttl_ms: 30_000,
    ..Config::default()
})?
.with_shared_fence(Arc::clone(&fence) as Arc<dyn tenkai::reconcile_fence::ReconcileTickFence>);
```

Without `with_shared_fence`, behavior matches the historical single-process model.

## Relation to store capabilities

`--replica-count > 1` requires `shared_replica_state` (Postgres hub, single-active
writer model). Tick fencing is the reconcile-side coordination once multiple
processes are allowed past capability negotiation. Durable store-backed claims
(table / advisory locks) can implement the same `ReconcileTickFence` port later.

## Ops

Operator failover and lab steps:
[multi-replica-hub-runbook.md](multi-replica-hub-runbook.md) (#130).

## Non-goals

- Multi-primary SQLite
- Product `high_availability` flag (still separate)
- Identity-plane co-location
