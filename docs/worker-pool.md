# Shikigami worker-pool lifecycle

Tenkai owns the environment-scoped worker-pool release, fixed replica intent,
drain, health, rollback, and recovery. It does not admit, claim, lease, or
acknowledge individual agent work. That authority stays with Sekai Chisei;
Shikigami executes Harness runs through `PlaneClaimIntake`.

See [ADR 0011](decisions/0011-shikigami-worker-pool-lifecycle.md) and
[ADR 0028](decisions/0028-live-worker-lifecycle-port.md).

```toml
[product]
name = "edge-workers"
version = "1.0.0"
kind = "worker_pool"

[worker_pool]
intake = "plane"
replicas = 2
drain_timeout_ms = 5000
```

`intake` must be `plane`. `filesystem` and unknown adapters fail closed before
planning or execution.

## Operator workflow

```bash
tenkaictl publish tenkai.toml --allow-unsigned-development
tenkaictl promote edge-workers@1.0.0 stable
tenkaictl env subscribe local edge-workers=stable
tenkaictl plan --env local
tenkaictl apply --env local
tenkaictl env inspect local
```

Apply observes a live `WorkerLifecyclePort`. The host document remains the
Shikigami `schema_version = 1` `shikigami.worker_lifecycle` snapshot. Live
admission also requires `source = live`, a fencing generation that matches the
environment execution lease, and a fresh `observed_at`. Retained
`worker/*.json` files reconstruct the last known pool record; they cannot
authorize drain, replacement, or any other process-lifetime change.

Scale-down and replacement request drain and wait for `active_claims = 0`. A
drain timeout leaves the pool `degraded` and never acknowledges work. Plane
outage cannot authorize scale-up. Stale or lost fencing rejects lifecycle
completion. Process start and stop stay with the selected executor adapter.

Select the local acceptance adapter with `TENKAI_WORKER_LIFECYCLE=local-process`
and, when needed, `TENKAI_WORKER_LIFECYCLE_FIXTURE` plus
`TENKAI_WORKER_LIFECYCLE_ROOT`. That adapter supervises
`tenkai-worker-lifecycle-fixture`. It is not a work scheduler.

Environment inspect shows
`worker_pool.<product>.{state,replicas,intake,detail,observation_source}`.
Recovery uses Tenkai operational state and retained snapshots; Chisei is not
required to reconstruct the pool record.
