# Shikigami worker-pool lifecycle

Tenkai owns the environment-scoped worker-pool release, fixed replica intent,
drain, health, rollback, and recovery. It does not admit, claim, lease, or
acknowledge individual agent work. That authority stays with Sekai Chisei;
Shikigami executes Harness runs through `PlaneClaimIntake`.

See [ADR 0011](decisions/0011-shikigami-worker-pool-lifecycle.md).

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

Apply reads versioned worker-host lifecycle snapshots from the release workdir
`worker/*.json` (the Shikigami `schema_version = 1` document). Scale-down and
replacement wait for `active_claims = 0`. A drain timeout leaves the pool
`degraded` and never acknowledges work. Plane outage cannot authorize scale-up.
Stale fencing rejects lifecycle completion.

Environment inspect shows `worker_pool.<product>.{state,replicas,intake,detail}`.
Recovery uses Tenkai operational state and retained snapshots; Chisei is not
required to reconstruct the pool record.
