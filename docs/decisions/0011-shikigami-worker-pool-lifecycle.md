# ADR 0011: Shikigami worker-pool lifecycle ownership

- Status: Accepted
- Date: 2026-07-31
- Issue: [#202](https://github.com/Sannrox/tenkai/issues/202)
- Follow-ups: [Shikigami #155](https://github.com/Sannrox/shikigami/issues/155),
  [Sekai Chisei #489](https://github.com/Sannrox/sekai-chisei/issues/489)
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [ADR 0005](0005-enterprise-integration-boundary.md),
  [ADR 0007](0007-model-runtime-fleet-control-plane.md)

## Context

Tenkai owns declarative releases, environments, plans, execution health,
rollback, and recovery. Its original boundary excluded orchestrating agent
work. Shikigami now has a serve host that pulls admitted `runtime_dispatch`
work from Sekai Chisei, claims it under the Chisei lease and fence, executes
the Harness, and reports a terminal acknowledgement.

Operators still need a coherent lifecycle for the long-lived Shikigami worker
hosts that provide capacity. A second work or fleet control plane would split
desired state, rollout, and recovery authority. The lifecycle boundary must
therefore be explicit before implementation adds public contracts.

## Decision

Tenkai extends its delivery control plane to own the lifecycle of a Shikigami
worker pool, but it does not own admission or execution of individual work.
Kubernetes, systemd, or another supported executor remains the process and
deployment backend. This lifecycle contract applies only to a Shikigami serve
host configured with the `PlaneClaimIntake` adapter. Filesystem-backed or
otherwise non-Chisei intake modes remain unmanaged by this product boundary
until a separate ownership decision defines their authority and recovery
semantics.

```text
Tenkai        -> pool desired state, deployment, capacity, health, rollout,
                 drain, and pool recovery
Sekai Chisei  -> policy, admission, work state, claims, leases, fencing,
                 retry/park decisions, and operation receipts
Shikigami     -> pull admitted work, claim it under Chisei, and execute Harness runs
```

### Authority matrix

| Concern | Authoritative owner | Contract boundary |
| --- | --- | --- |
| Worker-pool desired state | Tenkai | Immutable product release, environment scope, runtime identity, configuration references, capacity, and lifecycle intent are Tenkai delivery state. Secrets and task payloads are excluded. |
| Worker-pool observed state | Tenkai, from executor and host reports | Shikigami exposes versioned identity, readiness, drain, health, concurrency/capability, and opaque active-run/claim counts through the worker-host contract. Tenkai does not infer missing state. |
| Admitted work and work state | Sekai Chisei | Chisei owns policy, `runtime_dispatch` admission, claim selection, lease expiry, fencing, retry/park decisions, and operation receipts. Tenkai does not copy or mutate individual work state. |
| Execution | Shikigami | A serve host using `PlaneClaimIntake` pulls admitted work, claims it through Chisei, and invokes the shared Harness. Terminal acknowledgement remains under the Chisei claim fence. |
| Pool rollout and recovery | Tenkai plus the selected executor | Tenkai reconciles pool release and lifecycle state, observes health, drains before scale-down or replacement, and rolls back an unsafe pool rollout. Pool recovery must not require Chisei availability unless the selected policy explicitly requires Chisei evidence. |
| Work recovery | Sekai Chisei and Shikigami's execution contract | Lease expiry, fencing, retry/park, continuation, and terminal receipt semantics remain in the Chisei/Shikigami contract; Tenkai does not become a second recovery authority. |

The initial implementation phase manages fixed replicas and lifecycle state.
Autoscaling is a later phase, using bounded read-only Chisei claim pressure and
oldest-work-age signals together with Shikigami health. It must never turn
Tenkai into a work scheduler or copy Chisei claims into Tenkai state.

## Contract and failure rules

1. The worker-host lifecycle contract and the claim-pressure contract are
   versioned, authenticated, environment/runtime scoped, observable, and
   fail-closed when stale state could cause unsafe execution.
2. A managed pool must resolve to Shikigami's `PlaneClaimIntake`. Tenkai must
   reject a managed-pool configuration using `FilesystemQueueIntake` or an
   unknown intake adapter; those modes cannot inherit this ADR's Chisei claim,
   fencing, receipt, or recovery guarantees.
3. Tenkai may request rollout, drain, replacement, or capacity changes, but it
   cannot choose a work item, mint a claim, renew or revoke a Chisei lease, or
   acknowledge a terminal operation.
4. A stale or unavailable claim-pressure signal cannot authorize scale-up. The
   pool records degraded evidence and keeps the last safe lifecycle intent
   until fresh evidence is available.
5. An unavailable or unhealthy Shikigami host makes the pool not ready. Tenkai
   may reconcile through the executor, but it must not mark the rollout healthy
   without the required host evidence.
6. A lease expiry or fencing event is handled by Chisei. Stale worker events
   remain rejected under the Chisei generation; Tenkai must not compensate by
   accepting an out-of-band receipt.
7. Scale-down and replacement begin with a bounded drain. A drain timeout
   leaves the pool degraded and does not authorize force-acknowledging active
   work.
8. Disconnected environments retain the existing signed-bundle and
   environment-runtime recovery path. Chisei availability is not a recovery
   dependency, and autoscaling is unavailable when its evidence cannot be
   reached or verified.

## Sequencing

The smallest compatible sequence is:

1. Accept this ADR and freeze the ownership and failure boundary.
2. Land [Shikigami #155](https://github.com/Sannrox/shikigami/issues/155),
   defining the versioned worker-host lifecycle, readiness, and drain contract.
3. Shape a focused Tenkai implementation issue for fixed-replica lifecycle
   management against the worker-host contract. That implementation issue must
   include a local/minikube dogfood path and the rollout, crash, drain,
   fencing, Chisei-outage, provider-outage, and disconnected-environment
   failure matrix. It must not depend on claim-pressure reads.
4. Land [Sekai Chisei #489](https://github.com/Sannrox/sekai-chisei/issues/489),
   defining the bounded read-only claim-pressure contract for the later
   autoscaling phase.
5. Consider autoscaling only after fixed-replica lifecycle evidence is
   repeatable and both cross-repository contracts have compatibility tests.

No new Tenkai runtime or cross-repository protocol is introduced by this ADR.

## Alternatives

### Delegate the complete worker lifecycle to Kubernetes/systemd

This preserves the narrowest existing Tenkai product boundary and minimizes
Tenkai implementation work. It was rejected for this use case because pool
desired state, rollout, health, and recovery would remain outside the delivery
control plane, weakening environment-level visibility and creating a second
operator workflow. Kubernetes/systemd remains the execution backend under the
accepted decision.

### Build a separate Shikigami control plane

This could centralize worker concerns in Shikigami, but would create another
fleet authority beside Tenkai and another recovery path beside Chisei. It was
rejected because it duplicates lifecycle ownership while still requiring the
same admission, claim, and receipt boundary.

## Consequences

- Tenkai's product boundary includes worker-pool lifecycle, but its
  non-goal against agent-work scheduling remains intact.
- Operators get one delivery/recovery surface for pool release, health,
  rollout, drain, and capacity intent.
- Tenkai gains versioned lifecycle and scaling integrations and must preserve
  embedded/server equivalence, scoped credentials, compatibility negotiation,
  and fail-closed behavior.
- Chisei remains optional to Tenkai recovery. Operations that explicitly
  require Chisei admission or pressure evidence fail closed when that evidence
  is missing, stale, or invalid.
- Fixed-replica lifecycle is the first implementation boundary; autoscaling
  remains intentionally unimplemented until its evidence and contracts exist.

## Evidence and provenance

The accepted boundary is grounded in Tenkai's existing release, environment,
executor, reconciler, health, rollback, and recovery ownership, plus the
shipped Shikigami plane-claim path. The portable Sekai ontology was validated
before this ADR was written. It defines `TenkaiServerHost` as a host composing
shared application contracts and adapters, `ShikigamiServeHost` as a thin host
over the Harness, and `PlaneClaimIntake` as the adapter that obtains admitted
work from the Chisei governance plane and sends fenced terminal
acknowledgements. It does not define a worker-pool authority; the lifecycle
ownership in this ADR is therefore a project decision, not an inferred
ontology fact.
