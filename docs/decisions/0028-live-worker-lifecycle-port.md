# ADR 0028: Live worker-lifecycle observation and process lifetime

- Status: Accepted
- Date: 2026-09-12
- Issue: [#336](https://github.com/Sannrox/tenkai/issues/336)
- Discussion: [#371](https://github.com/Sannrox/tenkai/discussions/371)
- Owner: Tenkai maintainers
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [ADR 0011](0011-shikigami-worker-pool-lifecycle.md),
  [Worker-pool lifecycle](../worker-pool.md)

## Context

ADR 0011 assigns pool desired state, drain, health, rollout, and recovery to
Tenkai. It assigns individual work admission, claims, leases, fencing of runs,
and receipts to Sekai Chisei. Shikigami executes Harness runs. Kubernetes,
systemd, or another selected executor remains the process backend.

The shipped operator path reads retained `worker/*.json` snapshots from the
release workdir and treats those documents as enough to admit replacement.
That collapses three different evidence classes into one file:

1. a versioned host document (`shikigami.worker_lifecycle` schema 1);
2. a live observation of a running process;
3. recovery material retained after a previous apply.

Retained files cannot prove that a worker is draining, that a fence is still
held, or that replacement completed. They also cannot start, stop, or signal a
process. End-to-end replacement therefore needs an explicit application port
for live observation and drain, plus an explicit process-lifetime owner.

Transport is not a domain boundary. Embedded and server hosts must call the
same port. A Tenkai-only change cannot seize process lifetime from the
selected executor, and it cannot become a second work scheduler.

## Decision

Introduce `WorkerLifecyclePort` as a Tenkai application port. Both hosts use
it. Adapters differ.

1. **Live observation is the only admission authority for process change.**
   Start, stop, scale, drain, and replacement require observations with
   `source = live`, a fencing generation that matches the current environment
   execution lease, and an `observed_at` inside the pool's live TTL. Unknown
   schema, unknown protocol, lost fencing, or a stale generation fail closed.
2. **Retained snapshots are recovery material, not live authority.**
   `worker/*.json` may reconstruct the last known pool record for inspect and
   disconnected recovery. They cannot authorize `Apply` for replacement,
   scale-down, or any other process-lifetime change.
3. **Process lifetime stays with the selected executor adapter.**
   The port's `start_replica` and `stop_replica` verbs are executor-owned.
   Tenkai authorizes the change from live evidence; it does not fork workers
   as a hidden side effect of catalog files. The local acceptance adapter
   supervises a fixture process that speaks the versioned host document. A
   production Shikigami, Kubernetes, or systemd adapter is a later implementor
   of the same port.
4. **Drain is a request, never an acknowledgement.**
   Tenkai may ask a worker to drain. A drain timeout leaves the pool
   `degraded` and does not acknowledge, claim, lease, or complete individual
   work. Busy workers block replacement until they report idle under a live
   observation.
5. **The host document stays schema 1.**
   Do not mint a second lifecycle protocol. The live envelope
   (`source`, `observed_at_ms`, `fencing_generation`) wraps the existing
   `shikigami.worker_lifecycle` document. Compatibility is fail-closed, not
   silently upgraded.
6. **No port means no process change.**
   Apply without a live port fails closed for worker-pool products. Selecting
   `TENKAI_WORKER_LIFECYCLE=local-process` installs the local fixture adapter.
   Unknown selector values fail closed.

## Consequences

- Issue [#336](https://github.com/Sannrox/tenkai/issues/336) is unblocked: one
  reviewable pull request can drain, replace, and verify one local worker
  process from release A to B without claiming or scheduling runs.
- Operators can no longer complete replacement by planting snapshot files in
  a release workdir.
- Production worker-host adapters must speak the same port. They are not
  required in this change.
- Chisei remains optional for pool recovery. Work recovery stays with the
  Chisei/Shikigami contract.

## Alternatives

1. **Keep file snapshots as live authority.** Rejected: cached or projected
   evidence would inject cached files as execution authority, violating ADR
   0011 fail-closed rules and the issue's stale-snapshot acceptance evidence.
2. **Give Tenkai core direct process control.** Rejected: process lifetime
   belongs to the selected executor. A hidden `Command::spawn` in catalog
   apply would make transport and host details a domain boundary.
3. **Wait for a production Shikigami transport before defining the port.**
   Rejected: the control plane publishes the versioned observation contract;
   any managed host implements it. A local fixture is a valid first
   implementor. Waiting would leave replacement file-authorized.
4. **Mint schema 2 as a second protocol.** Rejected: freshness and generation
   are observation metadata, not a new host document. Schema 1 stays the
   worker-host contract.

## Evidence and provenance

The accepted boundary is grounded in ADR 0001 (one core, two hosts), ADR 0011
(pool versus work ownership), and the shipped `WorkerLifecycleSnapshot`
validator. This ADR does not change ontology classes. It records the missing
live-transport and process-lifetime contract named by #336.
