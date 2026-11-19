# ADR 0057: Advertise and enforce what each server and runtime can execute

- Status: Accepted
- Date: 2026-11-19
- Issue: [#1375](https://github.com/Sannrox/tenkai/issues/1375)
- Owner: Tenkai maintainers
- Builds on: [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md),
  [ADR 0048](0048-runtime-runs-built-in-executors.md),
  [runtime capabilities](../runtime-capabilities.md)
- Related: [HA failover runbook](../ha-failover-runbook.md),
  [runtime protocol v1](../runtime-protocol-v1.md)

## Context

A release declares its executor (`deploy.executor`, for example `docker`,
`helm` or `kubernetes-inprocess`). Whether a step can run depends on the
process that runs it, and today that shows only at apply, on that process.

A multi-replica hub runs steps on the replica that holds the hub writer
lease, and any standby can take the lease over. If replicas have different
executors installed, the same plan can apply before a failover and fail
after it. An environment with an enrolled runtime runs its steps there
(ADR 0048), and the server cannot see what that runtime has installed.
`/readyz` advertises each process's own capabilities, but nothing durable
lets a planner on one process see another's.

## Decision

### 1. Each process records its executor set

The set is the executor kinds that pass the same checks apply makes:
`shell`, `host` when the host executor is usable, and each kind whose
adapter is installed.

- **Server replica.** On every writer-lease renewal, before it asks for the
  lease, a replica upserts its set, version and the database time into
  `tenkai_hub_replicas`, keyed by its writer-lease holder name. Standbys
  write it too: the table sits beside the lease, outside the fenced store.
  Rows that have not checked in for 100 lease lifetimes are deleted. After
  renewing, the replica reads every row that checked in within 3 lease
  lifetimes, plus the live lease holder, into a local view.
- **Runtime.** A runtime that runs the built-in executors names its set in
  `x-tenkai-runtime-executors` on work pull. The server stores it in the
  runtime's existing `runtime_activity` row, in a new `executors` column. A
  pull without the header keeps the recorded set. A runtime that hands steps
  to an operator program names none.

The draft for this decision gave runtimes the record and replicas "the same
kind of record". A replica's record lives next to the writer lease instead
of in the operational store, because a standby cannot write the fenced
store, and it must record before it can lead.

### 2. An environment's supported set is derived, never configured

- **Runtime-run environment** (a runtime is enrolled, a configured runtime
  token serves it, or a runtime has recorded activity for it): the intersection over its runtime instances that
  checked in within 90 seconds. None checked in: `unknown`.
- **Server-run environment:** the intersection over the replicas in the
  view. An empty view (a single-replica server, or embedded `tenkaictl`)
  uses the planning process's own set.

A process in the set that recorded no executors (a version before this
decision), or a live lease holder with no row, makes the set `unknown`.

### 3. Plan creation refuses against that set

Every path that stores a plan checks each step whose release declares an
executor. A kind outside a `known` set refuses the plan and names the
release, the executor, and each replica or runtime that lacks it. An
`unknown` set refuses nothing. A release without a declared executor runs
on each process's default, which only apply can check.

Apply keeps its own check on the process that runs the step. It stays the
fence: the plan-time check refuses early and replaces nothing.

### 4. The sets are visible

- `GET /v1/fleet/status` lists `replicas` with their executors, version and
  last check-in, and each environment row lists its `runtimes`.
- `GET /v1/environments/{env}/runtime` reports `supported_executors`: the
  `known` set and the processes it came from, or `unknown` and why.
- A leader's `/readyz` names, in `replica_executors_differ`, peers whose
  set differs from its own. It never changes readiness. A standby answers
  `503` as before.

### 5. No step routing

ADR 0048 rejected capability-based routing, and that stands. This decision
only refuses earlier and makes the sets visible.

## Consequences

- One additive table (`tenkai_hub_replicas`, Postgres hubs only) and one
  additive nullable column (`runtime_activity.executors`, SQLite and
  Postgres). Fresh and upgraded stores create them on open. Older versions
  ignore both.
- Rolling deploy: an older replica writes no row. It counts only once it
  holds the lease, and then the set is `unknown`. Plans fall back to the
  apply-time check, as before this decision. A rollout that adds an
  executor is accepted in plans only once every replica that checked in
  has it.
- A replica missing an executor narrows what can be planned until it gains
  it or stops checking in for 3 lease lifetimes.
- Embedded `tenkaictl` now refuses a declared executor it lacks when it
  plans, not first at apply. The same process applies the plan, so the
  outcome is unchanged, only earlier.
- The record is an operator view and a planning aid. A failed write is
  reported, and the apply-time check still decides.
- Model engines and accelerator facts are not part of the set yet. A model
  release's engine is checked by the model runtime at apply.

## Rejected

- **An operator-configured supported list per environment.** It drifts from
  what is actually installed, and it fails open.
- **Requiring identical replicas at startup.** It blocks rolling deploys and
  rollbacks that add or remove an executor.
- **Routing steps to a capable replica or runtime.** It contradicts the
  single leader and the one runtime per environment.
- **Recording replica sets in the operational store.** Standbys cannot
  write it, so a standby's set would be missing exactly when a takeover
  matters.
