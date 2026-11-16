# ADR 0052: Provisioning executor with approval bound to the saved plan

- Status: Proposed
- Date: 2026-11-16
- Issue: [#902](https://github.com/Sannrox/tenkai/issues/902)
- Owner: Tenkai maintainers
- Builds on: [ADR 0022](0022-external-delivery-adapter-boundary.md),
  [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md),
  [ADR 0045](0045-sealed-secrets.md),
  [ADR 0048](0048-runtime-runs-built-in-executors.md)
- Related: [plan approval](../plan-approval.md),
  [software executor](../software-executor.md),
  [runtime protocol v1](../runtime-protocol-v1.md)

## Context

Operators provision infrastructure with a declarative provisioning tool:
a CLI that computes a saved plan of resource changes from configuration and
recorded state, then applies exactly that saved plan, holding a lock on the
state backend while it writes. Issue #902 names the two compatible CLIs in
use. Today they run from a shell step. Tenkai then approves a script, not the
change: the approver never sees what is created or destroyed, a destroy looks
like any other step, and the tool's state lock is not tied to Tenkai's lease,
so a takeover can race it.

## Decision

Go, for a narrow first cut: one built-in `provision` executor, run by the
environment runtime (ADR 0048), that applies only a saved plan whose digest
the approved Tenkai plan names.

### 1. The saved plan is bound by the existing plan digest

The provisioning tool needs the backend credentials and state to compute a
saved plan, and those live with the runtime, not the server. So a change is
two Tenkai plans:

1. **Prepare.** A `provision_prepare` step runs the tool's plan command on the
   runtime, read-only against infrastructure, and produces the saved plan.
   The runtime uploads it to the content store sealed to the environment's
   runtime recipient keys (ADR 0045), because saved plans can carry sensitive
   values in clear. As for generated secrets (ADR 0050), the approved prepare
   step names the recipient fingerprints, and the runtime seals only to keys
   that match a named fingerprint and include its own, so a compromised
   server cannot add a recipient of its own. It also sends a rendered summary: each resource address
   with its action (`create`, `update`, `replace`, `delete`, `read`), with
   every attribute value removed. The step's receipt names the digest of the
   plaintext saved plan and the digest of the summary.
2. **Apply.** Planning the change reads that receipt. The saved plan digest
   becomes a desired-state input of the executable plan, and the summary
   feeds the approval brief. Both are inside the plan digest, so the
   existing `plan_digest` in the signed approval already binds them.

No new approval field and no new approval evidence version are needed.
Before it applies, the runtime does not trust the server's pairing of digests
and summary. It:

1. evaluates the approval envelopes against its local approval policy, at
   the strict quorum it uses for sealed steps (ADR 0045), so the server
   cannot approve its own apply;
2. opens the saved plan, and refuses it when its plaintext digest differs
   from the one the approved plan names;
3. renders the summary again from that saved plan, with the same
   deterministic rendering, and refuses the step when it, or the risky-change
   codes derived from it (section 2), differ from the approved plan's.

A compromised server therefore cannot pair a destructive saved plan with a
harmless summary. The tool's own stale-plan check then refuses a saved plan
whose state changed since it was computed.

A prepare step changes no infrastructure but does take the tool's state lock
briefly and reads state with real credentials, so it is an ordinary approved
plan; an environment may auto-approve it under its policy.

### 2. Destroy and replace are flagged risky changes

The brief's rendered target-change counts gain the summary's actions, and the
fixed risky-change list gains two codes:

- `destroyed_resource`: the saved plan deletes a resource;
- `replaced_resource`: the saved plan deletes and recreates a resource.

A plan that carries either code always requires a human, like a downgrade or a
rollback, even under automatic approval; the brief lists the affected
addresses. Because the brief is in the plan digest, an approval given for a
plan without destroys cannot cover a later saved plan that has them.

### 3. Lease, fence and the tool's lock

Tenkai does not claim to fence the state backend. Three existing guards
together prevent a double apply:

- the runtime durably claims the `<plan-id>:<step-id>` idempotency key before
  it starts the tool, and returns the recorded outcome on reconnect
  (runtime protocol v1);
- the runtime holds the environment apply lease while the tool runs, renews
  it as other executors do, and kills the tool's process group on lease loss,
  so a fenced-out runtime stops;
- the tool takes its own state lock, and its stale-plan check refuses a saved
  plan once any apply changed the state, so a second apply of the same saved
  plan, or of an older one, fails.

The first cut supports only remote state backends that provide locking and
versioned state. A local state file, or a backend without locking, is
refused when the release is published. A lock left behind by a killed run is
reported, never broken automatically: releasing it is an operator action with
a recorded reason.

### 4. Crash between apply start and receipt

The idempotency claim means a restarted runtime never starts the same apply
twice. It reports the step `interrupted`, never succeeded. Because a partial
apply leaves the saved plan stale, continuing takes a new prepare and a new
approved plan, whose brief shows what the partial apply left to do.

### 5. Drift is an observation

Observation runs the tool's plan command in refresh-only form on the
runtime's normal observation schedule and reports `drifted` with the change
counts when it finds differences. It never applies. Reconciling drift is a
new prepare and an approved plan.

### 6. One executor, both CLIs

The release names which compatible CLI and which version it needs, signed
with the manifest. Saved plans are not portable across the two CLIs or across
versions, so the runtime refuses a release whose named CLI and version are not
the ones it runs, and a prepare and its apply must use the same pair.

## Kill criteria

Record a no-go if implementing shows any of these:

- the rendered summary cannot be produced deterministically from a saved
  plan, so the brief and the plan digest would differ between replicas;
- attribute values cannot be kept out of the summary and receipts;
- a supported CLI applies a saved plan without refusing a changed state.

## Out of scope

- Breaking or forcing the tool's state lock automatically.
- Backends without locking, and local state files.
- Applying drift corrections without an approved plan.
- Importing existing resources or moving state between configurations.

## Consequences

- An approver sees resource addresses and actions, and a destroy or replace
  always reaches a human.
- Every change costs two plans, prepare and apply; prepare may be automatic.
- Saved plans are stored sealed and bound by digest; the server never reads
  their values.
- A risky-change code list change and a new built-in executor; the approval
  envelope format is unchanged.

## Alternatives considered

- **Keep the shell step.** Approves a script, not the change.
- **Compute the saved plan on the server.** The server would need the backend
  credentials and state, which stay with the runtime.
- **A new approval field for the saved plan digest.** Redundant: the plan
  digest already covers the desired-state inputs, and a new field would need
  a new approval evidence version.
- **Fence the backend from Tenkai.** Needs per-backend conditional writes; the
  tool's stale-plan check and the idempotency claim already refuse a double
  apply.

## Follow-up on acceptance

A feature Issue for the first cut: the `provision` executor, the prepare
step and sealed saved-plan storage, the two risky-change codes, drift
observation, and operator documentation.
