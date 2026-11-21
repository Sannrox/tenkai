# ADR 0060: Agent budgets and release previews

- Status: Proposed
- Date: 2026-11-20
- Issue: [#1533](https://github.com/Sannrox/tenkai/issues/1533)
- Owner: Tenkai maintainers
- Amends: [ADR 0034](0034-agent-actor-mutations.md) §3
- Builds on: [ADR 0037](0037-multi-party-plan-approval.md),
  [ADR 0045](0045-sealed-secrets.md)
- Related: [plan approval](../plan-approval.md),
  [preview environments](../preview-environments.md), #1091, #1092

## Context

ADR 0034 lets an agent create plans and refuses every other agent mutation.
In an environment with automatic approval, an agent's forward plan runs as
the reconciler's own plan would. Operators can choose only between agents
never shipping (`forbid`) and agents shipping whatever automatic approval
allows. Two features need a middle ground:

- per-agent limits on what automatic approval signs for an agent (#1091);
- previews of a signed release that an agent creates and deploys to over
  the API, so it can collect evidence before a human approves production
  (#1092).

Facts this decision relies on, read from source:

- The approval brief records the proposer and its actor chain, and the plan
  digest covers the brief (`src/plan/approval_brief.rs`). The agent on a
  plan is therefore bound to the plan, not taken from the apply request.
- Automatic approval is signed by the reconciler inside the environment's
  generation-fenced tick (`src/reconciler/environment_lifecycle.rs`).
- `ApprovalPolicy` denies unknown fields (`src/approval_policy.rs`), so a
  server that does not know a new table refuses to load the policy.
- `evaluate` already requires a human for host steps, quorum `n > 1`,
  `skip_gates`, rollback, downgrade, migrations, and identity changes.
- Plans store `created_at`, `state`, and their steps. Product maintenance
  windows already apply to every plan.
- A preview is a `tenkai.environment` with `environment_kind=preview`,
  non-promotable, torn down at expiry by the reconciler
  (`src/preview.rs`). Only embedded `tenkaictl` creates one today.
- A sealed value's associated data names its environment and instance
  (ADR 0045 §1), so a runtime refuses to write a parent's secret into a
  preview.

## Decision

### 1. Agent rules live in the environment approval policy

An optional `[[agent]]` table on the approval policy (ADR 0037) limits what
automatic approval signs for an agent in that environment:

```toml
[[agent]]
id = "assistant-7"           # an agent id from the actor chain, or "*"
products = ["web", "api"]    # optional; absent means every product
max_criticality = "medium"   # optional; low, medium, high, critical
max_instances = 20           # optional; instances changed per period
period_ms = 86400000         # required with max_instances
```

- **Per environment.** A rule limits the environment whose policy carries
  it. "Allowed environments" is which environment policies name the agent.
  There is no fleet-wide budget.
- **Matching.** An exact `id` match wins over `"*"`. Two rules with the same
  `id` fail policy load. No glob patterns.
- **Every agent counts.** Each agent in the plan's actor chain, read from the
  approval brief, must match a rule and be inside it. One failing agent
  sends the plan to a human.
- **No rule, no automatic approval.** When a policy has any `[[agent]]`
  table and an agent on the plan matches none, the plan needs a human. A
  policy without `[[agent]]` evaluates exactly as today.
- **Windows are not a knob.** Maintenance windows already apply to every
  plan, agent or not. No rule field bypasses them.
- **Agent rules only take authority away.** They never satisfy a check that
  `evaluate` already requires a human for.

### 2. Budget use comes from stored plans

An agent's use is the number of distinct instances changed by plans in the
same environment whose approval brief names that agent and whose
`execution_admitted_at` is inside the last `period_ms`.

`execution_admitted_at` is a new plan field, written in the same store
transaction that moves a plan from `computed` to `running`. It sits outside
the plan's content address, like `maintenance_blocked`. Counting by
admission, not `created_at`, matters: a plan that waits through a
maintenance window counts from when it ran, so it cannot age out of the
period at the moment it runs. A plan without the field was admitted
before this feature and never counts, since no agent rule existed then.

Tenkai stores no separate counter, and a restarted server or a second
replica reads the same count from the same plans.

The count is taken where automatic approval is signed, inside the
environment's fenced tick, and that tick is also where the plan starts
running. Two replicas cannot both sign within one budget for the same
environment. A plan whose own instances would push the count over
`max_instances` needs a human. If the count cannot be read, the plan needs
a human.

### 3. Reason codes

Plans sent to a human by an agent rule carry a stable code in the approval
brief policy reason and in `status`:

| Code | Meaning |
| --- | --- |
| `agent_rule.none` | an agent on the plan matches no rule |
| `agent_rule.product` | a product is outside `products` |
| `agent_rule.criticality` | effective criticality is above `max_criticality` |
| `agent_rule.instances` | the plan would exceed `max_instances` in `period_ms` |
| `agent_rule.unreadable` | budget use could not be read |

The brief records the evaluation at planning time. The reconciler evaluates
again when signing, and that result decides. A plan that was in budget at
planning but not at signing waits for a human with the code in `status`.

### 4. Agents may open and close release previews

This amends ADR 0034 §3. An agent may create and close a preview through the
versioned API, and may plan in it. Nothing else changes in §3: an agent still
cannot apply, approve, set secrets, or write evidence. Previews run because
their approval is automatic, not because the agent is allowed to apply.

The parent environment's approval policy opts in with one table:

```toml
[preview]
max_active = 3
max_lifetime_ms = 86400000
products = ["web"]                 # optional; absent means every product
auto_signer_key = "/var/lib/tenkai/preview-approver.ed25519"
```

- No `[preview]` table, or a parent policy that cannot be read: preview
  creation over the API is refused. Embedded branch-pin previews keep
  working as they do now.
- Expiry is required and at most `max_lifetime_ms`.
- `max_active` counts the parent's previews that are not torn down.
  Admission writes to the parent environment record with a version check,
  so two concurrent creations cannot both take the last slot. The loser
  re-reads the count and is refused with `preview.limit`.
- A preview's plans are signed automatically by `auto_signer_key`. Every
  check that `evaluate` requires a human for still requires one: rollback,
  downgrade, migrations, identity changes, host steps, and `skip_gates`.
  `[[agent]]` rules do not apply inside a preview. The `[preview]` limits
  are its budget.
- The preview signer's trust-root entry is scoped with a new signer field,
  `preview_parents = ["<parent>"]`, next to `providers = ["builtin-auto"]`,
  instead of `environments`. It verifies only plans of previews whose
  parent is listed. It cannot sign for the parent or for any other
  environment.

### 5. A release preview is the existing preview with a second pin

A preview binds either the existing `tenkai.branch_pin.v1` or a new
`tenkai.release_pin.v1`: product, release id, and signed release digest.
Both use one environment kind and one teardown path, with the same
invariants (non-promotable, idempotent replay, torn-down names never
reused, teardown never touches a non-preview environment). A release pin
names a release that is already signed in the catalog. Pinning does not
publish anything.

Teardown today only forgets deployments: it clears the `deployed.*`
properties and marks the preview torn down (`src/preview.rs`
`persist_teardown`). That is not enough once agents deploy to previews. On
expiry or close, a preview with deployed instances first moves to
`closing`, and the reconciler runs a plan of `Remove` steps for them,
signed by the preview signer like any other preview plan. The preview is
marked torn down only after that plan succeeds. A `closing` preview still
counts toward `max_active`, cannot be planned onto, and retries removal
each tick. A failed removal stays visible in `status`. Closing or creating
previews over and over therefore cannot leave workloads running past
the limit.

### 6. Previews hold no parent secrets or data

A preview gets its own instances. Tenkai copies no volumes, sealed values, or
bindings from the parent. ADR 0045 already prevents a sealed value from being
written outside the environment and instance it was sealed for. A human may
set secrets for a preview with `secret set` like any environment. Agents
cannot. What "production data" means outside Tenkai's own state is out of
scope.

### 7. Preview evidence is derived, never attached

There is no attach route. When the planner builds a plan for an environment,
it looks up health-gate evidence that Tenkai recorded for that release digest
in previews whose parent is this environment, and lists it on the approval
brief (`preview:<preview>:<plan-id>`). Evidence from a different digest or
another parent never appears. The listing informs the approver. It does not
satisfy a gate or count as an approval. Test results reported by an agent are
evidence writes and stay refused.

## Consequences

- An operator can let an agent ship small changes to chosen products in one
  environment and send everything else to a human.
- Budgets add one optional plan field and no counter table. Older plans
  read without it. Their cost is a plan query in the signing tick,
  bounded by the period.
- During a rolling deploy, an older server refuses to load a policy with
  `[[agent]]` or `[preview]`. That environment stops automatic approval and
  reports the load error until every server is upgraded. That fails closed,
  but it is visible downtime for automatic approval, so release notes must
  say to upgrade every server before editing policies.
- Branch-pin preview teardown that actually removes deployed instances is
  [#1536](https://github.com/Sannrox/tenkai/issues/1536). This decision
  applies the same `closing` then `Remove` path to release previews.
- Previews widen agent authority to deploying inside a preview. Every
  human-only check still applies there, and a preview cannot receive a
  parent's secrets.
- The `preview_parents` signer scope must be enforced by plan approval
  verification before any preview signer is configured. A server that does
  not know the field must refuse that signer, never treat it as unscoped.

## Alternatives considered

- **A fleet-wide budget per agent.** Rejected: counting across environments
  is not fenced by any one environment's tick, so two replicas could both
  sign within the same budget.
- **A stored budget counter.** Rejected: it duplicates what plan records
  already say and adds a second place to keep consistent.
- **Counting by `created_at`.** Rejected: a plan that waits past the period
  before running would leave the count as it starts.
- **A maintenance-window flag on agent rules.** Rejected: windows already
  bind every plan, and a flag could only weaken them.
- **Letting agents call apply inside a preview.** Rejected: it adds a second
  path for agent authority. Automatic signing already runs plans.
- **A separate release-preview object.** Rejected: it would duplicate the
  teardown and invariants that the branch-pin preview already proves.
- **An attach-evidence route.** Rejected: it makes evidence an agent write.
  Derived evidence cannot be forged by the proposer.
- **Copying parent secrets into a preview when policy allows.** Rejected:
  sealed values are bound to their environment and instance by design.
