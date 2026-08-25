# Rollout-control simplification research

Issue: [#189](https://github.com/Sannrox/tenkai/issues/189)

Date: 2026-07-29

Conclusion: **standardize**

## Question and evidence

This research asks whether channels, canary designation and promotion policy,
waves, maintenance windows, environment facts, and constraints should become
one versioned operator-facing rollout policy.

The audit uses the tracked CLI definitions and the authoritative implementations
in `src/catalog.rs`, `src/canary.rs`, `src/wave.rs`, `src/maintenance.rs`,
`src/plan.rs`, `src/apply.rs`, and `src/storage.rs`. No tracked portable
ontology database is available in this worktree, so ontology supplies no
evidence for this decision.

## One responsibility per control

| Control | Responsibility | Persisted authority | Mutation / observation |
| --- | --- | --- | --- |
| Channel plus subscription | Select the publisher's release ceiling and the product stream an environment follows. | Revisioned channel head and environment subscription link. | `promote`; `env subscribe`; plan and status inspect the result. |
| Canary designation | Classify environments that may be named in a canary cohort. | Environment canary marker. | `canary designate`. |
| Canary promotion policy | Authorize one content-bound release promotion only after every named cohort outcome passes. | Versioned, activated policy plus durable attempt evidence and promotion lock. | `canary policy`; promotion fails closed; `repair` and `unlock` are explicit recovery. |
| Wave | Observe named environments in caller-provided order and stop or continue after an unhealthy/missing result. | No durable wave policy or history. | `wave run`; never applies or authorizes promotion. |
| Maintenance window | Schedule when a plan may start. | Governed, revisioned environment configuration with authorization evidence. | `env maintenance set/list/remove/repair`; apply blocks outside the window. |
| Environment facts | Record observed target capabilities. | Environment-scoped fact properties. | `env facts set/list/clear/probe`; facts alone do not select releases. |
| Constraints | Select eligible versions and require facts during planning. | Environment constraint properties. | `env constraints set/list/clear`; planning fails closed when unsatisfied. |
| Emergency override | Separately authorize starting outside a window with immutable principal/reason evidence. | Plan lifecycle and governed-action evidence. | `apply --emergency-reason`; does not bypass signing, approval, canary, health, or rollback. |
| Rollback | Recover the deployed environment to a pinned prior release without rewriting the channel head. | Durable rollback intent, checkpoint, lease generation, and outcome. | Automatic apply recovery or explicit `rollback`; status may remain `behind`. |

The controls overlap in the word “rollout,” not in authority. Selection,
ordering, authorization, scheduling, observation, and recovery remain separate:

- **Selection:** channel/subscription, version constraints, and fact matching.
- **Ordering:** immutable plan step order; waves only order observations.
- **Authorization:** release/plan approval, canary promotion evidence, and the
  separate emergency decision.
- **Scheduling:** maintenance eligibility at apply start.
- **Observation:** health, fleet posture, and wave reports.
- **Recovery:** automatic or deliberate rollback under lease fencing.

## Required scenarios

| Scenario | Decisions and state | Commands and evidence | Recovery |
| --- | --- | --- | --- |
| Stable-channel convergence | Publisher moves a revisioned channel head; environment subscription selects it; planner pins the release. | `promote`, `env subscribe`, `plan`, `apply`; signed release and plan approval where required. | Retry/reconcile from the durable plan; rollback does not rewrite the channel. |
| Canary before wider promotion | Designated cohort and content-bound policy require complete passing outcomes. | `canary designate`, promote to a free canary channel, `canary policy`, cohort plan/apply, then target-channel `promote`. | `canary repair` rebuilds evidence; `unlock` only clears an abandoned promotion lock. Failed or rolled-back outcomes remain blocking. |
| Canary → stage → production observation | The caller supplies observation order; each environment retains its own subscriptions, plans, approvals, and maintenance rules. | `wave run canary,stage,prod`; report includes ordered posture and stop/continue behavior. | Rerun observation after correcting the failed environment. Wave state cannot resume execution because it never executes. |
| Maintenance blocking | Governed schedule is evaluated at exact apply start; invalid or closed schedules fail closed. | `env maintenance set/list`; `apply` records a blocked plan with schedule detail. | Retry apply when open; `maintenance repair` replaces invalid configuration through the explicit recovery path. |
| Version pins and ranges | Planner resolves the subscribed head against environment constraints. | `env constraints set ... version_pin|version_range`; plan contains the selected immutable release. | Clear/change the constraint or promote a compatible release; old plans retain their interpretation. |
| Hardware-fact selection | Recorded facts are matched against model-runtime requirements and required-fact constraints. | `env facts probe/set`, `env constraints set ... require_fact`, `plan`. | Correct inventory or publish a feasible variant; absence/mismatch fails before mutation. |
| Emergency override | A separately governed decision permits only an out-of-window start and binds actor plus reason. | `apply --emergency-reason`; approval, signing, gates, fencing, health, and rollback still apply. | Normal rollback/reconcile paths; the override cannot be reused as general bypass evidence. |
| Partial failure and rollback | Apply records step/health outcome and durable rollback intent under the current lease generation. | `apply`, `status`, optional explicit `rollback`; receipts and checkpoints identify progress. | Resume/reconcile from Tenkai-owned state. Channel head stays unchanged, making residual `behind` posture visible. |

## Versioned policy prototype

`tests/rollout_policy_view_prototype.rs` preserves a research-only
`tenkai.rollout-policy-view.v1` representation. It composes references to the
existing authorities:

```rust
struct RolloutPolicyViewV1 {
    selection: SelectionRefs,
    authorization: AuthorizationRefs,
    scheduling: SchedulingRefs,
    observation: ObservationRefs,
    recovery: RecoveryRefs,
}
```

The test proves that all eight scenarios can be described in one read model,
but none can delete its source concepts: the view still needs channel,
subscription, constraint, fact, canary-policy, maintenance, wave, approval,
health, and rollback references. It is reproducible with:

```bash
cargo test --locked --test rollout_policy_view_prototype
```

This is useful as a diagnostic or documentation projection. Making it writable
would create a new authority that either duplicates existing state or attempts
a distributed update across channel revisions, governed maintenance evidence,
environment properties, canary activation, and non-durable wave input.

## Complexity accounting

Current operator surface directly involved in the scenarios:

- 7 named rollout-control concepts from the issue, plus the separately visible
  emergency and rollback concepts.
- 7 command families (`promote`, `env subscribe`, `canary`, `wave`,
  `env maintenance`, `env facts`, and `env constraints`).
- 19 relevant command operations or flags when canary recovery, maintenance
  recovery, fact/constraint CRUD, emergency apply, and rollback are counted.
- At least 6 documentation paths: README maintenance/constraints, local
  dogfood canary, rollout waves, model runtime selection/canary, software
  executor rollback, and maintenance/approval guidance.
- Distinct state transitions for channel revision, policy activation, plan
  blocking/execution, health outcome, and rollback lifecycle. Waves add no
  durable transition.

A new writable rollout-policy command cannot replace legacy forms without a
breaking migration. During compatibility it would produce:

- 1 additional public concept and at least `rollout-policy set/show`;
- 21 or more relevant operations while legacy commands remain supported;
- the same underlying state transitions plus projection/application status;
- a new schema version, cross-object validation, partial-update semantics,
  inspection mapping, migration, and conflict diagnostics; and
- no retired trust decision, because canary evidence, maintenance governance,
  approval, emergency authorization, and rollback must remain independently
  auditable.

A read-only view adds one documentation/diagnostic path but no state or
authority. It standardizes explanation without displacing failure complexity
into the planner.

## Recommendation

Standardize the operator model around five verbs:

1. **select** with channel/subscription, constraints, and facts;
2. **authorize** with signing, approval, and canary evidence;
3. **schedule** with maintenance windows and a separate emergency decision;
4. **observe** with status/fleet/waves and health evidence; and
5. **recover** with rollback and reconciliation.

Keep the existing commands and persisted owners. Integrate their diagnostics in
documentation and, only if operator evidence later justifies implementation, a
read-only versioned rollout view. Do not introduce a writable unified policy,
automatic wave execution, or migration now.

This conclusion does not recommend structural unification, so no Design
Discussion is required by #189. A future writable-policy proposal would require
one before implementation.

Amendment (2026-08-24, ADR 0017 / #283): executable waves now persist a durable
advancement coordinator over existing per-environment plans. That does not
collapse canary, maintenance, or rollback into the wave, and `wave run` remains
observe-only.
