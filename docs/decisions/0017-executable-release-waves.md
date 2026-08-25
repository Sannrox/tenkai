# ADR 0017: Executable release-wave advancement

- Status: Accepted
- Date: 2026-08-24
- Issue: [#283](https://github.com/Sannrox/tenkai/issues/283)
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [ADR 0010](0010-supported-operating-profiles.md),
  [Rollout waves](../rollout-waves.md),
  [Plan approval](../plan-approval.md),
  [Canary promotion](../model-runtime.md#canary-promotion-evidence-model_runtime)

## Context

Tenkai already observes an ordered environment cohort (`tenkaictl wave run`)
without durable wave identity, per-environment plan binding, or restart
resumption. Turning that observation into execution can split authority: a
wave scheduler that applies, promotes, or rolls back outside the existing
plan, approval, gate, lease, health, receipt, and recovery contracts would
become a second control plane.

The accepted observe-only contract must remain: `wave run` never applies and
never authorizes channel promotion. Canary cohort evidence remains the only
promotion gate.

## Decision

A wave is a **durable advancement coordinator**, not an executor, promoter, or
recovery store. Tenkai remains the sole operational owner of release,
environment, executable plan, approval, execution, health interpretation,
receipt, rollback, and recovery. Ontology, governance, and evaluation stay
bounded evidence providers; missing, stale, or invalid required evidence fails
closed. Optional providers are never required to resume or roll back a wave.

### Authority matrix

| Concern | Authoritative owner | Contract boundary |
| --- | --- | --- |
| Release identity and channel head | Tenkai Catalog | Wave admission pins one exact release (`release_id`, manifest digest, artifact digest) and the channel head that currently names it. A later head move is a stale-channel conflict, not a silent retarget. |
| Environment scope and subscriptions | Tenkai environment state | Every cohort member must exist and be subscribed to the pinned product/channel at admission and again immediately before that environment executes. |
| Executable plan, approval, gates, apply, health, receipts | Existing Tenkai plan and apply contracts | The wave creates or resumes one environment-scoped plan and calls `apply::execute_with_options`. It does not install, probe, or write deployed facts itself. |
| Wave identity, cohort order, stop/continue, operator stop | Tenkai wave record | Content-bound identity over name, product, version, channel, release digests, ordered environments, and fail policy. Same identity is idempotent; any change is a conflict. |
| Channel promotion | Canary evidence | Waves never promote a channel and never substitute for canary cohort evidence. |
| Environment leases and fencing | Existing apply lease/generation | Only the current generation may complete an environment's wave work. Late or foreign completions are rejected. |
| Rollback and recovery | Tenkai-owned rollback plans plus the wave record | Stop-on-failure keeps completed cohorts and leaves later work unstarted. Deliberate rollback uses Tenkai rollback plans. Restart reloads the wave from Tenkai operational storage. |

### Advancement rules

1. **Observe stays observe.** `tenkaictl wave run` remains a non-mutating
   posture report. Executable waves are a separate command family.
2. **One named wave, one identity.** `tenkai:wave:<name>` is the durable key.
   Retrying the same request resumes that record. Changing cohort order,
   release identity, channel, or fail policy under the same name is rejected.
3. **Advance one environment at a time.** The next unstarted (or
   awaiting-approval) environment is planned, revalidated, authorized, and
   executed only after the previous environment has a terminal receipt.
   Stop-on-failure marks remaining environments `skipped` and does not rewrite
   completed outcomes. Continue-after-failure records the failure and proceeds.
4. **Revalidate at admission and immediately before execute.** Release
   signatures or unsigned-local policy, content digests, channel head, recall
   state, environment registration, subscription, and plan approval are checked
   again before each environment mutates. Unauthorized starts, expired
   approvals, failed or missing gates, stale heads, and recalled content fail
   closed without advancing.
5. **Idempotent resume.** A completed environment is never applied again.
   Restart between cohorts or after a terminal receipt reloads durable state.
   A plan left `running` or an environment whose live state is unknown becomes
   `recovery_required` until normal environment reconciliation makes the
   target unambiguous; the wave does not guess success.
6. **Rollback is explicit.** `wave rollback` builds Tenkai rollback plans for
   succeeded cohorts (reverse order) and executes them through the same
   approval and fencing path. It does not invent a second rollback authority
   and does not require an optional provider.

### Compatibility

The first persisted wave schema is format version `1`. Older databases without
the wave object type require `tenkaictl init` (schema registration is additive).
Historical observe-only behavior and stored releases, plans, and receipts are
not reinterpreted. Wave records store identifiers, digests, statuses, and
bounded detail; credentials, private keys, command output, and unbounded logs
are excluded.

## Consequences

- Operators can start, inspect, resume, stop, and roll back one durable
  release wave through named cohorts.
- Embedded and server hosts share the same application functions, transaction
  boundaries, and recovery material.
- Downstream fleet scale and connectivity-class work (#286, #287) can assume
  this advancement contract without introducing a second promotion path.

## Alternatives

1. **Keep observe-only waves.** Rejected: operators still cannot carry one
   approved release through cohorts with restart-safe evidence.
2. **Wave as a fleet executor that applies without per-environment plans.**
   Rejected: that creates a second execution authority and bypasses approval,
   gates, leases, and receipts.
3. **Wave-authorized channel promotion.** Rejected: canary evidence is the
   promotion gate; a wave that promotes would split that authority.

## Sources

- [Issue #283](https://github.com/Sannrox/tenkai/issues/283)
- [Rollout-control simplification research](../research/rollout-control-simplification.md)
  (observe-only historical contract; this ADR extends execution without
  collapsing canary, maintenance, or rollback into the wave)
