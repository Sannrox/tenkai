# ADR 0020: Connectivity-class upgrade lifecycle

- Status: Accepted
- Date: 2026-08-25
- Issue: [#287](https://github.com/Sannrox/tenkai/issues/287)
- Related: [ADR 0003](0003-canonical-offline-delivery-archives.md),
  [ADR 0010](0010-supported-operating-profiles.md),
  [ADR 0017](0017-executable-release-waves.md),
  [Runtime protocol v1](../runtime-protocol-v1.md),
  [Offline bundles](../offline-bundles.md)

## Context

Connected pull runtimes, intermittent resume, and isolated archives already
exist as separate surfaces. Operators still cannot carry one signed release
and exact approved plan through a fleet that mixes those classes without
changing identity, trust, or recovery rules.

A second executor or a class-specific promotion path would split authority.
Connectivity must remain an environment property over one Tenkai-owned
lifecycle.

## Decision

Tenkai owns one **connectivity-class upgrade coordinator**. It does not apply,
import, or roll back outside existing plan, approval, gate, lease, receipt,
offline-bundle, and recovery contracts. Connectivity class selects the
adapter; it never weakens trust.

### Authority matrix

| Concern | Authoritative owner | Contract boundary |
| --- | --- | --- |
| Release, channel, plan, approval, apply, health, receipts, rollback, recovery | Tenkai | Same identity model for every class. First accepted receipt wins. |
| Environment connectivity class | Tenkai environment state | `connected`, `intermittent`, or `isolated`. Unknown values fail closed. |
| Connected work pull and completion | Existing runtime protocol | Lease generation fences mutation. Stale completions are rejected. |
| Intermittent transfer resume | Tenkai transfer checkpoint | Checkpoint binds plan, release, artifact, and generation. Resume continues only from verified content identity. Reconnect cannot revive an old generation. |
| Isolated archive and receipt | ADR 0003 offline bundle/receipt | Export, verify, execute, import, and replay use signed bundle and receipt identity. Damaged media is discarded and re-exported. |
| Optional providers | Evidence adapters | Missing required evidence fails closed. Recovery never depends on them. |

### Advancement rules

1. **One named upgrade, one identity.** Identity is content-bound over name,
   product, version, channel, release digests, ordered environments, and
   classes. Retry is idempotent; any change is a conflict.
2. **Revalidate before mutation.** Release signatures or unsigned-local policy,
   content digests, channel head, recall, environment registration,
   subscription, class, approval, and required capabilities are checked again
   immediately before each environment mutates.
3. **Class adapters only.** Connected executes the approved plan. Intermittent
   must complete a verified transfer checkpoint under the current generation
   before execution. Isolated must verify a signed bundle before execution and
   bind the signed receipt to that bundle.
4. **Interrupt is explicit.** An incomplete transfer or missing isolated
   receipt is `interrupted`, never success. Restart resumes the same
   identities without executing an accepted step twice.
5. **Conflicts stay visible.** Duplicate identical receipts are idempotent.
   Conflicting outcomes cannot overwrite the first accepted result.
6. **Rollback is Tenkai-owned.** Failed health or apply uses existing rollback
   plans. Failed restore records `recovery_required`.

### Compatibility

The first persisted upgrade schema is format version `1`. Older databases
require `tenkaictl init` (additive object type). Historical plans, receipts,
and offline archives keep their original decoders. Unknown protocol or bundle
versions fail closed.

## Consequences

- Operators can inspect one upgrade status across connected, intermittent, and
  isolated environments.
- Waves remain cohort coordinators (ADR 0017). Connectivity class does not
  promote channels.
- Embedded and server hosts share the same functions and recovery material.

## Alternatives

1. **Keep three operator workflows.** Rejected: transfer, reconnect, and
   receipt conflicts stay uncorrelated.
2. **Class-specific executors that skip approval or gates.** Rejected: that
   makes disconnection a trust bypass.
3. **Wave as the only coordinator.** Rejected: waves do not own transfer
   checkpoints or offline archive identity.

## Sources

- [Issue #287](https://github.com/Sannrox/tenkai/issues/287)
- [Issue #283](https://github.com/Sannrox/tenkai/issues/283) (completed predecessor)
