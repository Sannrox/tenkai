# ADR 0022: External delivery adapter boundary

- Status: Accepted
- Date: 2026-08-25
- Issue: [#292](https://github.com/Sannrox/tenkai/issues/292)
- Related: [ADR 0021](0021-portable-delivery-manifest-profile.md),
  [Runtime protocol v1](../runtime-protocol-v1.md)

## Context

External delivery systems can apply supported targets, but treating request
acceptance as success, or storing their platform state as deployment truth,
would create a second operational owner.

`#291` has landed the delivery-manifest profile. The remaining design choice is
how Tenkai may delegate a bounded effect without ceding plan, gate, receipt,
rollback, or recovery authority.

## Decision

External systems are **replaceable execution adapters**. They may apply,
observe, cancel where supported, and return attributable observations. They
cannot create or approve Tenkai plans, gates, releases, or rollback intent.

### Authority matrix

| Concern | Owner | Adapter |
| --- | --- | --- |
| Release, plan, approval, gates, lease, fence | Tenkai | Must fail closed before delegation if any is missing. |
| Terminal receipt and recovery | Tenkai operational store | Observations are admitted only as runtime completions bound to plan, environment, step, and attempt. |
| Apply acknowledgement | Adapter | Never success. The step stays non-terminal until a valid receipt. |
| Timeout / missing outcome | Tenkai | Explicit non-terminal; operator reconciles. Never inferred success. |
| Conflicting observations | Tenkai | First accepted receipt wins. |
| Credentials | Adapter secret store | Never in plans, receipts, or logs. |

### Observation model

Tenkai **polls** `observe`. A callback is only a way to present the same
`RuntimeCompletion` bytes; it has no extra authority. Unknown required adapter
capabilities fail closed. Duplicate identical receipts are idempotent.

## Consequences

- Two independent adapter fixtures can execute one signed plan and must produce
  equivalent Tenkai receipts.
- Health failure uses Tenkai rollback; failed restore stays recovery-required.
- New incompatible adapter contracts need a new major profile.

## Alternatives

Push-only callbacks were rejected: they would let a foreign host mutate
lifecycle without Tenkai polling correlation. Dual operational stores were
rejected: recovery must not depend on the adapter.
