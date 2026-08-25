# ADR 0019: Versioned prompt-package delivery

- Status: Accepted
- Date: 2026-08-25
- Issue: [#285](https://github.com/Sannrox/tenkai/issues/285)
- Related: [Staged products](../staged-products.md),
  [ADR 0013](0013-evaluation-gate-evidence-projection.md)

## Context

Tenkai already delivers policy, eval-suite, and agent-definition documents as
closed staged product kinds. Operators still cannot promote a prompt package
and know that the activated bytes are exactly those evaluated and approved.
Prompt authoring, model selection, and evaluation execution remain outside
Tenkai.

## Decision

Add `prompt_package` as a staged Catalog product kind. Tenkai owns immutable
package metadata, channel promotion, environment planning, activation records,
rollback, and recovery. External evaluation systems supply bounded gate
evidence only.

### Authority matrix

| Concern | Owner |
| --- | --- |
| Prompt package release, plan, activation, rollback, recovery | Tenkai |
| Prompt authoring, templating, model routing | Outside Tenkai |
| Evaluation run selection and scoring | Gate provider (fail closed when required) |

### Rules

1. Package identity is content-bound: package_id, runtime, eval_suite pin, and
   every prompt body participate in the staged document digest.
2. `[gate].eval_suite` must equal the package evaluation pin. Missing, stale,
   mismatched, or failing evidence blocks apply. Provider absence is not
   approval.
3. Credentials, private keys, prompt inputs, and model outputs are excluded.
4. Activation is atomic. Restart is idempotent. Failed activation restores the
   previous package or records recovery-required state through existing apply
   cleanup.

## Consequences

- Operators can publish, promote, plan, apply, inspect, and roll back one
  signed prompt package through the existing release lifecycle.
- Product-kind vocabulary grows by one closed staged kind; unknown kinds still
  fail closed.

## Alternatives

1. **Reuse `agent_definition`.** Rejected: agents are runtime descriptors, not
   prompt content, and would blur orchestration non-goals.
2. **Author prompts inside Tenkai.** Rejected by the issue non-goals.
