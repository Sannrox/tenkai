# ADR 0037: Multi-party plan approval

- Status: Accepted
- Date: 2026-10-25
- Issue: [#681](https://github.com/Sannrox/tenkai/issues/681)
- Owner: Tenkai maintainers
- Related: [plan approval](../plan-approval.md), [key ceremony](../key-ceremony.md)

## Context

A `tenkai.plan-approval.v1` envelope carries one `key_id` and one signature.
Sites that require two-person control for production changes, rollback, or
`--skip-gates` cannot express it. The key ceremony already has dual control;
plans did not. Changing the signed envelope would break every existing
approval.

## Decision

1. **Keep the v1 envelope.** Each envelope still binds one signer to one plan
   digest. N-of-M is a set of those envelopes, not a new schema.
2. **Policy names the quorum.** An optional `[[quorum]]` table on the
   environment approval policy sets `n`, named signer groups, purpose
   (`execute_plan`, `rollback`, `skip_gates`, `downgrade`), and whether the
   apply requester may count. Purpose is derived from the plan and apply
   flags. Absent a matching rule, one trusted envelope still authorizes.
3. **Distinctness is by key and principal.** Two envelopes from the same key
   or the same trust-root identity count once. Signers list optional `groups`
   on the trust roots. Automatic approval cannot satisfy `n > 1`.
4. **Collect offline or one at a time.** Apply accepts a file, a JSON array,
   or a directory of envelopes. `POST /v1/plans/{plan_id}/approve` stores one
   verified envelope. `GET /v1/plans/{plan_id}/approvals` shows collected and
   missing. Apply unions request envelopes with stored ones and refuses until
   N valid, unexpired envelopes are present, listing what is missing.

## Consequences

- Existing single-envelope policies, CLI flags, and apply bodies keep working.
- Dual control is an additive policy field, not a new signature format.
- Console collection UI is a later slice; this slice is the control plane.

## Alternatives considered

- **Put N signatures in one envelope.** Rejected: that changes the v1
  canonical bytes and forces every signer to share one document.
- **Distinctness by key only.** Rejected: one person with two keys would
  satisfy two-person control.
- **Require one signer from each named group.** Rejected: the issue is N of M
  distinct signers from the named groups, not M-of-M across groups.
