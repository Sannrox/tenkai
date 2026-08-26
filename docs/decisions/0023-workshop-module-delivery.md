# ADR 0023: Workshop module delivery profile

- Status: Accepted
- Date: 2026-08-26
- Issue: [#290](https://github.com/Sannrox/tenkai/issues/290)
- Related: [ADR 0018](0018-change-set-closure-pin.md),
  [ADR 0019](0019-prompt-package-delivery.md),
  [ADR 0021](0021-portable-delivery-manifest-profile.md),
  [Workshop modules](../workshop-modules.md)

## Context

Operators need to publish, promote, activate, and roll back one Workshop
module without changing the environment's type revision or runtime. Workshop
owns presentation. Type revisions and package grants stay with their external
authorities. Tenkai needs only immutable delivery metadata and compatibility
evidence.

`sekai-chisei#690` remains package-authority research (membership, grants,
revocation, conformance). Waiting on that contract would split delivery
ownership. ADR 0018 already admits an accepted change-set closure pin.

## Decision

Add `workshop_module` as a staged Catalog product kind with profile
`tenkai.workshop_module.v1`. Tenkai owns the signed module digest, opaque
type/runtime compatibility pins, channel/plan/apply, activation receipt,
rollback, recall, and recovery. Type and runtime identities are content-bound
digests only. Module payloads stay outside operational storage.

### Authority matrix

| Concern | Owner |
| --- | --- |
| Module release, plan, activation receipt, rollback, recall, recovery | Tenkai |
| Workshop presentation, rendering, sandboxing | Outside Tenkai |
| Type revisions, package grants, revocation authority | External contract (`sekai-chisei#690` related, not this schema) |

### Rules

1. Publication requires an accepted change-set pin. The pin must bind the
   module digest and every declared type/runtime compatibility digest.
2. Planning and apply fail closed unless the environment's observed type and
   runtime digests are in the release compatibility sets.
3. Module-only activation must not change those observed digests.
4. Duplicate apply and restart keep one accepted activation receipt.
5. Failed restore records recovery-required state and does not claim success.
6. Unknown profile, compatibility, or member versions fail closed.

## Consequences

- Operators can deliver one signed module independently of type and runtime
  upgrades.
- `sekai-chisei#690` stays related package-authority research, not a Tenkai
  delivery schema owner.

## Alternatives

1. **Wait for the portable package-authority contract.** Rejected: that
   contract owns grants and membership, not module activation, rollback, or
   recovery.
2. **Embed type or runtime upgrades in module apply.** Rejected by the issue
   non-goals and by operational ownership.
