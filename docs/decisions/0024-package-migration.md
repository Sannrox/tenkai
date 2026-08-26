# ADR 0024: Governed package-migration plan

- Status: Accepted
- Date: 2026-08-26
- Issue: [#289](https://github.com/Sannrox/tenkai/issues/289)
- Related: [ADR 0017](0017-executable-release-waves.md),
  [ADR 0018](0018-change-set-closure-pin.md),
  [ADR 0021](0021-portable-delivery-manifest-profile.md),
  [Package migrations](../package-migrations.md)

## Context

Tenkai can roll signed releases forward and back, but an interrupted stateful
package change is ambiguous unless source, target, compatibility evidence, and
checkpoint results live in one immutable plan. Package definitions and
compatibility classification stay with their external authorities. Tenkai must
consume those declarations without embedding transforms in the control plane.

`sekai-chisei#690` remains package-authority research (membership, grants,
revocation, conformance). Waiting on that contract would split operational
ownership of fencing, receipts, rollback, and recovery.

## Decision

Add profile `tenkai.package_migration.v1` as a Tenkai-owned coordinator. The
plan identity is content-bound over environment, source pin, target pin,
compatibility evidence, ordered checkpoints, and the backup receipt digest.
Tenkai executes, resumes,
rolls back, or records recovery-required state under the environment fence.

### Authority matrix

| Concern | Owner |
| --- | --- |
| Migration plan, approval digest, checkpoint receipts, fence, rollback, recovery | Tenkai |
| Package contents, ontology revisions, compatibility policy, transforms | External authorities |
| Package membership, grants, revocation | External contract (`sekai-chisei#690` related, not this schema) |

### Rules

1. Source and target pins must name the same product and published,
   non-recalled Catalog releases whose stored digests match the declaration.
2. Compatibility evidence is consumed, not classified. Only `compatible`
   status with a content-bound digest admits. Unknown versions fail closed.
3. Every checkpoint is `reversible`, `compensating`, or `irreversible` before
   approval. Irreversible checkpoints require explicit pre-admission
   `require_backup_receipt` and a backup receipt digest at admit.
4. Unauthorized, stale-fence, unapproved, or lease-held execution fails
   before the next effect. A signed approval is an identity-bound envelope
   verified against trust roots. Execution claims the environment migration
   lock and, for revalidation, the shared apply lease. Compensating
   checkpoints apply the target pin through existing plan execution.
   Restart resumes from durable receipts.
5. Identical identity is idempotent. A changed declaration under the same
   name is a conflict.
6. Rollback reverses accepted reversible and compensating work. Accepted
   irreversible work records `recovery_required` and never reports rollback
   success.

## Consequences

- Operators can preview, approve, execute, resume, and roll back one
  package cutover without inventing a second executor.
- `sekai-chisei#690` stays related package-authority research, not the
  migration-plan owner.

## Alternatives

1. **Wait for the portable package-authority contract.** Rejected: that
   contract owns grants and membership, not environment fencing, receipts,
   or recovery.
2. **Treat migration as an ordinary release apply.** Rejected: release status
   does not prove which checkpoint completed or whether reversal is safe.
3. **Embed transforms in Tenkai.** Rejected by the issue non-goals and by
   operational ownership.
