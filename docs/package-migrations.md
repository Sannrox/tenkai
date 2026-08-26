# Package migrations

A package migration is one immutable Tenkai-owned plan that binds a signed
source package, a signed target package, consumed compatibility evidence, and
ordered checkpoints. Tenkai does not author package contents, classify
compatibility, or run application transforms.

See [ADR 0024](decisions/0024-package-migration.md).

## Declaration

```json
{
  "version": 1,
  "profile": "tenkai.package_migration.v1",
  "source": {
    "product": "pkg",
    "version": "1.0.0",
    "digest": "sha256:…"
  },
  "target": {
    "product": "pkg",
    "version": "1.1.0",
    "digest": "sha256:…"
  },
  "compatibility": {
    "version": 1,
    "status": "compatible",
    "evidence_digest": "sha256:…"
  },
  "checkpoints": [
    { "id": "preflight", "class": "reversible" },
    { "id": "switch", "class": "compensating" },
    {
      "id": "drop-old",
      "class": "irreversible",
      "pre_admission": "require_backup_receipt"
    }
  ]
}
```

Plan identity is content-bound over environment, declaration, and the
optional backup receipt digest. Changing the backup changes the identity.

Source and target digests must match published Catalog releases. Recalled
releases, digest mismatch, unknown profile or compatibility versions, and
`incompatible` evidence fail before the first effect.

Checkpoint classes map to Tenkai-owned effects. `reversible` and
`irreversible` revalidate pins under the environment apply lease.
`compensating` creates and applies a plan for the target pin. Signed
migration approval is an identity-bound
`tenkai.package-migration-approval.v1` envelope; each generated apply plan
still needs its own plan approval next to that envelope as `<plan-id>.json`.

## Checkpoints

| Class | Meaning |
| --- | --- |
| `reversible` | Accepted work can be rolled back in reverse order. |
| `compensating` | Accepted work can be compensated on rollback. |
| `irreversible` | Requires `require_backup_receipt` plus a backup receipt digest at admit. After accept, rollback records `recovery_required` and does not claim success. |

Unknown classes or pre-admission values fail closed.

## Operator workflow

```bash
tenkaictl migrate preview cutover \
  --env local \
  --declaration declaration.json \
  --backup-receipt-digest sha256:…

tenkaictl migrate apply cutover \
  --env local \
  --declaration declaration.json \
  --backup-receipt-digest sha256:… \
  --approval cutover.approval.json \
  --approval-trust-roots migration-approvers.toml

tenkaictl migrate status cutover
tenkaictl migrate resume cutover \
  --approval cutover.approval.json \
  --approval-trust-roots migration-approvers.toml \
  --expected-generation 1
tenkaictl migrate rollback cutover \
  --approval cutover.approval.json \
  --approval-trust-roots migration-approvers.toml
```

Local-only development bypass is restricted to the built-in `local`
environment:

```bash
tenkaictl migrate apply cutover \
  --declaration declaration.json \
  --allow-unapproved-development \
  --development-reason "package migration drill"
```

Apply admits the plan if needed, binds the approval digest, and advances
until the migration is terminal or cannot take another checkpoint. Resume
continues the same identity. A stale `--expected-generation`, an active
environment apply, or another migration on the same environment stops
mutation. Ordinary apply is rejected while the migration lock is held.

Duplicate apply of the same identity is idempotent. Changing checkpoints,
pins, or evidence under the same name is a conflict.

## Recovery

- Compatibility, authorization, lease, or fence failure leaves the
  environment unchanged when no receipt exists.
- After mutation starts, restart reads durable receipts and does not replay
  accepted checkpoints.
- Failed compensation, accepted irreversible work, or rollback after the
  environment has left the migration target is `recovery_required`.
  Inspect the stored record, verify target state, and reconcile before later
  delivery.
- Recovery uses Tenkai receipts and the operator-supplied backup receipt
  digest. Ontology or governance availability is not required.

## Example

[examples/package-migration](../examples/package-migration/) contains
synthetic source and target software fixtures plus a declaration template.
