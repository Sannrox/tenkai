# Package migration fixture

Synthetic source-to-target software pins plus a bounded local fixture target.
The declaration binds Catalog digests and consumed compatibility evidence. It
does not include package transforms. The fixture owns synthetic records and
effect deduplication; Tenkai owns receipts, rollback, and recovery.

## Signed stateful upgrade drill

The reference proof is the signed crash-recovery drill. It does not use
unsigned or unapproved development bypasses:

```bash
./scripts/stateful-upgrade-drill.sh
```

See [package migrations](../../docs/package-migrations.md#signed-stateful-upgrade-drill)
for prerequisites, evidence limits, and the assertion report.

## Local unsigned preview

Unsigned publish remains available only for the built-in `local` environment.
Set `TMPDIR` so the fixture executor can write its target ledger:

```bash
export TMPDIR="${TMPDIR:-/tmp}"
tenkaictl init
tenkaictl publish examples/package-migration/source/tenkai.toml \
  --allow-unsigned-development
tenkaictl publish examples/package-migration/target/tenkai.toml \
  --allow-unsigned-development
tenkaictl release inspect pkg@1.0.0
tenkaictl release inspect pkg@1.1.0
```

Copy each release digest into `declaration.json` as `sha256:<hex>`. Preview
fails until the pins match published Catalog content.

```bash
tenkaictl migrate preview cutover \
  --declaration examples/package-migration/declaration.json
tenkaictl migrate apply cutover \
  --declaration examples/package-migration/declaration.json \
  --allow-unapproved-development \
  --development-reason "package migration drill"
tenkaictl migrate status cutover
tenkaictl migrate rollback cutover \
  --allow-unapproved-development \
  --development-reason "package migration drill"
```

Add an irreversible checkpoint only with
`"pre_admission": "require_backup_receipt"` and
`--backup-receipt-digest`. After that checkpoint is accepted, rollback
records `recovery_required` and does not claim success.
