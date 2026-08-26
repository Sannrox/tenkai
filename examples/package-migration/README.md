# Package migration fixture

Synthetic source-to-target software pins. The declaration binds Catalog
digests and consumed compatibility evidence. It does not include package
transforms.

```bash
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
