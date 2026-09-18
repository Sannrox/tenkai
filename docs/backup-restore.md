# Backup and restore runbook

Tenkai operational recovery depends on the **operational SQLite database**
(Catalog descriptors, environments, plans, leases, receipts, audit). Artifact
payloads and model weight caches are **not** inside that file.

## What is in a backup

| Included | Not included |
| --- | --- |
| Operational DB (`tenkai.db` by default under `.tenkai-state/`) | Deployment runtime working directories |
| Catalog release/channel metadata and digests | OCI/blob/weight bytes |
| Plans, leases, receipts, audit, provider outbox | Runtime bearer tokens / management tokens (re-inject from secret store) |

## Backup

Embedded only. Uses SQLite online backup API; consistent while another
`tenkaictl` process holds the DB open.

```bash
tenkaictl backup /secure/backups/tenkai-$(date +%Y%m%d).db
```

Treat backup files as **sensitive** (environment topology and operational
metadata).

## Restore

The CLI must be the **only writer** to the destination database path.

```bash
# Stop all tenkaictl / tenkai-server processes using this database.
tenkaictl restore /secure/backups/tenkai-YYYYMMDD.db
tenkaictl env list
tenkaictl inspect
```

After restore:

1. Re-inject `TENKAI_MANAGEMENT_TOKEN` / `TENKAI_RUNTIME_TOKENS` for server mode
   (not stored in the DB as plaintext operator secrets for remote access).
2. Rehydrate artifact payloads from registries if hosts lost content caches.
3. Confirm `env list` / `env inspect` for expected environments.

## Failure modes

- Missing backup path → fail closed with actionable error.
- Corrupt backup (integrity check fails) → restore refuses to write destination.
- Restoring over a live multi-writer setup → undefined; stop writers first.

## Automated drill

`cargo test --lib embedded_backup_restore_stays_on_typed_schema` proves the
operator `SqliteStore` backup → restore path on schema 11. The older
`online_backup_restores_complete_embedded_state` drill still covers the
pre-0029 graph-fixture factory used only to import leftover `embedded_*`
rows.
