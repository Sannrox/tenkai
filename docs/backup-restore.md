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

## Server-mode backups

`tenkai-server` takes the same online backups on a schedule when
`TENKAI_BACKUP_DIR` names a directory ([environment variables](environment-variables.md)).
Each backup is `tenkai-backup-<ms>.db` with a `tenkai-backup-<ms>.json` manifest that
records its `sha256` and size. A backup is written as a partial file and
synced; its manifest is made durable before the database is linked into
place, so a crash never leaves a half-written backup under a final name.
Cleanup removes only this subsystem's own leftovers, so the directory may
also hold `tenkaictl backup` copies. The newest `TENKAI_BACKUP_RETAIN` backups are kept. `status.json` in
the same directory records the last success and the last failure, and each
restore drill writes its own file under `drills/`. Both live beside the
backups, never inside the database. Manifests, status and drill evidence are
synced before they are renamed into place.

- `POST /v1/backups` takes a backup now. `GET /v1/backups` returns the
  status. Both cover the whole hub, so they need fleet management (`POST`)
  or fleet read (`GET`). An environment-scoped token is refused.
- `/healthz` and `/readyz` carry `backup.state`: `ok`, `stale` (older than
  `TENKAI_BACKUP_MAX_AGE_SECS`), `missing`, or `unreadable` when the status
  file cannot be read (the next backup writes a new one). A stale backup degrades health
  but does not fail readiness, because the server can still do its work.
  Alert on `backup.state`.
- Tenant-mode hubs keep their state in PostgreSQL; back it up with
  PostgreSQL's own tools. `TENKAI_BACKUP_DIR` is refused there.

## Restore drill

```bash
tenkaictl restore-drill /secure/backups/tenkai-backup-1761200000000.db --scratch-dir /var/tmp/tenkai-drill
```

The drill checks the backup against its manifest, restores it into a
scratch store, opens it on this Tenkai version (running its migrations),
checks integrity, and counts environments, releases and plans. It prints the
`tenkai.backup-drill.v1` evidence, records it under `drills/` (shown as
`last_drill` by `GET /v1/backups`), and removes the scratch store. It never touches live state,
so it can run on any host that can read the backup directory.

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

`cargo test --locked --lib embedded_backup_restore_stays_on_typed_schema` proves the
operator `SqliteStore` backup → restore path on the current typed schema
(`SCHEMA_VERSION` in `src/storage.rs`). The older
`online_backup_restores_complete_embedded_state` drill still covers the
pre-0029 graph-fixture factory used only to import leftover `embedded_*`
rows.
