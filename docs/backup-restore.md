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
- With `TENKAI_BACKUP_SIGNING_KEY`, each manifest gets a detached
  `tenkai-backup-<ms>.sig` signature over its exact bytes, written before the
  database appears and removed with it by retention.

## PostgreSQL backup evidence

Tenant-mode hubs keep their state in PostgreSQL. Tenkai does not copy that
database: back it up with PostgreSQL's own tools, then record each backup as
evidence in the hub's `TENKAI_BACKUP_DIR`:

```bash
tenkaictl backup-evidence /srv/tenkai/backups --backup /secure/hub-20261028.dump --tool "pg_dump 17"
```

The command records the file name, `sha256`, size, tool and time
(`--taken-at-ms`, default now) as the last success in `status.json`, and
prints the status. Evidence older than the last success changes nothing.
`/healthz` and `/readyz` report its age as `backup.state`, `missing` until the
first record and `stale` past `TENKAI_BACKUP_MAX_AGE_SECS` (default 172800).
Every replica must read the same directory.

Recording is a host action. Every tenant-mode credential belongs to one
tenant, and hub backups cover all of them, so `/v1/backups` refuses tenant
credentials. The interval, retention and signing settings are refused in
tenant mode, because the hub takes no backups itself.

## Restore drill

```bash
tenkaictl restore-drill /secure/backups/tenkai-backup-1761200000000.db --scratch-dir /var/tmp/tenkai-drill
```

With `--trust-roots <release-trust.toml>` (release signer roots), the drill
first refuses a backup whose manifest signature is missing or does not verify
against one of those signers, so a copy moved off-host can be authenticated.

The drill checks the backup against its manifest, restores it into a
scratch store, opens it on this Tenkai version (running its migrations),
checks integrity, and counts environments, releases and plans. It prints the
`tenkai.backup-drill.v1` evidence, records it under `drills/` (shown as
`last_drill` by `GET /v1/backups`, with every kept drill, newest first, as
`drills`), and removes the scratch store. The 30 newest drills are kept; a
new drill removes older ones (#818). Only drills that pass are recorded. It never touches live state,
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
