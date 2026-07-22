# Operational storage

Tenkai owns releases, channel heads, environments, plans, leases, receipts, and
rollback recovery state. `OperationalStore` is the application boundary for
that authority. `SqliteStore` is the complete solo-mode adapter; future server
database adapters must pass the same immutability, lifecycle, idempotency, and
generation-fencing contract.

The store also owns the provider-event retry queue used for audit and outcome
projection. Host implementations must add each event atomically with its
authoritative state change. Provider adapters can acknowledge delivery, but
cannot change or reconstruct operational truth. See
[provider contracts](provider-contracts.md) for delivery semantics.

Server management requests and their terminal outcomes are appended to the
`audit_events` table. Audit identifiers are immutable and survive server
restart. The table contains principals, operation/resource identifiers, and
outcomes only; bearer credentials and request secrets are never persisted.

Remote runtime claims are durable, environment-scoped, expiring, and
generation-fenced. Their completion payload retains per-step receipts and is
immutable after the first accepted completion. Tokens are represented only by
a one-way owner digest; raw runtime credentials are not stored. Polling renews
an active claim for the same owner. If completion persistence wins before the
authoritative plan transition finishes, the same owner receives the completed
claim again and can replay the identical completion until the plan is terminal.

SQLite databases are migrated transactionally when opened. Tenkai refuses to
open a database whose schema is newer than the binary supports. Back up the
database and its `-wal`/`-shm` files only while every writer is closed or
quiesced, or through an atomic filesystem snapshot. For a live database, use
SQLite's online backup API rather than sequential file copies. Restore testing
does not require sekai-chisei or another optional provider.

## Existing v0 installations

Existing v0 authority remains in sekai-chisei until an importer and host wiring
perform the ADR 0001 shadow-validation and explicit cutover. Issue #17 does not
silently introduce mixed writers. Operators have two supported paths:

- Keep using the v0 CLI until the import/cutover command is available. Do not
  point another Tenkai writer at the same environments.
- For a disposable solo installation, archive the old graph for audit, create a
  new SQLite database, republish releases, recreate channels/environments, and
  explicitly reconcile each verified deployed version before applying plans.

Deleting a SQLite database is reinitialization, not migration: it discards
Tenkai-owned operational history. Never reinitialize an installation with an
active or uncertain deployment; reconcile the target first.

Release payloads and runtime files do not belong in this database. The database
stores content descriptors and recovery authority; content remains in a
digest-verifying content store, and runtime state remains environment-scoped.
