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
a one-way owner digest bound to a fresh process instance; raw runtime
credentials are not stored. Heartbeats atomically renew only an unexpired claim
with the same owner and generation and never acquire work. If completion
persistence wins before the authoritative plan transition finishes, the same
owner receives the completed claim again and can replay the identical
completion until the plan is terminal.

SQLite databases are migrated transactionally when opened. Tenkai refuses to
open a database whose schema is newer than the binary supports. Use
`tenkaictl backup <destination>` for a live, consistent snapshot; do not copy a
database and its WAL files sequentially. Stop every writer before
`tenkaictl restore <source>`. Restore and integrity checks require no provider.

## Embedded-to-server migration

Embedded and server hosts use the same SQLite file and domain contracts. The
cutover is operational rather than a data reinterpretation:

1. Stop embedded reconcile loops and wait for active applies to finish.
2. Run `tenkaictl inspect` and reconcile any environment whose deployment state
   is unknown.
3. Run `tenkaictl backup /secure/tenkai-cutover.db`.
4. Copy that backup to the server host and restore it into the configured
   `TENKAI_DATABASE`.
5. Start `tenkai-server` in its default embedded-provider mode. Verify
   `/readyz`, inspect the first reconciliation result, and only then enable
   environment runtime credentials.
6. Keep the pre-cutover database read-only until rollback testing is complete.

Do not run the embedded CLI and server as concurrent mutation controllers for
the same environments. SQLite prevents database corruption, but it cannot make
two hosts a highly available control plane. Development-only unsigned release
permission is a per-publish CLI choice and is never enabled implicitly by
server startup.

Older sekai-backed v0 installations require an explicit republish and
reconciliation cutover: archive the graph for audit, initialize embedded state,
republish releases, recreate channels and environments, and record each
verified deployed version with `tenkaictl env reconcile` before applying.

Release payloads and runtime files do not belong in this database. The database
stores content descriptors and recovery authority; content remains in a
digest-verifying content store, and runtime state remains environment-scoped.
