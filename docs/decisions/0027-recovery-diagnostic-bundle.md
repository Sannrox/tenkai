# ADR 0027: Bounded recovery diagnostic bundle

- Status: Accepted
- Date: 2026-09-11
- Issue: [#337](https://github.com/Sannrox/tenkai/issues/337)
- Owner: Tenkai maintainers
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [Operational storage](../operational-storage.md),
  [Server diagnostics](../server-diagnostics.md)

## Context

Operators can inspect plans, receipts, and fences separately. A portable
record of one failed delivery would help reproduce recovery without copying
the operational database.

A public bundle that re-stores plan bodies, Catalog objects, or SQLite pages
would become a second copy of operational truth. Recovery must keep using
Tenkai-owned state. Cached or projected evidence cannot grant apply, rollback,
or fencing authority.

ADR 0001 requires one application core and two hosts. Transport is not a
domain boundary. The export must be the same derived document on embedded
and remote hosts.

## Decision

Export a versioned, allowlisted, read-only diagnostic. It is derived at
observed read time. It is not a store, backup, or grant.

1. **Schema** `tenkai.recovery_bundle.v1`. Unknown schema or unknown fields
   that would change admission fail closed.
2. **Identity** binds `plan_id` and `observed_at`. Mixed or missing state is
   listed in `findings`; it is not inferred into success.
3. **Allowlist** (only): environment id, plan id, plan content id, plan
   state, step product/to/release_id/release_digest, fence generation when
   known, `recovery_required`, consistency findings, observed read time.
4. **Exclude**: credentials, target payloads, workdirs, unrestricted logs,
   database dumps, private source, member documents.
5. **Authority disclaimer**: `authority` is always `none`. The file cannot
   authorize apply, rollback, resume, or fence advancement.
6. **One core.** Both hosts call `recovery_bundle::export`. Remote transport
   does not invent a second schema.
7. **Verify after transfer.** `recovery_bundle::verify` re-checks schema,
   identity fields, allowlist shape, and `authority = none`.

## Consequences

- Operators can move a bounded diagnostic offline without copying `.tenkai-state`.
- Recovery still runs against Tenkai operational state.
- A bundle that omits a field stays incomplete; callers must not fill gaps.
- Follow-up remote HTTP export, if added, must reuse this schema.

## Alternatives

- **SQLite copy / full inspect dump.** Rejected: second operational truth and
  credential/payload leakage.
- **Unsigned human text only.** Rejected: not verifiable after transfer.
- **Bundle as an apply grant.** Rejected: fail-open recovery authority.

## Source

- [#337](https://github.com/Sannrox/tenkai/issues/337)
- [ADR 0001](0001-standalone-core-and-service-evolution.md)
