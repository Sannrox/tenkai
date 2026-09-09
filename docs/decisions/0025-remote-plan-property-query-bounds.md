# ADR 0025: Remote plan property query bounds

- Status: Accepted
- Date: 2026-09-08
- Issue: [#318](https://github.com/Sannrox/tenkai/issues/318)
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [ADR 0014](0014-versioned-rust-client-facade.md),
  [Operational storage](../operational-storage.md)

## Context

After [#317](https://github.com/Sannrox/tenkai/pull/317), the embedded host
applies plan status filters, integer `created_at` order, and `LIMIT` in SQL.
The remote catalog path still calls vendored `FindByProperty` with only
`kind`, `key`, and `value`, then retains, sorts, and truncates after the
full object transfer. Application filter/order/limit semantics match; IO
cost does not.

`FindByPropertyRequest` has no filter, order, or limit fields.
`ListObjects` / `ListFilter` already expose `property_filters`, `limit`,
`offset`, `order_by`, and `descending`, but that RPC is the kind-wide
lister. Tenkai has not proven that a remote `ListFilter` can express
environment equality, status `IN`, and integer `created_at` order without a
full kind scan or lexicographic sort.

Embedded and server hosts share application contracts (ADR 0001). They do
not share a requirement that every adapter have the same IO cost.

## Decision

Keep remote `FindByProperty` plan listing as an in-process filter, integer
sort, and truncate after transfer. Do not version `FindByProperty` in this
change. Do not fail closed on a Tenkai-only unfiltered page size.

A follow-up implementation issue is **not** ready. Bounding remote IO
requires an explicit Sekai protocol version or proven `ListFilter`
semantics, with versioning, migration, and fail-closed unknown-field
behavior.

## Consequences

- Inspect-latest and other limited plan reads on a remote catalog still
  transfer every object matching `kind` + `environment` (or the equivalent
  property pair) before decode.
- Remote reconcile admission must not re-issue that transfer per
  `LIMIT`/`OFFSET` window. Fetch, filter, and sort once, then walk the
  transferred set in memory. SQL paging stays on the embedded host.
- Environment-index retarget detection does not use `FindByProperty`.
  Remote hosts kind-list plans with `ListObjects` and peek payload
  `environment` so a retargeted index cannot omit-succeed into Current.
- After decode, `created_at` index values must still match the plan payload
  ([#323](https://github.com/Sannrox/tenkai/issues/323)).
- Operators of the embedded SQLite host keep the SQL-bounded path.

## Alternatives

1. **Version `FindByProperty` with filter, order, and limit.** Unknown
   fields fail closed. Semantics can match embedded SQL, including integer
   `created_at` order. Rejected for now: it is a vendored protocol version,
   not a silent client tweak, and needs a Sekai host that implements the
   new fields.

2. **Tenkai-only fail-closed bound on the unfiltered remote page.** After
   `FindByProperty`, error if the result set exceeds N. Rejected: the
   environments that need bounding are the ones that would hit N, so a
   bound turns today’s successful listing into an availability failure. A
   silent truncated page is forbidden.

3. **Accepted residual (this ADR).** Leave the client as-is and document
   that remote listing is semantically equivalent and not IO-equivalent.
   Chosen: no protocol change, no new fail-closed availability cliff, and
   no claim of embedded SQL parity on the wire.
