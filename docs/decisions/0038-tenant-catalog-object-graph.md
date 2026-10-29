# ADR 0038: Tenant catalog object graph on PostgreSQL

- Status: Accepted
- Date: 2026-10-29
- Issue: [#764](https://github.com/Sannrox/tenkai/issues/764)
- Owner: Tenkai maintainers
- Related: [ADR 0008](0008-production-tenant-operational-store.md),
  [ADR 0010](0010-supported-operating-profiles.md),
  [ADR 0029](0029-hub-spoke-operational-store.md),
  [operational storage](../operational-storage.md)

## Context

A tenant-mode hub opens PostgreSQL as the sole operational store (ADR 0029)
and keeps typed releases, channels, environments, plans, and leases in each
tenant schema `tenkai_t_<tenant>`. Catalog lifecycle still speaks the
object/link/lease/action contract that SQLite implements as `catalog_*`
tables. On the hub that contract was `Unavailable`, so publish, promote,
plan, and apply could not run.

The remaining choice is which schema owns those catalog rows, and how tenant
isolation applies.

## Decision

1. **Catalog rows live in the tenant schema.** Objects, links, namespaced
   leases, schema types, action types, decisions, and the change feed sit in
   `tenkai_t_<tenant>` beside the typed operational tables. They do not live
   in `tenkai_hub`. Hub schema stays host-scoped (audit, runtime claims,
   writer fence, hub outbox).
2. **Same contract as SQLite.** Create-once, conditional update, property
   lookup, links, and namespaced leases keep the SQLite semantics. One
   conformance suite runs against SQLite and PostgreSQL.
3. **Isolation is the schema.** A request binds one tenant id; the adapter
   opens that tenant schema and cannot read another. Missing tenant on a hub
   catalog write fails closed.
4. **No second graph product.** This is the SQLite catalog sidecar on
   PostgreSQL, not a revival of `EmbeddedStore`. Typed operational tables
   remain authoritative for recovery; catalog rows are the object-graph API
   that publication and planning already use.

## Consequences

- `enterprise-experimental` can publish, promote, plan, and apply without
  opening SQLite.
- New tables only; SQLite is unchanged.
- Outbox wiring for tenant-mode outcome export stays a later slice (#765)
  in the same tenant schema.

## Alternatives considered

- **Hub-wide `tenkai_hub` catalog.** Rejected: catalog identity is
  tenant-owned. A shared graph would mix tenants or need a second isolation
  key on every row.
- **Project only typed tables into objects.** Rejected: publication stores
  verification claims, links, and other kinds that are not typed operational
  records.
