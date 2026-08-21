# Catalog application contract v1

The Catalog is a versioned in-process application boundary shared by the
embedded CLI and future server host. It is not a separately deployed service.
Its Rust contract version is `CATALOG_CONTRACT_VERSION = 1`.

## Operations and invariants

- **Publish** accepts a manifest, immutable content descriptors, signature and
  provenance evidence, and an authenticated request identity. A product version
  can acquire one content identity only. Artifact bytes stay in an OCI registry,
  blob store, or the embedded filesystem content-store adapter.
- **Lookup** returns immutable release identity, manifest and artifact digests,
  and an opaque content locator. Missing, malformed, untrusted, or recalled
  releases fail closed.
- **Promote** changes one channel head through one governed operation. The
  caller must present an `AuthenticatedRequestContext` with
  `DeliveryCapability::Management` before canary evaluation. The authorization
  decision, audit record (including `principal_id` and `principal_kind`), and
  head mutation share the adapter's atomic commit boundary; a transport must
  not acknowledge a partial result.
- **Recall** is an ordered, authenticated mutation (`tenkaictl release recall`)
  that makes subsequent lookup and planning fail closed. The first-writer
  `tenkai.release_recall` claim records who recalled the release; the release
  object then carries `recalled_at` / `recalled_by`. Recall does not delete
  immutable descriptors or bytes. Planning will not target a recalled channel
  head; a deployed recalled release rolls off to a non-recalled head without
  restoring the recalled pin. Rollback onto recalled content is denied unless
  the Plan records an audited `--allow-recalled-recovery --recovery-reason`
  inside the signed executable digest. Ordinary lookup and channel-head
  planning stay fail-closed. See
  [ADR 0016](decisions/0016-same-version-remediation.md).

Publication has the same atomic authorization and audit requirement as
promotion. The current sekai-backed compatibility adapter keeps its existing
governed operations; the Tenkai-owned persistence migration must not split
their authorization, audit, and state writes.

Registered release provenance is an optional immutable Catalog fact. See
[registered release provenance](release-provenance.md) for its compiled profile
registry, canonical digest, replay, inspection, and authority boundaries.

## Transport conformance

Embedded and remote adapters must run the same behavior cases:

1. publishing identical content is idempotent and conflicting content fails;
2. immutable lookup returns identical identities and digest metadata;
3. malformed trust evidence and recalled content fail closed;
4. promotion is ordered, authorized, audited, and visible atomically;
5. retrying a request identity does not duplicate a mutation or audit event;
6. deadlines and unavailable required providers never become success.

A remote API may add wire-version negotiation, authentication, rate limits, and
pagination, but must translate into this contract without exposing database rows
or sekai objects. Compatibility is additive within v1. Removing fields, changing
digest meaning, or changing failure semantics requires a new contract version
and dual-version conformance fixtures.

## Cache and failure behavior

Digest-keyed immutable metadata may be cached, but cache hits never authorize a
publication, promotion, or deployment. Channel heads and recall state require
bounded freshness or revalidation at plan approval and again before execution.
A stale or partitioned cache fails closed when freshness cannot be proven; it
must never make mutated or recalled content deployable. Required Catalog or
content-store failure blocks the operation. Optional projections remain visible
and durably retryable, and are never needed for Catalog recovery.

Catalog extraction is permitted only when ADR 0001's measured scale,
availability-isolation, ownership, compatibility, operations, and reversible
migration criteria are met.
