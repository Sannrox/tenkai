# ADR 0018: Accepted change-set closure pin admission

- Status: Accepted
- Date: 2026-08-25
- Issue: [#288](https://github.com/Sannrox/tenkai/issues/288)
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [Catalog contract](../catalog-contract.md),
  [Registered release provenance](../release-provenance.md)
- External contract: [Sannrox/sekai-chisei#683](https://github.com/Sannrox/sekai-chisei/issues/683)
  (completed), [definition branches](https://github.com/Sannrox/sekai-chisei/blob/main/docs/definition-branches.md)

## Context

Tenkai already binds a release to its own signed manifest and artifact tree.
A publisher can still present a valid Tenkai release whose externally governed
members are incomplete, changed after review, or unrelated to the closure that
was accepted. Change-set publication and member authority remain outside
Tenkai. The Catalog needs one fail-closed admission rule that retains the
exact accepted closure identity without importing change-set payloads or
becoming a second publication authority.

Sekai's completed publication contract treats a change set as a governed
branch proposal. Identity is `(namespace, branch_id, proposal_id, base_digest,
candidate_digest)`. Merge compare-and-swaps the published head and stores a
receipt. Members are content-addressed; named foreign digests confer nothing.
Tenkai must consume that evidence as a bounded pin, not as operational
authority.

## Decision

Tenkai owns an optional, versioned **change-set closure pin** as an immutable
Catalog fact. When a release manifest includes the pin, Catalog publication
fails closed unless one accepted, complete, authorized publication-evidence
document matches the pin exactly. After admission, Tenkai-owned stored pin
and evidence are sufficient for inspect, promote, plan, apply, rollback,
recall, and recovery. The change-set service is never a recovery store.

### Authority matrix

| Concern | Authoritative owner | Contract boundary |
| --- | --- | --- |
| Release, channel, plan, execution, rollback, recall, recovery | Tenkai Catalog and operational store | Pin fields are part of signed manifest identity. Stored pin and evidence are Catalog facts. |
| Change-set proposal, merge, member publication, live grants | External definition-branch authority | Tenkai never creates, reviews, merges, or mutates a change set. |
| Pin identity | Content-bound Tenkai object | `tenkai.change_set_pin.v1` binds contract, namespace, branch, proposal, base digest, closure digest, receipt digest, and ordered member `(kind, id, digest)` tuples. |
| Publication evidence | Bounded evidence adapter | `tenkai.change_set_publication_evidence.v1` reports accepted/unaccepted/incomplete/recalled/unauthorized/unavailable. Member payloads, credentials, and unrestricted records are excluded. |
| Freshness / recall of the *Tenkai* release | Existing Catalog recall | Recalled Tenkai releases fail lookup and planning as today. |
| Freshness of the *external* closure after admission | Stored evidence, then optional live recheck | A later live unaccepted or recalled status denies new promotion or execution. Missing live evidence after admission does not rewrite or delete the stored pin and does not block rollback or recovery. |

### Admission rules

1. **Optional pin, required evidence when present.** Releases without a pin
   keep today's admission. A pin without evidence, or evidence without a pin,
   fails closed before Catalog mutation.
2. **One accepted complete closure.** Evidence `status` must be `accepted`,
   `authorized` must be true, contract must be `tenkai.change_set_pin.v1`, and
   members must be a non-empty complete set that equals the pin member-for-member
   after canonical sort. Unknown contract versions, unknown member kinds, and
   unknown status values fail closed.
3. **Content-bound identity.** The signed manifest bytes include the pin, so
   the release signature covers closure identity, closure digest, receipt
   digest, and member digests. Stored evidence must name the same identities.
4. **Idempotent replay, immutable conflict.** Repeating the same pin and
   evidence is a no-op. Different closure evidence for an existing
   `product@version` is an immutable conflict. Provider unavailability or
   process restart before `create_once` leaves no release.
5. **No payload import.** Persist identities, digests, acceptance metadata, and
   credential-free evidence only.

### Compatibility

Unknown mandatory pin fields fail closed (`deny_unknown_fields`). Incompatible
meaning changes require a new contract identifier. Historical releases without
pin properties remain readable. Stored pin JSON is a version snapshot: later
registry changes do not reinterpret it.

## Consequences

- Operators can pin a Tenkai release to one accepted immutable closure and
  inspect the retained member-digest evidence.
- Downstream package-migration and module-delivery work can assume a Catalog
  pin without treating Sekai as a recovery path.
- Live Sekai RPCs are an evidence adapter, not a Catalog dependency. The first
  implementation admits a local evidence document and in-process fixtures.

## Alternatives

1. **Require every release to carry a pin.** Rejected: existing products have
   no change-set closure, and this issue is an admission rule for pinned
   releases, not a global mandate.
2. **Reuse generic release provenance envelopes.** Rejected: provenance is
   optional evidence retention and does not require complete accepted closures
   or member-digest equality.
3. **Copy member documents into Tenkai.** Rejected: that imports foreign
   authority and payloads excluded by the issue.

## Sources

- [Issue #288](https://github.com/Sannrox/tenkai/issues/288)
- [Sekai-Chisei #683](https://github.com/Sannrox/sekai-chisei/issues/683)
- [Sekai discussion 726](https://github.com/Sannrox/sekai-chisei/discussions/726)
