# ADR 0021: Portable delivery-manifest profile

- Status: Accepted
- Date: 2026-08-25
- Issue: [#291](https://github.com/Sannrox/tenkai/issues/291)
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [ADR 0003](0003-canonical-offline-delivery-archives.md),
  [Release signing](../release-signing.md),
  [Plan approval](../plan-approval.md),
  [Runtime protocol v1](../runtime-protocol-v1.md),
  [Delivery manifest profile](../delivery-manifest-profile.md)

## Context

Publishers, planners, and runtimes can disagree about release identity,
executable-plan binding, gates, receipts, rollback, and recovery. Ontology
packages are a different public schema and are explicitly out of this profile
(`#291` non-goals; `sekai-chisei#701`).

A second operational owner, or waiting on an ontology-package specification to
define delivery bytes, would split authority.

## Decision

Tenkai owns profile `tenkai.delivery-manifest.v1`. Canonical encodings are the
already-shipped release-signature, executable-plan digest, plan-approval, and
runtime receipt contracts. An independent planner and an independent runtime
must admit the same valid fixtures through those shipped functions and reject
altered bytes.

### Authority matrix

| Object / action | Owner | Others |
| --- | --- | --- |
| Signed release identity | Tenkai Catalog | Publishers emit content-bound bytes. |
| Executable plan, approval, gates | Tenkai | Optional providers return bound evidence only. |
| Lease, fence, receipt, rollback, recovery | Tenkai operational store | Runtimes return receipts. They are not recovery stores. |
| Ontology package | Foreign schema (`sekai-chisei#701`) | Delivery objects may name an opaque content-bound identity only. No payload. |

### Rules

1. Identity is content-bound. Unknown required fields, unknown required
   capabilities, missing/stale signatures, and missing required evidence fail
   closed and never map to success.
2. Duplicate identical receipts are idempotent. Conflicting results cannot
   overwrite the first accepted identity.
3. Recovery uses plan, checkpoint, and receipt state plus content-addressed
   artifacts. Optional providers are not recovery material.
4. Profile major version 1 is additive. Incompatible meaning requires a new
   major profile. Historical plans and receipts keep their original decoder.

## Consequences

- `sekai-chisei#701` remains related, not a schema owner for this profile.
- Conformance is a maintained fixture suite exercised by the shipped verifier
  functions, not a second control plane.
- Downstream adapter issues stay blocked until this profile and its fixtures
  land.

## Alternatives

Waiting on portable ontology packages was rejected: `#291` non-goals exclude
that schema, and delivery objects already have canonical encodings.
