# ADR 0003: Canonical offline delivery archives

- Status: Accepted
- Date: 2026-07-23
- Issue: [#8](https://github.com/Sannrox/tenkai/issues/8)
- Discussion: [#46](https://github.com/Sannrox/tenkai/discussions/46)

## Context

Disconnected environments need approved plans and immutable release content
without control-plane connectivity. Their execution evidence must later rejoin
the same Tenkai-owned lifecycle without trusting removable media, duplicating
execution, leaking credentials, or depending on an optional provider.

## Decision

Tenkai owns `tenkai.offline-bundle.v1`, a bounded self-verifying archive with a
signed canonical root. The root binds tenant and environment identities, plan
and approval digests, release identities, content-addressed entry descriptors,
exporter identity, and a validity interval. The runtime verifies the complete
archive against environment-scoped trust configuration before mutation.

Tenkai also owns `tenkai.offline-receipt.v1`. A runtime-signed receipt binds the
exact bundle root, tenant, environment, plan, runtime, deterministic step
receipt identities, results, and completion time. After verification, import
uses the same application completion and operational transaction contracts as
connected runtimes. First accepted identities remain authoritative; identical
replay is idempotent and conflicting content fails closed.

Bundles contain no reusable credential, private key, command output, arbitrary
log, unrelated tenant graph data, or recovery dependency on Sekai Chisei.
Unknown schemas, invalid or removed signers, stale validity, scope mismatch,
changed entries, unsafe paths, duplicate entries, and exceeded limits fail
closed.

## Consequences

- Canonical encodings, schemas, trust behavior, replay rules, and size limits
  are durable public compatibility and security contracts.
- Export, verification, receipt import, and recovery remain in the shared
  application core; transports are adapters.
- Aldunis tenant identity and required Sekai Chisei evidence are bounded
  identities or evidence references, not operational authority.
- New incompatible formats require a new schema and explicit migration policy.
- Partial or damaged media can be discarded and re-exported without changing
  control-plane truth.

## Alternatives

An OCI image layout was rejected. Although it offers descriptor tooling, it
introduces registry-oriented concepts and dependencies beyond the narrow
offline transfer requirement and risks becoming the general artifact registry
excluded by issue #8.
