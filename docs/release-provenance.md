# Registered release provenance

Catalog publication can retain bounded references to evidence issued by an
external authority without accepting subject payloads or arbitrary metadata.
Pass each strict JSON envelope with a repeatable `--provenance` option:

```sh
tenkaictl publish tenkai.toml \
  --signature release.sig.json \
  --trust-roots release-trust.toml \
  --provenance governed-subject.json \
  --provenance-trust-roots provenance-trust.toml
```

The generic envelope contains only a compiled versioned profile, issuer and
issuer key id, an opaque subject identity and canonical content digest, an
`allow` decision and receipt schema/digest, canonically sorted governed
references, observation and expiry times, and an Ed25519 issuer signature.
Tenkai requires operator-supplied provenance trust roots and verifies that the
signing key is trusted for the profile's allowlisted issuer.

The envelope `content_digest` is
`sha256(length(manifest_digest) || manifest_digest || length(artifact_digest) ||
artifact_digest)` with unsigned 64-bit big-endian lengths and the domain
separator `TENKAI-RELEASE-PROVENANCE-CONTENT-V1\0`. This binds external
evidence to the exact published manifest and immutable artifact tree.

Unknown fields, profiles, issuers, receipt schemas, reference kinds, denied or
stale evidence, duplicate profiles/references, noncanonical ordering, paths,
URLs, malformed digests, and oversized input fail before Catalog mutation.
Callers cannot register profiles or validators at runtime. A publish accepts at
most four envelopes, each no larger than 16 KiB.

## Immutability and authority

The issuer signature covers a serialization-independent canonical encoding
beginning with `TENKAI-RELEASE-PROVENANCE-V1\0`. Tenkai hashes that encoding
and the signature,
sorts envelopes by profile, and stores both the canonical envelopes and their
bounded projections with the release. Replaying the same product version
requires the same manifest, artifacts, and provenance. Adding, removing, or
changing provenance conflicts and requires a new product version.

Existing releases without provenance remain readable and may be replayed
without provenance. Stored projections are version snapshots: later profile
registry changes do not reinterpret them.

Provenance is evidence retention only. It is not release signing, plan
approval, gate satisfaction, promotion authority, or execution authorization.

## Compiled conformance profiles

- `example.governed-subject-receipt/v1` admits issuer `sekai-chisei`, receipt
  schema `chisei.governed-subject-receipt/v1`, and `operation` or `evidence`
  references. It exercises `Sannrox/sekai-chisei#415`.
- `example.build-attestation/v1` admits issuer `example-builder`, receipt schema
  `example.build-attestation-receipt/v1`, and `build` or `material` references.
  It proves that registry and persistence machinery are not subject-specific.

`tenkaictl release inspect` returns only the bounded projection. With
`--output json-v1`, successful publication adds one `release_provenance`
resource per canonical envelope digest. If a process exits without returning a
complete command result, reconcile through release inspection.
