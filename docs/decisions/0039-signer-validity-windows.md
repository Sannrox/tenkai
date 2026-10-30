# ADR 0039: Signer validity windows on trust-root format v1

- Status: Accepted
- Date: 2026-10-30
- Issue: [#812](https://github.com/Sannrox/tenkai/issues/812)
- Owner: Tenkai maintainers
- Related: [ADR 0036](0036-offline-key-revocation.md),
  [release signing](../release-signing.md),
  [plan approval](../plan-approval.md),
  [upgrade and rollback](../upgrade-and-rollback.md)

## Context

Trust roots list signers by key id and identity. They carried no validity
window, so verification could not tell when a trusted signer stopped being
valid, `GET /v1/trust` reported `signer_validity: "not_recorded"`, and a
credential runway could not name a signer whose validity ended before a
scheduled plan.

The format change has to stay readable next to files that omit the new
fields, and older releases must not silently trust a signer past its window
during a rolling deploy or a rollback.

## Decision

1. **Keep format version 1.** Optional `not_before` and `not_after` (Unix
   milliseconds) sit on each `[[signers]]` entry. Files without the fields
   stay valid and still report `not_recorded`.
2. **Verification refuses outside the window.** A signature from a signer
   with `at < not_before` is refused with reason `not_before`; `at > not_after`
   is refused with reason `not_after`. A signer with neither field is trusted
   until it is removed or revoked, as before. Load still accepts an expired
   window so the rest of the file keeps working.
3. **Older releases refuse files that carry the fields.** Trust-root types
   use `deny_unknown_fields`, so a release that does not know `not_before` /
   `not_after` fails closed on a file that has them. It never ignores the
   window and trusts the signer anyway.
4. **Rolling deploy and rollback.** Upgrade every host first, while files
   omit the fields. Then write windows. To roll back a host, restore files
   without the fields before running the older binary. Running an older
   binary against a file that still has the fields fails closed.

## Consequences

- `GET /v1/trust` reports `recorded` when any signer on a root carries a
  window, and lists that signer's `not_before` / `not_after`.
- `GET /v1/trust/runway` lists a signer whose `not_after` is at or before
  the plan's next window as `blocked_by`, the same way it lists a TLS
  certificate.
- Sites that do not need windows keep today's files and behavior.

## Alternatives considered

- **Bump the file to version 2.** Rejected: every trust file would have to
  be rewritten even when no window is set, and mixed v1/v2 files in one
  fleet would be a second migration.
- **Ignore unknown fields on older releases.** Rejected: that would silently
  trust a signer past its window.
- **Treat an expired window as a load error.** Rejected: one lapsed signer
  would stop every other key in the same file, the same failure ADR 0036
  already refused for revocation.
