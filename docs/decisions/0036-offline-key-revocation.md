# ADR 0036: Signed offline key revocation

- Status: Accepted
- Date: 2026-10-18
- Issue: [#641](https://github.com/Sannrox/tenkai/issues/641)
- Owner: Tenkai maintainers
- Related: [ADR 0035](0035-host-preflight-evidence.md)

## Context

Trust roots rotate by overlapping trust files, and removing an approval key
revokes its unexecuted plans. An isolated fleet had no way to revoke a
compromised release, bundle or approval key quickly, everywhere, and without
an online revocation check. Editing every trust file is slow, and a stale
copy keeps trusting the key.

## Decision

1. **A signed list.** A revocation authority, named in its own
   release-format trust roots, signs a `tenkai.key-revocations.v1` list of
   key ids with reasons and a sequence.
2. **Enforced where keys are trusted.** `signature_verification::trusted_key`
   refuses a revoked key id. Every signature verification goes through it,
   so revocation covers releases, bundles, plan and migration approvals,
   model evaluation evidence, and host preflight. Loading a trust file uses a separate structural check, so
   a file that still lists a revoked key keeps working for the other keys.
3. **Monotonic.** A new list needs a higher sequence and must keep every
   revoked key. An authority cannot revoke itself.
4. **Offline distribution.** `tenkaictl revocations import` installs a list
   file. An offline bundle may carry the list as `trust/key-revocations.json`,
   and bundle bind or install applies it before verifying the bundle.
   Processes load the installed list at startup.
5. **Rollover is documented.** Overlap, switch, revoke, remove, for each key
   kind and for CA rotation ([key rollover](../key-rollover.md)).

## Consequences

- One small file revokes a key on every host that imports it, with no
  network check.
- A running server applies a list imported through the CLI at its next
  restart. A bundle import applies it immediately in that process.
- Un-revoking a key is not possible. Issue a new key instead.

## Alternatives considered

- **Remove keys from every trust file.** Rejected: slow on an isolated
  fleet, and one stale copy keeps trusting the key.
- **Online revocation (OCSP-style).** Rejected: isolated sites cannot reach
  it.
- **Reject trust files that list a revoked key.** Rejected: one revoked key
  would stop all verification on that host until the file is edited.
