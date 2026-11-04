# ADR 0042: Signer windows are checked at an artifact's signed time

- Status: Accepted
- Date: 2026-11-04
- Issue: [#865](https://github.com/Sannrox/tenkai/issues/865)
- Owner: Tenkai maintainers
- Amends: [ADR 0039](0039-signer-validity-windows.md) §2
- Related: [release signing](../release-signing.md),
  [offline key revocation](0036-offline-key-revocation.md),
  [backup and restore](../backup-restore.md)

## Context

ADR 0039 §2 refuses a signature from a signer outside its `not_before` /
`not_after` window, and every verifier checked the window against its own
clock. Stored artifacts are verified again whenever they are used: the
installed revocation list at every process start, backups at restore, audit
exports and support bundles after transfer, stored releases at deploy, and
offline bundles at import. Setting `not_after` on a key, the documented
rotation step, therefore made everything that key had already signed stop
verifying: servers refused to start, backups could not be restored, and
imported releases became undeployable.

The signed statements already carry the time they were signed.

## Decision

1. **A signed artifact is checked at its signed time.** The signer's window
   is checked at the time the artifact's signed statement carries, not at the
   verifier's clock. The signed time must not be later than the verifier's
   clock plus a five-minute clock skew, so a key cannot sign for a time it is
   not yet valid and be accepted early. Audit exports are the exception: a
   chain keeps period ends monotonic across replicas whose clocks differ, so
   an export's period end may run ahead of the verifier's clock. The
   artifact's own expiry, where it has one, bounds freshness.
2. **Live admissions are checked at now.** A signature that authorizes an
   action at the moment it is taken, such as a plan or package-migration
   approval at apply, keeps checking the window at the verifier's clock. A
   back-dated timestamp cannot widen these paths: they do not read one.
3. **Revocation applies at now, for every class.** A revoked key is refused
   whatever the artifact's signed time.
4. **The rule per class** is listed in
   [release signing](../release-signing.md#signer-validity-windows). A new
   signed format names its class there.

## Consequences

- Rotating a key with `not_after` stops it from signing new artifacts while
  what it signed inside its window keeps verifying.
- The signed time is asserted by the signer. `not_after` therefore bounds an
  honest signer; it does not contain a leaked key, which could sign with a
  back-dated time. A key that may have leaked must be revoked
  ([ADR 0036](0036-offline-key-revocation.md)).
- No format changes. During a rolling deploy an older binary still checks
  stored artifacts at now, which refuses more and never accepts more; a
  rollback returns to that behavior.
- Verifiers that need the signed time, such as a host-side release applier,
  use the release envelope's signed time and the same signed-time check.

## Alternatives considered

- **Keep checking at now and re-sign stored artifacts on rotation.**
  Rejected: backups and audit exports are evidence of a past state, and a
  rotation would have to find and re-sign every copy.
- **Ignore the window for stored artifacts.** Rejected: an artifact claiming
  a time outside its signer's window would verify.
- **Check imports at now and only stored copies at the signed time.**
  Rejected: an offline bundle or a release in transit across a rotation
  would be refused although it was signed inside its signer's window, and a
  leaked key still needs revocation either way.
