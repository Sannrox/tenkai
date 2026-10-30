# Signed recall notices

A **recall notice** is a small signed file that tells an isolated spoke which
releases are recalled, before a fix bundle arrives. After import, planning of
those releases fails closed. Running workloads stay as they are until a
fix-forward wave is approved.

Trust matches the offline revocation list
([ADR 0036](decisions/0036-offline-key-revocation.md)): Ed25519, release-format
trust roots, and a revoked key is refused with no catalog write.

Related: [catalog contract](catalog-contract.md), [rollout waves](rollout-waves.md),
[ADR 0016](decisions/0016-same-version-remediation.md).

## Propose a recall and fix-forward wave

`tenkaictl remediate propose` takes an advisory id from the imported feed
([component inventory](catalog-contract.md)), recalls every matching release,
writes a signed notice, promotes the patched release, and admits a durable
stop-on-failure wave. The wave does not apply until signed plan approval
(or the documented local-development bypass) and `wave resume`.

```bash
tenkaictl remediate propose \
  --exposure TENKAI-2026-1 \
  --fix api@1.1.0 \
  --channel stable \
  --cohort canary,stage,prod \
  --signing-key notice.ed25519 \
  --notice-out notice.json
```

Carry `notice.json` by any medium. Optional `--wave-name` defaults to
`recall-<advisory-id>`. Use the existing apply emergency window when executing
the wave if a maintenance override is required.

## Import on a spoke

```bash
tenkaictl remediate import-notice \
  --notice notice.json \
  --trust-roots notice-roots.toml
```

Import verifies the signature, refuses a revoked signer, then stamps catalog
recall. Named releases that are not in the catalog still get a recall claim, so
a later publish of that identity is not deployable. It prints which
environments still run a recalled release. Re-import of the same notice is
idempotent.

A notice whose digest does not match a catalog release that is already present
is refused and leaves state unchanged.

## Fix-forward and rollback

Resume the admitted wave with the same approval flags as `wave execute`:

```bash
tenkaictl wave resume recall-TENKAI-2026-1 \
  --approval-dir ./approvals \
  --approval-trust-roots plan-approvers.toml
```

Completed environments are not repeated. Rollback onto recalled content still
requires `--allow-recalled-recovery --recovery-reason` inside the signed plan.
