# ADR 0051: Host operating system image updates across a reboot

- Status: Accepted
- Date: 2026-11-16
- Issue: [#901](https://github.com/Sannrox/tenkai/issues/901)
- Owner: Tenkai maintainers
- Builds on: [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md)
  (host applier, applied-state record, the interrupted-step rule)
- Related: [ADR 0022](0022-external-delivery-adapter-boundary.md),
  [ADR 0035](0035-host-preflight-evidence.md),
  [ADR 0017](0017-executable-release-waves.md),
  [runtime protocol v1](../runtime-protocol-v1.md),
  [host releases](../host-releases.md),
  [spoke standby](../spoke-standby.md)

## Context

Edge and disconnected-site operators also update the host operating system
under the software Tenkai delivers. Today they do it as a host release, or
outside Tenkai. Outside Tenkai skips approvals, maintenance windows, waves
and the audit record. As a host release it cannot be judged: the applier
writes `started` before the command and a result after, and an instance with
`started` but no result after a reboot resolves as interrupted and failed and
is never run again (ADR 0041 §2). An OS image update is the one change where
losing the runtime connection is the expected outcome.

That rule is a safety property: a host step authorizes one action, once.
Weakening it for every host step to fit a reboot is not acceptable.

Image-based hosts already have an on-host updater that writes an inactive
slot, selects the next boot, and falls back to the previous slot when a boot
fails. That is the part that must work with no network and no Tenkai, so it
stays on the host.

## Decision

Go, with a narrow scope: Tenkai owns the decision to update, its ordering,
the durable intent written before the reboot, and the verdict after it. The
on-host updater owns the slots and the boot.

### 1. Ownership split

| Tenkai | On-host updater |
| --- | --- |
| A signed, immutable OS image release and its approvals | Writing the image to the inactive slot |
| Ordering: preflight, window, wave, drain before, uncordon after | Selecting the next boot, one-shot until confirmed |
| Durable intent before the reboot: expected and previous image, deadline | Falling back to the previous slot when the new boot fails |
| The verdict after the reboot, and the audit record | Reporting which image is booted, and whether it is confirmed |
| When to confirm the new image | Making the booted image permanent on request |

Tenkai never writes a block device or a boot loader, and does not choose
between updaters. An updater is supported when it can do the five things in
its column from a root command, and can report the booted image digest and
its confirmed state to a root-side reader. The host layout must also keep
the applier's state (`/var/lib/tenkai-host`), its trust roots and policy
(`/etc/tenkai`), and the runtime's enrollment outside the slots, so they
survive a switch and a fallback without being rewound, and both images must
carry an applier that reads that state. A layout that keeps them per slot is
refused: the new image could not read `awaiting_boot`, and a fallback would
replay old generations. Others are out of scope.

### 2. An OS image release is a host release with its own step kind

The release is an ordinary signed release with `executor = "host"` and a
new manifest section naming the image:

```toml
[os_image]
digest = "sha256:..."   # the image the updater must boot
boot_deadline_seconds = 900
```

Its `deploy.install` stages the image through the updater and arms a
one-shot boot; it does not reboot. Its `deploy.confirm` asks the updater to
make the booted image permanent. Publication refuses an `[os_image]` section
on any other executor.

A plan updates the image in four host steps, all in one approved plan,
with the health steps of what runs on the host between `verify` and
`confirm`:

1. **`stage`**: a new host action that runs `deploy.install`. It advances
   the generation and sets `dirty(old, new)` as an install does, but success
   leaves the record `dirty(old, new)`, not `applied(new)`: the old image is
   still running. The interrupted rule applies unchanged.
2. **`reboot`**: a new host action. Under the product lock the applier
   advances the generation, durably writes `started` together with an
   `awaiting_boot` record (instance, expected image digest, previous image
   digest, deadline), and only then asks the updater to reboot into the
   armed slot.
3. **`verify`**: runs after the host comes back, at the current generation,
   and changes nothing but the `reboot` instance. The applier settles that
   instance from what it reads itself: the booted image digest from the
   updater, compared with the `awaiting_boot` record.
4. **`confirm`**: a new host action, run only after `verify` and the
   following health steps passed. It advances the generation and runs
   `deploy.confirm`. It sets `applied(new)` and the high-water release only
   when the updater then reports the booted image digest equal to the
   expected one and that image confirmed. Health steps of the OS release itself (`deploy.health`) need an
   applied release, so they come after `confirm`; before it, health means
   the health of the releases running on the host.

Every step before `confirm` leaves the record `dirty(old, new)`, so a crash
or a stopped plan between any two steps says exactly that: neither image is
recorded as applied, and continuing takes a new approved plan for the current
generation (the remaining steps, or a rollback).

The interrupted rule changes for no existing action. A `reboot` instance with
`started` and no result is the expected state, not an interruption, and only
`verify` (or the deadline, section 4) settles it. A `confirm` instance with
`started` and no result is settled the same way, by the next applier run,
with the same check: the booted digest equals the expected one and is
confirmed. A host that fell back to the old image in between settles the
`confirm` as failed, whatever the updater says about the old image. Neither is ever run
again: a second reboot or confirm is a new plan at the new generation.

**One fence for the whole host.** The updater's slots and next-boot choice
belong to the host, not to one environment or product. So every OS image
step takes one host-wide lock instead of the product lock, and the applier
keeps one host-wide OS image record, with the same generation, `dirty` and
high-water rules, in place of per-product records. A new update's `stage`
starts only when that record is `applied` or `empty`. While it is
`dirty(old, new)`, an OS
image step is admitted only when it expects the record's current generation
and its source is `old` or `new`: the takeover ADR 0041 §2 already defines
for a `dirty` record, so an approved continuation toward `new` or rollback
toward `old` can move on,
and its first step advances the generation, which fences out the plan it
replaces. A step for any third image, or at another generation, is refused
and names the pending pair. Two image updates can therefore never interleave
on one host.

### 3. Proof of post-reboot identity comes from the root side

The server does not trust a runtime's word for which image booted. The
`verify` result is written by the applier, root-owned, as for every host
step, and names the booted image digest the updater reported. The server
accepts it only when it matches the instance it started, as today.

The runtime reports a started `reboot` with a new non-terminal step outcome,
`awaiting_boot`, before it starts the unit; the server stores it durably with
the time it counts the deadline from. After the reboot a fresh runtime
instance on the same enrolled runner claims the plan again; the server hands
out the earlier steps' recorded receipts, as on any reconnect, and `verify`
as the next runnable step, whose result completes both `verify` and the
`reboot` it settles. This is a runtime protocol addition under a new
`os_image` capability, added within major version 1: a runtime that does not
name it is never handed an OS image plan, and the plan fails closed naming
the missing capability. A runtime that also reports
the booted digest as an inventory fact is a convenience for display and is
never the verdict.

### 4. Failure and rollback intent

| Outcome | How it is decided | Result |
| --- | --- | --- |
| Booted the expected image, health passes | `verify` reads the expected digest; the following health steps pass; `confirm` succeeds | Record `applied(new)` |
| Booted and healthy, but not confirmed | `confirm` fails, or is interrupted and the updater reports the image unconfirmed | Plan fails at `confirm`, record stays `dirty`; the next reboot may fall back |
| Never returns | No `verify` result before the deadline in the `awaiting_boot` record | Step fails `no_return`, record stays `dirty` |
| Returns on the previous image | `verify` reads the previous digest: the updater fell back | Step fails `fell_back`, record stays `dirty` |
| Returns on the new image, health fails | `verify` succeeds; a following health step fails | Plan fails at the health step, `confirm` never runs, record stays `dirty` |

`boot_deadline_seconds` is part of the signed release, and the server counts
it from the time it durably recorded handing out the `reboot` step. So it
judges `no_return` from its own store after a restart or a takeover, not from
memory, and never needs to read the host's files while the host is down.
A `verify` that arrives after the deadline still records which image booted,
for the audit, but does not turn the failed step into a success; continuing
takes a new plan at the current generation. When the server runs on the host
it updates, it judges after it comes back; the deadline is then a floor, and
a host that never returns has no judge on site. Sites that need a judge use a
hub or a spoke standby elsewhere.

Rollback intent is the previous image digest in the `awaiting_boot` record,
written before the reboot, so a rollback plan can be built from the host's
own record even when server state was lost. A rollback plan is the same four
steps toward `old`: its `stage` runs the previous release's `deploy.install`,
which re-arms the previous image (writing it again when its slot no longer
holds it), then `reboot`, `verify` and `confirm` judge it exactly as for an
update, and success sets `applied(old)` with the rollback approvals the host
policy requires. Booting back is the updater's
job when the new boot fails. Any other return to the previous image is an
approved rollback plan, as for every host release (ADR 0041 §2): no
automatic restore.

### 5. Ordering uses what exists

- **Drain and uncordon** are ordinary steps before `stage` and after
  `verify` in the same plan, through existing executors.
- **Preflight** (ADR 0035) gates the plan as for any plan.
- **Maintenance windows** must cover the whole deadline: a plan whose
  `reboot` step would start with less window left than
  `boot_deadline_seconds` waits for the next window.
- **Waves** (ADR 0017) treat the step like any other: the wave does not
  advance past an environment until its `verify` and health steps pass.

## Kill criteria

Stop and record a no-go if any of these proves true while implementing:

- a supported updater cannot report the booted image digest to a root-side
  reader, so `verify` would depend on the runtime's word;
- a supported host layout cannot keep the applier's state outside the slots;
- a supported updater cannot hold a new image unconfirmed until asked, and
  report whether it is confirmed, so `confirm` cannot be judged;
- the `reboot` action cannot be added without changing how an interrupted
  `install`, `uninstall` or `health` instance resolves;
- the deadline cannot be judged from durable state after a server restart or
  takeover.

## Out of scope

- Writing images, managing slots or boot loaders, or replacing an updater.
- Package-based (non-image) OS upgrades.
- Measured or attested boot as a stronger identity proof; a later decision
  can add it as another `verify` input.
- Cluster-managed node updates, where the cluster owns the reboot
  ([#994](https://github.com/Sannrox/tenkai/issues/994)).

## Consequences

- An OS image update goes through approvals, windows, waves and the audit
  record, and its success is judged after the reboot.
- The interrupted rule is unchanged for every existing host step; only the
  new `reboot` action expects to lose the connection.
- Each image update costs four attended host steps and one reboot.
- A host that never returns is reported failed only once the deadline passes,
  and only by a server that is not on that host.

## Alternatives considered

- **Treat the reboot as a host release command.** The started instance has no
  result after the reboot and resolves as failed every time.
- **Re-run interrupted host steps after a reboot.** Breaks "one action,
  once" for every host step.
- **Trust the runtime's reported image.** A compromised server-side user
  could forge it; the root side must be the witness.
- **Leave OS updates outside Tenkai.** No approvals, windows, waves or audit
  record for the riskiest change on an edge host.

## Follow-up on acceptance

Feature Issues: the `[os_image]` manifest section and its publication check;
the applier `stage`, `reboot`, `verify` and `confirm` actions with the
`awaiting_boot` record; the runtime `os_image` capability with the
`awaiting_boot` outcome and resume at `verify`;
the server's deadline judgement and window fit; operator documentation.
