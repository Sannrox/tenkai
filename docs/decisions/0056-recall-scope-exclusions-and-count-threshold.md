# ADR 0056: Recall removal scope, range exclusions and an instance-count threshold

- Status: Accepted
- Date: 2026-11-19
- Issue: [#1333](https://github.com/Sannrox/tenkai/issues/1333)
- Owner: Tenkai maintainers
- Builds on: [catalog contract, recall](../catalog-contract.md),
  [ADR 0036](0036-offline-key-revocation.md)
- Related: [management lifecycle](../management-lifecycle.md),
  [recall notices](../recall-notices.md)

## Context

A recall is blunt by design:

- **Removal covers the fleet.** Once a release is recalled, every
  environment that runs it rolls off to a non-recalled channel head on its
  next plan, and the recall read reports removal progress per environment.
- **A range recalls every release inside it.** A product range
  (`release recall <product> --from <v> [--before <v>]`) is consulted at
  lookup time. A range can be closed but never widened, and nothing can
  take one version back out of it.
- **The promotion-policy recall rule measures shares.** It recalls when the
  share of soak time with any replica failing exceeds `failing_max_share`.
  It has no instance-count trigger.

Three changes are wanted:

1. Remove a recalled release from some environments first, then widen.
2. Keep one version inside a recalled range in service.
3. Recall when a fixed number of instances fail.

The first two narrow a fail-closed control. They are acceptable only if
each narrowing is a separate, audited write that the recall read shows.

## Decision

All three are added. Lookup and planning onto a recalled release stay
fail-closed everywhere. Only the removal of already-deployed instances can be
scoped.

### 1. Limited removal

A recall may name the environments its removal covers. Without that list,
removal covers the fleet, as it does today.

- A listed environment rolls off the recalled release on its next plan,
  exactly as today.
- An unlisted environment that still runs the recalled release keeps running
  it. Its plans do not propose the roll-off, and they still refuse any new
  install or upgrade onto the recalled release. `status`, `env inspect` and
  the recall read report it as `recalled, removal not in scope`. This is a
  warning, not a hold or gate.
- Widening the scope is a new audited write that appends environments to
  the list or switches the recall to fleet-wide. It needs the recall
  permission and a reason, and it records the actor and the time. The scope
  never narrows: once an environment is in scope, it stays in scope.
- The recall read (`GET /v1/releases/{release}/recall`) carries the scope and
  every widening. `removal_environments` counts only in-scope environments,
  and a separate list names unlisted environments that still run the
  release.

### 2. Range exclusions

A version inside a recorded range can be excluded from it.

- An exclusion is its own audited write, naming the range (product and
  `from`), the version, a reason, the actor and the time. It needs the
  recall permission. It can be added after the range is recorded.
- Lookup subtracts exclusions from ranges at read time, as it already
  evaluates ranges. An excluded version is not recalled by that range.
- An exclusion lifts only the range. A release recalled on its own
  (`tenkai.release_recall`), or recalled by another range, stays recalled.
- Removing an exclusion is an audited write that recalls the version again
  through the range. That makes it a recall, so its fail-closed effects apply
  immediately.
- `release inspect` and `GET /v1/products/{product}/recall-ranges` list each
  range's exclusions.

### 3. Instance-count threshold

The promotion-policy recall rule gains an optional `failing_max_instances`.
It sits beside `failing_max_share` and does not replace it.

- A failing instance is counted with the same health evidence and over the
  same soak window as the share.
- When both thresholds are set, the first one reached fires the recall. The
  recall records which threshold fired and the measured value.
- When the field is absent, the rule behaves exactly as today.
- It is set through the existing recall-rule write (`PUT
  /v1/products/{product}/channels/{channel}/policy`) and versioned with the
  policy like the other recall-rule fields.

### 4. Disconnected spokes stay fail-closed

A signed recall notice (`tenkai.recall-notice.v2`) carries neither the
removal scope nor exclusions. A spoke that imports one applies a fleet-wide
recall with no exclusions. If spokes need scope or exclusions, a new notice
version adds them; v2 is not reinterpreted.

## Compatibility

- Removal scope, widening events, exclusions and `failing_max_instances` are
  additive stored fields and records. Recalls and ranges recorded before
  this change read as fleet-wide with no exclusions. A rule without the new
  field behaves as before.
- During a rolling upgrade, an older server ignores a removal scope and an
  exclusion. That fails closed: it removes the release fleet-wide and
  recalls the excluded version. Writes of scope, exclusions and the count
  threshold are refused until every server reads the new format, the same
  gate as ADR 0054.
- Embedded and server hosts evaluate scope and exclusions in the same
  lookup and planning code.

## Out of scope

- Narrowing a removal scope, or recalls that never remove anything.
- Exclusions for a single-release recall. A release recalled on its own
  stays recalled; rollback onto it keeps the audited recovery path.
- Count thresholds outside a promotion-policy recall rule.

## Rejected

- **Scope as a hold on unlisted environments.** It would block their other
  products, which the recall does not concern.
- **Editing a range to cut a hole in it.** A range never changes after it
  is recorded, apart from closing an open end. Exclusions keep the range and
  record the exception next to it.
- **Replacing shares with counts.** A count means different things at 10
  and at 10,000 instances. Shares stay the default, and counts are an extra
  trigger for small fleets and hard limits.

## Consequences

- An operator can stage a recall's removal and keep a known-good version
  inside a bad range, and both exceptions show on the recall read.
- A small fleet can recall after N failures without tuning a share.
- Recall reads and the HTTP contract grow fields, so clients that render
  recalls need an update to show scope and exclusions.

## Revisit if

Unlisted environments routinely stay on a recalled release for long periods.
If so, limited removal needs an expiry that widens it automatically.
