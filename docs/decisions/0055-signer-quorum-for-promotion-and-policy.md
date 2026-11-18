# ADR 0055: Signer quorum for promotion and policy changes

- Status: Proposed
- Date: 2026-11-18
- Issue: [#1187](https://github.com/Sannrox/tenkai/issues/1187)
- Owner: Tenkai maintainers
- Builds on: [ADR 0037](0037-multi-party-plan-approval.md),
  [ADR 0039](0039-signer-validity-windows.md),
  [ADR 0042](0042-signer-window-at-signed-time.md)
- Related: [plan approval](../plan-approval.md),
  [management lifecycle](../management-lifecycle.md),
  [offline bundles](../offline-bundles.md)

## Context

Multi-party approval (ADR 0037) covers four purposes, all on a plan:
`execute_plan`, `rollback`, `skip_gates` and `downgrade`. Two decisions
outside a plan take one authorized principal:

- **Promotion.** Moving a channel head takes one principal. Where an
  environment approves plans automatically, one person's promotion reaches
  it with nobody else involved.
- **Policies.** An environment approval policy decides who approves plans.
  A channel promotion policy promotes on evidence, so whoever edits it
  decides what ships. Either can be changed by one principal.

A site that requires two people for a production change cannot show that
Tenkai enforces it.

What exists:

- **Signing and checking.** Signed v1 plan envelopes, trust roots with
  `groups` and validity windows, and an N-of-M check that counts distinct
  keys and distinct principals.
- **Content to bind.** Promotion already returns the release's manifest
  digest and `replaced_head`. It accepts `expected_head`, which refuses
  when another release heads the channel.
- **Versions.** A promotion policy has a `policy_version` that each change
  advances. An approval policy file has a content digest.

Options:

1. **Extend the signer quorum.**
2. **Enforce it downstream only.** Require manual plan approval wherever
   two-person control is needed. This leaves automatically approving
   environments and promotion policies uncovered, and nothing can prove
   the control.
3. **A general approval request for every management change.** This adds
   a workflow, a store and a review surface, for actions that mostly do not
   need it.

## Decision

Option 1. Add two purposes, `promote` and `policy_change`. A quorum is
declared where the decision lives: on a channel for promotion and its
policy, and on an environment approval policy for changes to that policy.

### 1. A separate envelope, the same check

Signers sign a new `tenkai.change-approval.v1` envelope. Its canonical bytes
begin with that schema string, so they can never equal a v1 plan envelope
and neither can be counted as the other. The plan envelope's bytes are
unchanged.

The envelope binds:

- `purpose`;
- a subject;
- the content digest of the change;
- the state the change replaces;
- the issue time, expiry and `key_id`, as in the plan envelope.

| Purpose | Subject | Content | Replaces |
| --- | --- | --- | --- |
| `promote` | product and channel | release id and manifest digest | the current head, or `none` |
| `policy_change` | channel, or environment | digest of the new policy or quorum | current policy version or file digest |

Counting is the existing check, unchanged:

- distinct keys and distinct principals;
- named groups and `exclude_requester`;
- signer validity windows at signing time (ADR 0042);
- current trust membership.

Automatic approval never counts. A missing, expired, mismatched or untrusted
envelope fails closed and lists what is missing.

Signers come from a server-wide approver trust file, in the same format as
plan approval trust roots. It is separate from release-signing roots, because
publishers and approvers are different people. Embedded mode reads the same
file from its state directory.

The trust file decides who counts, so it is pinned like an approval policy
(§5). The server records the digest it accepted.

- **Additions.** A file that adds a signer, or adds a group to one, is
  refused until `policy_change` envelopes for its digest arrive. They must
  come from the file's own `[change]` quorum (`n`, `groups`), counted under
  the old file. Without that, one person with host access could add a
  second identity and satisfy any quorum alone.
- **Removals.** A file that only removes signers or groups is accepted on
  one principal. Revocation must stay fast (ADR 0036).
- **While refused.** Promotion into a quorum channel, and every
  `policy_change`, fail closed with `approver trust changed without
  approval`.

### 2. A channel declares its quorum

```text
tenkaictl channel quorum set <product> <channel> --n 2 --groups release,sre --exclude-requester
```

The quorum covers `promote` into that channel and `policy_change` on it.
`policy_change` here means changing the promotion policy or the quorum
itself.

A promotion into a quorum channel works like ADR 0037 §4:

- `promote` with a quorum records a pending promotion. The record holds
  the release, its digest and the expected head.
- Signers submit envelopes one at a time or all together.
- The promotion moves the head only when N valid envelopes are present and
  the head is still the one they signed. If the head moved, every envelope
  is stale and the promotion is refused.
- The pending record and the envelopes are stored durably. A crash between
  collection and the head move leaves a pending promotion, and repeating
  it is idempotent.

A channel without a declared quorum behaves exactly as today.

### 3. Changing a quorum

- **Tightening** takes the existing catalog-wide grant. A quorum the trust
  file cannot satisfy is refused when it is set, which prevents lockout:
  `n` larger than the distinct signers in the named groups, or a group with
  no signer. Tightening means
  declaring a quorum, raising `n`, or narrowing the groups. A stricter rule
  fails safe.
- **Loosening** needs `policy_change` signed by the current quorum.
  Loosening means removing a quorum, lowering `n`, widening the groups, or
  dropping `exclude_requester`. Otherwise one principal could remove the
  control and then promote alone.

### 4. Automatic promotion binds the policy version

A promotion policy acts without signers, so the quorum binds the policy
instead.

- **Policy versions.** On a channel with a quorum, each new promotion
  policy version needs `policy_change` envelopes for that version's content
  digest. This covers creating the policy and every configure change,
  including the recall rule (#1287).
- **Promoting.** The evaluator promotes only under a policy version that
  carries a quorum. Each promotion event records that version.
- **Declaring a quorum on a channel that already has a policy.** Automatic
  promotion stops until the current version is signed. It never continues
  under an unsigned version.
- **Pause and resume.** Pausing stops promotion and is exempt. Resuming
  continues the same signed version and is exempt too.

### 5. Changing an environment approval policy

An environment approval policy may include
`[[quorum]] purpose = "policy_change"`.

- The server records the digest of the policy file it accepted.
- If the file on disk later has another digest, the environment fails
  closed: every plan is refused with `approval policy changed without
  approval`. This holds until `policy_change` envelopes for the new digest
  are submitted, from signers counted under the old policy.
- `env approval-policy set` and `clear` are refused without that quorum.

A policy without this rule behaves as today.

### 6. Exempt actions, and why

- **Recall, and recording a recall range.** These are safety actions that
  reduce exposure, and they must stay fast. They take one principal and
  are audited as today.
- **Closing a recall range.** This bounds the range, so later versions can
  be promoted again. Each such promotion still needs the channel quorum,
  either through `promote` envelopes or through a promotion policy version
  the quorum signed (§4). The close itself therefore needs none.
- **Placing, releasing or scheduling a hold, and cancelling a freeze
  (#1182).** A hold changes when delivery runs, not what ships. Releasing a
  hold lets plans run that were already approved, under the quorum where
  one applies, and moves no channel head.

### 7. Disconnected sites

- **Carriage.** A bundle that carries a channel head also carries its
  `promote` envelopes. It carries the `policy_change` envelopes for the
  signed policy version when it carries a promotion policy.
- **Verification.** A site whose copy of the channel declares a quorum
  verifies the envelopes against its own approver trust file at import.
  Bundles travel for days, so two checks move:
  - **Expiry.** Each envelope's expiry and signer window are checked
    against the time the hub moved the head, not against import time. That
    time is carried in the signed bundle manifest.
  - **The replaced head.** Each envelope's `replaces` is checked against
    the bundle's chain of head moves for the channel, not the site's live
    head. The bundle carries every move since the head it starts from. That
    first head must equal the site's current head.

  A missing or invalid quorum, or a chain that does not start at the site's
  head, refuses that channel's head moves. This happens, for example, when
  the site skipped a bundle. The rest of the bundle imports, and the
  receipt names the refused channel and the head it needs.
- **Sites without a quorum.** A site that declares no quorum records the
  envelopes and moves the head as today.

### 8. Old servers refuse

- **Approval policy files.** `policy_change` is a new `QuorumPurpose`
  value. Older servers parse approval policies with unknown fields and
  values denied, so they refuse such a policy as malformed instead of
  ignoring the rule.
- **Channel quorums and signed policy versions.** These are stored state.
  They live in a store schema version the release introduces. A binary
  already refuses a store whose schema is newer than it supports
  ([operational storage](../operational-storage.md)), so once a store is
  migrated no older server can promote into it while ignoring a quorum.
  The usual pre-migration copy and rollback path applies.

## Out of scope

- A general approval workflow for other management changes (option 3).
- Quorum on publish. Release signing already binds the publisher.
- Quorum on subscribe, environment configuration or labels. Each of these
  reaches a target only through plan approval.

## Consequences

- Two-person control covers promotion, automatic promotion and the
  policies that decide approval. Environments that approve automatically
  are included.
- A quorum channel promotes more slowly, by design. Recall and holds stay
  single-principal.
- The approver trust file becomes server configuration, and operators
  rotate it like plan approval trust roots.

## Revisit if

Most quorum promotions are signed by the same two people moments apart.
That would mean the quorum sits on the wrong action. The control would
then belong on environment plan approval, not on the channel.
