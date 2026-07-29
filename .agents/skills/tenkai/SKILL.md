---
name: tenkai
description: Operate a Tenkai delivery control plane. Use when an agent needs to inspect Tenkai state, publish or verify a release, promote a channel, configure an environment, plan or apply delivery, observe or reconcile a fleet, roll back a product, or recover embedded operational state.
---

# Operate Tenkai

Treat Tenkai as the authority for releases, channels, environments, executable
plans, leases, receipts, rollback, and recovery. Follow one control loop:
**observe, transition, verify**.

## Establish the operating boundary

1. Resolve the `tenkaictl` binary, target mode, and environment.
2. For embedded mode, resolve the database explicitly with `--database` or
   `TENKAI_DATABASE`. Preserve the default only when the user clearly intends
   `.tenkai-state/tenkai.db`.
3. For remote mode, use `--target remote` and a configured server URL. Keep
   management and runtime credentials in environment or secret configuration,
   never command arguments or output.
4. Run `tenkaictl --help` and the relevant subcommand help when the installed
   version may differ from this skill. Installed help is authoritative for
   syntax and supported target modes.
5. Inspect current state before proposing a mutation. Read
   [references/commands.md](references/commands.md) for operation-specific
   commands.

Complete when the binary, target, database or server, environment, and current
authoritative state are explicit.

## Bound the transition

1. Translate the request into one Tenkai transition: publish, promote,
   subscribe or configure, plan, apply, reconcile, roll back, or recover.
2. Show the exact intended resource and environment before any execution that
   mutates a deployment or replaces operational state.
3. Create a fresh plan after desired state changes. Treat plan identifiers as
   opaque and apply only the selected stored plan.
4. Require content-bound release signatures and plan approvals outside the
   built-in local development path. Read
   [references/trust.md](references/trust.md) whenever publication, approval,
   gates, emergency execution, or development bypasses are involved.
5. Treat optional provider evidence as policy input only. Never reconstruct
   releases, plans, deployment state, rollback state, or recovery authority
   from a provider projection.

Complete when the transition has one target, its preconditions are satisfied,
and every required trust artifact is present and current.

## Execute once

1. Prefer `--output json-v1` for supported embedded commands when another
   agent or program must consume the result.
2. Execute the bounded transition once.
3. Preserve the complete result envelope, opaque resource identifiers, exit
   status, and sanitized diagnostics. Do not capture secrets, signing keys,
   bearer tokens, executor output, or deployment payloads.
4. On missing, malformed, truncated, or incompatible machine output, classify
   a mutation outcome as unknown. Inspect authoritative state before deciding
   whether a retry is safe.
5. Stop on denial, stale or absent evidence, a lease/fencing error, unknown
   deployment state, or a command that is unsupported in the selected target
   mode. Do not weaken policy to obtain success.

Complete when Tenkai records a terminal outcome or the operation is explicitly
classified as blocked or unknown.

## Verify the durable result

1. Re-inspect the affected release, environment, plan, or fleet.
2. Confirm observed deployment state, channel head, plan lifecycle, and trust
   evidence as applicable. A successful process exit is not an execution
   receipt.
3. For an unknown apply or rollback, inspect both the plan and environment
   before retrying. Never repeat deployment mutation blindly.
4. For failed cleanup or recovery, follow
   [references/recovery.md](references/recovery.md). Record manually reconciled
   state only after independently verifying the live target.

Complete when durable Tenkai state matches the intended outcome, or the report
names the blocker, current state, and safest next operator action.

## Report

Return:

- target mode, database or server, and environment;
- operation and affected opaque resource identifiers;
- observed pre-state and verified post-state;
- trust, approval, gate, lease, and recovery evidence that mattered;
- commands run with secrets omitted; and
- blockers, unknown outcomes, and actions deliberately not retried.
