---
name: tenkai
description: Run the Tenkai control loop with tenkaictl. Use when inspecting state, publishing or verifying a release, promoting a channel, configuring an environment, planning or applying delivery, reconciling a fleet, rolling back, migrating packages, or recovering operational state.
---

# Tenkai control loop

Every `tenkaictl` run is one **control loop**: observe, transition, verify.
Tenkai is the authority.

## 1. Observe

1. Resolve the `tenkaictl` binary, target mode, and environment.
2. For embedded mode, set `--database` or `TENKAI_DATABASE`. Use the default
   `.tenkai-state/tenkai.db` only when the user intends that path.
3. For remote mode, use `--target remote` with a configured server URL. Load
   credentials from environment, secret configuration, or `tenkaictl login`.
   Keep tokens, signing keys, and approval material out of argv, logs, and
   reports.
4. When the installed version may differ from this skill, run `tenkaictl --help`
   and the relevant subcommand help. Installed help is the syntax authority.
5. Inspect current state before proposing a mutation: `env list`,
   `env inspect <environment>`, `status --env <environment>`, and `inspect`
   (embedded totals). Use `fleet status` for cross-environment posture. For
   one drift sample, use `fleet watch --once`, with `--baseline` when
   comparing to a saved snapshot.

**Done when:** binary, target, database or server, environment, and current
authoritative state are explicit. If the request is observe-only, skip to
Report.

## 2. Bound the transition

1. Pick **one** family from [references/commands.md](references/commands.md)
   as the transition.
2. Name the exact resource and environment before any mutation.
3. Create a fresh plan after desired state changes. Plan identifiers are
   opaque; apply the selected stored plan.
4. For publication, approval, gates, emergency execution, or development
   bypasses, read [references/trust.md](references/trust.md) and require
   current content-bound evidence.
5. Treat provider evidence as policy input. Reconstruct releases, plans,
   deployment state, rollback state, and recovery authority from Tenkai.

**Done when:** the transition has one target, its preconditions hold, and every
required trust artifact is present and current.

## 3. Execute once

1. For supported embedded commands that another agent or program will consume,
   pass `--output json-v1` before the subcommand.
2. Execute the bounded transition once.
3. Preserve the complete result envelope, opaque resource identifiers, exit
   status, and sanitized diagnostics. Keep secrets, signing keys, bearer tokens,
   executor output, and deployment payloads out of captures and reports.
4. On missing, malformed, truncated, or incompatible machine output, classify
   the mutation as **unknown**. Inspect authoritative state before deciding
   whether a retry is safe.
5. **Fail closed** on denial, stale or absent evidence, a lease or fencing
   error, unknown deployment state, or a command unsupported in the selected
   target mode.

**Done when:** Tenkai records a terminal outcome, or the operation is classified
as blocked or unknown.

## 4. Verify

1. Re-inspect the affected release, environment, plan, or fleet.
2. Confirm observed deployment state, channel head, plan lifecycle, and trust
   evidence as they apply. A successful process exit is not a **receipt**.
3. For an unknown apply or rollback, failed cleanup, or recovery, follow
   [references/recovery.md](references/recovery.md). Inspect plan and
   environment before retrying. Record a manual observation only after
   independently verifying the live target.

**Done when:** durable Tenkai state matches the intended outcome, or the report
names the blocker, current state, and safest next operator action.

## Report

Return:

- target mode, database or server, and environment;
- operation and affected opaque resource identifiers;
- observed pre-state and verified post-state;
- trust, approval, gate, lease, and recovery evidence that mattered;
- commands run, with secrets omitted;
- blockers, unknown outcomes, and actions left unretried.

**Done when:** the report includes every item above.
