# Trust and authorization

## Releases

Require both a detached `tenkai.release-signature.v1` envelope and current
Ed25519 trust roots. The signature binds the exact manifest and declared deploy
inputs. Inspect or reverify stored evidence before promotion when its trust
status is material.

Registered provenance envelopes are immutable, payload-free evidence attached
to a release. Authority stays on signatures, approvals, gates, and Tenkai
state.

## Plans

Require a detached `tenkai.plan-approval.v1` envelope for non-local execution.
It must be unexpired and bound to the exact executable plan, environment,
purpose, gate-bypass choice, policy evidence, and current approver trust roots.
Create a new approval after any plan change.

If continuous reconciliation reports `awaiting_approval`, preserve the plan and
obtain approval for that exact identifier. Two delivery paths exist:

- `approval submit <plan-id> --env <env> --approval <envelope>
  --approval-trust-roots <roots>` (remote adds `--generation`) hands one
  envelope to one command; `apply` takes the same flags.
- A running `tenkai-server` or `tenkaictl reconcile` picks up
  `$TENKAI_PLAN_APPROVAL_DIR/<plan-id>.json` on its next tick and verifies it
  against `TENKAI_PLAN_APPROVAL_TRUST_ROOTS`. Both variables are read from the
  reconciler's environment at startup; without them every non-local plan stays
  `awaiting_approval`. An environment may opt into
automatic signing through `tenkaictl env approval-policy`; skip-gates and
rollback still need a human. Clearing the policy or the auto-signer key
revokes pending automatic envelopes.

## Gates and emergency starts

Evaluation evidence must match the release content and current suite
definition. Missing, stale, invalid, unavailable, or incomplete required
evidence blocks execution.

`--skip-gates` and `--emergency-reason` are break-glass inputs. Use them only
with separate operator authorization and an auditable, non-empty reason. Gate
skip and emergency start still require plan approval.

## Local development

The explicit development paths are limited to the built-in `local`
environment:

```sh
tenkaictl publish <manifest> --allow-unsigned-development
tenkaictl apply <plan-id> \
  --allow-unapproved-development \
  --development-reason "<reason>"
```

Use them only when the user requested local development or an established
development workflow requires them. Never infer development permission from a
loopback address, embedded mode, an absent provider, or missing credentials.

`tenkaictl dev` signing helpers are dogfood tooling, not a production KMS.

## Credentials

Load management tokens, runtime tokens, private signing keys, and approval
material from environment or secret configuration. Keep them out of command
arguments, logs, reports, repositories, backups, and executor payloads. Each
runtime credential must authorize exactly one environment.
Remote `tenkaictl` uses `TENKAI_MANAGEMENT_TOKEN` when set; otherwise it uses
the login saved under `$XDG_CONFIG_HOME/tenkai/tokens.json`.

Unattended jobs do not use interactive `login`. Prefer
`tenkaictl login --client-credentials`, which reads `TENKAI_OIDC_CLIENT_ID` and
`TENKAI_OIDC_CLIENT_SECRET` from the environment and never stores the secret.
Back it with an OIDC grant rule of `kind = "service"` scoped to the job: a
`publish` capability for CI (publish is always catalog-wide; `channels` only
confines promote), or
`management` with one `environment` for an environment bot. The fleet-wide
`TENKAI_MANAGEMENT_TOKEN` carries full management authority; use it only when
no scoped grant is available.
