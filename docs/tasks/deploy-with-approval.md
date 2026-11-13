# Deploy with approval

Goal: converge one environment onto its channel heads with a signed plan approval.

The five-minute local path uses development flags that every other environment refuses. This page is the governed path. Signing keys and approval envelopes stay in files; never on argv.

## Observe

```sh
tenkaictl --output json-v1 status --env prod
tenkaictl --output json-v1 env inspect prod
```

A successful `status` envelope looks like:

```json
{
  "schema": "tenkai.command-result/v1",
  "command": "status",
  "outcome": "succeeded",
  "retry": "not_needed",
  "resources": [{"kind": "environment", "id": "prod"}]
}
```

An absent, truncated, or unknown-schema envelope means the outcome is unknown. Inspect before retrying.

## Plan

```sh
tenkaictl --output json-v1 plan --env prod
tenkaictl plan show tenkai:plan:prod:1:opaque
```

`plan` returns resource ids and counts in json-v1. The approval brief (proposer, blast radius, risky changes, `auto` or `require_human`, agent budget) prints on human `plan` and `plan show`. Remote `env inspect` returns it on `latest_plan.approval_brief`. Remote `plan` also needs `--generation`.

## Human signs and records approval

An agent must stop here. A human signs a `tenkai.plan-approval.v1` envelope bound to this plan digest, then:

```sh
tenkaictl approval inspect tenkai:plan:prod:1:opaque
tenkaictl --output json-v1 approval submit tenkai:plan:prod:1:opaque \
  --env prod \
  --approval approval.json \
  --approval-trust-roots approvers.toml
```

`outcome: "awaiting_approval"` means the plan is stored and a human has not yet authorized it. Do not invent a bypass.

## Apply the approved plan

```sh
tenkaictl --output json-v1 apply tenkai:plan:prod:1:opaque \
  --approval approval.json \
  --approval-trust-roots approvers.toml
```

Then re-run `status` and `env inspect`. A failed health probe restores the previous pin and holds that target.

Contract detail: [command results](../command-results.md), [plan approval](../plan-approval.md).
