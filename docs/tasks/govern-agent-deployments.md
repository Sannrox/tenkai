# Govern agent deployments

Goal: let an agent observe state and propose a plan, and keep approval and apply with a human.

## Authority

[ADR 0034](../decisions/0034-agent-actor-mutations.md): an agent in the actor chain may create a forward plan. Apply, approve, publish, promote, recall, subscribe, holds, retry, reconcile, and evidence writes return 403. Rollback and downgrade plans always need a human-signed envelope. `TENKAI_AGENT_ACTOR_POLICY=forbid` refuses agent plans too.

Read, plan, explain:

```sh
tenkaictl --output json-v1 status --env prod
tenkaictl --output json-v1 env inspect prod
tenkaictl --output json-v1 plan --env prod
tenkaictl --output json-v1 explain prod api
```

Never run `approval submit` or `apply` as an agent. The packaged [tenkaictl skill](../../.agents/skills/tenkai/SKILL.md) follows that bound.

## Approval brief and agent budget

Every plan carries a brief covered by the plan digest. It names the proposer and actor chain, blast radius, risky changes, attached evidence, what live policy would do without a human (`auto` or `require_human`), and the agent budget (`inside`, `over`, or `not_configured`).

- `not_configured`: no agent in the chain
- `inside`: an agent proposed, and policy would auto-approve a forward plan
- `over`: an agent proposed, and policy requires a human

A refusal with `reason.code` `agent_budget` means the actor is outside that budget. json-v1 `plan` stays resource ids; read the brief from human `plan show` or `latest_plan.approval_brief` on `env inspect`.

## Previews

A preview environment is a short-lived, non-promotable environment bound to one branch pin. The brief records evidence `preview` when the environment is a preview. Provision is embedded-only.

```sh
tenkaictl env preview review \
  --pin pin.json \
  --expires-at 2026-09-16T00:00:00Z
tenkaictl --output json-v1 plan --env review
tenkaictl env close-preview review
```

Subscribe and promote of a preview are refused. Detail: [preview environments](../preview-environments.md).

## Tool adapter

A planned adapter will speak the existing HTTP v1 contract: read tools plus propose-only plan create. It adds no authority. Agent rules, budgets, and human-signed apply stay as they are. Until that adapter ships, drive Tenkai with `tenkaictl` and `--output json-v1`.

Contract detail: [plan approval](../plan-approval.md#approval-brief), [authenticated request context](../auth-request-context.md).
