# ADR 0034: Agent actors cannot make delivery changes on their own

- Status: Accepted
- Date: 2026-10-18
- Issue: [#648](https://github.com/Sannrox/tenkai/issues/648)
- Owner: Tenkai maintainers
- Related: [ADR 0030](0030-remote-management-lifecycle.md)

## Context

Tenkai accepts platform JWT assertions and OIDC access tokens (#589). When an
AI agent calls through a tool gateway, the token carries the user as `sub`
and the agent in the `act` (actor) claim. Tenkai ignored `act`, so an agent
could publish, promote, hold, approve, or apply with the user's full rights.
Remote apply also takes its approval envelope and trust roots from the
request, so a caller with management capability can present an approval it
signed itself. A signature check alone does not keep an agent out of the loop.

## Decision

1. **Parse the actor chain.** Both verifiers read `act` after signature and
   claim checks. It is a string actor id or a nested
   `{"sub": id, "kind"?: k, "act"?: ...}` object. Only `kind: "human"` marks
   a person. A bare string or any other kind is an agent, so an unlabelled
   actor never gets human authority. Empty ids, repeated actors, and chains
   deeper than eight fail closed as an invalid credential.
2. **Plans are the pending approval.** Under the default policy
   (`require_approval`), an agent may create a plan or a rollback plan. It
   goes through the environment's approval policy like any plan. An agent's
   plan uses the reconciler's own convergence, so held failed targets stay
   held and the plan authorizes nothing the reconciler would not run.
   Retrying a held target stays a human operation. Rollback and downgrade
   plans always need a human-signed envelope.
3. **Refuse every other agent mutation.** Apply, approve, publish, promote,
   recall, subscribe, retire, holds and their release, target retry,
   reconcile, package-migration apply, resume and rollback, evidence
   writes, and development fixture import and reset return 403. Tenkai has no approval queue for these, so a human
   makes the change.
4. **`forbid` refuses plans too.** `TENKAI_AGENT_ACTOR_POLICY=forbid` (or
   `--agent-actor-policy forbid`) refuses every agent mutation.
5. **Audit both principals.** Management audit records name the subject and
   the actors, for example `user-1 (act: assistant-7)`. Refusals are audited
   as `<operation>.refused`. Read routes are unchanged.

## Consequences

- An agent can propose a rollout as a plan. It cannot apply, approve, or
  change the catalog or desired state without a human principal. In an
  environment with automatic approval, a forward plan runs as the
  reconciler's own plan would.
- A delegating service that calls for a human must label the actor with
  `kind: "human"`, or its mutations are refused.
- The audit principal column carries both identities without a schema
  change. A dedicated actor column can follow if audit queries need it.

## Alternatives considered

- **Accept a human-signed approval on an agent's apply.** Rejected: remote
  apply trusts request-supplied roots, so the agent could sign its own.
- **A new pending-change queue for publish, promote and holds.** Rejected for
  now: it adds a second approval system next to plan approval. A refusal is
  safe, and a human repeats the call.
- **Treat any `act` as a person unless labelled an agent.** Rejected: an
  unlabelled actor would keep full user rights, which is the gap this closes.
