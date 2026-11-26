# Governance and intelligence provider contracts

Tenkai has three independent provider ports:

- **Gate provider:** library adapter for a required policy decision. Release
  `[gate].eval_suite` admission uses stored signed evaluation evidence, not a
  pulled provider projection.
- **Policy provider:** authorizes one named action for an authenticated
  principal and the same exact operational inputs.
- **Audit exporter:** receives immutable operational events after Tenkai has
  committed them locally.

Terminal-outcome and feedback-observation export were removed (#1580); see
[Removed outcome and feedback export](#removed-outcome-and-feedback-export-1580).

These ports do not expose planning, execution, lease, receipt, deployed-state,
or rollback mutations. An adapter cannot become authoritative for operational
state. The operational store remains sufficient to recover when every optional
adapter is absent.

## Evidence and required decisions

`EvidenceBinding` version 1 includes the release digest, immutable plan digest,
environment-configuration digest, and environment identity. Tenkai hashes the
length-delimited fields and requires a provider decision to return that exact
binding digest. Empty fields, unknown contract versions, stale or mismatched
bindings, malformed responses, denials, timeouts, and transport failures all
fail closed when the selected operation requires the decision.

Required-provider errors name the blocked action and retain the provider's
reason. A gate bypass is a separate governed action under ADR 0001; provider
absence is never interpreted as a bypass.

Every request carries a stable request ID. Adapters must treat it as an
idempotency key and return the same evidence identity when the same request is
retried. Hosts apply a finite operation deadline. Tenkai may retry an
unavailable required decision, but it cannot execute the governed action until
valid bound evidence is returned.

## Optional exports and retries

Optional deliveries (webhooks, health gates, exposure, recall notices) use a
Tenkai-owned durable outbox. Host wiring must commit the outbox event in the
same operational-store transaction as the state change that produced it.
The event is always durable before an adapter is called. Its destination kind
and stable event ID form the adapter idempotency key; enqueueing the same pair
and payload is safe, while reusing the pair with different content is rejected.

Workers atomically claim events with fresh, unique, expiring tokens; token
reuse while a claim is active is rejected. An event is acknowledged
only by its claimant after successful delivery. Failure or timeout
increments the durable attempt count, records an operator-visible error, and
schedules bounded exponential backoff (one second through roughly 17 minutes).
Restarting Tenkai does not lose pending events. Adapters may receive an event
more than once and must deduplicate by event ID. Optional lag degrades the
integration but never changes or rolls back committed operational truth.
The first delivery attempt binds a durable collection timestamp into the
outbox envelope; retries reuse that timestamp so Sekai replay-window checks do
not see a new evidence body on every attempt.

Each worker claims only its own destination kind, so one adapter cannot
consume or acknowledge another's events. Delivery failure and timeout leave
the attempt count, bounded retry time, and sanitized failure reason in the
durable row and emit a bounded degraded diagnostic; they do not make the
server unready.

### Health/SLO gate event v1

`ProviderEvent.payload_json` for provider kind `health_gate` contains
`tenkai.health_gate_evidence.v1`: each declared gate's name, query, threshold,
observed value, and verdict, plus halt-or-rollback policy. The binding uses the
gated release digest, plan content id, evidence digest, and environment.
Webhook delivery of this event remains available on the `health_gate` outbox
kind. Apply-lifecycle notifications (`apply.succeeded`, `apply.failed`,
`apply.rolled_back`) use provider kind `deploy_webhook`; see
[post-deploy webhooks](deploy-webhooks.md).

### Deploy webhook event v1

`ProviderEvent.payload_json` for provider kind `deploy_webhook` is an envelope
(`tenkai.deploy_webhook.envelope.v1`) that names the destination URL and
`secret_env`, plus the public body (`tenkai.deploy_webhook.v1`). Event identity
is a digest of destination URL, plan id, step id, and event name, so replaying
the same terminal step is idempotent. The worker POSTs only the public body,
signed with HMAC-SHA256, and binds `observed_at` from the outbox collection
timestamp on first delivery. Payloads contain environment, product, versions,
release id/digest, optional source revision, artifact digests, plan id, step id,
outcome, and that timestamp. Failed and rolled-back bodies also include the
first observation's `attempt_id` and a one-line redacted cause `summary`. They
contain no secrets, captured command output, or workdir paths. A replay of the
same outbox id keeps the first `attempt_id`. A rollback body sets `alert` and
includes both versions.
Delivery retries use the durable outbox; apply does not wait.

### Terminal outcome event

Tenkai no longer queues terminal outcomes (#1580). Rows that earlier releases
queued keep this format and stay readable in
[outcome inspection](#authenticated-outcome-inspection).

`ProviderEvent.payload_json` contains `tenkai.terminal_outcome.v2`, version
`2.0.0`. Its JSON Schema is
[`api/tenkai-terminal-outcome-v2.schema.json`](../api/tenkai-terminal-outcome-v2.schema.json),
generated from the payload type and checked by `make validate`. The payload
has:

- stable deployment, plan, release, product, environment, and configuration
  identities, plus the owning tenant on tenant-mode hubs (omitted on community
  hosts);
- one of `deployment_succeeded`, `deployment_failed`,
  `automatic_rollback_succeeded`, `rollback_succeeded`, `rollback_failed`,
  `execution_cancelled`, or `unknown_reconciled`; and
- the Tenkai observation timestamp.

The event's `EvidenceBinding` carries the exact release digest, immutable plan
digest, environment-configuration digest, and environment identity. Event
identity is a deterministic digest over the deployment, plan, release, terminal
state, observation time, and evidence binding. Replaying the same transition is
idempotent, while a later transition with the same operational inputs remains a
distinct fact. Payloads are bounded to 16 KiB and contain no status detail,
command output, environment facts, artifact/source content, approvals,
credentials, or signing material.

Versioning: the schema is closed and registered with exact compatibility. A
delivery worker derives the envelope (schema version, target kind, target id)
from the payload's `schema` id, so any change to the content, envelope, or
target needs a new id `.vN` at version `N.0.0`. Older releases then refuse
rows with an id they do not know, as a visible, retryable failure, instead of
resending them with a different envelope under the same idempotency key.
`.v2` (#867) added the optional `tenant_id` and the tenant-scoped target;
`.v1@1.0.0` rows queued before 0.7.0 still deliver exactly as before.

When a failed restore makes deployment state unknown, Tenkai records the
originating deployment, plan, and step identities on the environment in the
same terminal transaction. A later explicit reconciliation exports
`unknown_reconciled` only from that durable origin; legacy or manually created
unknown state without an attributable origin is cleared without inventing
learning evidence.

### Feedback observation v1

Every committed deployment outcome also leaves one
`tenkai.feedback_observation.v1` record (#802). It is captured always,
and is not a provider event; an endpoint may receive it as a signed
[`feedback.observation` webhook](deploy-webhooks.md). It is written
in the same transaction as the outcome, into a dedicated
`feedback_observations` table that refuses updates. On a tenant-mode
PostgreSQL hub that table lives in the tenant's schema, beside the catalog
objects the outcome commits (#868). An identical replay is a
no-op; a conflicting one keeps the stored record. A capture that cannot be
built keeps only the outcome's identity (`reason: degraded`), and one that
cannot be stored never interrupts the deployment or rollback.

Fields: `id` (the outcome's identity), `operation`, `environment`,
`product`, `plan_id`, `step_id`, `action`, `release_id`, `status`, `reason`,
`duration_ms` (from execution entry, when this process saw it start; absent
after a restart), `controller_version`, `lease_generation`, `observed_at_ms`,
and an optional `context`.

`operation` is `apply_step`, `runtime_completion`, `unknown_reconciliation`,
or, for outcomes no step commits (#803), `plan_blocked` (a maintenance window
or release gate held the plan), `plan_failed` (the plan failed before or
around its steps) or `orphan_recovery` (a plan left running by a stopped
controller was failed on recovery).

`reason` is one of `none`, `product_failed`, `product_failed_restored`,
`tenkai_failed`, `tenkai_failed_restored`, `cancelled`, `blocked`,
`state_unknown`, `reconciled`, `maintenance_blocked`, `gate_blocked`,
`plan_failed`, `abandoned` and `degraded`.

`context` carries what a retry or recovery is attributable to, each part only
when set: `takeover` (the lease was taken over from an expired holder),
`runtime_claim_generation`, `failed_target_retry` (the step retried a release
held as failed) and `recovery_reason` (the audited reason that admitted a
recalled rollback, bounded).

A record holds no detail text: no command output, credentials, signing
material, environment facts or content. Identifiers are bounded.

## Removed outcome and feedback export (#1580)

Releases before #1580 could export terminal outcomes
(`--outcome-provider chisei`) and feedback observations
(`--feedback-provider chisei`) to an external evidence service through the
outbox. Both exports are removed, so delivery state stays in Tenkai:

- `tenkai-server` refuses to start, before opening any store or connection,
  when either flag is `chisei` or any of `TENKAI_OUTCOME_NAMESPACE`,
  `TENKAI_FEEDBACK_NAMESPACE`, or `TENKAI_{OUTCOME,FEEDBACK}_PROVIDER_{URL,PRINCIPAL,REGISTRATION,TOKEN}`
  is set. The error names what to unset.
- Tenkai queues no new `outcome` or `feedback` outbox rows. Feedback
  observations are still captured locally and still feed webhooks.
- Rows already queued are kept, never deleted and never sent. Outcome rows
  stay visible in [outcome inspection](#authenticated-outcome-inspection).
  Rolling back to the previous release resumes their export.
- Model-runtime canary and smoke evidence is still signed and recorded in
  the local outbox whenever a model evidence signing key is configured
  ([model release evidence](model-release-evidence.md)).

## Standalone operation and external adapters

The built-in local gate consumes explicitly configured evidence, and the local
policy uses an explicit action allow-list. Without matching configuration they
deny rather than implicitly allow. The local audit sink is idempotent.
Together with SQLite these implementations exercise the complete provider
workflow without sekai-chisei or another external service.

External sekai/chisei or other adapters translate their protocol into these
ports. They must enforce transport authentication, bounded payloads and
deadlines, redact credentials, validate returned evidence, and pass the same
binding, denial, timeout, idempotency, and retry tests as the local adapters.

### Authenticated outcome inspection

The authenticated management projection returned by
`GET /v1/environments/{environment}` and `tenkaictl env inspect` includes a
bounded `terminal_outcomes` list. Each entry contains the stable event,
deployment, plan, release, product, environment, and configuration identities;
the evidence binding digests; the terminal state; the Tenkai observation time;
and one of `pending`, `in_flight`, `retrying`, or `delivered` with attempts,
bounded retry timing, acknowledgement time, and delivery lag. Claim tokens,
retry error text, event payloads, credentials, source content, and executor logs
are never returned. Tenkai queues no new rows (#1580); inspection shows rows
earlier releases queued. The absence of a row is not
inferred to mean that an outcome was delivered.
Tenant-mode hosts project terminal outcomes from the authenticated tenant
partition, so one tenant cannot observe another tenant's outcome identities.
Pre-v2 outcome rows remain durable for delivery but are omitted from this
projection because their historical identity did not bind every returned field.

The PostgreSQL adapter exposes the same kind-filtered queue contract.

## Remote gate HTTP JSON contract (#113)

Library adapter: `HttpRemoteGateProvider` in `src/providers.rs`. Apply
admission for `[gate].eval_suite` uses stored signed evaluation evidence
([evaluation gate evidence](evaluation-gate-evidence.md)). No shipped binary
constructs this HTTP adapter or reads `TENKAI_GATE_URL` / `TENKAI_GATE_TOKEN`.

| Field | Value |
| --- | --- |
| Method | `POST` |
| Body | JSON [`DecisionRequest`] (request_id, action, principal, binding) |
| Success | `2xx` with JSON [`ProviderDecision`] |
| Failure | non-2xx, timeout, invalid JSON, or mismatched binding → fail closed when required |

Example decision response:

```json
{
  "allowed": true,
  "reason": "eval suite passed",
  "evidence_id": "chisei:run:…",
  "binding_digest": "sha256:…",
  "request_id": "…",
  "action": "deploy",
  "principal": "operator"
}
```

`binding_digest` must equal `EvidenceBinding::digest()` for the request.
`request_id` / `action` / `principal` must match. Hosts wrap the call in
`required_decision` so denials, timeouts, and forged bindings block apply.

**Chisei mapping (compatible, not hard lock):** a chisei eval host may implement
this endpoint by evaluating the named suite against the bound digests and
returning its run id as `evidence_id`. Other eval products can use the same
JSON without vendored protocols.

**Configuration:** callers pass an endpoint URL and optional bearer into the
library constructor. Community ungated products never construct the remote
adapter and never open a network connection for gates.
