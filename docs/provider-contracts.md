# Governance and intelligence provider contracts

Tenkai has four independent provider ports:

- **Gate provider:** returns evaluation evidence for an exact release, plan,
  environment configuration, and environment.
- **Policy provider:** authorizes one named action for an authenticated
  principal and the same exact operational inputs.
- **Audit exporter:** receives immutable operational events after Tenkai has
  committed them locally.
- **Outcome provider:** receives terminal deployment outcomes for learning or
  analysis after Tenkai has committed them locally.

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

Audit and outcome delivery uses a Tenkai-owned durable outbox. Host wiring must
commit the outbox event in the same operational-store transaction as the state
change that produced it. The shipped SQLite host wiring uses that contract for
configured terminal-outcome export: embedded/server plan, deployment,
cancellation, and unknown-state reconciliation transitions write the versioned
outcome event in the same SQLite transaction as the terminal object update.
This is not a general planning or execution-event bus: audit mutations,
planning events, and non-terminal lifecycle changes are not wired to this
outcome queue.
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

Outcome workers claim only the `outcome` destination. A separate adapter cannot
consume or acknowledge audit events accidentally. Delivery failure and timeout
leave the attempt count, bounded retry time, and sanitized failure reason in
the durable row and emit a bounded degraded diagnostic; they do not make the
server unready.

### Terminal outcome event v1

`ProviderEvent.payload_json` contains `tenkai.terminal_outcome.v1` with:

- stable deployment, plan, release, product, environment, and configuration
  identities;
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

When a failed restore makes deployment state unknown, Tenkai records the
originating deployment, plan, and step identities on the environment in the
same terminal transaction. A later explicit reconciliation exports
`unknown_reconciled` only from that durable origin; legacy or manually created
unknown state without an attributable origin is cleared without inventing
learning evidence.

## Standalone operation and external adapters

The built-in local gate consumes explicitly configured evidence, and the local
policy uses an explicit action allow-list. Without matching configuration they
deny rather than implicitly allow. The local audit/outcome sink is idempotent.
Together with SQLite these implementations exercise the complete provider
workflow without sekai-chisei or another external service.

External sekai/chisei or other adapters translate their protocol into these
ports. They must enforce transport authentication, bounded payloads and
deadlines, redact credentials, validate returned evidence, and pass the same
binding, denial, timeout, idempotency, and retry tests as the local adapters.

## Chisei terminal-outcome adapter (#197)

Reference adapter: `ChiseiOutcomeProvider` in `src/providers.rs`.

The adapter maps each terminal event to the already-vendored
`ChiseiService.RecordSampleObservation` RPC:

- Tenkai event ID → `request_id` (downstream idempotency key);
- configured namespace → `namespace`;
- `tenkai.terminal_outcome.v1` → `spec`;
- the bounded payload → `output_content`; and
- terminal state → `sample_reason`.

Chisei authenticates the telemetry-writer principal and enforces namespace
membership. A `recorded=false` response, transport error, timeout, or gRPC
failure defers the event. The adapter never calls a Tenkai mutation or recovery
API.

Configure the server explicitly:

```sh
export TENKAI_OUTCOME_PROVIDER_URL=https://sekai.example.internal
export TENKAI_OUTCOME_NAMESPACE=delivery-learning
export TENKAI_OUTCOME_PROVIDER_PRINCIPAL=tenkai.outcome
export TENKAI_OUTCOME_PROVIDER_TOKEN='inject-from-secret-store'
tenkai-server --outcome-provider chisei
```

The token is environment-only, and remote plaintext endpoints are rejected
even when no token is configured. Outcome export requires embedded Tenkai
application state so the authoritative transition and outbox write share one
local transaction; the legacy `--provider-mode remote` composition is rejected.
With no `--outcome-provider`, Tenkai creates no adapter, queues no outcome
events, and opens no outcome-provider connection; embedded inspection may still
show already durable Tenkai-owned outcome rows.

### Authenticated outcome inspection

The authenticated management projection returned by
`GET /v1/environments/{environment}` and `tenkaictl env inspect` includes a
bounded `terminal_outcomes` list. Each entry contains the stable event,
deployment, plan, release, product, environment, and configuration identities;
the evidence binding digests; the terminal state; the Tenkai observation time;
and one of `pending`, `in_flight`, `retrying`, or `delivered` with attempts,
bounded retry timing, acknowledgement time, and delivery lag. Claim tokens,
retry error text, event payloads, credentials, source content, and executor logs
are never returned. An unconfigured outcome provider produces no new rows;
embedded inspection may show already durable rows. The absence of a row is not
inferred to mean that an outcome was delivered.
Tenant-mode hosts suppress the community embedded projection until the
authenticated tenant partition exposes the same bounded read, so one tenant
cannot observe another tenant's outcome identities.
Pre-v2 outcome rows remain durable for delivery but are omitted from this
projection because their historical identity did not bind every returned field.

The PostgreSQL adapter exposes the same kind-filtered queue contract, but the
current mixed SQLite/PostgreSQL composition does not provide atomic terminal
wiring for the gated `enterprise-experimental` profile. That profile therefore
does not advertise terminal-outcome, audit, or planning-event export until
PostgreSQL owns the complete authoritative state and its wiring and recovery
evidence are complete.

## Remote gate HTTP JSON contract (#113)

Reference adapter: `HttpRemoteGateProvider` in `src/providers.rs`.

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

**Configuration:** endpoint URL + optional bearer (env/file). Community
ungated products never construct the remote adapter and never open a network
connection for gates.
