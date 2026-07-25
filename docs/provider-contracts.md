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
change that produced it; the current provider module supplies the delivery
contract and retry queue but does not wire planning or execution mutations.
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
