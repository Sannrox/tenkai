# Post-deploy webhooks

Tenkai can notify an external HTTPS endpoint when an apply finishes. Delivery
uses the durable provider-event outbox: the observation is committed first,
then a background worker posts a signed JSON body. Endpoint downtime does not
fail apply, rollback, or recovery. Retries are visible on the outbox row.

This page is the operator contract for #546.

## Configure

Store only the URL, the name of a process environment variable that holds the
HMAC secret, and the events to send. Secret bytes never enter Tenkai state.

```bash
export TENKAI_WEBHOOK_SECRET
tenkaictl env webhooks set lab \
  --url https://hooks.example.test/tenkai \
  --secret-env TENKAI_WEBHOOK_SECRET \
  --events apply.succeeded,apply.failed,apply.rolled_back
tenkaictl env webhooks list lab
```

Omit `--events` to subscribe to every apply outcome. HTTPS is required except
for loopback HTTP used in local tests. URLs must not embed credentials.
`tenkai-server` delivers pending events; `tenkaictl apply` only enqueues them.

Clear one URL or every endpoint:

```bash
tenkaictl env webhooks clear lab --url https://hooks.example.test/tenkai
tenkaictl env webhooks clear lab
```

## Events and payload

| Event | When | `alert` |
| --- | --- | --- |
| `apply.succeeded` | A plan step records succeeded | `false` |
| `apply.failed` | A plan step records failed | `false` |
| `apply.rolled_back` | Automatic restore after a failed health/SLO gate | `true` |

Posted JSON (`tenkai.deploy_webhook.v1`) includes environment, product, version,
previous version when known, release id and digest, source revision from signed
release provenance when present, artifact digests, plan id, step id, outcome,
and the first-delivery timestamp. It does not include secrets, command output,
workdir paths, or the per-call deployment attempt id (that identity is minted
from the clock and would duplicate notifications on replay). A rollback event
carries both the rejected version and the restored previous version.

The outbox identity is a digest of the destination URL, plan id, step id, and
event name. Replaying the same terminal step reuses that row; HTTP retries
reuse `X-Tenkai-Idempotency-Key`. The posted `observed_at` is bound on first
delivery from the outbox collection timestamp so a replay does not mint a
second notification.

## Signature

Every POST is HMAC-SHA256 over the exact JSON body, using the secret from
`secret_env`. Headers:

| Header | Value |
| --- | --- |
| `X-Tenkai-Signature` | `sha256=<hex>` |
| `X-Tenkai-Signature-Alg` | `hmac-sha256` |
| `X-Tenkai-Event` | `apply.succeeded`, `apply.failed`, or `apply.rolled_back` |
| `X-Tenkai-Idempotency-Key` | Stable outbox event id |

Receivers must compare the header to a freshly computed HMAC of the raw body
with a constant-time equality check, then honor the idempotency key.

### Sample verifier

```python
import hashlib
import hmac

def verify(secret: bytes, body: bytes, header: str) -> bool:
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"
    return hmac.compare_digest(expected, header)
```

## Delivery status

Failed or timed-out posts increment the durable attempt count, store a
sanitized error (`webhook endpoint unreachable` or the HTTP status), and
schedule bounded exponential backoff. Restarting Tenkai does not drop pending
events. Adapters may see a delivery more than once and must deduplicate by
idempotency key.

## Operational events

Endpoints may also subscribe to operational events. They are listed in the
endpoint's separate `operational` field, so `events` keeps meaning apply
outcomes, and a version that does not know operational events ignores the
field and keeps delivering the apply outcomes. An endpoint receives an
operational event only when `operational` lists it. An endpoint whose
`events` is empty receives every apply outcome, unless it lists operational
events only: then it receives no apply outcome. With `tenkaictl env
webhooks set --events`, apply and operational names may be mixed; each is
stored in its field.

| Event | Scope | Fires when |
| --- | --- | --- |
| `plan.held` | Environment webhooks | A reconcile tick finds the environment's plan paused by a delivery hold. `code` is the hold scope |
| `plan.awaiting_approval` | Environment webhooks | A reconcile tick finds the plan waiting for a signed approval |
| `import.failed` | Environment webhooks | A server-side bundle import is refused. `resource` is the import job id |
| `backup.stale` | Host webhooks | Backup age turns `stale`, `missing` or `unreadable` |
| `clock.drift` | Host webhooks | The clock guard turns `warn` or `refuse` |

Host webhooks are configured with `TENKAI_HOST_WEBHOOKS`, a JSON list of
endpoints with the same shape as environment webhooks:
`[{"url": "...", "secret_env": "...", "operational": ["backup.stale", "clock.drift"]}]`.

Each event fires once per transition. A held plan is announced once, however
many ticks see it held, and again for each new hold: at another scope, or a
hold cleared and set again. A backup that recovers and turns stale again is
announced again. A host announcement the outbox could not take is kept in
`<database>.host-alerts.json` and retried at every check, across restarts,
even if the condition has recovered by then. Servers sharing a database merge
that file under a lock, so an overlapping restart loses no announcement. After a restart, a condition
that is still bad is announced once. A failed import is marked with a file beside its job once announced (the job
file keeps its format); the
server retries unannounced failures every minute, so a crash or a full outbox
only delays it. After a restart, a host condition that is still bad is announced once
more.

The body is `tenkai.operational_event.v1`, with `event`, `environment` (empty
for host events), `resource`, `code` and `observed_at`. It carries
identities and codes only, never a hold reason or an error message. It is
signed and retried exactly like apply outcomes, on its own outbox kind, so a
down sink never blocks reconcile, apply or import.

Delivery status, for apply outcomes and operational events, is at
`GET /v1/environments/{environment}/webhooks/deliveries` and, for host
webhooks, at `GET /v1/webhooks/deliveries`: apply outcomes, then operational
events, each newest recorded first. Each
delivery shows its state (`pending`, `retrying`, `delivered`), attempts, next attempt, delivery
time and the last error.
