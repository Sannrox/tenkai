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
`secret_env`: that variable, its `_FILE` path, or the secret directory (see
[secret files](environment-variables.md#secret-files)), read again on every
delivery so a rotated secret applies without a restart. Headers:

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
| `trust.expiring` | Host webhooks | The worst certificate status turns `warning`, `critical` or `expired` ([trust posture](run-tenkai-server.md#trust-posture)) |

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

## SMTP digests

Sites whose on-call staff are reachable only through an internal mail relay
can receive operational events as plain-text digests (#725).
`TENKAI_SMTP_SINKS` is a JSON list of sinks:

```json
[{"id": "oncall", "relay": "mail.internal:587",
  "from": "tenkai@site.example", "to": ["oncall@site.example"],
  "operational": ["plan.held", "backup.stale", "clock.drift"],
  "window_seconds": 900,
  "username_secret": "TENKAI_SMTP_USER",
  "password_secret": "TENKAI_SMTP_PASSWORD"}]
```

- **Batching:** each event a sink lists is queued for the end of the current
  window, so the sink gets one message per window listing that window's
  events. Each sink's due lines are claimed in one transaction, so one
  worker sends a whole window and replicas never split it; only a window of
  more than 10,000 events spills into a second message.
- **Deduplication:** an event announced again is not listed twice.
- **Payload:** like webhooks, lines carry identities and codes only.
- **TLS:** STARTTLS is required, trusting `TENKAI_CA_BUNDLE` and the built-in
  roots as other outbound clients do. A relay on loopback may set
  `"starttls": false`.
- **Authentication:** credentials are secret settings named by the sink, read
  through [secret files](environment-variables.md#secret-files), and sent
  with `AUTH PLAIN` after STARTTLS.
- **Failure:** a relay that is down or refuses defers the digest for five
  minutes. It never blocks reconcile, apply or import.
- **Delivery status:** digest lines appear in the delivery status above with
  the URL `smtp:<id>`.
