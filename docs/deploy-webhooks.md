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
