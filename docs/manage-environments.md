# Manage environments and maintenance windows

Register environments, describe what they can run, constrain what they accept,
and limit when deployments may start.

## Register, inspect, and retire

```bash
tenkaictl env add prod --description production
tenkaictl env list
tenkaictl env inspect prod
tenkaictl env retire prod --reason "service ended"
```

`env list` shows active environments with subscription and lease summary.
Retired environments leave the list and fleet status while `env inspect <name>`
continues to show their history and retirement reason, actor, and timestamp.
Retirement refuses an active apply lease; first verify the apply has stopped and
use `tenkaictl env unlock <name>`. Repeating retirement preserves the original
evidence. `env inspect <name>` also prints subscriptions, deployed versions,
lease/fencing state, and the latest plan. Latest-plan inspection includes
sanitized lifecycle detail and at most 256 ordered step summaries; executable
digests, work directories, payloads, and bearer tokens are not returned.
Subscriptions, plan steps, and status name an instance. An instance that is
not named is the product. `env subscribe <env> <product>=<channel>
--instance <name>` creates a second copy of that product in the environment;
`--instance` defaults to the product. Instance names are DNS labels of at
most 40 characters and unique in the environment.

`env add --connectivity <class>` also sets the connectivity class.

### Criticality

Environments and products may carry optional criticality (`low`, `medium`,
`high`, `critical`) with an owner and a reason. The declared value is set
through an audited mutation. A signed `tenkai.derived-criticality.v2`
envelope can add a derived value from an external evidence source
([wire format](#derived-criticality-wire-format)). The
effective value is the higher of the two; a stale or missing derived value
is shown and never lowers it.

```bash
tenkaictl env criticality set prod --level critical --owner alice --reason pci
tenkaictl product criticality set api --level high --owner alice --reason payments
tenkaictl criticality import --envelope derived.json --trust-roots criticality-trust.toml
```

`env inspect` and `fleet status` show it when set. Exposure queries sort and
filter by the effective value (`tenkaictl exposure query --min-criticality high`).
An environment-scoped token can declare only its own environment; product
criticality and derived import need fleet management. Unset criticality
behaves as before.

#### Derived criticality wire format

A producer serializes its statement once, signs those bytes, and sends them
as they are. Tenkai checks the signature over the received bytes before it
parses them, so the producer's JSON encoder, key order, and spacing are not
part of the contract. The envelope (`POST /v1/criticality/derived`, the
`--envelope` file, and the bundle entry `criticality/derived.json`) is:

```json
{
  "schema": "tenkai.derived-criticality.v2",
  "key_id": "sha256:<64 lowercase hex>",
  "statement": "<base64 of the statement bytes>",
  "signature": "<base64 Ed25519 signature>"
}
```

- `statement` is the standard base64 alphabet with padding, of the UTF-8
  JSON statement bytes.
- The signed message is the 29 ASCII bytes `TENKAI-DERIVED-CRITICALITY-V2`
  and one NUL byte (`0x00`), then the statement bytes. `signature` is the 64-byte Ed25519
  (RFC 8032) signature over that message, standard base64 with padding.
- `key_id` is `sha256:` and the lowercase hex SHA-256 of the 32-byte public
  key. It must name a signer in the criticality trust roots
  (`TENKAI_CRITICALITY_TRUST_ROOTS`, or `--trust-roots` for an embedded
  import), in the [trust-root format](release-signing.md).
- The envelope has exactly these four fields; any other is refused.

The statement is a JSON object:

| Field | Type | Rule |
| --- | --- | --- |
| `generated_at` | integer | Unix milliseconds, positive, at most 60 s after the import clock and not after a carrying bundle's issued-at |
| `max_age_ms` | integer | positive; the derived value is stale after it |
| `assignments` | array | 1 to 4096 objects, each `kind` and `name` pair once |
| `assignments[].kind` | string | `environment` or `product` |
| `assignments[].name` | string | ASCII letter or digit first, then letters, digits, `.`, `_`, `-`, `+` |
| `assignments[].level` | string | `low`, `medium`, `high`, or `critical` |
| `assignments[].source` | string | required, no control characters |
| `assignments[].reason` | string | optional (empty when omitted), at most 1024 bytes, no control characters |

A key may appear once per object. Fields Tenkai does not know are ignored
and stay covered by the signature, so a producer may add a field that an
older verifier can safely ignore. A field that changes what an assignment
means (for example, an expiry an older verifier would not enforce) needs a
new schema id instead.

To sign without Tenkai, in any language:

```text
bytes     = utf8(json(statement))            # serialize once, keep the bytes
message   = "TENKAI-DERIVED-CRITICALITY-V2" || 0x00 || bytes
signature = ed25519_sign(private_key, message)
envelope  = {schema, key_id, statement: base64(bytes), signature: base64(signature)}
```

Tenkai stores the values it applied (level, source, reason, `generated_at`,
`max_age_ms`, and `key_id`) on the environment or product, not the
envelope. An offline bundle carries the envelope bytes unchanged, so
verifying the bundle again checks the producer's own bytes.

`tenkai.derived-criticality.v1` is deprecated: its signature covered
Tenkai's re-encoding of the parsed statement, which no other encoder can
reproduce. This release still verifies v1 envelopes and bundles made by
earlier releases, never produces them, and `tenkaictl bundle build` refuses
them. A later release removes v1. Releases before 0.7.0 refuse a v2
envelope as malformed. Upgrade every server and every `tenkaictl` that
imports envelopes or bundles first, then switch producers to v2.

### Remote configuration

With `tenkaictl --target remote`, `env add` needs `--reason`. `facts`,
`constraints`, `maintenance`, `webhooks`, `approval-policy` and `criticality`
`set`, `clear` and `remove` need `--generation`, the `lease.generation` that remote
`env inspect` reports (`0` only before the environment's first apply or
change), and `--reason`. They call the
management routes in [management lifecycle](management-lifecycle.md#operations)
and run the same validation as the embedded commands. Every change is
audited with the authenticated actor and the reason. An
environment-scoped token can configure only its own environment and cannot
register environments. The `list` and `show` commands stay embedded; remote
`env inspect` shows the same configuration, including `webhooks` (URL,
`secret_env` and events; never a secret value), `approval_policy`, the
policy file path, and `criticality` when set, so a client can read what it edits (#820).

```bash
tenkaictl --target remote env add edge --connectivity isolated --reason "new site"
tenkaictl --target remote env inspect edge   # read lease.generation, for example 1
tenkaictl --target remote env facts set edge architecture=arm64 --generation 1 --reason inventory
```

For a scripted two-environment walkthrough (list/inspect/status), run:

```bash
./scripts/demo-multi-env.sh
```

## Facts and constraints

Facts describe an environment; constraints decide which releases the planner
may choose for it.

```bash
tenkaictl env facts set prod architecture=arm64
tenkaictl env facts set prod memory_gib=32
tenkaictl env facts set prod gpu_vram_gib=80
tenkaictl env facts list prod
tenkaictl env constraints set prod version_range hello-local 1.0.0..2.0.0
tenkaictl env constraints set prod require_fact architecture arm64
```

Admitted fact keys: `architecture`, `memory_gib`, `accelerator`,
`free_disk_gib`, and the GPU facts `gpu_vendor`, `gpu_family`, `gpu_model`,
`gpu_vram_gib`, `gpu_count`, `gpu_driver_version`, `gpu_runtime`, and
`gpu_runtime_version` (see [model runtime](model-runtime.md#gpu-requirements)),
and the placement facts `host` and `zone` that replica topologies check (see
[manifest](manifest.md#topology)).

## Plan approval policy

An environment may point at a TOML policy that signs `tenkai.plan-approval.v1`
envelopes for matching plans. The property stores a file path, never a private
key. Skip-gates and rollback stay human by default. See
[plan approval](plan-approval.md#unattended-approval-policy).

```bash
tenkaictl env approval-policy set lab /etc/tenkai/lab-approval-policy.toml
tenkaictl env approval-policy show lab
tenkaictl env approval-policy clear lab
```

Remote `show` reads `GET /v1/environments/{environment}/approval-policy`
and prints the effective policy (signer key ids, human rules, TTL). Remote
`set` and `clear` take `--generation` and `--reason`; the path names a file
on the server host. Inspect reports `latest_plan.approval`.

## Post-deploy webhooks

An environment may declare signed HTTPS endpoints that receive terminal apply
outcomes. Tenkai stores the URL and the name of a process variable that holds
the HMAC secret, never the secret itself. Delivery is asynchronous; a down
endpoint does not fail apply. See [post-deploy webhooks](deploy-webhooks.md).

```bash
tenkaictl env webhooks set lab --url https://hooks.example.test/tenkai --secret-env TENKAI_WEBHOOK_SECRET
tenkaictl env webhooks list lab
tenkaictl env webhooks clear lab
```

## Delivery hold

Hold pauses new execution without unsubscribing, recalling, or opening a
maintenance window. The reconciler still plans and reports `held`; `apply`
refuses a held plan and a pull-only runtime receives no work. In-flight
applies finish, and rollback-only plans are never held. `env inspect`,
`env list`, and `status` report the hold.

```bash
tenkaictl env hold prod set --reason "change freeze"
tenkaictl env hold prod show
tenkaictl env hold prod clear
```

A channel hold blocks every environment subscribed to that channel:

```bash
tenkaictl channel hold hello-local stable set --reason "pause stable"
tenkaictl channel hold hello-local stable show
tenkaictl channel hold hello-local stable clear
```

Setting and clearing a hold require the management credential, like promote.
The authenticated principal is recorded as the actor. Every set and clear
appends an immutable audit event; `show` prints the active hold and that
history. Promote, subscribe, and deploy do not touch a hold. Remote
`tenkaictl --target remote` uses the same HTTP routes; environment set,
clear, and failed-target retry require `--generation`.

A failed target stays held until an explicit retry. Remote and embedded
operators plan that retry with `tenkaictl env retry <env> <product> --reason …`.

## Maintenance windows

Recurring windows are configured per environment with an IANA timezone, ISO
weekdays, a local start time, and an elapsed duration. Each window has a name
(`weekday` below). Schedule changes use a governed action so maintenance
permissions can be separated from deployment permissions.

```bash
tenkaictl env maintenance set prod weekday \
  --timezone Europe/Berlin \
  --weekdays mon,tue,wed,thu,fri \
  --start 22:00 \
  --duration-minutes 120
tenkaictl env maintenance list prod
```

Plans can be computed outside a window, but `apply` records them as blocked and
exits nonzero while the window is closed. When a window opens, rerun
`tenkaictl apply <plan-id>`; blocked plans do not resume automatically. Invalid
rules and ambiguous or skipped DST starts fail closed. Once execution starts
inside a window, it may finish after that window closes.

A plan computed while the window is closed is checked against the
certificates the server serves and trusts (listener, client CA, runner CA,
outbound CA) and against trust-root signers that record `not_after`. If one
lapses before the window opens, the plan records it as `credential_runway`
and the plan message names the credential, its expiry and the window's
opening, so it can be renewed first. The check is advisory and runs only on
a server with those sources configured.
`GET /v1/trust/runway` repeats it for every plan still waiting, as of now
([trust posture](run-tenkai-server.md#trust-posture)).

Per-product windows use `tenkaictl product maintenance`; see
[ADR 0016](decisions/0016-same-version-remediation.md).

### Emergency start

An emergency start requires a non-empty reason and records the authenticated
principal through a governed action. Denied actions and actions requiring
out-of-band approval remain blocked.

```bash
tenkaictl apply <plan-id> --emergency-reason "restore critical service"
```

### Repair invalid maintenance configuration

If configuration audit evidence is incomplete or invalid, normal applies fail
closed. After inspecting the incident, quiesce deployment automation, reset the
configuration with `tenkaictl env maintenance repair <env>`, and recreate the
intended windows before allowing applies again. Repair installs an empty
schedule, which permits unrestricted execution until the intended windows are
restored.
