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
`tenkaictl env history <env> [--product <instance>] [--limit N]` lists recorded
deployment attempts newest first: time, instance, from, to, action, status,
plan id, and a one-line cause `summary` (or the stored `detail` on older
records). `--output json-v1` prints that page as JSON, including the full
structured `cause` and `restore` fields when present. `env inspect` includes
`latest_failures` (the latest failed or rolled back attempt per instance) and
points at `env history` for the rest. `status` shows the cause summary when
one was recorded and still cuts the held-target `detail` to 1,000 characters.
Remote mode reads `GET /v1/environments/{environment}/history`.
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

After reconcile, `env inspect` and `tenkaictl status` report out-of-band
target changes as `modified outside Tenkai` per instance when the row would
otherwise be `current`. In-process Kubernetes compares the applied pod
template with the live object. Host file and unit digest comparison is a
library helper; the unprivileged server does not periodically read dest files.
Kubernetes-managed fields (replica status, controller annotations, defaulted
image pull policy) and secret/env values are not compared. Drift never creates
a plan, never restarts, and never blocks reconcile. A server or adapter that
does not compute fingerprints omits the field (`unknown`), and does not
replace `current`. The next apply either clears the stored report or names the
fields that remain after the following reconcile.

A release may declare `[config]` overlay keys (type, required, default) and
secret names. `env overlay set` refuses a key or type the subscribed channel
head does not declare. Planning refuses a candidate whose schema the
environment overlays do not satisfy. `env inspect` shows defaults, overlays,
the digest, and secret names only. A release that omits `[config]` behaves as
today.

### Sealed secrets

A value for a declared secret can be set sealed (ADR 0045). The client seals
it to the environment's pinned runtime recipient keys; the server stores only
the ciphertext and one wrap per recipient, and cannot open it.

```sh
printf '%s' "$value" | tenkaictl --target remote secret set prod api db/password \
  --generation 7 --reason "rotate db password"
tenkaictl --target remote secret list prod
tenkaictl --target remote secret delete prod api db/password --generation 8 --reason "moved"
```

- `secret set` reads the exact bytes of standard input, so use `printf '%s'`
  rather than `echo` unless the value ends in a newline. It never takes the
  value from an argument or an environment variable, and refuses a terminal.
- Every offered recipient key must be pinned first
  (`secret recipients`, `secret trust`); an unpinned key is refused by
  fingerprint.
- The secret name must be one the instance's subscribed release declares.
- `secret list` shows instance, `secret/key`, the sealed digest, who set it,
  when, and how many recipients can open it. No command returns a value.
- Deleting a key of a secret the release declares is refused, naming the
  release, unless `--present-in-target` states the key exists in the target
  by other means.

A change is not written to the target. It changes the instance's
configuration digest, which covers each ciphertext digest but not the wraps,
so the next plan carries the same-version Restart an overlay change does,
and only for instances that read the key. Every non-remove step for the
instance names its sealed keys and digests (`sealed` in the plan), so they
are covered by the plan digest and its approval; a plan is stale, and not
executed, once those digests change. Adding a wrap changes nothing.
Because every step for such an instance is a sealed step, a runtime refuses
it without a local approval policy (`TENKAI_RUNTIME_APPROVAL_POLICY`,
[runtime protocol](runtime-protocol-v1.md)) and waits for the plan's
approvals. Install that policy on every runtime of the environment before
the first `secret set`; deleting the last sealed key of an instance lifts
the requirement. Changes are generation-fenced and audited like other environment
configuration (`PUT`/`DELETE /v1/environments/{environment}/sealed-secrets`,
`GET` to list).

#### Adding a recipient

A runtime enrolled after a value was sealed cannot open it. Re-wrap the
environment's values for its key through an approved plan (ADR 0045 §5):

```sh
tenkaictl --target remote secret recipients prod
tenkaictl --target remote secret rewrap prod --recipient sha256:<hex> --generation 9
```

- The recipient must be an unrevoked runtime key of the environment. The
  server builds one re-wrap step per instance with sealed values, pinned to
  its deployed release. An instance with nothing deployed yet is named in
  the result and re-wrapped by a later request.
- The plan needs signed approvals like any other, and the runtime checks
  them against its local approval policy. The approvals cover the
  recipient's fingerprint, so a server cannot point them at another key.
- A runtime that can open the values runs it: it opens each value, wraps the
  data key for the named key, and returns only the wraps. A runtime that
  cannot open them, such as the new one, fails the step and names why; apply
  the plan from one that can. The server keeps a wrap only for the approved
  recipient and for a value whose digest is unchanged. Ciphertext,
  configuration digest and deployments do not change.
- Revoking a runtime (`runtime revoke`) drops its wraps from every value. A
  value left with no wrap is listed in the revocation result, and every
  plan that writes it warns that no recipient can open it: set it again.
  Rotating a runtime's sealing key is enrolling a new runtime, re-wrapping
  for it, and revoking the old one.

#### Recovery key

Losing every runtime loses every sealed value, unless the environment has an
offline recovery key (ADR 0045 §7). Generate it on a machine that is not a
runtime, keep the private key offline, and record its public half:

```sh
tenkaictl secret recovery-key generate ./prod-recovery.pem
tenkaictl --target remote secret recovery-key set prod <public-key> --generation 10 --reason "recovery key"
tenkaictl --target remote secret recipients prod
tenkaictl --target remote secret rewrap prod --recipient <recovery-fingerprint> --generation 11
```

- The server offers the recovery key with the runtime keys (`recovery` in
  `secret recipients`). Pin it like they are; `secret set` then seals every
  new value to it too.
- A value sealed before the key was set has no wrap for it. `secret list`
  shows `recovery=no` for it, and the re-wrap above adds one. Without a key,
  `secret list` and `env inspect` (`sealed_recovery_warning`) warn.
- Replacing the key drops the old key's wraps from every value.

After losing every runtime, enroll a new one, pin its key, and recover on the
machine with the private key:

```sh
tenkaictl --target remote secret recover prod --key ./prod-recovery.pem \
  --recipient sha256:<new-runtime> --generation 12
```

The client reads each value's ciphertext and wraps (`GET` with
`?sealed=true`, which needs management access), opens its data key with the
recovery key, and wraps it for the new runtime. It submits only those wraps,
as a re-wrap request for the new runtime. The plan needs signed approvals as
any re-wrap does. Only the new runtime is handed it; it opens each value through its
recovered wrap, and returns a wrap of its own; until then nothing changes. A
value without a recovery wrap refuses the request by name: set it again first.

Servers that predate sealed secrets ignore the stored records and never plan
them. Set the first sealed value only once every server and runtime of the
environment understands them: an older server computes the configuration
digest without them and would plan its own restart.

Only an environment runtime in built-in mode writes a value to the target,
and only for `helm` releases: an immutable Secret named
`<instance>-<secret>-<digest8>` in the release's namespace, passed to the
chart as `tenkai.secrets.<secret>.name`
([built-in executors](run-tenkai-server.md)). Host targets follow (#1125).

#### Identity issuer

An environment has at most one workload identity issuer (ADR 0046 §2). Its
key exists unsealed only in the environment's runtimes; the server keeps its
CA certificate and the key sealed to the runtimes and the recovery key.
Creating and rotating it takes two steps:

```sh
tenkaictl --target remote identity-issuer prepare prod --generation 13
tenkaictl --target remote env inspect prod
tenkaictl --target remote identity-issuer plan prod --generation 13
tenkaictl --target remote identity-issuer rewrap prod --recipient sha256:<hex> --generation 14
```

- `prepare` asks for a candidate of the next generation. A runtime that
  names `workload_identity` generates it on its next poll, seals it to its
  own key only, and uploads its fingerprint, certificate and sealed key.
  `env inspect` (`identity_issuer`) and `status` show the candidate.
- `plan` builds one step that names the candidate's fingerprint. Approve it
  like any plan. The runtime that runs it refuses a key with any other
  fingerprint, and the server records the issuer only if its generation is
  the next one, so a stale plan fails and the issuer stays.
- `rewrap` wraps the issuer key for one more recipient: another runtime's
  key or the recovery key. Run it after activation; until then only the
  generating runtime can open the issuer. A runtime enrolled later can use
  the issuer only after that plan is approved. It is separate from
  `secret rewrap`, since the runtime that opens the issuer need not open the
  sealed values.
- Revoking a runtime drops its wrap. An issuer with no wrap left is lost:
  `status` says so, and a new one is prepared, planned and rotated in.
  An issuer plan whose key no unrevoked runtime holds, or one made before
  the issuer rotated past it, is blocked when the next runtime polls, so it
  does not hold up later plans. Plan it again.
- An environment without a separate runtime cannot issue workload
  certificates. The server never holds the issuing key, so it refuses plans
  that activate an issuer or issue a certificate, and the refusal says to
  enroll an environment runtime. There is no setting that lets the server's
  host issue them ([ADR 0046](decisions/0046-workload-identity-and-peer-policy.md) §8).

A release that declares [`[deploy.identity]`](manifest.md#workload-identity)
needs a current issuer: planning it without one fails and names
`identity-issuer prepare`. Each install, upgrade, rollback and restart step
of it grants its certificate, and the runtime that runs the step issues it,
valid for 24 hours. A step also grants the certificate of the release it
restores on failure.

The runtime renews a `reload = "runtime"` certificate on `helm` or `host` itself once
two thirds of its lifetime have passed, with no plan or approval
([ADR 0046](decisions/0046-workload-identity-and-peer-policy.md) §3). It
re-issues exactly the grant the old certificate proves, with a fresh key,
from the issuer it last verified at apply. A certificate from an older
issuer generation is not renewed: it needs a step after `identity-issuer
rewrap`.

A `reload = "restart"` certificate on `helm` renews the same way, then
restarts the release's Deployments, StatefulSets and DaemonSets, which
roll out under their own update strategy. It falls due up to two hours
later, by an amount fixed per environment, so replicas of one topology in
different environments do not restart together. A crash between the new
certificate and the restart finishes the restart on the next pass without
issuing again. Restart-reload certificates on `host` are not renewed yet;
apply a step before they expire. A host certificate installed by an applier older than
this release is renewed once a step installs it again.

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

## Dependency bindings

Several providers of one contract need a binding that says which provider
instance satisfies which contract for which dependent instance. One matching
provider satisfies without a binding. Tenkai never picks among several.

```bash
tenkaictl env bind prod app database=db-a
tenkaictl env unbind prod app database
```

Bindings are environment configuration: remote calls take `--generation` and
`--reason` like facts. Binding to an instance that does not provide a
satisfying version is refused. Unbinding a required contract on an installed
dependent is refused. The dependency document names the provider instance;
changing a binding re-renders the dependent.

A binding is also the only peer authorization
([ADR 0046](decisions/0046-workload-identity-and-peer-policy.md) §5). When
the dependent or the provider holds a
[workload certificate](manifest.md#workload-identity), its step's grant names
the other side, and the document carries it: in `servers` the provider
identity it accepts for each contract it requires, and in `callers` the
identities allowed to call each contract it provides. A unique provider without a binding counts
as bound; an instance with no edge is never a caller. The runtime refuses a
document whose peers differ from the approved step's, so a server cannot add
a peer. A provider admits a new caller before that caller deploys. A caller
that is rebound, removed, or upgraded away keeps its old provider's grant
for the rest of that plan, so it is never refused while it moves; the next
plan withdraws it. Host releases are not re-rendered for a binding change;
one picks up its peers on its next deploy, and its old provider keeps
admitting it until then. A rollback or restore never withdraws a caller.
Any plan with a step that needs a provider that does not admit it yet, and
is not admitted by an earlier step of that plan, is refused. This catches a
rollback, restart or migration, which changes only its own instance, and a
host provider, which is not re-rendered; deploy the provider with the
binding first. `status` and
`env dependencies` mark
such an edge `granted`. The product enforces it: Tenkai cannot see whether
it checks the peer.

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
