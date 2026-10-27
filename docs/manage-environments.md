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

`env add --connectivity <class>` also sets the connectivity class.

### Remote configuration

With `tenkaictl --target remote`, `env add` needs `--reason`. `facts`,
`constraints`, `maintenance`, `webhooks` and `approval-policy` `set`,
`clear` and `remove` need `--generation` (the current environment lease
generation, or `0` when no lease is held) and `--reason`. They call the
management routes in [management lifecycle](management-lifecycle.md#operations)
and run the same validation as the embedded commands. Every change is
audited with the authenticated actor and the reason. An
environment-scoped token can configure only its own environment and cannot
register environments. The `list` and `show` commands stay embedded; remote
`env inspect` shows the same configuration.

```bash
tenkaictl --target remote env add edge --connectivity isolated --reason "new site"
tenkaictl --target remote env facts set edge architecture=arm64 --generation 0 --reason inventory
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
outbound CA). If one lapses before the window opens, the plan records it as
`credential_runway` and the plan message names the certificate, its expiry
and the window's opening, so it can be renewed first. The check is advisory
and runs only on a server with those certificates configured.

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
