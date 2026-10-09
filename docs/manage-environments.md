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
tenkaictl env facts list prod
tenkaictl env constraints set prod version_range hello-local 1.0.0..2.0.0
tenkaictl env constraints set prod require_fact architecture arm64
```

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
history. Promote, subscribe, and deploy do not touch a hold. A hold is an
embedded operation; the v1 remote API does not expose it.

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
