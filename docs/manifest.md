# The manifest (`tenkai.toml`)

A manifest describes one immutable release of one product: what to install,
how to check its health, and which gates it must pass. Publish it with
`tenkaictl publish <manifest>`.

```toml
[product]
name = "hello-local"
version = "0.1.0"

[deploy]
workdir = "."                    # relative to the manifest
install = "docker compose up -d" # any command; activates this release
uninstall = "docker compose down"
health = "curl -sf localhost:8080/healthz"  # exit 0 = healthy; failure rolls back
inputs = ["compose.yaml"]          # immutable files/directories used by these commands

[gate]
eval_suite = "my-suite"          # chisei eval suite; latest run must fully pass
bake_window_seconds = 60         # optional SLO bake window; first breach halts
on_fail = "halt"                 # or "rollback" to the previously signed pin

[[gate.slo]]                     # optional; omit to keep today's apply behavior
name = "error_rate"
query = "sum(rate(http_requests_total{status=~\"5..\"}[5m])) / sum(rate(http_requests_total[5m]))"
op = "lte"
threshold = 0.01

[delivery]
has_migration = false            # schema or data migration; auto policy stays human
changes_identity_config = false  # identity-provider realm/client change; same
```

This example shows every common field. The minimal working manifest used by the
quickstart is [`examples/hello-local/tenkai.toml`](../examples/hello-local/tenkai.toml).
Deploy commands run with a cleared environment; see
[environment variables](environment-variables.md#set-by-tenkai-for-deploy-commands)
for what they receive.

## Delivery signals

Optional `[delivery]` flags are part of the signed manifest. Both default to
`false`. Changing them for an already-published version is rejected; bump
`product.version`. Unattended auto approval always requires a human when
either flag is true; see [plan approval](plan-approval.md#unattended-approval-policy).

## Immutability

Releases are immutable: re-publishing the same version with different manifest
content or different declared deploy inputs is rejected — bump
`product.version`. Runtime state must live outside declared `inputs`.

## Signing

Release publication fails closed unless `--signature` and `--trust-roots` are
provided. Local development can opt into `--allow-unsigned-development`.
Inspect stored trust evidence or reverify signed content against current trust
roots with:

```bash
tenkaictl release inspect hello-local@0.1.0
tenkaictl release verify hello-local@0.1.0 \
  --trust-roots /etc/tenkai/release-trust.toml
```

The detached envelope and trust-root formats are documented in
[release signing](release-signing.md). Executing a plan separately requires a
signed approval bound to the exact plan and environment; see
[plan approval](plan-approval.md).

## Software compatibility

Software releases can declare a versioned `[compatibility]` profile with immutable
component pins, required and provided contracts, runtime capabilities, facts, and
schema bounds. The profile is signed with the manifest. Planning, apply, restart,
and rollback check fresh environment-scoped evidence before mutation;
`--skip-gates` does not bypass these checks. See
[software compatibility preflight](software-compatibility.md) for the contract,
observation format, and CLI/API commands.

## Topology

A release can declare its replicas. A replica is an environment, and a
topology names the environments that each run one replica and the placement
fact they must not share:

```toml
[topology]
name = "ledger-ha"
environments = ["ledger-a", "ledger-b", "ledger-c"]
anti_affinity = "host"   # or "zone"
```

The facts are the environments' `host` and `zone` facts, set by the operator
(`tenkaictl env facts set ledger-a host node-1`) or reported by an environment
runtime that knows its node. They are not probed: a container's host name is not
the machine it runs on, so a replica without the fact is refused, not guessed. Planning the release for a replica is refused while two
replicas share the fact (`replicas ledger-a and ledger-c both have host=h1`),
while a replica has not reported it, or for an environment that is not one of
the replicas. Apply checks again before it changes anything, for the release
being deployed and the one a failure would restore, and runtime delivery checks
before it hands out new work, so a stored plan cannot outlive a placement
change. A topology needs at least two distinct replicas. Releases without
a `[topology]` plan as before.

`min_available` (optional, at least 1 and fewer than the replicas) keeps a
minimum of replicas serving during a rolling wave. Before the wave runs a plan
that changes a replica that is serving (its `deployment_health.<product>`
reads `healthy`), at least that many of the other replicas must be healthy too,
and a replica with a plan left running (a run in progress, or one a crash
interrupted before it recorded an outcome) does not count;
otherwise it refuses before executing, naming the replicas that are not, and a
later `advance` retries once they recover. The check and the run hold the
topology's lease, so two waves cannot take two of its replicas down at once;
the second is told to retry. Rollback runs under the same guard, applying the
topology of each release the plan deploys or would restore on failure as well
as the wave's, and every such release's minimum. A replica
whose plan changes nothing is not held. The topology lease, like the wave lease,
lasts two hours and is refreshed with the environment apply fence while a
plan runs, so an execution longer than that stays exclusive; a lost lease
stops the run before its next mutation (#834). Upgrading a replica that is not
serving takes nothing down, so a first install and the repair of a failed
replica proceed. This can slow upgrades by design.

## Failover drill

`tenkaictl topology drill <release> <replica> --signing-key <seed> --out <file>`
takes one serving replica out of service on explicit request, checks that
`min_available` still holds and the remaining replicas stay healthy, restores
the replica, and writes signed evidence of the loss, the measured recovery,
and the restore. Out of service is Tenkai's serving signal
(`deployment_health.<product>`), the same one a rolling wave reads; remaining
replicas staying healthy is the traffic observation. A drill that would leave
fewer than `min_available` replicas healthy is refused before anything is
taken down. The outage and the previous health are written together, so a
crash mid-drill leaves a restartable record, including the apply-lease
token; the next drill releases that leftover lease, restores the replica
only while it is still out of service, then starts. The
drill holds the same topology lease as a rolling wave, so it cannot run
while a wave is already changing a replica of that topology. It holds the
replica's apply lease while it changes `deployment_health`, so a concurrent
apply cannot overwrite the outage.
It records the latest evidence on the drilled environment. It does not run
unless requested.

## Gates

If a release declares `gate.eval_suite`, `apply` blocks unless the suite's
latest eval run in chisei exists and every current case passed (fail closed).
The run's `config_ref` must match the content-bound reference shown in the
blocked-plan detail; it covers the manifest, immutable deploy inputs, and the
current suite definition, so stale evidence cannot authorize changed content.
`--skip-gates` is the current v0 break-glass action, and the bypass is recorded
on the Tenkai plan and audit record like any other apply. Under the standalone
architecture, a bypass must carry separately authorized, auditable override
evidence; inability to authorize the override fails closed. Migrated plans
preserve their original bypass evidence and version rather than gaining
implicit authorization.

An embedded apply with `[gate].eval_suite` fails closed locally unless a remote
provider host is explicitly configured; ungated solo deploys never open a
network connection. The evidence format is in
[evaluation gate evidence](evaluation-gate-evidence.md).

Optional `[[gate.slo]]` queries are evaluated after activation succeeds and
before the step is recorded as succeeded, against a Prometheus-compatible
instant source.
A failing sample inside `bake_window_seconds` halts the rollout, or restores
the plan's previously signed pin when `on_fail = "rollback"`. See
[health and SLO gate evidence](health-gate-evidence.md).

## Product kinds

Products are `software` by default (`product.kind`). Other kinds reuse the same publish, promote,
plan, apply, and rollback path:

| Kind | Page |
| --- | --- |
| `routing_config` | [below](#routing-configuration-products) |
| `model_runtime` | [model runtime](model-runtime.md) |
| `policy_bundle`, `eval_suite`, `agent_definition`, `prompt_package` | [staged products](staged-products.md) |
| `workshop_module` | [workshop modules](workshop-modules.md) |
| `worker_pool` | [worker pools](worker-pool.md) |

The portable subset other tools can emit is the
[delivery manifest profile](delivery-manifest-profile.md).

### Routing-configuration products

Tenkai can deliver a versioned model-routing document without sekai-chisei.
The manifest declares `product.kind = "routing_config"`, a JSON configuration,
and the providers admitted by that release:

```toml
[product]
name = "model-routing"
version = "1.0.0"
kind = "routing_config"

[routing]
config = "routing.json"
allowed_providers = ["local"]
```

The JSON contract is versioned and rejects unknown fields, invalid references,
duplicate routes, unsupported providers, and invalid weights before mutation.
The local executor publishes atomically, observes the resulting digest, and
uses the normal pinned-release plan path for rollback. See
[`examples/routing-local`](../examples/routing-local) and
[ADR 0002](decisions/0002-tenkai-owned-routing-configuration.md).

sekai-chisei may supply policy, evaluation, provenance, or an explicitly
configured adapter, but it is not required for standalone routing delivery and
does not own release, plan, apply, rollback, or recovery state.
