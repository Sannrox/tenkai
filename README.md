# tenkai

`tenkai` (展開, "deployment / unfolding") is a local-first, constraint-based
delivery control plane with optional governance, evaluation, and graph
integration through [sekai-chisei](https://github.com/Sannrox/sekai-chisei).

You don't script deployments. You **publish** immutable releases, **promote**
them into channels, and **subscribe** environments to channels. `tenkaictl`
computes the plan that converges an environment on its channels, gates it on
chisei eval runs, executes it, health-probes it, and rolls back automatically
on failure. The accepted architecture makes Tenkai the operational owner and
uses a sekai projection for lineage and audit; current v0 still uses sekai as
its operational store until that migration is implemented.

This is the **local v0**: one machine, the CLI plays catalog + planner +
executor. Embedded and future server operation share one application core. The
durable boundary and service-evolution rules are recorded in
[ADR 0001](docs/decisions/0001-standalone-core-and-service-evolution.md); see
[DESIGN.md](DESIGN.md) for the roadmap.

## Quickstart

Run a sekai-chisei server in one terminal:

```bash
cd ../sekai-chisei && SEKAI_INSECURE=1 cargo run --bin sekai-chisei
```

Then:

```bash
cargo build

# register the tenkai schema in sekai + create the `local` environment
./target/debug/tenkaictl init

# publish an immutable release and promote it to a channel
./target/debug/tenkaictl publish examples/hello-local/tenkai.toml
./target/debug/tenkaictl promote hello-local@0.1.0 stable

# subscribe this machine and converge
./target/debug/tenkaictl env subscribe local hello-local=stable
./target/debug/tenkaictl plan --env local
./target/debug/tenkaictl apply <plan-id-from-previous-command>
./target/debug/tenkaictl status
```

Publish a new version and `apply` again to upgrade. If the health probe of a
new release fails, the previous release is restored automatically. Use
`tenkaictl rollback <product>` to return to the previously deployed version.
If failed cleanup leaves deployment state unknown, reconcile the external
target manually, then run `tenkaictl env reconcile <env> <product>` after
cleanup or add `--deployed <version>` to record the verified live version.

Environment execution uses short-lived, generation-fenced Sekai leases. An
expired lease is taken over atomically; a paused older controller cannot
refresh or release the replacement generation and revalidates ownership before
each deployment step. A local supervisor holds the process fence while mutation
commands receive `TENKAI_FENCING_GENERATION`; controller death closes its
control pipe, terminates the complete command group, and releases the fence
before replacement work starts. Legacy object-only leases are never taken over
automatically: stop the old controller and its children, then use
`tenkaictl env unlock <environment>` as the explicit compatibility fallback.

## The manifest (`tenkai.toml`)

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
```

Releases are immutable: re-publishing the same version with different manifest
content or different declared deploy inputs is rejected — bump
`product.version`. Runtime state must live outside declared `inputs`.

## Gates

If a release declares `gate.eval_suite`, `apply` blocks unless the suite's
latest eval run in chisei exists and every current case passed (fail closed).
The run's `config_ref` must match the content-bound reference shown in the
blocked-plan detail; it covers the manifest, immutable deploy inputs, and the
current suite definition, so stale evidence cannot authorize changed content.
`--skip-gates` is the current v0 break-glass action, and the bypass is recorded
in the graph like any other apply. Under the standalone architecture, a bypass
must carry separately authorized, auditable override evidence; inability to
authorize the override fails closed. Migrated plans preserve their original
bypass evidence and version rather than gaining implicit authorization.

## Maintenance windows

Recurring windows are configured per environment with an IANA timezone, ISO
weekdays, a local start time, and an elapsed duration. Schedule changes use a
governed action so maintenance permissions can be separated from deployment
permissions.

```bash
tenkaictl env add prod --description production
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

An emergency start requires a non-empty reason and records the authenticated
principal through a governed action. Denied actions and actions requiring
out-of-band approval remain blocked.

If configuration audit evidence is incomplete or invalid, normal applies fail
closed. After inspecting the incident, quiesce deployment automation, reset the
configuration with `tenkaictl env maintenance repair <env>`, and recreate the
intended windows before allowing applies again. Repair installs an empty
schedule, which permits unrestricted execution until the intended windows are
restored.

```bash
tenkaictl apply <plan-id> --emergency-reason "restore critical service"
```

## Deploying from GitHub

GitHub is the artifact source; tenkai is the local delivery plane. The
pattern (sekai-chisei itself is the first product using it):

1. **The product repo owns its manifest** — e.g. `deploy/tenkai.toml` in
   sekai-chisei, pinning the container image tag that matches
   `product.version`. Keep its deploy commands self-contained (no repo
   checkout needed).
2. **A release workflow publishes the image** — on tag `v*`, GitHub Actions
   builds and pushes `ghcr.io/<owner>/<repo>:<version>`.
3. **Publish the manifest straight from the tag** — no checkout required:

```bash
gh api "repos/Sannrox/sekai-chisei/contents/deploy/tenkai.toml?ref=v0.2.0" \
  --jq .content | base64 -d | tenkaictl publish -
tenkaictl promote sekai-chisei@0.2.0 stable
tenkaictl plan --env local
tenkaictl apply <plan-id>
```

A new tag on GitHub becomes: publish → promote → `apply`, with the same
gates, health probes, and rollback as any other product. Container executors
are just shell commands in the manifest — Apple `container` and Docker both
work.

The instance tenkai deploys should be a separate *workload* instance
(different ports/data) from the control-plane instance tenkai talks to — the
control plane can't safely restart its own backend mid-apply.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `TENKAI_SEKAI_URL` | `http://127.0.0.1:$GRPC_PORT` | sekai-chisei gRPC endpoint |
| `GRPC_PORT` | `50051` | Port used for the default URL |
| `SEKAI_AUTH_TOKEN` | unset | Bearer token, when the server requires auth |
| `TENKAI_PRINCIPAL` | `tenkai` | Caller identity (`x-principal`) |
| `TENKAI_STATE_DIR` | `<workdir-parent>/.tenkai-state` | Immutable deploy-input snapshots and per-environment runtime directories; must be outside the source workdir |
| `TENKAI_EXECUTOR_GUARD` | installed sibling binary | Explicit path to `tenkai-executor-guard` for applications embedding the Tenkai library |

## Ontology

The current v0 authoritatively encodes domain objects in the sekai graph under
namespace `tenkai`:

`tenkai.product` ← `release_of` — `tenkai.release` ← `promotes` — `tenkai.channel`
← `subscribes` — `tenkai.environment`; each apply writes a `tenkai.plan` and
per-step `tenkai.deployment` records linked to the release, environment, and
plan. Current v0 state lives on the environment object (`deployed.<product>`).
The accepted standalone architecture will move operational authority to
Tenkai-owned persistence while retaining this graph as an optional projection;
that persistence migration is not implemented in v0.

## Status

v0 walking skeleton. Working: publish/promote/subscribe, plan/apply/status,
eval gates, health probes, auto-rollback, deliberate rollback, recurring
maintenance windows, and a full graph audit trail. Not yet: multiple
environments beyond registration, version constraints, signed releases,
environment runtimes, disconnected environments — see [DESIGN.md](DESIGN.md)
for the roadmap.

Active implementation work and dependencies are tracked in GitHub Issues.

## Recorded rollback replay

The deterministic replay capture runs a healthy deployment followed by a
deliberately unhealthy upgrade, records Tenkai's automatic rollback, and asks
`sekaictl replay export` for a static JSON bundle rooted at the incident plan:

```sh
./scripts/capture-rollback-replay.sh
```

By default it expects `../sekai-chisei`, uses an isolated temporary database,
and writes `artifacts/replay/rollback-incident.json`. Override the repository
with `SEKAI_CHISEI_DIR` or the destination with `REPLAY_OUTPUT_DIR`.
