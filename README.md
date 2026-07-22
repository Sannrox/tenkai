# tenkai

tenkai currently supports Unix deployment hosts (Linux and macOS).

`tenkai` (展開, "deployment / unfolding") is a local-first, constraint-based
delivery control plane in the spirit of Palantir Apollo, backed by
[sekai-chisei](https://github.com/Sannrox/sekai-chisei).

You don't script deployments. You **publish** immutable releases, **promote**
them into channels, and **subscribe** environments to channels. `tenkaictl`
computes the plan that converges an environment on its channels, gates it on
chisei eval runs, executes it, health-probes it, and rolls back automatically
on failure. Every product, release, channel, plan, and deployment is a typed
object in the sekai graph — the full delivery history is queryable and audited.

This is the **local v0**: one machine, the CLI plays catalog + planner +
executor. The seams (immutable releases, channels, gates, rollback, the graph
ontology) are the ones the fleet version grows along — see [DESIGN.md](DESIGN.md).

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

## The manifest (`tenkai.toml`)

```toml
[product]
name = "hello-local"
version = "0.1.0"

[deploy]
executor = "local-shell"          # optional; local-shell is the default
workdir = "."                    # relative to the manifest
install = "docker compose up -d" # any command; activates this release
uninstall = "docker compose down"
observe = "./observe-version"       # stdout = installed semver; exit 3 = confirmed absent
health = "curl -sf localhost:8080/healthz"  # exit 0 = healthy; failure rolls back
inputs = ["compose.yaml", "observe-version"] # immutable files/directories used by these commands
timeout_seconds = 600              # maximum duration of each deployment command

[gate]
eval_suite = "my-suite"          # chisei eval suite; latest run must fully pass
```

Releases are immutable: re-publishing the same version with different manifest
content or different declared deploy inputs is rejected — bump
`product.version`. Runtime state must live outside declared `inputs`.
Manifests without `inputs` retain legacy in-place workdir execution; declare
all command inputs to enable immutable snapshots and per-environment isolation.

## Gates

If a release declares `gate.eval_suite`, `apply` blocks unless the suite's
latest eval run in chisei exists and every current case passed (fail closed).
The run's `config_ref` must match the content-bound reference shown in the
blocked-plan detail; it covers the manifest, immutable deploy inputs, and the
current suite definition, so stale evidence cannot authorize changed content.
`--skip-gates` bypasses, and the bypass is recorded in the graph like any
other apply.

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

## Ontology

Everything lives in the sekai graph under namespace `tenkai`:

`tenkai.product` ← `release_of` — `tenkai.release` ← `promotes` — `tenkai.channel`
← `subscribes` — `tenkai.environment`; each apply writes a `tenkai.plan` and
per-step `tenkai.deployment` records linked to the release, environment, and
plan. Desired channel state, last-applied state (`deployed.<product>`), and
executor-reported state (`observed.<product>`) remain separate on the
environment object. `plan` and `status` refresh observations and report drift.

## Status

v0 walking skeleton. Working: publish/promote/subscribe, plan/apply/status,
eval gates, health probes, auto-rollback, deliberate rollback, full graph
audit trail. Not yet: multiple environments beyond registration, maintenance
windows, version constraints, signed releases, agents, disconnected
environments — see [DESIGN.md](DESIGN.md) for the roadmap.

Implementation work is split into one-task plans under
[`docs/plans/`](docs/plans/README.md). The
[`execution roadmap`](docs/plans/ROADMAP.md) shows dependencies, parallel
waves, critical paths, and external sekai-chisei gates.
