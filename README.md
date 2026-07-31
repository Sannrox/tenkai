# tenkai

`tenkai` (展開, "deployment / unfolding") is a local-first, constraint-based
delivery control plane with optional governance, evaluation, and graph
integration through [sekai-chisei](https://github.com/Sannrox/sekai-chisei).

You don't script deployments. You **publish** immutable releases, **promote**
them into channels, and **subscribe** environments to channels. `tenkaictl`
computes the plan that converges an environment on its channels, executes it,
health-probes it, and rolls back automatically on failure. Optional governance
providers can add evaluation gates; Tenkai remains the operational owner.

The default **embedded mode** runs the application core, SQLite store, Catalog,
and executor through one `tenkaictl` binary. It opens no network connection and
requires no database or provider service. Embedded and server operation share
the same application core. The
durable boundary and service-evolution rules are recorded in
[ADR 0001](docs/decisions/0001-standalone-core-and-service-evolution.md); see
[DESIGN.md](DESIGN.md) for the roadmap.
The versioned Catalog application port, transport conformance requirements,
cache rules, and failure semantics are documented in
[the Catalog contract](docs/catalog-contract.md).
Authenticated local integration demos may opt into the disabled-by-default
[development fixture contract](docs/development-fixtures.md); it creates only
tenant-scoped, non-executable projections and is not a production mutation API.
Disconnected environments use bounded self-verifying archives and signed,
replay-safe receipts documented in
[the offline bundle contract](docs/offline-bundles.md).
Typed local adapters can request the bounded
[machine-readable command result contract](docs/command-results.md) with
`--output json-v1`.
Publication can also retain [registered immutable provenance
envelopes](docs/release-provenance.md) without accepting subject payloads or
granting external evidence delivery authority.

## Quickstart

```bash
cargo build --bin tenkaictl

# initialize .tenkai-state/tenkai.db and create the local environment
./target/debug/tenkaictl init

# publish an immutable release and promote it to a channel
./target/debug/tenkaictl publish examples/hello-local/tenkai.toml \
  --allow-unsigned-development
./target/debug/tenkaictl promote hello-local@0.1.0 stable

# subscribe this machine and converge
./target/debug/tenkaictl env subscribe local hello-local=stable
./target/debug/tenkaictl plan --env local
./target/debug/tenkaictl apply <plan-id-from-previous-command> \
  --allow-unapproved-development \
  --development-reason "local quickstart"
./target/debug/tenkaictl status
./target/debug/tenkaictl inspect
```

Publish a new version and `apply` again to upgrade. If the health probe of a
new release fails, the previous release is restored automatically. Use
`tenkaictl rollback <product>` to return to the previously deployed version.
If failed cleanup leaves deployment state unknown, reconcile the external
target manually, then run `tenkaictl env reconcile <env> <product>` after
cleanup or add `--deployed <version>` to record the verified live version.

Environment execution uses short-lived, generation-fenced Tenkai leases. An
expired lease is taken over atomically; a paused older controller cannot
refresh or release the replacement generation and revalidates ownership before
each deployment step. A local supervisor holds the process fence while mutation
commands receive `TENKAI_FENCING_GENERATION`; controller death closes its
control pipe, terminates the complete command group, and releases the fence
before replacement work starts. Legacy object-only leases are never taken over
automatically: stop the old controller and its children, then use
`tenkaictl env unlock <environment>` as the explicit compatibility fallback.

## Local dogfood (minikube, no remote server)

The file-based quickstart above uses shell install commands. To exercise the
**Kubernetes software executor** entirely on a laptop (embedded SQLite, no
`tenkai-server`, no cloud):

```bash
# once: brew install minikube && minikube start --driver=docker
export TENKAI_SOFTWARE_EXECUTOR=kubernetes
./scripts/dogfood-minikube.sh
kubectl -n local get deploy,pods

# Signed multi-env (local + stage) with tenkaictl dev signing:
# TENKAI_DOGFOOD_MODE=signed-multi-env ./scripts/dogfood-minikube.sh
#
# Software canary cohort (designate → blocked promote → apply → stable):
# TENKAI_DOGFOOD_MODE=canary ./scripts/dogfood-minikube.sh
```

| Path | Notes |
| --- | --- |
| Example product | [`examples/hello-minikube/`](examples/hello-minikube/) |
| One-shot script | [`scripts/dogfood-minikube.sh`](scripts/dogfood-minikube.sh) (`local`, `signed-multi-env`, or `canary`) |
| Ops notes (trust, rollback, multi-env, canary) | [`docs/local-dogfood-minikube.md`](docs/local-dogfood-minikube.md) |
| Native/Helm apply contract | [`docs/software-executor.md`](docs/software-executor.md) |

**Trust reminders proven in dogfood:** `--allow-unsigned-development` applies only
to the built-in `local` environment. A second env (e.g. `stage`) needs **signed
releases** and **signed plan approvals** via `tenkaictl dev init-keys` /
`dev sign-release` / `dev sign-approval` (or
`TENKAI_DOGFOOD_MODE=signed-multi-env`). Software canary evidence gates
(`TENKAI_DOGFOOD_MODE=canary`) use the same canary product rules as
`model_runtime` (#7 / #108): waves observe; promote fails closed without
complete cohort outcomes. See the [ops note](docs/local-dogfood-minikube.md).

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
[`docs/release-signing.md`](docs/release-signing.md).

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
[`examples/routing-local`](examples/routing-local) and
[ADR 0002](docs/decisions/0002-tenkai-owned-routing-configuration.md).

sekai-chisei may supply policy, evaluation, provenance, or an explicitly
configured adapter, but it is not required for standalone routing delivery and
does not own release, plan, apply, rollback, or recovery state.

Plan execution likewise fails closed unless it has a signed, unexpired approval
bound to the exact executable plan and environment. The provider-independent
format, current-trust-root key rotation behavior, standalone policy boundary,
and local-only development bypass are documented in
[`docs/plan-approval.md`](docs/plan-approval.md).

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
tenkaictl env list
tenkaictl env inspect prod
tenkaictl env facts set prod architecture=arm64
tenkaictl env facts set prod memory_gib=32
tenkaictl env facts list prod
tenkaictl env constraints set prod version_range hello-local 1.0.0..2.0.0
tenkaictl env constraints set prod require_fact architecture arm64
tenkaictl env maintenance set prod weekday \
  --timezone Europe/Berlin \
  --weekdays mon,tue,wed,thu,fri \
  --start 22:00 \
  --duration-minutes 120
tenkaictl env maintenance list prod
```

`env list` shows every registered environment with subscription and lease
summary. `env inspect <name>` prints JSON for subscriptions, deployed versions,
lease/fencing state, and the latest plan. Latest-plan inspection includes
sanitized lifecycle detail and at most 256 ordered step summaries; executable
digests, work directories, payloads, and bearer tokens are not returned.

For a scripted two-environment walkthrough (list/inspect/status), run:

```bash
./scripts/demo-multi-env.sh
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

## Continuous reconciliation

Run the controller to converge every registered environment whenever a
subscribed channel changes:

```bash
tenkaictl reconcile
```

Each environment is planned and executed independently. Generation-fenced
leases prevent overlapping execution, failures use bounded per-environment
backoff, and an orphaned running plan is terminated after its lease expires so
a later tick can converge from durable state. For local operation and tests,
`tenkaictl reconcile --once` performs one deterministic tick and exits nonzero
when any environment fails.

## Embedded state operations

Embedded mode stores its complete control-plane state in
`.tenkai-state/tenkai.db` by default. Inspect and back it up without starting a
service:

```sh
tenkaictl inspect
tenkaictl backup /secure/backups/tenkai.db
```

`backup` uses SQLite's online backup API and is consistent while another
embedded command is reading. Restore only when every Tenkai writer using the
database is stopped:

```sh
tenkaictl restore /secure/backups/tenkai.db
tenkaictl inspect
tenkaictl env list
```

The backup contains operational records and Catalog descriptors. Deployment
runtime directories and external artifact payloads must be backed up according
to their own storage policy. Full operator runbook:
[backup and restore](docs/backup-restore.md).

## Network server

`tenkai-server` hosts the same reconciliation contract as embedded CLI mode,
serves unauthenticated liveness (`/healthz`) and readiness (`/readyz`) probes,
and shuts down gracefully on SIGINT. Management mutations require a bearer
token and append request and outcome records to the Tenkai operational
database. Environment runtimes use separate tokens, each scoped server-side to
exactly one environment. Continuous reconcile ticks emit structured diagnostics
documented in [server diagnostics](docs/server-diagnostics.md).

Community embedded and server modes are tenant-free. Enterprise compositions
may plug an auth extension that verifies short-lived, audience-bound assertions
and derives optional tenant context through the versioned
[authenticated request context](docs/auth-request-context.md) contract; Tenkai
remains authoritative for catalog, planning, reconciliation, and recovery.
Tenant mode must pass the deterministic
[tenant isolation conformance](docs/tenant-isolation-conformance.md) harness
before release. Hosts negotiate storage and extension
[runtime capabilities](docs/runtime-capabilities.md) at startup so tenant mode,
multi-replica, HA, and enterprise authentication cannot be requested from a
tenant-free SQLite profile. The public
[enterprise integration boundary](docs/enterprise-integration-boundary.md)
records ownership between the browser-facing enterprise plane and Tenkai’s
delivery authority without coupling community mode to private components.
[Federated identity](docs/federated-identity.md) maps stable opaque identifiers
with issuer and audience binding; governance providers stay authoritative only
for their own evidence. Open-weight
[model runtime](docs/model-runtime.md) products describe engines and
content-addressed weights while inference plugins remain outside the core.

The server accepts plaintext HTTP only on loopback. Put a TLS reverse proxy in
front of it for remote access; never pass tokens on a command line. By default
the server opens the same in-process state backend as `tenkaictl` and requires
no provider service. `--provider-mode remote` is explicit and never inherits
embedded development permissions.

```sh
export TENKAI_MANAGEMENT_TOKEN='replace-from-secret-store'
export TENKAI_RUNTIME_TOKENS='{"runtime-token":"prod"}'
cargo run --bin tenkai-server -- --database .tenkai-state/tenkai.db

# In another shell, request an immediate server-side tick.
TENKAI_MANAGEMENT_TOKEN="$TENKAI_MANAGEMENT_TOKEN" \
  tenkaictl --target remote --server-url http://127.0.0.1:8080 \
  reconcile --once
```

The server also reconciles continuously. Remote v1 CLI support is intentionally
limited to requesting a reconciliation tick; unsupported commands fail with an
explicit instruction to use `--target embedded` instead of silently changing
execution mode. Runtime work is polled at
`GET /v1/runtime/environments/{environment}/work` with the assigned runtime
bearer token. A returned plan carries a durable, expiring fencing generation;
the runtime reports one receipt per step to
`POST /v1/runtime/environments/{environment}/complete`. Completion is
idempotent, updates verified deployed observations, and makes the plan
terminal. Environments with runtime tokens are never executed by the embedded
server executor, preventing split ownership.

Run one pull-only runtime per assigned environment. The bearer token is read
only from runtime configuration and is not passed to the executor:

```sh
export TENKAI_SERVER_URL=https://tenkai.example.internal
export TENKAI_RUNTIME_ENVIRONMENT=prod
export TENKAI_RUNTIME_TOKEN='replace-from-secret-store'
export TENKAI_RUNTIME_EXECUTOR=/opt/tenkai/bin/environment-executor
tenkai-runtime
```

The configured executor receives only non-secret arguments:
`--action`, `--product`, `--target-version`, `--release-digest`,
`--artifact-digest`, `--workdir`, and `--idempotency-key`. It must durably
deduplicate the idempotency key before mutating its target. The runtime renews
its generation-fenced claim while the executor runs, terminates the executor
when renewal fails, and reports one fixed-shape receipt per step without
capturing command output. `tenkai-runtime --once` performs one deterministic
pull for supervisors and tests.

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
release_signature=$(mktemp)
gh api "repos/Sannrox/sekai-chisei/contents/deploy/tenkai.sig.json?ref=v0.2.0" \
  --jq .content | base64 -d > "$release_signature"
gh api "repos/Sannrox/sekai-chisei/contents/deploy/tenkai.toml?ref=v0.2.0" \
  --jq .content | base64 -d | tenkaictl publish - \
    --signature "$release_signature" \
    --trust-roots /etc/tenkai/release-trust.toml
rm -f "$release_signature"
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
| `TENKAI_SEKAI_URL` | `http://127.0.0.1:$GRPC_PORT` | Optional provider endpoint used by the server host |
| `GRPC_PORT` | `50051` | Port used for the optional provider URL |
| `SEKAI_AUTH_TOKEN` | unset | Optional provider bearer token |
| `TENKAI_PRINCIPAL` | `tenkai` | Embedded audit principal or remote provider caller identity |
| `TENKAI_STATE_DIR` | `<workdir-parent>/.tenkai-state` | Immutable deploy-input snapshots and per-environment runtime directories; must be outside the source workdir |
| `TENKAI_EXECUTOR_GUARD` | current `tenkaictl` binary | Optional explicit guard path for applications embedding the Tenkai library |
| `TENKAI_SERVER_URL` | unset | Remote control-plane URL used with `tenkaictl --target remote` |
| `TENKAI_MANAGEMENT_TOKEN` | unset | Required bearer secret for server management requests and remote CLI mode |
| `TENKAI_RUNTIME_TOKENS` | `{}` | Server-only JSON object mapping bearer secrets to one environment each |
| `TENKAI_RUNTIME_ENVIRONMENT` | unset | The one environment assigned to an environment-runtime process |
| `TENKAI_RUNTIME_TOKEN` | unset | Runtime-only bearer secret; kept out of command-line arguments and executor state |
| `TENKAI_RUNTIME_EXECUTOR` | unset | Absolute path to the environment executor implementing the idempotency contract |
| `TENKAI_OUTCOME_PROVIDER` | `disabled` | Set to `chisei` to enable durable terminal-outcome export |
| `TENKAI_OUTCOME_PROVIDER_URL` | unset | Explicit Chisei endpoint used only with `tenkai-server --outcome-provider chisei` |
| `TENKAI_OUTCOME_NAMESPACE` | unset | Namespace authorized for terminal-outcome admission |
| `TENKAI_OUTCOME_PROVIDER_PRINCIPAL` | `tenkai.outcome` | Authenticated telemetry-writer principal for outcome admission |
| `TENKAI_OUTCOME_PROVIDER_TOKEN` | unset | Optional outcome-adapter bearer secret; environment-only and never persisted |
| `TENKAI_DATABASE` | `.tenkai-state/tenkai.db` | Embedded or server-owned operational SQLite database |
| `TENKAI_LISTEN` | `127.0.0.1:8080` | Server listen address; must remain loopback behind a TLS proxy |

## Ontology

Tenkai authoritatively encodes domain objects in its embedded store under
namespace `tenkai`:

`tenkai.product` ← `release_of` — `tenkai.release` ← `promotes` — `tenkai.channel`
← `subscribes` — `tenkai.environment`; each apply writes a `tenkai.plan` and
per-step `tenkai.deployment` records linked to the release, environment, and
plan. Current state lives on the environment object (`deployed.<product>`).
Server mode uses the same domain contracts and may project events to optional
providers without transferring operational authority.

## Status

**v0 control-plane kernel** (architecture program complete; product depth still
growing). Tenkai owns operational recovery state; optional providers never own
it ([ADR 0001](docs/decisions/0001-standalone-core-and-service-evolution.md),
[operational storage](docs/operational-storage.md)).

### Shipped

| Capability | Where to read |
| --- | --- |
| Embedded one-binary mode (no required network/provider) | Quickstart above; ADR 0001 |
| Networked server + continuous reconciliation | [Network server](#network-server); #19 |
| Scoped pull-based environment runtimes + fencing | [Runtime protocol](docs/runtime-protocol-v1.md); #5, #20 |
| Signed release publication and provenance | [Release signing](docs/release-signing.md) |
| Signed plan execution approval | [Plan approval](docs/plan-approval.md) |
| Catalog application boundary | [Catalog contract](docs/catalog-contract.md); ADR 0001 |
| Health probes, auto-rollback, deliberate rollback | Quickstart; apply/reconciler |
| Maintenance windows | CLI `env maintenance` |
| Canary cohort promotion evidence | #7; `src/canary.rs` |
| Canary × model_runtime promote E2E | [Model runtime](docs/model-runtime.md#canary-promotion-evidence-model_runtime); #108 |
| Multi-environment list/inspect | `tenkaictl env list` / `env inspect`; #56 |
| Authenticated remote status/inspect | `--target remote`; #58 |
| Fleet status (embedded and remote) | `tenkaictl fleet status`; [server diagnostics](docs/server-diagnostics.md); #91 |
| Fleet drift watch (baseline + exit codes) | `tenkaictl fleet watch`; [server diagnostics](docs/server-diagnostics.md#fleet-drift-watch); #107 |
| Environment capability facts + planner constraints | `env facts` / `env constraints`; #63, #57 |
| Planner model_runtime variant selection by facts | [Model runtime](docs/model-runtime.md); #66 |
| Ordered model_runtime → routing_config rollout | [examples/model-routing-rollout](examples/model-routing-rollout/); #67 |
| Governed `routing_config` products | [ADR 0002](docs/decisions/0002-tenkai-owned-routing-configuration.md) |
| `model_runtime` product kind + weight cache/eviction | [Model runtime](docs/model-runtime.md); [ADR 0007](docs/decisions/0007-model-runtime-fleet-control-plane.md); #48, #62, #65 |
| Reference llama.cpp engine plugin (fake for CI) | [Model runtime](docs/model-runtime.md); #64 |
| Self-verifying offline bundles | [Offline bundles](docs/offline-bundles.md); [ADR 0003](docs/decisions/0003-canonical-offline-delivery-archives.md) |
| Optional governance/intelligence provider ports | [Provider contracts](docs/provider-contracts.md) |
| Durable terminal outcome export to Chisei | [Provider contracts](docs/provider-contracts.md#chisei-terminal-outcome-adapter-197); #197 |
| Remote HTTP GateProvider (chisei-compatible JSON) | [Provider contracts](docs/provider-contracts.md#remote-gate-http-json-contract-113); #113 |
| Optional advisory plan priors (default off) | [Plan priors](docs/plan-priors.md); #114 |
| Staged products: policy_bundle, eval_suite, agent_definition | [Staged products](docs/staged-products.md); #115, #116, #117 |
| Runtime capability negotiation at startup | [Runtime capabilities](docs/runtime-capabilities.md) |
| Multi-replica / HA capability profile (decision) | [ADR 0009](docs/decisions/0009-multi-replica-reconcile-and-ha-profile.md); #109 |
| AuthStack management HTTP + federation accept path | [Auth context](docs/auth-request-context.md), [federated identity](docs/federated-identity.md); #68, #71 |
| JWT EdDSA enterprise assertion verifier (static keys) | [Auth context](docs/auth-request-context.md#reference-jwt-assertion-verifier-110); #110 |
| Tenant-isolation harness + in-memory tenant store | [Tenant isolation](docs/tenant-isolation-conformance.md); #37, #69, #70 |
| Tenant isolation on all HTTP management surfaces | [Tenant isolation HTTP exposure](docs/tenant-isolation-conformance.md#http-exposure-vs-registry-112); #112 |
| Optional Postgres multi-tenant hub store (feature `postgres`) | [Postgres tenant store](docs/postgres-tenant-store.md); #111 |
| tenkai-server tenant mode → Postgres hub store | [Postgres server wiring](docs/postgres-tenant-store.md#tenkai-server-wiring-127); #127 |
| Postgres hub `shared_replica_state` (single-active writer) | [Shared replica state](docs/postgres-tenant-store.md#shared-replica-state-128); #128 |
| Multi-host reconcile tick fencing | [Tick fencing](docs/reconcile-tick-fencing.md); #129 |
| Fenced multi-replica delivery effects | [Conformance](docs/delivery-effect-conformance.md); #180 |
| Multi-replica hub ops runbook | [Multi-replica hub runbook](docs/multi-replica-hub-runbook.md); #130 |
| Durable Postgres tick fence + inventory heartbeat + OpenMetrics + outcome priors | #135–#138; [tick fencing](docs/reconcile-tick-fencing.md), [plan priors](docs/plan-priors.md) |
| Local minikube dogfood (embedded, no remote server) | [Local dogfood](#local-dogfood-minikube-no-remote-server); [ops note](docs/local-dogfood-minikube.md); #145–#146, #152 |
| Dogfood `tenkaictl dev` release/plan signing (not production KMS) | [ops note](docs/local-dogfood-minikube.md#first-class-dogfood-signing-149); #149 |
| K8s software phase diagnostics (apply/health/restore/remove) | [software executor](docs/software-executor.md); [ops note](docs/local-dogfood-minikube.md#apply--health--restore-diagnostics-150); #150 |
| Software canary cohort drill on minikube dogfood | [ops note](docs/local-dogfood-minikube.md#software-canary-cohort-drill-154); #154 |
| Backup/restore drill and server reconcile diagnostics | [operational storage](docs/operational-storage.md); [server diagnostics](docs/server-diagnostics.md); #59, #60 |
| Release readiness checklist | [release readiness](docs/release-readiness.md); #72 |

Governance integrations remain optional. Required policy or gate decisions fail
closed; configured terminal-outcome export uses a durable retry outbox, while
audit and planning-event export remain unwired and the enterprise profile stays
gated as documented in the [provider contracts](docs/provider-contracts.md) and
[supported operating profiles](docs/decisions/0010-supported-operating-profiles.md).
An embedded apply with `[gate].eval_suite` fails closed locally unless a remote
provider host is explicitly configured; ungated solo deploys never open a
network connection.

### Deferred (next-era product work)

Tracked in open GitHub Issues. The architecture program (ADRs 0001–0009) and
the Phase 5 first cut (fleet status/watch/waves, software executors, optional
Postgres hub + multi-replica fencing) are landed on main. Remaining work is
**depth**, not re-litigating operational ownership:

| Track | Intent |
| --- | --- |
| Release packaging | [v0.2.0 notes](docs/releases/0.2.0.md) (tagged); next notes when needed |
| Hub HA product claim | Criteria + automated drills before advertising `high_availability` (fence already shipped #135) |
| Intelligence loop depth | Fail-closed prior policy; live remote OutcomeProvider history |
| Executor / model depth | Peer/regional weight caches; additional engines; in-process kube client only if dependency weight is accepted |
| Enterprise host | JWKS rotation, live IdP drills, tenant-isolated prior stores |
| Local dogfood | [minikube path](docs/local-dogfood-minikube.md): unsigned + signed multi-env (#152) + **software canary drill** (#154) landed; inventory → `env facts` drill still optional |

Explicit non-priorities until measured need: Catalog service extraction
(ADR 0001), multi-primary SQLite HA (ADR 0009), identity-plane DB co-location.

Founding product intent and long-range roadmap remain in [DESIGN.md](DESIGN.md);
accepted architecture decisions are the decision log under
[docs/decisions/](docs/decisions/README.md).

Active implementation work and dependencies are tracked in **GitHub Issues**
(source of truth for readiness and assignment). Before tagging a release, follow
the [release readiness checklist](docs/release-readiness.md).

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

Independent fresh-checkout evidence for the provider-free embedded workflow,
including automatic rollback and backup/restore, is recorded in the
[embedded golden-path usability exercise](docs/research/embedded-golden-path-usability.md).
