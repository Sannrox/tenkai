# Run reconciliation, `tenkai-server`, and environment runtimes

Tenkai converges environments in one of three ways: an embedded `tenkaictl`
controller, the networked `tenkai-server`, or a server plus pull-only
`tenkai-runtime` processes for environments the server cannot reach. All three
use the same reconciliation contract. Every variable used here is listed in
[environment variables](environment-variables.md).

## Continuous reconciliation in embedded mode

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

## Run `tenkai-server`

`tenkai-server` hosts the same reconciliation contract as embedded CLI mode,
binds its listener before opening the operational store, serves unauthenticated
liveness (`/healthz`) immediately and readiness (`/readyz`) after the store is
open, and shuts down gracefully on SIGINT or SIGTERM. Shutdown stops
accepting requests, cancels an in-flight deploy command under its fence, lets
the current tick record that outcome, and exits 0, so supervisors that send
SIGTERM (systemd, Docker, Kubernetes) need no `KillSignal` override;
`tenkaictl reconcile` without `--once` stops the same way. A large legacy graph import cannot
delay bind; `/readyz` stays 503 until import finishes, and a restart keeps
already-copied rows. Management mutations require a bearer
token and append request and outcome records to the Tenkai operational
database. Environment runtimes use separate tokens, each scoped server-side to
exactly one environment. Continuous reconcile ticks emit structured diagnostics
documented in [server diagnostics](server-diagnostics.md).

The server accepts plaintext HTTP only on loopback. Put a TLS reverse proxy in
front of it for remote access; never pass tokens on a command line. By default
the server opens the same in-process state backend as `tenkaictl` and requires
no provider service. `--provider-mode remote` is explicit and never inherits
embedded development permissions. The server reconciles every
`--reconcile-interval` seconds (default 10) and works on at most
`--max-concurrency` environments at once (default 8).

```sh
export TENKAI_MANAGEMENT_TOKEN='replace-from-secret-store'
export TENKAI_RUNTIME_TOKENS='{"runtime-token":"prod"}'
cargo run --bin tenkai-server -- --database .tenkai-state/tenkai.db

# In another shell, request an immediate server-side tick.
TENKAI_MANAGEMENT_TOKEN="$TENKAI_MANAGEMENT_TOKEN" \
  tenkaictl --target remote --server-url http://127.0.0.1:8080 \
  reconcile --once
```

### Install a server host

Install `tenkai-server` and `tenkai-executor-guard` side by side, as shown in
[release binaries](release-binaries.md#install-a-server-host), or point
`TENKAI_EXECUTOR_GUARD` at the guard. The server resolves the guard at startup:
when it is missing, it logs `tenkai-server warning: shell executor
unavailable`, omits `shell_executor:v1` from `/readyz` capabilities, and the
first shell-executor apply fails with the same instruction. Pass
`--require-executor` to refuse to start instead.

A reference systemd unit keeps secrets in an `EnvironmentFile` (never argv),
listens on loopback behind a TLS proxy, and relies on the default SIGTERM stop:

```ini
# /etc/systemd/system/tenkai-server.service
[Unit]
Description=Tenkai control plane
After=network-online.target
Wants=network-online.target

[Service]
User=tenkai
Group=tenkai
# Holds the management and runtime tokens; owner-only mode 0600.
EnvironmentFile=/etc/tenkai/server.env
StateDirectory=tenkai
ExecStart=/usr/local/bin/tenkai-server \
  --listen 127.0.0.1:8080 \
  --database /var/lib/tenkai/tenkai.db \
  --require-executor
# SIGTERM is the default stop signal and shuts down gracefully.
TimeoutStopSec=60
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
MemoryMax=2G
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

A stop cancels an in-flight deploy command under its fence, so
`TimeoutStopSec` only has to cover the current tick recording that outcome; the
next start converges from durable state.

To authenticate with enterprise JWT assertions or with an identity provider
(OIDC) instead of shared bearer tokens, see
[configure server authentication](configure-server-authentication.md).

### Open the web console

Release binaries of `tenkai-server` embed the
[web console](https://github.com/Sannrox/tenkai-console) and serve it at `/ui/`
on the API's origin; `GET /` redirects there. Open
`http://127.0.0.1:8080/ui/`, or the matching URL behind your TLS proxy. The
console works at `/ui/` and under a proxy sub-path (`/<prefix>/ui/`) because
the redirect and every console URL are relative. For nested console routes,
such as the OIDC callback `/ui/auth/callback`, the server adds a relative
`<base href>` (for example `../`) to `index.html` so those relative URLs still
resolve to `/ui/`; it changes nothing else in the bundle. It signs in with OIDC
when `TENKAI_OIDC_CONFIG` has a `[client]` section (walkthrough:
[sign in with Keycloak](console-sign-in-with-keycloak.md)), and otherwise asks
for a bearer token, which it keeps in memory for the tab.

Console responses carry a strict Content-Security-Policy (`default-src
'self'`, no inline or evaluated script, no framing). When OIDC is configured,
`connect-src` also allows the issuer's origin, because the browser calls the
identity provider's discovery and token endpoints directly. Providers whose
token endpoint is on another origin need it in `[client] connect_origins`
([OIDC access tokens](configure-server-authentication.md#oidc-access-tokens-468)).

The bundle is a pinned console release built in with
Cargo feature `ui` ([ADR 0031](decisions/0031-web-console.md)):

```sh
cargo build --release --locked -p tenkai-server --features ui
```

The build downloads the release named in `ui/console.pin` and fails unless its
SHA-256 matches. Offline builders set `TENKAI_UI_BUNDLE` to a downloaded copy of
that zip; the checksum is still enforced. Builds without `ui` serve no console
and need no network. For console development, `--ui-dir <path>` serves a local
console build (a directory with `index.html`) instead of the embedded one.

### Remote CLI

Remote v1 CLI support covers `reconcile --once`, `fleet status`, `fleet watch`,
`env list`, `env inspect`, `env subscribe`, `status`, `publish`, `promote`,
`release recall`, `plan`, `approval submit`, `apply`, `rollback`, and the
`migrate` family. Unsupported commands fail with an explicit instruction to use
`--target embedded` instead of silently changing execution mode. The HTTP
contract is [remote management lifecycle](management-lifecycle.md).

### Operating profiles

Community embedded and server modes are tenant-free. Enterprise compositions
may plug an auth extension that verifies short-lived, audience-bound assertions
and derives optional tenant context through the versioned
[authenticated request context](auth-request-context.md) contract; Tenkai
remains authoritative for catalog, planning, reconciliation, and recovery.
Tenant mode must pass the deterministic
[tenant isolation conformance](tenant-isolation-conformance.md) harness
before release. Hosts negotiate storage and extension
[runtime capabilities](runtime-capabilities.md) at startup so tenant mode,
multi-replica, HA, and enterprise authentication cannot be requested from a
tenant-free SQLite profile. The public
[enterprise integration boundary](enterprise-integration-boundary.md)
records ownership between the browser-facing enterprise plane and Tenkai’s
delivery authority without coupling community mode to private components.
[Federated identity](federated-identity.md) maps stable opaque identifiers
with issuer and audience binding; governance providers stay authoritative only
for their own evidence.

## Run an environment runtime

Environments with runtime tokens are executed by a pull-only `tenkai-runtime`
in that environment, never by the embedded server executor, preventing split
ownership. The runtime polls
`GET /v1/runtime/environments/{environment}/work` with its bearer token. A
returned plan carries a durable, expiring fencing generation; the runtime
renews that claim, reports inventory, and reports one receipt per step.
Completion is idempotent, updates verified deployed observations, and makes the
plan terminal. The endpoints are specified in
[runtime protocol v1](runtime-protocol-v1.md).

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

## Execution leases and fencing

Environment execution uses short-lived, generation-fenced Tenkai leases. An
expired lease is taken over atomically; a paused older controller cannot
refresh or release the replacement generation and revalidates ownership before
each deployment step. A local supervisor holds the process fence while mutation
commands receive `TENKAI_FENCING_GENERATION`; controller death closes its
control pipe, terminates the complete command group, and releases the fence
before replacement work starts. Legacy object-only leases are never taken over
automatically: stop the old controller and its children, then use
`tenkaictl env unlock <environment>` as the explicit compatibility fallback.
Multi-host hubs add [reconcile tick fencing](reconcile-tick-fencing.md).
