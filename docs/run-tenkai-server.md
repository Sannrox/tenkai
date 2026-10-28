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

Remote publication and non-local deployment verify signatures against the current
host file `TENKAI_RELEASE_TRUST_ROOTS`. Caller-supplied roots cannot add trusted
signers. Removing a signer from the host file prevents subsequent deployment of
its releases. Configure OIDC grant rules with `products = ["api"]` to confine
publication and promotion to those products; omitted product bindings retain
catalog-wide authority. Fleet management grants retain full catalog authority.

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

Plaintext HTTP is accepted only on loopback. For remote access, either put a
TLS reverse proxy in front of it or serve TLS natively (see
[native TLS](#native-tls)); never pass tokens or keys on a command line. By default
the server opens the same in-process state backend as `tenkaictl` and requires
no provider service. `--provider-mode remote` is explicit and never inherits
embedded development permissions. The server reconciles every
`--reconcile-interval` seconds (default 10) and works on at most
`--max-concurrency` environments at once (default 8).

```sh
export TENKAI_MANAGEMENT_TOKEN='replace-from-secret-store'
export TENKAI_RUNTIME_TOKENS='{"runtime-token":"prod"}'
# Host-owned release signing roots; remote publish never trusts caller-supplied roots.
export TENKAI_RELEASE_TRUST_ROOTS=/etc/tenkai/release-trust.toml
cargo run --bin tenkai-server -- --database .tenkai-state/tenkai.db

# In another shell, request an immediate server-side tick.
TENKAI_MANAGEMENT_TOKEN="$TENKAI_MANAGEMENT_TOKEN" \
  tenkaictl --target remote --server-url http://127.0.0.1:8080 \
  reconcile --once
```

### Native TLS

`tenkai-server` serves TLS itself when `--tls-cert` (`TENKAI_TLS_CERT`) names a
PEM certificate chain (#671). The private key is the secret setting
`TENKAI_TLS_KEY` (inline, `TENKAI_TLS_KEY_FILE`, or `$TENKAI_SECRET_DIR/TENKAI_TLS_KEY`),
never an argument.

- **Binding.** A non-loopback `--listen` needs TLS; a plaintext non-loopback
  bind is refused. `--enable-metrics` stays loopback-only because `/metrics`
  is unauthenticated.
- **Versions.** TLS 1.3 only by default; `--tls-min-version 1.2` also accepts
  TLS 1.2.
- **Client certificates.** With `--tls-client-ca` (`TENKAI_TLS_CLIENT_CA`), a
  client certificate is verified against that CA when presented and is
  optional otherwise; an untrusted one fails the handshake.
  `--tls-require-runtime-client-cert` additionally refuses `/v1/runtime/*` on
  connections without one (`403`), except enrollment and certificate
  renewal, which are how a runner gets a certificate. Management routes accept either, and
  `/healthz` never requires one. Without a runner CA, bearer tokens are
  still required as before; with one, a runner certificate is the runner's
  identity ([runner certificates](#runner-certificates)).
- **Renewal.** The certificate, key and client CA are read again every five
  seconds and on `SIGHUP`. Changed material applies to new connections; open
  connections keep theirs, and runner leases, which live in the store, are not
  affected. A renewal that does not load is logged as
  `tenkai.tls_reload outcome=failed` and the certificate in use stays.
- **Proxy mode** stays supported: bind loopback without `--tls-cert`.

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

### Exports over HTTP

With `TENKAI_EXPORT_DIR` and `TENKAI_EXPORT_SIGNING_KEY` (an Ed25519 seed
file) set, an operator without shell access on the host can create and
download the files the CLI otherwise writes there (#682):

| `kind` | Scope | Artifact |
| --- | --- | --- |
| `support-bundle` | hub | signed [support bundle](support-bundle.md), without log events |
| `audit-export` | hub | the next signed [audit export](audit-export.md) of the chain kept under `TENKAI_EXPORT_DIR/audit-chain` |
| `recovery-bundle` | `environment`, `plan_id` | ADR 0027 recovery diagnostic |
| `offline-receipt` | `environment`, `upgrade` | the accepted `tenkai.offline-receipt.v1` of an isolated environment |

- `POST /v1/exports` with `{"kind": ..., "reason": ..., ...}` produces one
  export and answers it with `201`. `GET /v1/exports` lists exports newest
  first, `GET /v1/exports/{id}` shows one, and
  `GET /v1/exports/{id}/download?reason=...` returns the artifact as an
  attachment under the name the CLI gives it.
- **Unchanged formats.** A downloaded file is byte for byte what the server
  stored. Support bundles and audit exports verify with
  `tenkaictl support-bundle verify` and `tenkaictl audit verify` like locally
  produced ones, and a receipt imports with `tenkaictl upgrade import-receipt`.
- **Who and why.** Every creation and download needs a reason. Each is kept
  with its principal and time beside the export and shown on inspect, and
  each writes an `export.<kind>.*` audit record naming the export. A
  download is recorded before any byte is sent.
- **Scope.** Management capability only; read-only credentials can neither
  create nor list exports. An environment-scoped credential creates and sees
  only its own environment's recovery bundles and offline receipts.
- **Durability.** An export is assembled in a staging directory and renamed
  into place, so a crash never leaves a partial export. Exports are never
  deleted by the server. If the audit chain advanced but an entry's export was
  not stored, audit-export requests store such entries, oldest first, before
  the chain advances again, so the downloaded chain has no gap. A lock on the
  export directory serializes this across overlapping server processes.
- **Key rotation.** After rotating `TENKAI_EXPORT_SIGNING_KEY`, point
  `TENKAI_EXPORT_TRUST_ROOTS` at trust roots naming the earlier key so the
  audit chain continues.
- **Receipts.** The hub keeps an accepted receipt from this version on.
  Importing a receipt accepted by an older version again stores it.
- **Tenant mode** refuses the setting at startup, and a tenant-mode host
  answers every export route with `503`: tenant records live in PostgreSQL.

### Remote CLI

Remote v1 CLI support covers `reconcile --once`, `fleet status`, `fleet watch`,
`env list`, `env inspect`, `env subscribe`, `env add`, the `set`, `clear` and
`remove` commands of `env facts`, `env constraints`, `env maintenance`,
`env webhooks` and `env approval-policy`, `status`, `publish`, `promote`,
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

### Enrolling a runtime

Instead of a long-lived token in `TENKAI_RUNTIME_TOKENS`, a runtime can enroll
once with a short-lived, single-use token and keep its own credential (#630):

```sh
# Operator, with a management credential:
tenkaictl --target remote runtime enroll prod --ttl-seconds 900

# On the host, once:
export TENKAI_RUNTIME_CREDENTIAL_FILE=/var/lib/tenkai-runtime/credential
export TENKAI_RUNTIME_ENROLLMENT_TOKEN='tke_...'
tenkai-runtime
```

- **Exchange.** On first start the runtime posts the token to
  `POST /v1/runtime/environments/{environment}/enroll` and writes the
  credential it gets to `TENKAI_RUNTIME_CREDENTIAL_FILE`, owner-only. It
  never replaces that file, and later starts use it without the token.
- **Single use.** A token works once, before it expires (15 minutes by
  default, 24 hours at most), and only for the environment it was issued
  for. Of two concurrent redemptions, one wins. Unknown, spent, expired and
  foreign tokens are all refused alike, and a refused token is not spent. If
  the runtime stops before writing the file, issue a new token.
- **Storage.** Tenkai stores only SHA-256 digests of tokens and credentials.
  A credential's digest is its id: the runtime prints it at enrollment, and
  `tenkaictl --target remote runtime revoke sha256:... --reason '...'`
  revokes it. The runtime is refused from its next request on. A completion it already
  stored is applied by the server when a runtime of that environment next
  polls after the claim lapsed, so revoking a runtime mid-plan and enrolling
  its replacement does not strand the environment.
- **Hand-off.** Issuing the first enrollment marks the environment
  runtime-managed for good, revoked credentials or not. From then on only its
  runtime runs its plans. Every server execution checks the mark while
  holding the environment's lease, and a runtime claims no work while the
  server holds that lease. So a plan the server began before the enrollment
  finishes there, and the two never run one environment together. A lease
  left by a crashed server is taken over once it expires, as server
  execution takes one over. A plan the server had started is not run again
  from its first step: once its lease is gone, it is failed, as server
  recovery fails it, and a rollback plan recovers the environment. Issuing and redeeming tokens needs a trusted clock. Issue
  enrollments once every server replica runs this version.

### Trust posture

`GET /v1/trust` (read capability, fleet-wide credentials only) shows what
this host trusts and how long its certificates last (#676):

- **Signing.** Each configured trust-root file (`release`,
  `package_migration_approval`, `bundle_import`, `key_revocation`) with its
  signers' key ids and identities, each marked `revoked` when the installed
  key revocation list revokes it, and that list's sequence and signer.
  The list also carries `issued_at`, when its authority signed it, and
  `installed_at`, when the installed file was last written by an install
  or bundle import (#811). Trust-root files record no signer validity, so
  each root says `signer_validity: "not_recorded"`: a signer is trusted
  until it is removed or revoked.
- **TLS.** Every certificate in the listener chain (`TENKAI_TLS_CERT`), the
  TLS client CA, the runner CA and the outbound CA bundle
  (`TENKAI_CA_BUNDLE`), with subject, `not_after`, days left and a status:
  `ok`, `warning` (fewer than `TENKAI_TRUST_WARNING_DAYS`, default 30),
  `critical` (fewer than `TENKAI_TRUST_CRITICAL_DAYS`, default 7) or
  `expired`. An unreadable file is `critical`. Each readable certificate
  carries `sha256_fingerprint`, as `openssl x509 -fingerprint -sha256`
  prints it (#809).
- **Runner client certificates.** `runtime_client_cert_required` is `true`
  when `TENKAI_TLS_REQUIRE_RUNTIME_CLIENT_CERT` is in force (#809).

Each entry says its `source`: `loaded` is the material the server uses
now (the listener chain, client CA and runner CA), so a renewal that
failed to load keeps its warning; `file` is a file as it is on disk.
Release, bundle-import and revocation-authority trust roots are read from
disk on each use, so their `file` entry is what is in force. The
package-migration approval roots are loaded once at start: they appear
twice, as `file` and as `loaded`, and a changed file takes effect after a
restart (#811). Outbound clients read the CA bundle at start, so restart
after replacing it. Signer
`revoked` flags follow the revocations this process enforces, and the
installed list is shown only once it verifies against its authorities.
The worst certificate status also appears on `/readyz` as `trust`, from a
snapshot refreshed every minute, without failing readiness. Only public
certificates and trust roots are read, never key files, and files are
named without their directories.
**Runway (#811).** `GET /v1/trust/runway` (same audience) lists each
environment's latest plan that has yet to apply (`computed` or `blocked`),
the next maintenance window it waits for (`window_opens_at_ms`, absent when
it may apply now), and `blocked_by`: the first TLS certificate that lapses
at or before that window. It is computed on each request with the same
check plan creation uses ([maintenance windows](manage-environments.md#maintenance-windows)).
Signers are not checked, as trust roots record no signer validity.
**Announcements (#775).** When the worst certificate status turns
`warning`, `critical` or `expired`, host webhooks that list `trust.expiring`
are notified once per turn, as for `backup.stale` and `clock.drift`.
On a multi-replica hub only the writer announces.
**Change events (#784).** With `TENKAI_TRUST_CHANGE_EVENTS=true` each such
turn also appends one `trust_threshold_crossed` change event, resource
`trust/warning`, `trust/critical` or `trust/expired`, to `/v1/events`, and
a return to `ok` after one appends `trust/ok` once. Whether a turn is new
is read from the store, not remembered: it is skipped while the latest
trust event names the same status, so a restart or a writer takeover does
not repeat it. The `trust/ok` marker lets the next turn count, including
for an unreadable certificate, and a renewed certificate that lapsed again
while no server ran is announced from its expiry. Only the writer appends, and the check and the append are one
fenced transaction. The setting is off by default: releases before #775
fail a change-event page that holds a kind they do not know, so enable it
only once every replica, and any release you may roll back to, includes
#775. On a tenant-mode hub the event lands in the hub partition, which
tenant `/v1/events` pages do not include. Plans computed while a window is closed flag a certificate
that lapses before it opens ([maintenance windows](manage-environments.md#maintenance-windows)).

### Runner certificates

With a runner CA, a runtime agent's identity is a short-lived client
certificate instead of a long-lived bearer (#674).

```sh
# Once: create the runner CA, or bring your own certificate and key.
tenkaictl runner-ca init --dir /etc/tenkai/runner-ca
export TENKAI_RUNNER_CA_CERT=/etc/tenkai/runner-ca/runner-ca.pem
export TENKAI_RUNNER_CA_KEY=/etc/tenkai/runner-ca/runner-ca-key.pem
export TENKAI_TLS_CLIENT_CA=/etc/tenkai/runner-ca/runner-ca.pem

# On the runner host, with an enrollment token as above:
export TENKAI_RUNTIME_CERTIFICATE_DIR=/var/lib/tenkai-runtime/certificate
```

- **Enrollment.** The agent generates its key in the certificate directory
  (owner-only) and sends only a CSR with the enrollment token. The server
  issues a certificate valid for 24 hours whose only identity is
  `urn:tenkai:runner:<environment>:<runner id>`, whatever names the CSR
  asked for. The runner id is the registry id of the credential the
  enrollment produced. A CSR the server cannot sign is refused before the
  token is spent.
- **Admission.** The agent presents its certificate on every request. A
  certificate issued by the runner CA, valid now, names the runner. The
  runner may act only in that environment, and only while its credential is
  enrolled and not revoked in the [registry](#runner-registry). A
  certificate from any other CA the TLS client CA trusts names no runner. A
  presented runner certificate that fails is refused, not retried as a
  bearer.
- **Keys.** The runner CA key is separate from release and approval signing
  keys. A production profile should keep it under the same controls as
  those.
- **Renewal.** The agent renews its certificate over
  `POST /v1/runtime/environments/{environment}/certificate` once a third of
  its lifetime is left, with a CSR over the same key, admitted by the
  current certificate. Once a certificate has expired (an agent offline
  for a day), the agent renews with its enrolled bearer credential, on that
  route only. Like enrollment, the route is exempt from the runtime
  client-certificate requirement. An agent with a certificate directory
  never uses its bearer for work, so a runner keeps one lease identity
  across renewals.
- **Rotation (#769).** `TENKAI_RUNNER_CA_CERT` may list several CAs: the
  first issues, with its key in `TENKAI_RUNNER_CA_KEY`, and every listed CA
  is admitted. Enrollment and renewal return the whole list as the runner's
  trust bundle, which runners present with their certificate. Use the same
  file as `TENKAI_TLS_CLIENT_CA`. Rotate in three steps, so that no server
  ever refuses a certificate another one issued:
  1. **Accept.** Old CA first, new CA second, old key, on every server.
     Nothing changes for runners yet.
  2. **Issue.** New CA first, old CA second, new key, on every server.
     Runners move to the new CA as they renew.
  3. **Retire.** Every runner renews within two thirds of a certificate's
     lifetime (16 hours). One lifetime (24 hours) after the last server
     finished step 2, remove the old CA. Its certificates are refused from
     then on.

  The server rereads the TLS client CA on its own; restart it to reload the
  runner CA.
- **Isolated sites (#770).** A dark site runs its own server, and that
  server is its runners' registry and CA. Runners enroll there, and
  revocation there takes effect from the runner's next request, with no
  list to carry. Rotation follows the steps above with the site's own CA
  files. A connected source never names a site's runners, so offline
  bundles carry no runner revocations or runner trust bundle. A runner cut
  off from its server past its certificate's expiry claims no new work.
  When contact returns, it renews with its enrolled bearer on the renewal
  route and reports under the same lease identity. A plan whose lease lapsed
  meanwhile has its stored completion applied by the server's lapsed
  completion recovery.

### Runner registry

`tenkaictl --target remote runner list` (`runner` is an alias of `runtime`)
shows every runner: each enrolled credential, active or revoked, and each
token in `TENKAI_RUNTIME_TOKENS` as a read-only `static` runner (#673).
`runner inspect sha256:...` shows one. The HTTP surface is `GET /v1/runners`,
`GET /v1/runners/{id}` and `POST /v1/runners/{id}/revoke` with
`{"reason": "..."}`; all need the management capability, and an
environment-scoped credential sees only its environment's runners.

- **Ids, never secrets.** A runner's id is the `sha256:` digest of its
  credential or token. No listing returns a credential, token or enrollment
  token.
- **Instances.** For each instance that presented the runner's credential:
  its instance id, the agent version it sends in `x-tenkai-runtime-version`,
  its last work pull, heartbeat and inventory report, and whether it holds a
  runtime plan lease now, and its `skew` against the server's version:
  `current`, `behind` (one minor release behind, supported during a rolling
  upgrade), `unsupported` (further behind, or another major) or `ahead`.
  Before 1.0 the minor number is the compatibility line. `/readyz` and
  fleet status report the server's own `version`. Activity is written at
  most every 30 seconds per
  instance and kind, so it can trail by that much, and a failed write never
  fails the runtime's request.
- **Auth (#809).** `client_certificate` once the runner CA has issued the
  runner a certificate, at enrollment with a CSR or at a renewal; `bearer`
  for a static token or an enrolled credential never issued one. It is
  read from what the server issued, not from what a request presented: an
  agent with a certificate never uses its bearer for work, though the
  bearer stays valid for renewal unless certificates are required. A
  runner certified before this release, or by a replica one release
  behind, reads `bearer` until its next renewal, within a day.
- **Revocation.** A reason is required, and it and the revoking principal
  are shown on inspect. The earlier bodyless
  `POST /v1/runtime-credentials/{id}/revoke` keeps working for released
  clients and records that no reason was given. A static runner cannot be revoked: remove its token
  from `TENKAI_RUNTIME_TOKENS`.
- **Rolling upgrades.** The registry's tables are additive. Older servers
  ignore them and the version header.
- **Scope.** Enrollment is for single-tenant hosts; tenant mode refuses it.
- **Compatibility.** Token-configured runtimes keep working. Enrollment and
  credentials are additive tables in SQLite and PostgreSQL, which an older
  server ignores.

The runtime stays pull-only: it opens every connection, and Tenkai has no
path to the host.

### Upgrading the runtime agent

The runtime agent is a component like any other (#685). It ships as signed
releases of the product `tenkai-runtime`, whose deploy inputs are exactly
`tenkai-runtime` and `tenkai-runtime-guard`. Publishing, compatibility
profiles, plans, approvals, rollback and receipts work as for every product,
and the agent runs its own step:

```sh
tenkai-runtime install --home /var/lib/tenkai-runtime   # once, on the host
export TENKAI_RUNTIME_HOME=/var/lib/tenkai-runtime      # then run current/tenkai-runtime
```

- **Fetch.** The agent pulls the two binaries from the server over its
  runtime credential (`POST /v1/runtime/environments/{environment}/self-release`),
  which serves them only to the runtime holding the plan's current claim.
  The agent needs no access to the server's files, and the server opens no
  connection to the host.
- **Before any switch.** The downloaded binaries, with their modes, must hash
  to the artifact digest of the signed release the plan names, and so must
  the staged copy; changed content is refused.
  The new version must answer `tenkai-runtime protocol`, within ten seconds,
  with the runtime
  protocol this agent speaks to the server (same major, this minor); one that
  does not is refused. Neither refusal stages or switches anything.
- **Switch.** The agent copies the release's binaries to
  `versions/<artifact digest>/` and checks the new version starts. It records the
  switch in `pending.json`, repoints `current` (keeping `previous`), and
  exits, so its supervisor starts the new version. The new version reports
  the step's receipt. Every write is a rename, so a crash leaves the old or
  the new layout.
- **Rollback.** `tenkaictl rollback` plans the previous release, which the
  agent switches back to the same way.
- **A version that does not start.** Before every start the supervisor runs
  `tenkai-runtime prestart` from a version known to run (`previous`, else
  `current`). While a switch is unreported it counts the new version's
  starts in the home, and after three it reverts: it restores the previous
  version and marks the new one failed on this host, so it is not switched
  to again. The previous version then reports the step as failed. The count
  does not depend on how fast the new version fails or on supervisor start
  limits. `tenkai-runtime revert` reverts at once, by hand.
  [`examples/runtime-agent-systemd`](../examples/runtime-agent-systemd/tenkai-runtime.service)
  holds the unit.
- **Rules.** The agent's own release must be its plan's last step; a plan
  that runs other products as well finishes them first. Without
  `TENKAI_RUNTIME_HOME` the step fails, and nothing changes on the host.
  The agent confirms its claim just before switching, so a runtime that has
  taken over the plan meanwhile is never raced. A
  runtime-run component now records the version it replaced, as server
  execution does, so `tenkaictl rollback` works for every component a
  runtime runs.

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
