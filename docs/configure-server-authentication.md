# Configure `tenkai-server` authentication

`tenkai-server` authenticates every management request before Tenkai's own
delivery authorization runs. The server always requires the fleet management
token `TENKAI_MANAGEMENT_TOKEN` and refuses to start without it. On top of that
token, pick one mode for people and automation, then configure it as below. Runtime tokens for `tenkai-runtime` are configured
separately in every mode ([run tenkai-server](run-tenkai-server.md)). The
contract behind all modes is [authenticated request context](auth-request-context.md).

| Mode | Use when | Configure with |
| --- | --- | --- |
| Host identity (Linux Unix socket) | People on the server host, including the first install and the console over SSH | `/run/tenkai/tenkai.sock` plus `/etc/tenkai/host-grants.toml` ([ADR 0047](decisions/0047-host-identity.md)) |
| Community bearer tokens only | Automation and break-glass | `TENKAI_MANAGEMENT_TOKEN`, optionally `TENKAI_ENVIRONMENT_MANAGEMENT_TOKENS` |
| Enterprise JWT assertions | A trusted gateway mints short-lived Ed25519-signed assertions, optionally with tenant claims | `TENKAI_JWT_VERIFIER_CONFIG` |
| OIDC access tokens | People sign in through your identity provider, for example with the web console or `tenkaictl login` | `TENKAI_OIDC_CONFIG` |
| JWT and OIDC together | Platform assertions and IdP access tokens in one process | both `TENKAI_JWT_VERIFIER_CONFIG` and `TENKAI_OIDC_CONFIG`, with distinct `iss` values |

JWT and OIDC may run in the same process. Tokens are selected by issuer
(`iss`); each verifier keeps its own JWKS and audience. An unknown issuer is
rejected. The fleet management token stays valid as the break-glass
credential, and environment-scoped tokens keep working; keep the fleet token
in your secret store.

The canonical tenant claim is `tenant_id`. Platform JWTs that send only
`tenkai_tenant` still authenticate and log a deprecation warning.

## Community bearer tokens

Set the fleet management token, and optionally management tokens confined to
one environment each:

```sh
export TENKAI_MANAGEMENT_TOKEN='replace-from-secret-store'
export TENKAI_ENVIRONMENT_MANAGEMENT_TOKENS='{"replace-from-secret-store":"prod"}'
tenkai-server --database /var/lib/tenkai/tenkai.db
```

The fleet token has `read` and `management` on every route. An
environment-scoped token may call only operations bound to its environment;
catalog-wide publish, promote, recall, and fleet-wide reconcile fail closed
([management lifecycle](management-lifecycle.md)). Never pass tokens on a
command line.

## Host identity (Linux)

`tenkai-server` also listens on `/run/tenkai/tenkai.sock` (`TENKAI_UNIX_SOCKET`,
`--unix-socket`; `--no-unix-socket` disables it). Each connection is identified
by kernel peer credentials. OS groups in `/etc/tenkai/host-grants.toml`
(`TENKAI_HOST_GRANTS`) map to the same grant-rule shape as OIDC:

| OS group | Grant |
| --- | --- |
| `tenkai-viewer` | `read` |
| `tenkai-operator` | `management` (implies `read` and `publish`) |
| `tenkai-admin` | `management` |

Install creates the groups, writes the mapping file, puts the installing
user in `tenkai-viewer` and `tenkai-operator`, adds the `tenkai` service user
to `tenkai-viewer`, and creates `/run/tenkai` so that user can bind
`tenkai.sock` group `tenkai-viewer` mode `0660`. A user in no mapped group, a uid
with no passwd entry, or an NSS failure is refused. TCP and the management
token stay for automation and break-glass.

On the host, `tenkaictl` uses the socket when it exists and sends no token.
The console is reached with `ssh -L 8080:/run/tenkai/tenkai.sock <host>` and
`GET /v1/auth/me` shows the user, groups, and `source=host`. Peer-credential
requests require a loopback `Host`; an `Origin` or `Referer`, if present, must
be a loopback console origin. Plans are still approved by offline keys.

## Enterprise JWT assertions

The shipped server enables the reference extension only when
`TENKAI_JWT_VERIFIER_CONFIG` names a readable, valid trust file in the
[reference JWT trust format](auth-request-context.md#reference-jwt-assertion-verifier-110):

```sh
export TENKAI_JWT_VERIFIER_CONFIG=/etc/tenkai/aldunis-jwt-trust.toml
tenkai-server --with-enterprise-auth --require-enterprise-auth
```

The file contains public Ed25519 verification keys only. Do not put assertion
tokens or private signing keys in it. The server loads and validates the file
before binding its listener, attaches `JwtEnterpriseAuthExtension`, and
advertises `enterprise_authentication` only after that succeeds.
`--with-enterprise-auth` and `--require-enterprise-auth` both fail startup with
an actionable configuration error when the env path is absent or unusable;
neither flag creates a capability-only claim.

Aldunis assertions must use the exact `audience` configured in the trust file.
Issuer, audience, signature, expiry, principal, and optional tenant claims are
verified for every request. The tenant claim is `tenant_id`. `tenkai_tenant` is
a deprecated alias: it is still accepted when `tenant_id` is absent, and the
server logs a warning. Conflicting values fail closed. Tenant-mode compositions
require a verified tenant claim and reject caller-selected tenant metadata.

Trust roots are a startup snapshot. For key rotation, publish a trust file that
temporarily contains both the old and new public keys, restart every server
replica, switch Aldunis signing to the new key, then remove the old key and
restart again after all assertions signed by it have expired. An invalid
rotation fails before listen; rollback restores the previous trust file and
restarts the server. Configuration errors identify the file and validation
problem but do not print file contents, assertions, tokens, private keys, or
customer data.

## OIDC access tokens (#468)

`tenkai-server` can verify OIDC access tokens from the deployment's
identity provider ([ADR 0031](decisions/0031-web-console.md)). Tenkai is a
resource server only: it runs no login flow, stores no passwords, and holds no
client secrets. Set `TENKAI_OIDC_CONFIG` to a TOML file. Combine it with
`TENKAI_JWT_VERIFIER_CONFIG` when the same process must also accept platform
JWT assertions; the two files must name different issuers.

```toml
issuer = "https://idp.example.com/realms/ops"   # exact `iss`; https except loopback
audience = "tenkai"                             # must appear in `aud` (string or array)
# algorithms = ["RS256", "ES256"]               # default; `none` and HS* are never accepted
# jwks_uri = "https://idp.example.com/..."      # skip discovery
# jwks_file = "/etc/tenkai/jwks.json"           # air-gapped: static keys, no network
# clock_skew_secs = 60
# jwks_refresh_secs = 600

[client]                     # optional; served at GET /v1/auth/oidc for the console
client_id = "tenkai-console" # public client (Authorization Code + PKCE)
# display_name = "Example Org" # sign-in label; clients fall back to the issuer host
scopes = ["openid", "groups"]
# connect_origins = ["https://login.example.net"] # token endpoint on another origin

[grants]
claim = "groups"             # string or array claim holding group/role values
# tenant_claim = "tenant_id" # required on tenant-mode hubs; refuse tokens without it on tenant routes

[[grants.rules]]
value = "tenkai-admins"
capabilities = ["read", "management"]

[[grants.rules]]
value = "prod-operators"
capabilities = ["management"]
environment = "prod"         # confine management to one environment

[[grants.rules]]
value = "ci-publishers"
capabilities = ["publish"]
channels = ["stable"]        # confine promote; publish stays catalog-wide
kind = "service"             # CI client; default remains human
```

Behavior:

- For a worked example with Keycloak, including the identity-provider side,
  see [sign in to the web console with Keycloak](console-sign-in-with-keycloak.md).
- For a customer LDAP or Active Directory, federate it through a site-local
  OIDC provider. Tenkai never handles directory passwords
  ([sign in against a customer directory](directory-sign-in.md)).
- A missing, unknown, expired, or otherwise rejected credential gets **401**
  with `WWW-Authenticate: Bearer` (`error="invalid_token"` when a token was
  sent), so clients ask for new credentials. A valid credential that may not
  be used (no matching grant, grants for more than one environment, a missing
  required tenant claim, or a missing capability or environment scope) gets
  **403**. Response bodies do not
  say which check failed.
- Clients send the access token as `Authorization: Bearer`. A compact-JWS
  bearer is offered to the extension; configured community tokens still take
  precedence.
- Without `jwks_uri` or `jwks_file`, the server reads
  `<issuer>/.well-known/openid-configuration` once at startup and requires its
  `issuer` to match exactly. Startup fails closed when no usable signing key
  loads.
- Keys refresh in a background thread every `jwks_refresh_secs`, and when a
  token names an unknown `kid` (at most once per 30 seconds). That token is
  refused; a refresh failure keeps the previous keys. Request authentication
  never performs network I/O.
- Tenant comes from `grants.tenant_claim` (prefer `tenant_id`). Tenant-mode
  hosts refuse to start without that mapping, and tenant-scoped routes refuse
  tokens that do not resolve a tenant.
- Grants come only from `grants.rules`. A token matching no rule authenticates
  but has no delivery capability. Rules with `environment` bind management to
  that environment exactly like an environment-scoped management token, unless
  another rule already grants fleet management. Rules for more than one
  environment are refused. Rules with `channels` bind promote to those
  channel names (unioned across matching rules) unless a matching rule already
  grants fleet management. Publish ignores channel bindings. `kind = "service"`
  sets the principal kind to service; the default remains human. Runtime
  principals still cannot call management lifecycle.
- The principal is `<sub>@<iss>` in audit records.
- `GET /v1/auth/oidc` is unauthenticated and returns only `issuer`,
  `audience`, `client_id`, `scopes`, and `display_name` when set; it is 404
  when no `[client]` is set.
- The console's Content-Security-Policy allows the browser to call the issuer's
  origin. If the provider's token endpoint is on another origin, list it in
  `[client] connect_origins` (https, or http on loopback, and no path); it is never served
  to clients.

### First administrator

Administrators are not records in Tenkai's store. A person administers the
fleet when their token matches a grant rule with `management` and no
`environment`, so the first administrator exists as soon as that rule is in
the OIDC config and the person is in that group. Nothing has to be created
on first start, and no long-lived token is handed out for it.

1. Create the administrator group in the identity provider, for example
   `tenkai-admins`, and add the first person.
2. Map it in the config:

   ```toml
   [[grants.rules]]
   value = "tenkai-admins"
   capabilities = ["read", "management"]
   ```

3. Start the server and check the startup line:

   ```text
   tenkai.auth first_administrator=configured claim=groups values=tenkai-admins
   ```

   `first_administrator=missing` means no rule gives fleet management, so
   only `TENKAI_MANAGEMENT_TOKEN` can administer the server. The same
   status is on the unauthenticated `GET /healthz` as
   `"first_administrator": "configured"` or `"missing"` (`missing` without
   OIDC), so a console can show first-run guidance before sign-in. It names
   no claim, rule or identity, and is absent while the server is still
   starting.
4. Sign in (`tenkaictl login`, or the web console) and confirm a management
   read such as `tenkaictl --target remote fleet status`.

Keep `TENKAI_MANAGEMENT_TOKEN` in the secret store as the break-glass
credential, not for day-to-day administration. Every management mutation
records the authenticated principal in the audit log, so the first
administrator's actions are attributable from the first request.

### Stored grant rules

Grant rules can also live in the hub's store instead of the config file,
so the first administrator can be set up, and administration changed,
without editing the file and restarting every replica (#836). The
`[grants]` section may then list no rules at all.

- The effective rules are the file's plus the stored ones. The file stays
  authoritative for what it names: a stored rule may not use a claim value
  the file declares, and if the file gains a value later, the stored rule
  for it is ignored.
- For a token the file grants anything, stored rules only add. The file's
  matching rules are merged first; then each matching stored rule applies
  only if the grant with it still has every capability, the same principal
  kind (`human` or `service`), the same or no environment, and no channel
  or product binding the grant left open.
  A stored rule that fails this is skipped for that token, and the server
  logs `OIDC stored grant rule ... ignored` once per rule. So a stored rule for another
  group cannot lock out, relabel, or confine a member of a group the file
  declares. Tokens the file grants nothing merge stored rules as the file's
  merge its own: matching two environments is refused with `403`.
- There is one stored rule per claim value, at most 256. Each records who
  created it, when, and why. The store keeps a generation that grows with
  every change; every replica checks it every 5 seconds and reloads the
  rules when it moved, and the replica that made a change applies it at
  once: the change reads the rules back in its own transaction (#848). A
  change whose write fails may still have committed, so the replica that
  tried it applies no stored rules, and `/readyz` reports it not ready,
  until it reads the rules again (at once if the store answers, else at
  the next check). Stored rules sit in the hub-wide tables on PostgreSQL, so every
  replica shares them.
- `first_administrator` on `/healthz` and in the startup line counts stored
  rules too (`stored_rules=` on the startup line).
- Each stored rule is read on its own (#850). A row this release cannot
  read (a newer stored format, or a rule field it does not know) or a rule
  that fails its checks (a capability or kind it does not know) is
  withheld: this replica does not apply it, logs
  `tenkai.auth stored_grant_rule=<value> applied=false detail=...` when the
  rules change, and counts it in `stored_grant_rules_withheld` on
  `/healthz`. The other stored rules still apply and readiness is not
  affected. Withholding only removes grants: a token the file grants
  nothing that matches a withheld claim value is refused with `403` on
  that replica, since the withheld rule might have confined what the other
  rules give it. A token the file grants keeps the file's grant.
- Rolling deploys: releases before this one ignore stored rules. Change
  stored rules only once every replica runs a release with this change,
  or a request on an older replica will not see them. The console's
  first-run form uses the API below; use it only once every replica runs
  this release. Rows keep the shape releases before #850 read, so those
  replicas still read every rule a newer replica stores; but they stop
  applying all stored rules on one row they cannot read, so a new stored
  format or rule field waits until every replica reads rows one at a time.

Manage them over HTTP (#837):

- `GET /v1/grant-rules` lists the stored rules with their `generation`,
  who created each, when and why, and `declared_by_config` for a rule the
  file now overrides. `applied` is `false`, with a `not_applied_reason`,
  for a rule the file overrides or that fails this release's checks;
  `unreadable` lists the `value` and `reason` of each row this release
  cannot read. `DELETE` removes any of them by `value`.
- `POST /v1/grant-rules` with `{"rule": {"value": ..., "capabilities":
  [...], ...}, "reason": ..., "generation": ...}` stores one rule (the same
  fields as a `[[grants.rules]]` entry) and answers `201` with the new
  list. `DELETE /v1/grant-rules` with `{"value": ..., "reason": ...,
  "generation": ...}` removes one.
- A change names the `generation` it listed and is refused with `409` when
  the rules changed since. When the rules already hold the change, as when
  a retry follows a change that committed, the `409` says so. A claim
  value the file declares is refused with `400`; one already stored with
  `409`. A change answers `201`/`200` once it commits; a `503` means its
  write failed and may still have committed, so list the rules before
  retrying.
- Listing and every change need fleet management: the
  `TENKAI_MANAGEMENT_TOKEN` for that request (recorded as `management`,
  never stored or logged), or a signed-in principal whose grants give
  management with no environment. A signed-in user without it, an
  environment-scoped credential, a tenant credential and an agent are
  refused, and nothing is written.
- Each change is audited before and after it is written
  (`grant_rule.create.*`, `grant_rule.remove.*`) with its principal and
  reason (`grant-rule/<value> reason=<reason>`): `requested`, then
  `completed` once it commits, `refused` when nothing was written, or
  `failed` when the write failed and may still have committed.

To set up the first administrator with no rule in the file, list with the
management token, then create `tenkai-admins` with `read` and
`management` using the listed generation. `/healthz` reports
`first_administrator: "configured"` on that replica at once and on the
others within 5 seconds.


### CLI sign-in

`tenkaictl login` is an OIDC client of the same public `[client]` the console
uses. It discovers `GET /v1/auth/oidc`, opens Authorization Code + PKCE in a
browser, and waits on a loopback redirect `http://127.0.0.1:<port>/callback`.
The access and refresh tokens are stored in `$XDG_CONFIG_HOME/tenkai/tokens.json`
(mode `0600`), keyed by server URL, with the issuer and token endpoint pinned
at login. Refresh talks only to that pinned endpoint.

```sh
export TENKAI_SERVER_URL=https://tenkai.example.internal
tenkaictl login --callback-port 9876
tenkaictl --target remote env list
tenkaictl logout
```

Register `http://127.0.0.1:9876/callback` on the public client (or pass a
registered `--callback-port`). `--client-id` / `TENKAI_OIDC_CLIENT_ID` /
`TENKAI_CLIENT_ID` overrides the discovered id. `--no-browser` prints the
authorization URL. Remote commands use `TENKAI_MANAGEMENT_TOKEN` when it is
set; otherwise they use the saved login. The server still requires the fleet
management token at process start; that token remains the break-glass bearer.

### CI client-credentials login

CI jobs use a confidential OIDC client and
`tenkaictl login --client-credentials`. The secret is `TENKAI_OIDC_CLIENT_SECRET`
in the runner environment only. It is never an argv flag, never written to
`tokens.json`, and never configured on `tenkai-server`. Tenkai stays a resource
server: it verifies access tokens and holds no client secrets.

```sh
export TENKAI_SERVER_URL=https://tenkai.example.internal
export TENKAI_OIDC_CLIENT_ID=tenkai-ci
export TENKAI_OIDC_CLIENT_SECRET=replace-from-secret-store
tenkaictl login --client-credentials
tenkaictl --target remote publish tenkai.toml \
  --signature tenkai.sig.json \
  --trust-roots /etc/tenkai/release-trust.toml
tenkaictl --target remote promote product@1.2.3 stable
```

Client-credentials tokens typically have no refresh token. When the saved
access token expires, `tenkaictl` re-requests with `TENKAI_OIDC_CLIENT_SECRET`
still in the environment; otherwise run login again. Grant the CI client
`capabilities = ["publish"]` and optional `channels` / `kind = "service"` as
above. Do not put the fleet `TENKAI_MANAGEMENT_TOKEN` on the runner.

Release signing is unchanged. Hold the 32-byte Ed25519 seed as an
environment-protected CI secret, sign the digest-pinned manifest in the job,
and keep only public trust roots on the server. Rotate by overlapping the old
and new public keys in the trust-root file, then removing the old key after
signatures signed by it have been published; see
[release signing](release-signing.md). Do not use
`--allow-unsigned-development` in CI. A sample workflow is
[examples/ci-publish](../examples/ci-publish/).
