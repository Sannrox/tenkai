# Configure `tenkai-server` authentication

`tenkai-server` authenticates every management request before Tenkai's own
delivery authorization runs. The server always requires the fleet management
token `TENKAI_MANAGEMENT_TOKEN` and refuses to start without it. On top of that
token, pick one mode for people and automation, then configure it as below. Runtime tokens for `tenkai-runtime` are configured
separately in every mode ([run tenkai-server](run-tenkai-server.md)). The
contract behind all modes is [authenticated request context](auth-request-context.md).

| Mode | Use when | Configure with |
| --- | --- | --- |
| Community bearer tokens only | One team, shared secrets from a secret store | `TENKAI_MANAGEMENT_TOKEN`, optionally `TENKAI_ENVIRONMENT_MANAGEMENT_TOKENS` |
| Enterprise JWT assertions | A trusted gateway mints short-lived Ed25519-signed assertions, optionally with tenant claims | `TENKAI_JWT_VERIFIER_CONFIG` |
| OIDC access tokens | People sign in through your identity provider, for example with the web console or `tenkaictl login` | `TENKAI_OIDC_CONFIG` |

The JWT and OIDC modes are mutually exclusive. In both, the fleet management
token stays valid as the break-glass credential, and environment-scoped tokens
keep working; keep the fleet token in your secret store.

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
verified for every request. Tenant-mode compositions require a verified tenant
claim and reject caller-selected tenant metadata.

Trust roots are a startup snapshot. For key rotation, publish a trust file that
temporarily contains both the old and new public keys, restart every server
replica, switch Aldunis signing to the new key, then remove the old key and
restart again after all assertions signed by it have expired. An invalid
rotation fails before listen; rollback restores the previous trust file and
restarts the server. Configuration errors identify the file and validation
problem but do not print file contents, assertions, tokens, private keys, or
customer data.

## OIDC access tokens (#468)

`tenkai-server` can instead verify OIDC access tokens from the deployment's
identity provider ([ADR 0031](decisions/0031-web-console.md)). Tenkai is a
resource server only: it runs no login flow, stores no passwords, and holds no
client secrets. Set `TENKAI_OIDC_CONFIG` to a TOML file; it is mutually
exclusive with `TENKAI_JWT_VERIFIER_CONFIG`.

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
# tenant_claim = "tenant"    # required on tenant-mode hubs

[[grants.rules]]
value = "tenkai-admins"
capabilities = ["read", "management"]

[[grants.rules]]
value = "prod-operators"
capabilities = ["management"]
environment = "prod"         # confine management to one environment
```

Behavior:

- For a worked example with Keycloak, including the identity-provider side,
  see [sign in to the web console with Keycloak](console-sign-in-with-keycloak.md).
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
- Grants come only from `grants.rules`. A token matching no rule authenticates
  but has no delivery capability. Rules with `environment` bind management to
  that environment exactly like an environment-scoped management token, unless
  another rule already grants fleet management. Rules for more than one
  environment are refused.
- The principal is `<sub>@<iss>` in audit records.
- `GET /v1/auth/oidc` is unauthenticated and returns only `issuer`,
  `audience`, `client_id`, `scopes`, and `display_name` when set; it is 404
  when no `[client]` is set.
- The console's Content-Security-Policy allows the browser to call the issuer's
  origin. If the provider's token endpoint is on another origin, list it in
  `[client] connect_origins` (https, or http on loopback, and no path); it is never served
  to clients.

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
registered `--callback-port`). `--client-id` / `TENKAI_CLIENT_ID` overrides the
discovered id. `--no-browser` prints the authorization URL. Remote commands
use `TENKAI_MANAGEMENT_TOKEN` when it is set; otherwise they use the saved
login. The server still requires the fleet management token at process start;
that token remains the break-glass bearer.
