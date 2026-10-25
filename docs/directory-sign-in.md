# Sign in against a customer directory

Disconnected sites often have only an LDAP or Active Directory. Tenkai stays a
resource server: it never binds to the directory, never stores directory
passwords, and never runs a login form. Operators sign in at a **site-local
OIDC provider** that federates to the directory. Tenkai verifies the access
token and maps a group claim through the existing `[grants]` rules.

Standalone Tenkai needs no other platform product. The site-local OIDC
provider is a customer-side dependency, the same class of software as a TLS
proxy. Revisit a native directory bind only if a site cannot run an OIDC
provider.

## 1. Federate the directory

Point the site-local issuer at the customer directory (LDAP/AD group
membership, or the provider's built-in user federation). Configure it to put
**plain group names** in the access-token claim Tenkai will read, for example
`tenkai-admins`, not a distinguished name.

A worked local issuer is
[sign in to the web console with Keycloak](console-sign-in-with-keycloak.md).
The same mapping applies to any OIDC provider that can federate a directory.

## 2. Map groups in Tenkai

Keep Tenkai's trust file public. Do not put directory credentials in it.

```toml
issuer = "https://idp.example.internal/realms/ops"
audience = "tenkai"
# Isolated site: pin keys, skip discovery. Connected sites omit jwks_file.
# jwks_file = "/etc/tenkai/oidc-jwks.json"

[client]
client_id = "tenkai-console"
scopes = ["openid", "groups"]

[grants]
claim = "groups"

[[grants.rules]]
value = "tenkai-admins"
capabilities = ["read", "management"]
```

`TENKAI_OIDC_CONFIG` and the rest of the OIDC contract are unchanged
([configure server authentication](configure-server-authentication.md#oidc-access-tokens-468)).
Existing JWT trust files and short-lived service tokens keep working alongside
this path when their issuers differ.

## 3. Isolated network

On a host with no route out, use `jwks_file` (or a loopback issuer). Tenkai
loads keys at startup and never performs network I/O on the request path.
Discovery against a provider that is down fails closed before listen.

CI covers this as part of
[isolated-network conformance](offline-bundles.md#isolated-network-conformance):
directory login and group mapping against a static JWKS, and a directory or
loopback-issuer outage that fails closed.

## Failure behaviour

| Situation | What happens |
| --- | --- |
| Directory down | The site-local issuer refuses login. Tenkai never sees a token and rejects the request (401). |
| Issuer down at startup | Discovery or JWKS load fails; the server does not listen. |
| Issuer down after start | Already-loaded keys still verify unexpired tokens. Unknown `kid` is refused. Refresh failure keeps the last good keys. |
| User not in a mapped group | Token verifies; grants are empty (403 on gated routes). |
| No other platform product | Tenkai plus the site-local issuer is enough. |

Keep `TENKAI_MANAGEMENT_TOKEN` in the secret store as break-glass access. It is
not a directory credential.
