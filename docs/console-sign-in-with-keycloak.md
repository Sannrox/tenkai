# Sign in to the web console with Keycloak

In this tutorial you run Keycloak and `tenkai-server` on your machine, connect
them, and sign in to the web console at `/ui/` as a Keycloak user whose group
grants delivery access. It takes about fifteen minutes. Everything runs on
loopback, so plain `http` is allowed; a production deployment uses `https` (see
[Going to production](#going-to-production)).

You need Docker, a `tenkai-server` release binary (or a source build with
`-p tenkai-server --features ui`), and a browser.

## 1. Start Keycloak

```sh
docker run -d --name tenkai-keycloak -p 127.0.0.1:8081:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.4 start-dev
```

Wait until `http://127.0.0.1:8081/realms/master` answers.

## 2. Create the realm, client, and user

The console is a public client: it runs in the browser, holds no secret, and
uses Authorization Code with PKCE. Tenkai only verifies the access tokens.
Save this as `keycloak-setup.sh`:

```sh
set -eu
KC=/opt/keycloak/bin/kcadm.sh
CONSOLE=http://127.0.0.1:8080
$KC config credentials --server http://localhost:8080 --realm master --user admin --password admin
$KC create realms -s realm=ops -s enabled=true

# Public client for the console: Authorization Code + PKCE only.
CID=$($KC create clients -r ops -i \
  -s clientId=tenkai-console -s publicClient=true -s standardFlowEnabled=true \
  -s directAccessGrantsEnabled=false -s implicitFlowEnabled=false \
  -s 'redirectUris=["'$CONSOLE'/ui/auth/callback"]' \
  -s 'webOrigins=["'$CONSOLE'"]' \
  -s 'attributes={"pkce.code.challenge.method":"S256","post.logout.redirect.uris":"'$CONSOLE'/ui/"}')

# Access tokens must carry Tenkai's audience.
$KC create clients/$CID/protocol-mappers/models -r ops \
  -s name=tenkai-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
  -s 'config={"included.custom.audience":"tenkai","access.token.claim":"true","id.token.claim":"false"}'

# A "groups" scope whose claim lists plain group names.
SID=$($KC create client-scopes -r ops -i -s name=groups -s protocol=openid-connect \
  -s 'attributes={"include.in.token.scope":"true"}')
$KC create client-scopes/$SID/protocol-mappers/models -r ops \
  -s name=groups -s protocol=openid-connect -s protocolMapper=oidc-group-membership-mapper \
  -s 'config={"claim.name":"groups","full.path":"false","access.token.claim":"true","id.token.claim":"true","userinfo.token.claim":"true"}'
$KC update clients/$CID/default-client-scopes/$SID -r ops

# A group Tenkai maps to grants, and a user in it.
$KC create groups -r ops -s name=tenkai-admins
$KC create users -r ops -s username=alice -s enabled=true -s email=alice@example.com \
  -s emailVerified=true -s firstName=Alice -s lastName=Example
$KC set-password -r ops --username alice --new-password alice-password
USER_ID=$($KC get users -r ops -q username=alice --fields id --format csv --noquotes)
GROUP_ID=$($KC get groups -r ops -q search=tenkai-admins --fields id --format csv --noquotes)
$KC update users/$USER_ID/groups/$GROUP_ID -r ops -s realm=ops -s userId=$USER_ID -s groupId=$GROUP_ID -n
```

Run it inside the container:

```sh
docker cp keycloak-setup.sh tenkai-keycloak:/tmp/keycloak-setup.sh
docker exec tenkai-keycloak bash /tmp/keycloak-setup.sh
```

What each part does, in the Keycloak admin console's terms (`Clients` →
`tenkai-console`):

| Setting | Value | Why |
| --- | --- | --- |
| Client authentication | Off | Public client; the browser cannot keep a secret |
| Standard flow / PKCE method | On / `S256` | Authorization Code with PKCE |
| Valid redirect URIs | `<console URL>/ui/auth/callback` | Where Keycloak returns after login |
| Valid post logout redirect URIs | `<console URL>/ui/` | Where sign-out returns |
| Web origins | The console's origin | The browser calls Keycloak's discovery and token endpoints directly (CORS) |
| Audience mapper | `tenkai` in the access token | Tenkai rejects tokens whose `aud` lacks its audience |
| Group membership mapper | claim `groups`, full group path off | Grants match plain names such as `tenkai-admins`, not `/tenkai-admins` |

## 3. Configure Tenkai

Save as `oidc.toml`:

```toml
issuer = "http://127.0.0.1:8081/realms/ops"
audience = "tenkai"

[client]
client_id = "tenkai-console"
display_name = "Example Org"
scopes = ["openid", "groups"]

[grants]
claim = "groups"

[[grants.rules]]
value = "tenkai-admins"
capabilities = ["read", "management"]
```

`issuer` must equal the `issuer` in
`http://127.0.0.1:8081/realms/ops/.well-known/openid-configuration` exactly.
The full format is in
[OIDC access tokens](configure-server-authentication.md#oidc-access-tokens-468).

## 4. Start the server

```sh
export TENKAI_MANAGEMENT_TOKEN='replace-from-secret-store'   # always required; break-glass access
export TENKAI_OIDC_CONFIG=$PWD/oidc.toml
tenkai-server --database .tenkai-state/tenkai.db
```

The server reads Keycloak's discovery document and signing keys at startup and
logs `tenkai-server console at /ui/`. Check what the console will use:

```sh
curl -s http://127.0.0.1:8080/v1/auth/oidc
```

## 5. Sign in

Open `http://127.0.0.1:8080/` and choose **Sign in with Example Org**. Log in
as `alice` / `alice-password`. Keycloak returns you to the console, signed in
as `alice`. **Access** shows the method `OIDC via 127.0.0.1:8081`, and the
delivery pages load because `tenkai-admins` grants `read` and `management`.

The console keeps tokens in memory only and renews them before they expire
while the tab is open. Reloading the page signs in again.

## Going to production

- Serve Keycloak and Tenkai over `https`; Tenkai refuses a non-loopback `http`
  issuer. Put `tenkai-server` behind a TLS reverse proxy
  ([run tenkai-server](run-tenkai-server.md)).
- Set Keycloak's hostname (`KC_HOSTNAME`) so the issuer is stable and matches
  `issuer` in `oidc.toml` regardless of how Keycloak is reached.
- Register the public console URL, for example
  `https://tenkai.example.com/ui/auth/callback`, as the redirect URI and its
  origin as the web origin. Sub-path deployments use
  `https://example.com/tenkai/ui/auth/callback`.
- Map real groups to the narrowest capabilities; a rule with `environment`
  confines management to one environment.
- If Keycloak's token endpoint is on a different origin from the issuer, add it
  to `[client] connect_origins`.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Server exits: `OIDC issuer must use https` | Non-loopback `http` issuer; use `https` |
| Server exits while loading keys, or issuer mismatch | `issuer` differs from the discovery document; set `KC_HOSTNAME` and copy the issuer exactly |
| Keycloak: `Invalid parameter: redirect_uri` | Redirect URI is not `<console URL>/ui/auth/callback` exactly |
| Browser console: CORS error on the token request | Console origin missing from the client's Web origins |
| Browser console: request blocked by Content-Security-Policy | Token endpoint on another origin; add it to `connect_origins` |
| Console returns to sign-in with "Session expired" right after login | The server rejected the token (401): usually the access token's `aud` lacks `tenkai`; add the audience mapper. Also check the issuer matches exactly |
| Console says "Signed in, no access" | The token is valid but grants nothing usable (403), for example groups that map to more than one environment, or no matching rule: the user is not in the group, the `groups` scope is not a default scope of the client, or full group path is on (the claim must say `tenkai-admins`, not `/tenkai-admins`) |
