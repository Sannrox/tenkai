# ADR 0047: Host identity as the default operator sign-in

- Status: Proposed
- Date: 2026-11-06
- Issue: [#997](https://github.com/Sannrox/tenkai/issues/997)
- Owner: Tenkai maintainers
- Amends: [ADR 0004](0004-authenticated-request-context.md) (credential kinds),
  [ADR 0031](0031-web-console.md) (console sign-in)
- Related: [ADR 0006](0006-federated-identity.md),
  [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md),
  [#995](https://github.com/Sannrox/tenkai/issues/995),
  [authenticated request context](../auth-request-context.md),
  [configure server authentication](../configure-server-authentication.md),
  [plan approval](../plan-approval.md)

## Context

A fresh server install has no human sign-in. Operators use the management
token from a root-only env file (#995). The web console at `/ui/` needs an
OIDC provider that a first install usually does not have. Asking for an
identity provider before Tenkai can be used makes the first install heavier.
An identity provider that Tenkai itself delivers would lock operators out
exactly when Tenkai is needed to repair it.

ADR 0004 already requires a principal on every authenticated call.
`CommunityTokenAuthenticator` maps bearer tokens. OIDC maps a group claim to
the same grants. Neither reuses the identity the operator already used to log
in to the host.

The server runs unprivileged (ADR 0041). PAM would need a root-side helper or
membership of `shadow` to verify another user's password, and it would load
host-configured native modules into the server. SSH already applied the host's
account policy when the operator logged in.

## Decision

The default identity for a single-host Linux install is the host's own: the
Linux user and their groups, taken from kernel peer credentials on a Unix
socket.

### 1. One Unix socket

`tenkai-server` also listens on `/run/tenkai/tenkai.sock`, owned
`root:tenkai-viewer` mode `0660`. `tenkai-viewer` is the socket-access group,
not a role ceiling: install puts every mapped user in it, including operators
and admins. Role groups add capabilities; they do not replace viewer
membership. A user in only `tenkai-operator` or `tenkai-admin` cannot connect
until they are also in `tenkai-viewer`.

Console and API already share one HTTP origin (ADR 0031); authorization is the
peer, not which socket, so there is one socket.

TCP loopback stays enabled by default. The management token remains the
automation and break-glass path (#995 `client.toml`). Disabling TCP is an
explicit configuration change.

Linux is the first platform (`SO_PEERCRED`). Other kernels keep today's token
and OIDC paths until a later Issue names an equivalent.

### 2. Peer credentials are a credential kind

Authenticated request context (ADR 0004) gains a third credential kind: peer
credentials, only on the Unix socket. A Unix connection without readable peer
credentials is refused. TCP still requires a bearer or an assertion. Empty
bearer on TCP still fails closed.

The authenticator:

1. Reads `SO_PEERCRED` (uid; the connecting process's credentials at
   `connect(2)`).
2. Resolves the uid to a passwd entry and that user's groups from NSS on
   **every request**. There is no cache. If the passwd or group database is
   unavailable, or the uid has no passwd entry, the request is refused.
3. Maps the user's groups through the grant rules below. A user in no mapped
   group is refused, not authenticated with empty grants.
4. Builds `PrincipalKind::Human` with a stable id derived from the uid (for
   example `host:uid:<n>`), never from a caller-selected header.

The server stays unprivileged. Peer credentials need no root.

Directory users still work: NSS is the lookup, so LDAP or SSSD users and
groups behave like local ones.

### 3. OS groups map to the same grants as OIDC

A root-owned mapping file uses the same `[[grants.rules]]` shape as OIDC
(`value`, `capabilities`, optional `environment`). Default groups, written by
the server install:

| OS group | Grant | Effective today |
| --- | --- | --- |
| `tenkai-viewer` | `read` | `read` |
| `tenkai-operator` | `management` | `read`, `management`, `publish` |
| `tenkai-admin` | `management` | same as operator |

`management` already implies `read` and `publish`
(`AuthenticatedRequestContext::has_delivery_capability`). Listing `publish` on
admin would not make it stronger. The three group names stay so a site can
later give admin extra rules (for example fleet vs one environment) without
renaming accounts. This ADR does not change that implication.

When OIDC is enabled, those rules apply to both the OIDC group claim and the
OS groups, so switching the identity source does not rewrite who may do what.
If OIDC is not configured, the mapping file is the only grant source for
peer-credential principals.

A host identity never grants apply authority. Plans are still approved only by
signatures from offline keys under the host's quorum policy.

### 4. CLI uses the socket by default

On the host, when `/run/tenkai/tenkai.sock` exists, `tenkaictl` uses it and
sends no token. An operator in `tenkai-operator` can run `tenkaictl status`
without the token or `sudo`. Flags, environment variables, and `client.toml`
still override, so automation that uses the token file keeps working.

### 5. Console sign-in is the SSH login

The console remains a public-API client (ADR 0031). There are no
console-private routes.

Reached over SSH stream-local forwarding:

```sh
ssh -L 8080:/run/tenkai/tenkai.sock <host>
```

With OpenSSH privilege separation (the default for many years), the forwarded
connection is opened as the authenticated user, so `SO_PEERCRED` is that user.
OpenSSH 7.4 and later refuse Unix forwarding when privilege separation is off,
so the unsafe root-forwarding case does not arise.

The local forwarded port is as privileged as the SSH session. Any process on
the workstation that can connect to it acts as that user. This path is for a
single-user workstation. Do not forward on a shared multi-user machine. Bind
only to loopback (`ssh -L` default).

Peer credentials make the connection ambient: a request through the tunnel
carries the SSH user's authority without a Bearer header. ADR 0031 omitted
CSRF tokens because a cross-site page cannot set `Authorization`. That
justification does not hold here. For peer-credential requests:

- `Host` must be a loopback authority (`127.0.0.1`, `localhost`, or `[::1]`,
  with or without a port). Any other `Host` is refused, including a name that
  has been rebound to loopback.
- If `Origin` (or `Referer` when `Origin` is absent) is present, it must be a
  loopback console origin. Any other origin is refused.
- CLI clients send a loopback `Host` and no `Origin`, and are allowed.
- Mutating routes still require JSON. A cross-site HTML form cannot satisfy
  that, and a cross-site `fetch` with JSON is a CORS preflight the server
  does not allow.

Sign-in is the SSH login, which can be key-only and hardware-backed. The
browser never sees a password page, holds no cookie, and holds no durable
credential. The console shows the user, groups, and `source=host` from the
authenticated principal. Sign-out is closing the tunnel.

### 6. Audit

Every request records the uid, user name, the groups it was authorized by, and
`source=host`. Audit must not include passwords, tokens, or raw credential
bytes.

### 7. Upgrade path

OIDC stays the option for central identity, browser access without SSH, or
many hubs. The management token stays for automation and break-glass. Enabling
OIDC does not disable the Unix socket or the token.

## Out of scope

- PAM, and a root-side PAM broker. Add them only when a deployment needs
  browser sign-in without SSH and has no OIDC provider; the broker would be
  built like the host applier.
- Darwin or Windows peer-credential equivalents.
- Disabling TCP loopback by default.
- Applying a plan without the offline approval key.
- Implementation of the socket, mapping file, CLI default, or console chrome
  in this ADR. Those follow in later Issues.

## Consequences

- A fresh Linux server install can be operated by OS group membership, without
  an identity provider and without sharing the management token with humans.
- Compromising a mapped OS account is compromising that Tenkai role, bounded
  by the host's SSH and account policy. Compromising the unprivileged server
  still cannot mint peer credentials for another uid.
- The SSH forward's local port is the operator's Tenkai session. A shared
  workstation, a rebound hostname, or a browser tab on another origin must not
  be able to use it: single-user workstation, loopback bind, loopback `Host`,
  Origin check, JSON mutations.
- Rolling compatibility: a server that does not listen on the Unix socket
  ignores this path. A client that does not know the socket keeps using
  `client.toml` or the token. Hosts without the socket behave as today.
- No store schema change. The mapping file is host configuration.

## Alternatives considered

- **PAM as the default.** Rejected: an unprivileged server cannot verify
  another user's password without reading `/etc/shadow` or a new root-side
  helper; PAM modules are native code loaded into the server; SSH already
  applied PAM at login. Kept as a later option for browser sign-in without
  SSH at a site with no OIDC provider.
- **OIDC required on first install.** Rejected: it makes the first install
  depend on an identity provider, including one Tenkai might itself deliver.
- **Two sockets (`api.sock` and `ui.sock`).** Rejected: they would share
  ownership and mode; the HTTP origin is already one (ADR 0031); authorization
  is the peer.
- **Cache group lookups.** Rejected: a short TTL would delay a group removal;
  NSS on a local host is cheap; unavailable NSS must fail closed, which a
  stale cache would hide.
- **Disable TCP once the socket exists.** Rejected: #995 automation and the
  management token would break. TCP stays until an operator turns it off.
- **Authenticate with empty grants when the user is in no mapped group.**
  Rejected for this path: a host identity with no role is a refusal, not a
  signed-in principal who cannot act. OIDC tokens that match no rule keep
  today's authenticate-then-403 behaviour.
- **A second client credential on the forwarded port.** Rejected: it reintroduces
  a secret the operator must copy, which this design removes. The trust
  boundary is the workstation that holds the SSH session; CSRF is handled by
  the Origin check and JSON mutating routes, not by another token.
- **Separate socket groups per role.** Rejected: the kernel checks one owning
  group. POSIX ACLs would work but are extra host configuration. One access
  group plus role groups is the usual Unix split.
- **Make `management` stop implying `publish` so admin is stronger.** Rejected
  here: that is a contract change for every authenticator, not a host-identity
  default. Operator and admin grant the same capabilities until a later Issue
  splits them.
