# ADR 0046: Workload identity and peer policy from dependency bindings

- Status: Proposed
- Date: 2026-11-06
- Issue: [#1023](https://github.com/Sannrox/tenkai/issues/1023)
- Owner: Tenkai maintainers
- Builds on: [ADR 0043](0043-product-dependencies.md),
  [ADR 0044](0044-product-instances-and-dependency-bindings.md),
  [ADR 0045](0045-sealed-secrets.md)
- Related: [#1010](https://github.com/Sannrox/tenkai/issues/1010),
  [runtime protocol v1](../runtime-protocol-v1.md)

## Context

Tenkai's own plane is zero trust: releases and approvals are signed, and
environment runtimes enroll and then call the server with short-lived client
certificates, optionally attested. Network location grants nothing.

The products Tenkai deploys get none of this. Two instances that call each
other trust each other through a shared key and a network policy, and each
product suite that wants mutual TLS builds its own certificate setup in the
cluster. In practice they skip it, and a caller is trusted for being
reachable.

Tenkai already knows the edges. A release requires contracts (ADR 0043), and
a binding names which provider instance serves which dependent instance
(ADR 0044). It does not turn those edges into identity or authorization.

## Decision

### 1. A release declares its certificate needs

```toml
[deploy.identity]
certificate = "server"   # "server", "client" or "both"
```

The field is part of the signed manifest. A release without it gets no
certificate and behaves as today.

### 2. The environment issues workload certificates

Each environment runtime holds an issuing key for that environment. Like the
sealing key (ADR 0045), it never leaves the environment, and the server stores
only the public trust bundle. At apply, the runtime issues each instance that
declares a need a short-lived certificate:

- The identity names the environment and the instance (ADR 0044), for example
  `tenkai://<environment>/<instance>`, as a URI subject alternative name. A
  server certificate also carries the DNS names the release declares for its
  Service.
- The certificate, its key and the environment trust bundle are delivered the
  way a sealed secret is written (ADR 0045 §4): a Kubernetes Secret in the
  instance's namespace, or 0600 files for a host release. The key exists only
  in the runtime's memory and in the target.
- Lifetime is short, 24 hours by default. The runtime renews at two thirds of
  the lifetime through the same apply path. Renewal writes a new certificate
  without a restart. A product that cannot reload certificates declares it,
  and gets a same-version restart instead (ADR 0016).

Several runtimes of one environment share the issuing key by the same
per-runtime wrapping as a sealed value (ADR 0045 §1 and §5), so any of them
can issue and none needs the server to.

Issuance is idempotent per instance and lease generation: a retry after a
crash reissues for the same identity and never leaves two live keys for one
instance in the target.

### 3. Peer policy comes from bindings

A binding is the authorization. When dependent instance D is bound to
provider instance P for a contract, or is satisfied by P as the only provider
(ADR 0044 §3), then:

- P may accept D's identity as a client for that contract;
- D may accept P's identity as the server for that contract.

Nothing else is allowed by Tenkai. An edge that is not in the graph has no
grant, even if the network lets it through.

### 4. The dependency document carries peers, not credentials

The dependency document (ADR 0043 §6) gains, for each contract, the
provider's identity, and for each instance, the identities allowed to call
it. It still carries no keys, secrets or endpoints. The certificate and key
arrive separately (section 2). Changing a binding re-renders both sides in
the same plan, so a withdrawn binding withdraws its grant.

### 5. Products enforce, Tenkai does not proxy

The product terminates TLS, requires and verifies the peer certificate
against the trust bundle, and checks the peer identity against its peer
document. Tenkai runs no sidecar, proxy or mesh, and changes no traffic.

### 6. Rotation without outage

The trust bundle can hold the current and the next issuing key. Rotating the
issuing key adds the next key to every bundle, then issues from it, then
removes the old key once every certificate signed by it has expired. Each
step is a plan, and no step makes a valid peer fail.

## Out of scope

- A service mesh, sidecars, or traffic encryption by Tenkai.
- Network policy generation. A later decision may derive policies from the
  same edges.
- Identity for human users or tenants.
- Identity across environments.
- External certificate authorities. A later adapter can sign with one in the
  same place the runtime signs today.

## Consequences

- A product suite gets mutual TLS between its instances without building a
  certificate setup, and its authorization matches the graph that Tenkai
  shows and approves.
- An edge that is not bound cannot be authorized by Tenkai, so a missing
  binding fails closed.
- The dependency view (#1010) can show each edge's identities, its
  authorization, and its certificate expiry.
- Losing every runtime of an environment loses its issuing key. A new runtime
  creates a new one, and the next plan rotates every instance to it.
- Rolling compatibility: runtimes advertise a `workload_identity` capability.
  A plan that issues certificates is offered only to runtimes that advertise
  it, and a server that predates it ignores the declaration and issues
  nothing. Declare `[deploy.identity]` only once every server and runtime of
  the environment understands it.

## Alternatives considered

- **Each product suite runs its own certificate setup.** Rejected as the
  default: it repeats the same work in every suite, and its authorization is
  not tied to the graph Tenkai approves.
- **Authorize by shared client secrets.** Rejected: a shared secret proves
  possession, not identity, and either side can present it.
- **Tenkai runs a mesh.** Rejected: it adds a runtime to every workload and
  takes over traffic Tenkai does not own.
- **The server issues certificates.** Rejected: compromising the server
  would then let an attacker mint any workload identity.
