# ADR 0046: Workload identity and peer policy from dependency bindings

- Status: Accepted
- Date: 2026-11-06 (revised 2026-11-07)
- Issue: [#1023](https://github.com/Sannrox/tenkai/issues/1023)
- Owner: Tenkai maintainers
- Amends: [ADR 0016](0016-same-version-remediation.md) (restart on certificate renewal)
- Builds on: [ADR 0043](0043-product-dependencies.md),
  [ADR 0044](0044-product-instances-and-dependency-bindings.md),
  [ADR 0045](0045-sealed-secrets.md)
- Related: [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md),
  [#1010](https://github.com/Sannrox/tenkai/issues/1010),
  [#1057](https://github.com/Sannrox/tenkai/issues/1057),
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

### Threat model

The goal is that a compromised server cannot mint a workload identity or
grant a peer, the same bar ADR 0045 sets for secret values. A compromised
server controls what it sends to runtimes. Without further checks it could:

1. hand a runtime an issuing key of its own, sealed to the runtime's public
   key, so that it holds the private half of what the runtime issues from;
2. ask a runtime to issue a certificate for an identity or DNS name the
   release never declared;
3. render a peer document that grants a caller no binding allows.

Each is closed below by the runtime-side plan verification of ADR 0045 §4.

A second goal pulls the other way: certificates are short-lived, so their
renewal must never wait for something that can legitimately stay closed, such
as a signed approval, a maintenance window, a delivery hold, or the server
itself on an intermittent link. Otherwise Tenkai's own safety controls cause
the outage. The decision therefore separates what changes trust, which is an
approved plan, from what only renews it, which is a runtime duty.

## Decision

### 1. A release declares its certificate needs

```toml
[deploy.identity]
certificate = "server"        # "server", "client" or "both"
reload = "runtime"            # "runtime" or "restart"
dns_names = ["${TENKAI_INSTANCE}"]
```

The table is part of the signed manifest. A release without it gets no
certificate and behaves as today.

- `reload = "runtime"` means the product re-reads its certificate, key and
  trust bundle files while running. `"restart"` means it reads them only at
  start, which includes files mounted with `subPath` and values passed as
  environment variables.
- `dns_names` applies to server certificates. Entries are expanded per
  instance with the same substitution native Kubernetes manifests use
  (ADR 0044), so two instances of one release never share a name. A literal
  name without an instance placeholder is refused for a release that allows
  several instances.

### 2. The environment owns one issuer, created by an approved plan

Each environment has at most one issuing key. Its private half exists only
inside the environment's runtimes. The server stores the issuer's public
certificate and the key sealed to the environment's recipients exactly like a
sealed value (ADR 0045 §1), never the key itself.

- **Creation and rotation are plan steps.** A step names the issuer's public
  key fingerprint and is approved like any other step. The runtime that
  claims it verifies the plan itself (ADR 0045 §4), generates the key, and
  submits the sealed key and the public certificate. A runtime only ever
  issues from a key whose fingerprint matches the latest approved issuer
  step. A key the server supplies is therefore useless to it: the server
  cannot get its own key approved without the approvers' keys.
- **One issuer per generation.** The issuer record carries a generation, and
  the server accepts a new issuer only as a compare-and-set on the previous
  generation, in the same transaction that records the step outcome. Two
  runtimes that race to create the first issuer produce one record; the loser
  discards its key and adopts the winner's through its wrap.
- **New runtimes** receive the issuing key through the approved re-wrap step
  of ADR 0045 §5. A runtime with no wrap for the current issuer refuses to
  issue with a named, retryable reason.
- **Losing every recipient** loses the issuing key. A new runtime cannot
  recreate it silently: creating a replacement is the same approved step,
  followed by the rotation of section 7. The recovery key of ADR 0045 §7, when
  set, also wraps the issuing key.

### 3. Issuance is an approved step; renewal is a runtime duty

**Issuance** happens when a plan step first gives an instance an identity, or
changes it: a new instance, a changed `dns_names` or certificate role, a new
issuer generation, or an operator's explicit reissue after a suspected key
leak. The step names the instance, its identity and its SANs, so it is covered
by the plan digest and the runtime verifies it as in ADR 0045 §4 before
issuing. The identity is a URI subject alternative name,
`tenkai://<environment>/<instance>`; a server certificate adds the expanded
DNS names.

**Renewal** re-issues exactly what the last verified issuance granted: the
same identity, the same SANs, the same role, from the same issuer
generation, with a fresh key. It is not a plan:

- It needs no approval, and is not blocked by maintenance windows, delivery
  holds, or the server being unreachable. It only refreshes trust that
  an approved plan already granted, and it cannot widen it.
- The runtime records the granted identity alongside the certificate in the
  target, where the server cannot write. Any runtime of the environment, after
  a restart or takeover, finds the instances due for renewal from what is in
  the target, not from a timer in memory.
- It starts at two thirds of the lifetime, 24 hours by default, and retries
  until it succeeds. The runtime reports each instance's certificate expiry.
  A certificate inside its last sixth that has not been renewed is shown as
  near expiry in `status`, with the reason. Once post-deploy health (#1057)
  exists, it also reports the instance as `warning` there. Renewal does not
  depend on it.
- For a release with `reload = "restart"`, renewal finishes with a rolling
  restart of the same version and configuration, performed by the runtime
  and honouring `min_available`. This narrowly amends ADR 0016, which
  otherwise makes every restart an approved plan and rejects restarts on a
  timer: this restart only loads trust an approved plan already granted, and
  without it the product would stop serving when its certificate expires. It
  is recorded as an attempt like any other.

### 4. Certificates are written in place, under a stable name

Certificates are not sealed values: they change every renewal, and a renewal
must not roll the workload. So they do not use the content-addressed,
immutable Secrets of ADR 0045 §4.

- **Kubernetes:** one Tenkai-owned Secret per instance,
  `<instance>-tenkai-identity`, replaced in one write. It holds `cert.pem`,
  `key.pem` and `ca.pem` (the trust bundle). The release receives the name as
  `tenkai.identity.secret`. Kubernetes refreshes files of a mounted Secret in
  place, so a product with `reload = "runtime"` sees the new files without a
  rollout. The pod template carries the issuer generation, not the
  certificate digest, so only an issuer rotation that needs a restart rolls
  pods.
- **Host:** the same three files in a directory owned by the release's user,
  whose path the release receives as `tenkai.identity.dir`. Each is written
  to a temporary path and renamed into place, mode 0600 for the key, by the
  host applier inside its verified apply (ADR 0041 §2).

The key exists only in the runtime's memory and in the target. It never
appears in a completion, receipt, log line, support bundle, evidence record
or error. Issuance and renewal are idempotent per instance: a retry after a
crash replaces the same Secret or files, so the target never holds two live
keys for one instance, and a crash between write and record is a retry.

### 5. Peer policy comes from bindings

A binding is the authorization. When dependent instance D is bound to
provider instance P for a contract, or is satisfied by P as the only provider
(ADR 0044 §3), then:

- P may accept D's identity as a client for that contract;
- D may accept P's identity as the server for that contract.

Nothing else is allowed by Tenkai. An edge that is not in the graph has no
grant, even if the network lets it through.

The dependency document (ADR 0043 §6) gains, for each contract, the
provider's identity, and for each instance, the identities allowed to call
it. It still carries no keys, secrets or endpoints. The document is part of
the plan the runtime verifies, so a server cannot add a peer the approved
bindings do not contain. Changing a binding re-renders both sides in the same
plan, so a withdrawn binding withdraws its grant.

### 6. Products enforce, Tenkai does not proxy

The product terminates TLS, requires and verifies the peer certificate
against the trust bundle, and checks the peer identity against its peer
document. Tenkai runs no sidecar, proxy or mesh, and changes no traffic.

### 7. Issuer rotation waits for the bundle to be taken up

The trust bundle can hold the current and the next issuer. Rotation is three
approved steps, and none makes a valid peer fail:

1. **Add** the next issuer to every bundle.
2. **Issue** from the next issuer. This step is refused until every instance
   with an identity has taken up the bundle from step 1:
   - with `reload = "restart"`, the restart rollout that step 1 triggers has
     completed and the instance is healthy;
   - with `reload = "runtime"`, the Secret or files are written and a fixed
     propagation bound has passed since, 10 minutes by default, which covers
     the Kubernetes refresh of mounted Secrets and a product's reload
     interval. An environment may raise it.
3. **Remove** the old issuer, once every certificate it signed has expired or
   been renewed from the next issuer.

The refusal of step 2 names the instances that have not taken up the bundle.

### 8. Environments without a separate runtime

Helm, kubectl and in-process Kubernetes releases can run inside the server's
process, with no separate runtime. There the issuing key would sit on the
server's host, which is the case ADR 0045 calls out for sealed values.

An environment without a separate runtime refuses plans that issue
identities, naming the reason, unless the environment explicitly records
`identity_issuer = "server-host"`. Setting it is a governed, audited change,
and `env inspect`, `status` and the dependency view show it. With it,
issuance and renewal run on the server's host and protect the store, backups
and the API, but not the host. The documentation must say so.

## Out of scope

- A service mesh, sidecars, or traffic encryption by Tenkai.
- Network policy generation. A later decision may derive policies from the
  same edges.
- Identity for human users or tenants.
- Identity across environments. An identity is only meaningful against its
  own environment's trust bundle.
- External certificate authorities. A later adapter can sign with one in the
  same place the runtime signs today.
- Revocation lists. Short lifetimes are the revocation mechanism.

## Consequences

- A product suite gets mutual TLS between its instances without building a
  certificate setup, and its authorization matches the graph that Tenkai
  shows and approves.
- An edge that is not bound cannot be authorized by Tenkai, so a missing
  binding fails closed.
- A compromised server cannot mint an identity, widen a SAN, or grant a peer.
  It can withhold plans, which stops new issuance but not renewal of what is
  already granted.
- Renewal keeps working through closed maintenance windows, holds and lost
  connectivity, for as long as a runtime of the environment is running.
- Authorization is only as strong as the product's enforcement. Tenkai grants
  and shows edges; it cannot tell whether a product requires client
  certificates. The dependency view (#1010) therefore shows an edge as
  granted, not as enforced.
- A leaked instance key stays valid until its certificate expires, at most
  one lifetime after an explicit reissue. Environments that need a shorter
  window lower the lifetime.
- Every runtime that issues needs the local approval policy and trust roots
  of ADR 0045 §4.
- Charts that read the certificate read the Secret name from
  `tenkai.identity.secret` instead of a fixed name.
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
- **Renew through approved plans.** Rejected: a closed window, a hold or an
  unanswered approval would let certificates expire. Renewal cannot widen a
  grant, so approving it adds no protection.
- **Deliver certificates as immutable, content-addressed Secrets like sealed
  values.** Rejected: every renewal would change the pod template and roll
  the workload once a day.
- **Rotate the issuer on a timer instead of on take-up.** Rejected: a product
  that reloads slowly, or reads files through `subPath`, would reject peers
  issued from the next issuer.
- **Require every product to reload certificates while running.** Rejected:
  many products read their certificate only at start. Excluding them would
  leave the suites that most need mutual TLS without it.
- **Issue silently from the server's host when no runtime exists.** Rejected
  as the default: it breaks the threat model without anyone deciding to.
