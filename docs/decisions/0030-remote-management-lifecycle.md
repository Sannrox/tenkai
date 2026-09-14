# ADR 0030: Versioned remote management lifecycle

- Status: Accepted
- Date: 2026-09-14
- Issue: [#393](https://github.com/Sannrox/tenkai/issues/393)
- Discussion: [#384](https://github.com/Sannrox/tenkai/discussions/384)
- Owner: Tenkai maintainers
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [ADR 0004](0004-authenticated-request-context.md),
  [ADR 0025](0025-remote-plan-property-query-bounds.md),
  [ADR 0026](0026-remote-package-migration-parity.md),
  [Management lifecycle](../management-lifecycle.md),
  [Runtime protocol](../runtime-protocol-v1.md)

## Context

Remote operators already inspect environments, request a reconcile tick, and
run package-migration verbs (ADR 0026). Publishing a release, promoting a
channel, subscribing an environment, planning, approving, applying, rolling
back, and recalling still require embedded `tenkaictl` on the hub host.

[#374](https://github.com/Sannrox/tenkai/issues/374) asks for that full
lifecycle behind authenticated, versioned remote contracts. Implementing the
entire A→B→rollback drill in one change is larger than one reviewable pull
request. [Discussion #384](https://github.com/Sannrox/tenkai/discussions/384)
accepted the contract and required a split.

The spoke runtime protocol (`Negotiate`, `Pull`, `CompleteStep`, `Heartbeat`)
is pull-only and maps a token to exactly one environment. Reusing it as an
operator API would mix runtime fencing with catalog and plan authority.
Shipping `--allow-unapproved-development` on the wire would give remote
callers the embedded local-development bypass.

This ADR records the accepted management contract. It does not implement the
lifecycle routes.

## Decision

Transport is not a domain boundary. Remote management calls the same
application core as embedded `tenkaictl`. The network host is not a weaker
product.

1. **One versioned management contract.** `tenkai.management-lifecycle.v1`
   covers publish, promote, subscribe, plan, approve, apply, rollback, and
   recall. New operations are additive and versioned. Unknown operations,
   unknown schema versions, and unknown fields that would change admission
   fail closed. Do not reuse unversioned CLI JSON as the wire contract.
2. **Credentials stay inside their grant.** Management credentials and
   environment-scoped management credentials cannot cross their grant.
   Runtime tokens cannot call management lifecycle operations. Missing
   approval evidence fails closed. A stale fencing generation cannot
   complete apply. Tenant-mode hosts keep the existing non-disclosing deny.
3. **No implicit development permissions on the wire.** Documented flags
   only. `--allow-unapproved-development` and equivalent bypass fields stay
   embedded-only and restricted to the built-in `local` environment. A
   remote request that carries a development-bypass field is rejected.
4. **Evidence is identical.** Signed releases, plan approvals, receipts, and
   fencing tokens have the same content-bound identity on both hosts.
   Cached files and inspect payloads cannot grant execution authority.
5. **Queries stay bounded** (ADR 0025). Package-migration remote parity
   (ADR 0026) remains a distinct operation family, not a generic apply
   wrapper.

### Surface

Use the authenticated HTTP management API, sibling to `/v1/reconcile` and
`/v1/migrations/*`. Do not place these verbs on the environment runtime
protocol (`proto/tenkai/runtime/v1`) and do not overload `POST /v1/reconcile`.

Reserved paths and the fail-closed request header live in
[management lifecycle](../management-lifecycle.md) and
`src/management_lifecycle.rs`. Exact request bodies land with [#394](https://github.com/Sannrox/tenkai/issues/394)
and [#395](https://github.com/Sannrox/tenkai/issues/395).

## Consequences

- [#393](https://github.com/Sannrox/tenkai/issues/393) is the named contract.
  Remaining work is routes, client methods, CLI remote dispatch, and the
  remote A→B→rollback drill, not a further design gate.
- [#374](https://github.com/Sannrox/tenkai/issues/374) stays the parent
  tracker until [#395](https://github.com/Sannrox/tenkai/issues/395) lands.
- Existing remote v1 inspect, reconcile, and package-migration routes stay
  unchanged.
- Remote operators cannot acquire the embedded local-development bypass.

## Alternatives

1. **Keep lifecycle verbs embedded-only.** Rejected: it makes transport a
   domain boundary and leaves the server host a weaker product.
2. **Reuse spoke `Negotiate` / `Pull` / `CompleteStep` as management.**
   Rejected: those RPCs are environment-runtime pull work, not catalog or
   operator plan authority.
3. **Implement the full #374 drill in one change.** Rejected: larger than
   one reviewable pull request. Discussion #384 requires the split.
4. **Ship embedded development bypasses over the network.** Rejected: remote
   and embedded modes must not acquire implicit development permissions.
