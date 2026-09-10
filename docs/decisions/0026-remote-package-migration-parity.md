# ADR 0026: Remote package-migration lifecycle parity

- Status: Accepted
- Date: 2026-09-10
- Issue: [#338](https://github.com/Sannrox/tenkai/issues/338)
- Owner: Tenkai maintainers
- Related: [ADR 0001](0001-standalone-core-and-service-evolution.md),
  [ADR 0004](0004-authenticated-request-context.md),
  [ADR 0024](0024-package-migration.md),
  [Package migrations](../package-migrations.md)

## Context

ADR 0024 added profile `tenkai.package_migration.v1` as a Tenkai-owned
coordinator. The embedded CLI already exposes preview, apply, status, resume,
and rollback over that core. Remote `tenkaictl --target remote migrate …`
falls through to the catch-all:

```text
this command is not available through the v1 remote API; use --target embedded
```

`tenkai-server` has no package-migration management routes. Identity,
checkpoint receipts, the environment migration lock, fencing generation, and
`recovery_required` therefore exist only on the laptop host.

ADR 0001 requires one application core and two hosts that share the same
contracts. Transport is not a domain boundary. Leaving migrate embedded-only
makes the network host a second, weaker product for the same operation.

The CLI human formatter and unversioned declaration JSON are not a network
contract. Generic apply or plan routes do not encode migration identity, the
migration lock, or checkpoint receipts. Wrapping those routes, or shipping
`--allow-unapproved-development` over the wire, would create a hidden second
protocol and give remote callers the embedded local-development bypass.

Issue [#334](https://github.com/Sannrox/tenkai/issues/334) already proves the
embedded crash-recovery drill. Remote parity must match those identities and
recovery states, not invent a parallel executor.

This ADR records the accepted remote contract. It does not implement the
routes.

## Decision

Expose package-migration preview, apply, status, resume, and rollback as
additive authenticated management operations on the server host. Both hosts
call the existing `package_migration` application core.

1. **One core.** Server adapters authenticate and authorize, then call
   `package_migration::{preview, run_until_blocked, load, resume, rollback}`.
   Do not add a second executor, checkpoint engine, or identity scheme.
2. **Versioned fail-closed request and result.** Each request and result
   carries an explicit contract version. Unknown version, unknown profile,
   unknown checkpoint class, or an unknown field that would change admission
   fails closed. Do not reuse unversioned CLI JSON or `format_migration` text
   as the wire contract.
3. **No remote local-development bypass.**
   `--allow-unapproved-development` and `unapproved_development_reason` remain
   embedded-only and restricted to the built-in `local` environment. Remote
   apply, resume, and rollback require a signed identity-bound
   `tenkai.package-migration-approval.v1` envelope verified against trust
   roots. A remote request that carries a development-bypass flag is rejected.
4. **Tenant, fence, and environment scope on the wire.** Calls use an
   authenticated management principal (ADR 0004). Tenant-mode hosts require
   tenant context and reject cross-tenant environment identifiers with the
   existing non-disclosing deny. Mutating verbs require `expected_generation`
   matching the current environment fencing generation. A stale generation
   fails before the next effect.
5. **Identity and recovery stay Tenkai-owned.** Plan identity remains
   content-bound over environment, declaration, and the optional backup
   receipt digest (ADR 0024). Remote and embedded fixtures must produce the
   same plan identifiers, checkpoint receipts, and `recovery_required`
   states. Interrupted or retried requests replay from durable receipts; they
   must not double-execute an accepted checkpoint. Recovery does not depend
   on `sekai-chisei`.
6. **CLI is an adapter.** `tenkaictl --target remote migrate …` maps onto
   these management operations. It does not wrap generic apply, plan, or
   reconcile routes as a hidden second protocol.

### Surface

Use the authenticated HTTP management API, sibling to `/v1/reconcile` and
`/v1/environments/*`. Do not place these verbs on the environment runtime
protocol (`proto/tenkai/runtime/v1`) and do not overload `POST /v1/reconcile`.

Exact paths and field layout land with the #338 implementation in server
types and [package migrations](../package-migrations.md). They must stay
additive, versioned, and fail-closed as specified here.

## Consequences

- Implementation of [#338](https://github.com/Sannrox/tenkai/issues/338) is
  unblocked once this ADR is the named accepted contract. Remaining work is
  routes, client methods, CLI remote dispatch, and fixture parity tests, not
  a further design gate.
- Remote operators cannot acquire the embedded local-development bypass.
- Existing remote v1 routes are unchanged.
- Request/result schema documentation is maintained next to the
  implementation, not as a second competing ADR.

## Alternatives

1. **Keep migrate embedded-only.** Rejected: it makes transport a domain
   boundary and leaves the server host unable to execute, resume, or recover
   the same coordinator plan.
2. **CLI `--target remote` wrapping generic apply or plan RPCs.** Rejected:
   those routes do not encode migration identity, checkpoint receipts, or the
   migration lock. Mapping migrate onto them would smuggle embedded flags and
   hide a second protocol.
3. **Reuse unversioned CLI JSON as the HTTP body.** Rejected: unknown
   versions must fail closed, and formatter output is not a wire contract.
