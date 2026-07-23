# ADR 0002: Tenkai-owned routing configuration

- Status: Accepted
- Date: 2026-07-23
- Issue: [#6](https://github.com/Sannrox/tenkai/issues/6)
- Discussion: [#44](https://github.com/Sannrox/tenkai/discussions/44)

## Context

Tenkai must deliver governed model-routing configuration through the same
immutable release, ordered plan, approval, execution, audit, and rollback
lifecycle as software. Making sekai-chisei interpret the payload or own applied
and recovery state would conflict with ADR 0001 and prevent standalone
operation.

## Decision

Tenkai owns the versioned `routing_config` product contract, payload
validation, content identity, ordered plan execution, applied-state
observation, rollback intent, and audit lineage. Mutation is exposed through
the provider-neutral `RoutingConfigExecutor` application port.

The embedded adapter applies a validated JSON document atomically to an
environment- and product-scoped local target, then observes its content
identity. Invalid references, unsupported schema versions, and providers not
admitted by the release fail before mutation. A previous release is restored
through the normal pinned rollback step.

sekai-chisei may provide policy, evaluation, provenance, projection, or a
future executor adapter when explicitly configured. It is required for an
operation only when policy or the approved plan requires its evidence. It
never owns Tenkai releases, plans, receipts, rollback, or recovery state.

This decision adds only routing configuration as an intelligence product type.
Software and routing products coexist as ordinary ordered plan steps.
Credentials and secrets are not routing payload fields.

## Consequences

- The public manifest has a versioned `product.kind = "routing_config"`
  variant and a routing section.
- Routing configuration is part of the immutable release artifact digest.
- Provider admission is explicit and fails closed before mutation.
- Embedded Tenkai can publish, plan, apply, observe, and roll back routing
  products without sekai-chisei.
- Future remote adapters must pass the same validation, atomicity,
  observation, fencing, and rollback conformance tests.

## Alternatives

A generic opaque provider action was rejected. It would reduce the initial
surface but move routing semantics and recovery correctness into
provider-specific behavior.
