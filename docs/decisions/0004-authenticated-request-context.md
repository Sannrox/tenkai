# ADR 0004: Authenticated request context for enterprise composition

- Status: Accepted
- Date: 2026-07-25
- Issue: [#36](https://github.com/Sannrox/tenkai/issues/36)

## Context

Tenkai must stay fully operable as a tenant-free community runtime while
allowing an enterprise composition (an external identity/tenant plane in front
of the standalone Tenkai service) to present short-lived, audience-bound
assertions. Folding that identity plane into the Tenkai process, or allowing
callers to select tenant membership through ordinary metadata, would either
force enterprise identity on community users or create a forgeable authority
path.

ADR 0001 already requires each use case to carry a principal and keeps Tenkai
authoritative for operational state. Provider ports (issue #18) authorize
governed decisions but do not define transport authentication or optional
tenant context.

## Decision

Define a versioned, backend-neutral **authenticated request context** contract:

1. **Principal identity** is always present on an authenticated call.
2. **Tenant context** is optional and community modes never require it.
3. **Tenant derivation** is possible only with a host-granted
   `TenantDerivationAuthority` issued when an enterprise auth extension loads
   successfully at startup—not from caller headers, query parameters, or other
   untrusted metadata.
4. **Credential material** may carry bearer tokens and opaque assertions but
   never a caller-selected tenant id.
5. **Enterprise auth** is an object-safe extension port
   (`EnterpriseAuthExtension`) that verifies assertions and builds context.
   Tenkai retains catalog, planning, reconciliation, execution, and recovery
   authority.
6. **Startup fail-closed**: missing or incompatible *required* extensions abort
   host composition before the process accepts deployment work.
7. **Community default**: `AuthHostConfig::community()` plus
   `CommunityTokenAuthenticator` require no enterprise binary.

Documented in `docs/auth-request-context.md` and implemented in
`src/auth_context.rs`.

## Consequences

- Community embedded and server hosts keep a tenant-free surface.
- Enterprise hosts can plug an external assertion verifier without a second
  delivery backend.
- Forged tenant strings outside verified authentication cannot select Tenkai
  authority.
- Contract version bumps are required for semantic changes to principal/tenant
  derivation or startup failure rules.
- Follow-on work may wire `AuthStack` into HTTP middleware and record tenant on
  audit events; this ADR does not implement OIDC or tenant lifecycle.

## Alternatives

- **Always-on multi-tenant core:** rejected; breaks the one-binary solo
  experience and couples community users to enterprise identity.
- **Caller-supplied `X-Tenant-Id` trusted after any authn:** rejected; forges
  tenant authority from ordinary metadata.
- **Hard-link an identity provider into Tenkai:** rejected; makes enterprise
  identity a required dependency and confuses process boundaries.
