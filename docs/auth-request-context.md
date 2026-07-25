# Authenticated request context

Tenkai authenticates transports and authorizes delivery-domain use cases. This
document defines the backend-neutral request-context contract used by community
hosts and by enterprise compositions that verify short-lived, audience-bound
assertions. It does not implement OIDC, tenant lifecycle, billing, or a
console.

Source of truth for types and startup composition: `src/auth_context.rs`.
Architecture decision: [ADR 0004](decisions/0004-authenticated-request-context.md).
Product composition boundary:
[ADR 0005](decisions/0005-enterprise-integration-boundary.md) and
[enterprise integration boundary](enterprise-integration-boundary.md).
Identity federation:
[ADR 0006](decisions/0006-federated-identity.md) and
[federated identity](federated-identity.md).

## Ownership

| Concern | Owner |
| --- | --- |
| Catalog, channels, releases | Tenkai |
| Planning, reconciliation, leases, receipts, rollback | Tenkai |
| Operational recovery state | Tenkai |
| Principal identity on a call | Authenticator that verified credentials |
| Optional tenant membership | Enterprise auth extension after verification |
| Identity provider UX / token minting | External identity plane |

Authentication adapters never become authoritative for operational objects.
Tenkai remains the delivery-domain authority even when an enterprise gateway
supplies authenticated tenant context.

## Principal vs tenant

`AuthenticatedRequestContext` always carries:

- a contract version;
- a stable request id;
- a **principal** (`PrincipalIdentity`: id + kind);
- the authenticator id that produced the context.

It may also carry optional **tenant** context. Tenant context:

- is absent in community embedded and community server modes;
- can be attached only with a host-granted `TenantDerivationAuthority`;
- records which extension derived it.

Callers cannot select a tenant through ordinary request metadata. The
credential envelope (`CredentialMaterial`) deliberately omits a tenant field.
Tenant membership is derived only inside trusted authenticators after
credential verification.

## Credential material

| Field | Meaning |
| --- | --- |
| `request_id` | Stable per-call identity for audit and idempotency correlation |
| `bearer_token` | Community or host-local secret mapping (optional) |
| `assertion` | Opaque enterprise assertion bytes (optional) |

At least one of `bearer_token` or `assertion` must be present. Empty tokens or
empty assertions fail closed.

## Community authentication

`CommunityTokenAuthenticator` maps configured bearer tokens to principals and
never attaches tenant context. Community hosts call:

```text
AuthHostConfig::community() + build_auth_stack(..., extension = None, ...)
```

Embedded mode and the loopback community server use this path. No enterprise
identity binary is required.

### Management HTTP wiring

`tenkai-server` management routes (`/v1/reconcile`, `/v1/environments/*`)
authenticate through the composed `AuthStack` in `src/server.rs`:

1. Extract the bearer token (runtime tokens remain on separate routes).
2. Build `CredentialMaterial` with a request id (`x-request-id` or generated).
3. Call `AuthStack::authenticate` — never raw token equality alone.
4. Use the returned principal for audit; optional tenant is only present when an
   enterprise extension derived it under host authority.

Caller-selected headers such as `x-tenkai-tenant` cannot attach tenant context.
When enterprise authentication is required, startup fails if the extension is
missing (capability negotiation and `build_auth_stack` both fail closed).

## Enterprise authentication extension

`EnterpriseAuthExtension` is an object-safe port for verifying audience-bound
assertions and producing an `AuthenticatedRequestContext` that includes tenant
membership. The host:

1. Loads the extension only through explicit host wiring.
2. Grants `TenantDerivationAuthority` solely when the extension passes startup
   checks.
3. Fails process startup when a *required* extension is missing or incompatible.
4. Never consults the extension for catalog, planning, reconciliation, or
   recovery authority.

Extension duties:

- verify cryptographic integrity and expiry of assertions;
- enforce the configured audience;
- map verified claims to principal identity and tenant id;
- use `AuthenticatedRequestContextBuilder::with_tenant` with the granted
  authority.

Non-duties: minting Tenkai plans, mutating operational state, or bypassing
Tenkai authorization.

## Lifecycle and version compatibility

| Stage | Behavior |
| --- | --- |
| Host configuration | `AuthHostConfig` declares optional `required_extension_id`, expected contract version, and expected audience |
| Startup composition | `build_auth_stack` validates extension id, contract version, and audience |
| Missing required extension | `AuthStartupError::MissingRequiredExtension` — process must not accept work |
| Incompatible contract version | `AuthStartupError::IncompatibleExtensionContract` (or host contract mismatch) |
| Audience mismatch | `AuthStartupError::AudienceMismatch` |
| Per-request authentication | Authenticator returns typed `AuthError`; unauthorized or invalid credentials fail closed |
| Runtime operation without extension | Community stack continues; no tenant surface is exposed |

Contract version is `AUTH_CONTEXT_CONTRACT_VERSION` (currently `1`). Changing
principal/tenant field meaning, derivation authority rules, or startup failure
semantics requires a new contract version and coordinated host/extension
updates.

## Failure behavior

| Failure | When | Effect |
| --- | --- | --- |
| Required extension absent | Startup | Fail closed; do not serve deployments |
| Extension contract mismatch | Startup | Fail closed |
| Audience mismatch | Startup | Fail closed |
| Invalid / unknown credentials | Request | `AuthError::Unauthorized` or `InvalidCredential` |
| Forged tenant metadata | Request | Cannot select authority; community path ignores assertion tenant hints; enterprise path requires verified assertion |

Deployment-time discovery of a missing required enterprise identity plane is
forbidden: hosts that require an extension must fail before accepting
management or runtime work.

## Composition without a single implementation

`CredentialAuthenticator` and `EnterpriseAuthExtension` are object-safe
(`Send + Sync`, no generic methods). Hosts store `Arc<dyn …>` and can substitute
community tokens, enterprise assertion verification, or test doubles without
linking Tenkai domain logic to one identity product.

## Security invariants

1. Principal and tenant are distinct fields; tenant is optional.
2. Tenant context cannot be minted from caller-selected headers or query
   parameters.
3. Only startup-granted `TenantDerivationAuthority` enables
   `with_tenant`.
4. Tenkai domain authorization still applies after authentication.
5. Credentials stay outside plans, receipts, and operational payloads.

## Relationship to providers

Governance providers ([provider contracts](provider-contracts.md)) authorize
named actions against operational bindings. They consume a principal string and
do not replace transport authentication. Request context supplies the
authenticated principal (and optional tenant) that policy and audit layers may
record; providers still cannot own recovery state.
