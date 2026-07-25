# Federated identity

How Tenkai correlates identities with an enterprise identity plane and optional
governance providers—without shared databases or caller-selected tenants.

Source of truth: `src/federated_identity.rs`.  
Decision: [ADR 0006](decisions/0006-federated-identity.md).  
Related: [authenticated request context](auth-request-context.md),
[enterprise integration boundary](enterprise-integration-boundary.md),
[provider contracts](provider-contracts.md).

## Ownership

| Identity | Owner |
| --- | --- |
| Tenant, principal, service | Enterprise identity plane |
| Environment, agent, product, plan, deployment history | **Tenkai** |
| Policy / eval / evidence records | Issuing governance provider |

Tenkai never reads another product’s tenant database. Providers never own
Tenkai recovery state.

## Identifier shape

```text
FederatedIdentifier {
  contract_version,
  kind,       # tenant | principal | service | environment | ...
  issuer,     # who mints the subject
  audience,   # who may consume it
  subject     # opaque stable id
}
```

## Mapping rules

1. Verify signed, audience-bound context (enterprise auth extension).
2. Accept assertion once (replay cache by `assertion_id`).
3. Write `IdentityMapping` only with `MappingAuthority` for the configured
   issuer/audience.
4. Resolve mappings for correlation; revoked/expired mappings fail closed.
5. Rotate with higher `generation`; reject stale generations and same-generation
   handle conflicts.
6. Delete mappings only through the same authority.

**Forbidden:** selecting tenant (or overwriting mappings) from request headers,
query parameters, or untrusted body fields.

## Provider failure

| Class | Outcome |
| --- | --- |
| Required decision | Fail closed |
| Optional export | Degrade + durable retry; recovery continues |

Standalone enterprise Tenkai does **not** require a governance provider for
authentication or recovery.

## Community vs enterprise

| Mode | Enterprise issuer | Tenant federation |
| --- | --- | --- |
| Community | Not configured | Not used |
| Enterprise | Required when enterprise auth is enabled | Via signed context + mappings only |

### Management HTTP accept path

When `ServerConfig.federation` sets `required_enterprise_issuer`, the host wraps
the enterprise auth extension with `FederatingAuthExtension`:

1. Extension verifies the signed assertion (ADR 0004).
2. Host parses federation claims as `SignedIdentityContext`.
3. `IdentityDirectory::accept_signed_context` binds issuer/audience and records
   the assertion id (replay fails closed).
4. Optional mapping resolve/put uses `MappingAuthority` only.
5. Audit uses `audit_correlation_token` (hash of assertion id) — no secrets.

Community servers keep `FederationConfig::community()` and the management bearer
path unchanged. Caller headers such as `x-tenkai-tenant` are rejected and never
select authority.

## Security checklist

- [ ] Issuer and audience bound on every signed context  
- [ ] No cross-product DB reads  
- [ ] No caller-selected tenant metadata  
- [ ] Replay protection on assertion ids  
- [ ] Rotation / revocation / deletion defined  
- [ ] Audit correlation without secrets  
- [ ] Required vs optional provider unavailability defined  
