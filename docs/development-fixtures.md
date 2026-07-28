# Authenticated development fixtures

Tenkai can expose a narrow fixture import/reset surface for deterministic local
integration demos. It is absent by default and never creates executable or
production-authorized delivery state.

## Enablement

The server must already run in tenant mode with enterprise JWT authentication.
Enable fixtures explicitly and allow only dedicated service or management
principals:

```sh
export TENKAI_JWT_VERIFIER_CONFIG=/run/tenkai/aldunis-trust.toml
export TENKAI_POSTGRES_URL=postgres://...
export TENKAI_DEVELOPMENT_FIXTURE_PRINCIPALS='["aldunis-demo-seed"]'

tenkai-server \
  --tenant-mode \
  --with-enterprise-auth \
  --require-enterprise-auth \
  --with-development-fixtures
```

Startup fails if the allowlist is empty or the required tenant/authentication
capabilities are absent. Setting the allowlist without the flag also fails.
Principal IDs are authorization configuration, not credentials; tokens and
assertions must never be placed in the allowlist or command line.

## Import contract

Send a short-lived enterprise assertion as `x-tenkai-assertion`:

```http
POST /v1/development/fixtures/import
Content-Type: application/json
X-Tenkai-Assertion: <short-lived assertion>
```

```json
{
  "contract_version": 1,
  "fixture_id": "buyer-demo",
  "releases": [
    {
      "name": "api",
      "product": "api",
      "version": "1.0.0",
      "content_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ],
  "channels": [
    {
      "name": "stable",
      "product": "api",
      "release": "api"
    }
  ],
  "environments": [
    {
      "name": "prod-eu",
      "posture": "awaiting_approval",
      "description": "sanitized demo"
    }
  ],
  "plans": [
    {
      "name": "approval",
      "environment": "prod-eu",
      "blocked_reason": "awaiting approval"
    }
  ]
}
```

The authenticated context supplies the tenant. The document has no tenant
field, and caller tenant headers remain forbidden. Names are placed in a
reserved `fx-<fixture-id>-...` namespace. Repeating byte-equivalent semantic
input is idempotent; reusing an identity with different content returns a
conflict without partial writes.

Only sanitized projections are admitted:

- releases are marked `fixture_only` and non-executable;
- channels may reference only releases in the same fixture;
- environments carry one documented demo posture; and
- plans contain no steps and are permanently created as blocked.

The importer cannot approve, apply, reconcile, create leases or receipts,
trigger rollback, or bypass release signing and plan-approval rules.

## Reset and recovery

```http
DELETE /v1/development/fixtures/buyer-demo
X-Tenkai-Assertion: <short-lived assertion>
```

Reset requires the same tenant and an allowlisted service/management principal.
It deletes only the reserved fixture namespace in reverse dependency order.
Reset refuses when leases, receipts, runtime claims, offline imports, or
rollback state depend on a fixture object.

Import and reset are single tenant-store transactions and record sanitized
audit evidence: principal, operation, fixture identity or digest, request ID,
and outcome. They never record assertions, tokens, signing keys, provider
credentials, database URLs, executable payloads, or customer data.

Disable the feature by removing `--with-development-fixtures` and restarting.
Recovery remains Tenkai-owned: fixture records are ordinary operational state
inside the selected tenant partition and never depend on Aldunis databases.
