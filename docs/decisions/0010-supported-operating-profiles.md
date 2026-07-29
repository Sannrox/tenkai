# ADR 0010: Supported operating profiles

- Status: Accepted
- Date: 2026-07-29
- Issue: [#190](https://github.com/Sannrox/tenkai/issues/190)
- Depends on: [#187](https://github.com/Sannrox/tenkai/issues/187)
- Research inputs: [#188](https://github.com/Sannrox/tenkai/issues/188),
  [#189](https://github.com/Sannrox/tenkai/issues/189)

## Context

Tenkai ships independently negotiable host, store, authentication, execution,
provider, and connectivity capabilities. Startup negotiation prevents unsafe
compositions, but it does not define which complete combinations are product
paths with support and stability promises.

The existing enterprise composition opens PostgreSQL tenant state alongside
SQLite host/application state. That is useful integration evidence, but it has
no single transaction, backup, restore, or cutover boundary and therefore
cannot be a supported enterprise recovery model.

Sekai-Chisei provides the applicable precedent: a deployment selects either
SQLite or PostgreSQL as its runtime database, rejects configuration for both,
and fails closed when a selected backend does not implement a required
operation. Tenkai adopts the same single-authority model.

## Decision

Tenkai defines three operator-facing profiles:

- `local`: stable embedded operation with SQLite;
- `fleet`: experimental single-server operation with SQLite and scoped remote
  runtimes;
- `enterprise-experimental`: experimental tenant-isolated server operation
  with PostgreSQL as the sole authoritative operational store.

A profile is a complete contract, not a label over arbitrary flags. Startup
must reject a selected profile unless all required capabilities are present.
The current mixed SQLite/PostgreSQL enterprise composition is not the
`enterprise-experimental` profile and must not advertise itself as such.

All profiles preserve Tenkai's operational ownership. Optional providers and
Sekai-Chisei projections remain outside recovery; policy-required evidence
continues to fail the affected operation closed.

### `local`

| Property | Contract |
| --- | --- |
| Intended operator and outcome | Individual or small-team operator learning and running Tenkai locally without a server or external service. |
| Processes | One `tenkaictl` embedded host; local executor subprocesses as required by the product. |
| Store | Tenkai-owned SQLite, tenant-free, one writer. |
| Authentication | Local filesystem/process access with a caller-supplied audit principal; this is not authenticated OS identity. Explicit development-only bypasses remain restricted to the built-in `local` environment. No remote management bearer. |
| Execution ownership | Embedded application core owns plan, lease, execution, health, rollback, and recovery. |
| Recovery | `tenkaictl backup` / `restore`, artifact rehydration, then inspect/list/status. No optional provider is required. |
| Provider behavior | Built-in local providers or no optional provider. A policy-required provider still fails the operation closed. |
| Upgrade path | Back up SQLite; upgrade within documented schema compatibility; restore the previous binary and database backup on failed migration. |
| Guarantees | Embedded/server core semantics, immutable releases and plans, explicit trust bypasses, health rollback, one-writer recovery. |
| Non-guarantees | Tenant isolation, remote runtime transport, shared replica state, product HA, enterprise authentication, or server availability. |
| Stability | **Stable/default.** Three independent fresh-checkout sessions in #187 cover publish through rollback and recovery. |

### `fleet`

| Property | Contract |
| --- | --- |
| Intended operator and outcome | Single-organization operator managing multiple environments through one network control-plane host and environment-scoped pull runtimes. |
| Processes | One `tenkai-server`, zero or more `tenkai-runtime` processes each scoped to exactly one environment, authenticated TLS termination in front of loopback HTTP. |
| Store | Tenkai-owned SQLite, tenant-free, one server writer. |
| Authentication | Management bearer plus distinct environment-scoped runtime bearers, injected from secret storage. Enterprise identity assertions are not part of this profile. |
| Execution ownership | Server application core owns plans, leases, receipts, rollback, and recovery; runtimes execute only immutable scoped work under fencing. |
| Recovery | Stop the server writer, use SQLite backup/restore, re-inject runtime and management credentials, restart one server, and verify readiness/fleet posture. |
| Provider behavior | Local providers by default. Explicit remote provider adapters may enrich or gate operations; required evidence fails closed. Optional audit/outcome export is unavailable until host mutations transactionally enqueue the existing outbox contract. |
| Upgrade path | Back up SQLite before store migration. Server and runtimes must remain on the same advertised protocol minor until the implementation supports and tests a current/previous-minor window. |
| Guarantees | Environment-scoped pull transport, protocol negotiation, receipt idempotency, lease fencing, authenticated management, single-server recovery. |
| Non-guarantees | Tenant isolation, shared server writers, automatic server failover, product HA, enterprise authentication, or arbitrary plaintext remote binding. |
| Stability | **Experimental.** Protocol and conformance evidence exists, but #187 supplies no independent server/runtime usability evidence. |

### `enterprise-experimental`

| Property | Contract |
| --- | --- |
| Intended operator and outcome | Enterprise operator running tenant-isolated delivery through an authenticated network control plane with shared PostgreSQL durability. |
| Processes | One `tenkai-server`, environment-scoped runtimes, PostgreSQL, an enterprise assertion verifier, and authenticated TLS termination. |
| Store | One Tenkai-owned PostgreSQL deployment is the sole authoritative store for releases, channels, environments, plans, execution, receipts, rollback, recovery, identity bindings, tenant state, leases, fencing, and any activated provider outbox. SQLite is not opened for authoritative runtime state. |
| Authentication | Verified enterprise JWT assertions establish management and tenant context; distinct environment runtime credentials scope execution. Caller metadata never establishes tenant authority. |
| Execution ownership | Tenkai remains sole operational owner. Enterprise identity and optional provider systems cannot mint plans, mutate receipts, or enter recovery. |
| Recovery | PostgreSQL-native consistent backup and restore covers the complete authoritative state. Restore one compatible database point, start a compatible Tenkai version, re-inject credentials, and verify migrations, tenant isolation, fencing, readiness, and fleet posture before admitting writes. |
| Provider behavior | Required evidence fails the affected operation closed. Optional audit/outcome delivery remains unavailable until host mutations transactionally enqueue a PostgreSQL-backed outbox; providers never own recovery. |
| Upgrade path | Take and verify a PostgreSQL recovery point, migrate under the documented compatibility window, keep server/runtime protocol minors compatible, and restore the prior binary plus database recovery point if migration fails. |
| Guarantees | Tenant isolation, federated assertion verification, PostgreSQL durability, leases/fencing, and single-store recovery once every required PostgreSQL capability passes startup validation and conformance. |
| Non-guarantees | Multiple server replicas, automatic failover, multi-AZ packaging, multi-active writers, zero-downtime migration, browser OIDC sessions, or product `high_availability`. |
| Stability | **Experimental and gated.** The profile is unavailable until PostgreSQL implements every required authoritative surface and passes enterprise recovery and usability drills. Component-level PostgreSQL evidence alone does not activate it. |

## Backend and recovery rules

1. A process selects exactly one authoritative operational backend.
2. `local` and `fleet` select SQLite; `enterprise-experimental` selects
   PostgreSQL.
3. Supplying both SQLite and PostgreSQL runtime configuration is invalid.
4. No authoritative operation may fall back from PostgreSQL to SQLite.
5. Missing backend support fails startup when required by the profile, or
   fails the affected operation closed for an explicitly optional capability.
6. Host-local caches, credential injection, and retry spools may exist only
   when loss or replay cannot change authority. They are not a second system of
   record.
7. Migration from SQLite to enterprise PostgreSQL stops all writers, preserves
   a verified rollback backup, imports the complete authoritative state,
   validates conformance, then performs an explicit traffic cutover.

## Complete capability inventory

A checkmark assigns a shipped capability to a complete profile contract. A
gated mark means the enterprise profile requires it but cannot be selected
until the PostgreSQL implementation and evidence exist.

| Shipped capability | `local` | `fleet` | `enterprise-experimental` | Status / constraint |
| --- | :---: | :---: | :---: | --- |
| Embedded application host | ✓ |  |  | Stable default |
| Network control-plane host |  | ✓ | gated | Experimental |
| SQLite operational store | ✓ | ✓ |  | Stable in one-writer use |
| PostgreSQL operational store |  |  | gated | Must cover all authoritative state, not tenant state alone |
| Tenant-free operation | ✓ | ✓ |  | Default |
| Tenant isolation |  |  | gated | Requires PostgreSQL and enterprise verifier |
| Single writer / single server | ✓ | ✓ | ✓ | Supported posture |
| Shared replica state |  |  |  | Component evidence exists, but no complete profile admits multiple server replicas |
| `high_availability` capability |  |  |  | Unsupported; requirement remains fail-closed |
| Community/local authentication | ✓ |  |  | Local process only |
| Management bearer authentication |  | ✓ |  | Secret-store injection; TLS proxy for remote access |
| Environment-scoped runtime bearer |  | ✓ | gated | One environment per credential |
| Enterprise JWT assertion verification |  |  | gated | Not general browser OIDC |
| Local execution | ✓ |  |  | Embedded process fencing |
| Connected remote runtime execution |  | ✓ | gated | Runtime protocol v1 |
| Offline bundle/receipt contract |  |  |  | Unexposed library contract; unsupported until a shipped workflow exists |
| Local gate/policy provider | ✓ | ✓ | gated | Fails closed when required inputs are absent |
| Explicit remote provider adapters |  | ✓ | gated | Experimental; never on recovery path |
| Durable optional-provider outbox |  |  | gated | Queue contract exists, but host mutations are not wired transactionally |
| OpenMetrics endpoint |  | ✓ | gated | Optional, disabled by default, protected at network boundary |
| Development fixture surface |  |  |  | Lab-only, disabled by default |
| Fleet status/watch/waves | ✓ embedded view | ✓ | gated | Waves observe; they do not execute or authorize |
| All shipped product kinds and executors | ✓ where local prerequisites exist | ✓ where runtime prerequisites exist | gated where enterprise prerequisites exist | Product contracts stay profile-independent |

Capabilities assigned to no complete profile are deliberately unsupported, not
implicitly composable. Product `high_availability` and offline delivery remain
unsupported. Development fixtures and the current mixed-store enterprise
composition remain test-only integration surfaces.

## Compatibility and invalid combinations

Profile adoption is additive at first: existing releases, channels,
environments, plans, receipts, rollback state, and store schemas are not
silently rewritten.

| Combination | Result |
| --- | --- |
| Community SQLite + tenant mode | Fail startup: no `tenant_isolation`. |
| Community SQLite + replica count greater than one | Fail startup: no `shared_replica_state`. |
| Enterprise profile + any SQLite operational-state path | Fail before listen. |
| Enterprise profile + incomplete PostgreSQL authoritative surfaces | Fail before listen and report the missing capabilities. |
| Both SQLite and PostgreSQL runtime configuration | Fail before opening either store. |
| Any profile + required product HA | Fail startup: no `high_availability`. |
| Enterprise authentication required without a usable verifier | Fail before listen. |
| Plaintext non-loopback server listener | Reject; use authenticated TLS termination. |
| Development fixture principals without the fixture flag | Reject. |
| Remote provider mode without a configured reachable provider | Fail the affected startup or operation; never silently fall back. |
| Profile name plus contradictory low-level flags | Reject. Legacy no-profile invocations continue through capability validation during the compatibility window. |

## Documentation and release contract

1. README quick paths lead with `local`, then `fleet`, and describe
   `enterprise-experimental` as gated until its PostgreSQL readiness checks
   pass.
2. `docs/runtime-capabilities.md` distinguishes profile readiness from
   component capability claims.
3. `tenkai-server --help` shows profile selection first and groups low-level
   compatibility flags as advanced.
4. `/healthz` and `/readyz` report the selected profile, backend identity, and
   composed capability list.
5. `docs/release-readiness.md` requires one support statement and evidence row
   per profile affected by a release.
6. Existing runbooks remain the detailed operational evidence behind the
   profiles rather than independent implied support promises.

## Freeze, hide, and deprecate

- **Freeze unsupported:** `--require-high-availability` remains a fail-closed
  assertion and is admitted by no profile until automated failover and recovery
  evidence supports an honest capability claim.
- **Hide from default paths:** raw replica, tenant, enterprise-auth, provider,
  metrics, and development-fixture composition flags move to advanced
  documentation. They remain visible for compatibility and diagnostics.
- **Freeze as test-only:** the mixed SQLite/PostgreSQL enterprise composition,
  authenticated development fixtures, and incomplete PostgreSQL surfaces must
  not activate an operating profile.
- **No immediate deprecation:** existing flags and diagnostic profile strings
  continue during an explicit compatibility window. Deprecation requires a
  separate CLI/versioning decision and must not reinterpret persisted state.

## Consequences

- Enterprise delivery requires broader PostgreSQL parity than today's
  tenant-store adapter and therefore more implementation work.
- The enterprise transaction and recovery boundary is simple and auditable:
  PostgreSQL contains all authoritative state.
- SQLite remains a complete, independent local and fleet backend rather than a
  required sidecar of enterprise.
- Backend-neutral application ports and shared conformance fixtures become the
  migration mechanism; runtime dual-writing and fallback are prohibited.
- Enterprise remains experimental until independent recovery and usability
  evidence exists, and component tests cannot be presented as profile support.

## Alternatives rejected

### Keep enterprise as an incomplete lab

This avoids near-term PostgreSQL parity work but does not provide the
enterprise product path required by the project. It also leaves the intended
store ownership model unresolved.

### Coordinate live SQLite and PostgreSQL recovery

This preserves the current split implementation but creates a permanent
cross-store transaction, backup, restore, and cutover problem. It was rejected
in favor of the single-backend model already used by Sekai-Chisei.

## Impact assessment

| Surface | Decision effect | Required evidence before profile activation |
| --- | --- | --- |
| Product contract | Three profiles; enterprise is named but gated | Consistent README, help, diagnostics, and release statements |
| Runtime capability negotiation | Profile selection maps to mandatory backend and capability requirements | Startup rejection tests for missing or contradictory capabilities |
| Operational persistence | Enterprise moves all authoritative state behind PostgreSQL application ports | Shared SQLite/PostgreSQL conformance, migration, backup, restore, and cutover drills |
| Authentication/trust | Each profile has one documented authority posture | Enterprise verifier and tenant-scope negative tests |
| Runtime protocol/execution | Remote profiles retain scoped pull execution and fencing | Same-minor compatibility until a wider window is proven |
| Providers | Provider requirements do not change by profile | Transactional host wiring plus SQLite/PostgreSQL outbox conformance; recovery remains provider-independent |
| HA/replicas | Shared state remains distinct from product HA | Preserve explicit non-guarantee and fail-closed HA requirement |
| Ontology | The current portable ontology has no operating-profile or backend definitions | Add portable definitions only when the repository adopts a tracked ontology artifact |
| Security | Dual-store fallback and caller-selected tenant authority are prohibited | Fail-closed startup and authorization tests |

## Implementation sequence

1. Accept this ADR without changing runtime behavior.
2. Add profile identifiers and validation. `local` and `fleet` may become
   selectable; `enterprise-experimental` remains gated.
3. Move every authoritative application port required by enterprise to
   PostgreSQL with shared backend conformance.
4. Add a complete SQLite-to-PostgreSQL migration and rollback procedure.
5. Run enterprise backup/restore, tenant-isolation, replica-loss, upgrade, and
   independent operator usability drills.
6. Activate `enterprise-experimental` only when its readiness gate is
   mechanically satisfied.

Do not combine profile-contract implementation with unrelated executor,
provider, authentication, or HA work.
