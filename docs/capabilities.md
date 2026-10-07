# Capabilities and roadmap

## Status

**v0 control-plane kernel** (architecture program complete; product depth still
growing). Tenkai owns operational recovery state; optional providers never own
it ([ADR 0001](decisions/0001-standalone-core-and-service-evolution.md),
[operational storage](operational-storage.md)).

## Shipped

| Capability | Where to read |
| --- | --- |
| Embedded one-binary mode (no required network/provider) | [Quickstart](../README.md#try-it-in-five-minutes); [ADR 0001](decisions/0001-standalone-core-and-service-evolution.md) |
| Networked server + continuous reconciliation | [Network server](run-tenkai-server.md); #19 |
| Scoped pull-based environment runtimes + fencing | [Runtime protocol](runtime-protocol-v1.md); #5, #20 |
| Signed release publication and provenance | [Release signing](release-signing.md) |
| Digest-bound OCI artifact references + environment mirrors | [Release signing](release-signing.md#publication-policy); [Catalog contract](catalog-contract.md); #375 |
| Signed plan execution approval | [Plan approval](plan-approval.md) |
| Portable delivery-manifest profile | [Delivery manifest](delivery-manifest-profile.md); [ADR 0021](decisions/0021-portable-delivery-manifest-profile.md); #291 |
| External delivery adapters | [ADR 0022](decisions/0022-external-delivery-adapter-boundary.md); #292 |
| Catalog application boundary | [Catalog contract](catalog-contract.md); ADR 0001 |
| Health probes, auto-rollback, deliberate rollback | [Upgrade and rollback](upgrade-and-rollback.md) |
| Same-version restart, recall roll-off, product windows | [ADR 0016](decisions/0016-same-version-remediation.md); `restart`, `release recall`, `product maintenance` |
| Maintenance windows | [Manage environments](manage-environments.md#maintenance-windows); `product maintenance` |
| Canary cohort promotion evidence | #7; `src/canary.rs` |
| Evaluation gate evidence projection | [Evaluation gate evidence](evaluation-gate-evidence.md); [ADR 0013](decisions/0013-evaluation-gate-evidence-projection.md) |
| Multi-environment rollout waves | [Rollout waves](rollout-waves.md); [ADR 0017](decisions/0017-executable-release-waves.md) |
| Canary × model_runtime promote E2E | [Model runtime](model-runtime.md#canary-promotion-evidence-model_runtime); #108 |
| Multi-environment list/inspect | `tenkaictl env list` / `env inspect`; #56 |
| Authenticated remote status/inspect | `--target remote`; #58 |
| Remote catalog publish / promote / subscribe / recall | [Management lifecycle](management-lifecycle.md); #394 |
| Versioned remote management lifecycle contract | [Management lifecycle](management-lifecycle.md); [ADR 0030](decisions/0030-remote-management-lifecycle.md); #393 |
| Fleet status (embedded and remote) | `tenkaictl fleet status`; [server diagnostics](server-diagnostics.md); #91 |
| Synthetic thousand-environment workload | `tenkaictl fleet generate`; [fleet workload](fleet-workload.md); #299 |
| Fleet drift watch (baseline + exit codes) | `tenkaictl fleet watch`; [server diagnostics](server-diagnostics.md#fleet-drift-watch); #107 |
| Environment capability facts + planner constraints | `env facts` / `env constraints`; #63, #57 |
| Planner model_runtime variant selection by facts | [Model runtime](model-runtime.md); #66 |
| Ordered model_runtime → routing_config rollout | [examples/model-routing-rollout](../examples/model-routing-rollout/); #67 |
| Governed `routing_config` products | [ADR 0002](decisions/0002-tenkai-owned-routing-configuration.md) |
| `model_runtime` product kind + weight cache/eviction | [Model runtime](model-runtime.md); [ADR 0007](decisions/0007-model-runtime-fleet-control-plane.md); #48, #62, #65 |
| Reference llama.cpp engine plugin (fake for CI) | [Model runtime](model-runtime.md); #64 |
| Self-verifying offline bundles | [Offline bundles](offline-bundles.md); [ADR 0003](decisions/0003-canonical-offline-delivery-archives.md) |
| Optional governance/intelligence provider ports | [Provider contracts](provider-contracts.md) |
| Web console served at `/ui/` from a pinned, checksum-verified release (feature `ui`, on in release binaries) | [Open the web console](run-tenkai-server.md#open-the-web-console); [ADR 0031](decisions/0031-web-console.md); #463 |
| OIDC access tokens with group-to-grant mapping, for the web console | [Configure server authentication](configure-server-authentication.md#oidc-access-tokens-468); [ADR 0031](decisions/0031-web-console.md); #468 |
| Durable terminal outcome export to Chisei | [Provider contracts](provider-contracts.md#chisei-terminal-outcome-adapter-197); #197 |
| Remote HTTP GateProvider library adapter (chisei-compatible JSON; not wired into shipped binaries) | [Provider contracts](provider-contracts.md#remote-gate-http-json-contract-113); #113 |
| Optional advisory plan priors (default off) | [Plan priors](plan-priors.md); #114 |
| Staged products: policy_bundle, eval_suite, agent_definition, prompt_package, workshop_module | [Staged products](staged-products.md); [Workshop modules](workshop-modules.md); #115, #116, #117, #285, #290 |
| Change-set closure pin admission | [Change-set pins](change-set-pin.md); [ADR 0018](decisions/0018-change-set-closure-pin.md); #288 |
| Preview environments from a branch pin | [Preview environments](preview-environments.md); #379 |
| Two-environment immutable closure drill | [Change-set pins](change-set-pin.md#two-environment-drill); `examples/two-environment-closure`; #360 |
| Fixed-replica Shikigami worker-pool lifecycle | [Worker pools](worker-pool.md); [ADR 0011](decisions/0011-shikigami-worker-pool-lifecycle.md); [ADR 0028](decisions/0028-live-worker-lifecycle-port.md); #284 / #336 |
| Connectivity-class upgrades | [Connectivity upgrades](connectivity-upgrades.md); [ADR 0020](decisions/0020-connectivity-class-upgrade.md); #287 |
| Governed package migrations | [Package migrations](package-migrations.md); [ADR 0024](decisions/0024-package-migration.md); #289, #334 |
| Signed stateful upgrade crash-recovery drill | [Package migrations](package-migrations.md#signed-stateful-upgrade-drill); `./scripts/stateful-upgrade-drill.sh`; #334 |
| Runtime capability negotiation at startup | [Runtime capabilities](runtime-capabilities.md) |
| Multi-replica / HA capability profile (decision) | [ADR 0009](decisions/0009-multi-replica-reconcile-and-ha-profile.md); #109 |
| AuthStack management HTTP + federation accept path | [Auth context](auth-request-context.md), [federated identity](federated-identity.md); #68, #71 |
| JWT EdDSA enterprise assertion verifier (static keys) | [Auth context](auth-request-context.md#reference-jwt-assertion-verifier-110); #110 |
| Tenant-isolation harness + in-memory tenant store | [Tenant isolation](tenant-isolation-conformance.md); #37, #69, #70 |
| Tenant isolation on all HTTP management surfaces | [Tenant isolation HTTP exposure](tenant-isolation-conformance.md#http-exposure-vs-registry-112); #112 |
| Hub PostgreSQL / spoke-embedded SQLite, one operational port | [Operational storage](operational-storage.md); [ADR 0010](decisions/0010-supported-operating-profiles.md); [ADR 0029](decisions/0029-hub-spoke-operational-store.md); #373 |
| Optional Postgres multi-tenant hub store (feature `postgres`) | [Postgres tenant store](postgres-tenant-store.md); #111 |
| tenkai-server tenant mode → Postgres hub store | [Postgres server wiring](postgres-tenant-store.md#tenkai-server-wiring-127); #127 |
| Postgres hub `shared_replica_state` (single-active writer) | [Shared replica state](postgres-tenant-store.md#shared-replica-state-128); #128 |
| Multi-host reconcile tick fencing | [Tick fencing](reconcile-tick-fencing.md); #129 |
| Fenced multi-replica delivery effects | [Conformance](delivery-effect-conformance.md); #180 |
| Multi-replica hub ops runbook | [Multi-replica hub runbook](multi-replica-hub-runbook.md); #130 |
| Durable Postgres tick fence + inventory heartbeat + OpenMetrics + outcome priors | #135–#138; [tick fencing](reconcile-tick-fencing.md), [plan priors](plan-priors.md) |
| Local minikube dogfood (embedded, no remote server) | [ops note](local-dogfood-minikube.md); #145–#146, #152 |
| Dogfood `tenkaictl dev` release/plan signing (not production KMS) | [ops note](local-dogfood-minikube.md#first-class-dogfood-signing-149); #149 |
| K8s software phase diagnostics (apply/health/restore/remove) | [software executor](software-executor.md); [ops note](local-dogfood-minikube.md#apply--health--restore-diagnostics-150); #150 |
| Software canary cohort drill on minikube dogfood | [ops note](local-dogfood-minikube.md#software-canary-cohort-drill-154); #154 |
| Backup/restore drill and server reconcile diagnostics | [operational storage](operational-storage.md); [server diagnostics](server-diagnostics.md); #59, #60 |
| Delivery OTLP traces and metrics keyed by operation identity | [telemetry](telemetry.md); #380 |
| Release readiness checklist | [release readiness](release-readiness.md); #72 |

Governance integrations remain optional. Required policy or gate decisions fail
closed; configured terminal-outcome export uses a durable retry outbox, while
audit and planning-event export remain unwired and the enterprise profile stays
gated as documented in the [provider contracts](provider-contracts.md) and
[supported operating profiles](decisions/0010-supported-operating-profiles.md).
An embedded apply with `[gate].eval_suite` fails closed locally unless a remote
provider host is explicitly configured; ungated solo deploys never open a
network connection.

## Not yet shipped

Shaped into GitHub Issues as work starts. The architecture program (ADRs 0001–0009) and
the Phase 5 first cut (fleet status/watch/waves, software executors, optional
Postgres hub + multi-replica fencing) are landed on main. Remaining work is
**depth**, not re-litigating operational ownership:

| Track | Intent |
| --- | --- |
| Release packaging | [GitHub Release binaries](release-binaries.md); [v0.4.2 notes](releases/0.4.2.md) |
| Hub HA product claim | Criteria + automated drills before advertising `high_availability` (fence already shipped #135) |
| Intelligence loop depth | Fail-closed prior policy; live remote OutcomeProvider history |
| Executor / model depth | Peer/regional weight caches; additional engines (`kubernetes-inprocess` already shipped) |
| Enterprise host | Live IdP drills, tenant-isolated prior stores (OIDC JWKS discovery and key rotation shipped in #468) |
| Local dogfood | [minikube path](local-dogfood-minikube.md): unsigned + signed multi-env (#152) + **software canary drill** (#154) landed; inventory → `env facts` drill still optional |

Explicit non-priorities until measured need: Catalog service extraction
(ADR 0001), multi-primary SQLite HA (ADR 0009), identity-plane DB co-location.

Founding product intent and long-range roadmap remain in [DESIGN.md](../DESIGN.md);
accepted architecture decisions are the decision log under
[decisions](decisions/README.md).

Active implementation work and dependencies are tracked in **GitHub Issues**
(source of truth for readiness and assignment). Before tagging a release, follow
the [release readiness checklist](release-readiness.md).
