# Tenkai documentation

Operator and contributor docs for the Tenkai delivery control plane. Start at
the [root README](../README.md) for the local golden path, then use this index
to find a topic. Architecture choices live in
[decisions](decisions/README.md). Contributor and agent workflow live in
[CONTRIBUTING.md](../CONTRIBUTING.md) and [AGENTS.md](../AGENTS.md).

## Operate

| Topic | Page |
| --- | --- |
| Local minikube dogfood | [local-dogfood-minikube.md](local-dogfood-minikube.md) |
| Software apply / health / restore | [software-executor.md](software-executor.md) |
| Backup and restore | [backup-restore.md](backup-restore.md) |
| Server diagnostics and fleet tables | [server-diagnostics.md](server-diagnostics.md) |
| Remote management lifecycle | [management-lifecycle.md](management-lifecycle.md) |
| Multi-replica hub runbook | [multi-replica-hub-runbook.md](multi-replica-hub-runbook.md) |
| Release readiness | [release-readiness.md](release-readiness.md) |
| Telemetry | [telemetry.md](telemetry.md) |

## Delivery contracts

| Topic | Page |
| --- | --- |
| Catalog | [catalog-contract.md](catalog-contract.md) |
| Runtime protocol v1 | [runtime-protocol-v1.md](runtime-protocol-v1.md) |
| Runtime capabilities | [runtime-capabilities.md](runtime-capabilities.md) |
| Release signing | [release-signing.md](release-signing.md) |
| Release provenance | [release-provenance.md](release-provenance.md) |
| Plan approval | [plan-approval.md](plan-approval.md) |
| Command results | [command-results.md](command-results.md) |
| Development fixtures | [development-fixtures.md](development-fixtures.md) |
| Offline bundles | [offline-bundles.md](offline-bundles.md) |
| Delivery manifest profile | [delivery-manifest-profile.md](delivery-manifest-profile.md) |
| Delivery-effect conformance | [delivery-effect-conformance.md](delivery-effect-conformance.md) |
| Provider contracts | [provider-contracts.md](provider-contracts.md) |

## Environments, plans, and rollout

| Topic | Page |
| --- | --- |
| Preview environments | [preview-environments.md](preview-environments.md) |
| Change-set pins | [change-set-pin.md](change-set-pin.md) |
| Plan priors | [plan-priors.md](plan-priors.md) |
| Evaluation gate evidence | [evaluation-gate-evidence.md](evaluation-gate-evidence.md) |
| Rollout waves | [rollout-waves.md](rollout-waves.md) |
| Package migrations | [package-migrations.md](package-migrations.md) |
| Connectivity upgrades | [connectivity-upgrades.md](connectivity-upgrades.md) |
| Reconcile tick fencing | [reconcile-tick-fencing.md](reconcile-tick-fencing.md) |
| Fleet workload | [fleet-workload.md](fleet-workload.md) |
| Worker pools | [worker-pool.md](worker-pool.md) |
| Model runtime | [model-runtime.md](model-runtime.md) |
| Staged products | [staged-products.md](staged-products.md) |
| Workshop modules | [workshop-modules.md](workshop-modules.md) |

## Trust, tenancy, and storage

| Topic | Page |
| --- | --- |
| Authenticated request context | [auth-request-context.md](auth-request-context.md) |
| Tenant isolation | [tenant-isolation-conformance.md](tenant-isolation-conformance.md) |
| Federated identity | [federated-identity.md](federated-identity.md) |
| Enterprise integration boundary | [enterprise-integration-boundary.md](enterprise-integration-boundary.md) |
| Operational storage | [operational-storage.md](operational-storage.md) |
| Postgres tenant store | [postgres-tenant-store.md](postgres-tenant-store.md) |

## History and research

- [Architecture decisions](decisions/README.md)
- [Release 0.2.0 notes](releases/0.2.0.md)
- [Embedded golden-path usability](research/embedded-golden-path-usability.md)
- [Rollout-control simplification](research/rollout-control-simplification.md)
- [Staged-document product kinds](research/staged-document-product-kinds.md)
