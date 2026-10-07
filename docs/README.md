# Tenkai documentation

Operator, integrator, and contributor docs for the Tenkai delivery control
plane. New here? Run "Try it in five minutes" in the [root README](../README.md)
first. Then pick a section by what you need:

- **[Tutorials](#tutorials)**: learn Tenkai by running a guided path end to end.
- **[How-to guides](#how-to-guides)**: carry out one operational task.
- **[Reference](#reference)**: look up a contract, format, flag, or protocol.
- **[Explanation](#explanation)**: understand why Tenkai is built the way it is.

Several pages still mix these types; each is listed under its main purpose and
will be split over time. Contributor and agent workflow live in
[CONTRIBUTING.md](../CONTRIBUTING.md) and [AGENTS.md](../AGENTS.md).

## Tutorials

| Tutorial | What you do |
| --- | --- |
| [Sign in to the web console with Keycloak](console-sign-in-with-keycloak.md) | Connect a local Keycloak, sign in to `/ui/` with OIDC, and see your grants |
| [Local minikube dogfood](local-dogfood-minikube.md) | Deliver to a laptop Kubernetes cluster, then repeat with signed multi-environment releases and a software canary |
| [Hello minikube example](../examples/hello-minikube/) | The scripts and manual steps behind the minikube path |

## How-to guides

### Operate

| Task | Page |
| --- | --- |
| Install and verify release binaries | [release-binaries.md](release-binaries.md) |
| Run reconciliation, `tenkai-server`, and environment runtimes | [run-tenkai-server.md](run-tenkai-server.md) |
| Configure server authentication (bearer tokens, enterprise JWT, OIDC) | [configure-server-authentication.md](configure-server-authentication.md) |
| Manage environments and maintenance windows | [manage-environments.md](manage-environments.md) |
| Upgrade, roll back, and recover a product | [upgrade-and-rollback.md](upgrade-and-rollback.md) |
| Deploy releases from GitHub | [deploy-from-github.md](deploy-from-github.md) |
| Back up and restore embedded state | [backup-restore.md](backup-restore.md) |
| Diagnose a server and watch fleet drift | [server-diagnostics.md](server-diagnostics.md) |
| Observe and execute rollout waves | [rollout-waves.md](rollout-waves.md) |
| Run a stateful package migration | [package-migrations.md](package-migrations.md) |
| Upgrade across connected, intermittent, and isolated environments | [connectivity-upgrades.md](connectivity-upgrades.md) |
| Run a signed stateful upgrade drill | [examples/package-migration](../examples/package-migration/) |
| Roll out a model, then its routing | [examples/model-routing-rollout](../examples/model-routing-rollout/) |
| Walk through a model-runtime canary | [examples/model-runtime-canary](../examples/model-runtime-canary/) |
| Deliver a workshop module | [examples/workshop-module](../examples/workshop-module/) |
| Drill a two-environment change-set closure | [examples/two-environment-closure](../examples/two-environment-closure/) |

### Maintain and verify Tenkai

| Task | Page |
| --- | --- |
| Tag a release | [release-readiness.md](release-readiness.md) |
| Run the Postgres multi-replica hub lab | [multi-replica-hub-runbook.md](multi-replica-hub-runbook.md) |
| Run the 1,000-environment scale drill | [fleet-workload.md](fleet-workload.md) |

## Reference

| Topic | Page |
| --- | --- |
| Environment variables | [environment-variables.md](environment-variables.md) |
| Capabilities and roadmap | [capabilities.md](capabilities.md) |

### Products and executors

| Topic | Page |
| --- | --- |
| The manifest (`tenkai.toml`) and product kinds | [manifest.md](manifest.md) |
| Software executors (Helm, Kubernetes) | [software-executor.md](software-executor.md) |
| `model_runtime` products | [model-runtime.md](model-runtime.md) |
| Policy, eval-suite, and agent products | [staged-products.md](staged-products.md) |
| Worker pools | [worker-pool.md](worker-pool.md) |
| Workshop modules | [workshop-modules.md](workshop-modules.md) |
| Preview environments | [preview-environments.md](preview-environments.md) |
| Change-set pins | [change-set-pin.md](change-set-pin.md) |
| Advisory plan priors | [plan-priors.md](plan-priors.md) |
| Telemetry spans and metrics | [telemetry.md](telemetry.md) |

### Contracts and formats

| Topic | Page |
| --- | --- |
| Catalog contract | [catalog-contract.md](catalog-contract.md) |
| Delivery manifest profile | [delivery-manifest-profile.md](delivery-manifest-profile.md) |
| Command results (`--output json-v1`) | [command-results.md](command-results.md) |
| Remote management lifecycle (HTTP) | [management-lifecycle.md](management-lifecycle.md) |
| Runtime protocol v1 | [runtime-protocol-v1.md](runtime-protocol-v1.md) |
| Runtime capabilities | [runtime-capabilities.md](runtime-capabilities.md) |
| Provider contracts | [provider-contracts.md](provider-contracts.md) |
| Evaluation gate evidence | [evaluation-gate-evidence.md](evaluation-gate-evidence.md) |
| Offline bundles | [offline-bundles.md](offline-bundles.md) |
| Development fixtures | [development-fixtures.md](development-fixtures.md) |

### Trust and identity

| Topic | Page |
| --- | --- |
| Release signing | [release-signing.md](release-signing.md) |
| Release provenance | [release-provenance.md](release-provenance.md) |
| Plan approval | [plan-approval.md](plan-approval.md) |
| Authenticated request context contract | [auth-request-context.md](auth-request-context.md) |
| Federated identity | [federated-identity.md](federated-identity.md) |

### Storage and conformance

| Topic | Page |
| --- | --- |
| Postgres tenant store | [postgres-tenant-store.md](postgres-tenant-store.md) |
| Delivery-effect conformance | [delivery-effect-conformance.md](delivery-effect-conformance.md) |
| Tenant isolation conformance | [tenant-isolation-conformance.md](tenant-isolation-conformance.md) |

### Releases

- [Release 0.4.2 notes](releases/0.4.2.md)
- [Release 0.4.1 notes](releases/0.4.1.md)
- [Release 0.4.0 notes](releases/0.4.0.md)
- [Release 0.3.2 notes](releases/0.3.2.md)
- [Release 0.3.1 notes](releases/0.3.1.md)
- [Release 0.3.0 notes](releases/0.3.0.md)
- [Release 0.2.0 notes](releases/0.2.0.md)

## Explanation

| Topic | Page |
| --- | --- |
| Architecture | [DESIGN.md](../DESIGN.md) |
| Design history (founding plan and what was decided since) | [design-history.md](design-history.md) |
| Architecture decisions (ADRs) | [decisions/README.md](decisions/README.md) |
| Operational storage and recovery authority | [operational-storage.md](operational-storage.md) |
| Reconcile tick fencing | [reconcile-tick-fencing.md](reconcile-tick-fencing.md) |
| Enterprise integration boundary | [enterprise-integration-boundary.md](enterprise-integration-boundary.md) |

### Research

- [Embedded golden-path usability](research/embedded-golden-path-usability.md)
- [Rollout-control simplification](research/rollout-control-simplification.md)
- [Staged-document product kinds](research/staged-document-product-kinds.md)
