# tenkai — a constraint-based deployment control plane on sekai-chisei

> Founding design document, v0.1 (2026-07-08). Working name: **tenkai** (展開,
> "deployment / unfolding") — sibling to sekai (world) and chisei (intelligence).
> Rename freely; the name is used as a placeholder throughout.

## Purpose

`tenkai` is a continuous deployment control plane for **declarative,
constraint-based, fleet-scale software delivery**. It
does not run pipelines that push builds to environments. Publishers cut
releases into channels; environment owners declare constraints; a reconciler
continuously computes and executes valid upgrade plans per environment, gated
by health and eval checks, with automatic rollback.

Two kinds of things are deployable, as equals:

1. **Software** — services, containers, agent runtimes, edge binaries.
2. **Intelligence artifacts** — model routing configs, chisei policies, eval
   suites, action definitions, agent definitions, capability bundles.

The second is the differentiator. Argo CD can ship a container; nothing today
ships "the new Claude model, adopted per-environment the moment that
environment's own eval gates pass, on that environment's own channel policy."
tenkai treats a model migration and a service upgrade as the same governed
operation.

In the accepted target architecture, `sekai-chisei` provides optional graph
projection, governance, evaluation, and learning while Tenkai is the operational
system of record. Current v0 still uses sekai as its operational store pending
the migration in ADR 0001. chisei evidence is required, and failure is closed,
only when an environment policy or approved plan makes that evidence part of
the operation's contract.

## Why this product

- **GitOps stops at the cluster boundary.** Argo/Flux assume a connected
  cluster you control and a git repo as desired state. Fleets of heterogeneous,
  regulated, or disconnected environments — customer VPCs, on-prem, edge,
  air-gapped — need a *catalog + constraints + planner* model, not a repo sync.
- **Nobody governs intelligence rollout.** Model upgrades, prompt/policy
  changes, and agent definition changes ship today as config edits with no
  channels, no gates, no rollback. sekai-chisei already has the eval and policy
  machinery; tenkai gives it a delivery mechanism.
- **Deployment outcomes are learning signal.** Tenkai records every rollout,
  failure, and rollback in operational state. When configured, the durable
  sekai projection feeds those outcomes to chisei's evolve/pattern-mining loop,
  which can learn "upgrades of product P fail on environments with property X"
  and feed that back into planning.

## Non-goals

- Not a CI system: tenkai consumes built, signed artifacts; it never builds.
- Not an orchestrator/scheduler of agent work (that stays out, same as
  sekai-chisei Plan 10).
- Not a git replacement: desired state lives in the Tenkai Catalog and
  environment constraints, with optional audit projection to sekai; git can
  feed the Catalog.
- Not multi-tenant SaaS in v1: single-org control plane first.

## Core concepts (the ontology)

These are Tenkai domain types. Current v0 authoritatively encodes them as
**sekai schema types** in a `tenkai` namespace, where links provide lineage
(release → artifacts → SBOM; deployment → plan → release → publisher) via
`Traverse`. After ADR 0001's persistence migration and explicit authority
cutover, the graph becomes an optional integration projection of Tenkai-owned
operational state.

| Concept | What it is |
| --- | --- |
| **Product** | The unit of delivery: a versioned manifest declaring artifacts (OCI images, binaries, bundles), configuration schema, dependencies on other products (semver ranges), required capabilities of the target, and health probes. Intelligence products declare governance artifacts instead of images. |
| **Release** | An immutable, signed version of a product: artifact digests, SBOM, provenance, changelog. |
| **Channel** | A named stream per product (`dev`, `canary`, `stable`, `hotfix`). Publishing = pointing a channel at a release. |
| **Environment** | A managed target: k8s cluster, VM host, edge device, air-gapped enclave. Declares: subscribed channels, maintenance windows, compliance/policy constraints, capability facts (k8s version, GPU, region, data classification), connectivity class (connected / intermittent / disconnected). |
| **Constraint** | A rule bounding what the planner may do: version pins/ranges, "only releases that passed eval suite E in this environment", "no upgrades outside window W", "products with data_class=restricted never leave region R". |
| **Plan** | A computed, ordered set of install/upgrade/rollback steps for one environment, satisfying every constraint and the product dependency graph. Immutable once approved; the audit answers "why did this change happen" forever. |
| **Deployment** | The record of a plan's execution: per-step status, health results, gate results, rollback linkage. |

## Architecture

```
                    ┌──────────────────────────────┐
 publishers ──────▶│  Catalog (in-process)          │
 (CI, humans)      │  releases, channels, signing  │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐        ┌─────────────────┐
                    │  Tenkai application core      │◀──────▶│  sekai-chisei    │
                    │  reconciler + constraint     │  gRPC  │  graph, audit,   │
                    │  solver + gate orchestration │        │  policy, evals,  │
                    └──────────────┬───────────────┘        │  budget, actions │
                                   │ plans (pull)           └─────────────────┘
             ┌─────────────────────┼─────────────────────┐
             ▼                     ▼                     ▼ (signed bundle
      ┌─────────────┐       ┌─────────────┐       ┌─────────────┐  export/import)
      │ env runtime  │       │ env runtime  │       │ env runtime  │
      │ env: prod-eu │       │ env: edge-7  │       │ env: airgap  │
      └─────────────┘       └─────────────┘       └─────────────┘
```

One Rust application core supports an embedded CLI host and a networked server
host. Application contracts, transactions, and recovery semantics are shared;
gRPC is a transport rather than a domain boundary:

- **Catalog** — initially an in-process application boundary. Accepts release publications
  (manifest + digests + signature), manages channels, serves artifact metadata
  (artifacts themselves live in OCI registries / blob stores; the catalog
  stores references and digests). Verifies signatures on publish (sigstore-
  style keyless or org keys).
- **Planner/reconciler** — the heart of the application core. A loop per environment:
  observe desired state (channel heads + constraints) vs reported state,
  compute a plan (dependency/version solving — start with a simple topological
  + semver solver, not full SAT), run pre-gates, emit the plan for the
  environment runtime, watch execution, run post-gates, trigger rollback plans
  on failure.
- **environment runtime** — a small executor scoped to one environment. Pulls plans (never
  pushed — works through NAT/firewalls), applies steps via pluggable
  executors (`kubernetes` first; `compose`/`systemd` later), reports state and
  health. For disconnected environments the same runtime consumes **signed
  bundles** (plan + artifacts) imported out-of-band, and exports signed state
  receipts back.
- **tenkaictl** — CLI: `publish`, `promote`, `env register`, `env constrain`,
  `plan show`, `rollback`, `fleet status`.

Catalog extraction is deferred until measured scaling or isolation needs,
versioned remote contracts, consistency, operations, and a reversible migration
are all demonstrated. Full criteria and provider failure rules are in ADR 0001.

### What sekai-chisei can provide (the connection)

These optional capabilities exist on sekai-chisei's gRPC surface. A capability
becomes required for an operation when policy or an approved plan requires its
evidence; that operation then fails closed if the provider is unavailable or
invalid. Optional failures remain visible and durably retryable. Recovery never
depends on these integrations:

| tenkai need | sekai-chisei API |
| --- | --- |
| Domain projections, links, lineage | `SekaiService` objects/links/`Traverse`, `CreateSchemaType` for the tenkai ontology |
| Immutable audit of every publish/promote/plan/deploy | audit records + object history |
| "Who may promote to prod-eu?" | `ResolvePolicy` / namespace policy |
| Eval-gated promotion | `CreateEvalRun` / `GetEvalRun` / `CompareRuns` — a gate is "run suite S against candidate, compare to baseline, block on regression" |
| Governed execution of destructive steps | `PlanExecution` / `ExecutePlan(Stream)` — tenkai plan steps map onto governed actions (PR #57) |
| Cost-aware rollout (esp. model rollouts) | `CheckBudget` / `RecordUsage` |
| Learning from deployment outcomes | `RecordSampleObservation`, evolve/pattern APIs — mine failure patterns across the fleet |
| AI-assisted ops (plan explanation, incident triage, release notes) | `LlmService.Chat` through the governed gateway |

### Trust model

- Releases are signed at publish; environment runtimes verify digests +
  signatures before applying anything. Catalog descriptors refer to payloads
  in external content-addressed OCI or blob storage.
- Environment runtimes hold scoped credentials for exactly one environment. A
  runtime can only pull that environment's plans.
- Plans are approved artifacts: for constrained environments, human or policy
  approval evidence is captured in the Tenkai-owned versioned plan before an
  environment runtime will execute it.
- Air-gapped flow: export bundle = versioned plan + content-addressed payloads +
  signatures + approval evidence. sekai projection data may be included as
  optional metadata but is never verification or recovery material. Receipt
  import targets the same Tenkai application contract as connected execution.

## Integration prerequisites

1. **Tenkai operational persistence.** In the target architecture, the embedded
   host needs durable local storage; horizontally scaled server hosts
   additionally need transactional fencing and coordination. After authority
   cutover, neither mode uses sekai as its recovery store.
2. **Stable public gRPC surface.** For optional sekai-chisei integrations,
   version the protos (or vendor them with a compatibility policy).
3. **Schema-type registration for the tenkai ontology** — already supported via
   `CreateSchemaType`; needs only a reserved namespace convention.
4. **Scoped principals** — the Tenkai server and each environment runtime use
   distinct identities with least-privilege grants.

## Phasing

The phase narrative below captures the product evolution. Active,
dependency-aware work is maintained in GitHub Issues.

Walking skeleton first; every phase ends with something demoable.

- **Phase 0 — Contracts.** Establish transport-independent application ports,
  an in-process Catalog boundary, Tenkai-owned plan/step formats, optional sekai
  projection schemas, and an embedded `tenkaictl` host.
- **Phase 1 — Skeleton (imperative).** Catalog accepts a signed release;
  `tenkaictl deploy <product> <env>` produces a trivial plan; one local
  environment runtime applies it to a k8s (kind) cluster; Tenkai persists the
  lifecycle and durably projects it to sekai when configured. No channels,
  solver, or gates. *Demo: deploy a container through the embedded application
  core and recover from Tenkai-owned state.*
- **Phase 2 — Declarative core.** Channels, environment subscriptions,
  constraints, the reconciler loop, semver dependency solving, drift
  detection. *Demo: promote to `stable`; three environments converge on their
  own schedules; a version-pinned environment correctly refuses.*
- **Phase 3 — Gates & rollback.** Pre/post gates via chisei eval runs and
  health probes; automatic rollback plans; maintenance windows; canary
  (deploy to canary-channel envs, gate fleet-wide promotion on their
  outcomes). *Demo: a bad release auto-rolls-back and blocks fleet promotion.*
- **Phase 4 — Intelligence artifacts.** Product type for governance bundles:
  model routing configs, policies, eval suites, agent definitions. Applying =
  writing through sekai-chisei APIs instead of a cluster. *Demo: a new model
  version rolls out eval-gated across environments — the Plan 16 model-
  sovereignty story, delivered.*
- **Phase 5 — Fleet & disconnection.** Add a server host and versioned remote
  environment-runtime transport around the same application ports, scale-out
  reconciliation, fleet dashboards (`fleet status`, rollout waves), signed
  bundle export/import for air-gapped environments, and optional outcome
  pattern-mining fed back into planning priors.

## Risks

- **Scope: fighting Argo/Flux.** Mitigation: never compete on "sync my repo to
  my cluster." The wedge is fleet + constraints + gates + intelligence
  artifacts. For a single connected cluster, tenkai may even *delegate* to
  Argo as an executor rather than replace it.
- **Constraint solver complexity.** Full dependency SAT is a tarpit. Start
  with semver ranges + topological ordering; add solver sophistication only
  when a real constraint demands it.
- **Runtime blast radius.** The environment runtime is the most privileged component.
  Mitigations: pull-only, plan signatures, scoped credentials, governed-action
  approval for destructive steps, per-environment isolation.
- **Integration coupling.** Governance and learning features may depend on
  sekai-chisei, but Tenkai execution and recovery do not. Required governed
  decisions fail closed; optional projections expose degraded status and retry.
- **Solo-scale.** This is a platform product. The phasing is designed so that
  Phases 1–3 alone are a useful single-team tool ("eval-gated deploys with a
  real audit graph") even if the fleet vision takes longer.

## Open questions

- Plan/step format: custom proto vs embedding an existing spec (e.g. OCI
  artifact + KRM-style objects) — decide in Phase 0.
- Executor strategy: native k8s client vs shelling to helm vs delegating to
  Argo as a backend executor.
- Which measured scaling, availability, or ownership signal will first justify
  extracting Catalog under ADR 0001's criteria?
- Naming: tenkai vs something else in the sekai/chisei family.
