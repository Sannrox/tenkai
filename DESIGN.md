# tenkai — a constraint-based deployment control plane on sekai-chisei

> Founding design document, v0.1 (2026-07-08). Working name: **tenkai** (展開,
> "deployment / unfolding") — sibling to sekai (world) and chisei (intelligence).
> Rename freely; the name is used as a placeholder throughout.

## Purpose

`tenkai` is a continuous deployment control plane in the spirit of Palantir
Apollo: **declarative, constraint-based, fleet-scale software delivery**. It
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

`sekai-chisei` is the backend: sekai is the system of record (every
environment, release, plan, and deployment is a typed object with links,
lineage, and audit), chisei is the gatekeeper (eval gates, policy resolution,
budget-aware rollout decisions, learning from deployment outcomes).

## Why this product

- **GitOps stops at the cluster boundary.** Argo/Flux assume a connected
  cluster you control and a git repo as desired state. Fleets of heterogeneous,
  regulated, or disconnected environments — customer VPCs, on-prem, edge,
  air-gapped — need a *catalog + constraints + planner* model, not a repo sync.
- **Nobody governs intelligence rollout.** Model upgrades, prompt/policy
  changes, and agent definition changes ship today as config edits with no
  channels, no gates, no rollback. sekai-chisei already has the eval and policy
  machinery; tenkai gives it a delivery mechanism.
- **Deployment outcomes are learning signal.** Every rollout, failure, and
  rollback lands in the sekai graph. chisei's evolve/pattern-mining loop can
  learn "upgrades of product P fail on environments with property X" and feed
  that back into planning — a CD system that gets better at deploying.

## Non-goals

- Not a CI system: tenkai consumes built, signed artifacts; it never builds.
- Not an orchestrator/scheduler of agent work (that stays out, same as
  sekai-chisei Plan 10).
- Not a git replacement: desired state lives in the catalog + environment
  constraints, both fully audited in sekai; git can feed the catalog.
- Not multi-tenant SaaS in v1: single-org control plane first.

## Core concepts (the ontology)

All of these are **sekai schema types** in a `tenkai` namespace. tenkai owns no
private database for domain state; sekai's graph is the source of truth. Links
give lineage (release → artifacts → SBOM; deployment → plan → release →
publisher) for free via `Traverse`.

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
 publishers ──────▶│  tenkai-catalog               │
 (CI, humans)      │  releases, channels, signing  │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐        ┌─────────────────┐
                    │  tenkai-planner              │◀──────▶│  sekai-chisei    │
                    │  reconciler + constraint     │  gRPC  │  graph, audit,   │
                    │  solver + gate orchestration │        │  policy, evals,  │
                    └──────────────┬───────────────┘        │  budget, actions │
                                   │ plans (pull)           └─────────────────┘
             ┌─────────────────────┼─────────────────────┐
             ▼                     ▼                     ▼ (signed bundle
      ┌─────────────┐       ┌─────────────┐       ┌─────────────┐  export/import)
      │ tenkai-agent │       │ tenkai-agent │       │ tenkai-agent │
      │ env: prod-eu │       │ env: edge-7  │       │ env: airgap  │
      └─────────────┘       └─────────────┘       └─────────────┘
```

Rust workspace, gRPC-first, mirroring sekai-chisei's stack:

- **tenkai-catalog** — registry service. Accepts release publications
  (manifest + digests + signature), manages channels, serves artifact metadata
  (artifacts themselves live in OCI registries / blob stores; the catalog
  stores references and digests). Verifies signatures on publish (sigstore-
  style keyless or org keys).
- **tenkai-planner** — the heart. A reconciliation loop per environment:
  observe desired state (channel heads + constraints) vs reported state,
  compute a plan (dependency/version solving — start with a simple topological
  + semver solver, not full SAT), run pre-gates, emit the plan for the
  environment's agent, watch execution, run post-gates, trigger rollback plans
  on failure.
- **tenkai-agent** — small per-environment executor. Pulls plans (never
  pushed — works through NAT/firewalls), applies steps via pluggable
  executors (`kubernetes` first; `compose`/`systemd` later), reports state and
  health. For disconnected environments the same agent consumes **signed
  bundles** (plan + artifacts) imported out-of-band, and exports signed state
  receipts back.
- **tenkaictl** — CLI: `publish`, `promote`, `env register`, `env constrain`,
  `plan show`, `rollback`, `fleet status`.

### What sekai-chisei provides (the connection)

Everything below already exists on sekai-chisei's gRPC surface — this is why
the separate-repo choice works without duplicating plumbing:

| tenkai need | sekai-chisei API |
| --- | --- |
| Domain state, links, lineage | `SekaiService` objects/links/`Traverse`, `CreateSchemaType` for the tenkai ontology |
| Immutable audit of every publish/promote/plan/deploy | audit records + object history |
| "Who may promote to prod-eu?" | `ResolvePolicy` / namespace policy |
| Eval-gated promotion | `CreateEvalRun` / `GetEvalRun` / `CompareRuns` — a gate is "run suite S against candidate, compare to baseline, block on regression" |
| Governed execution of destructive steps | `PlanExecution` / `ExecutePlan(Stream)` — tenkai plan steps map onto governed actions (PR #57) |
| Cost-aware rollout (esp. model rollouts) | `CheckBudget` / `RecordUsage` |
| Learning from deployment outcomes | `RecordSampleObservation`, evolve/pattern APIs — mine failure patterns across the fleet |
| AI-assisted ops (plan explanation, incident triage, release notes) | `LlmService.Chat` through the governed gateway |

### Trust model

- Releases are signed at publish; agents verify digests + signatures before
  applying anything. The catalog is not trusted to mutate content.
- Agents hold scoped credentials per environment (sekai's per-key identity —
  Plan 10 Phase D). An agent can only pull its own environment's plans.
- Plans are approved artifacts: for constrained environments, a human or
  policy approval (chisei `ResolvePolicy`) is recorded on the plan object
  before agents will execute it.
- Air-gapped flow: export bundle = plan + artifacts + signatures + the sekai
  object subgraph needed for verification; import produces the same audit
  trail as connected operation.

## Prerequisites on the sekai-chisei side

1. **Plan 20 first (multi-env HA persistence).** A separate product talking to
   sekai-chisei over the network makes the remote/HA store a hard
   prerequisite — single-node SQLite behind one process cannot back a fleet
   control plane. Phase A (storage abstraction) unblocks tenkai development;
   Phase B (Postgres) unblocks production.
2. **Stable public gRPC surface.** tenkai becomes the first external consumer;
   version the protos (or vendor them with a compatibility policy).
3. **Schema-type registration for the tenkai ontology** — already supported via
   `CreateSchemaType`; needs only a reserved namespace convention.
4. **Per-service principals** — tenkai-planner and each tenkai-agent as
   distinct identities with scoped grants (falls out of Plan 10 D / Plan 22).

## Phasing

The phase narrative below captures the product evolution. The executable,
dependency-aware work breakdown is maintained in
[`docs/plans/`](docs/plans/README.md), with parallel lanes in its
[`ROADMAP.md`](docs/plans/ROADMAP.md).

Walking skeleton first; every phase ends with something demoable.

- **Phase 0 — Contracts.** New repo, workspace layout, `tenkai.proto`
  (catalog + planner + agent APIs), sekai schema definitions for the ontology,
  `tenkaictl` stub. Decision record for the plan/step format.
- **Phase 1 — Skeleton (imperative).** Catalog accepts a signed release;
  `tenkaictl deploy <product> <env>` produces a trivial plan; one agent applies
  it to a local k8s (kind) cluster; every object lands in sekai with audit.
  No channels, no solver, no gates. *Demo: deploy a container through the
  full catalog→plan→agent→audit path.*
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
- **Phase 5 — Fleet & disconnection.** Scale-out planner, fleet dashboards
  (`fleet status`, rollout waves), signed bundle export/import for air-gapped
  environments, outcome pattern-mining fed back into planning priors.

## Risks

- **Scope: fighting Argo/Flux.** Mitigation: never compete on "sync my repo to
  my cluster." The wedge is fleet + constraints + gates + intelligence
  artifacts. For a single connected cluster, tenkai may even *delegate* to
  Argo as an executor rather than replace it.
- **Constraint solver complexity.** Full dependency SAT is a tarpit. Start
  with semver ranges + topological ordering; add solver sophistication only
  when a real constraint demands it.
- **Agent blast radius.** The agent is the most privileged component.
  Mitigations: pull-only, plan signatures, scoped credentials, governed-action
  approval for destructive steps, per-environment isolation.
- **Backend coupling.** tenkai's viability depends on sekai-chisei Plan 20
  landing. If it slips, Phase 0–1 can run against local single-node
  sekai-chisei, but do not build fleet features on that.
- **Solo-scale.** This is a platform product. The phasing is designed so that
  Phases 1–3 alone are a useful single-team tool ("eval-gated deploys with a
  real audit graph") even if the fleet vision takes longer.

## Open questions

- Plan/step format: custom proto vs embedding an existing spec (e.g. OCI
  artifact + KRM-style objects) — decide in Phase 0.
- Executor strategy: native k8s client vs shelling to helm vs delegating to
  Argo as a backend executor.
- Does the catalog store go in sekai too, or does high-churn artifact metadata
  warrant its own store with only references in the graph? (Default: sekai
  until it hurts.)
- Naming: tenkai vs something else in the sekai/chisei family.
