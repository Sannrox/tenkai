# Tenkai architecture

Tenkai (展開, "deployment / unfolding") is a constraint-based delivery control
plane. This page explains how it is built and why. Accepted decisions are the
[architecture decision records](docs/decisions/README.md); founding-era
planning is kept in [design history](docs/design-history.md).

## Purpose

`tenkai` is a continuous deployment control plane for **declarative,
constraint-based, fleet-scale software delivery**. It
does not run pipelines that push builds to environments. Publishers cut
releases into channels; environment owners declare constraints; a reconciler
continuously computes and executes valid upgrade plans per environment, gated
by health and eval checks, with automatic rollback.

Two kinds of things are deployable, as equals:

1. **Software** — services, containers, agent runtimes, edge binaries.
2. **Intelligence artifacts** — model routing configs, governance policies, eval
   suites, action definitions, agent definitions, capability bundles.

The second is the differentiator. Argo CD can ship a container; nothing today
ships "the new Claude model, adopted per-environment the moment that
environment's own eval gates pass, on that environment's own channel policy."
tenkai treats a model migration and a service upgrade as the same governed
operation.

Tenkai is the operational system of record. It owns releases, channels,
environments, plans, execution, rollback, and recovery, and owns all of its
state, types, and contracts. It has no runtime, build, or wire dependency on an
external graph or governance service. Evidence flows in: producers push signed
evidence (evaluation results, provenance, approvals) to Tenkai, and an
operation fails closed only when an environment policy or approved plan makes
that evidence part of its contract
([ADR 0064](docs/decisions/0064-tenkai-stands-alone.md)).

## Why this product

- **GitOps stops at the cluster boundary.** Argo/Flux assume a connected
  cluster you control and a git repo as desired state. Fleets of heterogeneous,
  regulated, or disconnected environments — customer VPCs, on-prem, edge,
  air-gapped — need a *catalog + constraints + planner* model, not a repo sync.
- **Nobody governs intelligence rollout.** Model upgrades, prompt/policy
  changes, and agent definition changes ship today as config edits with no
  channels, no gates, no rollback. Tenkai gives them the same channels,
  signed evaluation evidence gates, and rollback as software.
- **Deployment outcomes are the record.** Tenkai records every rollout,
  failure, and rollback in its own operational state, inspectable through the
  CLI and HTTP API and delivered to opt-in webhooks.

## Non-goals

- Not a CI system: tenkai consumes built, signed artifacts; it never builds.
- Not an orchestrator/scheduler of agent work: Tenkai may manage the
  deployment and lifecycle of a Shikigami worker pool, but admission, work
  selection, claims, leases, fencing, retry/park decisions, and receipts stay
  with the worker system (ADR 0011).
- Not a git replacement: desired state lives in the Tenkai Catalog and
  environment constraints; git can feed the Catalog.
- Not a hosted multi-tenant service: community profiles are tenant-free, and
  tenant isolation is an experimental enterprise profile
  ([ADR 0010](docs/decisions/0010-supported-operating-profiles.md)).

## Core concepts

These are Tenkai domain types, persisted in Tenkai's own operational store (see
[domain objects](docs/operational-storage.md#domain-objects)), with record
types defined in `proto/tenkai/`. Lineage (release → artifacts → SBOM;
deployment → plan → release → publisher) lives in the same store.

| Concept | What it is |
| --- | --- |
| **Product** | The unit of delivery: a versioned manifest declaring artifacts (OCI images, binaries, bundles), configuration schema, dependencies on other products (semver ranges), required capabilities of the target, health probes, and optional post-apply SLO gates. Intelligence products declare governance artifacts instead of images. |
| **Release** | An immutable, signed version of a product: artifact digests, SBOM, provenance, changelog. |
| **Channel** | A named stream per product (`dev`, `canary`, `stable`, `hotfix`). Publishing = pointing a channel at a release. |
| **Environment** | A managed target: k8s cluster, VM host, edge device, air-gapped enclave. Declares: subscribed channels, maintenance windows, compliance/policy constraints, capability facts (k8s version, GPU, region, data classification), connectivity class (connected / intermittent / isolated). |
| **Constraint** | A rule bounding what the planner may do: version pins/ranges, "only releases that passed eval suite E in this environment", "no upgrades outside window W", "products with data_class=restricted never leave region R". |
| **Plan** | A computed, ordered set of install/upgrade/rollback steps for one environment, satisfying every constraint and the product dependency graph. Immutable once approved; the audit answers "why did this change happen" forever. |
| **Deployment** | The record of a plan's execution: per-step status, health results, gate results, rollback linkage. |

## Architecture

```
 publishers (CI, humans)          operators: tenkaictl, web console
          │ publish / promote               │ HTTP management API
          ▼                                 ▼
 ┌────────────────────────────────────────────────────┐
 │ Tenkai application core                            │◀┄┄ signed evidence
 │ Catalog · planner/reconciler · gates · approvals   │    (evaluation results,
 │ operational store (SQLite; Postgres hub)           │     provenance), pushed in
 │ hosted by: tenkaictl (embedded) or tenkai-server   │
 └───────────┬───────────────────────┬────────────────┘
             │ executes in-process   │ plans pulled
             ▼                       ▼
     local executors          tenkai-runtime (one per environment)
     (shell, Helm,            ── or signed offline bundles for
      Kubernetes)                isolated environments
```

One Rust application core runs in two hosts with the same contracts,
transactions, and recovery semantics; transport is not a domain boundary:

- **`tenkaictl`** is the embedded host and CLI. With no server it runs the whole
  core against a local SQLite store, and with `--target remote` it calls a
  server instead (see [run tenkai-server](docs/run-tenkai-server.md)).
- **`tenkai-server`** hosts the same core over HTTP: a versioned management API
  ([management lifecycle](docs/management-lifecycle.md)), continuous
  reconciliation, health probes, and scoped runtime endpoints. It verifies
  bearer, JWT, or OIDC credentials
  ([authenticated request context](docs/auth-request-context.md)).
- **Catalog** is an in-process application boundary. It accepts release
  publications (manifest, digests, signature), manages channels, and stores
  references to payloads that live in OCI registries or blob stores. Signatures
  are verified on publish ([release signing](docs/release-signing.md)).
  Extraction into a service is deferred until ADR 0001's criteria are met.
- **Planner and reconciler** is the heart of the core. Per environment it
  compares channel heads and constraints with reported state, computes a plan
  (semver ranges and topological ordering, not a full SAT solver), checks
  gates, maintenance windows, and approvals, executes under a generation-fenced
  lease, probes health, and rolls back on failure.
- **Executors** apply plan steps. Manifests run shell commands by default;
  in-tree Helm, native `kubectl`, in-process server-side-apply, and Docker host
  executors handle software targets ([software executors](docs/software-executor.md)).
- **`tenkai-runtime`** is a pull-only process scoped to one environment. It
  pulls plans (never pushed, so it works through NAT and firewalls), runs a
  local executor under the claim's fencing generation, and reports receipts
  ([runtime protocol v1](docs/runtime-protocol-v1.md)). Isolated environments
  instead import signed [offline bundles](docs/offline-bundles.md) and export
  receipts.
- **Shikigami worker-pool lifecycle**: when configured as a delivery product,
  Tenkai binds an immutable release to an environment-scoped pool and
  reconciles its capacity, rollout, drain, health, and recovery. The Shikigami
  serve host pulls and executes admitted work; Tenkai never selects or
  acknowledges individual work
  ([ADR 0011](docs/decisions/0011-shikigami-worker-pool-lifecycle.md),
  [worker pools](docs/worker-pool.md)).
- **Web console** is a separate client of the public HTTP API, with no
  privileged access ([ADR 0031](docs/decisions/0031-web-console.md)).

Operating profiles (`local`, `fleet`, `enterprise-experimental`) fix which
store, processes, and authentication a deployment uses
([ADR 0010](docs/decisions/0010-supported-operating-profiles.md)).

### Evidence and integrations

Tenkai stores the evidence its gates read; it never pulls it from another
system. Evaluation results arrive as signed evaluation evidence through the
[model release evidence](docs/model-release-evidence.md) ingest path, and
`[gate].eval_suite` blocks on missing, stale, or invalid recorded evidence.
Gate providers, deploy webhooks, and notifications are optional adapters: their
failures stay visible and durably retryable, and recovery never depends on
them. The evidence identifiers and adapter contracts are in
[provider contracts](docs/provider-contracts.md).

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
  signatures + approval evidence. Receipt
  import targets the same Tenkai application contract as connected execution.
