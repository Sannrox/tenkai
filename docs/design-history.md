# Design history

Founding-era planning from the original design document (v0.1, 2026-07-08),
kept as history. The current architecture is explained in
[DESIGN.md](../DESIGN.md); accepted decisions are the
[ADRs](decisions/README.md); shipped capabilities are in
[capabilities and roadmap](capabilities.md).

## Decided since

| Founding question or plan | Outcome |
| --- | --- |
| sekai-chisei as the operational store | Tenkai owns operational persistence; sekai-chisei is an optional provider ([ADR 0001](decisions/0001-standalone-core-and-service-evolution.md), [operational storage](operational-storage.md)) |
| Plan/step format | Tenkai-owned, versioned plan and step formats ([runtime protocol v1](runtime-protocol-v1.md), [offline bundles](offline-bundles.md)) |
| Executor strategy | Manifest shell commands plus in-tree Helm, native `kubectl`, and in-process server-side-apply executors ([software executors](software-executor.md)) |
| Intelligence artifacts written through sekai-chisei APIs (Phase 4) | Tenkai delivers `routing_config` and other staged products itself ([ADR 0002](decisions/0002-tenkai-owned-routing-configuration.md), [staged products](staged-products.md)) |
| Single-org first | Community profiles are tenant-free; tenant isolation is an experimental enterprise profile ([ADR 0010](decisions/0010-supported-operating-profiles.md)) |
| Catalog extraction | Still deferred until ADR 0001's criteria are met |

## Founding plan (v0.1)

### Integration prerequisites

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

### Phasing

The phase narrative below captures the product evolution. Active,
dependency-aware work is maintained in GitHub Issues. The standalone-core,
server/runtime, offline-bundle, and enterprise-composition **architecture**
phases are largely landed on main (see ADRs 0001–0007 and the README Status
table). Remaining work is product depth (multi-env ops tooling, planner
constraints, model executors, enterprise host wiring)—not re-litigating
operational ownership.

Historical note: early phases began as a walking skeleton; every phase still
ends with something demoable.

- **Phase 0 — Contracts.** Establish transport-independent application ports,
  an in-process Catalog boundary, Tenkai-owned plan/step formats, optional sekai
  projection schemas, and an embedded `tenkaictl` host.
- **Phase 1 — Skeleton (imperative).** Catalog accepts a signed release;
  a founding `deploy` sketch (not a live `tenkaictl` command; operators now
  `publish` / `plan` / `apply`) produces a trivial plan; one local
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

### Risks

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

### Open questions

- Plan/step format: custom proto vs embedding an existing spec (e.g. OCI
  artifact + KRM-style objects) — decide in Phase 0.
- Executor strategy: native k8s client vs shelling to helm vs delegating to
  Argo as a backend executor.
- Which measured scaling, availability, or ownership signal will first justify
  extracting Catalog under ADR 0001's criteria?
- Naming: tenkai vs something else in the sekai/chisei family.
