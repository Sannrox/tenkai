# ADR 0049: Removing instances of built-in executors

- Status: Accepted
- Date: 2026-11-09
- Issue: [#1137](https://github.com/Sannrox/tenkai/issues/1137)
- Owner: Tenkai maintainers
- Amends: [ADR 0048](0048-runtime-runs-built-in-executors.md) §3 (which
  removals a plan makes),
  [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md) §1
  (how a product changes executor)
- Builds on: [ADR 0043](0043-product-dependencies.md) §3 and §5,
  [ADR 0044](0044-product-instances-and-dependency-bindings.md) §3,
  [ADR 0045](0045-sealed-secrets.md)
- Implementation: [#1132](https://github.com/Sannrox/tenkai/issues/1132)

## Context

A plan removes only `host` releases. `env unsubscribe` refuses an instance
whose deployed release runs on `helm`, `kubernetes`, `kubernetes-inprocess`,
`docker` or `shell`, and the planner and the runtime release package refuse
such a removal too. No decision record chose that rule. ADR 0048 §3 repeats
it in passing, and the server guide and the runtime protocol document it.

ADR 0041 §1 assumes the opposite: moving a product to another executor "is an
explicit remove of the old product followed by an install of the new one".
Outside `host`, that remove cannot be planned today.

So operators uninstall these products by hand, and Tenkai keeps recording
them as deployed. Its plans, dependency documents and status describe a
deployment that is gone. On an environment runtime, a Helm instance removed
by hand also leaves its Tenkai-owned sealed Secrets behind (ADR 0048 §4).

Every built-in executor already has a removal path. The Helm, Kubernetes and
Docker executors implement `remove`, which apply already uses when it restores
a failed step's previous release, and a `shell` release may declare
`deploy.uninstall`. The planner already orders removals against dependency
edges (ADR 0043 §3).

## Decision

### 1. Scope

- A `helm`, `kubernetes`, `kubernetes-inprocess` or `docker` release is
  removed through its executor's `remove`.
- A `shell` release is removed through its `deploy.uninstall`. A `shell`
  release without one cannot be removed: unsubscribing is refused and names
  the missing command. Tenkai never forgets a deployment that keeps running.
- `host` releases keep their removal through the root-side applier
  (ADR 0041 §2).
- Model-runtime and routing-config products are out of scope.

The executor is the one the deployed release resolves to (ADR 0041 §1). When
a failed step left the deployment unknown, each release that may be present
is removed with its own executor, as host removals already do.

### 2. Approval

A removal is a plan step, approved like any other change under the
environment's approval policy, as host uninstalls already are. A plan with a
removal takes the `execute_plan` quorum, and the quorum rules for the
environment's criticality apply as to any other plan. There is no separate
removal purpose; one can be added if an environment needs a stricter quorum
for removals alone. Nothing is removed at unsubscribe time: unsubscribing
changes desired state, and the next approved plan removes the instance.

### 3. Dependents

Unsubscribing an instance is refused, naming the dependents, while another
subscribed instance holds a dependency binding to it (ADR 0044 §3) or needs
it as the sole provider of a required contract (ADR 0043 §5). Unsubscribing
those dependents first lifts the refusal, and the next plan removes them all.
The planner orders the removal steps dependents first, as ADR 0043 §3
already orders removals, and refuses a plan that would invert an edge.

### 4. Fence

Unsubscribing names the version it expects to remove: the deployed version,
or the failed target's when that is all that is recorded. It is the
counterpart of the generation a host step names. It is refused, naming what
is recorded, when it names another version, or names none while a release is
recorded. It is refused while a plan for the environment is applying, because
unsubscribing holds the environment apply lease. A remote unsubscribe also
keeps its `--generation`, the environment lease generation (#703).

### 5. Data

A removal deletes what the release declares, through its executor, and
nothing else. Tenkai adds no data deletion of its own and no retention
override. What survives is the release's packaging decision:

- **Helm:** `helm uninstall` deletes the chart's resources, including
  PersistentVolumeClaims the chart declares directly. Resources annotated
  `helm.sh/resource-policy: keep` survive, and so do claims created from a
  StatefulSet's claim templates under the default `Retain` retention policy;
  a StatefulSet that declares `whenDeleted: Delete` loses them.
- **`kubernetes` and `kubernetes-inprocess`:** every resource in the
  release's manifests is deleted, including a declared PersistentVolumeClaim.
  Claims created from a StatefulSet's claim templates follow that
  StatefulSet's retention policy, as above.
- **Docker:** containers and networks are removed. Volumes are not.
- **`shell`:** whatever `deploy.uninstall` deletes.

The operator guide lists this per executor, and the plan shows the removal
step before it is approved. Tenkai-owned sealed Secrets are deleted with the
instance, as a runtime already does on every Helm removal it runs (ADR 0048
§4, #1128).

### 6. Recorded state

As for a host uninstall, a removed instance is recorded as no longer
deployed, and the removed release becomes its rollback target. Subscribing
again installs it fresh.

### 7. Rolling compatibility

The server and the environment runtime both run removals. A server that
predates this decision refuses a non-host removal: its planner refuses the
plan, and its release-package endpoint answers `412`, so a runtime that
claims the step from it fails the step visibly. A removal is never skipped,
and an instance is recorded as removed only by a removal that ran.

### 8. Changing executor

This confirms ADR 0041 §1: a product moves to another executor by unsubscribing
it, applying the approved removal, then subscribing the release that declares
the new executor. A plan that would replace the installed release with one of
another executor in place stays refused.

## Consequences

- `env unsubscribe` works for every built-in executor, and Tenkai's records
  stay true after a product is removed.
- The executor change ADR 0041 describes can be planned.
- A removal is a destructive step under ordinary approval. Environments that
  want more friction raise their `execute_plan` quorum or criticality.
- Whether product data outlives the instance depends on how the release
  packages it. A release that declares its data claims directly loses them
  on removal. Data that survives stays an operator task to reclaim, and
  subscribing again may find it.
- An unsubscribe request names the expected version, which it did not before.
- Once implemented (#1132), this supersedes the sentence "Only host releases
  are removed by a plan" in ADR 0048 §3, the server guide and the runtime
  protocol. The guide and the protocol change with that implementation.

## Alternatives considered

- **Keep host-only removal.** Rejected: operators remove products outside
  Tenkai anyway, and Tenkai then records a deployment that does not exist and
  leaves its own Secrets behind.
- **Forget the deployment without removing it.** Rejected: the product keeps
  running while Tenkai stops managing it, and its sealed Secrets stay.
- **Tenkai deletes all product data with the instance.** Rejected:
  irreversible, and Tenkai cannot tell product data from data other things
  still need.
- **Tenkai keeps every PersistentVolumeClaim, overriding the release.**
  Rejected: Tenkai would change what a signed release declares, a product
  that wants its claims removed could not say so, and Helm offers no
  uninstall flag for it. Retention stays a packaging decision the release
  makes and the guide documents.
- **Remove dependents automatically.** Rejected: removing one instance would
  silently remove others. Naming the dependents keeps every removal explicit.
- **A stricter quorum or a separate approval purpose for removals.**
  Deferred: host uninstalls already run under ordinary approval, and a
  `remove` purpose is an additive policy change once an environment needs
  it.
- **Fence on the environment lease generation alone.** Rejected: that
  generation advances with every change in the environment, so it does not
  say which release the operator meant to remove.
