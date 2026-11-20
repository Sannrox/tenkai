# ADR 0059: OpenShift cluster updates through CVO and MCO

- Status: Accepted
- Date: 2026-11-20
- Issue: [#994](https://github.com/Sannrox/tenkai/issues/994)
- Owner: Tenkai maintainers
- Builds on: [ADR 0022](0022-external-delivery-adapter-boundary.md),
  [ADR 0051](0051-host-os-image-updates.md),
  [ADR 0058](0058-no-openshift-executor-adapter.md)
- Related: [external delivery adapters](0022-external-delivery-adapter-boundary.md),
  [software executor](../software-executor.md#openshift-compatibility),
  [OpenShift cluster-update research](../research/openshift-cluster-version-updates.md)

## Context

Operators change OpenShift cluster and node versions with the cluster's own
controllers. Those changes skip Tenkai approvals, maintenance windows, waves
and durable receipts. CVO (Cluster Version Operator) owns the cluster payload.
MCO (Machine Config Operator) owns node config and the reboot. Tenkai must not
replace either, and must not treat a node reboot as a host-applier step
(ADR 0051 leaves cluster-managed reboots out of scope).

ADR 0022 already lets an external system apply a bounded effect while Tenkai
owns the plan, the receipt and recovery. The remaining choice is whether
Tenkai may *request* a CVO update and *judge* it from `ClusterVersion` and
`MachineConfigPool` conditions.

## Decision

Go, with a narrow adapter: Tenkai owns the decision to update, the durable
intent written before the request, the window, and the verdict. CVO and MCO
stay the source of truth for the payload and the nodes.

This is not a software executor and not a fourth Kubernetes apply path
(ADR 0058). It is an ADR 0022 adapter that runs on the Tenkai server.

### 1. Ownership split

| Tenkai | CVO / MCO |
| --- | --- |
| Signed release naming the target payload digest | Selecting and applying the release payload |
| Approval, maintenance window, durable intent | Rebooting nodes and reconciling machine config |
| Patch of `ClusterVersion.spec.desiredUpdate` | `ClusterVersion` and `MachineConfigPool` status |
| Verdict from those status objects | Continuing the update if Tenkai disconnects |
| Audit receipt bound to plan, environment, attempt | |

Tenkai never writes a node, a boot loader, or a machine config, and never
replaces CVO or MCO.

### 2. Request

The signed release names the payload **image digest** (and the version string
when the image carries one). Publication refuses a cluster-update release on
any software or host executor.

The adapter, on the server, patches the cluster-scoped `ClusterVersion` named
`version`:

- `spec.desiredUpdate.image` is the digest the approved plan names;
- `spec.desiredUpdate.version` is set only when the release also names it, and
  must match the image;
- `spec.desiredUpdate.force` is never true.

Apply acknowledgement is not success (ADR 0022). The step stays non-terminal
until observe returns a receipt.

Before the patch, the adapter fails closed when:

- the named digest is lower than the completed history version (no downgrade,
  including z-stream);
- `Upgradeable=False` would block the path;
- the digest is not in `status.availableUpdates`, unless the release is the
  disconnected form that names an already-mirrored digest;
- a previous update is still `Progressing` or a history entry is `Partial`.

### 3. Observe

Tenkai polls. A callback has no extra authority.

Conditions on `ClusterVersion` are admitted only when
`status.observedGeneration` equals `metadata.generation`. Success requires
all of:

1. `ClusterVersion` `Available=True`, `Progressing=False`, `Degraded=False`;
2. `status.history[0]` `state=Completed` for the expected image;
3. every `MachineConfigPool`: `Updated=True`, `Updating=False`, `Degraded=False`.

`Available=True` on `ClusterVersion` while a pool is still `Updating` is not
success. Control plane done is not cluster done.

| Outcome | How it is decided | Result |
| --- | --- | --- |
| Payload and every pool match the digest | observe as above | Receipt success |
| `Degraded=True` on `ClusterVersion` or a pool | poll until the deadline, then fail naming the object | Receipt failure; CVO keeps the cluster |
| A node returns late, pool stays `Updating` | same deadline | Receipt failure `no_return` on that pool |
| Controller or API disconnect | intent already durable; observe resumes | Non-terminal until deadline |
| Deadline with no success | server clock from the stored intent | Receipt failure `no_return` |

The deadline is part of the signed release. The server counts it from the
time it durably recorded the apply acknowledgement, so a restart or takeover
can still judge `no_return`.

### 4. Credentials

The adapter uses a **cluster-scoped** kubeconfig that is not the environment
runtime credential and not a software-executor kubeconfig.

Least privilege, and no others:

| API | Verbs |
| --- | --- |
| `clusterversions.config.openshift.io` | get, list, watch, patch |
| `clusteroperators.config.openshift.io` | get, list, watch |
| `machineconfigpools.machineconfiguration.openshift.io` | get, list, watch |

The credential is never in a plan, a receipt, a log, or a command line. It
does not grant namespace creates, workload applies, or host-applier rights.

### 5. Where the adapter runs, windows, waves

The server calls `apply` / `observe` (the existing `DeliveryAdapter` port).
The environment runtime does not hold this credential: the nodes it runs on
reboot during the update.

If the only Tenkai server is on the cluster it is updating, it cannot judge
`no_return` while it is down. Sites that need that verdict keep a hub or
spoke standby elsewhere, as for a host OS image update (ADR 0051 §4).

A maintenance window must cover the whole deadline. The plan waits rather
than start with less window left than that.

A cluster update is one plan against the cluster, not a workload wave
(ADR 0017). Environments that run on that cluster stay held until the
receipt is success. The adapter's `rollback_fails` is true: health failure
must not start a Tenkai rollback of the cluster version.

### 6. No downgrade, no Tenkai rollback

OpenShift does not support reverting a cluster version. Tenkai never writes
a `desiredUpdate` lower than the completed history, never sets `force`, and
never treats a previous payload as a restore target.

A failed or partial update stays the cluster's problem. Recovery is a new
approved plan toward a newer supported payload, or operator action outside
Tenkai. Tenkai recovery of *its own* store does not depend on CVO.

## Kill criteria

Stop and record a no-go if any of these proves true while implementing:

- observe cannot be implemented without `force` or a downgrade write;
- the cluster-scoped credential cannot be kept off software-executor and
  runtime kubeconfigs;
- `ClusterVersion` success cannot be combined with every
  `MachineConfigPool` reaching `Updated` (so a late node would be recorded
  as success);
- the deadline cannot be judged from durable state after a server restart
  or takeover;
- apply acknowledgement completes the Tenkai plan.

## Out of scope

- Replacing CVO or MCO, or patching node OS images as a host release
  (ADR 0051).
- Pausing `MachineConfigPool` objects, EUS hops, or channel changes.
- Unsigned payloads and `desiredUpdate.force`.
- Allowlisting `ClusterVersion` on `kubernetes-inprocess` (ADR 0058).

## Consequences

- Cluster and node version changes can go through Tenkai approval, windows
  and receipts without Tenkai owning the updater.
- A software executor still cannot write cluster-scoped update objects.
- Operators lose Tenkai-driven rollback for this change class. That matches
  the platform.
- An in-progress CVO update continues if Tenkai dies; Tenkai only fails the
  step at the deadline.

## Alternatives considered

- **Leave cluster updates outside Tenkai.** Approvals, windows and receipts
  stay skipped for the riskiest change on the cluster.
- **Write `ClusterVersion` from a software executor.** Mixes cluster-scoped
  update rights with workload apply and the in-process kind allowlist
  (ADR 0058).
- **Treat the node reboot as ADR 0051 host OS steps.** The cluster owns the
  reboot; the host applier is not the witness.
- **Judge only `ClusterVersion` `Available`.** Control plane can be done
  while a pool is still updating or degraded.

## Drill

Non-production cases (procedure in the
[research note](../research/openshift-cluster-version-updates.md#drill)):

1. Upgrade to a recommended digest.
2. A pool that stays `Degraded` through the deadline.
3. Tenkai disconnected after apply acknowledgement, CVO still running.
4. A node that returns after the deadline.

## Follow-up on acceptance

Feature Issues: the cluster-update release section and publication check;
the server-side adapter on `DeliveryAdapter` with `rollback_fails`; the
separate cluster-scoped credential; deadline and window fit; operator
documentation. Do not file them from this research lane.
