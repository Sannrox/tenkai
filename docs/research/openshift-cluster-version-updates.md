# OpenShift cluster updates through CVO and MCO

Research for issue [#994](https://github.com/Sannrox/tenkai/issues/994).
The design conclusion is
[ADR 0059](../decisions/0059-openshift-cluster-version-updates.md):
Tenkai may request a supported update and judge it; CVO and MCO stay the
owners of the payload and the nodes.

Revision exercised: `267713903e8d6babcb411a87fe4285d14b376f8a`.

## Question and method

Can Tenkai request a supported OpenShift update and observe
`ClusterVersion` and `MachineConfigPool` without owning node updates?

Evidence is the tracked sources on this revision, plus the published
`config.openshift.io/v1` `ClusterVersion` types. Facts below are marked
`read from source` or `not verified`. No cluster was attached to this lane.

- ADR 0022 adapter port: `apply` acknowledgement is never success; Tenkai
  polls `observe`; receipts are `RuntimeCompletion`
  (`src/delivery_bridge.rs`; `docs/decisions/0022-external-delivery-adapter-boundary.md`)
- Host OS image updates own the reboot only when Tenkai owns the host;
  cluster-managed reboots are out of scope
  (`docs/decisions/0051-host-os-image-updates.md`)
- Kubernetes executors do not write `ClusterVersion`
  ([ADR 0058](../decisions/0058-no-openshift-executor-adapter.md))
- `ClusterVersion.spec.desiredUpdate` triggers the update; conditions
  `Available`, `Progressing`, `Degraded` are valid only when
  `status.observedGeneration` matches `metadata.generation`; history
  entries are `Completed` or `Partial` (`read from source`:
  `config.openshift.io/v1` `ClusterVersion`)
- `MachineConfigPool` conditions `Updated`, `Updating`, `Degraded`
  (`read from source`: operator docs and pool status columns)

Non-goals: replacing CVO/MCO, host-applier node images, workload `Route`
support (#993).

## Comparison

| Concern | Software executors | ADR 0051 host OS | This adapter |
| --- | --- | --- | --- |
| Who applies | Helm / kubectl / in-process | On-host updater | CVO, then MCO |
| Who reboots | none | Tenkai `reboot` step | MCO |
| Credential | environment kubeconfig | root applier | separate cluster-scoped kubeconfig |
| Rollback | previous release | previous image, new plan | none; never a lower `desiredUpdate` |
| Disconnect | ordinary observe | `awaiting_boot` | durable intent, then poll |
| Success | workload ready | booted digest + confirm | `ClusterVersion` completed **and** every pool `Updated` |

## Decision

Generalize the ADR 0022 poll-observe port and the ADR 0051 durable-intent
pattern. Do not add a software executor. Do not allowlist `ClusterVersion`
on in-process. Do not set `force`. Details in ADR 0059.

## Drill

Non-production procedure. Requires an environment-scoped **cluster-update**
kubeconfig (the verbs in ADR 0059 §4), not the workload `TENKAI_CLUSTER_CONFIG`
from [`scripts/drill-openshift-executors.sh`](../../scripts/drill-openshift-executors.sh).

Record API version, current `ClusterVersion` history, and each pool's
`Updated` / `Updating` / `Degraded` before any write.

| Case | What to do | Expected Tenkai verdict |
| --- | --- | --- |
| Upgrade | patch `desiredUpdate` to a recommended digest; poll | success only when history is `Completed` **and** every pool is `Updated` |
| Degraded condition | hold a worker pool degraded (or inject `Degraded=True`) during the update | non-terminal while degraded; fail at deadline naming the pool |
| Disconnected controller | stop the Tenkai server after apply ack, leave CVO running, start it again | intent survived; observe resumes; no second patch |
| Delayed node return | cordon or delay one worker until after the deadline | fail `no_return` on that pool; CVO/MCO may still finish later |

Do not run `--force` or a lower version. Do not use the workload executor
kubeconfig for the patch.

| Field | This lane |
| --- | --- |
| Distribution | none attached (`not verified`) |
| Version | none |
| Recommended updates listed | not queried |
| Pools | not queried |

Assumption from #994: a local single-node OKD or a compact cluster. A
single-node cluster still has at least one `MachineConfigPool`; the success
rule does not skip pools.

## Gaps

Live upgrade, degraded pool, disconnect, and delayed node were not observed
on a cluster in this lane. The drill table is the procedure; it does not
change the go. Workload executor compatibility remains ADR 0058.
