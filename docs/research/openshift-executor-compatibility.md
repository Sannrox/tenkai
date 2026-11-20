# OpenShift compatibility of the Kubernetes executors

Research for issue [#993](https://github.com/Sannrox/tenkai/issues/993).
The design conclusion is [ADR 0058](../decisions/0058-no-openshift-executor-adapter.md):
no OpenShift adapter, and no in-process allowlist of `Route`.

Revision exercised: `61c6046c2f7192e8e54bf0de57fd83b64a11024c`.

## Question and method

Do `helm`, `kubernetes` (kubectl), and `kubernetes-inprocess` work on
OpenShift, and does OpenShift need its own executor or an allowlisted
`Route`?

Evidence is the tracked sources on this revision, plus the existing kind
admission drill. A cluster attached to this lane is recorded under
[Drill](#drill). Facts below are marked `read from source` or `not verified`.

- In-process kind allowlist and plan-time refusal
  (`builtin_api_version` / `builtin_resource` in
  `crates/tenkai-executor/src/in_process_kubernetes.rs`; #1208)
- Helm `upgrade --install --create-namespace --wait --timeout 5m`
  (`crates/tenkai-executor/src/helm.rs`)
- kubectl `create namespace` then `apply -f` (`crates/tenkai-executor/src/kubernetes.rs`)
- Rollout wait that names image pull, crash loop, and admission
  (`docs/software-executor.md#waiting-for-rollout`)
- Restricted Pod Security kind drill
  (`an_admission_refusal_fails_the_step_naming_the_policy` in
  `crates/tenkai-executor/tests/in_process_kubernetes_kind.rs`)

Non-goals: cluster provisioning, CVO/MCO (#994).

## Shared contract

OpenShift is a Kubernetes API distribution. Tenkai already has three
executors for that API. A fourth executor would have to keep:

| Obligation | What already exists |
| --- | --- |
| Selection | `[deploy] executor` / `TENKAI_SOFTWARE_EXECUTOR` (ADR 0041) |
| Cluster access | environment-scoped kubeconfig path, never CLI argv or SQLite bytes |
| Namespace | environment name; create if missing |
| Failure | named cause; failed apply cleans up only this attempt |
| Rollback | previous release through the same executor |
| Health | Helm `--wait`; in-process revision wait; kubectl apply then observe |
| CI | default `cargo test` stays cluster-free |

## Comparison

| Concern | Helm | kubectl | In-process |
| --- | --- | --- | --- |
| Supported kinds | whatever the chart and the cluster admit (`read from source`) | whatever the manifests and the cluster admit (`read from source`) | fixed allowlist; `Route` refused at plan and apply (`read from source`) |
| `Route` | applied if `route.openshift.io` exists | applied if the API exists | refused, naming the file and object |
| Restricted SCC / PSS | admission refuses the pod; Helm `--wait` fails | apply may succeed, then observe/wait sees the refusal | wait fails at once on `is forbidden` / `denied the request` |
| Namespace-scoped RBAC | still needs namespace create, or a pre-created namespace | same | same; `Role` / `RoleBinding` only, not `ClusterRole` |
| Image pulls | chart / cluster | same | `ImagePullBackOff` named after 45 s; pre-pull Job copies `imagePullSecrets` |
| Extra privileges | chart may include cluster-scoped objects and CRDs | same if the YAML has them | Namespace create is the only cluster-scoped write |

## Decision

Reuse the three executors. Do not add an OpenShift adapter. Do not allowlist
`Route` on in-process. Record the operator profile in
[software executor](../software-executor.md#openshift-compatibility).

Helm and kubectl are the path for OpenShift-only kinds. In-process is the
fail-closed subset. `Ingress` is already allowlisted when the cluster serves
`networking.k8s.io/v1`. A later namespaced allowlist is a new Issue.

## Drill

Repeatable procedure: [`scripts/drill-openshift-executors.sh`](../../scripts/drill-openshift-executors.sh).
It refuses implicit `KUBECONFIG`, requires an environment-scoped
`TENKAI_CLUSTER_CONFIG` file, records the API server version and whether
`route.openshift.io` and `security.openshift.io` exist, then runs the
ignored in-process kind tests and the kubectl smoke.

| Field | This lane |
| --- | --- |
| Distribution | none attached (`not verified`) |
| Version | none |
| `route.openshift.io` | not queried |
| `security.openshift.io` | not queried |

Assumption from #993: a local single-node OKD cluster, or MicroShift as a
lighter stand-in. MicroShift omits some OpenShift APIs (for example some
operators, and sometimes `Route`). The script prints which groups it saw.

Kind-cluster CI already covers deploy, upgrade, failed upgrade, rollback,
image pull, crash loop, and restricted Pod Security for in-process. That is
Kubernetes admission, not SCC. The drill's OpenShift-gated test
(`restricted_openshift_security_refuses_an_unconfigured_workload_and_names_the_cause`)
applies the same pause Deployment without a security context when
`security.openshift.io` exists.

## Gaps

None that change the decision. Live SCC and `Route` API presence were not
observed on a cluster in this lane; run the drill to fill the table above.
CVO/MCO remains #994.
