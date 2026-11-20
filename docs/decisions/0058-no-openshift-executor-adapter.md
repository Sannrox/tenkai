# ADR 0058: No OpenShift executor adapter

- Status: Accepted
- Date: 2026-11-20
- Issue: [#993](https://github.com/Sannrox/tenkai/issues/993)
- Owner: Tenkai maintainers
- Builds on: [ADR 0041](0041-per-release-executor-and-privileged-host-releases.md)
- Related: [software executor](../software-executor.md#openshift-compatibility),
  [OpenShift compatibility research](../research/openshift-executor-compatibility.md)

## Context

Operators on OpenShift cannot tell from the docs whether `helm`, `kubernetes`
(kubectl), and `kubernetes-inprocess` work there. The in-process executor
allowlists built-in kinds and refuses everything else, including
`route.openshift.io/v1` `Route`, before it mutates (#1208). Helm and kubectl
send the chart or manifests to the cluster API with no Tenkai kind list.

The question is whether OpenShift needs a fourth executor, or an allowlisted
custom-resource path for `Route`, without broadening privileges.

## Decision

Do not add an OpenShift executor. Do not allowlist `Route` or other
OpenShift custom resources on `kubernetes-inprocess`.

- `helm` and `kubernetes` already apply whatever the cluster admits. An
  OpenShift HTTP route belongs in a chart or a kubectl manifest on those
  executors.
- `kubernetes-inprocess` stays the fail-closed subset of built-in namespaced
  kinds in `builtin_resource`. Discovery of installed APIs, or a
  distribution-specific allowlist, would make two processes disagree and
  would apply kinds the rollout wait does not understand.
- Tenkai creates a Kubernetes `Namespace` named for the environment. It does
  not create an OpenShift `Project`. Pre-create that namespace when the
  credential cannot create namespaces.
- Tenkai does not inject a security context or an SCC. A workload that
  violates restricted SCC or Pod Security is refused by admission; the
  in-process wait already names `is forbidden` / `denied the request`.

CVO and MCO upgrades are [ADR 0059](0059-openshift-cluster-version-updates.md).

## Consequences

Operators who need `Route` use `helm` or `kubernetes`. Operators who need
fail-closed kinds use `kubernetes-inprocess` and `Ingress` (`networking.k8s.io/v1`)
when the cluster serves it. A later allowlist of one namespaced kind is a
new Issue; it is not an adapter.

## Rejected alternatives

- **OpenShift executor.** A new `deploy.executor` value that wraps the same
  Helm or kubectl path. No second implementation exists; ADR 0041 already
  selects per release.
- **Allowlist `Route` on in-process.** Namespaced and no extra cluster-scoped
  verbs, but it is a custom resource the allowlist was written to refuse, and
  rollout health does not wait on Routes.
- **Discover CRDs from the cluster.** Fail-open. Two replicas can see
  different APIs during a rolling deploy.
