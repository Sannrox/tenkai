# Software executor (Kubernetes)

Tenkai applies `product.kind = software` releases through a pluggable port so
cluster delivery does not require hard-linking a cluster client into the core
crate by default.

Source: `src/software_executor.rs`. Apply wiring: `src/apply.rs`.

## Strategies

| Executor | Env value | Packaging | Binary |
| --- | --- | --- | --- |
| Shell (default) | *(unset)* | `deploy.install` / `uninstall` commands | n/a |
| **Helm** (#95) | `helm` | Chart root = release workdir | `TENKAI_HELM_BIN` or `helm` |
| **Native Kubernetes** (#105) | `kubernetes` / `k8s` / `native` | `{workdir}/manifests/**/*.yaml` | `TENKAI_KUBECTL_BIN` or `kubectl` |
| Fake (tests) | `fake` | in-memory | n/a |

**Helm** is the chart-oriented path. **Native** is for plain multi-doc YAML (no
Helm release lifecycle). Argo/Flux are out of scope here.

Native uses **kubectl argv** (not an in-process kube client) to keep zero new
crate dependencies and match the Helm external-binary pattern. An in-process
client is a valid follow-on if dependency weight is accepted later.

## Ports

| Type | Role |
| --- | --- |
| `SoftwareExecutor` | apply / remove / observe |
| `FakeSoftwareExecutor` | CI without cluster |
| `HelmSoftwareExecutor` | Helm chart path |
| `KubernetesSoftwareExecutor` | Native manifests path |

## Helm enablement

```bash
export TENKAI_SOFTWARE_EXECUTOR=helm
export TENKAI_HELM_BIN=/usr/local/bin/helm   # optional
tenkaictl reconcile --once
```

```text
helm upgrade --install <product> <workdir> \
  --namespace <environment> --create-namespace --wait --timeout 5m \
  --set tenkai.version=<version> --set tenkai.releaseId=<release_id>
```

## Native Kubernetes enablement

### Workdir contract

```text
<release-workdir>/
  manifests/
    00-namespace-optional.yaml    # optional; Tenkai also creates the env namespace
    10-deployment.yaml
    20-service.yaml
    nested/more.yaml              # recursive; apply order is sorted by path
```

Rules:

- Only `.yaml` / `.yml` files under `manifests/` are applied (sorted path order).
- Namespace for resources is the **environment name** (`kubectl --namespace`).
- Tenkai ensures the namespace exists (`kubectl create namespace` if missing).
- After apply, resources are labeled (overwrite):
  - `tenkai.product`
  - `tenkai.version`
  - `tenkai.release-id` (sanitized for Kubernetes label charset)
- Product, version, and environment names must not contain path separators.

Kustomize is **not** supported in this surface.

### Operator env

```bash
export TENKAI_SOFTWARE_EXECUTOR=kubernetes   # or k8s / native
export TENKAI_KUBECTL_BIN=/usr/local/bin/kubectl   # optional
# Use standard kubeconfig discovery; optional file path only (not a secret string):
export KUBECONFIG=$HOME/.kube/config

tenkaictl reconcile --once
```

| Variable | Meaning |
| --- | --- |
| `TENKAI_SOFTWARE_EXECUTOR=kubernetes` | Native manifests path |
| `TENKAI_KUBECTL_BIN` | Path to kubectl |
| `KUBECONFIG` | Standard kubectl config file path (operator-managed) |

Remove walks manifests in **reverse** sorted order with `--ignore-not-found`.

Observe: `kubectl get -f` for each file; **Present** only if all succeed.

### Optional live smoke

```bash
# Requires kubectl + reachable cluster; not default CI
TENKAI_KUBECTL_BIN=kubectl \
  cargo test --locked kubernetes_operator_kind_path_smoke -- --ignored --nocapture
```

## Security

- No kubeconfig or tokens on Tenkai CLI argv for software apply.
- Never store raw kubeconfig in operational SQLite.
- Scope cluster credentials per environment outside Tenkai.
- Failures leave the plan step failed; rollback remains Tenkai-authoritative.
- Label values are sanitized; do not put secrets in label fields.

## Tests

```bash
cargo test --locked software_executor
```

Default CI does not require a cluster, helm, or kubectl binary.
