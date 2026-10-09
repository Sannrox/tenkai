# Software executor (Kubernetes and Docker host)

Tenkai applies `product.kind = software` releases through a pluggable port so
cluster or Docker-host delivery does not require hard-linking a cluster client
into the core crate by default.

Software releases can declare [signed compatibility preflight requirements](software-compatibility.md) independently of executor health checks.

Source: `src/software_executor.rs`. Apply wiring: `src/apply.rs`.

## Strategies

| Executor | Env value | Packaging | Binary |
| --- | --- | --- | --- |
| Shell (default) | *(unset)* | `deploy.install` / `uninstall` commands | n/a |
| **Helm** (#95) | `helm` | Chart root = release workdir | `TENKAI_HELM_BIN` or `helm` |
| **Native Kubernetes** (#105) | `kubernetes` / `k8s` / `native` | `{workdir}/manifests/**/*.yaml` | `TENKAI_KUBECTL_BIN` or `kubectl` |
| **In-process Kubernetes** (#376) | `kubernetes-inprocess` | `{workdir}/manifests/**/*.yaml` | in-process client |
| **Docker host** (#528) | `docker` | `{workdir}/docker/host.json` | `TENKAI_DOCKER_BIN` or `docker` |
| Fake (tests) | `fake` | in-memory | n/a |

**Helm** is the chart-oriented path. **Native** is for plain multi-doc YAML via
`kubectl` argv (no Helm release lifecycle). **In-process** applies the same
manifest tree with server-side apply and field manager `tenkai`. Argo/Flux are
out of scope here. Custom-resource operators are refused.

## Ports

| Type | Role |
| --- | --- |
| `SoftwareExecutor` | apply / remove / observe / restart, plus `cleanup_failed_apply` (defaults to remove) |
| `FakeSoftwareExecutor` | CI without cluster |
| `HelmSoftwareExecutor` | Helm chart path |
| `KubernetesSoftwareExecutor` | Native manifests path (`kubectl`) |
| `InProcessKubernetesExecutor` | Native manifests with server-side apply |
| `DockerHostExecutor` | Digest-pinned host containers, networks, and volumes |

Hosts (`tenkaictl`, the reconciler) select the adapter from
`TENKAI_SOFTWARE_EXECUTOR` and pass it into apply. Apply does not read that
env var during activate/deactivate. Helm and kubectl failures capture sanitized
stderr. The in-process path waits on workload conditions and fails closed when
`Available` is not `True`, naming the condition. A foreign field manager is an
explicit conflict, not a silent overwrite.

Kubeconfig is never placed on CLI argv and is never stored as file bytes in
SQLite. The in-process path requires an environment-scoped file path:

```bash
tenkaictl env cluster-config set lab /var/lib/tenkai/lab.kubeconfig
```

`SoftwareApplyRequest.cluster_config_path` carries that path only. Implicit
`KUBECONFIG` / in-cluster discovery is refused.

## Helm enablement

```bash
export TENKAI_SOFTWARE_EXECUTOR=helm
export TENKAI_HELM_BIN=/usr/local/bin/helm   # optional
tenkaictl reconcile --once
```

```text
helm upgrade --install <product> <workdir> \
  --namespace <environment> --create-namespace --wait --timeout 5m \
  --set tenkai.version=<version> --set tenkai.releaseId=<release_id> \
  [--set tenkai.configDigest=<digest> --set tenkai.config.<key>=<value> ...]
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
- When a non-secret overlay digest is present, apply and restart also annotate
  `tenkai.config-digest` on Deployments and StatefulSets labeled
  `tenkai.product`.
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
**Mismatched** when a live `tenkai.version` label (or Helm `tenkai.version` /
`tenkai.releaseId` / `tenkai.configDigest` values) disagrees with the requested
pin. **Unknown** never becomes a Plan.

Restart (same version): Helm `upgrade --install` with `tenkai.restartNonce` and
any current non-secret overlays; native **re-apply** of the pinned manifests,
then `kubectl rollout restart` of Deployments/StatefulSets labeled
`tenkai.product`. Native restart fails closed when no labeled workload exists
after apply.
Reconcile may emit a Restart plan when Helm/Kubernetes observe is `Absent` or
`Mismatched`, recorded apply health is `unhealthy`, or environment overlays
changed since the last apply. `tenkaictl plan` does not probe live targets or
execute `deploy.health`, but it does emit Restart when Tenkai-owned overlays
are stale.

## In-process Kubernetes enablement (#376)

```bash
export TENKAI_SOFTWARE_EXECUTOR=kubernetes-inprocess
tenkaictl env cluster-config set lab /var/lib/tenkai/lab.kubeconfig
tenkaictl reconcile --once
```

Rules beyond the native workdir contract:

- Field manager is always `tenkai`. Apply never sets `force`.
- Apply re-reads the signed workdir and the environment-scoped kubeconfig file.
  Cached cluster objects cannot grant apply authority.
- Health comes from Deployment / StatefulSet / DaemonSet conditions. A bounded
  wait refuses to complete when observed state disagrees with the payload.
- Kind-cluster CI covers A → B → rollback and a failing rollout that names the
  disagreeing condition. Default `make test` stays cluster-free.

```bash
# Requires kind + a copied kubeconfig file path; CI's kind job runs this, `make test` does not
TENKAI_CLUSTER_CONFIG=$HOME/tenkai-cluster/config \
  cargo test --locked -p tenkai-executor --test in_process_kubernetes_kind -- --ignored --nocapture
```

### Optional kubectl live smoke

```bash
# Requires kubectl + reachable cluster; not default CI
TENKAI_KUBECTL_BIN=kubectl \
  cargo test --locked kubernetes_operator_kind_path_smoke -- --ignored --nocapture
```

## Security

- No kubeconfig or tokens on Tenkai CLI argv for software apply.
- Never store raw kubeconfig in operational SQLite. Store only an
  environment-scoped file path (`tenkaictl env cluster-config`).
- Docker `env_file` values stay in operator-managed files. Store only the
  environment-scoped directory path (`tenkaictl env docker-secrets`).
- Volume mount targets are allowlisted unix paths. Comma, `=`, quotes, and
  whitespace are refused so they cannot inject extra `--mount` fields.
- Scope cluster credentials per environment outside Tenkai.
- Failures leave the plan step failed; rollback remains Tenkai-authoritative.
- Label values are sanitized; do not put secrets in label fields.

## Tests

```bash
cargo test --locked software_executor
```

Default CI does not require a cluster, helm, kubectl, or docker binary.

## Docker host enablement (#528)

```bash
export TENKAI_SOFTWARE_EXECUTOR=docker
export TENKAI_DOCKER_BIN=/usr/bin/docker   # optional
tenkaictl env docker-secrets set lab /var/lib/tenkai/lab-secrets
tenkaictl reconcile --once
```

### Workdir contract

```text
<release-workdir>/
  docker/
    host.json
```

`host.json` declares digest-pinned containers, networks, named volumes, mounts,
`depends_on` order, optional health commands, and optional `env_file` basenames,
plus these per-container runtime settings:

| Field | Meaning |
| --- | --- |
| `image` | `<repository>@sha256:<64 hex>` (registry manifest digest, pulled when missing) or `sha256:<64 hex>` (a local image ID that must already be on the host). Tags are refused, alone or next to a digest. |
| `ports` | `[{"host_ip": "127.0.0.1", "host_port": 8080, "container_port": 80, "protocol": "tcp"}]`. `host_ip` defaults to loopback and `protocol` to `tcp` (`udp` allowed). Ports are 1-65535, and a host address, port, and protocol may be published once per topology. |
| `entrypoint` | Argument array. The first element becomes `--entrypoint`; the rest lead the container arguments. Setting it clears the image command, as `docker run --entrypoint` does. |
| `command` | Argument array passed after the image. Absent keeps the image default. |
| `aliases` | `{"<network>": ["<alias>"]}` DNS aliases on networks the container joins, unique per network. |

Arguments are stored in the release and visible through `docker inspect`, so
credential-looking values are refused; secrets belong in `env_file`. There is no
free-form Docker flag escape hatch. Bind mounts and inline environment values
are refused. `env_file` is a basename under the environment-scoped
secret directory; Tenkai never writes those bytes into SQLite, argv values,
labels, or typed receipts. Apply hashes the resolved path and contents in memory
into each container's `tenkai.spec-digest` label (`docker inspect` already
shows the values), so rotating an `env_file`, or pointing
`env docker-secrets` at another directory, makes observe report `Mismatched`
and the next apply or restart recreate that container with the new values. No
new release is needed. Containers created before this label existed are
recreated once on their next apply.

Apply creates networks and volumes, pulls missing digest-pinned images,
then replaces containers in dependency order. A running container whose
image and Tenkai labels already match, and whose health is not `unhealthy`, is
left in place. A container being replaced is stopped and kept as
a `-prev-` name until the apply succeeds. Apply waits until each declared
health check is `healthy` (or the container is running when no health is
declared), then deletes those previous containers and removes leftover
containers labeled for the same product and environment. When a container
fails to start or become healthy, apply removes the containers it started,
renames and starts the previous ones, and reports
`restored the previous containers`; failed-activation cleanup then only finishes
a restore that apply could not complete, and the rollback to the previous
release finds its containers already running. Host apply, restart, and remove run
inside `tokio::task::block_in_place` on the multi-thread runtime so a long
Docker wait does not pin a Tokio worker without the runtime knowing. Runtime names are `t` plus a 12-hex
digest of environment and product, then `-ctr-` / `-net-` / `-vol-` and the
declared name, so hyphenated environment or product values cannot collide.
Existing objects whose Tenkai ownership labels differ are refused rather than
reused or `rm -f`'d. Named volumes stay on remove so
application data is not deleted. Restart bounces the current pin in the same
order with `docker restart`, which keeps a container's original environment,
so a container whose spec digest changed is recreated instead. Observe is
`Present` only when every declared container matches its image and Tenkai
version, release, config digest, and spec digest labels.

Shell `deploy.install` remains the default when `TENKAI_SOFTWARE_EXECUTOR` is
unset. Docker products should keep a fail-closed install reminder, the same
pattern as Helm and Kubernetes examples. Default tests drive a fake Docker CLI.

## Local dogfood

Laptop path (embedded `tenkaictl`, minikube, no remote server):
[local-dogfood-minikube.md](local-dogfood-minikube.md) and
[examples/hello-minikube/](../examples/hello-minikube/).

## Failure diagnostics (#150)

Kubernetes apply/remove capture kubectl stderr (sanitized). Operator errors
include **phase** (`apply` / `health` / `restore` / `remove`), product@version,
and environment/namespace. Auto-rollback does not rewrite channel head — status
may show `behind` until re-promote. Laptop dogfood script modes:
`TENKAI_DOGFOOD_MODE=local|signed-multi-env|canary` (see local dogfood note).

### Completion-gated initialization jobs

A Docker topology may declare a container as a bounded one-shot job:

```json
{
  "name": "init",
  "image": "registry.example/app@sha256:<digest>",
  "mode": {"one_shot": {"timeout_secs": 300}}
}
```

A dependent service can require `started`, `healthy`, or
`completed_successfully` directly in `depends_on`, for example
`[{"container": "init", "condition": "completed_successfully"}]`.
Legacy string dependencies retain their existing service readiness ordering. One-shot jobs must
use `completed_successfully`; they cannot declare a health probe. Tenkai waits
for an exited container with exit code zero and keeps that container as
release-bound completion evidence. It never copies job output into receipts.

Successful apply retains the current completion container and the most recent
predecessor for each declared job; older and removed-job evidence is reclaimed.
Matching successful jobs are reused by reconciliation and restart, so an
ordinary observe or restart does not replay initialization side effects. A
changed release, configuration, or job specification gets a new job identity
and may run once. A failed job blocks dependents and may be retried explicitly.
Rollback may replay the target release's job when its completion evidence is no
longer present; database effects remain application-owned and are not reversed
by Tenkai. Removing a product removes managed job containers in reverse
lifecycle order and preserves named volumes.
