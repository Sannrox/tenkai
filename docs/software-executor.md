# Software executor (Kubernetes and Docker host)

Tenkai applies `product.kind = software` releases through a pluggable port so
cluster or Docker-host delivery does not require hard-linking a cluster client
into the core crate by default.

Software releases can declare [signed compatibility preflight requirements](software-compatibility.md) independently of executor health checks.

Source: `src/software_executor.rs` (port, fake, selector) and
`crates/tenkai-executor` (Helm, kubectl, Docker CLI, in-process Kubernetes).
Apply wiring: `src/apply.rs`. Rollout-time harness: `src/rollout_time.rs`,
baseline `perf/rollout-baseline.json`. Hosts call `tenkai_executor::install()`
before `SoftwareExecutors::from_process`.

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

In-process apply supports the built-in kinds `Namespace`, `ConfigMap`,
`Secret`, `Service`, `ServiceAccount`, `PersistentVolumeClaim` (`v1`),
`Deployment`, `StatefulSet`, `DaemonSet` (`apps/v1`), `Job`, `CronJob`
(`batch/v1`), `Ingress`, `NetworkPolicy` (`networking.k8s.io/v1`), `Role`,
`RoleBinding` (`rbac.authorization.k8s.io/v1`), and `PodDisruptionBudget`
(`policy/v1`). A release that names any other kind or apiVersion is refused
when it is planned, and again before apply changes anything, naming the file
and the object.

## Ports

| Type | Role |
| --- | --- |
| `SoftwareExecutor` | apply / remove / observe / restart, plus `cleanup_failed_apply` (defaults to remove), report-only `observe_spec_drift` (#1028), and `render_target_changes` for plan-time desired-versus-live diffs (#1077) |
| `SoftwareExecutors` | the process default plus adapters for declared kinds; resolves one per release |
| `FakeSoftwareExecutor` | CI without cluster |
| `HelmSoftwareExecutor` | Helm chart path (`tenkai-executor`) |
| `KubernetesSoftwareExecutor` | Native manifests path (`kubectl`, `tenkai-executor`) |
| `InProcessKubernetesExecutor` | Native manifests with server-side apply (`tenkai-executor`) |
| `DockerHostExecutor` | Digest-pinned host containers, networks, and volumes (`tenkai-executor`) |

Hosts (`tenkaictl`, the reconciler) call `tenkai_executor::install()`, then
pass `SoftwareExecutors::try_from_process()` into apply: the
`TENKAI_SOFTWARE_EXECUTOR` default plus every installed adapter. An unknown
name, or a known name whose adapter is not installed, is refused there (and
at `tenkai-server` start) with the same shape as a missing declared executor;
it never falls back to shell. Apply does not
read that env var during activate/deactivate. Helm and kubectl
failures capture sanitized stderr. The in-process path waits on the applied
revision with a short backoff starting at 100 ms (capped at 200 ms) and fails
closed until that revision is the one serving, naming the gap and its cause
([waiting for rollout](#waiting-for-rollout)). A foreign field manager is
an explicit conflict, not a silent overwrite.

Apply renews the environment apply lease while a software executor runs, at a
quarter of the shortest lease TTL it holds and at most every 10 s. A rollout
may take longer than the lease TTL without losing its lease; the executor's own
timeout bounds the step instead. A renewal that fails, or takes longer than
one interval, leaves at least half a TTL of the lease: apply tells the
executor to stop, waits for it to return, and reports the lost lease after
the step's own failure, if any; a
cancelled apply stops it too. The in-process executor checks before every
cluster call and bounds each call to 10 s, so it applies nothing more and
returns within one call; other executors finish their current call. A
kubeconfig `exec` credential helper runs synchronously inside the cluster
client, so a helper that hangs holds that call until it returns. When a step fails and releasing the lease also fails, the error names the
step failure first and the release failure after it.

## Per-release selection

A release can declare its executor with
[`[deploy] executor`](manifest.md#executor), which accepts the same names
([ADR 0041](decisions/0041-per-release-executor-and-privileged-host-releases.md)).
Every operation resolves the executor of the release it acts on: activating a
target uses the target's, and removing or restoring the previous release uses
the previous release's. That covers apply, rollback, failed-apply recovery,
restart, and reconcile observation. One process can therefore apply a `shell`
release and a `kubernetes-inprocess` release in the same environment.

- A release without the field uses the process default, exactly as before.
  Apply through the management API now uses the same process default as the
  reconciler; it used to run every release on the shell path. Shell is that
  default only when `TENKAI_SOFTWARE_EXECUTOR` is unset (or set to `shell`).
  `/readyz` lists `software_executor:<kind>` for the effective default.
- A declared `shell` always runs `deploy.install`, even when the process default
  is another executor.
- A declared executor this process does not have fails the step before anything
  runs and names it. It never falls back to another executor. `host` needs
  the host executor ([run host releases](run-tenkai-server.md#run-host-releases)).
- A product keeps one executor in an environment. A plan whose target release
  resolves to a different executor than the installed release of that product
  is refused, at plan creation and again at apply, and the error names both.
  Kinds are compared, not text: `k8s` and `kubernetes` are the same executor,
  and an undeclared release counts as the process default. To move a product,
  remove it and install it again.
- A `host` release runs only as a host plan step through the root-side applier
  ([privileged host releases](host-releases.md)). It is never cleaned up,
  restored, or re-applied automatically after a failure, and reconcile
  neither observes nor restarts it. A failed host step stays failed until an
  approved rollback plan runs.

Resolution reads only signed release content and the process configuration, so
two server versions in a rolling deploy agree on undeclared releases.

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
helm upgrade --install <instance> <workdir> \
  --namespace <environment> --create-namespace --wait --timeout 5m \
  --set tenkai.version=<version> --set tenkai.releaseId=<release_id> \
  --set tenkai.instance=<instance> \
  [--set tenkai.configDigest=<digest> --set tenkai.config.<key>=<value> ...] \
  [--set-file tenkai.dependencies=<path-to-canonical-json>]
```

Remove runs `helm uninstall <instance> --namespace <environment> --wait
--ignore-not-found`, so a retried removal finds nothing to do. That flag
needs Helm 3.13 or later.

A release that declares requirements also gets a dependency document
([software compatibility](software-compatibility.md)). Helm charts read it as
`tenkai.dependencies`. Native and in-process Kubernetes apply ConfigMap
`tenkai-dependencies-<instance>` in the environment namespace, data key
`tenkai-dependencies.json`. The default instance is the product, so existing
names stay. Docker copies the file to
`/etc/tenkai/dependencies.json` in each container. Host apply writes
`tenkai-dependencies.json` next to `request.json` in the spool instance
directory. Executors never write the document into signed release content.
An instance with a workload certificate always gets one, naming its peers
even when it requires nothing, so a withdrawn peer is overwritten
([manage environments](manage-environments.md#dependency-bindings)).

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
  - `tenkai.instance` (the product when the instance is not named)
  - `tenkai.version`
  - `tenkai.release-id` (sanitized for Kubernetes label charset)
- Observe, restart, and remove select on `tenkai.product` and `tenkai.instance`
  so two instances of one product do not share a selector.
- Native and in-process apply substitute `${TENKAI_INSTANCE}` as a literal
  string in `{workdir}/manifests/**/*.yaml` and nowhere else. The signed
  workdir is not rewritten. A default-named instance of a manifest without
  the placeholder keeps today's object names.
- When a non-secret overlay digest is present, apply and restart also annotate
  `tenkai.config-digest` on Deployments and StatefulSets labeled
  `tenkai.product` and `tenkai.instance`.
- When the apply request carries a dependency document, apply also creates
  ConfigMap `tenkai-dependencies-<instance>` with key `tenkai-dependencies.json`.
- Product, version, instance, and environment names must not contain path separators.

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
changed since the last apply. `tenkaictl plan` does not execute `deploy.health`,
but it does emit Restart when Tenkai-owned overlays are stale. Executors that
implement `render_target_changes` also record a desired-versus-live diff on
each step; `tenkaictl plan` prints it, the plan digest covers it, and apply
refuses the step as stale if the live object moved.

## In-process Kubernetes enablement (#376)

```bash
export TENKAI_SOFTWARE_EXECUTOR=kubernetes-inprocess
tenkaictl env cluster-config set lab /var/lib/tenkai/lab.kubeconfig
tenkaictl reconcile --once
```

Rules beyond the native workdir contract:

- Field manager is always `tenkai`. Apply never sets `force`.
- `env cluster-config set` stores an existing file by its canonical path. A
  file that does not exist yet is stored as given, which must be absolute
  without `.` or `..` components, so the path can be set when the
  environment is created and before a host release writes the file.
- Apply re-reads the signed workdir and the environment-scoped kubeconfig file.
  Cached cluster objects cannot grant apply authority.
- A missing or unreadable kubeconfig file, or an environment without
  `cluster-config`, refuses the step before anything is applied. The plan
  fails naming the reason, the deployment stays as it was, and reconcile
  retries with its backoff until the file exists, for example once a host
  release has installed the cluster
  ([ADR 0041](decisions/0041-per-release-executor-and-privileged-host-releases.md)).
- Removal deletes only objects whose `tenkai.instance` label (or, on objects
  applied before that label existed, `tenkai.product`) names the instance
  being removed. An object another instance owns, for example one a successor
  took over by name, stays. An object without Tenkai labels stays and fails
  the removal naming it, so an operator decides.
- Failed-apply cleanup deletes only objects the failed attempt created; apply
  marks them with the `tenkai.created-by-attempt` annotation. Objects that
  existed before, carried over from the previous release or adopted by name,
  stay for the restore. Failed-apply cleanup never deletes a
  `PersistentVolumeClaim`, nor a `Namespace`, whose deletion would take its
  claims with it.
- Health comes from Deployment / StatefulSet / DaemonSet rollout status. A
  bounded wait refuses to complete when observed state disagrees with the
  applied revision.
- Kind-cluster CI covers A → B → rollback, a slow but healthy rollout, and
  rollouts that fail on an image pull, a crash loop, and an admission refusal,
  each naming its cause. Default `make test` stays cluster-free.

### Waiting for rollout

The wait polls each applied workload until the applied revision is the one
serving, for at most 300 s. `Available=True` is not enough: during an upgrade
the previous ReplicaSet keeps a Deployment Available. A Deployment step
succeeds only when `observedGeneration` has reached the applied generation,
`updatedReplicas` and `availableReplicas` equal the desired count, and no old
replicas remain. A StatefulSet step waits for `currentRevision ==
updateRevision` with all replicas ready. A DaemonSet step waits until
`updatedNumberScheduled` and `numberAvailable` equal `desiredNumberScheduled`.
Every 2 s a workload that has not rolled out is diagnosed from its conditions
and from up to 20 pods of its current revision (the Deployment's newest
ReplicaSet, or the StatefulSet's update revision). Pods of an older revision
are ignored, so a rollout that replaces a crashing release is not failed by
the pods it replaces.

| Signal | Fails the step |
| --- | --- |
| `ReplicaFailure=True`, reason `FailedCreate`, refused by admission (`is forbidden`, `denied the request`) | at once |
| `Progressing=False`, reason `ProgressDeadlineExceeded` | at once |
| Container waiting in `CrashLoopBackOff` with 3 or more restarts | at once |
| Container waiting in `ImagePullBackOff`, `ErrImagePull` or `InvalidImageName` | after 45 s, at least three kubelet pull attempts |
| `FailedCreate` for an exceeded quota or a missing service account | no, named as the cause |
| `CreateContainerConfigError`, `CreateContainerError`, `RunContainerError` | no, named as the cause |
| Pod not scheduled (`Unschedulable`, unbound PersistentVolumeClaims) | no, named as the cause |

Conditions the controller has not yet reconciled against the applied
generation are ignored. Containers that are still creating, pods that are not
yet ready, and crash loops below the restart threshold keep the wait going, so
a slow but healthy rollout completes. A timeout names the last cause seen.

The cause carries the condition or container reason, the restart count, the
last exit code and termination message, and the pending reason. Each message
is cut to 240 characters and at most three causes are named per workload. It
never contains environment variable values. The cause reaches the CLI error,
the plan step detail, and the subscription error. A remote apply names the
first failed step and its cause before the count of failed steps.

Diagnosis lists ReplicaSets and pods, so the cluster credential needs `list`
on both in the environment namespace. When it cannot read them, the wait
names that as the cause and keeps going on conditions alone.

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
| `user` | Optional bounded username or `UID:GID`; whitespace and `:`, `,`, `=` are refused. |
| `volumes[].read_only` | Mounts a declared named volume read-only when `true`. |
| `tmpfs` | Ephemeral mounts with absolute targets, 1 byte to 16 GiB, unique paths, and mode `000` to `0777`; `uid` and `gid` default to zero. |
| `restart` | `no` (the default), `on_failure` with 1 to 10 retries, `always`, or `unless_stopped`. One-shot jobs require `no`. |

Arguments are stored in the release and visible through `docker inspect`, so
credential-looking values are refused; secrets belong in `env_file`. There is no
free-form Docker flag escape hatch. Bind mounts, arbitrary host mounts, privileged
mode, and inline environment values are refused. Tmpfs data is removed with the
container and is never persistent release state. `env_file` is a basename under the environment-scoped
secret directory; Tenkai never writes those bytes into SQLite, argv values,
labels, or typed receipts. Apply hashes the resolved path and contents in memory
into each container's `tenkai.spec-digest` label (`docker inspect` already
shows the values), so rotating an `env_file`, or pointing
`env docker-secrets` at another directory, makes observe report `Mismatched`
and the next apply or restart recreate that container with the new values. No
new release is needed. Containers created before this label existed are
recreated once on their next apply.

A Docker container is recreated only when its image, its `tenkai.spec-digest`
or the environment's overlay digest differ from the request. `tenkai.version`
and `tenkai.release-id` record which release created it and are not compared:
a release that leaves a container unchanged leaves it running with its older
labels, and observe still reports it Present (#669).

When the release names OCI artifacts, the Docker executor deploys from the
environment-mirror references Tenkai admitted for the apply: each
digest-pinned image is pulled, run and observed as `<mirror>/<repository>@<digest>`.
An image that is not one of those artifacts is refused, a local image ID
too; origin pull is never used. Releases without artifacts keep the images as written.

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
release finds its containers already running. Host apply and restart run on
Tokio's blocking pool while apply renews the lease, and remove runs inside
`tokio::task::block_in_place` on the multi-thread runtime, so a long Docker
wait does not pin a Tokio worker without the runtime knowing. Runtime names are `t` plus a 12-hex
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
unset. A typo or an adapter this process did not install is refused; it does
not become shell. Docker products should keep a fail-closed install reminder, the same
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

### Release-owned Docker configuration files

A container may declare non-secret files from the release workdir:

```json
{"source":"docker/realm.json","destination":"/etc/app/realm.json","read_only":true}
```

Sources are regular files beneath the release root. Source symlinks, including
symlinked parent directories, are rejected through descriptor-relative file
access on Unix; this input feature fails closed on other platforms. Destinations are absolute,
non-traversing paths and may not collide with each other or declared volume
mounts. Tenkai creates the container, streams the file archive through the
Docker client, sets root ownership and mode `0444` for `read_only` or `0644` otherwise, and
starts the container only after every file is installed. The parent directory
must already exist in the image. Read-only is a Unix permission rule: root or a
process with suitable capabilities can still modify a file. It is not a
read-only mount. At most 64 files per container and 16 MiB per file are admitted.

File bytes are excluded from receipts. Observe checks the declared source
bytes and file specification against the stored container spec digest; it does
not inspect the live writable layer for missing or modified files. This is the
supported verification boundary. Source changes cause replacement on apply or
restart; upgrades and rollback install their own release's bytes before start.
Secret material remains an environment-scoped `env_file`.

## Rollout-time budget

`src/rollout_time.rs` times Docker (and in-process Kubernetes) apply phases for
fixtures of 1, 5, and 20 services: fresh install, no-op re-apply, one-service
upgrade, and rollback. One-service upgrade changes one image under a new
release identity; Docker recreates only that container, because version and
release-id labels are provenance and not part of the recreate check (#669). It also times planner compute and one reconcile tick
at 100 and 1_000 environments. Default `cargo test` drives the fake Docker CLI
and records planner and reconcile times at 100 and 1_000 environments.
Published apply budgets gate live Docker daemon samples:

- no-op re-apply of 20 services ≤ 2 s
- one-service upgrade ≤ image pull + health wait + 5 s
- reconcile tick ≤ 1 s at 1_000 environments

The stored runner baseline is `perf/rollout-baseline.json`. The scheduled CI
job (`scripts/check-rollout-time.sh`) runs the same harness against a live
Docker daemon and a kind cluster, fails on those published budgets, and fails
on a >20% regression versus that baseline.
