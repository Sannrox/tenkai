# Local dogfood: Apple `container` cluster + embedded tenkaictl

Goal: deliver [`examples/hello-minikube/`](../examples/hello-minikube/) to a
local Kubernetes cluster on Apple silicon, without a Docker daemon VM, a
separate Kubernetes distribution, or a remote Tenkai server.

The cluster is ordinary Kubernetes. Tenkai applies the same way it does on
minikube: an environment-scoped kubeconfig plus `kubernetes-inprocess` or
`kubernetes`. Cluster creation stays with `container`. Tenkai does not hold
new credentials.

| Piece | Choice |
| --- | --- |
| Control plane | Embedded `tenkaictl` + SQLite |
| Cluster | `container cluster create` (lightweight VMs) |
| Executor | `kubernetes-inprocess` or `kubernetes` |
| Product | [`examples/hello-minikube/`](../examples/hello-minikube/) |
| Kubeconfig | `tenkaictl env cluster-config set` to a dedicated file |

Related: [software executor](software-executor.md),
[minikube dogfood](local-dogfood-minikube.md),
[upgrade and rollback](upgrade-and-rollback.md).

## Requirements

- A Mac with Apple silicon.
- `container` **1.7.1** or later for the commands on this page. Local clusters
  first shipped in **1.2.0** as `container k8s`; later releases renamed that
  to `container cluster`.
- `kubectl` on `PATH`. `hello-minikube` still runs `deploy.health` through
  `kubectl`, including when apply itself uses `kubernetes-inprocess`.
- `tenkaictl` (from this tree: `cargo build --bin tenkaictl`).

`container --version` must report 1.7.1 or newer. If the runtime is stopped,
start it once with `container system start`.

## Leave the image store unshared

Do **not** pass `--shared-image-store` on `container cluster create`. Sharing
is off by default. Leave it off.

With sharing on, anything with root on a node (including a privileged pod or a
pod with a `hostPath` mount) can read every image in the local `container`
image store, including private images pulled with registry credentials. A
local image also wins over a registry image of the same name, for every pull
policy, and without the pod's pull secrets. Nodes cannot add, change, or
delete images in that store.

Without `--shared-image-store`, nodes pull every image from a registry, as in
a standard cluster. `hello-minikube` uses a public digest-pinned `nginx`
image, so a registry pull is enough. Both executors work with sharing on or
off; the difference is only where the node gets the image.

Sharing is fixed at cluster create. To change it, delete the cluster and
create it again.

## Create the cluster and a scoped kubeconfig

```bash
container cluster create --name tenkai-local
container cluster list
```

`container` also merges a context into the default kubeconfig. Do not point
Tenkai at that file. Write a dedicated kubeconfig, then pin both Tenkai and
`kubectl` to it:

```bash
mkdir -p .tenkai-dogfood-container
container cluster write-config --name tenkai-local \
  --kubeconfig .tenkai-dogfood-container/kubeconfig
chmod 600 .tenkai-dogfood-container/kubeconfig
export KUBECONFIG="$PWD/.tenkai-dogfood-container/kubeconfig"
kubectl config use-context tenkai-local
kubectl get nodes
```

If `write-config` is missing, minify the context `container` already wrote:

```bash
kubectl --context tenkai-local config view --minify --flatten \
  > .tenkai-dogfood-container/kubeconfig
chmod 600 .tenkai-dogfood-container/kubeconfig
export KUBECONFIG="$PWD/.tenkai-dogfood-container/kubeconfig"
```

`kubernetes-inprocess` never reads `KUBECONFIG` or in-cluster discovery. It
refuses apply until the environment names a readable kubeconfig file.
`kubernetes` passes that same path as `kubectl --kubeconfig`. Keep
`KUBECONFIG` set to the same file so `deploy.health` does not follow another
context.

## Point `local` at the file and apply

```bash
export TENKAI_DATABASE="$PWD/.tenkai-dogfood-container/tenkai.db"
export TENKAI_SOFTWARE_EXECUTOR=kubernetes-inprocess   # or kubernetes
export TENKAI_MANAGEMENT_TOKEN="${TENKAI_MANAGEMENT_TOKEN:-tenkai-local-management}"
cargo build --bin tenkaictl
BIN=./target/debug/tenkaictl

$BIN init
$BIN env cluster-config set local "$PWD/.tenkai-dogfood-container/kubeconfig"

$BIN publish examples/hello-minikube/tenkai.toml --allow-unsigned-development
$BIN promote hello-minikube@0.1.0 stable
$BIN env subscribe local hello-minikube=stable

PLAN=$($BIN plan --env local | sed -n 's/^plan id: //p')
$BIN apply "$PLAN" \
  --allow-unapproved-development \
  --development-reason "local container-cluster dogfood"

$BIN status --env local
kubectl -n local get deploy,pods
```

Unsigned development is `local`-only. That is trust policy, not a cluster
quirk. State under `.tenkai-dogfood-container/` is gitignored.

Expect `status` to show `current` and the Deployment ready in namespace
`local`.

To use `kubernetes` instead, set `TENKAI_SOFTWARE_EXECUTOR=kubernetes` before
`init` (or before the process that applies). Both executors take the
environment kubeconfig the same way. `kubernetes` also needs `kubectl` for
apply, not only for `deploy.health`.

## Broken upgrade rolls back

After a good install, publish a newer `hello-minikube` whose Deployment image
tag does not exist, promote it to `stable`, plan, and apply. Expect a
non-zero exit and automatic restore of the previous pin.

`kubernetes-inprocess` often fails while waiting for the rollout
(`phase=apply`, `ImagePullBackOff` after 45 s). `kubernetes` may get past
apply and fail `deploy.health` (`phase=health`). Either path then restores
(`phase=restore`). Channel head is not rewritten; `status` may show `behind`
until you re-promote a good version. Errors name the phase, product@version,
and environment, without secrets.

## Tear down

```bash
kubectl --kubeconfig .tenkai-dogfood-container/kubeconfig \
  delete ns local --ignore-not-found
container cluster delete --name tenkai-local
rm -rf .tenkai-dogfood-container
```

If the control-plane node stopped (for example after `container system stop`),
delete and create the cluster again. A stopped cluster is not recovered in
place.

## Out of scope

- Running `docker/host.json` releases on the `container` engine directly.
- Signed multi-environment apply, software canary, and the minikube dogfood
  script. Those stay on [minikube dogfood](local-dogfood-minikube.md).
- A Tenkai code change. If this cluster needs one, that is a follow-up Issue.
