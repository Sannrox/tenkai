# hello-minikube — local dogfood (no remote server)

Fully **on your machine**:

| Piece | What |
| --- | --- |
| Control plane | Embedded `tenkaictl` + SQLite (`.tenkai-state/`) |
| Cluster | minikube (Docker driver) |
| Apply path | `TENKAI_SOFTWARE_EXECUTOR=kubernetes` → `kubectl` |

No `tenkai-server`, no Postgres, no cloud cost.

## One-time setup

```bash
brew install minikube   # kubectl via minikube or kubernetes-cli
minikube start --driver=docker
kubectl get nodes
```

## Run the path

From the repo root (or use `scripts/dogfood-minikube.sh`):

```bash
export TENKAI_SOFTWARE_EXECUTOR=kubernetes
# optional: export TENKAI_KUBECTL_BIN=$(which kubectl)

cargo build --bin tenkaictl
BIN=./target/debug/tenkaictl

$BIN init
$BIN env add local   # namespace "local" on the cluster

$BIN publish examples/hello-minikube/tenkai.toml --allow-unsigned-development
$BIN promote hello-minikube@0.1.0 stable
$BIN env subscribe local hello-minikube=stable

PLAN=$($BIN plan --env local | tail -1)   # adjust if plan prints multi-line
$BIN apply "$PLAN" --allow-unapproved-development \
  --development-reason "local minikube dogfood"

$BIN status
kubectl -n local get deploy,svc,pods
```

## Upgrade dogfood

Bump `[product].version` and the Deployment image tag (or a label), republish,
promote, plan, apply. Break health to watch automatic rollback.

## Tear down

```bash
# remove deployment via Tenkai rollback / uninstall path, or:
kubectl delete ns local --ignore-not-found
minikube stop   # optional
```
