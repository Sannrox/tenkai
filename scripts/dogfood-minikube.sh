#!/usr/bin/env bash
# Local dogfood: embedded tenkaictl + minikube. No tenkai-server, no cloud.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export TENKAI_SOFTWARE_EXECUTOR=kubernetes
export TENKAI_KUBECTL_BIN="${TENKAI_KUBECTL_BIN:-$(command -v kubectl)}"

if ! command -v minikube >/dev/null; then
  echo "minikube not found; install with: brew install minikube" >&2
  exit 1
fi
if ! minikube status >/dev/null 2>&1; then
  echo "starting minikube (docker driver)…"
  minikube start --driver=docker
fi
kubectl get nodes

if [[ ! -x "$ROOT/target/debug/tenkaictl" ]]; then
  cargo build --bin tenkaictl
fi
BIN="$ROOT/target/debug/tenkaictl"

DB="${TENKAI_DATABASE:-$ROOT/.tenkai-dogfood-minikube/tenkai.db}"
mkdir -p "$(dirname "$DB")"
export TENKAI_DATABASE="$DB"
ENV_NAME="${TENKAI_DOGFOOD_ENV:-local}"

echo "==> init ($DB)"
"$BIN" --database "$DB" init 2>/dev/null || true
"$BIN" --database "$DB" env add "$ENV_NAME" 2>/dev/null || true

echo "==> publish / promote / subscribe"
"$BIN" --database "$DB" publish "$ROOT/examples/hello-minikube/tenkai.toml" \
  --allow-unsigned-development
"$BIN" --database "$DB" promote hello-minikube@0.1.0 stable
"$BIN" --database "$DB" env subscribe "$ENV_NAME" hello-minikube=stable

echo "==> plan"
PLAN_OUT="$("$BIN" --database "$DB" plan --env "$ENV_NAME")"
echo "$PLAN_OUT"
PLAN_ID="$(echo "$PLAN_OUT" | sed -n 's/^plan id: //p' | tail -1)"
if [[ -z "${PLAN_ID:-}" ]]; then
  echo "could not parse plan id from plan output" >&2
  exit 1
fi
echo "using plan: $PLAN_ID"

echo "==> apply"
"$BIN" --database "$DB" apply "$PLAN_ID" \
  --allow-unapproved-development \
  --development-reason "local minikube dogfood"

echo "==> status"
"$BIN" --database "$DB" status --env "$ENV_NAME" 2>/dev/null \
  || "$BIN" --database "$DB" status
kubectl -n "$ENV_NAME" get deploy,svc,pods

echo "dogfood ok: hello-minikube@0.1.0 in namespace $ENV_NAME (db=$DB)"
echo "Next (optional): signed multi-env + rollback walkthrough in examples/hello-minikube/README.md"
