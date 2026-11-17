#!/bin/sh
# Health action of the cluster host release, run as root by the host applier
# as an approved step after each install. Healthy means: the pinned binary
# runs, the API server and the node are ready, and the kubeconfig the tenkai
# user reads works with exactly the scope it should have.
set -eu
# api.out holds the service account token while the kubeconfig is composed.
umask 077

# shellcheck source=cluster.env
. ./cluster.env
# shellcheck source=cluster-lib.sh
. ./cluster-lib.sh

fail() {
  printf 'cluster health: %s\n' "$1" >&2
  exit 1
}

environment=${TENKAI_ENVIRONMENT:?TENKAI_ENVIRONMENT is unset}
k3s=/usr/local/bin/k3s
kubectl() { "$k3s" kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml "$@"; }

# k3s restarts on its own (Restart=always), for example once after a
# downgrade, so the API server can drop out at any point of this check
# (#1130). Every read waits out such a gap, up to one window for the whole
# check, and a read is judged only against an API server that answers. A
# k3s that does not come back fails health once the window ends.
api_window=${HEALTH_API_WINDOW_S:-120}
api_deadline=$(($(date +%s) + api_window))

api_up() {
  systemctl is-active --quiet k3s.service && kubectl get --raw /readyz >/dev/null 2>&1
}

# Waits until the API server answers, or fails naming it once the window ends.
await_api() {
  until api_up; do
    if [ "$(date +%s)" -ge "$api_deadline" ]; then
      state=$(systemctl is-active k3s.service 2>/dev/null || true)
      restarts=$(systemctl show -p NRestarts --value k3s.service 2>/dev/null || true)
      fail "the API server at 127.0.0.1:6443 did not answer within ${api_window}s (k3s.service ${state:-unknown}${restarts:+, restarted ${restarts} times})"
    fi
    sleep 2
  done
}

# Runs a read with its output in api.out and returns its status. A read that
# fails while the API server is down is retried once it answers, so only a
# read the API server answered is ever judged.
api_read() {
  while :; do
    if "$@" >api.out 2>/dev/null; then
      return 0
    fi
    if api_up; then
      return 1
    fi
    await_api
  done
}

[ "$(sha256sum "$k3s" | awk '{print $1}')" = "$K3S_SHA256" ] ||
  fail "${k3s} is not the pinned k3s ${K3S_VERSION}"
await_api
# Not running_version: its pipeline hides a failed read.
api_read kubectl get --raw /version || fail "the API server does not report its version"
version=$(sed -n 's/^ *"gitVersion": *"\([^"]*\)".*/\1/p' api.out)
[ "$version" = "$K3S_VERSION" ] ||
  fail "the API server runs ${version}, not ${K3S_VERSION}"
api_read kubectl wait --for=condition=Ready node --all --timeout=60s ||
  fail "the node is not Ready"

# In-cluster releases rely on a default StorageClass for their volumes.
api_read kubectl get storageclass -o 'jsonpath={.items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")].metadata.name}' || true
[ -s api.out ] || fail "the cluster has no default StorageClass"

# Its namespaces keep workloads off the host: the restricted Pod Security
# standard refuses privileged pods, host paths, and host namespaces.
for namespace in "$environment" tenkai-system; do
  api_read kubectl get namespace "$namespace" -o 'jsonpath={.metadata.labels.pod-security\.kubernetes\.io/enforce}' || true
  [ "$(cat api.out)" = restricted ] ||
    fail "namespace ${namespace} does not enforce the restricted Pod Security standard"
done

# The tenkai user's kubeconfig is that user's to change, so root never loads
# it: a kubeconfig can name commands to run. Root reads it as the tenkai
# user, requires it to equal what install wrote, and checks the identity with
# its own copy.
api_read compose_kubeconfig "$environment" || fail "the tenkai service account has no valid token"
mv api.out tenkai.kubeconfig
setpriv --reuid="$TENKAI_USER" --regid="$TENKAI_USER" --init-groups -- \
  cat "${KUBECONFIG_DIR}/${environment}.kubeconfig" >held.kubeconfig ||
  fail "the tenkai user cannot read ${KUBECONFIG_DIR}/${environment}.kubeconfig"
cmp -s tenkai.kubeconfig held.kubeconfig ||
  fail "${KUBECONFIG_DIR}/${environment}.kubeconfig is not the one install wrote; run install again"
as_tenkai() { "$k3s" kubectl --kubeconfig tenkai.kubeconfig "$@"; }
api_read as_tenkai get namespace "$environment" ||
  fail "the Tenkai identity cannot read namespace ${environment}"
# `auth can-i` exits non-zero for "no"; the answer is in api.out.
api_read as_tenkai auth can-i create deployments.apps -n "$environment" || true
[ "$(cat api.out)" = yes ] ||
  fail "the Tenkai identity cannot create deployments in ${environment}"
# Scoped: nothing outside the environment's namespace, and not its labels.
for denied in "create namespaces" "patch namespaces/${environment}" "get secrets -n tenkai-system" "get nodes"; do
  # shellcheck disable=SC2086 # split the verb and resource
  api_read as_tenkai auth can-i $denied || true
  if [ "$(cat api.out)" = yes ]; then
    fail "the Tenkai identity may ${denied}"
  fi
done
rm -f tenkai.kubeconfig held.kubeconfig api.out
printf 'k3s %s is healthy\n' "$K3S_VERSION"
