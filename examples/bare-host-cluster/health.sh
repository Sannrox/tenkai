#!/bin/sh
# Health action of the cluster host release, run as root by the host applier
# as an approved step after each install. Healthy means: the pinned binary
# runs, the API server and the node are ready, and the kubeconfig the tenkai
# user reads works with exactly the scope it should have.
set -eu

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

[ "$(sha256sum "$k3s" | awk '{print $1}')" = "$K3S_SHA256" ] ||
  fail "${k3s} is not the pinned k3s ${K3S_VERSION}"
systemctl is-active --quiet k3s.service || fail "k3s.service is not active"
kubectl get --raw /readyz >/dev/null || fail "the API server is not ready"
[ "$(running_version)" = "$K3S_VERSION" ] ||
  fail "the API server runs $(running_version), not ${K3S_VERSION}"
kubectl wait --for=condition=Ready node --all --timeout=60s >/dev/null ||
  fail "the node is not Ready"

# Its namespaces keep workloads off the host: the restricted Pod Security
# standard refuses privileged pods, host paths, and host namespaces.
for namespace in "$environment" tenkai-system; do
  [ "$(kubectl get namespace "$namespace" -o 'jsonpath={.metadata.labels.pod-security\.kubernetes\.io/enforce}')" = restricted ] ||
    fail "namespace ${namespace} does not enforce the restricted Pod Security standard"
done

# The tenkai user's kubeconfig is that user's to change, so root never loads
# it: a kubeconfig can name commands to run. Root reads it as the tenkai
# user, requires it to equal what install wrote, and checks the identity with
# its own copy.
umask 077
compose_kubeconfig "$environment" >tenkai.kubeconfig || fail "the tenkai service account has no valid token"
setpriv --reuid="$TENKAI_USER" --regid="$TENKAI_USER" --init-groups -- \
  cat "${KUBECONFIG_DIR}/${environment}.kubeconfig" >held.kubeconfig ||
  fail "the tenkai user cannot read ${KUBECONFIG_DIR}/${environment}.kubeconfig"
cmp -s tenkai.kubeconfig held.kubeconfig ||
  fail "${KUBECONFIG_DIR}/${environment}.kubeconfig is not the one install wrote; run install again"
as_tenkai() { "$k3s" kubectl --kubeconfig tenkai.kubeconfig "$@"; }
as_tenkai get namespace "$environment" >/dev/null ||
  fail "the Tenkai identity cannot read namespace ${environment}"
[ "$(as_tenkai auth can-i create deployments.apps -n "$environment")" = yes ] ||
  fail "the Tenkai identity cannot create deployments in ${environment}"
# Scoped: nothing outside the environment's namespace, and not its labels.
for denied in "create namespaces" "patch namespaces/${environment}" "get secrets -n tenkai-system" "get nodes"; do
  # shellcheck disable=SC2086 # split the verb and resource
  if [ "$(as_tenkai auth can-i $denied 2>/dev/null)" = yes ]; then
    fail "the Tenkai identity may ${denied}"
  fi
done
rm -f tenkai.kubeconfig held.kubeconfig
printf 'k3s %s is healthy\n' "$K3S_VERSION"
