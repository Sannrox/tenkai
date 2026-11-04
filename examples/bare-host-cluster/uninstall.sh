#!/bin/sh
# Uninstall action of the cluster host release, run as root by the host
# applier for an approved plan that removes the product. Removes the cluster
# and everything in it, its state included: in-cluster releases of the
# environment fail closed from here on, because their kubeconfig is gone.
set -eu

# shellcheck source=cluster.env
. ./cluster.env
# shellcheck source=cluster-lib.sh
. ./cluster-lib.sh

environment=${TENKAI_ENVIRONMENT:?TENKAI_ENVIRONMENT is unset}

# 1. The kubeconfig first, removed by the tenkai user in its own home.
setpriv --reuid="$TENKAI_USER" --regid="$TENKAI_USER" --init-groups -- \
  rm -f "${KUBECONFIG_DIR}/${environment}.kubeconfig"

# 2. Stop k3s. Its unit stops only the k3s process; containers keep running.
if [ -f /etc/systemd/system/k3s.service ]; then
  systemctl disable --now --quiet k3s.service
fi

# 3. Containers, mounts, and network state. Unmounting and deleting
# interfaces needs capabilities the applier's sandbox does not grant, so it
# runs as a transient unit of its own, under one fixed name: a cleanup that
# outlived an interrupted uninstall is waited for, here and by install.sh,
# never run twice at once or raced by an install.
await_cleanup || {
  printf 'cluster uninstall: %s from an earlier attempt is still running\n' "$CLEANUP_UNIT" >&2
  exit 1
}
systemctl reset-failed "$CLEANUP_UNIT" 2>/dev/null || true
systemd-run --wait --collect --quiet --unit "$CLEANUP_UNIT" /bin/sh "$PWD/cleanup.sh"

# 4. The binary and the unit.
rm -f /usr/local/bin/k3s /etc/systemd/system/k3s.service
systemctl daemon-reload
systemctl reset-failed k3s.service 2>/dev/null || true
printf 'k3s removed\n'
