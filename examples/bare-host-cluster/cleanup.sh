#!/bin/sh
# Removes what a stopped k3s leaves on the host: container processes, mounts,
# network namespaces and interfaces, packet filter rules, and its state
# directories. uninstall.sh runs it as a transient systemd unit, outside the
# host applier's sandbox. Every step tolerates what is already gone.
set -u

# Container shims and everything below them.
for pid in $(ps -e -o pid= -o args= | awk '$2 ~ /k3s\/data\/[^\/]*\/bin\/containerd-shim/ {print $1}'); do
  kill -9 "$pid" $(pgrep -P "$pid") 2>/dev/null || true
done

# Mounts below these paths, deepest first.
for prefix in /run/k3s /var/lib/rancher/k3s /var/lib/kubelet/pods /var/lib/kubelet/plugins /run/netns/cni-; do
  awk -v prefix="$prefix" 'index($2, prefix) == 1 {print $2}' /proc/self/mounts | sort -r |
    while read -r mount; do umount -f "$mount" 2>/dev/null || umount -l "$mount" 2>/dev/null || true; done
done

ip netns show 2>/dev/null | awk '/^cni-/ {print $1}' | while read -r ns; do ip netns delete "$ns" 2>/dev/null || true; done
ip -o link show 2>/dev/null | awk -F': ' '/master cni0/ {sub(/@.*/, "", $2); print $2}' |
  while read -r iface; do ip link delete "$iface" 2>/dev/null || true; done
for iface in cni0 flannel.1 flannel-v6.1 flannel-wg flannel-wg-v6 kube-ipvs0; do
  ip link delete "$iface" 2>/dev/null || true
done

for save in iptables ip6tables; do
  if command -v "${save}-save" >/dev/null 2>&1; then
    "${save}-save" | grep -v -e KUBE- -e CNI- -e flannel | "${save}-restore" || true
  fi
done

rm -rf /etc/rancher/k3s /etc/rancher/node /run/k3s /run/flannel /var/lib/rancher/k3s /var/lib/kubelet /var/lib/cni
