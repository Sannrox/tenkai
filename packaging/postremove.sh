#!/bin/sh
# postremove of the tenkai .deb (remove, purge, ...) and .rpm (0 on remove).
# Removal keeps the store in /var/lib/tenkai and the token and settings in
# /etc/tenkai; a .deb purge deletes the token and server.env postinstall
# wrote. The tenkai user and groups stay, as sysusers entries do.
set -eu

if [ "${1:-}" = purge ]; then
  rm -f /etc/tenkai/management.token /etc/tenkai/server.env
  rmdir /etc/tenkai 2>/dev/null || true
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
