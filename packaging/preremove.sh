#!/bin/sh
# preremove of the tenkai .deb (remove, or upgrade) and .rpm (0 on remove,
# 1 on upgrade). On removal it stops and disables tenkai-server; an upgrade
# leaves it running.
set -eu

case "${1:-}" in
  remove | 0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now tenkai-server.service || true
    fi
    ;;
esac
