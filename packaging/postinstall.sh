#!/bin/sh
# postinstall of the tenkai .deb (configure [old-version]) and .rpm (1 on
# install, 2 on upgrade). Creates the tenkai user, its groups and
# /run/tenkai; on first install writes a management token to
# /etc/tenkai/management.token (for `sudo tenkaictl`) and to
# /etc/tenkai/server.env (for the unit), both root-owned and mode 0600. It
# never enables or starts tenkai-server; an upgrade restarts it only if it
# was running.
set -eu

systemd-sysusers /usr/lib/sysusers.d/tenkai.conf
# /run may be missing or read-only in a container build; the unit's
# directory is created again at boot.
systemd-tmpfiles --create /usr/lib/tmpfiles.d/tenkai.conf 2>/dev/null || true

# Written once, then left alone: a reinstall or upgrade keeps the token.
token_file=/etc/tenkai/management.token
env_file=/etc/tenkai/server.env
umask 077
if [ ! -e "$token_file" ]; then
  token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  [ "${#token}" -eq 64 ] || { echo "tenkai: cannot read /dev/urandom" >&2; exit 1; }
  pending="$(mktemp /etc/tenkai/.tenkai-package.XXXXXX)"
  printf '%s\n' "$token" >"$pending"
  mv "$pending" "$token_file"
fi
if [ ! -e "$env_file" ]; then
  pending="$(mktemp /etc/tenkai/.tenkai-package.XXXXXX)"
  {
    echo "# tenkai-server settings. Root-owned, mode 0600; the unit reads it."
    echo "# TENKAI_MANAGEMENT_TOKEN matches /etc/tenkai/management.token."
    token="$(cat "$token_file")"
    echo "TENKAI_MANAGEMENT_TOKEN=${token}"
  } >"$pending"
  mv "$pending" "$env_file"
fi

# Only on a host that runs systemd; a container build has no manager.
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  case "${1:-}:${2:-}" in
    configure:?* | 2:*) systemctl try-restart tenkai-server.service ;;
  esac
fi
