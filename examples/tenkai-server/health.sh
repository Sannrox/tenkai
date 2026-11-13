#!/bin/sh
# Prove the staged host is the signed version. When a unit runs
# current/tenkai-server, replace this probe with curl of /readyz and /ui/.
set -eu

root="${HOME:?HOME is required}/tenkai-hubs/${TENKAI_INSTANCE:?}"
current="$root/current/tenkai-server"
version="${1:?version}"
[ -x "$current" ]
grep -qx "$version" "$root/version"
"$current" --version >/dev/null
