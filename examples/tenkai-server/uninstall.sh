#!/bin/sh
set -eu

root="${HOME:?HOME is required}/tenkai-hubs/${TENKAI_INSTANCE:?}"
version="${1:?version}"
rm -rf "$root/versions/$version"
if [ -e "$root/current" ]; then
  target=$(readlink "$root/current" || true)
  if [ "$target" = "versions/$version" ]; then
    rm -f "$root/current" "$root/version"
  fi
fi
rmdir "$root/versions" 2>/dev/null || true
rmdir "$root" 2>/dev/null || true
