#!/bin/sh
# Stage signed Tenkai hosts for a second hub. The coordinating server never
# runs this: it refuses product tenkai-server. A runtime applies it.
set -eu

required="tenkai-server tenkai-executor-guard tenkaictl"
for name in $required; do
  if [ ! -x "$name" ]; then
    printf '%s\n' "tenkai-server release is missing executable $name; pack hosts before signing" >&2
    exit 1
  fi
done

root="${HOME:?HOME is required}/tenkai-hubs/${TENKAI_INSTANCE:?}"
version="${1:?version}"
dest="$root/versions/$version"
mkdir -p "$dest"
for name in $required; do
  cp "$name" "$dest/$name"
  chmod 0755 "$dest/$name"
done
ln -sfn "versions/$version" "$root/current"
printf '%s\n' "$version" >"$root/version"
