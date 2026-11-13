#!/usr/bin/env bash
# Pack a signed-ready catalog release of tenkai-server from verified hosts (#1080).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hosts=""
version=""
out=""

usage() {
  printf 'usage: %s --hosts-dir DIR --version X.Y.Z --out DIR\n' "$0" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts-dir)
      hosts="${2:?}"
      shift 2
      ;;
    --version)
      version="${2:?}"
      shift 2
      ;;
    --out)
      out="${2:?}"
      shift 2
      ;;
    -h | --help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$hosts" && -n "$version" && -n "$out" ]] || usage
[[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]*$ && "$version" != *..* ]] || {
  printf 'pack-tenkai-release: version must start with a letter or digit and contain only letters, digits, ".", "_", "-", or "+"\n' >&2
  exit 1
}
[[ -d "$hosts" ]] || {
  printf 'pack-tenkai-release: hosts dir not found: %s\n' "$hosts" >&2
  exit 1
}

mkdir -p "$out"
cp "$ROOT/examples/tenkai-server/install.sh" \
  "$ROOT/examples/tenkai-server/uninstall.sh" \
  "$ROOT/examples/tenkai-server/health.sh" \
  "$out/"
chmod 0755 "$out/install.sh" "$out/uninstall.sh" "$out/health.sh"
for name in tenkai-server tenkai-executor-guard tenkaictl; do
  src="$hosts/$name"
  [[ -f "$src" ]] || {
    printf 'pack-tenkai-release: missing host %s\n' "$src" >&2
    exit 1
  }
  cp "$src" "$out/$name"
  chmod 0755 "$out/$name"
done

cat >"$out/tenkai.toml" <<EOF
[product]
name = "tenkai-server"
version = "$version"
description = "Tenkai control-plane host, including the web console at /ui/"
kind = "software"

[deploy]
workdir = "."
install = "sh install.sh $version"
uninstall = "sh uninstall.sh $version"
health = "sh health.sh $version"
inputs = [
  "install.sh",
  "uninstall.sh",
  "health.sh",
  "tenkai-server",
  "tenkai-executor-guard",
  "tenkaictl",
]
EOF

printf 'packed %s@%s in %s\n' "tenkai-server" "$version" "$out"
