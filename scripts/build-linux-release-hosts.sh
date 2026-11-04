#!/usr/bin/env bash
# Build and package the linux-x86_64 release hosts inside a RHEL 8 image
# (glibc 2.28), so they start on every supported distribution (#904). A host
# built on a newer system links newer glibc symbols and fails to load there.
# The release workflow and the CI release dry run both call this.
#
# Usage: scripts/build-linux-release-hosts.sh --out DIR
#
# Needs docker; on a non-x86-64 machine docker must emulate linux/amd64.
# Build state (toolchain, registry, target) lives in
# ${CARGO_TARGET_DIR:-target}/linux-release-hosts, apart from native builds.
# Writes the six packaged linux-x86_64 hosts to DIR and checks them with
# scripts/package-release-binaries.sh check-glibc.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# UBI 8.10. Its glibc is LINUX_GLIBC_FLOOR in package-release-binaries.sh.
IMAGE=registry.access.redhat.com/ubi8/ubi@sha256:c322aa68f2d630b36b9faab64094357f62720be2f56f7099376ca2d6c4fe389b
RUSTUP_VERSION=1.29.3
RUSTUP_SHA256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55

fail() {
  printf 'build-linux-release-hosts: %s\n' "$1" >&2
  exit 1
}

out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 ]] || fail "--out requires a directory"
      out="$2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[[ -n "$out" ]] || fail "--out is required"
command -v docker >/dev/null 2>&1 || fail "docker is required"

mkdir -p "$out"
out="$(cd "$out" && pwd)"
state="${CARGO_TARGET_DIR:-${ROOT}/target}/linux-release-hosts"
mkdir -p "$state"

# Runs as root to install the C toolchain, then hands written files back to
# the caller so later steps and cache tooling can read and remove them.
docker run --rm --platform linux/amd64 \
  -v "${ROOT}:/src:ro" -v "${state}:/state" -v "${out}:/out" \
  -e RUSTUP_VERSION="$RUSTUP_VERSION" -e RUSTUP_SHA256="$RUSTUP_SHA256" \
  -e OWNER="$(id -u):$(id -g)" \
  "$IMAGE" bash -euo pipefail -c '
    trap "chown -R \"\$OWNER\" /state /out" EXIT
    dnf -y -q install gcc binutils diffutils >/dev/null
    export RUSTUP_HOME=/state/rustup CARGO_HOME=/state/cargo CARGO_TARGET_DIR=/state/target
    if [[ ! -x "${CARGO_HOME}/bin/rustup" ]]; then
      curl -fsSL -o /tmp/rustup-init \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init"
      echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - >/dev/null
      chmod 0755 /tmp/rustup-init
      /tmp/rustup-init -y -q --profile minimal --default-toolchain none --no-modify-path >/dev/null
    fi
    export PATH="${CARGO_HOME}/bin:${PATH}"
    cd /src
    ldd --version | head -n 1
    # Same commands as the macOS hosts in release-binaries.yml.
    cargo build --release --locked --workspace --features tenkai-server/ui \
      --bin tenkaictl \
      --bin tenkai-server \
      --bin tenkai-executor-guard \
      --bin tenkai-runtime \
      --bin tenkai-runtime-guard
    bash scripts/package-release-binaries.sh package \
      --out /out --bin-dir /state/target/release --platform linux-x86_64 --strip
    cargo build --release --locked -p tenkai-server --features postgres,ui
    bash scripts/package-release-binaries.sh package-hub \
      --out /out --bin-dir /state/target/release --platform linux-x86_64 --strip
    bash scripts/package-release-binaries.sh check-glibc --out /out
  '
printf 'linux-x86_64 hosts in %s\n' "$out"
