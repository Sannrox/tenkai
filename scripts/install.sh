#!/bin/sh
# Install Tenkai hosts from a GitHub Release, verified against its SHA256SUMS.
# Attached to each release as install.sh with that release's version baked in
# by scripts/package-release-binaries.sh install-script. POSIX sh. Usage and
# options: see usage() below or run with --help.
#
# Every file is checked against the release's SHA256SUMS before anything is
# installed; a mismatch or a missing entry installs nothing. Each binary is
# renamed into place, so a reader sees the old file or the new one. A
# tenkaictl self-upgrade home is refused: self-upgrade owns those hosts.
# --with-host-applier also installs the root side of privileged host
# releases at fixed root-owned paths, and starts nothing.
set -eu

# Written by scripts/package-release-binaries.sh install-script when the
# script is attached to a release. Empty in the source tree.
RELEASE_VERSION=""
REPO=Sannrox/tenkai
GLIBC_FLOOR=2.28
# Where --with-host-applier installs. The unit's ExecStart names the binary.
APPLIER_DIR=/usr/local/libexec/tenkai
UNIT_DIR=/etc/systemd/system
RULES_DIR=/etc/polkit-1/rules.d

die() {
  printf 'tenkai install: %s\n' "$1" >&2
  exit 1
}

say() {
  printf '%s\n' "$1"
}

usage() {
  cat <<EOF
Install Tenkai hosts from a GitHub Release, verified against its SHA256SUMS.

  curl -fsSL https://github.com/${REPO}/releases/download/vX.Y.Z/install.sh | sh -s -- --role server

Options:
  --role cli|server|runtime  cli: tenkaictl (default)
                             server: tenkaictl, tenkai-server, tenkai-executor-guard
                             runtime: tenkai-runtime, tenkai-runtime-guard
  --with-host-applier        also install the privileged host release applier
                             (linux-x86_64, as root): ${APPLIER_DIR}/tenkai-host-applier,
                             ${UNIT_DIR}/tenkai-host-apply@.service and
                             ${RULES_DIR}/50-tenkai-host-apply.rules.
                             Starts nothing.
  --version X.Y.Z            release to install (default: ${RELEASE_VERSION:-none, required})
  --prefix DIR               install directory (default: /usr/local/bin as
                             root, ~/.local/bin otherwise)
  --sysconfdir DIR           for --role server: write client.toml and a
                             management token under DIR/tenkai
                             (default: /etc)
  --base-url URL             release download root
                             (default: https://github.com/${REPO}/releases/download)

Supported: linux-x86_64 with glibc ${GLIBC_FLOOR} or newer, darwin-aarch64.
EOF
  exit "${1:-0}"
}

role=cli
version="$RELEASE_VERSION"
prefix=""
sysconfdir=/etc
base_url="https://github.com/${REPO}/releases/download"
with_applier=false
while [ $# -gt 0 ]; do
  case "$1" in
    --role | --version | --prefix | --sysconfdir | --base-url)
      [ $# -ge 2 ] || die "$1 needs a value"
      case "$1" in
        --role) role="$2" ;;
        --version) version="$2" ;;
        --prefix) prefix="$2" ;;
        --sysconfdir) sysconfdir="$2" ;;
        --base-url) base_url="$2" ;;
      esac
      shift 2
      ;;
    --with-host-applier)
      with_applier=true
      shift
      ;;
    -h | --help) usage 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

case "$role" in
  cli) binaries="tenkaictl" ;;
  # The guard is installed first, so a server never starts without it.
  server) binaries="tenkai-executor-guard tenkai-server tenkaictl" ;;
  runtime) binaries="tenkai-runtime-guard tenkai-runtime" ;;
  *) die "unknown role ${role}; use cli, server or runtime" ;;
esac

[ -n "$version" ] || die "no release version; pass --version X.Y.Z"
version="${version#v}"
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$' \
  || die "invalid version ${version}; expected X.Y.Z or X.Y.Z-rc.N"
tag="v${version}"

# Linux hosts link glibc (they load the system's PKCS#11 module), so a
# musl or older glibc system cannot run them.
check_glibc() {
  libc="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
  if [ -z "$libc" ]; then
    if ls /lib/ld-musl-* >/dev/null 2>&1 || ldd --version 2>&1 | grep -qi musl; then
      die "musl libc is not supported; Tenkai Linux hosts need glibc ${GLIBC_FLOOR} or newer"
    fi
    die "cannot determine the glibc version; Tenkai Linux hosts need glibc ${GLIBC_FLOOR} or newer"
  fi
  found="${libc#glibc }"
  if ! printf '%s %s\n' "$found" "$GLIBC_FLOOR" | awk '{
    split($1, a, "."); split($2, b, ".")
    exit !((a[1] + 0 > b[1] + 0) || (a[1] + 0 == b[1] + 0 && a[2] + 0 >= b[2] + 0))
  }'; then
    die "glibc ${found} is too old; Tenkai Linux hosts need glibc ${GLIBC_FLOOR} or newer"
  fi
}

os="$(uname -s)"
arch="$(uname -m)"
# A shell under Rosetta reports x86_64 on Apple silicon.
if [ "$os" = Darwin ] && [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
  arch=arm64
fi
case "${os}:${arch}" in
  Linux:x86_64 | Linux:amd64)
    platform=linux-x86_64
    check_glibc
    ;;
  Darwin:arm64 | Darwin:aarch64) platform=darwin-aarch64 ;;
  *) die "no Tenkai hosts are published for ${os} ${arch}; supported: linux-x86_64, darwin-aarch64. Build from source instead." ;;
esac

# Refuse unless absolute directory $1 and every directory above it are owned
# by root, writable by nobody else, and not symbolic links, so no other user
# can swap what root installs or runs.
require_root_only() {
  checked="$1"
  while :; do
    if [ -L "$checked" ]; then
      die "${checked} is a symbolic link; refusing to install the host applier (install it by hand: docs/host-releases.md#install)"
    fi
    # shellcheck disable=SC2046 # split ls -ldn into mode, links, uid, ...
    set -- $(ls -ldn "$checked")
    case "$1" in
      d*) ;;
      *) die "${checked} is not a directory; refusing to install the host applier" ;;
    esac
    [ "$3" = 0 ] || die "${checked} is owned by uid $3, not root; refusing to install the host applier"
    case "$1" in
      ?????w* | ????????w*) die "${checked} is writable by group or others; refusing to install the host applier" ;;
    esac
    [ "$checked" = / ] && break
    checked="$(dirname "$checked")"
  done
}

# The nearest existing directory at or above $1.
existing_parent() {
  found="$1"
  while [ ! -e "$found" ] && [ ! -L "$found" ]; do
    found="$(dirname "$found")"
  done
  printf '%s\n' "$found"
}

if $with_applier; then
  [ "$platform" = linux-x86_64 ] || die "the host applier is published for linux-x86_64 only (it runs under systemd)"
  [ "$(id -u)" = 0 ] || die "--with-host-applier must run as root"
  for dir in "$APPLIER_DIR" "$UNIT_DIR" "$RULES_DIR"; do
    require_root_only "$(existing_parent "$dir")"
  done
  for target in "${APPLIER_DIR}/tenkai-host-applier" "${UNIT_DIR}/tenkai-host-apply@.service" \
    "${RULES_DIR}/50-tenkai-host-apply.rules"; do
    if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
      die "${target} exists and is not a regular file; refusing to install"
    fi
  done
fi

if [ -z "$prefix" ]; then
  if [ "$(id -u)" = 0 ]; then
    prefix=/usr/local/bin
  else
    [ -n "${HOME:-}" ] || die "HOME is unset; pass --prefix"
    prefix="${HOME}/.local/bin"
  fi
fi

# A self-upgrade home (versions/, current -> versions/<digest>, upgrade.json)
# and links into one are owned by tenkaictl self-upgrade, whose store check,
# backup and rollback a plain replace would skip.
is_home() {
  [ -e "$1/upgrade.json" ] || { [ -d "$1/versions" ] && [ -L "$1/current" ]; }
}
for dir in "$prefix" "$prefix/.." "$prefix/../.."; do
  if [ -d "$dir" ] && is_home "$dir"; then
    die "${prefix} is in a tenkaictl self-upgrade home; upgrade it with tenkaictl self-upgrade (docs/release-binaries.md#upgrade-a-server-host)"
  fi
done
for binary in $binaries; do
  if [ -L "${prefix}/${binary}" ]; then
    die "${prefix}/${binary} is a symbolic link (to $(readlink "${prefix}/${binary}")); upgrade the host it points to with tenkaictl self-upgrade, or remove the link"
  fi
  # mv would move the host into a directory and report success.
  if [ -e "${prefix}/${binary}" ] && [ ! -f "${prefix}/${binary}" ]; then
    die "${prefix}/${binary} exists and is not a regular file; refusing to install"
  fi
done

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto-redir =https -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "curl or wget is required"
fi
if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  digest() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "sha256sum or shasum is required"
fi

# Download asset $2 into directory $1 and check it against $1/SHA256SUMS.
fetch_verified() {
  fetch "${url}/$2" "$1/$2" || die "cannot download ${url}/$2"
  expected="$(awk -v name="$2" '$2 == name || $2 == "*" name {print $1}' "$1/SHA256SUMS")"
  [ -n "$expected" ] || die "SHA256SUMS has no entry for $2; refusing to install"
  [ "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" = 1 ] || die "SHA256SUMS lists $2 more than once; refusing to install"
  actual="$(digest "$1/$2")"
  [ "$actual" = "$expected" ] || die "checksum mismatch for $2: expected ${expected}, got ${actual}; refusing to install"
}

mkdir -p "$prefix" 2>/dev/null || die "cannot create ${prefix}; run as root or pass --prefix"
# Staged inside the prefix, so the final rename stays on one file system.
stage="$(mktemp -d "${prefix}/.tenkai-install.XXXXXX" 2>/dev/null)" \
  || die "cannot write to ${prefix}; run as root or pass --prefix"
applier_stage=""
pending=""
trap 'rm -rf "$stage" $applier_stage $pending' EXIT
trap 'exit 1' HUP INT TERM

# The applier's files are staged and checked in a root-only directory, apart
# from a prefix another user may control.
if $with_applier; then
  umask 022
  for dir in "$APPLIER_DIR" "$UNIT_DIR" "$RULES_DIR"; do
    mkdir -p "$dir"
    require_root_only "$dir"
  done
  applier_stage="$(mktemp -d "${APPLIER_DIR}/.tenkai-install.XXXXXX")"
fi

url="${base_url%/}/${tag}"
say "Installing Tenkai ${tag} (${role}, ${platform}) into ${prefix}"

# Verify every file before installing any of them.
fetch "${url}/SHA256SUMS" "${stage}/SHA256SUMS" || die "cannot download ${url}/SHA256SUMS"
for binary in $binaries; do
  fetch_verified "$stage" "${binary}-${platform}"
done
if $with_applier; then
  fetch "${url}/SHA256SUMS" "${applier_stage}/SHA256SUMS" || die "cannot download ${url}/SHA256SUMS"
  for asset in "tenkai-host-applier-${platform}" tenkai-host-apply.service tenkai-host-apply.rules; do
    fetch_verified "$applier_stage" "$asset"
  done
fi

for binary in $binaries; do
  asset="${binary}-${platform}"
  if [ "$binary" = tenkai-server ] && [ -e "${prefix}/tenkai-server" ]; then
    say "Replacing ${prefix}/tenkai-server: restart the service to run it. For upgrades with a store check, backup and rollback, use tenkaictl self-upgrade."
  fi
  chmod 0755 "${stage}/${asset}"
  mv -f "${stage}/${asset}" "${prefix}/${binary}"
  say "  ${prefix}/${binary}"
done

# Copy $1 from the applier stage to $2, owned by root with mode $3, renamed
# into place within its directory.
install_root_file() {
  pending="${2}.tenkai-install.$$"
  cp "${applier_stage}/$1" "$pending"
  chown 0:0 "$pending"
  chmod "$3" "$pending"
  mv -f "$pending" "$2"
  pending=""
  say "  $2"
}

applier_files=""
if $with_applier; then
  install_root_file "tenkai-host-applier-${platform}" "${APPLIER_DIR}/tenkai-host-applier" 0755
  install_root_file tenkai-host-apply.service "${UNIT_DIR}/tenkai-host-apply@.service" 0644
  install_root_file tenkai-host-apply.rules "${RULES_DIR}/50-tenkai-host-apply.rules" 0644
  applier_files="${APPLIER_DIR}/tenkai-host-applier ${UNIT_DIR}/tenkai-host-apply@.service ${RULES_DIR}/50-tenkai-host-apply.rules"
fi

say ""
say "Checksums matched SHA256SUMS. To verify build provenance with the GitHub CLI:"
for file in $binaries $applier_files; do
  case "$file" in
    /*) ;;
    *) file="${prefix}/${file}" ;;
  esac
  say "  gh attestation verify ${file} --repo ${REPO} --signer-workflow ${REPO}/.github/workflows/release-binaries.yml --source-ref refs/heads/main"
done
# A relative prefix (the quickstart's --prefix .) is used by path, not PATH.
case "$prefix" in
  /*) case ":${PATH:-}:" in
    *":${prefix}:"*) ;;
    *) say "" && say "${prefix} is not on PATH; add it to run the binaries by name." ;;
  esac ;;
esac
# Server hosts: a client config so `sudo tenkaictl status --env <env>` talks
# to the local server instead of an empty embedded store. The token stays in
# a root-only file, never in client.toml.
write_server_client_config() {
  case "$sysconfdir" in
    /*) ;;
    *)
      mkdir -p "$sysconfdir" || die "cannot create ${sysconfdir}"
      sysconfdir="$(CDPATH= cd -- "$sysconfdir" && pwd)" || die "cannot resolve ${sysconfdir}"
      ;;
  esac
  conf_dir="${sysconfdir}/tenkai"
  mkdir -p "$conf_dir" || die "cannot create ${conf_dir}"
  if [ "$(id -u)" = 0 ]; then
    chmod 0755 "$conf_dir" || die "cannot set permissions on ${conf_dir}"
    checked="$conf_dir"
    while :; do
      if [ -L "$checked" ]; then
        die "${checked} is a symbolic link; refusing to write client config"
      fi
      # shellcheck disable=SC2046 # split ls -ldn into mode, links, uid, ...
      set -- $(ls -ldn "$checked")
      case "$1" in
        d*) ;;
        *) die "${checked} is not a directory; refusing to write client config" ;;
      esac
      [ "$3" = 0 ] || die "${checked} is owned by uid $3, not root; refusing to write client config"
      case "$1" in
        ?????w* | ????????w*) die "${checked} is writable by group or others; refusing to write client config" ;;
      esac
      [ "$checked" = / ] && break
      checked="$(dirname "$checked")"
    done
  fi
  token_file="${conf_dir}/management.token"
  client_file="${conf_dir}/client.toml"
  if [ ! -e "$token_file" ]; then
    [ -r /dev/urandom ] || die "cannot read /dev/urandom to create ${token_file}"
    token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    [ -n "$token" ] || die "cannot create ${token_file}"
    pending="$(umask 077; mktemp "${conf_dir}/.tenkai-install.XXXXXX")" \
      || die "cannot create a temporary file in ${conf_dir}"
    printf '%s\n' "$token" >"$pending"
    if [ "$(id -u)" = 0 ]; then
      chown 0:0 "$pending"
    fi
    chmod 0600 "$pending"
    if ln "$pending" "$token_file" 2>/dev/null; then
      rm -f "$pending"
      pending=""
      say "  ${token_file}"
    elif [ -e "$token_file" ]; then
      rm -f "$pending"
      pending=""
    else
      rm -f "$pending"
      pending=""
      die "cannot create ${token_file}"
    fi
  fi
  if [ ! -e "$client_file" ]; then
    pending="$(umask 077; mktemp "${conf_dir}/.tenkai-install.XXXXXX")" \
      || die "cannot create a temporary file in ${conf_dir}"
    cat >"$pending" <<EOF
# Written by install.sh --role server. Flags and environment variables override this file.
target = "remote"
server_url = "http://127.0.0.1:8080"
token_file = "${token_file}"
EOF
    if [ "$(id -u)" = 0 ]; then
      chown 0:0 "$pending"
    fi
    chmod 0644 "$pending"
    if ln "$pending" "$client_file" 2>/dev/null; then
      rm -f "$pending"
      pending=""
      say "  ${client_file}"
    elif [ -e "$client_file" ]; then
      rm -f "$pending"
      pending=""
    else
      rm -f "$pending"
      pending=""
      die "cannot create ${client_file}"
    fi
  fi
  grants_file="${conf_dir}/host-grants.toml"
  if [ ! -e "$grants_file" ]; then
    pending="$(umask 022; mktemp "${conf_dir}/.tenkai-install.XXXXXX")" \
      || die "cannot create a temporary file in ${conf_dir}"
    cat >"$pending" <<'EOF'
# Host identity grants (ADR 0047). Root-owned; not writable by group or others.
# OS group names map to the same capabilities as OIDC grant rules.

[[grants.rules]]
value = "tenkai-viewer"
capabilities = ["read"]

[[grants.rules]]
value = "tenkai-operator"
capabilities = ["management"]

[[grants.rules]]
value = "tenkai-admin"
capabilities = ["management"]
EOF
    if [ "$(id -u)" = 0 ]; then
      chown 0:0 "$pending"
    fi
    chmod 0644 "$pending"
    if ln "$pending" "$grants_file" 2>/dev/null; then
      rm -f "$pending"
      pending=""
      say "  ${grants_file}"
    elif [ -e "$grants_file" ]; then
      rm -f "$pending"
      pending=""
    else
      rm -f "$pending"
      pending=""
      die "cannot create ${grants_file}"
    fi
  fi
  if [ "$(id -u)" = 0 ] && [ "$sysconfdir" = /etc ]; then
    for group in tenkai-viewer tenkai-operator tenkai-admin; do
      if command -v groupadd >/dev/null 2>&1; then
        groupadd -r "$group" 2>/dev/null || true
      fi
    done
    if [ -n "${SUDO_USER:-}" ] && command -v usermod >/dev/null 2>&1; then
      usermod -aG tenkai-viewer,tenkai-operator "$SUDO_USER" 2>/dev/null || true
    fi
    if getent passwd tenkai >/dev/null 2>&1; then
      if command -v usermod >/dev/null 2>&1; then
        usermod -aG tenkai-viewer tenkai 2>/dev/null || true
      fi
      if [ -d /run ]; then
        mkdir -p /run/tenkai
        chown tenkai:tenkai-viewer /run/tenkai
        chmod 0750 /run/tenkai
        say "  /run/tenkai"
      fi
    else
      say "create the tenkai user, then: usermod -aG tenkai-viewer tenkai && systemd-tmpfiles --create /usr/lib/tmpfiles.d/tenkai.conf"
    fi
    if [ -d /usr/lib/tmpfiles.d ]; then
      tmpfiles=/usr/lib/tmpfiles.d/tenkai.conf
      if [ ! -e "$tmpfiles" ]; then
        printf 'd /run/tenkai 0750 tenkai tenkai-viewer -\n' >"$tmpfiles"
        chmod 0644 "$tmpfiles"
        say "  ${tmpfiles}"
      fi
    fi
  fi
  say ""
  say "As root, set TENKAI_MANAGEMENT_TOKEN in ${conf_dir}/server.env to the"
  say "contents of ${token_file}. systemd injects that value; the tenkai user"
  say "cannot read a root-only token file. Operators in tenkai-operator use"
  say "the Unix socket /run/tenkai/tenkai.sock without the token:"
  say "  tenkaictl status --env <env>"
}

if [ "$role" = server ]; then
  if [ "$(id -u)" = 0 ] || [ "$sysconfdir" != /etc ]; then
    write_server_client_config
  else
    say ""
    say "Not root; skipped ${sysconfdir}/tenkai/client.toml (pass --sysconfdir or re-run as root)."
  fi
fi

if $with_applier; then
  say ""
  say "The host applier is installed and nothing was started. Next, as root"
  say "(https://github.com/${REPO}/blob/${tag}/docs/host-releases.md#install):"
  say "  1. create the tenkai user and its spool directory;"
  say "  2. write /etc/tenkai/host-applier.toml, release-trust-roots.toml and"
  say "     host-approval-policy.toml, owned by root and writable by root only;"
  say "  3. systemctl daemon-reload;"
  say "  4. check that tenkai may start and stop only tenkai-host-apply@<instance>.service."
fi
