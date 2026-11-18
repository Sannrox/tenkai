#!/usr/bin/env bash
# Install Tenkai on a macOS runner the two ways operators do (#917), and
# undo both. Runs only on a disposable macOS host with passwordless sudo:
# it writes a LaunchDaemon and /var/db/tenkai-runtime.
#
# Usage: scripts/test-macos-install.sh --dist DIR
#
# DIR holds tenkai.rb (written by scripts/release/metadata.py formula) and
# the darwin-aarch64 runtime hosts. Checks:
#   - Homebrew: the formula installs tenkaictl, tenkai-server and
#     tenkai-executor-guard; `brew test` passes; `brew services start tenkai`
#     serves /readyz with the shell executor (the server found its guard) and
#     /ui/; tenkaictl reaches it with the formula's management token.
#   - launchd: the runtime installs its home, and the LaunchDaemon in
#     examples/runtime-agent-launchd starts it from the home at load and
#     starts it again after it exits.
# The release workflow runs it before pushing the formula to the tap; its
# dry run runs it against locally built hosts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAP=tenkai-release-test/local
LABEL=com.github.sannrox.tenkai-runtime
PLIST="${ROOT}/examples/runtime-agent-launchd/${LABEL}.plist"
RUNTIME_HOME=/var/db/tenkai-runtime

fail() {
  printf 'test-macos-install: %s\n' "$1" >&2
  exit 1
}

dist=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist)
      [[ $# -ge 2 ]] || fail "--dist requires a directory"
      dist="$(cd "$2" && pwd)"
      shift 2
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[[ -f "${dist}/tenkai.rb" ]] || fail "--dist DIR with tenkai.rb is required"
[[ "$(uname -s)" == Darwin ]] || fail "runs on macOS only"
command -v brew >/dev/null 2>&1 || fail "brew is required"

# Wait up to $1 seconds for the command after it to succeed.
wait_for() {
  local seconds="$1"
  shift
  for _ in $(seq 1 "$seconds"); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-macos-install.$$.XXXXXX")"
cleanup() {
  brew services stop "${TAP}/tenkai" >/dev/null 2>&1 || true
  brew uninstall --force "${TAP}/tenkai" >/dev/null 2>&1 || true
  brew untap "$TAP" >/dev/null 2>&1 || true
  sudo launchctl bootout "system/${LABEL}" >/dev/null 2>&1 || true
  sudo rm -rf "/Library/LaunchDaemons/${LABEL}.plist" "$RUNTIME_HOME" /etc/tenkai-runtime \
    /var/log/tenkai-runtime.log
  rm -rf "$tmp"
}
trap cleanup EXIT

# Homebrew installs formulae only from a tap.
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1
brew tap-new --no-git "$TAP" >/dev/null
cp "${dist}/tenkai.rb" "$(brew --repository "$TAP")/Formula/tenkai.rb"
brew install --formula "${TAP}/tenkai"
brew test "${TAP}/tenkai"
brew services start "${TAP}/tenkai"
token="$(brew --prefix)/var/tenkai/management.token"
[[ "$(stat -f %Lp "$token")" == 600 ]] || fail "${token} is not mode 0600"
if ! wait_for 60 curl -fsS -o "${tmp}/readyz" http://127.0.0.1:8080/readyz; then
  tail -n 20 "$(brew --prefix)/var/log/tenkai-server.log" >&2 || true
  fail "brew services did not serve /readyz"
fi
grep -q shell_executor "${tmp}/readyz" || fail "/readyz lacks the shell executor"
curl -fsS -o /dev/null http://127.0.0.1:8080/ui/ || fail "/ui/ is not served"
"$(brew --prefix)/bin/tenkaictl" --target remote --server-url http://127.0.0.1:8080 \
  --token-file "$token" env list >/dev/null || fail "tenkaictl cannot reach the brew service"
brew services stop "${TAP}/tenkai"
printf 'homebrew: installed, served, and stopped\n'

# The runtime installs its home from a staged binary and guard.
mkdir -p "${tmp}/runtime"
cp "${dist}/tenkai-runtime-darwin-aarch64" "${tmp}/runtime/tenkai-runtime"
cp "${dist}/tenkai-runtime-guard-darwin-aarch64" "${tmp}/runtime/tenkai-runtime-guard"
chmod 0755 "${tmp}/runtime/"*
sudo "${tmp}/runtime/tenkai-runtime" install --home "$RUNTIME_HOME"
# No server settings: the agent starts, names the missing setting, and exits,
# so launchd starting it twice shows it runs at load and again after an exit.
sudo rm -f /var/log/tenkai-runtime.log
sudo mkdir -p /etc/tenkai-runtime
sudo install -m 0600 -o root -g wheel /dev/null /etc/tenkai-runtime/env
sudo install -m 0644 -o root -g wheel "$PLIST" /Library/LaunchDaemons/
sudo launchctl bootstrap system "/Library/LaunchDaemons/${LABEL}.plist"
started_twice() {
  local count
  count="$(sudo grep -c 'TENKAI_SERVER_URL is required' /var/log/tenkai-runtime.log 2>/dev/null || true)"
  [[ "${count:-0}" -ge 2 ]]
}
if ! wait_for 60 started_twice; then
  sudo launchctl print "system/${LABEL}" >&2 || true
  sudo tail -n 20 /var/log/tenkai-runtime.log >&2 || true
  fail "launchd did not start the runtime from its home twice"
fi
printf 'launchd: started the runtime from its home at load and after it exited\n'
