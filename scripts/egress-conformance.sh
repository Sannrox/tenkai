#!/usr/bin/env bash
# Isolated-network conformance (#628): run the install, first deploy, upgrade
# and rollback drills with no route out, and fail on any outbound attempt.
#
# The drills are built normally (dependencies may download), then run in a
# fresh network namespace that has only loopback, under strace. Every
# connect() or addressed send (sendto/sendmsg/sendmmsg, as unconnected UDP
# uses) to a non-loopback address, and every DNS lookup to any address, is an
# outbound attempt; the report names the process that made it.
# Linux only; needs strace, unshare, ip, and root or passwordless sudo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export LC_ALL=C

# Integration drills: deploy, upgrade, rollback and offline bind.
DRILLS=(stateful_upgrade_drill connectivity_upgrade_cli two_environment_closure_drill offline_fleet_drill)
# Library tests by filter: the offline first install into an empty catalog.
LIB_FILTERS=(connectivity::tests::first_install)
REPORT="${EGRESS_REPORT:-$ROOT/target/egress-report.txt}"
mkdir -p "$(dirname "$REPORT")"

for tool in strace unshare ip jq; do
  command -v "$tool" >/dev/null || { echo "egress conformance needs $tool" >&2; exit 2; }
done

cargo build --locked --bins --workspace
binaries=()
for drill in "${DRILLS[@]}"; do
  binary="$(cargo test --locked --workspace --test "$drill" --no-run --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' \
    | tail -n 1)"
  [[ -x "$binary" ]] || { echo "no test binary for $drill" >&2; exit 2; }
  binaries+=("$drill=$binary=")
done
lib_binary="$(cargo test --locked -p tenkai --lib --no-run --message-format=json \
  | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' \
  | tail -n 1)"
[[ -x "$lib_binary" ]] || { echo "no tenkai library test binary" >&2; exit 2; }
for filter in "${LIB_FILTERS[@]}"; do
  binaries+=("${filter//:/_}=$lib_binary=$filter")
done

work="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-egress.XXXXXX")"
trap 'rm -rf "$work"' EXIT
user="$(id -un)"
as_root=()
[[ "$(id -u)" -eq 0 ]] || as_root=(sudo)

status=0
findings="$work/findings"
: > "$findings"
for entry in "${binaries[@]}"; do
  IFS='=' read -r drill binary filter <<< "$entry"
  trace="$work/$drill.trace"
  echo "egress conformance: $drill"
  # A new network namespace with loopback up and nothing else; the drill
  # runs as the invoking user, traced with process names (-Y).
  # sudo resets PATH and HOME, so they are passed through explicitly.
  if ! "${as_root[@]}" unshare --net -- sh -c '
      ip link set lo up
      exec sudo --preserve-env -u "$1" env PATH="$4" HOME="$5" \
        strace -f -qq -Y -e trace=connect,sendto,sendmsg,sendmmsg -o "$2" "$3" --test-threads=1 $6
    ' sh "$user" "$trace" "$binary" "$PATH" "$HOME" "$filter"; then
    echo "$drill: drill failed" >> "$findings"
    status=1
  fi
  # Outbound: a connect or an addressed send (unconnected UDP) to IPv4
  # outside 127/8 or IPv6 other than loopback, or to port 53 anywhere. Each
  # destination on a line is judged on its own: one sendmmsg can carry
  # several, and a loopback one must not hide another.
  if [[ -f "$trace" ]]; then
    # No network syscall at all is the expected clean trace: grep's "no
    # match" (1) is not an error, anything above it is.
    calls="$(grep -E '(connect|sendto|sendmsg|sendmmsg)\(' "$trace")" || [[ $? -eq 1 ]]
    [[ -n "$calls" ]] && while IFS= read -r line; do
      outbound=false
      while IFS= read -r address; do
        case "$address" in
          127.* | ::1 | ::ffff:127.*) ;;
          *) outbound=true ;;
        esac
      done < <(grep -oE 'inet_addr\("[^"]+"\)|inet_pton\(AF_INET6?, "[^"]+"' <<< "$line" \
        | sed -E 's/.*"([^"]+)".*/\1/')
      if [[ "$line" =~ htons\(53\) ]]; then
        echo "$drill: dns: $line"
      elif $outbound; then
        echo "$drill: $line"
      fi
    done <<< "$calls" >> "$findings"
  fi
done

{
  echo "isolated-network conformance: ${#binaries[@]} drills: ${DRILLS[*]} ${LIB_FILTERS[*]}"
  echo "attempted destinations:"
  if [[ -s "$findings" ]]; then sort -u "$findings"; else echo "none"; fi
} > "$REPORT"
cat "$REPORT"
if [[ -s "$findings" || "$status" -ne 0 ]]; then
  echo "egress conformance failed (report: $REPORT)" >&2
  exit 1
fi
