#!/usr/bin/env bash
# Linux proof for the server side of privileged host releases (ADR 0041 §2):
# tenkai-server runs as the unprivileged `tenkai` user, plans a signed host
# release against the applier's record, installs it and runs its health step,
# then uninstalls it, all through tenkai-host-apply@.service with approvals
# the server cannot sign itself. Run it after scripts/host-applier-systemd-drill.sh, which
# installs the applier, the unit, and the polkit rule. Needs root (via sudo)
# and systemd as PID 1. Never run it on a host you care about.
#
# Usage: scripts/host-executor-drill.sh <directory with tenkai-server and tenkaictl>
set -euo pipefail

bin=$(cd "${1:?directory with tenkai-server and tenkaictl}" && pwd)
evidence=/var/lib/tenkai-host-server-drill
unit=tenkai-drill-server
work=$(mktemp -d)
cleanup() {
  sudo systemctl stop "$unit" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "host executor drill: $*" >&2
  sudo journalctl -u "$unit" --no-pager -o cat | tail -n 50 >&2 || true
  exit 1
}

tenkaictl() {
  "$bin/tenkaictl" "$@"
}

remote() {
  "$bin/tenkaictl" --target remote "$@"
}

json_field() {
  # json_field <python expression over r>
  python3 -c "import json,sys; r=json.load(sys.stdin); print($1)"
}

generation() {
  remote env inspect host-env | json_field 'r["lease"]["generation"] or 0'
}

echo "== operator keys stay outside the server's reach"
keys="$work/keys"
tenkaictl dev init-keys --dir "$keys" >/dev/null
mkdir -p "$work/release"
cat >"$work/release/tenkai.toml" <<EOF
[product]
name = "host-drill"
version = "1.0.0"

[deploy]
executor = "host"
install = "mkdir -p $evidence && id -u > $evidence/installed"
uninstall = "rm -rf $evidence"
health = "test \"\$(cat $evidence/installed)\" = 0 && touch $evidence/healthy"
EOF
tenkaictl dev sign-release "$work/release/tenkai.toml" --keys "$keys" \
  --signature "$work/signature.json" --trust-roots "$work/release-trust.toml" >/dev/null
# The trusted approver's public key, from an approval of nothing in particular.
tenkaictl dev sign-approval --plan-digest "sha256:$(printf '0%.0s' $(seq 1 64))" --env host-env \
  --keys "$keys" --approval "$work/probe.json" --trust-roots "$work/approvers.toml" >/dev/null
sudo install -o root -g root -m 0644 "$work/release-trust.toml" /etc/tenkai/release-trust-roots.toml
# Only this approver may authorize host steps.
sudo install -o root -g root -m 0644 "$work/approvers.toml" /etc/tenkai/host-approval-policy.toml

echo "== tenkai-server runs as tenkai with the host executor"
sudo install -o root -g root -m 0755 "$bin/tenkai-server" "$bin/tenkaictl" /usr/local/bin/
server_dir=/var/lib/tenkai/drill-server
sudo install -o tenkai -g tenkai -m 0700 -d "$server_dir"
sudo install -o tenkai -g tenkai -m 0644 "$work/release-trust.toml" "$server_dir/release-trust.toml"
sudo -u tenkai /usr/local/bin/tenkaictl --database "$server_dir/tenkai.db" init >/dev/null
token=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
sudo systemd-run --unit "$unit" --uid tenkai --gid tenkai \
  --setenv TENKAI_MANAGEMENT_TOKEN="$token" \
  --setenv TENKAI_RELEASE_TRUST_ROOTS="$server_dir/release-trust.toml" \
  --setenv TENKAI_HOST_SPOOL_DIR=/var/lib/tenkai/host-spool \
  --setenv TENKAI_STATE_DIR="$server_dir/state" \
  /usr/local/bin/tenkai-server --listen 127.0.0.1:0 \
  --database "$server_dir/tenkai.db" --reconcile-interval 3600 >/dev/null
address=
for _ in $(seq 1 150); do
  address=$(sudo journalctl -u "$unit" --no-pager -o cat |
    sed -n 's/^tenkai-server listening on \([^ ]*\).*/\1/p' | tail -n 1)
  [ -n "$address" ] && curl -fsS "http://$address/readyz" >"$work/readyz" 2>/dev/null && break
  sleep 0.2
done
[ -s "$work/readyz" ] || fail "the server never became ready"
grep -q 'host_executor:v1' "$work/readyz" || fail "/readyz does not report host_executor:v1: $(cat "$work/readyz")"
pid=$(systemctl show -p MainPID --value "$unit")
[ "$(ps -o user= -p "$pid" | tr -d ' ')" = tenkai ] || fail "the server does not run as tenkai"
export TENKAI_SERVER_URL="http://$address" TENKAI_MANAGEMENT_TOKEN="$token"

echo "== a host release is planned against the applier's record"
remote env add host-env --reason "host executor drill" >/dev/null
remote publish "$work/release/tenkai.toml" --signature "$work/signature.json" \
  --trust-roots "$work/release-trust.toml" >/dev/null
remote promote host-drill@1.0.0 stable >/dev/null
remote env subscribe host-env host-drill=stable --generation "$(generation)" >/dev/null
remote plan --env host-env --generation "$(generation)" >"$work/plan.txt"
plan=$(sed -n 's/^plan id: //p' "$work/plan.txt")
digest=$(sed -n 's/^plan digest: //p' "$work/plan.txt")
[ -n "$plan" ] && [ -n "$digest" ] || fail "no plan: $(cat "$work/plan.txt")"

echo "== an approval the root side does not trust runs nothing"
# The server accepts this approver; the root-owned host policy does not.
tenkaictl dev init-keys --dir "$work/other-keys" >/dev/null
tenkaictl dev sign-approval --plan-digest "$digest" --env host-env --keys "$work/other-keys" \
  --approval "$work/untrusted.json" --trust-roots "$work/untrusted-approvers.toml" >/dev/null
before=$(date +%s)
if remote apply "$plan" --approval "$work/untrusted.json" \
  --approval-trust-roots "$work/untrusted-approvers.toml" --generation "$(generation)" >/dev/null 2>&1; then
  fail "a plan approved only by an untrusted approver applied"
fi
sudo test ! -e "$evidence/installed" || fail "an unapproved host step ran"
sudo journalctl -t tenkai-host-apply --since "@$before" --no-pager -o cat |
  grep -q 'refused: host approval policy' ||
  fail "the applier did not refuse the untrusted approval"
remote plan --env host-env --generation "$(generation)" >"$work/plan.txt"
plan=$(sed -n 's/^plan id: //p' "$work/plan.txt")
digest=$(sed -n 's/^plan digest: //p' "$work/plan.txt")
[ -n "$plan" ] && [ -n "$digest" ] || fail "no plan after the refusal: $(cat "$work/plan.txt")"

echo "== an approved plan installs as root, then runs its health step"
tenkaictl dev sign-approval --plan-digest "$digest" --env host-env --keys "$keys" \
  --approval "$work/approval.json" --trust-roots "$work/approvers.toml" >/dev/null
remote apply "$plan" --approval "$work/approval.json" --approval-trust-roots "$work/approvers.toml" \
  --generation "$(generation)" >"$work/apply.txt" || fail "apply failed: $(cat "$work/apply.txt")"
[ "$(sudo cat "$evidence/installed")" = 0 ] || fail "the install did not run as root"
sudo test -e "$evidence/healthy" || fail "the health step did not run"
outcomes=$(sudo python3 -c '
import glob, json
for path in glob.glob("/var/lib/tenkai-host/instances/*/result.json"):
    r = json.load(open(path))
    if r["product"] == "host-drill":
        print(r["action"], r["outcome"], r["generation"])
' | sort)
[ "$outcomes" = "$(printf 'health succeeded 1\ninstall succeeded 1')" ] ||
  fail "unexpected host results: $outcomes"
remote env inspect host-env | json_field 'r["latest_plan"]["state"]' >"$work/state"
[ "$(cat "$work/state")" = succeeded ] || fail "the plan is $(cat "$work/state")"
# The server removes what it spooled once a step ended; the applier drill's
# own fixtures stay.
left=$(sudo python3 -c '
import glob, json, os
for path in glob.glob("/var/lib/tenkai-host/instances/*/result.json"):
    if json.load(open(path))["product"] == "host-drill":
        instance = os.path.basename(os.path.dirname(path))
        if os.path.exists(os.path.join("/var/lib/tenkai/host-spool", instance)):
            print(instance)
')
[ -z "$left" ] || fail "the server left its spool behind: $left"

echo "== the environment is converged"
remote plan --env host-env --generation "$(generation)" >"$work/again.txt"
grep -q 'host-env is up to date' "$work/again.txt" ||
  fail "a converged environment planned steps: $(cat "$work/again.txt")"

echo "== unsubscribing uninstalls the host release through an approved plan"
remote env unsubscribe host-env host-drill --generation "$(generation)" >/dev/null
remote plan --env host-env --generation "$(generation)" >"$work/remove.txt"
plan=$(sed -n 's/^plan id: //p' "$work/remove.txt")
digest=$(sed -n 's/^plan digest: //p' "$work/remove.txt")
[ -n "$plan" ] && [ -n "$digest" ] || fail "no removal plan: $(cat "$work/remove.txt")"
tenkaictl dev sign-approval --plan-digest "$digest" --env host-env --keys "$keys" \
  --approval "$work/remove-approval.json" --trust-roots "$work/approvers.toml" >/dev/null
remote apply "$plan" --approval "$work/remove-approval.json" --approval-trust-roots "$work/approvers.toml" \
  --generation "$(generation)" >"$work/apply.txt" || fail "removal failed: $(cat "$work/apply.txt")"
sudo test ! -e "$evidence" || fail "the uninstall did not run"
record=$(sudo python3 -c '
import glob, json
for path in glob.glob("/var/lib/tenkai-host/records/*.json"):
    r = json.load(open(path))
    if r["environment"] == "host-env" and r["product"] == "host-drill":
        print(r["state"], r["generation"])
')
[ "$record" = "empty 2" ] || fail "unexpected applied-state record after the uninstall: $record"
remote plan --env host-env --generation "$(generation)" >"$work/again.txt"
grep -q 'host-env is up to date' "$work/again.txt" ||
  fail "a removed product planned steps: $(cat "$work/again.txt")"

echo "host executor drill passed"
