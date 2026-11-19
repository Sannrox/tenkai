#!/usr/bin/env bash
# Starts what the publish-release step's CI proof publishes to: a loopback
# OIDC issuer (scripts/publish-step-issuer.py) and a tenkai-server that trusts
# it for one service client, plus a dev-signed release and a changed manifest
# of the same version. The server's management token stays in its own
# environment; the step only gets the machine credential. Both processes run
# in the background until the job ends. Test-only.
#
# Usage: scripts/publish-step-fixture.sh <directory with tenkai-server and tenkaictl> <work dir>
# Prints KEY=VALUE lines for the step's inputs; CI appends them to GITHUB_ENV.
set -euo pipefail

bin=$(cd "${1:?directory with tenkai-server and tenkaictl}" && pwd)
work=${2:?work directory}
mkdir -p "$work"
work=$(cd "$work" && pwd)
here=$(cd "$(dirname "$0")" && pwd)

fail() {
  echo "publish step fixture: $*" >&2
  for log in "$work"/*.log; do
    [ -e "$log" ] && { echo "--- $log" >&2; tail -n 30 "$log" >&2; }
  done
  exit 1
}

wait_for() {
  # wait_for <file> waits until it exists and is not empty.
  for _ in $(seq 1 150); do
    [ -s "$1" ] && return 0
    sleep 0.2
  done
  return 1
}

client_id=ci-publisher
client_secret=$(python3 -c 'import secrets; print(secrets.token_hex(24))')

python3 "$here/publish-step-issuer.py" "$work" "$client_id" "$client_secret" ci-publishers \
  >"$work/issuer.log" 2>&1 &
wait_for "$work/issuer-url" || fail "the issuer never listened"
issuer=$(cat "$work/issuer-url")

cat >"$work/oidc.toml" <<EOF
issuer = "$issuer"
audience = "tenkai"
algorithms = ["ES256"]
jwks_uri = "$issuer/jwks"

[client]
client_id = "$client_id"
scopes = []

[grants]
claim = "groups"

[[grants.rules]]
value = "ci-publishers"
capabilities = ["publish"]
channels = ["stable"]
kind = "service"
EOF

keys="$work/keys"
"$bin/tenkaictl" dev init-keys --dir "$keys" >/dev/null
sign() {
  # sign <release dir>: writes <dir>/signature.json and $work/release-trust.toml.
  "$bin/tenkaictl" dev sign-release "$1/tenkai.toml" --keys "$keys" \
    --signature "$1/signature.json" --trust-roots "$work/release-trust.toml" >/dev/null
}
for variant in release changed; do
  mkdir -p "$work/$variant"
  cat >"$work/$variant/tenkai.toml" <<EOF
[product]
name = "publish-step"
version = "1.0.0"

[deploy]
install = "echo $variant"
EOF
  sign "$work/$variant"
done

"$bin/tenkaictl" --database "$work/tenkai.db" init >/dev/null
: >"$work/server.log"
TENKAI_MANAGEMENT_TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(32))') \
  TENKAI_RELEASE_TRUST_ROOTS="$work/release-trust.toml" \
  TENKAI_OIDC_CONFIG="$work/oidc.toml" \
  TENKAI_STATE_DIR="$work/state" \
  "$bin/tenkai-server" --listen 127.0.0.1:0 --database "$work/tenkai.db" \
  --reconcile-interval 3600 >"$work/server.log" 2>&1 &
address=
for _ in $(seq 1 150); do
  address=$(sed -n 's/^tenkai-server listening on \([^ ]*\).*/\1/p' "$work/server.log" | tail -n 1)
  [ -n "$address" ] && curl -fsS "http://$address/readyz" >/dev/null 2>&1 && break
  address=
  sleep 0.2
done
[ -n "$address" ] || fail "the server never became ready"

echo "PUBLISH_STEP_SERVER_URL=http://$address"
echo "PUBLISH_STEP_CLIENT_ID=$client_id"
echo "PUBLISH_STEP_CLIENT_SECRET=$client_secret"
echo "PUBLISH_STEP_TRUST_ROOTS=$work/release-trust.toml"
echo "PUBLISH_STEP_RELEASE=$work/release"
echo "PUBLISH_STEP_CHANGED=$work/changed"
