#!/usr/bin/env bash
# Body of the publish-release action: log in with client credentials, publish
# the signed release, and promote it when a channel is named. A re-run with
# the same signed manifest is a no-op; a changed manifest for a published
# version fails, as the server refuses it.
#
# Reads PUBLISH_MANIFEST, PUBLISH_SIGNATURE, PUBLISH_TRUST_ROOTS,
# PUBLISH_CHANNEL, PUBLISH_TENKAICTL, TENKAI_SERVER_URL,
# TENKAI_OIDC_CLIENT_ID and TENKAI_OIDC_CLIENT_SECRET. Writes `release` to
# GITHUB_OUTPUT.
set -euo pipefail

fail() {
  echo "::error::publish-release: $*" >&2
  exit 1
}

# The step publishes as a scoped machine principal only.
[ -z "${TENKAI_MANAGEMENT_TOKEN:-}" ] ||
  fail "TENKAI_MANAGEMENT_TOKEN is set; this step authenticates only with a machine client credential"
for name in PUBLISH_MANIFEST PUBLISH_SIGNATURE PUBLISH_TRUST_ROOTS TENKAI_SERVER_URL \
  TENKAI_OIDC_CLIENT_ID TENKAI_OIDC_CLIENT_SECRET; do
  [ -n "${!name:-}" ] || fail "${name} is empty"
done
for name in PUBLISH_MANIFEST PUBLISH_SIGNATURE PUBLISH_TRUST_ROOTS; do
  [ -f "${!name}" ] || fail "${name} names no file: ${!name}"
done
echo "::add-mask::${TENKAI_OIDC_CLIENT_SECRET}"

# The saved login lives only as long as this step.
XDG_CONFIG_HOME=$(mktemp -d "${RUNNER_TEMP:-/tmp}/tenkai-publish.XXXXXX")
export XDG_CONFIG_HOME
trap 'rm -rf "$XDG_CONFIG_HOME"' EXIT

tenkaictl=${PUBLISH_TENKAICTL:-tenkaictl}
remote() {
  "$tenkaictl" --target remote "$@"
}

"$tenkaictl" login --client-credentials
# A changed manifest for a published version is a conflict, never an update.
published=$(remote --output json-v1 publish "$PUBLISH_MANIFEST" \
  --signature "$PUBLISH_SIGNATURE" --trust-roots "$PUBLISH_TRUST_ROOTS") ||
  fail "the server refused the release: $published"
release=$(printf '%s' "$published" | python3 -c '
import json, sys
result = json.load(sys.stdin)
releases = [r["id"] for r in result.get("resources", []) if r.get("kind") == "release"]
if len(releases) != 1:
    sys.exit("publish named no release")
print(releases[0])
') || fail "unexpected publish result: $published"
echo "published $release"
if [ -n "${PUBLISH_CHANNEL:-}" ]; then
  remote promote "$release" "$PUBLISH_CHANNEL"
fi
echo "release=$release" >>"${GITHUB_OUTPUT:-/dev/null}"
