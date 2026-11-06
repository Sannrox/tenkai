#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  printf 'validate-release-packaging: %s\n' "$1" >&2
  exit 1
}

bash scripts/package-release-binaries.sh self-test
bash scripts/test-install-script.sh
bash scripts/verify-release-tag.sh self-test
python3 scripts/release-metadata.py self-test

workflow="$ROOT/.github/workflows/release-binaries.yml"
dispatcher="$ROOT/.github/workflows/release-dispatch.yml"
[[ -f "$workflow" ]] || fail "missing ${workflow}"
[[ -f "$dispatcher" ]] || fail "missing ${dispatcher}"

# The dispatcher only turns a v* tag push into a main run of release-binaries.yml.
grep -F 'tags: ["v*"]' "$dispatcher" >/dev/null || fail "${dispatcher} must trigger on v* tags"
grep -F "actions: write" "$dispatcher" >/dev/null || fail "${dispatcher} must be able to dispatch workflows"
if grep -E '^[[:space:]]*(-[[:space:]]+)?uses:|workflow_dispatch|pull_request|contents: write' "$dispatcher" >/dev/null; then
  fail "${dispatcher} must only dispatch: no actions, other triggers, or write access"
fi
dispatch_runs="$(grep -E '^[[:space:]]*(-[[:space:]]+)?run:' "$dispatcher")"
[[ "$dispatch_runs" =~ ^[[:space:]]*run:\ gh\ workflow\ run\ release-binaries\.yml\ --ref\ main\ -f\ tag=\"\$TAG\"$ ]] \
  || fail "${dispatcher} must run only: gh workflow run release-binaries.yml --ref main -f tag=\"\$TAG\""

# release-binaries.yml runs from main for a tag input; a tag push never runs it.
if grep -E '^  push:|^[[:space:]]+tags:' "$workflow" >/dev/null; then
  fail "${workflow} must not run on push; release-dispatch.yml starts it from main"
fi
grep -F "workflow_dispatch:" "$workflow" >/dev/null || fail "${workflow} must allow a non-tag dry-run"
grep -F 'group: release-${{ inputs.tag || github.ref }}' "$workflow" >/dev/null || fail "${workflow} must run one release per tag"
grep -F '[[ "$WORKFLOW_REF" == refs/heads/main ]]' "$workflow" >/dev/null || fail "${workflow} must refuse tagged runs that are not from main"
grep -F "ref: \${{ inputs.tag && format('refs/tags/{0}', inputs.tag) || '' }}" "$workflow" >/dev/null || fail "${workflow} must check out the release tag"
grep -F 'git fetch --force origin "refs/tags/${TAG}:refs/tags/${TAG}"' "$workflow" >/dev/null || fail "${workflow} must fetch the annotated tag object"
grep -F 'sha="$(git rev-parse "${TAG}^{commit}")"' "$workflow" >/dev/null || fail "${workflow} must resolve the tagged commit"
grep -F 'bash "${MAIN_TREE}/scripts/verify-release-tag.sh" verify-signed "$TAG" "$sha"' "$workflow" >/dev/null || fail "${workflow} must verify the tag with main's verifier against the tagged commit"
grep -F 'RELEASE_TAG_FINGERPRINTS="${MAIN_TREE}/security/release-tag-fingerprints"' "$workflow" >/dev/null || fail "${workflow} must verify against main's allowed keys"
grep -F 'git merge-base --is-ancestor "$sha" refs/remotes/origin/main' "$workflow" >/dev/null || fail "${workflow} must require the tagged commit on main"
if grep -E 'github\.sha|github\.ref_name|GITHUB_SHA|GITHUB_REF_NAME|github\.event_name' "$workflow" >/dev/null; then
  fail "${workflow} must use the tagged commit and tag input, not the event SHA or ref name"
fi
grep -F "if: needs.verify-tag.outputs.tag != ''" "$workflow" >/dev/null || fail "${workflow} must gate package/attest/publish on a verified tag"
grep -F "if: needs.verify-tag.outputs.tag == ''" "$workflow" >/dev/null || fail "${workflow} must dry-run when dispatched without a tag"
grep -F -- "--verify-tag" "$workflow" >/dev/null || fail "${workflow} must create the release for the existing tag"
grep -F '[[ "$TAG" == *-* ]]' "$workflow" >/dev/null || fail "${workflow} must treat a tag with - as a pre-release"
grep -Fq -- '--prerelease="$prerelease" --latest="$latest"' "$workflow" || fail "${workflow} must publish rc tags as pre-release never latest"
[[ "$(grep -c 'already published; releases are immutable' "$workflow")" -ge 3 ]] \
  || fail "${workflow} must refuse a published release early, when attesting, and when publishing"

checkouts="$(grep -c 'uses: actions/checkout@' "$workflow")"
sha_checkouts="$(grep -c 'ref: ${{ needs.verify-tag.outputs.sha }}' "$workflow")"
head_checks="$(grep -c 'test "$(git rev-parse HEAD)" = "$SHA"' "$workflow")"
[[ "$checkouts" -eq $((sha_checkouts + 2)) ]] || fail "${workflow} must check out the release commit in every job after verify-tag"
[[ "$head_checks" -eq "$sha_checkouts" ]] || fail "${workflow} must check HEAD after every release-commit checkout"

grep -Fq 'cargo build --release --locked --workspace --features tenkai-server/ui' "$workflow"
grep -Fq 'cargo build --release --locked -p tenkai-server --features postgres,ui' "$workflow"
grep -Fq 'package-hub' "$workflow"
# Linux hosts build at the glibc floor, checked again before checksums (#904).
linux_build="$ROOT/scripts/build-linux-release-hosts.sh"
grep -Fq 'cargo build --release --locked --workspace --features tenkai-server/ui' "$linux_build"
grep -Fq 'cargo build --release --locked -p tenkai-server --features postgres,ui' "$linux_build"
# The host applier ships for Linux only and is smoke-run there (#949).
grep -Fq -- '--bin tenkai-host-applier' "$linux_build"
grep -Fq 'tenkai-runtime tenkai-runtime-guard tenkai-host-applier; do' "$ROOT/.github/workflows/ci.yml"
grep -Fq 'build-linux-release-hosts.sh --out dist' "$workflow"
grep -Fq 'package-release-binaries.sh check-glibc --out dist' "$workflow"
grep -Fq 'release-dry-run.sh --linux-hosts' "$ROOT/.github/workflows/ci.yml"
# install.sh is attached for the tag's version and installed on clean
# distributions in CI (#905).
grep -Fq 'install-script --out dist --version "${TAG#v}"' "$workflow" \
  || fail "${workflow} must write install.sh for the tag version"
grep -Fq 'test-install-script.sh --linux-hosts linux-hosts' "$ROOT/.github/workflows/ci.yml"
grep -Fq 'verify-release-tag.sh" verify-signed' "$workflow" \
  || fail "${workflow} must run verify-signed from main's tree"
grep -Fq 'release-metadata.py manifest' "$workflow"
grep -Fq 'sbom-path: dist/tenkai.cdx.json' "$workflow"
grep -Fq -- '--notes-file' "$workflow"
grep -Fq -- '--git-sha "${SHA}"' "$workflow"
grep -Fq 'compiled_host_feature_report' "$ROOT/crates/tenkai-server/src/main.rs"
grep -Fq 'require_hub_tenant_mode' "$ROOT/crates/tenkai-server/src/main.rs"
