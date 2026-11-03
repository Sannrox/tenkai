#!/usr/bin/env bash
# Release dry run for pull requests: the v* workflow's metadata steps against
# stub host binaries. Writes the CHANGELOG notes for the workspace version, a
# CycloneDX SBOM validated against its schema, and the family release
# manifest. Never attests, tags, or publishes. Needs cargo, python3 and
# network access for the pinned SBOM validator.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  printf 'release-dry-run: %s\n' "$1" >&2
  exit 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-release-dry-run.$$.XXXXXX")"
trap "rm -rf $(printf '%q' "$tmp")" EXIT

workflow=.github/workflows/release-binaries.yml
grep -Eq '^[[:space:]]+pull_request' "$workflow" && fail "${workflow} must not run on pull requests"
sed -n '1,/^jobs:/p' "$workflow" | grep -Eq 'attestations: write|id-token: write' \
  && fail "${workflow} must grant attestation permissions per job, not workflow-wide"

python3 scripts/release-metadata.py self-test
version="$(awk '
  /^\[/ { in_package = ($0 == "[package]") }
  in_package && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }
' Cargo.toml)"
[[ -n "$version" ]] || fail "Cargo.toml has no [package] version"
python3 scripts/release-metadata.py notes "$version" >"${tmp}/notes.md"
[[ -s "${tmp}/notes.md" ]] || fail "empty release notes for ${version}"

dist="${tmp}/dist"
mkdir -p "$dist"
while IFS= read -r name; do
  printf 'dry-run %s\n' "$name" >"${dist}/${name}"
done < <(bash scripts/package-release-binaries.sh names)
cp api/tenkai-http-v1.schema.json "$dist/"
bash scripts/package-release-binaries.sh checksums --out "$dist" --require-complete

python3 scripts/release-metadata.py sbom "${dist}/tenkai.cdx.json"
python3 -m venv "${tmp}/venv"
"${tmp}/venv/bin/pip" install --quiet --disable-pip-version-check -r scripts/release-sbom-requirements.txt
"${tmp}/venv/bin/python" scripts/release-metadata.py check-sbom "${dist}/tenkai.cdx.json"

# A version whose tag already exists was released before the CHANGELOG
# carried gate flags; a version still to be tagged must list them.
gate_args=()
if git ls-remote --exit-code --tags origin "refs/tags/v${version}" >/dev/null 2>&1; then
  gate_args=(--allow-missing-gate-flags)
else
  printf 'gate flags for v%s: %s\n' "$version" "$(python3 scripts/release-metadata.py gate-flags "$version")"
fi
python3 scripts/release-metadata.py manifest ${gate_args[@]+"${gate_args[@]}"} \
  --version "$version" \
  --git-sha "$(git rev-parse HEAD)" \
  --tag "v${version}" \
  --dist "$dist" \
  --attestation "https://github.com/Sannrox/tenkai/attestations/dry-run" \
  --out "${dist}/tenkai-release.json"
bash scripts/package-release-binaries.sh names | LC_ALL=C sort >"${tmp}/expected-names"
python3 - "${dist}/tenkai-release.json" "$version" "${tmp}/expected-names" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
expected = open(sys.argv[3]).read().split()
assert manifest["schema"] == "tenkai.family-release-manifest.v1", manifest["schema"]
assert manifest["component"] == "tenkai" and manifest["version"] == sys.argv[2], manifest
assert sorted(item["name"] for item in manifest["binaries"]) == expected, manifest["binaries"]
assert manifest["images"] == [] and "latest" not in json.dumps(manifest), manifest
PY
printf 'release dry run passed for v%s (%s assets)\n' "$version" "$(wc -l <"${tmp}/expected-names" | tr -d ' ')"
