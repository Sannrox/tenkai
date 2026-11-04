#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash scripts/package-release-binaries.sh self-test
bash scripts/verify-release-tag.sh self-test
python3 scripts/release-metadata.py self-test

workflow="$ROOT/.github/workflows/release-binaries.yml"
grep -Fq 'cargo build --release --locked --workspace --features tenkai-server/ui' "$workflow"
grep -Fq 'cargo build --release --locked -p tenkai-server --features postgres,ui' "$workflow"
grep -Fq 'package-hub' "$workflow"
# Linux hosts build at the glibc floor, checked again before checksums (#904).
linux_build="$ROOT/scripts/build-linux-release-hosts.sh"
grep -Fq 'cargo build --release --locked --workspace --features tenkai-server/ui' "$linux_build"
grep -Fq 'cargo build --release --locked -p tenkai-server --features postgres,ui' "$linux_build"
grep -Fq 'build-linux-release-hosts.sh --out dist' "$workflow"
grep -Fq 'package-release-binaries.sh check-glibc --out dist' "$workflow"
grep -Fq 'release-dry-run.sh --linux-hosts' "$ROOT/.github/workflows/ci.yml"
grep -Fq 'verify-release-tag.sh verify-signed' "$workflow"
grep -Fq 'release-metadata.py manifest' "$workflow"
grep -Fq 'sbom-path: dist/tenkai.cdx.json' "$workflow"
grep -Fq -- '--notes-file' "$workflow"
grep -Fq -- '- "v[0-9]+.[0-9]+.[0-9]+-rc.[0-9]+"' "$workflow"
grep -Fq -- '--prerelease="$prerelease" --latest="$latest"' "$workflow"
grep -Fq 'compiled_host_feature_report' "$ROOT/crates/tenkai-server/src/main.rs"
grep -Fq 'require_hub_tenant_mode' "$ROOT/crates/tenkai-server/src/main.rs"
