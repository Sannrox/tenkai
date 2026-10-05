#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash scripts/package-release-binaries.sh self-test
bash scripts/verify-release-tag.sh self-test

workflow="$ROOT/.github/workflows/release-binaries.yml"
grep -Fq 'cargo build --release --locked --features ui' "$workflow"
grep -Fq 'cargo build --release --locked --features postgres,ui --bin tenkai-server' "$workflow"
grep -Fq 'package-hub' "$workflow"
grep -Fq 'compiled_host_feature_report' "$ROOT/src/bin/tenkai-server.rs"
grep -Fq 'require_hub_tenant_mode' "$ROOT/src/bin/tenkai-server.rs"
