#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Regenerate api/tenkai-http-v1.schema.json from the HTTP route types (#471),
# api/tenkai-terminal-outcome-v2.schema.json from the outcome payload (#867),
# and api/tenkai-feedback-observation-v1.schema.json from the observation (#1101).
TENKAI_UPDATE_API_CONTRACT=1 cargo test --locked -p tenkai-http --lib contract --quiet
