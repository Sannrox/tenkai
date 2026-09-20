#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash .agents/skills/deliver-ready-issue/scripts/issue-lane.sh capacity --self-test
