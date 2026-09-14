#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SKILLS_ROOT=".agents/skills"

fail() {
  printf 'workflow skill parity check failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || fail "missing $1"
}

require_line() {
  grep -Fqx "$2" "$1" || fail "$1 is missing canonical line: $2"
}

require_fragment() {
  grep -Fq "$2" "$1" || fail "$1 is missing required metadata: $2"
}

# Parallel lanes: the lead procedure lives with deliver-ready-issue, the policy
# lives in AGENTS.md, and both must stay linked.
PARALLEL_REFERENCE="$SKILLS_ROOT/deliver-ready-issue/references/parallel-delivery.md"
LANE_SCRIPT="$SKILLS_ROOT/deliver-ready-issue/scripts/issue-lane.sh"
require_file "$PARALLEL_REFERENCE"
require_file "$LANE_SCRIPT"
require_fragment "$SKILLS_ROOT/deliver-ready-issue/SKILL.md" "references/parallel-delivery.md"
require_fragment "$SKILLS_ROOT/deliver-ready-issue/SKILL.md" "scripts/issue-lane.sh"
require_fragment "$SKILLS_ROOT/advance-issue-frontier/SKILL.md" "issue-lane.sh check"
require_line "AGENTS.md" "## Parallel delivery lanes"
require_fragment "$PARALLEL_REFERENCE" "AGENTS.md"
require_fragment "AGENTS.md" "issue-lane.sh claim"
grep -Fq "/.worktrees/" .gitignore || fail ".gitignore does not ignore the /.worktrees/ lane directory"

printf 'workflow skill parity check passed\n'
