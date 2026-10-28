#!/usr/bin/env bash
# Inspect, claim, or release the delivery lane of one GitHub Issue.
#
# A lane claim lives on GitHub so agents on different machines see it:
#   1. the branch <type>/<issue>, created from the default branch with an
#      atomic ref creation (POST /git/refs fails when the ref exists, so the
#      first claimant wins and every other claimant sees "claimed");
#   2. the authenticated login assigned to the Issue, visible in the Issue
#      list and timestamped by the Issue timeline.
# Open Pull Requests that reference the Issue and any branch matching
# */<issue> or */<issue>-* count as claims too.
#
# Usage:
#   bash issue-lane.sh check <issue> [--json]
#   bash issue-lane.sh claim <issue> [--dry-run]
#   bash issue-lane.sh release <issue> [--yes]
#   bash issue-lane.sh capacity [--json]
#   bash issue-lane.sh capacity --self-test
#
# Exit codes: 0 unclaimed, done, or remaining capacity; 3 claimed by another
# lane; 1 error or no remaining lane capacity.
# Requires an authenticated gh, git, and jq except for --self-test (jq only).
# Run inside the repository.
set -euo pipefail

STALE_HOURS=6
LANE_LIMIT=3

usage() {
  sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}

fail() {
  printf 'issue-lane: %s\n' "$1" >&2
  exit 1
}

require_tools() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing required command: $tool"
  done
}

# Claim branches are <type>/<issue> or <type>/<issue>-<slug>.
CLAIM_BRANCH_RE='^[^/]+/[0-9]+(-[^/]*)?$'

# Count open implementation PRs plus live claim branches that have no open PR.
# Branches whose Issue is closed, or whose PR already merged, are stale.
capacity_from_json() {
  local merged_heads="${4:-[]}"
  jq -n --argjson branches "$1" --argjson prs "$2" --argjson open_issues "$3" \
    --argjson merged_heads "$merged_heads" \
    --argjson limit "$LANE_LIMIT" --arg re "$CLAIM_BRANCH_RE" '
      def bname: if type == "string" then . else .name end;
      def bsha: if type == "object" then .sha else null end;
      def claim: test($re);
      def issue_of: capture("^(?<type>[^/]+)/(?<n>[0-9]+)(-[^/]*)?$") | .n | tonumber;
      def impl_prs: [($prs // [])[] | select(.headRefName | type == "string" and claim)];
      def claim_branches: [($branches // [])[] | select((. | bname) | type == "string" and claim)];
      def open_set: [($open_issues // [])[] | .number];
      def pr_heads: [impl_prs[].headRefName];
      def merged_name($n):
        any($merged_heads[]?; type == "string" and . == $n);
      def merged_sha($n; $sha):
        $sha != null and any($merged_heads[]?; type == "object" and .headRefName == $n and .sha == $sha);
      def is_merged($b):
        ($b | bname) as $n | ($b | bsha) as $sha
        | merged_name($n) or merged_sha($n; $sha);
      def live_orphan:
        . as $b | ($b | bname) as $n
        | (pr_heads | index($n) | not) and (is_merged($b) | not) and (open_set | index($n | issue_of));
      def stale:
        . as $b | ($b | bname) as $n
        | (pr_heads | index($n) | not) and ((open_set | index($n | issue_of) | not) or is_merged($b));
      def orphans: [claim_branches[] | select(live_orphan) | bname];
      def stale_branches: [claim_branches[] | select(stale) | bname];
      (impl_prs | length) as $pr_count
      | (orphans | length) as $orphan_count
      | ($pr_count + $orphan_count) as $used
      | {
          limit: $limit,
          used: $used,
          remaining: (if ($limit - $used) < 0 then 0 else ($limit - $used) end),
          implementation_prs: impl_prs,
          orphan_claim_branches: orphans,
          stale_claim_branches: stale_branches
        }'
}

print_capacity() {
  local report="$1"
  if [ "$json_output" = true ]; then
    printf '%s\n' "$report" | jq .
    return
  fi
  printf '%s\n' "$report" | jq -r '
    "lane capacity: \(.used)/\(.limit) used, \(.remaining) remaining",
    "implementation PRs: \(if (.implementation_prs | length) == 0 then "none" else ([.implementation_prs[] | "#\(.number) \(.headRefName)"] | join(", ")) end)",
    "orphan claim branches: \(if (.orphan_claim_branches | length) == 0 then "none" else (.orphan_claim_branches | join(", ")) end)",
    "stale claim branches: \(if (.stale_claim_branches | length) == 0 then "none" else (.stale_claim_branches | join(", ")) end)"'
}

capacity_exit() {
  [ "$(printf '%s' "$1" | jq -r '.remaining')" -gt 0 ]
}

run_capacity_self_test() {
  local report
  require_tools jq

  report="$(capacity_from_json '[]' '[]' '[]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 0 ] || fail "self-test: empty should use 0"
  [ "$(printf '%s' "$report" | jq -r '.remaining')" = 3 ] || fail "self-test: empty should remain 3"

  report="$(capacity_from_json '["main","feat/1","docs/note"]' '[]' '[{"number":1}]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 1 ] || fail "self-test: one orphan claim"
  [ "$(printf '%s' "$report" | jq -c '.orphan_claim_branches')" = '["feat/1"]' ] \
    || fail "self-test: ignore non-claim branches"

  report="$(capacity_from_json '["feat/1"]' '[]' '[]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 0 ] || fail "self-test: closed-issue branch is stale"
  [ "$(printf '%s' "$report" | jq -c '.stale_claim_branches')" = '["feat/1"]' ] \
    || fail "self-test: report stale closed-issue branch"

  report="$(capacity_from_json '["feat/1"]' '[{"number":10,"headRefName":"feat/1"}]' '[{"number":1}]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 1 ] || fail "self-test: PR must not double-count its branch"
  [ "$(printf '%s' "$report" | jq -c '.orphan_claim_branches')" = '[]' ] \
    || fail "self-test: claimed branch with PR is not an orphan"

  report="$(capacity_from_json '["feat/1","fix/2","docs/3"]' \
    '[{"number":1,"headRefName":"feat/1"},{"number":2,"headRefName":"fix/2"}]' \
    '[{"number":1},{"number":2},{"number":3}]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 3 ] || fail "self-test: two PRs plus one orphan"
  [ "$(printf '%s' "$report" | jq -r '.remaining')" = 0 ] || fail "self-test: at limit remaining is 0"

  report="$(capacity_from_json '["main"]' '[{"number":9,"headRefName":"dependabot/npm"}]' '[]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 0 ] || fail "self-test: non-claim PR is not a lane"

  report="$(capacity_from_json '["codex/12-slug"]' '[]' '[{"number":12}]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 1 ] || fail "self-test: legacy slug branch counts"

  report="$(capacity_from_json '[]' \
    '[{"number":1,"headRefName":"feat/1"},{"number":2,"headRefName":"fix/2"},{"number":3,"headRefName":"docs/3"},{"number":4,"headRefName":"chore/4"}]' \
    '[]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 4 ] || fail "self-test: over-limit used"
  [ "$(printf '%s' "$report" | jq -r '.remaining')" = 0 ] || fail "self-test: over-limit remaining clamps to 0"

  report="$(capacity_from_json '["feat/201"]' '[]' '[{"number":201}]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 1 ] || fail "self-test: issue numbers above 200 still count"

  report="$(capacity_from_json '["feat/1"]' '[]' '[{"number":1}]' '["feat/1"]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 0 ] || fail "self-test: merged PR head is not a live orphan"
  [ "$(printf '%s' "$report" | jq -c '.stale_claim_branches')" = '["feat/1"]' ] \
    || fail "self-test: merged PR head is stale even when the issue is open"

  report="$(capacity_from_json '[{"name":"feat/1","sha":"aaa"}]' '[]' '[{"number":1}]' \
    '[{"headRefName":"feat/1","sha":"bbb"}]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 1 ] || fail "self-test: recreated branch with new sha is live"
  [ "$(printf '%s' "$report" | jq -c '.orphan_claim_branches')" = '["feat/1"]' ] \
    || fail "self-test: recreated branch is an orphan claim"

  report="$(capacity_from_json '[{"name":"feat/1","sha":"aaa"}]' '[]' '[{"number":1}]' \
    '[{"headRefName":"feat/1","sha":"aaa"}]')"
  [ "$(printf '%s' "$report" | jq -r '.used')" = 0 ] || fail "self-test: leftover merged sha is stale"
  [ "$(printf '%s' "$report" | jq -c '.stale_claim_branches')" = '["feat/1"]' ] \
    || fail "self-test: leftover merged sha is reported stale"

  printf 'issue-lane capacity self-test passed\n'
}

command_name="${1:-}"
case "$command_name" in
  -h | --help | "") usage 0 ;;
  capacity | check | claim | release) ;;
  *) usage ;;
esac
shift

json_output=false
dry_run=false
confirm=false
self_test=false
issue=""
for arg in "$@"; do
  case "$arg" in
    --json) json_output=true ;;
    --dry-run) dry_run=true ;;
    --yes) confirm=true ;;
    --self-test) self_test=true ;;
    *)
      if [ -z "$issue" ] && printf '%s' "$arg" | grep -Eq '^[0-9]+$'; then
        issue="$arg"
      else
        usage
      fi
      ;;
  esac
done

if [ "$command_name" = "capacity" ] && [ "$self_test" = true ]; then
  run_capacity_self_test
  exit 0
fi

if [ "$command_name" != "capacity" ]; then
  [ -n "$issue" ] || fail "Issue number required"
fi

require_tools gh git jq

repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
default_branch="$(gh repo view --json defaultBranchRef --jq .defaultBranchRef.name)"

require_json_array() {
  local desc="$1" value="$2"
  printf '%s' "$value" | jq -e 'type == "array"' >/dev/null \
    || fail "${desc} for lane capacity is not a JSON array"
}

load_capacity_listing() {
  local desc="$1" varname="$2" out st
  shift 2
  set +e
  out="$("$@")"
  st=$?
  set -e
  [ "$st" -eq 0 ] || fail "cannot load ${desc} for lane capacity"
  require_json_array "$desc" "$out"
  printf -v "$varname" '%s' "$out"
}

live_capacity_json() {
  local branches prs open_issues merged_heads
  load_capacity_listing "claim branches" branches bash -c \
    'set -euo pipefail; gh api "$1" --paginate | jq -sc "[.[][] | {name: (.ref | ltrimstr(\"refs/heads/\")), sha: .object.sha}]"' \
    _ "repos/${repo}/git/matching-refs/heads/"
  load_capacity_listing "open pull requests" prs bash -c \
    'set -euo pipefail; gh api --paginate "$1" | jq -s "[.[][] | {number, headRefName: .head.ref}]"' \
    _ "repos/${repo}/pulls?state=open&per_page=100"
  load_capacity_listing "open issues" open_issues bash -c \
    'set -euo pipefail; gh api --paginate "$1" | jq -s "[.[][] | select(.pull_request == null) | {number}]"' \
    _ "repos/${repo}/issues?state=open&per_page=100"
  load_capacity_listing "merged pull request heads" merged_heads bash -c \
    'set -euo pipefail; gh api --paginate "$1" | jq -s "[.[][] | select(.merged_at != null and .head.sha != null) | {headRefName: .head.ref, sha: .head.sha}]"' \
    _ "repos/${repo}/pulls?state=closed&per_page=100"
  capacity_from_json "$branches" "$prs" "$open_issues" "$merged_heads"
}

if [ "$command_name" = "capacity" ]; then
  report="$(live_capacity_json)" || fail "cannot compute lane capacity"
  print_capacity "$report"
  if capacity_exit "$report"; then
    exit 0
  fi
  exit 1
fi

login="$(gh api user --jq .login)"

issue_json="$(gh issue view "$issue" --json number,title,state,labels,assignees,closedByPullRequestsReferences)"
issue_state="$(printf '%s' "$issue_json" | jq -r .state)"
issue_title="$(printf '%s' "$issue_json" | jq -r .title)"

# Derive the lane type deterministically so every machine computes the same
# branch: Conventional Commit type in the title (bug -> fix), then the type
# label, then chore.
lane_type() {
  local from_title
  from_title="$(printf '%s' "$issue_title" | sed -nE 's/^([a-z]+)(\([^)]*\))?!?:.*/\1/p')"
  case "$from_title" in
    bug) printf 'fix' ; return ;;
    "") ;;
    *) printf '%s' "$from_title" ; return ;;
  esac
  if printf '%s' "$issue_json" | jq -e '.labels[] | select(.name == "bug")' >/dev/null; then
    printf 'fix'
  elif printf '%s' "$issue_json" | jq -e '.labels[] | select(.name == "enhancement")' >/dev/null; then
    printf 'feat'
  elif printf '%s' "$issue_json" | jq -e '.labels[] | select(.name == "documentation")' >/dev/null; then
    printf 'docs'
  else
    printf 'chore'
  fi
}
lane_branch="$(lane_type)/${issue}"

# Every branch named <anything>/<issue> or <anything>/<issue>-<slug>.
claim_branches_json() {
  gh api "repos/${repo}/git/matching-refs/heads/" --paginate \
    | jq -sc --arg issue "$issue" '
        [.[][] | .ref | ltrimstr("refs/heads/")
          | select(test("^[^/]+/" + $issue + "(-[^/]*)?$"))]'
}

# Open Pull Requests that GitHub links to the Issue or whose head is a claim branch.
open_prs_json() {
  local numbers branches
  numbers="$(printf '%s' "$issue_json" | jq -r '.closedByPullRequestsReferences[].number')"
  branches="$(printf '%s' "$1" | jq -r '.[]')"
  {
    for number in $numbers; do
      gh pr view "$number" --json number,state,isDraft,headRefName,updatedAt,url,author \
        | jq -c 'select(.state == "OPEN")'
    done
    for branch in $branches; do
      gh pr list --state open --head "$branch" --json number,state,isDraft,headRefName,updatedAt,url,author \
        | jq -c '.[]'
    done
  } | jq -sc 'unique_by(.number) | sort_by(.number)'
}

# Assignees plus the age of the latest assignment event in hours.
assignment_json() {
  local last_assigned now_epoch then_epoch age_hours
  last_assigned="$(gh api "repos/${repo}/issues/${issue}/timeline" --paginate \
    | jq -rs '[.[] | .[]? // empty] | map(select(.event == "assigned")) | sort_by(.created_at) | last | .created_at // empty')"
  age_hours=null
  if [ -n "$last_assigned" ]; then
    now_epoch="$(date -u +%s)"
    then_epoch="$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$last_assigned" +%s 2>/dev/null \
      || date -u -d "$last_assigned" +%s)"
    age_hours=$(( (now_epoch - then_epoch) / 3600 ))
  fi
  printf '%s' "$issue_json" | jq -c --arg at "${last_assigned:-}" --argjson age "$age_hours" \
    '{assignees: [.assignees[].login], last_assigned_at: (if $at == "" then null else $at end), age_hours: $age}'
}

report_json() {
  local branches prs assignment verdict hint
  branches="$(claim_branches_json)"
  prs="$(open_prs_json "$branches")"
  assignment="$(assignment_json)"
  verdict=unclaimed
  hint=""
  if [ "$issue_state" != "OPEN" ]; then
    verdict=closed
  elif [ "$(printf '%s' "$prs" | jq length)" -gt 0 ] || [ "$(printf '%s' "$branches" | jq length)" -gt 0 ]; then
    verdict=claimed
  elif [ "$(printf '%s' "$assignment" | jq '.assignees | length')" -gt 0 ]; then
    if [ "$(printf '%s' "$assignment" | jq '.age_hours // 0')" -lt "$STALE_HOURS" ]; then
      verdict=claimed
    else
      hint="assignment older than ${STALE_HOURS}h without a branch or Pull Request; ask the maintainer before claiming"
    fi
  fi
  jq -n \
    --arg repo "$repo" --argjson issue "$issue" --arg title "$issue_title" --arg state "$issue_state" \
    --arg lane_branch "$lane_branch" --argjson branches "$branches" --argjson prs "$prs" \
    --argjson assignment "$assignment" --arg verdict "$verdict" --arg hint "$hint" \
    '{repo: $repo, issue: $issue, title: $title, state: $state, lane_branch: $lane_branch,
      claim_branches: $branches, open_prs: $prs, assignment: $assignment,
      verdict: $verdict, hint: (if $hint == "" then null else $hint end)}'
}

print_report() {
  local report="$1"
  if [ "$json_output" = true ]; then
    printf '%s\n' "$report" | jq .
    return
  fi
  printf '%s\n' "$report" | jq -r '
    "Issue #\(.issue) [\(.state)] \(.title)",
    "lane branch: \(.lane_branch)",
    "claim branches: \(if (.claim_branches | length) == 0 then "none" else (.claim_branches | join(", ")) end)",
    "open PRs: \(if (.open_prs | length) == 0 then "none" else ([.open_prs[] | "#\(.number) \(if .isDraft then "draft" else "ready" end) \(.headRefName) by \(.author.login) updated \(.updatedAt)"] | join("; ")) end)",
    "assignees: \(if (.assignment.assignees | length) == 0 then "none" else (.assignment.assignees | join(", ")) + " (assigned \(.assignment.last_assigned_at // "unknown"), \(.assignment.age_hours // "?")h ago)" end)",
    "verdict: \(.verdict)\(if .hint then " — " + .hint else "" end)"'
}

verdict_exit() {
  case "$(printf '%s' "$1" | jq -r .verdict)" in
    unclaimed) return 0 ;;
    claimed) return 3 ;;
    *) return 1 ;;
  esac
}

case "$command_name" in
  check)
    report="$(report_json)"
    print_report "$report"
    verdict_exit "$report"
    ;;

  claim)
    report="$(report_json)"
    if ! verdict_exit "$report"; then
      print_report "$report" >&2
      printf 'issue-lane: refusing to claim #%s\n' "$issue" >&2
      exit 3
    fi
    capacity="$(live_capacity_json)" || fail "cannot compute lane capacity"
    if ! capacity_exit "$capacity"; then
      print_capacity "$capacity" >&2
      fail "three-lane limit reached; release or land a lane before claiming #${issue}"
    fi
    base_sha="$(gh api "repos/${repo}/git/ref/heads/${default_branch}" --jq .object.sha)"
    printf 'claim plan: branch %s from %s@%s, assign %s to #%s\n' \
      "$lane_branch" "$default_branch" "${base_sha:0:12}" "$login" "$issue" >&2
    if [ "$dry_run" = true ]; then
      printf 'dry run; no GitHub mutation.\n' >&2
      exit 0
    fi
    if ! gh api -X POST "repos/${repo}/git/refs" \
      -f ref="refs/heads/${lane_branch}" -f sha="$base_sha" >/dev/null 2>&1; then
      printf 'issue-lane: could not create %s; another lane probably claimed #%s first:\n' \
        "$lane_branch" "$issue" >&2
      print_report "$(report_json)" >&2
      exit 3
    fi
    rollback_claim_ref() {
      local reason="$1"
      if ! gh api -X DELETE "repos/${repo}/git/refs/heads/${lane_branch}" >/dev/null; then
        fail "created ${lane_branch} but ${reason} and failed to delete the claim ref"
      fi
      fail "created ${lane_branch} but ${reason}; rolled back the claim ref"
    }
    capacity="$(live_capacity_json)" || rollback_claim_ref "cannot recompute lane capacity"
    if [ "$(printf '%s' "$capacity" | jq -r '.used')" -gt "$LANE_LIMIT" ]; then
      print_capacity "$capacity" >&2
      rollback_claim_ref "three-lane limit exceeded"
    fi
    gh issue edit "$issue" --add-assignee "@me" >/dev/null
    jq -n --arg repo "$repo" --argjson issue "$issue" --arg branch "$lane_branch" \
      --arg base "$base_sha" --arg assignee "$login" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{repo: $repo, issue: $issue, branch: $branch, base_sha: $base, assignee: $assignee, claimed_at: $at}'
    ;;

  release)
    report="$(report_json)"
    if [ "$(printf '%s' "$report" | jq '.open_prs | length')" -gt 0 ]; then
      print_report "$report" >&2
      fail "an open Pull Request exists; close it first or let it land"
    fi
    if printf '%s' "$report" | jq -e --arg b "$lane_branch" '.claim_branches | index($b)' >/dev/null; then
      ahead="$(gh api "repos/${repo}/compare/${default_branch}...${lane_branch}" --jq .ahead_by)"
      if [ "$ahead" -gt 0 ] && [ "$confirm" != true ]; then
        fail "${lane_branch} has ${ahead} commit(s) beyond ${default_branch}; pass --yes to delete it anyway"
      fi
      gh api -X DELETE "repos/${repo}/git/refs/heads/${lane_branch}" >/dev/null
      printf 'deleted branch %s\n' "$lane_branch" >&2
    fi
    if printf '%s' "$report" | jq -e --arg me "$login" '.assignment.assignees | index($me)' >/dev/null; then
      gh issue edit "$issue" --remove-assignee "@me" >/dev/null
      printf 'removed assignee %s from #%s\n' "$login" "$issue" >&2
    fi
    print_report "$(report_json)"
    ;;
esac
