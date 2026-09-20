---
name: advance-issue-frontier
description: Advance the tenkai GitHub issue frontier after work merges or when asked what is ready next. Use to evaluate dependency-linked open issues, detect Pull Request, claim-branch, and assignment claims across machines, update blocked or ready status, enforce active-lane limits, and recommend the next deliverable or parallel lane set without implementing it.
---

# Advance Issue Frontier

Compute the delivery frontier from live GitHub state. A frontier issue is open,
has no unresolved dependency, and has no claim on GitHub. Lanes run on several
machines, so only GitHub shows every claim; the worktrees on this machine are
local isolation and are reported separately.

## Establish authority and scope

Default to **report-only**. Modify issue state only when the user explicitly
asks to update or advance the frontier.

Resolve:

- the repository and relevant issue set;
- whether a merge, closure, or full backlog review triggered the run;
- the active-lane limit, defaulting to three (`LANE_LIMIT=3`);
- the permitted mutation: none, labels, or a documented body fallback.

Read `README.md`, `DESIGN.md`, `AGENTS.md`, repository instructions, and live
issues and pull requests. Do not rely on a stale local backlog export.

## Build the dependency graph

1. Fetch open backlog issues and implementation pull requests. Include recently
   closed predecessors needed to evaluate dependencies. Collect the GitHub
   claims in the same pass, then the local isolation on this machine:

   ```sh
   bash .agents/skills/deliver-ready-issue/scripts/issue-lane.sh capacity
   gh pr list --state open --json number,headRefName,isDraft,updatedAt,body
   gh issue list --state open --limit 200 --json number,assignees,updatedAt
   git worktree list --porcelain
   ```

   Map each branch `<type>/<issue>` or `*/<issue>-*` (including legacy
   `codex/<issue>-<slug>`) to its Issue number. For a candidate whose state
   matters, run
   `bash .agents/skills/deliver-ready-issue/scripts/issue-lane.sh check <issue>`;
   it resolves linked Pull Requests, claim branches, and the assignment age
   from the Issue timeline. Do not run `git fetch --prune` while another lane
   on this machine is mutating shared Git state; the GitHub reads above do not
   need it.
2. Parse dependencies only from each issue's `## Dependencies` section. Resolve
   referenced issues in the same repository unless the text explicitly names
   another repository.
3. Treat explicit statements that prerequisites are completed as delivered
   evidence. Treat `None` or equivalent language as an empty dependency set.
4. Treat a referenced closed issue as delivered only when its closure state is
   consistent with the dependency wording. If it was closed as unplanned or
   superseded, require evidence that the dependent outcome remains valid.
5. Treat textual gates such as an active predecessor or external decision as
   blocking until the issue explicitly records them as delivered.
6. Detect missing references, contradictory status, self-dependencies, and
   cycles. Keep affected issues blocked and report the anomaly rather than
   guessing.

Never infer a dependency from ordinary prose, issue numbering, roadmap phases,
milestones, or similar subject matter.

## Compute the frontier

For each open issue, classify it as:

- **blocked**: at least one dependency is unresolved or ambiguous;
- **ready**: every dependency is delivered and no claim exists on GitHub;
- **active**: a claim exists on GitHub. In precedence order: an open Pull
  Request, draft or ready, that references the Issue; a branch
  `<type>/<issue>` or `*/<issue>-*`; or an assignment less than six hours old;
- **anomalous**: the dependency graph cannot be evaluated safely.

An assignment older than six hours with neither branch nor Pull Request is an
ownership hint: report it and leave the Issue ready with the hint attached,
so the maintainer decides. A claim is live while its Issue is open and its
branch or Pull Request is neither merged nor closed. A branch whose Issue is
closed or whose Pull Request has merged, and a local worktree on this machine
in the same situation, are stale: report them for cleanup by their owner and
do not count them as lanes. Because `main` is squash-merged, confirm a landing
with `gh pr view --json state,mergeCommit`, not `git branch --merged`.

Count live lanes with
`bash .agents/skills/deliver-ready-issue/scripts/issue-lane.sh capacity`:
open implementation Pull Requests plus claim branches without one,
repository-wide. Recommend no more candidates than the remaining capacity of
the three-lane limit. Assigned or planned work is not a running lane. When
several issues are equally ready, order the report by
downstream-unblocking depth and then issue number. Call this a deterministic
presentation order, not project priority.

Parallel candidates must not depend on each other or collide on a shared
surface: `proto/`, operational persistence, the planner, execution, or catalog
versus environment state. Read each candidate's affected boundary and scope;
when two candidates name the same surface, present them as sequential, not
parallel, and report the collision for maintainer judgment.

## Apply authorized status changes

When mutation is authorized:

1. Use the existing `status:ready` and `status:blocked` labels. Do not create a
   new label taxonomy implicitly.
2. Update only issues whose computed state changed. Avoid status comments that
   add notification noise without becoming the source of truth.
3. Re-read changed issues to confirm the intended label and dependency section
   survived intact.

Readiness does not authorize assignment, implementation, closure, milestone
changes, or priority changes. Never mark an issue active merely because a lane
is available.

## Report the frontier

Return:

- trigger and mutation authority;
- newly unblocked issues;
- active issues with their claim signal (Pull Request, claim branch, fresh
  assignment) and remaining lane capacity;
- stale assignment hints awaiting the maintainer's decision;
- stale claims found on GitHub or locally, for cleanup by their owner
  (keep hostnames and absolute checkout paths in the session, never on
  GitHub);
- still-blocked issues with their unresolved dependencies;
- anomalous issues and the exact evidence needed to resolve them;
- recommended candidates in deterministic presentation order, marking which
  of them can run as parallel lanes and which must run in sequence;
- every issue mutation performed.

If nothing changed, say so without manufacturing work.

## Boundaries

- Report only unless issue mutation was explicitly authorized.
- Do not create or close issues, claim lanes, start branches, open pull
  requests, or merge.
- Do not remove worktrees, delete branches, or change assignments, even stale
  ones; report them.
- Do not assign contributors or invent priority, deadlines, or milestones.
- Do not silently repair dependency text or choose between conflicting sources.
- Do not exceed the active-lane limit when recommending simultaneous delivery.
- Never put hostnames, FQDNs, home directories, absolute worktree paths, LAN
  or employer network names, or other private environment inventory on public
  Issues, Pull Requests, comments, or commit messages. GitHub-facing lane
  text may list only claim branch, repo-relative worktree, base SHA, and
  published SHA.
