---
name: advance-issue-frontier
description: Advance the tenkai GitHub issue frontier after work merges or when asked what is ready next. Use to evaluate dependency-linked open issues, update blocked or ready status, enforce active-lane limits, and recommend the next deliverable without implementing it.
---

# Advance Issue Frontier

Compute the delivery frontier from live GitHub state. A frontier issue is open,
has no unresolved dependency, and has no implementation already in flight.

## Establish authority and scope

Default to **report-only**. Modify issue state only when the user explicitly
asks to update or advance the frontier.

Resolve:

- the repository and relevant issue set;
- whether a merge, closure, or full backlog review triggered the run;
- the active-lane limit, defaulting to three and accepting a documented limit
  of two or three;
- the permitted mutation: none, labels, or a documented body fallback.

Read `README.md`, `DESIGN.md`, repository instructions, and live issues and pull
requests. Do not rely on a stale local backlog export.

## Build the dependency graph

1. Fetch open backlog issues and implementation pull requests. Include recently
   closed predecessors needed to evaluate dependencies.
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
- **ready**: every dependency is delivered and no implementation is in flight;
- **active**: an implementation pull request, branch, worktree, or explicit
  ownership record identifies ongoing work;
- **anomalous**: the dependency graph cannot be evaluated safely.

Count active issues before recommending more work. Recommend no more candidates
than the remaining active-lane capacity. When several issues are equally ready,
order the report by downstream-unblocking depth and then issue number. Call this
a deterministic presentation order, not project priority.

Parallel candidates must not depend on each other or visibly collide on the
same protocol, ontology, persistence, planner, execution, or ownership boundary.
Report possible collisions for maintainer judgment.

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
- active issues and remaining lane capacity;
- still-blocked issues with their unresolved dependencies;
- anomalous issues and the exact evidence needed to resolve them;
- recommended candidates in deterministic presentation order;
- every issue mutation performed.

If nothing changed, say so without manufacturing work.

## Boundaries

- Report only unless issue mutation was explicitly authorized.
- Do not create or close issues, start branches, open pull requests, or merge.
- Do not assign contributors or invent priority, deadlines, or milestones.
- Do not silently repair dependency text or choose between conflicting sources.
- Do not exceed the active-lane limit when recommending simultaneous delivery.
