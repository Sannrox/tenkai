---
name: deliver-ready-issue
description: Deliver a dependency-ready tenkai GitHub issue through a bounded implementation workflow. Use when asked to implement, publish, or land a specific ready issue, or to take the next explicitly approved frontier item through verification and review.
---

# Deliver Ready Issue

Take one approved issue from readiness check to the highest delivery stage the
user authorized. Keep the issue as planning truth and the pull request as
implementation truth.

## Establish the authority ceiling

Infer the ceiling from the user's explicit request. When it is unclear, choose
the lower ceiling and state what remains:

- **Implement**: change the local working tree and verify it.
- **Publish**: implement, commit, push, and open a ready pull request.
- **Land**: publish, resolve review and CI, then merge and clean up.

Permission for a higher stage includes its preceding stages. It never includes
unrelated issue creation, prioritization, assignment, release publication,
force-pushing protected branches, or weakening repository protections.

## Deliver the issue

### 1. Prove readiness

1. Resolve the exact repository and issue. If the user asks for the "next"
   issue, require an explicit selection or a recommendation produced by
   `advance-issue-frontier` before starting.
2. Read repository instructions, `README.md`, `DESIGN.md`, the issue, linked
   decisions, and the live pull request and issue state.
3. Read `## Dependencies` literally. Treat an open predecessor or unresolved
   non-issue dependency as blocking; accept explicit completed-prerequisite
   evidence as delivered.
4. Search for an existing branch, pull request, worktree, or claimed
   implementation that overlaps the outcome.
5. Confirm that the issue is open, unblocked, focused enough for one pull
   request, and has testable acceptance evidence.

Stop without creating a branch when readiness, ownership, or dependencies are
ambiguous. Report the smallest action that would unblock delivery.

### 2. Isolate the work

1. Inspect the working tree and preserve every unrelated user change.
2. Start from the current default branch. Fetch or fast-forward it when safe.
3. Use an isolated worktree when the current tree is dirty or another task is
   active. Otherwise create a narrow `codex/<issue>-<slug>` branch.
4. Comment, assign, or otherwise claim the issue only when explicitly
   authorized or required by documented maintainer policy.

Never discard, overwrite, stash, or commit unrelated work merely to obtain a
clean tree.

### 3. Bound the implementation

1. Assess the issue and affected paths across product, protocol, ontology,
   persistence, execution, operations, and sekai-chisei integration boundaries.
2. Translate the issue acceptance evidence into code, tests, documentation,
   migration, configuration, compatibility, and security obligations.
3. Implement one coherent outcome. Avoid opportunistic cleanup.
4. If the issue cannot produce one reviewable pull request, stop and recommend
   a split. Do not create follow-up issues without authorization.

### 4. Verify and review

1. Add focused deterministic tests while implementing.
2. Run focused checks, then the normal repository gates before ship-level
   handoff:

   ```bash
   cargo fmt --check
   cargo test --locked
   cargo clippy --all-targets --locked -- -D warnings
   ```

3. Run `autoreview` before committing. Fix actionable findings and rerun the
   relevant checks until no material finding remains or a documented blocker
   requires maintainer judgment.
4. Inspect the final diff for scope, generated artifacts, secrets, databases,
   `.tenkai-state`, and accidental runtime state.

### 5. Publish when authorized

1. Stage only intended paths and create a narrow imperative commit.
   Never use `--no-gpg-sign`. If signing fails, stop and fix GPG.
2. Publish the topic branch with **GitHub-verified** commits via
   `scripts/gh-verified-push.sh` (GraphQL `createCommitOnBranch`), not a plain
   `git push`, unless the user explicitly asks for git-protocol push:
   - New branch:
     `scripts/gh-verified-push.sh --create-branch-from origin/main --branch <topic> --sync-local`
   - Update existing branch:
     `scripts/gh-verified-push.sh --branch <topic> --sync-local`
   - Confirm the script reports `verification.verified=true` and that the
     hosted tree matches local `HEAD`.
3. Open a ready pull request that:
   - links and closes the issue;
   - summarizes behavior rather than file operations;
   - lists verification evidence and skipped checks;
   - calls out protocol, ontology, configuration, compatibility, migration,
     sekai-chisei integration, and security impact;
   - includes an agent transcript when the repository workflow requires it.
4. Return the pull request URL. Do not publish when the ceiling is Implement.

### 6. Land when authorized

1. Wait for required CI and review. Resolve actionable feedback in the same
   branch and rerun affected checks. Re-publish review fixes with
   `scripts/gh-verified-push.sh` so the PR tip stays Verified.
2. Recheck that dependencies and repository protections still permit landing.
3. Prefer squash merge for Verified linear history on `main`:
   `gh pr merge --squash --delete-branch`.
   Use `--match-head-commit` with the published tip when available. Do not use
   GitHub rebase-merge when Verified commits matter.
4. Confirm the issue closed, the default branch contains the merge, and the
   local checkout is synchronized when safe.
5. Invoke `advance-issue-frontier` in report-only mode unless the user also
   authorized frontier status updates.

Never enable auto-merge, bypass checks, relax protection, or merge beyond the
authority ceiling.

## Report completion

Return:

- issue and authority ceiling;
- branch, commit, and pull request when created;
- implemented outcome;
- verification and review evidence;
- merge state and newly available follow-up work when applicable;
- blockers, skipped checks, and remaining uncertainty.

## Boundaries

- Deliver only the selected issue; do not choose project priority.
- Do not implement blocked work or infer that silence grants ownership.
- Keep secrets, credentials, logs, databases, and runtime state out of Git.
- Do not substitute a successful build for issue acceptance evidence.
- Do not close an issue manually when the implementation has not landed.
