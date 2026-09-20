# Repository Guidelines

## Project Structure & Ownership

`tenkai` is a Rust 2024 local-first, constraint-based delivery control plane.
It is the operational owner of releases, channels, environments, plans,
execution, rollback, and recovery. `sekai-chisei` is an optional provider for
graph projection, governance, evaluation, and learning; Tenkai must remain
operable and recoverable without it unless an operation's policy explicitly
requires provider evidence.

Source code lives in `src/`. `src/lib.rs` exports the application core.
Shipped binaries are `tenkaictl` (embedded and remote CLI), `tenkai-server`
(network service), `tenkai-executor-guard` (local process fencing),
`tenkai-runtime` and `tenkai-runtime-guard` (pull-only environment runtime),
and `tenkai-worker-lifecycle-fixture` (live worker-lifecycle observation host).
The Postgres delivery-effect harness is an autodiscovered `src/bin/` target
behind feature `postgres`, not a packaged product binary; see
[delivery-effect conformance](docs/delivery-effect-conformance.md). Keep domain
logic in the library and treat CLI, HTTP, gRPC, SQLite, and provider clients as
adapters around shared application contracts. Protocol definitions live in
`proto/`, documentation in `docs/`, examples in `examples/`, and operational
scripts in `scripts/`. The Rust toolchain is pinned at 1.96.1.

Read `README.md`, `DESIGN.md`, and
`docs/decisions/0001-standalone-core-and-service-evolution.md` before changing
system boundaries or ownership. GitHub Issues are the planning source of truth.
Project-specific Skills under `.agents/skills/` are the workflow inventory
(shaping, delivering, verifying, assessing, documenting, releasing, operating,
and advancing the issue frontier).

## Build, Test, and Development Commands

- `cargo fmt --check` verifies Rust formatting.
- `cargo test --locked` runs the unit and integration test suite.
- `cargo build --all-targets --locked` verifies all binaries and test targets compile.
- `cargo clippy --all-targets --all-features --locked -- -D warnings` runs
  strict linting when Clippy is available (matches `make validate`).
- `make test` runs the default test suite.
- `make validate` runs every `scripts/validate-*.sh` (format, clippy, shell,
  diff, make dry-run, workflow-skill parity, rust filenames, secrets, and
  issue-lane capacity).
- `make test-integration` runs all checked-in integration-test targets.
- `make update` formats Rust and refreshes build-generated protobuf bindings
  without changing the locked dependency graph.

The Makefile is a thin façade over `scripts/make-targets/`. Validation and
update fan out over sorted `scripts/validate-*.sh` and `scripts/update-*.sh`
files. `WHAT=<one test filter> make test` and the equivalent integration target
run one explicit Cargo test filter without shell evaluation.
- `cargo run --bin tenkaictl -- init` initializes embedded local state.
- `cargo run --bin tenkaictl -- inspect` inspects embedded state without
  starting the server.
- `cargo run --bin tenkaictl -- reconcile --once` performs one deterministic
  reconciliation tick.
- `cargo run --bin tenkai-server -- --database .tenkai-state/tenkai.db` starts
  the loopback development server when the required tokens are configured.

Use the quickstart in `README.md` for an end-to-end local deployment. Never
weaken signing, approval, authentication, or provider requirements merely to
make a development command pass; use the documented development-only flags and
recorded reasons.

The repository does not install or require Codex hooks. Run the four Make
targets explicitly; external-provider tests remain opt-in and must be invoked
with their documented prerequisites.

## Architecture and Integration Policy

Preserve the embedded/server equivalence: both hosts use the same application
core, transaction boundaries, recovery semantics, and versioned contracts.
Transport is not a domain boundary. Keep the Catalog as an application port
until the extraction criteria in ADR 0001 are met.

Treat these boundaries as authoritative:

- Tenkai owns operational persistence and recovery state.
- `sekai-chisei` projections are derived, retryable integrations, not recovery
  material.
- Optional provider failures remain visible and durably retryable.
- If policy or an approved plan requires provider evidence, the affected
  operation fails closed when evidence is absent, stale, invalid, or
  unavailable.
- Signed releases, executable plans, approval evidence, fencing generations,
  and environment scope must remain content-bound and versioned.
- Remote and embedded modes must not acquire implicit development permissions.
- Compatibility changes to vendored Sekai or Chisei protocols require explicit
  versioning, migration, and failure semantics.

For provider work, read `docs/provider-contracts.md`. For transport work, read
`docs/runtime-protocol-v1.md`. For signing or approval work, read
`docs/release-signing.md` and `docs/plan-approval.md`. For persistence changes,
read `docs/operational-storage.md`.

## Ontology Policy

For portable ontology definitions, classes, relations, provenance, validation,
import, export, or structural queries, always use the project-local
`sekai-ontology` Skill in `.agents/skills/sekai-ontology/`.

Select the ontology database explicitly with `--db <path>` or `SEKAI_DB`, then
run `sekai --db <path> --json validate` before relying on its contents. Treat
successful ontology output as structured repository evidence, preserve its
provenance in answers, and state when validation fails or the requested fact
is absent rather than inferring it. Do not use Tenkai's operational SQLite
database as a portable ontology database.

## Agent boundaries

- **Always** work in a claimed delivery lane (one Issue, one branch, one
  worktree, one Pull Request). Run the documented Make and Cargo commands.
  Treat GitHub Issues as planning truth.
- **Ask first** before claiming an Issue whose assignment is older than six
  hours with neither branch nor Pull Request, before taking over another
  lane, and before rewriting protected `main`.
- **Never** commit secrets, bearer tokens, signing keys, provider credentials,
  or `.tenkai-state/`. Never put hostnames, home paths, or other private
  environment inventory on public Issues or Pull Requests. Never split one
  Issue across lanes or carry a second Issue in one lane.

## Coding Style & Naming

Follow standard Rust formatting (`scripts/validate-format.sh`). Use
`snake_case` for files (`scripts/validate-rust-filenames.sh`; hyphens only in
`src/bin/`), modules, functions, and variables; `PascalCase` for types and
traits; and `SCREAMING_SNAKE_CASE` for constants. Prefer explicit domain types and
validated state transitions over loosely structured strings or hidden side
effects. Keep provider-specific behavior behind application ports and keep
protocol conversion at adapter boundaries.

Errors that affect trust, authorization, consistency, fencing, or recovery
must be explicit and actionable. Do not silently downgrade, skip, or reinterpret
invalid evidence. Preserve backward compatibility deliberately; migrations
must retain the original semantics and evidence version.

## Testing Guidelines

Add focused deterministic tests for changes touching planning, reconciliation,
leases, process fencing, persistence, migrations, signing, approvals,
authorization, provider behavior, rollback, or protocol compatibility. Test
failure and recovery paths, not only success paths. Avoid external-service
dependencies in the normal suite; isolate and document service-dependent tests.

Verification should be proportional to the change. At minimum, format and run
the narrowest relevant tests. Before delivery, prefer the project-local
`verify-change` Skill to select and report the appropriate broader checks.
Before commit or PR, run `make validate` and `autoreview` and fix actionable findings (see
`deliver-ready-issue`).

## Commit & Pull Request Guidelines

Recent history uses short imperative subjects, often Conventional Commit
style: `fix(reconciler): preserve fencing generation`,
`feat(catalog): reject changed immutable releases`,
`docs: clarify provider failure semantics`, and
`chore: update vendored protocols`. Keep commits narrow and describe the
affected subsystem when useful. Pull requests should contain a concise behavior
summary, tests run, linked issue or decision context, and any protocol,
persistence, migration, configuration, operational, or security implications.

Do not combine architectural boundary changes with unrelated cleanup. Capture
accepted architectural or project outcomes with the project-local
`capture-project-decision` Skill. Use `assess-change-impact` for changes that
cross product, trust, protocol, ontology, execution, or operational boundaries.
Do not put hostnames, FQDNs, home directories, absolute worktree paths, LAN
or employer network names, or other private environment inventory on public
Issues, Pull Requests, comments, or commit messages.

### Verified commits on GitHub

Prefer publishing PR branch tips with GitHub-signed commits so GitHub shows
**Verified**:

1. Implement and commit locally as usual (`commit.gpgsign` may still apply).
2. Publish the branch tip with `scripts/gh-verified-push.sh` instead of a plain
   `git push` when you want the hosted commit Verified (OpenClaw-style GraphQL
   `createCommitOnBranch`). That path creates one server-side commit with the
   local `HEAD` tree; committer is typically **GitHub**.
3. New branch:
   `scripts/gh-verified-push.sh --create-branch-from origin/main --branch <topic> --sync-local`
4. Existing PR branch:
   `scripts/gh-verified-push.sh --branch <topic> --sync-local`
   (uses the current remote tip as `expectedHeadOid`).
5. Never pass `--no-gpg-sign` for local commits; if GPG fails, stop and fix it.
6. After publish, confirm `verification.verified=true` (the script prints this).

When merging PRs, prefer **squash** (`gh pr merge --squash --delete-branch`) so
the land commit on `main` is also GitHub-signed/Verified and history stays
linear. Use `gh pr merge --merge` only when multi-commit history must be kept
(original SHAs preserved). Avoid GitHub **rebase** merges when Verified history
matters: rebase-merge rewrites commits and drops signatures. Do not rewrite
protected `main` after merging unless the user explicitly approves; if
protection is temporarily relaxed, restore force-push and status-check settings
immediately after the correction.

## Parallel delivery lanes

A delivery lane is one Issue, one branch, one isolated checkout, one Pull
Request, and one owner. Several agents may deliver several Issues at the same
time, on one machine or on many, only as separate lanes. One Issue is never
split across lanes, and one lane never carries a second Issue.

### Claims live on GitHub

Machines cannot see each other's worktrees, so a claim is only what GitHub
shows. An Issue is claimed, and therefore active, when any of the following
exists:

1. an open Pull Request, draft or ready, that references the Issue;
2. a branch `<type>/<issue>`, or any branch matching `*/<issue>-*`;
3. the authenticated login assigned to the Issue less than six hours ago.

An assignment older than six hours with neither branch nor Pull Request is an
ownership hint, not a veto: report it and ask the maintainer before claiming.
A claim is stale once its Issue is closed or its Pull Request has merged; its
owner or the maintainer removes it. Any other takeover first preserves the
existing branch, Pull Request, and evidence and requires the maintainer's
confirmation, unless the lead of the same parallel run owns the stalled lane.

A lane claims before it implements, under Publish or Land authority or with an
explicit claim authorization under Implement, using
`bash .agents/skills/deliver-ready-issue/scripts/issue-lane.sh claim <issue>`:

- the branch `<type>/<issue>` is created on GitHub from the default branch by
  an atomic ref creation, so when two machines race exactly one claim
  succeeds and the other sees `claimed`;
- the authenticated login is assigned to the Issue, which shows the claim in
  the Issue list and timestamps it in the Issue timeline.

`<type>` is derived deterministically so that every machine computes the same
branch: the Conventional Commit type in the Issue title, with `bug` mapped to
`fix`; otherwise the type label (`bug` → `fix`, `enhancement` → `feat`,
`documentation` → `docs`); otherwise `chore`. Lane branches carry no slug
because the name is the claim; the Pull Request title carries the description.
Human topic branches may keep `<type>/<issue>-<slug>`. A claim is any branch
matching `*/<issue>` or `*/<issue>-*`, including legacy `codex/<issue>` and
`codex/<issue>-<slug>`.

An Implement-only lane cannot claim and is invisible to other machines. Say so
in the report, or ask for claim authority before starting.

### Isolation on each machine

Local isolation protects lanes that share a machine; it is not a claim.

- Each lane checks out its claim branch in `.worktrees/issue-<issue>` inside
  the repository, ignored by Git. A fresh clone dedicated to the lane, as on a
  cloud agent, is equivalent. The base SHA is recorded in the lane report.
- The primary checkout belongs to the maintainer. Agents never switch its
  branch, reset it, stash it, or run long jobs in it while another lane is
  active.
- A worktree serves exactly one Issue. Finished lanes are removed; a worktree is
  never reused for a different Issue or renamed to hide its origin.
- Shared Git state is mutated in short, serialized slots: `git fetch --prune`,
  worktree creation and removal, local branch deletion, and merging belong to
  the lead of a parallel run or happen one lane at a time on a shared machine.
  A lane commits and publishes its own branch from its own worktree; that is
  not a shared mutation. Nobody holds a slot across implementation, test runs,
  or a remote wait.

### Limits, collisions, and landing

The three-lane limit counts claims visible on GitHub per repository: open
implementation Pull Requests plus claim branches without one. Assigned or
planned work with neither is not a running lane.
`bash .agents/skills/deliver-ready-issue/scripts/issue-lane.sh capacity`
prints the count; `claim` refuses when remaining capacity is zero.
`check` inspects one Issue; `release` removes a finished claim.

Parallel lanes must not collide. Collision surfaces in this repository are
`proto/`, operational persistence, the planner, execution, and catalog versus
environment state. Lanes that would both change one of these surfaces run in
sequence, not in parallel.

A lane publishes its first Verified commit to the claim branch as a draft Pull
Request that closes the Issue and may list public lane fields only: claim
branch, repo-relative worktree (for example `.worktrees/issue-N`, never an
absolute path), base SHA, published SHA, and authority ceiling. Never hostname,
FQDN, home path, absolute worktree path, LAN or employer network name, or other
environment inventory. Keep absolute paths and machine or host names in the
private agent session only. It marks the Pull Request ready when verification
and review are complete. Immediately before publishing, the lane fetches and
confirms that the default branch is an ancestor of its head; it refreshes onto
`main` only for a conflict, a failing gate, an explicit request, or a sibling
landing on a shared surface, not merely because `main` advanced. Publish the
existing claim branch with
`scripts/gh-verified-push.sh --branch <type>/<issue> --sync-local`.

Landing is sequential. After each merge, fetch, recompute the frontier, and let
the remaining lanes recheck `mergeable` against the new `main`. A failed or
timed-out merge response may still have merged; reconcile the remote state
before retrying.

The lead of a parallel run keeps a ledger per lane: Issue, branch, base SHA,
owner, state, Pull Request, evidence, blockers, and cleanup. Report verified
outcomes, not launched work. Keep hostnames and absolute checkout paths in the
session with the maintainer, never on GitHub. The executable lead procedure is
`.agents/skills/deliver-ready-issue/references/parallel-delivery.md`.

## Security & Configuration

Never commit secrets, bearer tokens, signing keys, provider credentials, local
SQLite databases, `.tenkai-state/`, deployment payloads, or generated runtime
state. Path and diff denylists are `scripts/validate-secrets.sh`. Bind plaintext development servers to loopback and put authenticated TLS
termination in front of remote deployments. Environment runtime credentials
must be scoped to exactly one environment, and management credentials must not
be passed on command lines.

Treat break-glass actions as separately authorized, reasoned, and auditable.
Never make rollback or recovery depend on `sekai-chisei` availability.
Never put hostnames, FQDNs, home directories, absolute worktree paths, LAN
or employer network names, or other private environment inventory on public
Issues, Pull Requests, comments, or commit messages.
