# Repository Guidelines

## Project Structure & Ownership

`tenkai` is a Rust 2024 local-first, constraint-based delivery control plane.
It is the operational owner of releases, channels, environments, plans,
execution, rollback, and recovery. `sekai-chisei` is an optional provider for
graph projection, governance, evaluation, and learning; Tenkai must remain
operable and recoverable without it unless an operation's policy explicitly
requires provider evidence.

Source code lives in `src/`. `src/lib.rs` exports the application core;
`src/bin/tenkaictl.rs` hosts the embedded and remote CLI;
`src/bin/tenkai-server.rs` hosts the network service; and
`src/bin/tenkai-executor-guard.rs` enforces local process fencing. Keep domain
logic in the library and treat CLI, HTTP, gRPC, SQLite, and provider clients as
adapters around shared application contracts. Protocol definitions live in
`proto/`, documentation in `docs/`, examples in `examples/`, and operational
scripts in `scripts/`.

Read `README.md`, `DESIGN.md`, and
`docs/decisions/0001-standalone-core-and-service-evolution.md` before changing
system boundaries or ownership. GitHub Issues are the planning source of truth.
Project-specific Skills under `.agents/skills/` define the expected workflows
for shaping, delivering, verifying, assessing, documenting, and releasing work.

## Build, Test, and Development Commands

- `cargo fmt --check` verifies Rust formatting.
- `cargo test` runs the unit and integration test suite.
- `cargo build --all-targets` verifies all binaries and test targets compile.
- `cargo clippy --all-targets --all-features -- -D warnings` runs strict
  linting when Clippy is available.
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

## Coding Style & Naming

Follow standard Rust formatting. Use `snake_case` for files, modules,
functions, and variables; `PascalCase` for types and traits; and
`SCREAMING_SNAKE_CASE` for constants. Prefer explicit domain types and
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

## Security & Configuration

Never commit secrets, bearer tokens, signing keys, provider credentials, local
SQLite databases, `.tenkai-state/`, deployment payloads, or generated runtime
state. Bind plaintext development servers to loopback and put authenticated TLS
termination in front of remote deployments. Environment runtime credentials
must be scoped to exactly one environment, and management credentials must not
be passed on command lines.

Treat break-glass actions as separately authorized, reasoned, and auditable.
Never make rollback or recovery depend on `sekai-chisei` availability.
