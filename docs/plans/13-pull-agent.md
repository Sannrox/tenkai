# Plan 13 — Pull-based environment agent

**Task:** Execute approved plans through a scoped agent that pulls work for one
environment.

**Depends on:** Plans 01, 02, 09, and 12.

## Scope

- Add a `tenkai-agent` binary configured for exactly one environment identity.
- Pull eligible plan work; do not accept pushed execution requests.
- Verify plan approval, report observations and per-step outcomes, and send
  heartbeats.
- Enforce lease/idempotency semantics for reconnects and duplicate delivery.
- Keep scoped credentials outside plan payloads and logs.

## Acceptance criteria

- An agent can only fetch plans for its configured environment.
- Duplicate delivery cannot execute a completed step twice.
- Disconnect and restart preserve a deterministic plan lifecycle.
- The planner cannot mark success without an agent execution receipt.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
