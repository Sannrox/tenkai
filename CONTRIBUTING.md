# Contributing

Use the four repository Make targets from a clone:

```bash
make test
make validate
make test-integration
make update
```

`WHAT=<one test filter> make test` (and the same for `make test-integration`)
runs one Cargo filter without shell evaluation. The default suite is
`cargo test --locked`. Live Kubernetes, Llama, and PostgreSQL checks stay
opt-in and documented.

## Issues and pull requests

GitHub Issues are the planning source of truth. Shape new work with the
`shape-work-item` Skill when you need a repository-consistent body
(problem, observable outcome, acceptance evidence, non-goals, dependencies,
impact).

One Issue is one delivery lane: one claim branch, one isolated checkout, one
Pull Request. Agent and parallel-lane policy lives in [AGENTS.md](AGENTS.md).

Pull requests should include a concise behavior summary, tests run, the
linked Issue, and any protocol, persistence, migration, configuration,
operational, or security implications.

## Review gates

Before review, run `make validate` and the focused tests for the change.
`make validate` runs every `scripts/validate-*.sh`. Clippy matches
`cargo clippy --all-targets --all-features --locked -- -D warnings`.
