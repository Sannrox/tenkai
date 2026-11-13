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
`cargo test --locked --workspace`. Live Kubernetes, Llama, and PostgreSQL checks stay
opt-in for `make test` and are documented; CI additionally runs the kind
in-process Kubernetes test on pull requests, pushes to `main`, and weekly.

## Issues and pull requests

GitHub Issues are the planning source of truth. Shape new work with the
`shape-work-item` Skill when you need a repository-consistent body
(tenant or operator problem, observable outcome, acceptance evidence, primary
area, boundaries and dependencies, compatibility and risk).

One Issue is one delivery lane: one claim branch, one isolated checkout, one
Pull Request. Agent and parallel-lane policy lives in [AGENTS.md](AGENTS.md).

Pull requests should include a concise behavior summary, tests run, the
linked Issue, and any protocol, persistence, migration, configuration,
operational, or security implications. Do not edit `CHANGELOG.md`; the
release step drafts it ([RELEASING.md](RELEASING.md)).

When callers must act, mark the title `type!:` or add a `## Breaking` or
`## Upgrade` section, and add the `risk:breaking` label. The CI `Semver` job
runs `cargo-semver-checks` on the library crates against the pull request
base; a reported major break passes only with that marker and label.

## Review gates

Before review, run `make validate` and the focused tests for the change.
`make validate` runs every `scripts/validate-*.sh`. Clippy matches
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`.
The CI `Proto breaking` job runs `buf breaking` (rules in `proto/buf.yaml`)
against the last final `v*` tag. A reported break passes only when the pull
request title is `type!:` or its body has a `## Breaking` or `## Upgrade`
section, and the pull request carries the `risk:breaking` label.
