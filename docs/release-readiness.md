# Release readiness checklist

Use this checklist before tagging a Tenkai release. It does **not** invent a
version number; the maintainer chooses the target version. Pair with the
project-local `prepare-release` skill for notes and evidence assembly.

## 1. Scope

- [ ] Target version and base tag/commit identified
- [ ] Merged PR / closed issue range listed
- [ ] User-visible changes classified: Added / Changed / Fixed / Security / Migration

## 2. Versions and contracts

Confirm compatibility for any public or host-facing contract touched by the range:

| Surface | Where | Check |
| --- | --- | --- |
| Crate version | `Cargo.toml` / `Cargo.lock` | Bump consistent with SemVer policy |
| SQLite schema | `src/storage.rs` `SCHEMA_VERSION` | Migration tested; newer DBs still fail closed |
| Runtime protocol | `docs/runtime-protocol-v1.md`, `proto/tenkai/runtime/v1/` | Wire compatibility or explicit break |
| Auth context | `AUTH_CONTEXT_CONTRACT_VERSION` | Extension hosts pin correctly |
| Runtime capabilities | `RUNTIME_CAPABILITY_CONTRACT_VERSION` | Capability matrix still accurate |
| Federated identity | `FEDERATED_IDENTITY_CONTRACT_VERSION` | Issuer/audience rules unchanged or versioned |
| Provider contracts | `PROVIDER_CONTRACT_VERSION` | Binding/digest rules intact |
| Model runtime | `MODEL_RUNTIME_CONTRACT_VERSION` | Descriptor validation still fail-closed |
| Plan format | `PLAN_FORMAT_VERSION` | Old plans decode or fail visibly |

## 3. Security and trust

- [ ] Signing / plan-approval defaults still fail closed without development flags
- [ ] Development bypasses remain explicit and audited
- [ ] No secrets in examples, fixtures, or release artifacts
- [ ] Management vs runtime credentials remain distinct
- [ ] Tenant mode / enterprise flags still default off for community SQLite

## 4. Operator surfaces

- [ ] CLI help and README cover new commands/flags
- [ ] Server flags (capability requirements, auth) documented
- [ ] Examples still parse (`examples/**/tenkai.toml`)
- [ ] Backup/restore notes still accurate if storage changed

## 5. Validation gates

Run (or confirm CI ran) at the release commit:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --all-targets --locked
```

- [ ] Local or CI: fmt
- [ ] Local or CI: tests
- [ ] Local or CI: clippy `-D warnings`
- [ ] GitHub required checks green on the release branch/tag commit

## 6. Artifacts

- [ ] `tenkaictl`, `tenkai-server`, runtime/guard binaries build
- [ ] Optional container/bundle packaging (if any) version-aligned
- [ ] No `.tenkai-state/`, SQLite DBs, or credentials in the tree

## 7. Upgrade / rollback notes

- [ ] Migration steps for operators (if schema or flags changed)
- [ ] Explicit “not in backup” items still true (payloads, weight caches)
- [ ] Rollback: previous binary + restore DB procedure stated when needed

## 8. Go / no-go

Release is **go** only when:

1. Required checks pass  
2. No known release-blocking issue remains open for this version  
3. Upgrade and security implications are written in the release notes draft  

Then use `prepare-release` to assemble notes; tag/publish only with explicit
maintainer authorization.
