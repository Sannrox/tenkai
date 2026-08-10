# Staged document product-kind consolidation research

Issue: [#188](https://github.com/Sannrox/tenkai/issues/188)

Date: 2026-07-29

Conclusion: **keep separate**

## Question and method

This research tests whether `policy_bundle`, `eval_suite`, and
`agent_definition` should become one public, versioned document-artifact kind.
It audits the authoritative manifest, validation, execution, persistence, and
operator paths on `main` at `2d0fdd3`, and exercises the representative
fixtures already used by the staged-product end-to-end test.

No tracked portable ontology database is available in this delivery worktree.
An untracked database in another local checkout is not reproducible repository
evidence and is not published with this research. Ontology therefore supplies
no evidence for or against consolidation; the tracked sources below are
authoritative for this comparison.

## Comparison

| Concern | Shared behavior | Semantic difference and source |
| --- | --- | --- |
| Content identity | The raw manifest and every declared document are included in immutable release digests. | Each manifest retains a distinct `ProductKind`, section name, and document schema (`src/manifest.rs`). |
| Manifest fields | Each kind declares one safe relative JSON document and forbids shell, routing, and model-runtime sections. | The public sections are `[policy]`, `[eval_suite_product]`, and `[agent]`; mixed sections fail closed (`src/manifest.rs`). |
| Schema validation | JSON decoding denies unknown fields; validation occurs before publication or mutation. | Policy validates unique policy IDs, identifier-shaped actions, and allow/deny effects; eval validates a suite identifier and unique cases; agent validates identity, runtime, and a traversal-free entrypoint (`src/staged_artifact.rs`). |
| Planning | All three use ordinary immutable releases, channels, subscriptions, and plan steps. | The planner does not assign different ordering or constraint behavior to these three kinds (`src/plan.rs`). |
| Execution and staging | All use `LocalStagedArtifactExecutor`, atomic rename, post-write digest observation, and the same fencing/integrity checks. | Apply selects a schema-specific decoder before passing serialized JSON to the shared executor; state directories retain the kind name (`src/apply.rs`, `src/staged_artifact.rs`). |
| Health and gates | None runs a shell health probe. All may carry the ordinary independent `[gate].eval_suite` gate. | An `eval_suite` product stages a versioned suite contract; it does not itself execute the gate. Gate lookup remains provider-owned (`src/apply.rs`, `docs/staged-products.md`). |
| Rollback and recovery | All remove or restore the atomically staged prior document through the normal plan lifecycle. Failed pre-mutation validation needs no shell cleanup. | Recovery paths differ only by kind-specific state directory and schema decoder (`src/apply.rs`, `src/staged_artifact.rs`). |
| Persistence | Catalog persistence stores the original raw manifest and content-bound properties; plans pin the release. | The distinct kind remains embedded in the immutable manifest. Reinterpreting it would change signed content semantics (`src/catalog.rs`, `src/storage.rs`). |
| Operator inspection | The same publish, promote, subscribe, plan, apply, status, and release-inspect commands apply. | Kind and section names tell operators and downstream consumers which schema and purpose they are handling (`docs/staged-products.md`). |

The lifecycle is shared; the schema identity and external meaning are not.
`policy_bundle` is authorization input, `eval_suite` is evaluation input, and
`agent_definition` is an execution descriptor. Tenkai stages all three but does
not assume the corresponding external consumer's authority.

## Prototype

The smallest shared contract tested was an internal descriptor with four
operations:

```rust
struct StagedSchema {
    kind: ProductKind,
    document_path: fn(&Manifest) -> Result<&str>,
    validate_json: fn(&[u8]) -> Result<serde_json::Value>,
    state_namespace: &'static str,
}
```

Three registry entries delegate to the existing typed validators. The
representative policy, suite, and agent fixtures all pass through the same
prototype path, while an empty policy list, duplicate eval case, and traversing
agent entrypoint still fail validation. The research-only artifact is
`tests/staged_document_contract_prototype.rs` and is reproducible with:

```bash
cargo test --locked --test staged_document_contract_prototype
```

The prototype reduced dispatch repetition but could not remove the three typed
schemas, validators, stable kind names, or compatibility semantics. It was
kept only as a regression-checkable research artifact; no production or
persisted-state change is part of this research.

## Complexity accounting

Current directly relevant public and implementation surface:

- 3 public `ProductKind` variants.
- 3 public manifest sections and section structs.
- 3 typed JSON documents and validators.
- 3 decoder functions.
- 3 schema-specific apply dispatch arms.
- 1 shared staging executor, removal path, and observation mechanism.
- 1 combined end-to-end lifecycle test, focused schema tests, and 1
  research-only registry prototype test.
- 1 combined operator documentation path.

A new generic public kind would initially produce:

- 4 public variants, not 1, because existing signed manifests and persisted
  releases cannot be reinterpreted or removed immediately.
- 4 manifest representations during migration: three legacy sections plus a
  generic section containing a required schema identifier and version.
- The same 3 validators, plus a registry and unknown-schema/version failure
  handling.
- At least 2 compatibility directions: legacy-to-runtime normalization and
  generic-version decoding.
- No executor, planning, rollback, recovery, or documentation lifecycle retired;
  those paths are already shared.

Only after a breaking compatibility window could consolidation retire two kind
variants, two manifest section shapes, and two outer dispatch branches. It
would still retain three schema implementations and would add registry,
migration, inspection, and debugging concepts. The measurable near-term result
is therefore negative.

## Migration implications

Existing manifests, signatures, release digests, stored raw manifests, plans,
and staged state paths must retain their original interpretation forever.
A viable consolidation would require:

1. a new manifest-contract version and an explicit schema identifier;
2. decoding legacy kinds without rewriting their raw manifests;
3. preserving kind-specific state namespaces or an idempotent, reversible state
   migration;
4. inspection that reports both original and normalized identities;
5. compatibility fixtures for every legacy kind and schema version; and
6. an accepted design decision before any public change.

That migration moves complexity into a schema registry and compatibility layer
without reducing the current operational lifecycle.

## Recommendation

Keep the three public kinds separate. Their distinct names are cheap,
content-bound schema identities and useful operator signals, while their
Tenkai-owned lifecycle is already consolidated.

If future implementation work touches this dispatch, it may standardize the
private mapping from kind to document path, decoder, and state namespace. That
internal refactor should preserve typed validators, public manifests, stored
release interpretation, and fail-closed unknown-version behavior. It does not
require a public Design Discussion because this research does not recommend
public consolidation.

**Follow-up (implemented):** `src/staged_artifact.rs` now owns that private
kind→schema mapping behind `is_staged_kind` / `activate` / `deactivate` /
`validate_document_bytes`. Public kinds and stored release interpretation are
unchanged.
