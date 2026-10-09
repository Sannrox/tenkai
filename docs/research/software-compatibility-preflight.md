# Software compatibility preflight

Research for issue #534. The design conclusion is to declare compatibility in
signed release content and evaluate it against current, environment-scoped
observations before execution.

## Evidence-backed design

- Releases declare dependencies, provided contracts, schema bounds, and
  incompatibilities. Operators do not maintain separate upgrade scripts.
- Compatibility is checked in both directions: the proposed release must fit
  retained components, and retained components must fit the proposed final set.
- Planning evidence is temporary authorization. Changed, stale, ambiguous,
  future-dated, or digest-mismatched observations require a fresh evaluation.
- Compatibility is separate from health and readiness. A newer version is not
  automatically compatible.
- Catalog declarations and observed environment state jointly determine plan
  eligibility.
- Blocked plans return deterministic typed reasons without private payloads.

## Tenkai contract

- Include the complete versioned profile in the signed release content digest.
- Represent required and provided contracts explicitly; reject duplicate or
  contradictory declarations at publish time. For same-major minor compatibility,
  require the declared major and at least the requested minor. Exact matching
  is an explicit rule; compatibility is not inferred across major versions.
- Record component identities and immutable revision or artifact digests. Bind
  observations to the exact release content digest, environment, and evaluation
  time. Sort final-set report entries deterministically and expose the same
  application contract through embedded and remote hosts.
- Compare requirements with scoped observations and require compatible schema
  and migration state without executing migrations during preflight.
- Reuse the evaluator for planning, apply, rollback, restart, and recovery.
- Keep specialized compatibility checks active; the generic profile cannot
  bypass stricter product rules.
- Fail closed when required evidence is absent or unverifiable. Any emergency
  bypass requires separate authorization and durable audit evidence.

The research establishes declaration-based constraints, observed-state planning,
schema metadata, and health separation. It does not define Tenkai's signature,
digest, freshness, or migration-state contracts; those remain Tenkai-owned.
