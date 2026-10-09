# Completion-gated Docker initialization jobs

Research for issue #531. The design conclusion is to make initialization
explicit, bounded, and product-owned while Tenkai owns ordering, completion
state, evidence, and cleanup.

## Evidence-backed design

- Deployment hooks and startup dependencies distinguish resource readiness from
  bounded work that must complete before dependents start.
- Docker dependencies distinguish started, healthy, and completed-successfully.
  A running process with exit code zero is not completion evidence; require a
  terminal exited state and zero exit code.
- Retain exited job containers until explicit cleanup so completion evidence can
  be inspected. Preserve named volumes during container removal.
- Runtime restart policies must not independently replay one-shot side effects.
- Public behavior does not establish exactly-once execution, retry
  deduplication, or reversal of database effects. Tenkai therefore documents
  replay policy explicitly and leaves application side effects product-owned.

## Tenkai contract

- One-shot jobs have a bounded timeout and explicit dependency conditions.
- Matching successful jobs are reused by observe, reconcile, and restart.
- Failed or timed-out jobs block dependents; explicit retry may run them again.
- New releases and rollback targets may replay jobs when completion evidence is
  absent. Rollback restores software, not database contents.
- Remove managed jobs and services in reverse dependency order, preserve named
  volumes, and keep raw logs out of receipts.
