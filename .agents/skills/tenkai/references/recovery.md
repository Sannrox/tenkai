# Recovery

## Unknown mutation outcome

For an unknown `publish`, inspect the immutable release. For an unknown
`promote`, inspect the channel and environment desired state. For an unknown
`apply` or `rollback`, inspect the plan lifecycle, environment deployment
observations, and lease/fencing state before any retry.

Retry only when Tenkai's recorded state and command retry guidance make the
next action safe.

## Unknown deployment state

When failed cleanup leaves the external target unknown:

1. Quiesce automation for the affected environment.
2. Inspect Tenkai's environment, latest plan, and lease/fencing state.
3. Independently inspect and repair the live deployment target.
4. Record the verified observation:

   ```sh
   tenkaictl env reconcile <environment> <product> --deployed <version>
   ```

   Omit `--deployed` only after verifying that cleanup left no deployed
   version.
5. Re-inspect the environment, create a fresh plan, and resume normal delivery.

`env reconcile` records an observation of the already-verified target.

## After an automatic rollback

A failed health probe rolls back to the previous release and ends the plan
`failed`. Until the planner keeps a failed-target marker, the next reconcile
tick computes a new plan for the same failed release, and non-local
environments report `awaiting_approval` for it. Do not approve that plan.
Recall the release (`release recall`) or promote a fixed version, then plan
again.

Derive deploy outcomes from the plan's terminal state plus the subscription's
`deployed` and `health` in `env inspect`, not from `latest_plan` alone: a
re-plan replaces `latest_plan` right after a rollback. There is no outbound
deploy-outcome notification yet; poll `env inspect` or `fleet watch`.

## Leases and fences

An expired generation-fenced lease is taken over through normal reconciliation.

For a legacy object-only lease, first stop the old controller and every child
process, verify no apply is running, then use:

```sh
tenkaictl env unlock <environment>
```

Unlock only after that verification.

## Backup

Create a consistent embedded backup through Tenkai:

```sh
tenkaictl --database /path/to/tenkai.db \
  backup /secure/backups/tenkai.db
```

Treat backups as sensitive operational data. They include Catalog descriptors,
environments, plans, leases, receipts, audit, and provider outbox records. They
exclude artifact payloads, runtime directories, caches, and plaintext remote
credentials.

## Restore

Restore only with explicit authorization because it replaces operational
state:

1. Resolve the exact destination database and backup.
2. Stop every CLI loop, server, and other writer using the destination.
3. Preserve the current database through a Tenkai backup when practical.
4. Run:

   ```sh
   tenkaictl --database /path/to/tenkai.db \
     restore /secure/backups/tenkai.db
   ```

5. Verify with `env list`, `inspect`, and affected `env inspect` commands.
6. Re-inject remote credentials from the secret store and rehydrate external
   artifacts separately.
