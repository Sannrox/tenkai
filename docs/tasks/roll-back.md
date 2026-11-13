# Roll back

Goal: restore the previously deployed version of one product through the normal plan path.

Automatic rollback already runs when a health probe fails. Use this page for a deliberate restore.

```sh
tenkaictl --output json-v1 status --env prod
tenkaictl --output json-v1 rollback api --env prod
```

json-v1 `rollback` returns a plan resource when the restore is stored. Non-local rollback can stop at `awaiting_approval`; a human signs that plan, then apply proceeds as in [deploy with approval](deploy-with-approval.md). Rollback plans always need a human-signed envelope.

A successful restore still holds the environment so the next automatic tick does not re-apply the bad pin. Clear the hold only after a human decides the fleet should move again.

Recalled previous pins need `--allow-recalled-recovery` and `--recovery-reason`. Same-version bounce is `restart`, not rollback.

Contract detail: [upgrade and rollback](../upgrade-and-rollback.md), [command results](../command-results.md).
