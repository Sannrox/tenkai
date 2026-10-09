# Upgrade, roll back, and recover a product

## Upgrade

Publish a new version, promote it, and `apply` the new plan to upgrade. If the
health probe of a new release fails, the previous release is restored
automatically.

After a failed deployment or automatic rollback, the environment retains the
failed release and originating plan identity. Automatic convergence holds that
target instead of creating another attempt on every tick. Status and inspect
report that the target failed and automatic retry is held; fleet status retains
the failure posture. A different selected release can converge normally.

To retry deliberately, create a new plan with `tenkaictl plan --env <env>`,
approve its exact digest, and apply it. Explicit planning includes the held
target; it does not clear the hold merely by computing a plan. Successful
deployment clears the marker, while another failure retains it. Unknown
deployment state still requires manual recovery before any new plan.

## Roll back deliberately

Use `tenkaictl rollback <product>` to return to the previously deployed
version. Same-version remediations (`tenkaictl restart`, environment overlays,
recall, and audited `--allow-recalled-recovery`) are recorded in
[ADR 0016](decisions/0016-same-version-remediation.md).

## Recover unknown deployment state

If failed cleanup leaves deployment state unknown, reconcile the external
target manually, then run `tenkaictl env reconcile <env> <product>` after
cleanup or add `--deployed <version>` to record the verified live version.

For stateful products whose upgrades need data migration, see
[package migrations](package-migrations.md). To restore Tenkai's own state, see
[backup and restore](backup-restore.md).

## Capture a rollback replay

The deterministic replay capture runs a healthy deployment followed by a
deliberately unhealthy upgrade, records Tenkai's automatic rollback, and asks
`sekaictl replay export` for a static JSON bundle rooted at the incident plan:

```sh
./scripts/capture-rollback-replay.sh
```

By default it expects `../sekai-chisei`, uses an isolated temporary database,
and writes `artifacts/replay/rollback-incident.json`. Override the repository
with `SEKAI_CHISEI_DIR` or the destination with `REPLAY_OUTPUT_DIR`.

Independent fresh-checkout evidence for the provider-free embedded workflow,
including automatic rollback and backup/restore, is recorded in the
[embedded golden-path usability exercise](research/embedded-golden-path-usability.md).
