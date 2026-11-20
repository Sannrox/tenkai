# Upgrade, roll back, and recover a product

## Upgrade

Publish a new version, promote it, and `apply` the new plan to upgrade. If the
health probe of a new release fails, the previous release is restored
automatically. Optional SLO gates (#590) can also halt the rollout or restore
that same previously signed pin after a bake-window breach.

Embedded human `tenkaictl plan` and `tenkaictl plan show <plan-id>` print
the approval brief first, then each step's desired-versus-live target
change (object or file). Secret values appear only as a content digest.
The recorded diff and the brief are part of the plan digest; apply refuses
the step as stale if that live object moved, and an approval cannot cover a
different brief. Environment inspect returns the brief on
`latest_plan.approval_brief`.

After a failed deployment or automatic rollback, the environment retains the
failed release and originating plan identity. Automatic convergence holds that
target instead of creating another attempt on every tick. Status and inspect
report that the target failed and automatic retry is held; fleet status retains
the failure posture. A different selected release can converge normally.

To retry deliberately, run `tenkaictl env retry <env> <product> --reason …`
(or `tenkaictl plan --env <env>`), approve the exact digest, and apply it.
Explicit planning includes the held target; it does not clear the hold merely
by computing a plan. Successful deployment clears the marker, while another
failure retains it. Unknown deployment state still requires manual recovery
before any new plan. Remote retry requires `--generation`.

SLO gates declared on a release or channel are evaluated after activation
succeeds and before the step is recorded as succeeded. `on_fail = "halt"`
stops further steps and leaves the new release deployed. `on_fail = "rollback"`
restores the plan's previously signed pin and does not re-evaluate SLO gates
on that restore. See [health and SLO gate evidence](health-gate-evidence.md).

## Roll back deliberately

Use `tenkaictl rollback <product>` to return to the previously deployed
version. Same-version remediations (`tenkaictl restart`, environment overlays,
recall, and audited `--allow-recalled-recovery`) are recorded in
[ADR 0016](decisions/0016-same-version-remediation.md).

## Stop and start without unsubscribing

`tenkaictl stop <product> --env <env> --reason <text>` plans a stop of the
deployed instance: Kubernetes scales to zero, Docker stops the container, and
the subscription and deployed pin stay. Status reports `stopped`; health,
pacing, and recall skip the instance instead of counting it as failing. A
channel upgrade waits until `tenkaictl start <product> --env <env>` returns it
to the recorded release. Both commands create a plan that needs signed
approval, embedded and remote. Host OS releases refuse stop and start.

## Adopt a live workload without redeploying

`tenkaictl adopt <env> <product@version>` records a subscribed instance as
deployed when the catalog pin already matches the live target. Status lists
live Helm, Kubernetes, and host workloads no recorded instance owns as
`unmanaged`; planning skips an install over those names. Adopt never mutates
the target. A live diff is refused with the changed fields; resolve it or
approve a regular plan as the change. The adopt plan needs signed approval,
embedded and remote. Remote adopt requires `--generation`. After adopt, drift
and reconcile treat the instance like any other.

## Recover unknown deployment state

If failed cleanup leaves deployment state unknown, reconcile the external
target manually, then run `tenkaictl env reconcile <env> <product>` after
cleanup or add `--deployed <version>` to record the verified live version.

Against a running server, pass the environment's current generation (the
`generation` that `tenkaictl env inspect <env>` reports) instead of stopping
the server:

```bash
tenkaictl --target remote env reconcile <env> <product> \
  --deployed <version> --generation <generation>
```

The server records the state as the embedded command does and audits it with
the caller. It refuses a stale generation and refuses while an apply holds the
environment; neither changes anything. An environment-scoped management token
may reconcile only its own environment. The call claims the apply lease for
the write, so the generation advances: read it again before the next fenced
call.

For stateful products whose upgrades need data migration, see
[package migrations](package-migrations.md). To restore Tenkai's own state, see
[backup and restore](backup-restore.md). To deliver Tenkai's own server and
console as a catalog product, see [deliver Tenkai with Tenkai](deliver-tenkai.md).

Trust-root files may carry optional signer `not_before` / `not_after` windows
on format v1 ([ADR 0039](decisions/0039-signer-validity-windows.md)). Upgrade
every host before writing those fields. Restore files without the fields
before running an older binary; an older release refuses a file that still
has them.

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
