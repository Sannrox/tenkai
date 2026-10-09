# Completion-gated Docker initialization jobs

Research for [issue #531](https://github.com/Sannrox/tenkai/issues/531), reviewed
2026-10-09. Primary sources establish ordering and completion gates. The replay
policy below is a Tenkai design choice, not a claim about Apollo internals.

## Palantir approach and its limits

Apollo's default Helm `manageRollout` applies resources, waits for readiness,
and fails the Plan with rollback if application or readiness fails. Helm hooks
have a separate five-minute operation timeout, distinct from Apollo's resource
readiness timeout. This supports bounded deployment work that must finish before
success is reported. The documented `applyChangesNoWait` alternative still
permits hook timeouts; it does not make every deployment operation asynchronous.
[Apollo rollout strategies and timeouts](https://www.palantir.com/docs/apollo/core/helm-rollouts)

Helm defines install, upgrade, delete, and rollback hooks before and after the
corresponding operation. Job and Pod hooks block until successful completion;
failure fails the release. Hook weights establish order. Hook deletion is
separate from release cleanup, with policies for before a new creation, success,
or failure. These are Helm facts; Apollo's documentation confirms it runs Helm
hooks but does not specify an independent Apollo Docker-job protocol.
[Helm chart hooks](https://helm.sh/docs/topics/charts_hooks/)

The reviewed public Apollo documentation does not establish exactly-once job
execution, retry deduplication, replay on an ordinary service restart, or automatic
reversal of database migration side effects. Do not attribute the policies below
to Palantir. The transferable approach is product-owned initialization code,
explicit lifecycle ordering, bounded completion, and deployment failure on an
unsatisfied gate.

## Docker semantics

Compose explicitly distinguishes `service_started`, `service_healthy`, and
`service_completed_successfully`. The last requires successful completion before
the dependent service starts. Ordinary dependency ordering alone does not mean
readiness. A dependency's `restart: true` concerns an explicit Compose update or
restart, not automatic container-runtime recovery.
[Compose startup order](https://docs.docker.com/compose/how-tos/startup-order/)

Docker inspect exposes `State.Status`, `Running`, `ExitCode`, `OOMKilled`, and
timestamps. A running container can report `ExitCode: 0`; therefore zero alone
is not completion evidence. Require a terminal `exited` state as well as zero.
The wait endpoint returns an exit code after a container stops; missing containers
are a distinct error. These are process facts, not proof that an application
transaction committed.
[Engine API inspect and wait](https://docs.docker.com/reference/api/engine/version/v1.51/)

Docker retains exited containers by default, allowing final-state inspection.
`--rm` removes that evidence. Container removal with `--rm` removes anonymous
volumes but preserves named volumes. Jobs should therefore remain inspectable
until explicit Tenkai cleanup, without automatic removal.
[Docker run cleanup](https://docs.docker.com/reference/cli/docker/container/run/)

Docker's `no` restart policy performs no automatic restart; `on-failure` retries
nonzero exits, while `always` and `unless-stopped` can restart successful exits.
Use `no` for one-shot jobs so Docker cannot independently replay their effects.
[Docker restart policies](https://docs.docker.com/engine/containers/start-containers-automatically/)

## Recommended Tenkai policy

- Add a typed job mode with a required bounded timeout and explicit dependency
  conditions. Keep legacy service behavior. Validate condition/mode mismatches
  and cycles before mutations.
- Bind retained completion evidence to the managed container's release and
  configuration identity. Observe only inspects. Reconciliation and ordinary
  service restart retain matching successful jobs; absence or malformed evidence
  is not success.
- Run one attempt per explicit activation attempt. Nonzero exit or timeout blocks
  dependents and yields only safe status, exit code, and bounded receipt metadata.
  Do not copy raw container logs into receipts. An explicit retry may run failed
  work again; it must not silently replay matching successful work.
- A new release activation may replay its jobs. Rollback activation may replay
  the target release's jobs if their containers were removed or replaced. State
  this prominently: rollback restores software, not database contents. Application
  jobs must tolerate replay; exactly-once external side effects are out of scope.
- Remove managed service and job containers in reverse dependency order. Preserve
  named data volumes. Test success, nonzero exit, timeout, repeated observation,
  retry, restart, and rollback using deterministic Docker command fixtures.
