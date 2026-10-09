# Command routing

Installed `--help` is the syntax authority.

## Target

Embedded mode owns local SQLite state:

```sh
tenkaictl --database /path/to/tenkai.db <command>
```

Remote mode uses a server URL. Sign in with `tenkaictl login`, or load
`TENKAI_MANAGEMENT_TOKEN` from a secret store.

```sh
TENKAI_SERVER_URL=<server-url> tenkaictl login
TENKAI_SERVER_URL=<server-url> tenkaictl --target remote <command>
```

Remote CLI support can be narrower than embedded support. Stay in the selected
target mode. `--output json-v1` is embedded-only; in remote mode read state
back with `env inspect <env>`, which prints JSON.

Remote `plan`, `apply`, `approval submit`, `rollback`, and `env subscribe`
require `--generation`. Read it from `lease.generation` in
`tenkaictl --target remote env inspect <env>`; pass `0` when it is `null`
(no lease was ever taken). A released or expired lease keeps its generation.
`stale fencing generation N cannot complete; expected M` means another tick or
operator moved the fence: re-inspect, re-plan when the plan changed, and retry
with `M`.

A `--tenant-mode` hub refuses lifecycle routes for credentials without a tenant
claim, including the fleet management token. Continuous delivery of a host's
own services needs a separate community `tenkai-server` with its own database,
token, and an OIDC config without `tenant_claim`.

Embedded `promote`, `release recall`, and `canary designate` record an
authenticated actor. They need `TENKAI_MANAGEMENT_TOKEN` (or
`TENKAI_JWT_ASSERTION` with `TENKAI_JWT_VERIFIER_CONFIG`) even with no server
running.

## Route

| Job | Family |
| --- | --- |
| Bootstrap | `init` |
| Sign in | `login`, `logout` |
| Publish | `publish`, `release inspect`, `release verify` |
| Promote | `promote`, `canary` |
| Configure | `env add`, `env subscribe`, `env facts`, `env overlay`, `env constraints`, `env maintenance`, `env connectivity`, `env observe`, `env preview`, `env close-preview`, `env retire`, `env artifact-mirror`, `env cluster-config`, `env docker-secrets`, `env approval-policy`, `product maintenance` |
| Plan and apply | `plan`, `apply`, `approval inspect`, `approval submit` |
| Reconcile | `reconcile --once` |
| Roll back | `rollback`, `restart`, `release recall` |
| Migrate | `migrate` |
| Wave | `wave` |
| Upgrade | `upgrade` |
| Recover | `env reconcile`, `env unlock`, `backup`, `restore`, `recovery export` |

For syntax, flags, and target-mode support, run `tenkaictl <family> --help`.

## Adopt a running version

To put an already-running deployment under Tenkai without a redeploy:

1. Publish a release whose manifest pins exactly what is running, and promote
   it to the channel.
2. `env subscribe <env> <product>=<channel>`.
3. `env reconcile <env> <product> --deployed <version>` records the verified
   running version.
4. `plan --env <env>` must report the environment up to date. Any step means
   the release does not match what runs; fix the release, not the target.

## Invariants

**Login.** `login` is Authorization Code + PKCE against `GET /v1/auth/oidc`.
`logout` forgets the saved login for that server URL.

**Plans.** Stored dry runs over current desired state. A maintenance-blocked
plan may be re-applied or resumed by reconcile when the resolved environment
and product windows are open.

**Overlays.** Non-secret product config. An overlay change can emit a
same-version Restart.

**Artifact mirrors.** Apply pulls OCI artifacts only from
`env artifact-mirror`. A missing mirror refuses origin pull.

**Cluster config.** Store an environment-scoped kubeconfig path. Never
credential bytes.

**Docker secrets.** Store an environment-scoped secret-file directory path.
Never secret bytes.

**Approval policy.** Store an environment-scoped plan approval policy file
path. Never signer key bytes. Skip-gates and rollback stay human.

**Publication.** Creates an immutable release. Republish identical content only
to reconcile an uncertain outcome; changed content requires a new version.

**Machine results.** Require `schema = "tenkai.command-result/v1"`. Treat
identifiers as opaque. Reject unknown fields or enum values.

**Reconcile.** `--once` for a bounded agent operation. Continuous reconciliation
belongs under an operator-managed supervisor.

**Shell executor.** On a failed install or health probe Tenkai runs
`uninstall` of the new release, then `install` and `health` of the previous
release. The plan ends `failed` with step `rolled_back` only when every one of
those succeeds; a missing or failing `uninstall` leaves deployment state
unknown. Make `uninstall` safe and idempotent. Commands run under `sh -c` with
a cleared environment: `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`,
`LC_CTYPE`, `TMPDIR`, `TMP`, `TEMP`, `TZ` when set, plus `TENKAI_ENVIRONMENT`,
`TENKAI_PRODUCT`, `COMPOSE_PROJECT_NAME`, and `TENKAI_FENCING_GENERATION`.
Use absolute paths in wrappers and never expect control-plane credentials.

**Rollback.** Creates and executes the normal pinned-release plan path.
Non-local rollback can stop at approval-required state and return the plan
identifier.

**Canary.** Policy requires successful evidence from every named environment
before promotion. Repair rebuilds durable outcomes for a completed apply.

**Preview.** `env preview` registers a non-promotable environment from a branch
pin. `env close-preview` tears down only a preview.

**Migrate.** Declaration is `tenkai.package_migration.v1`. Compensating
checkpoints apply the target pin through existing plans. Irreversible
checkpoints require `--backup-receipt-digest` at admit. Accepted irreversible
work records `recovery_required` and never reports rollback success.
Local-development bypass stays on the built-in `local` environment.

**Wave.** `wave run` observes an ordered cohort. `wave execute` admits a durable
named wave; the name is a content-bound identity key. Stop skips remaining
cohorts without rewriting completed ones. Rollback uses Tenkai rollback plans.

**Upgrade.** One signed upgrade across connected, intermittent, and isolated
environments. Isolated work binds a `tenkai.offline-bundle.v1` and imports a
`tenkai.offline-receipt.v1`; conflicts fail closed.

**Recovery export.** Read-only diagnostic for one plan. Recovery authority
stays on Tenkai state.
