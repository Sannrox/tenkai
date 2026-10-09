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
target mode. Remote `plan`, `apply`, `approval submit`, `rollback`, and
`env subscribe` require `--generation`.

## Route

| Job | Family |
| --- | --- |
| Bootstrap | `init` |
| Sign in | `login`, `logout` |
| Publish | `publish`, `release inspect`, `release verify` |
| Promote | `promote`, `canary` |
| Configure | `env add`, `env subscribe`, `env facts`, `env overlay`, `env constraints`, `env maintenance`, `env connectivity`, `env observe`, `env preview`, `env close-preview`, `env retire`, `env artifact-mirror`, `env cluster-config`, `env docker-secrets`, `product maintenance` |
| Plan and apply | `plan`, `apply`, `approval inspect`, `approval submit` |
| Reconcile | `reconcile --once` |
| Roll back | `rollback`, `restart`, `release recall` |
| Migrate | `migrate` |
| Wave | `wave` |
| Upgrade | `upgrade` |
| Recover | `env reconcile`, `env unlock`, `backup`, `restore`, `recovery export` |

For syntax, flags, and target-mode support, run `tenkaictl <family> --help`.

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

**Publication.** Creates an immutable release. Republish identical content only
to reconcile an uncertain outcome; changed content requires a new version.

**Machine results.** Require `schema = "tenkai.command-result/v1"`. Treat
identifiers as opaque. Reject unknown fields or enum values.

**Reconcile.** `--once` for a bounded agent operation. Continuous reconciliation
belongs under an operator-managed supervisor.

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
